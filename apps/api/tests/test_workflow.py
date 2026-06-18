from datetime import datetime, timezone

import pytest

from sysadmin_api.models import (
    AgentName,
    CampaignRequest,
    ExecutionResult,
    HostInput,
    MaintenanceWindow,
    PatchPolicy,
    ScanRequest,
)
from sysadmin_api.providers import ModelRouter


def host_input(name: str = "web-1", **overrides) -> HostInput:
    values = {
        "name": name,
        "address": "10.0.0.10",
        "port": 22,
        "username": "ubuntu",
        "distro_family": "debian",
        "environment": "production",
        "tags": ["web"],
        "criticality": "high",
        "availability_class": "high_availability",
        "patch_policy": PatchPolicy(),
    }
    values.update(overrides)
    return HostInput(**values)


@pytest.mark.asyncio
async def test_three_agents_and_reboot_are_explicit(service):
    host = service.create_host(host_input())
    scan = await service.run_scan(ScanRequest(host_id=host.id))

    assert scan.status == "completed"
    assert {report.agent.name for report in scan.agent_reports} == {
        "log_analyst",
        "linux_state_analyst",
    }
    assert all(report.agent.model_tier == "deterministic" for report in scan.agent_reports)

    remediation = service.list_remediations()[0]
    assignments = {item.name: item for item in remediation.ai_decision.agent_assignments}
    assert set(assignments) == {
        "orchestrator",
        "log_analyst",
        "linux_state_analyst",
    }
    assert remediation.update_scope == "all"
    assert remediation.reboot_assessment.status == "required_after_patch"
    assert remediation.reboot_assessment.approved_if_required is False
    assert remediation.rollout_policy.batch_size == 1
    assert remediation.execution_state == "not_started"


@pytest.mark.asyncio
async def test_approval_covers_patch_and_required_reboot(service):
    host = service.create_host(host_input())
    scan = await service.run_scan(ScanRequest(host_id=host.id))
    remediation_id = scan.remediation_ids[0]

    approved = await service.approve_remediation(remediation_id)

    assert approved.approval_scope == "patch_and_reboot_if_required"
    assert approved.reboot_assessment.approved_if_required is True
    assert approved.execution_state == "succeeded"
    assert approved.result is not None
    assert approved.result.reboot_performed is True


@pytest.mark.asyncio
async def test_maintenance_window_waits_after_approval(service):
    policy = PatchPolicy(
        execution_timing="maintenance_window",
        maintenance_window=MaintenanceWindow(
            timezone="UTC",
            weekdays=[0],
            start_time="02:00",
            duration_minutes=60,
        ),
    )
    host = service.create_host(host_input(patch_policy=policy))
    scan = await service.run_scan(ScanRequest(host_id=host.id))

    approved = await service.approve_remediation(
        scan.remediation_ids[0],
        now=datetime(2026, 6, 18, 12, 0, tzinfo=timezone.utc),
    )

    assert approved.approval_state == "approved"
    assert approved.execution_state == "waiting_for_window"
    assert approved.result is None


@pytest.mark.asyncio
async def test_reboot_never_policy_blocks_uncertain_or_required_reboot(service):
    policy = PatchPolicy(reboot_policy="never")
    host = service.create_host(host_input(patch_policy=policy))
    scan = await service.run_scan(ScanRequest(host_id=host.id))

    with pytest.raises(ValueError, match="forbids reboot risk"):
        await service.approve_remediation(scan.remediation_ids[0])

    blocked = service.repository.get_remediation(scan.remediation_ids[0])
    assert blocked is not None
    assert blocked.approval_state == "manual_review"
    assert blocked.execution_state == "blocked"


class FailingExecutor:
    async def execute(self, host, remediation):
        return ExecutionResult(
            success=False,
            summary="Validation failed",
            changed=True,
            reboot_performed=False,
            phases=[],
            failure_actions_taken=[
                "remaining campaign hosts stopped",
                "operator notification recorded",
                "predefined recovery diagnostics attempted",
            ],
        )


@pytest.mark.asyncio
async def test_campaign_halts_remaining_hosts_on_failure(service):
    first = service.create_host(host_input("web-1"))
    second = service.create_host(
        host_input("web-2", address="10.0.0.11")
    )
    campaign = await service.create_campaign(
        CampaignRequest(name="Production wave", host_ids=[first.id, second.id])
    )
    service.executor = FailingExecutor()

    result = await service.approve_campaign(campaign.id)

    assert result.batch_size == 1
    assert result.status == "halted"
    assert result.current_batch == 1
    second_remediation = service.repository.get_remediation(result.remediation_ids[1])
    assert second_remediation is not None
    assert second_remediation.execution_state == "not_started"


@pytest.mark.asyncio
async def test_host_findings_show_only_the_latest_scan(service):
    host = service.create_host(host_input())
    first = await service.run_scan(ScanRequest(host_id=host.id))
    second = await service.run_scan(ScanRequest(host_id=host.id))

    visible_ids = {item.id for item in service.list_findings(host.id)}

    assert visible_ids == set(second.finding_ids)
    assert visible_ids.isdisjoint(first.finding_ids)


def test_model_router_assigns_capable_and_economy_models(settings):
    settings.openai_api_key = "test-key"
    settings.openai_strong_model = "strong-model"
    settings.openai_economy_model = "economy-model"
    router = ModelRouter(settings)

    orchestrator = router.route(AgentName.ORCHESTRATOR)
    specialist = router.route(AgentName.LOG_ANALYST)

    assert orchestrator.identity.model_tier == "capable"
    assert orchestrator.identity.model == "strong-model"
    assert specialist.identity.model_tier == "economy"
    assert specialist.identity.model == "economy-model"
