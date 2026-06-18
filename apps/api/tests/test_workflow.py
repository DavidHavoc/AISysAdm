import asyncio
from datetime import datetime, timezone

import pytest

from sysadmin_api.agents import (
    validate_orchestrator_response,
    validate_review_response,
)
from sysadmin_api.collector import DemoCollector
from sysadmin_api.executor import SimulatedExecutor
from sysadmin_api.models import (
    AgentName,
    ApprovalRequest,
    Finding,
    HostInput,
    MaintenanceWindow,
    PatchPolicy,
    RecommendedAction,
    ScanRequest,
    Severity,
    utc_now,
)
from sysadmin_api.providers import ModelRouter
from sysadmin_api.verifier import DeterministicVerifier


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


async def completed_scan(service, host):
    job = service.create_scan_job(ScanRequest(host_id=host.id))
    completed = await service.process_scan(job.id)
    return service.get_scan(completed.scan_id)


def approval_for(host, remediation):
    return ApprovalRequest(
        plan_version=remediation.plan_version,
        plan_hash=remediation.plan_hash,
        hostname_confirmation=host.name,
    )


@pytest.mark.asyncio
async def test_three_agents_and_reboot_are_explicit(service):
    host = service.create_host(host_input())
    scan = await completed_scan(service, host)

    assert scan.status == "completed"
    assert {report.agent.name for report in scan.agent_reports} == {
        "log_analyst",
        "linux_state_analyst",
    }
    assert all(
        report.agent.model_tier == "deterministic"
        for report in scan.agent_reports
    )
    peer_reviews = [
        message
        for message in service.list_agent_messages(scan.id)
        if message.from_agent in ("log_analyst", "linux_state_analyst")
        and message.to_agent in ("log_analyst", "linux_state_analyst")
    ]
    assert len(peer_reviews) == 2
    assert {message.from_agent for message in peer_reviews} == {
        "log_analyst",
        "linux_state_analyst",
    }

    remediation = service.list_remediations()[0]
    assert remediation.update_scope == "all"
    assert remediation.reboot_assessment.status == "required_after_patch"
    assert remediation.reboot_assessment.approved_if_required is False
    assert remediation.rollout_policy.batch_size == 1
    assert remediation.execution_state == "not_started"


@pytest.mark.asyncio
async def test_approval_binds_job_to_exact_plan_and_required_reboot(service):
    host = service.create_host(host_input())
    scan = await completed_scan(service, host)
    remediation = service.repository.get_remediation(scan.remediation_ids[0])

    approved_plan = service.approve_remediation_plan(
        remediation.id,
        approval_for(host, remediation),
        "admin",
    )
    assert approved_plan.reboot_approval_state == "pending"
    service.approve_remediation_reboot(
        remediation.id,
        approval_for(host, remediation),
        "admin",
    )
    job = service.prepare_remediation_job(
        remediation.id,
        "admin",
    )
    completed = await service.process_remediation(job.id)
    approved = service.repository.get_remediation(remediation.id)

    assert job.approved_plan_version == remediation.plan_version
    assert job.approved_plan_hash == remediation.plan_hash
    assert job.approval_scope == "patch_and_reboot_if_required"
    assert completed.status == "completed"
    assert approved.execution_state == "succeeded"
    assert approved.result.reboot_performed is True


@pytest.mark.asyncio
async def test_changed_plan_is_blocked_before_executor_runs(service):
    host = service.create_host(host_input())
    scan = await completed_scan(service, host)
    remediation = service.repository.get_remediation(scan.remediation_ids[0])
    service.approve_remediation_plan(
        remediation.id,
        approval_for(host, remediation),
        "admin",
    )
    service.approve_remediation_reboot(
        remediation.id,
        approval_for(host, remediation),
        "admin",
    )
    job = service.prepare_remediation_job(
        remediation.id,
        "admin",
    )
    remediation.update_scope = "security"
    service.repository.save_remediation(remediation)

    result = await service.process_remediation(job.id)

    assert result.status == "failed"
    assert "approved plan" in result.error
    invalidated = service.repository.get_remediation(remediation.id)
    assert invalidated.approval_state == "pending"
    assert invalidated.reboot_approval_state == "pending"
    assert invalidated.execution_state == "blocked"


@pytest.mark.asyncio
async def test_duplicate_worker_delivery_executes_scan_once(service):
    class CountingCollector(DemoCollector):
        calls = 0

        async def collect(self, host, job_id="", scan_id=""):
            self.calls += 1
            await asyncio.sleep(0)
            return await super().collect(host, job_id, scan_id)

    collector = CountingCollector()
    service.collector = collector
    host = service.create_host(host_input())
    job = service.create_scan_job(ScanRequest(host_id=host.id))

    first, second = await asyncio.gather(
        service.process_scan(job.id),
        service.process_scan(job.id),
    )

    assert collector.calls == 1
    assert {first.status, second.status} <= {"running", "completed"}
    assert service.get_job(job.id).status == "completed"


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
    scan = await completed_scan(service, host)
    remediation = service.repository.get_remediation(scan.remediation_ids[0])

    service.approve_remediation_plan(
        remediation.id,
        approval_for(host, remediation),
        "admin",
    )
    service.approve_remediation_reboot(
        remediation.id,
        approval_for(host, remediation),
        "admin",
    )
    job = service.prepare_remediation_job(
        remediation.id,
        "admin",
    )

    assert job.status == "scheduled"
    assert service.repository.get_remediation(remediation.id).execution_state == (
        "waiting_for_window"
    )


@pytest.mark.asyncio
async def test_reboot_never_policy_blocks_uncertain_or_required_reboot(service):
    host = service.create_host(
        host_input(patch_policy=PatchPolicy(reboot_policy="never"))
    )
    scan = await completed_scan(service, host)
    remediation = service.repository.get_remediation(scan.remediation_ids[0])

    service.approve_remediation_plan(
        remediation.id,
        approval_for(host, remediation),
        "admin",
    )
    with pytest.raises(ValueError, match="forbids reboot risk"):
        service.approve_remediation_reboot(
            remediation.id,
            approval_for(host, remediation),
            "admin",
        )

    blocked = service.repository.get_remediation(remediation.id)
    assert blocked.approval_state == "approved"
    assert blocked.reboot_approval_state == "blocked"
    assert blocked.execution_state == "blocked"


@pytest.mark.asyncio
async def test_scheduled_scan_can_propose_but_never_approve(service):
    host = service.create_host(host_input())
    job = service.create_scan_job(
        ScanRequest(
            host_id=host.id,
            trigger="scheduled",
            idempotency_key="scheduled-test",
        ),
        actor="scheduler",
    )

    await service.process_scan(job.id)
    remediation = service.list_remediations()[0]

    assert remediation.approval_state == "pending"
    assert not [
        item
        for item in service.list_jobs()
        if item.job_type == "remediation"
    ]


@pytest.mark.asyncio
async def test_executor_refuses_unapproved_remediation(service):
    host = service.create_host(host_input())
    scan = await completed_scan(service, host)
    remediation = service.repository.get_remediation(scan.remediation_ids[0])

    result = await SimulatedExecutor().execute(host, remediation)

    assert result.success is False
    assert "not approved" in result.summary


def test_provider_cannot_clear_deterministic_conflicts():
    fallback = {
        "update_scope": "all",
        "risk_level": "high",
        "explanation": "Verified fallback",
        "status": "insufficient_evidence",
        "supporting_citations": ["packages.updates"],
        "unresolved_conflicts": ["finding-1 lacks evidence"],
    }

    result = validate_orchestrator_response(
        {
            "status": "plan_ready",
            "unresolved_conflicts": [],
            "supporting_citations": ["packages.updates"],
        },
        fallback,
        ["packages.updates"],
    )

    assert result["status"] == "insufficient_evidence"
    assert result["unresolved_conflicts"] == ["finding-1 lacks evidence"]


def test_provider_cannot_relax_deterministic_evidence_request():
    finding = Finding(
        id="finding-1",
        host_id="host-1",
        source_agent=AgentName.LOG_ANALYST,
        category="logs",
        severity=Severity.HIGH,
        summary="Claim",
        explanation="Claim",
        evidence=[],
        recommended_action=RecommendedAction(
            action_type="manual_review",
            title="Review",
            rationale="Evidence is missing",
        ),
        requires_approval=True,
        confidence=0.9,
        created_at=utc_now(),
    )
    fallback = {
        "response": "request_evidence",
        "claim_ids": [finding.id],
        "reasoning": "Missing evidence",
        "citations": [],
    }

    result = validate_review_response(
        {
            "response": "confirm",
            "claim_ids": [finding.id],
            "reasoning": "Looks fine",
            "citations": [],
        },
        [finding],
        fallback,
    )

    assert result["response"] == "request_evidence"


@pytest.mark.asyncio
async def test_unsupported_ai_action_is_rejected_before_plan_synthesis(service):
    host = service.create_host(host_input())
    collected = await service.collector.collect(host)
    finding = Finding(
        id="unsupported-finding",
        host_id=host.id,
        source_agent=AgentName.LOG_ANALYST,
        category="logs",
        severity=Severity.HIGH,
        summary="Run arbitrary command",
        explanation="Unsupported provider claim",
        evidence=[
            {
                "source": "package inventory",
                "excerpt": "updates available",
                "citation": "packages.updates",
            }
        ],
        recommended_action=RecommendedAction(
            action_type="run_shell",
            title="Run shell command",
            rationale="Provider requested an uncataloged action",
        ),
        requires_approval=True,
        confidence=0.99,
        created_at=utc_now(),
    )

    verified, rejected = DeterministicVerifier().verify_findings(
        collected.snapshot,
        [finding],
        [],
    )

    assert verified == []
    assert rejected
    assert "not in the remediation catalog" in rejected[0]


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
