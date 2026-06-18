import pytest

from sysadmin_api.executor import SimulatedExecutor
from sysadmin_api.models import (
    ApprovalRequest,
    CampaignRequest,
    ExecutionResult,
    HostInput,
    PatchPolicy,
)


def host_input(name, **overrides):
    values = {
        "name": name,
        "address": "10.0.0.10",
        "username": "ubuntu",
        "environment": "production",
        "tags": ["web"],
        "criticality": "high",
        "availability_class": "high_availability",
    }
    values.update(overrides)
    return HostInput(**values)


def approval_for(host, host_plan):
    return ApprovalRequest(
        plan_version=host_plan.plan_version,
        plan_hash=host_plan.plan_hash,
        hostname_confirmation=host.name,
    )


async def campaign_with_proposals(service, *hosts):
    campaign = service.create_campaign(
        CampaignRequest(
            name="Production patch wave",
            host_ids=[host.id for host in hosts],
        ),
        "admin",
    )
    _, jobs = service.queue_campaign_proposals(campaign.id, "admin")
    for job in jobs:
        await service.process_scan(job.id)
    return service.get_campaign(campaign.id)


def approve_host(service, campaign, host):
    host_plan = next(item for item in campaign.hosts if item.host_id == host.id)
    request = approval_for(host, host_plan)
    campaign = service.approve_campaign_host(
        campaign.id,
        host.id,
        request,
        "admin",
    )
    campaign = service.approve_campaign_host_reboot(
        campaign.id,
        host.id,
        request,
        "admin",
    )
    return campaign


@pytest.mark.asyncio
async def test_campaign_executes_only_individually_approved_host_plans(service):
    first = service.create_host(host_input("web-1"))
    second = service.create_host(host_input("web-2"))
    third = service.create_host(host_input("web-3"))
    campaign = await campaign_with_proposals(service, first, second, third)

    assert campaign.status == "awaiting_approval"
    assert all(item.plan_version and item.plan_hash for item in campaign.hosts)

    campaign = approve_host(service, campaign, first)
    second_plan = next(item for item in campaign.hosts if item.host_id == second.id)
    campaign = service.approve_campaign_host(
        campaign.id,
        second.id,
        approval_for(second, second_plan),
        "admin",
    )

    campaign, jobs = service.prepare_campaign_execution(campaign.id, "admin")

    assert [job.host_id for job in jobs] == [first.id]
    states = {item.host_id: item.state for item in campaign.hosts}
    assert states[first.id] == "queued"
    assert states[second.id] == "awaiting_reboot_approval"
    assert states[third.id] == "awaiting_approval"

    await service.process_remediation(jobs[0].id)
    campaign = service.get_campaign(campaign.id)

    assert campaign.status == "partially_succeeded"
    states = {item.host_id: item.state for item in campaign.hosts}
    assert states[first.id] == "succeeded"
    assert states[second.id] == "awaiting_reboot_approval"
    assert states[third.id] == "awaiting_approval"


@pytest.mark.asyncio
async def test_campaign_changed_plan_invalidates_host_approval(service):
    host = service.create_host(host_input("web-1"))
    campaign = await campaign_with_proposals(service, host)
    campaign = approve_host(service, campaign, host)
    host_plan = campaign.hosts[0]
    original_remediation_id = host_plan.remediation_id
    remediation = service.repository.get_remediation(host_plan.remediation_id)
    remediation.update_scope = "security"
    service.repository.save_remediation(remediation)

    with pytest.raises(ValueError, match="no approved host plans"):
        service.prepare_campaign_execution(campaign.id, "admin")

    campaign = service.get_campaign(campaign.id)
    invalidated = service.repository.get_remediation(host_plan.remediation_id)
    assert campaign.hosts[0].state == "plan_changed"
    assert campaign.hosts[0].plan_hash != invalidated.plan_hash
    assert invalidated.approval_state == "pending"
    assert invalidated.reboot_approval_state == "pending"

    _, jobs = service.queue_campaign_proposals(campaign.id, "admin")
    assert len(jobs) == 1
    await service.process_scan(jobs[0].id)
    refreshed = service.get_campaign(campaign.id)

    assert refreshed.hosts[0].state == "awaiting_approval"
    assert refreshed.hosts[0].remediation_id != original_remediation_id
    assert refreshed.hosts[0].approval_state == "pending"
    assert refreshed.hosts[0].reboot_approval_state == "pending"


@pytest.mark.asyncio
async def test_campaign_reports_partial_success_after_host_failure(service):
    class SelectiveFailureExecutor(SimulatedExecutor):
        async def execute(self, host, remediation, job_id=""):
            if host.name == "web-2":
                return ExecutionResult(
                    success=False,
                    summary="Simulated campaign host failure",
                    changed=True,
                    reboot_performed=False,
                    phases=[],
                )
            return await super().execute(host, remediation, job_id)

    service.executor = SelectiveFailureExecutor()
    first = service.create_host(host_input("web-1"))
    second = service.create_host(host_input("web-2"))
    campaign = await campaign_with_proposals(service, first, second)
    campaign = approve_host(service, campaign, first)
    campaign = approve_host(service, campaign, second)
    campaign, jobs = service.prepare_campaign_execution(campaign.id, "admin")

    assert len(jobs) == campaign.batch_size == 1
    await service.process_remediation(jobs[0].id)
    campaign, jobs = service.prepare_campaign_execution(campaign.id, "admin")
    await service.process_remediation(jobs[0].id)
    campaign = service.get_campaign(campaign.id)

    assert campaign.status == "partially_succeeded"
    assert {item.state for item in campaign.hosts} == {"succeeded", "failed"}
    assert "Simulated campaign host failure" in campaign.failure_summary


@pytest.mark.asyncio
async def test_campaign_reports_failure_when_no_host_succeeds(service):
    class FailureExecutor(SimulatedExecutor):
        async def execute(self, host, remediation, job_id=""):
            return ExecutionResult(
                success=False,
                summary="Simulated terminal failure",
                changed=True,
                reboot_performed=False,
                phases=[],
            )

    service.executor = FailureExecutor()
    host = service.create_host(host_input("web-1"))
    campaign = await campaign_with_proposals(service, host)
    campaign = approve_host(service, campaign, host)
    campaign, jobs = service.prepare_campaign_execution(campaign.id, "admin")

    await service.process_remediation(jobs[0].id)
    campaign = service.get_campaign(campaign.id)

    assert campaign.status == "failed"
    assert campaign.hosts[0].state == "failed"


@pytest.mark.asyncio
async def test_campaign_cancellation_cancels_queued_host_jobs(service):
    first = service.create_host(host_input("web-1"))
    second = service.create_host(host_input("web-2"))
    campaign = await campaign_with_proposals(service, first, second)
    campaign = approve_host(service, campaign, first)
    campaign = approve_host(service, campaign, second)
    campaign, jobs = service.prepare_campaign_execution(campaign.id, "admin")

    canceled = service.cancel_campaign(campaign.id, "admin")

    assert canceled.status == "canceled"
    assert {item.state for item in canceled.hosts} == {"canceled"}
    assert {service.get_job(job.id).status for job in jobs} == {"canceled"}


@pytest.mark.asyncio
async def test_campaign_cancellation_represents_running_work(service):
    host = service.create_host(host_input("web-1"))
    campaign = await campaign_with_proposals(service, host)
    campaign = approve_host(service, campaign, host)
    campaign, jobs = service.prepare_campaign_execution(campaign.id, "admin")
    job = jobs[0]
    job.status = "running"
    service.repository.save_job(job)
    remediation = service.repository.get_remediation(job.remediation_id)
    remediation.execution_state = "running"
    service.repository.save_remediation(remediation)

    cancelling = service.cancel_campaign(campaign.id, "admin")

    assert cancelling.status == "cancelling"
    assert cancelling.hosts[0].state == "running"


@pytest.mark.asyncio
async def test_campaign_reboot_approval_is_separate_and_obeys_host_policy(service):
    host = service.create_host(
        host_input(
            "web-1",
            patch_policy=PatchPolicy(reboot_policy="never"),
        )
    )
    campaign = await campaign_with_proposals(service, host)
    host_plan = campaign.hosts[0]
    request = approval_for(host, host_plan)

    campaign = service.approve_campaign_host(
        campaign.id,
        host.id,
        request,
        "admin",
    )
    assert campaign.hosts[0].state == "awaiting_reboot_approval"

    with pytest.raises(ValueError, match="forbids reboot risk"):
        service.approve_campaign_host_reboot(
            campaign.id,
            host.id,
            request,
            "admin",
        )

    campaign = service.get_campaign(campaign.id)
    assert campaign.hosts[0].state == "blocked"
    with pytest.raises(ValueError, match="cannot execute|no approved host plans"):
        service.prepare_campaign_execution(campaign.id, "admin")
