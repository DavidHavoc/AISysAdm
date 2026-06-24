from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from datetime import timedelta
from threading import Barrier, Event
from time import sleep

import pytest
from sqlalchemy import select

from sysadmin_api.database import JobRecord
from sysadmin_api.models import ApprovalRequest, CampaignRequest, HostInput, PatchCampaign, utc_now
from sysadmin_api.repository import SqlRepository
from sysadmin_api.runtime import build_runtime


pytestmark = pytest.mark.integration


def host_input(name: str, **overrides) -> HostInput:
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


def approval_for(host, host_plan) -> ApprovalRequest:
    return ApprovalRequest(
        plan_version=host_plan.plan_version,
        plan_hash=host_plan.plan_hash,
        hostname_confirmation=host.name,
    )


async def campaign_with_proposals(service, *hosts) -> PatchCampaign:
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


@contextmanager
def built_service(integration_settings):
    runtime = build_runtime(integration_settings)
    try:
        yield runtime.service
    finally:
        if runtime.redis_client is not None:
            runtime.redis_client.close()
        if isinstance(runtime.repository, SqlRepository):
            runtime.repository.engine.dispose()


@pytest.mark.asyncio
async def test_concurrent_prepare_remediation_job_reuses_existing_job(
    integration_settings,
    runtime,
):
    host = runtime.service.create_host(host_input("web-1"))
    scan = await campaign_with_proposals(runtime.service, host)
    host_plan = scan.hosts[0]
    remediation = runtime.repository.get_remediation(host_plan.remediation_id)
    runtime.service.approve_remediation_plan(
        remediation.id,
        approval_for(host, host_plan),
        "admin",
    )
    runtime.service.approve_remediation_reboot(
        remediation.id,
        approval_for(host, host_plan),
        "admin",
    )
    barrier = Barrier(2)

    def prepare_request():
        with built_service(integration_settings) as service:
            barrier.wait(timeout=5)
            return service.prepare_remediation_job(remediation.id, "admin")

    with ThreadPoolExecutor(max_workers=2) as executor:
        jobs = list(executor.map(lambda _: prepare_request(), range(2)))

    remediation_jobs = [
        job
        for job in runtime.repository.list_jobs()
        if job.remediation_id == remediation.id
    ]

    assert len({job.id for job in jobs}) == 1
    assert len(remediation_jobs) == 1


@pytest.mark.asyncio
async def test_concurrent_campaign_execute_requests_queue_one_batch(
    integration_settings,
    runtime,
):
    host = runtime.service.create_host(host_input("web-1"))
    campaign = await campaign_with_proposals(runtime.service, host)
    campaign = approve_host(runtime.service, campaign, host)
    barrier = Barrier(2)

    def execute_request():
        with built_service(integration_settings) as service:
            barrier.wait(timeout=5)
            try:
                _, jobs = service.prepare_campaign_execution(campaign.id, "admin")
                return ("jobs", [job.id for job in jobs])
            except ValueError as error:
                return ("error", str(error))

    with ThreadPoolExecutor(max_workers=2) as executor:
        results = list(executor.map(lambda _: execute_request(), range(2)))

    queued_jobs = [
        job
        for job in runtime.repository.list_jobs()
        if job.campaign_id == campaign.id and job.job_type == "remediation"
    ]
    final = runtime.service.get_campaign(campaign.id)

    assert sum(kind == "jobs" for kind, _ in results) == 1
    assert sum(kind == "error" for kind, _ in results) == 1
    assert len(queued_jobs) == 1
    assert final.status == "running"
    assert final.hosts[0].state in ("queued", "scheduled")


@pytest.mark.asyncio
async def test_concurrent_campaign_execute_and_cancel_requests_are_serialized(
    integration_settings,
    runtime,
):
    host = runtime.service.create_host(host_input("web-1"))
    campaign = await campaign_with_proposals(runtime.service, host)
    campaign = approve_host(runtime.service, campaign, host)
    barrier = Barrier(2)

    def execute_request():
        with built_service(integration_settings) as service:
            barrier.wait(timeout=5)
            try:
                _, jobs = service.prepare_campaign_execution(campaign.id, "admin")
                return ("execute", [job.id for job in jobs])
            except ValueError as error:
                return ("execute_error", str(error))

    def cancel_request():
        with built_service(integration_settings) as service:
            barrier.wait(timeout=5)
            try:
                canceled = service.cancel_campaign(campaign.id, "admin")
                return ("cancel", canceled.status)
            except ValueError as error:
                return ("cancel_error", str(error))

    with ThreadPoolExecutor(max_workers=2) as executor:
        execute_future = executor.submit(execute_request)
        cancel_future = executor.submit(cancel_request)
        results = [execute_future.result(), cancel_future.result()]

    jobs = [
        job
        for job in runtime.repository.list_jobs()
        if job.campaign_id == campaign.id and job.job_type == "remediation"
    ]
    final = runtime.service.get_campaign(campaign.id)

    assert {kind for kind, _ in results} <= {
        "execute",
        "execute_error",
        "cancel",
        "cancel_error",
    }
    assert len(jobs) <= 1
    assert all(job.status == "canceled" for job in jobs)
    assert final.status == "canceled"
    assert final.hosts[0].state == "canceled"


@pytest.mark.asyncio
async def test_campaign_cancel_does_not_overwrite_a_concurrent_worker_claim(
    integration_settings,
    integration_database_url: str,
    runtime,
):
    host = runtime.service.create_host(host_input("web-1"))
    campaign = await campaign_with_proposals(runtime.service, host)
    campaign = approve_host(runtime.service, campaign, host)
    _, jobs = runtime.service.prepare_campaign_execution(campaign.id, "admin")
    job = jobs[0]
    claim_started = Event()
    cancel_started = Event()
    release_commit = Event()
    claimed_at = utc_now()

    def claim_job_in_transaction():
        worker_repository = SqlRepository(integration_database_url)
        try:
            with worker_repository.Session.begin() as session:
                row = session.scalar(
                    select(JobRecord)
                    .where(JobRecord.id == job.id)
                    .with_for_update()
                )
                claimed = worker_repository._job_from_row(row)
                claimed.status = "running"
                claimed.started_at = claimed.started_at or claimed_at
                claimed.attempts += 1
                claimed.lease_owner = "worker-1"
                claimed.lease_expires_at = claimed_at + timedelta(seconds=60)
                claimed.heartbeat_at = claimed_at
                claimed.completed_at = None
                claimed.error = None
                claimed.updated_at = claimed_at
                for key, value in worker_repository._job_values(claimed).items():
                    setattr(row, key, value)
                claim_started.set()
                release_commit.wait(timeout=5)
            return True
        finally:
            worker_repository.engine.dispose()

    def cancel_request():
        with built_service(integration_settings) as service:
            claim_started.wait(timeout=5)
            cancel_started.set()
            return service.cancel_campaign(campaign.id, "admin")

    with ThreadPoolExecutor(max_workers=2) as executor:
        claim_future = executor.submit(claim_job_in_transaction)
        cancel_future = executor.submit(cancel_request)
        claim_started.wait(timeout=5)
        cancel_started.wait(timeout=5)
        sleep(0.1)
        release_commit.set()
        assert claim_future.result() is True
        canceled = cancel_future.result()

    final_job = runtime.repository.get_job(job.id)
    final_campaign = runtime.service.get_campaign(campaign.id)

    assert canceled.status == "cancelling"
    assert final_job is not None
    assert final_job.status == "running"
    assert final_job.lease_owner == "worker-1"
    assert final_campaign.status == "cancelling"
    assert final_campaign.hosts[0].state == "running"
