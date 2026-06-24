from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta
from threading import Barrier

import pytest
from sqlalchemy import text

from sysadmin_api.collector import DemoCollector
from sysadmin_api.models import ApprovalRequest, DurableJob, HostInput, ScanRequest, utc_now
from sysadmin_api.repository import SqlRepository


pytestmark = pytest.mark.integration


def durable_job(
    job_id: str,
    idempotency_key: str,
    max_attempts: int = 3,
) -> DurableJob:
    now = utc_now()
    return DurableJob(
        id=job_id,
        job_type="scan",
        status="queued",
        host_id="host-1",
        scan_id="scan-1",
        idempotency_key=idempotency_key,
        max_attempts=max_attempts,
        created_at=now,
        updated_at=now,
    )


def host_input(name: str = "worker-test") -> HostInput:
    return HostInput(
        name=name,
        address="10.0.0.50",
        username="ubuntu",
    )


async def completed_scan(service, host):
    queued = service.create_scan_job(ScanRequest(host_id=host.id))
    completed = await service.process_scan(queued.id)
    return service.get_scan(completed.scan_id)


def approval_for(host, remediation) -> ApprovalRequest:
    return ApprovalRequest(
        plan_version=remediation.plan_version,
        plan_hash=remediation.plan_hash,
        hostname_confirmation=host.name,
    )


def test_job_decisions_prefer_indexed_columns_over_stale_payload(repository):
    job = durable_job("job-stale-payload", "scan:stale-payload")
    repository.save_job(job)
    claimed_at = utc_now()
    claimed = repository.claim_job(
        job.id,
        "worker-1",
        claimed_at,
        claimed_at + timedelta(seconds=60),
    )

    with repository.engine.begin() as connection:
        connection.execute(
            text(
                "UPDATE jobs "
                "SET payload = jsonb_set("
                "jsonb_set(payload::jsonb, '{status}', '\"queued\"'::jsonb), "
                "'{attempts}', '0'::jsonb"
                ") "
                "WHERE id = :job_id"
            ),
            {"job_id": job.id},
        )

    duplicate = repository.claim_job(
        job.id,
        "worker-2",
        claimed_at + timedelta(seconds=1),
        claimed_at + timedelta(seconds=61),
    )
    loaded = repository.get_job(job.id)

    assert claimed is not None
    assert duplicate is None
    assert loaded is not None
    assert loaded.status == "running"
    assert loaded.attempts == 1


def test_postgresql_lease_expiration_allows_reclaim(repository):
    job = durable_job("job-lease-expired", "scan:lease-expired")
    repository.save_job(job)
    claimed_at = utc_now()

    first = repository.claim_job(
        job.id,
        "worker-1",
        claimed_at,
        claimed_at + timedelta(seconds=10),
    )
    duplicate = repository.claim_job(
        job.id,
        "worker-2",
        claimed_at + timedelta(seconds=5),
        claimed_at + timedelta(seconds=15),
    )
    reclaimed = repository.claim_job(
        job.id,
        "worker-2",
        claimed_at + timedelta(seconds=11),
        claimed_at + timedelta(seconds=21),
    )

    assert first is not None
    assert duplicate is None
    assert reclaimed is not None
    assert reclaimed.lease_owner == "worker-2"
    assert reclaimed.attempts == 2
    assert reclaimed.last_failure is not None
    assert reclaimed.last_failure.category == "worker_lease_expired"


def test_postgresql_heartbeat_extends_lease(repository):
    job = durable_job("job-heartbeat", "scan:heartbeat")
    repository.save_job(job)
    claimed_at = utc_now()
    repository.claim_job(
        job.id,
        "worker-1",
        claimed_at,
        claimed_at + timedelta(seconds=10),
    )

    heartbeat_at = claimed_at + timedelta(seconds=5)
    heartbeat = repository.heartbeat_job(
        job.id,
        "worker-1",
        heartbeat_at,
        heartbeat_at + timedelta(seconds=10),
    )
    duplicate = repository.claim_job(
        job.id,
        "worker-2",
        claimed_at + timedelta(seconds=11),
        claimed_at + timedelta(seconds=21),
    )

    assert heartbeat is not None
    assert heartbeat.heartbeat_at == heartbeat_at
    assert heartbeat.lease_expires_at == heartbeat_at + timedelta(seconds=10)
    assert duplicate is None


def test_postgresql_rejects_stale_worker_write_after_lease_expiry(repository):
    job = durable_job("job-stale-write", "scan:stale-write")
    repository.save_job(job)
    claimed_at = utc_now()
    stale = repository.claim_job(
        job.id,
        "worker-1",
        claimed_at,
        claimed_at + timedelta(seconds=5),
    )
    assert stale is not None

    stale.status = "completed"
    stale.current_phase = "completed"
    stale.completed_at = claimed_at + timedelta(seconds=6)
    stale.updated_at = claimed_at + timedelta(seconds=6)
    stale.lease_owner = None
    stale.lease_expires_at = None

    saved = repository.save_job(stale, lease_owner="worker-1")
    current = repository.get_job(job.id)

    assert saved is None
    assert current is not None
    assert current.status == "running"
    assert current.lease_owner == "worker-1"


def test_postgresql_rejects_stale_worker_after_reclaim(repository):
    job = durable_job("job-stale-reclaim", "scan:stale-reclaim")
    repository.save_job(job)
    claimed_at = utc_now()
    stale = repository.claim_job(
        job.id,
        "worker-1",
        claimed_at,
        claimed_at + timedelta(seconds=5),
    )
    replacement = repository.claim_job(
        job.id,
        "worker-2",
        claimed_at + timedelta(seconds=6),
        claimed_at + timedelta(seconds=16),
    )
    assert stale is not None
    assert replacement is not None

    stale.status = "completed"
    stale.current_phase = "completed"
    stale.completed_at = claimed_at + timedelta(seconds=7)
    stale.updated_at = claimed_at + timedelta(seconds=7)
    stale.lease_owner = None
    stale.lease_expires_at = None

    saved = repository.save_job(stale, lease_owner="worker-1")
    current = repository.get_job(job.id)

    assert saved is None
    assert current is not None
    assert current.status == "running"
    assert current.lease_owner == "worker-2"
    assert current.attempts == 2


def test_recovery_schedulers_only_recover_one_expired_job(
    repository,
    integration_database_url: str,
):
    job = durable_job("job-recover-once", "scan:recover-once")
    repository.save_job(job)
    claimed_at = utc_now()
    repository.claim_job(
        job.id,
        "worker-1",
        claimed_at,
        claimed_at + timedelta(seconds=5),
    )
    recovered_at = claimed_at + timedelta(seconds=6)
    barrier = Barrier(2)

    def recover_from_scheduler():
        worker_repository = SqlRepository(integration_database_url)
        try:
            barrier.wait(timeout=5)
            recovered, exhausted = worker_repository.recover_expired_jobs(recovered_at)
            return [item.id for item in recovered], [item.id for item in exhausted]
        finally:
            worker_repository.engine.dispose()

    with ThreadPoolExecutor(max_workers=2) as executor:
        results = list(executor.map(lambda _: recover_from_scheduler(), range(2)))

    recovered_ids = [job_id for recovered, _ in results for job_id in recovered]
    exhausted_ids = [job_id for _, exhausted in results for job_id in exhausted]
    claimed = repository.claim_job(
        job.id,
        "worker-2",
        recovered_at,
        recovered_at + timedelta(seconds=60),
    )
    duplicate = repository.claim_job(
        job.id,
        "worker-3",
        recovered_at,
        recovered_at + timedelta(seconds=60),
    )

    assert recovered_ids == [job.id]
    assert exhausted_ids == []
    assert claimed is not None
    assert duplicate is None


def test_service_recovers_expired_jobs_and_requeues(runtime):
    now = utc_now()
    job = durable_job("job-service-recovery", "scan:service-recovery")
    runtime.repository.save_job(job)
    runtime.repository.claim_job(
        job.id,
        "crashed-worker",
        now,
        now + timedelta(seconds=5),
    )

    recovered = runtime.service.recover_expired_jobs(now + timedelta(seconds=6))
    current = runtime.repository.get_job(job.id)

    assert [item.id for item in recovered] == [job.id]
    assert current is not None
    assert current.status == "queued"
    assert current.current_phase == "retry_scheduled"
    assert current.last_failure is not None
    assert current.last_failure.category == "worker_lease_expired"


@pytest.mark.asyncio
async def test_retry_exhaustion_stays_bounded_on_postgresql(runtime):
    class FailingCollector(DemoCollector):
        calls = 0

        async def collect(self, host, job_id="", scan_id=""):
            self.calls += 1
            raise RuntimeError("temporary collection failure")

    collector = FailingCollector()
    runtime.service.collector = collector
    host = runtime.service.create_host(host_input())
    queued = runtime.service.create_scan_job(ScanRequest(host_id=host.id))

    first = await runtime.service.process_scan(queued.id, "worker-1")
    second = await runtime.service.process_scan(queued.id, "worker-2")
    third = await runtime.service.process_scan(queued.id, "worker-3")

    assert first.status == "queued"
    assert second.status == "queued"
    assert third.status == "failed"
    assert third.attempts == third.max_attempts == 3
    assert third.last_failure is not None
    assert third.last_failure.retryable is False
    assert collector.calls == 3


@pytest.mark.asyncio
async def test_approval_validation_failure_does_not_retry_on_postgresql(runtime):
    host = runtime.service.create_host(host_input())
    scan = await completed_scan(runtime.service, host)
    remediation = runtime.repository.get_remediation(scan.remediation_ids[0])
    runtime.service.approve_remediation_plan(
        remediation.id,
        approval_for(host, remediation),
        "admin",
    )
    runtime.service.approve_remediation_reboot(
        remediation.id,
        approval_for(host, remediation),
        "admin",
    )
    queued = runtime.service.prepare_remediation_job(remediation.id, "admin")
    remediation = runtime.repository.get_remediation(remediation.id)
    remediation.approval_state = "pending"
    runtime.repository.save_remediation(remediation)

    failed = await runtime.service.process_remediation(queued.id, "worker-1")
    duplicate = await runtime.service.process_remediation(queued.id, "worker-2")

    assert failed.status == "failed"
    assert failed.attempts == 1
    assert failed.last_failure is not None
    assert failed.last_failure.category == "approval_validation"
    assert failed.last_failure.retryable is False
    assert duplicate.attempts == 1


@pytest.mark.asyncio
async def test_safety_validation_failure_does_not_retry_on_postgresql(runtime):
    class DriftCollector(DemoCollector):
        async def collect(self, host, job_id="", scan_id=""):
            collected = await super().collect(host, job_id, scan_id)
            collected.snapshot.package_summary.reboot_required_now = (
                not collected.snapshot.package_summary.reboot_required_now
            )
            return collected

    host = runtime.service.create_host(host_input("drift-test"))
    scan = await completed_scan(runtime.service, host)
    remediation = runtime.repository.get_remediation(scan.remediation_ids[0])
    runtime.service.approve_remediation_plan(
        remediation.id,
        approval_for(host, remediation),
        "admin",
    )
    runtime.service.approve_remediation_reboot(
        remediation.id,
        approval_for(host, remediation),
        "admin",
    )
    queued = runtime.service.prepare_remediation_job(remediation.id, "admin")
    runtime.service.collector = DriftCollector()

    failed = await runtime.service.process_remediation(queued.id, "worker-1")
    duplicate = await runtime.service.process_remediation(queued.id, "worker-2")

    assert failed.status == "failed"
    assert failed.attempts == 1
    assert failed.last_failure is not None
    assert failed.last_failure.category == "safety_validation"
    assert failed.last_failure.retryable is False
    assert duplicate.attempts == 1
