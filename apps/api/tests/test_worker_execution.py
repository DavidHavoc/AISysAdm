import asyncio
from datetime import timedelta

import pytest
from fastapi.testclient import TestClient

from sysadmin_api.collector import DemoCollector
from sysadmin_api.config import BEAT_HEALTH_KEY, WORKER_HEALTH_KEY
from sysadmin_api.main import create_app
from sysadmin_api.models import ApprovalRequest, DurableJob, HostInput, ScanRequest, utc_now
from sysadmin_api.repository import InMemoryRepository
from sysadmin_api.runtime import build_runtime


def job(job_id: str = "job-1", max_attempts: int = 3) -> DurableJob:
    now = utc_now()
    return DurableJob(
        id=job_id,
        job_type="scan",
        status="queued",
        host_id="host-1",
        scan_id="scan-1",
        idempotency_key="scan:%s" % job_id,
        max_attempts=max_attempts,
        created_at=now,
        updated_at=now,
    )


def host_input() -> HostInput:
    return HostInput(
        name="worker-test",
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


def test_expired_lease_can_be_claimed_by_another_worker():
    repository = InMemoryRepository()
    queued = job()
    repository.save_job(queued)
    claimed_at = utc_now()

    first = repository.claim_job(
        queued.id,
        "worker-1",
        claimed_at,
        claimed_at + timedelta(seconds=10),
    )
    duplicate = repository.claim_job(
        queued.id,
        "worker-2",
        claimed_at + timedelta(seconds=5),
        claimed_at + timedelta(seconds=15),
    )
    recovered = repository.claim_job(
        queued.id,
        "worker-2",
        claimed_at + timedelta(seconds=11),
        claimed_at + timedelta(seconds=21),
    )

    assert first is not None
    assert duplicate is None
    assert recovered is not None
    assert recovered.lease_owner == "worker-2"
    assert recovered.attempts == 2
    assert recovered.last_failure.category == "worker_lease_expired"


def test_heartbeat_extends_lease_and_blocks_reclaim():
    repository = InMemoryRepository()
    queued = job()
    repository.save_job(queued)
    claimed_at = utc_now()
    repository.claim_job(
        queued.id,
        "worker-1",
        claimed_at,
        claimed_at + timedelta(seconds=10),
    )

    heartbeat_at = claimed_at + timedelta(seconds=5)
    heartbeat = repository.heartbeat_job(
        queued.id,
        "worker-1",
        heartbeat_at,
        heartbeat_at + timedelta(seconds=10),
    )
    duplicate = repository.claim_job(
        queued.id,
        "worker-2",
        claimed_at + timedelta(seconds=11),
        claimed_at + timedelta(seconds=21),
    )

    assert heartbeat is not None
    assert heartbeat.heartbeat_at == heartbeat_at
    assert heartbeat.lease_expires_at == heartbeat_at + timedelta(seconds=10)
    assert duplicate is None


def test_stale_worker_cannot_save_after_lease_reclaim():
    repository = InMemoryRepository()
    queued = job()
    repository.save_job(queued)
    claimed_at = utc_now()
    stale = repository.claim_job(
        queued.id,
        "worker-1",
        claimed_at,
        claimed_at + timedelta(seconds=5),
    )
    replacement = repository.claim_job(
        queued.id,
        "worker-2",
        claimed_at + timedelta(seconds=6),
        claimed_at + timedelta(seconds=11),
    )
    stale.status = "completed"
    stale.lease_owner = None

    saved = repository.save_job(stale, lease_owner="worker-1")

    assert replacement is not None
    assert saved is None
    assert repository.get_job(queued.id).lease_owner == "worker-2"


@pytest.mark.asyncio
async def test_worker_crash_is_recovered_and_job_completes(service):
    host = service.create_host(host_input())
    queued = service.create_scan_job(ScanRequest(host_id=host.id))
    claimed_at = utc_now()
    service.repository.claim_job(
        queued.id,
        "crashed-worker",
        claimed_at,
        claimed_at + timedelta(seconds=5),
    )

    recovered = service.recover_expired_jobs(
        claimed_at + timedelta(seconds=6)
    )
    completed = await service.process_scan(queued.id, "replacement-worker")

    assert [item.id for item in recovered] == [queued.id]
    assert completed.status == "completed"
    assert completed.attempts == 2
    assert completed.last_failure.category == "worker_lease_expired"


@pytest.mark.asyncio
async def test_retry_exhaustion_reaches_terminal_failure(service):
    class FailingCollector(DemoCollector):
        calls = 0

        async def collect(self, host, job_id="", scan_id=""):
            self.calls += 1
            raise RuntimeError("temporary collection failure")

    collector = FailingCollector()
    service.collector = collector
    host = service.create_host(host_input())
    queued = service.create_scan_job(ScanRequest(host_id=host.id))

    first = await service.process_scan(queued.id, "worker-1")
    second = await service.process_scan(queued.id, "worker-2")
    third = await service.process_scan(queued.id, "worker-3")

    assert first.status == "queued"
    assert second.status == "queued"
    assert third.status == "failed"
    assert third.attempts == third.max_attempts == 3
    assert third.last_failure.retryable is False
    assert collector.calls == 3


@pytest.mark.asyncio
async def test_approval_failure_is_terminal_and_not_retried(service):
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
    queued = service.prepare_remediation_job(remediation.id, "admin")
    remediation = service.repository.get_remediation(remediation.id)
    remediation.approval_state = "pending"
    service.repository.save_remediation(remediation)

    failed = await service.process_remediation(queued.id, "worker-1")
    duplicate = await service.process_remediation(queued.id, "worker-2")

    assert failed.status == "failed"
    assert failed.attempts == 1
    assert failed.last_failure.category == "approval_validation"
    assert failed.last_failure.retryable is False
    assert duplicate.attempts == 1


@pytest.mark.asyncio
async def test_duplicate_delivery_executes_only_one_worker(service):
    class BlockingCollector(DemoCollector):
        calls = 0

        async def collect(self, host, job_id="", scan_id=""):
            self.calls += 1
            await asyncio.sleep(0.02)
            return await super().collect(host, job_id, scan_id)

    collector = BlockingCollector()
    service.collector = collector
    host = service.create_host(host_input())
    queued = service.create_scan_job(ScanRequest(host_id=host.id))

    await asyncio.gather(
        service.process_scan(queued.id, "worker-1"),
        service.process_scan(queued.id, "worker-2"),
    )

    assert collector.calls == 1
    assert service.get_job(queued.id).status == "completed"


def test_operational_health_reports_worker_and_beat_freshness(settings):
    class HealthRedis:
        values = {}

        def ping(self):
            return True

        def get(self, key):
            return self.values.get(key)

    runtime = build_runtime(settings, repository=InMemoryRepository())
    runtime.redis_client = HealthRedis()
    client = TestClient(create_app(runtime=runtime))

    unhealthy = client.get("/health/ops")
    runtime.redis_client.values = {
        WORKER_HEALTH_KEY: "2026-06-18T12:00:00+00:00",
        BEAT_HEALTH_KEY: "2026-06-18T12:00:00+00:00",
    }
    healthy = client.get("/health/ops")

    assert unhealthy.status_code == 503
    assert unhealthy.json()["detail"]["checks"]["worker"]["healthy"] is False
    assert unhealthy.json()["detail"]["checks"]["celeryBeat"]["healthy"] is False
    assert healthy.status_code == 200
    assert healthy.json()["checks"]["worker"]["healthy"] is True
    assert healthy.json()["checks"]["celeryBeat"]["healthy"] is True
