from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from datetime import timedelta
from inspect import signature
from threading import Barrier

import pytest
from alembic.config import Config
from alembic.script import ScriptDirectory
from celery.contrib.testing.worker import start_worker
from fastapi.testclient import TestClient
from redis import Redis
from sqlalchemy import inspect, text
from sqlalchemy.exc import IntegrityError

from sysadmin_api.database import Base
from sysadmin_api.main import create_app
from sysadmin_api.models import DurableJob, Severity, StructuredLogEvent, utc_now
from sysadmin_api.repository import SqlRepository
from sysadmin_api.runtime import get_runtime


pytestmark = pytest.mark.integration


def durable_job(job_id: str, idempotency_key: str) -> DurableJob:
    now = utc_now()
    return DurableJob(
        id=job_id,
        job_type="scan",
        status="queued",
        host_id="host-1",
        scan_id="scan-1",
        idempotency_key=idempotency_key,
        created_at=now,
        updated_at=now,
    )


def claim_job(repository: SqlRepository, job_id: str, worker_id: str):
    started_at = utc_now()
    if "lease_owner" in signature(repository.claim_job).parameters:
        return repository.claim_job(
            job_id,
            worker_id,
            started_at,
            started_at + timedelta(seconds=60),
        )
    return repository.claim_job(job_id, started_at)


def test_fresh_database_is_at_alembic_head(repository: SqlRepository):
    alembic_config = Config("alembic.ini")
    expected_revision = ScriptDirectory.from_config(alembic_config).get_current_head()
    with repository.engine.connect() as connection:
        revision = connection.scalar(text("SELECT version_num FROM alembic_version"))

    assert revision == expected_revision
    assert set(inspect(repository.engine).get_table_names()) >= {
        table.name for table in Base.metadata.sorted_tables
    }


def test_atomic_job_claim_allows_only_one_claim(repository: SqlRepository):
    job = durable_job("job-atomic", "scan:atomic")
    repository.save_job(job)

    claimed = claim_job(repository, job.id, "worker-1")
    duplicate = claim_job(repository, job.id, "worker-2")

    assert claimed is not None
    assert claimed.status == "running"
    if hasattr(claimed, "lease_owner"):
        assert claimed.lease_owner == "worker-1"
    assert duplicate is None
    assert repository.get_job(job.id).attempts == 1


def test_concurrent_workers_claim_one_job(
    repository: SqlRepository,
    integration_database_url: str,
):
    job = durable_job("job-concurrent", "scan:concurrent")
    repository.save_job(job)
    worker_count = 8
    barrier = Barrier(worker_count)

    def claim_from_worker():
        worker_repository = SqlRepository(integration_database_url)
        try:
            barrier.wait(timeout=5)
            return claim_job(
                worker_repository,
                job.id,
                "worker-%s" % id(worker_repository),
            )
        finally:
            worker_repository.engine.dispose()

    with ThreadPoolExecutor(max_workers=worker_count) as executor:
        claims = list(executor.map(lambda _: claim_from_worker(), range(worker_count)))

    successful = [claim for claim in claims if claim is not None]
    assert len(successful) == 1
    assert successful[0].attempts == 1
    assert repository.get_job(job.id).status == "running"


def test_failed_transaction_rolls_back_and_connection_recovers(
    repository: SqlRepository,
):
    first = durable_job("job-first", "scan:duplicate")
    duplicate = durable_job("job-duplicate", "scan:duplicate")
    repository.save_job(first)

    with pytest.raises(IntegrityError):
        repository.save_job(duplicate)

    assert repository.get_job(first.id) is not None
    assert repository.get_job(duplicate.id) is None
    assert repository.healthcheck() is True


def test_readiness_succeeds_with_postgresql_and_redis(runtime):
    response = TestClient(create_app(runtime=runtime)).get("/health/ready")

    assert response.status_code == 200
    assert response.json()["checks"]["database"] is True
    assert response.json()["checks"]["redis"] is True


def test_readiness_reports_redis_failure(runtime):
    failed_redis = Redis.from_url(
        "redis://127.0.0.1:1/15",
        decode_responses=True,
        socket_connect_timeout=0.2,
        socket_timeout=0.2,
    )
    failed_runtime = replace(runtime, redis_client=failed_redis)
    try:
        response = TestClient(create_app(runtime=failed_runtime)).get("/health/ready")
    finally:
        failed_redis.close()

    assert response.status_code == 503
    assert response.json()["detail"]["database"] is True
    assert response.json()["detail"]["redis"] is False


def test_readiness_reports_postgresql_failure(runtime):
    failed_repository = SqlRepository(
        "postgresql+psycopg://sysadmin@127.0.0.1:1/sysadmin_integration"
        "?connect_timeout=1"
    )
    failed_runtime = replace(runtime, repository=failed_repository)
    try:
        response = TestClient(create_app(runtime=failed_runtime)).get("/health/ready")
    finally:
        failed_repository.engine.dispose()

    assert response.status_code == 503
    assert response.json()["detail"]["database"] is False
    assert response.json()["detail"]["redis"] is True


def test_log_retention_deletes_only_expired_events(runtime):
    now = utc_now()
    runtime.repository.save_log_events(
        [
            StructuredLogEvent(
                id="expired-log",
                timestamp=now - timedelta(days=91),
                event_type="test",
                evidence_category="test",
                severity=Severity.INFO,
                status="succeeded",
            ),
            StructuredLogEvent(
                id="retained-log",
                timestamp=now - timedelta(days=89),
                event_type="test",
                evidence_category="test",
                severity=Severity.INFO,
                status="succeeded",
            ),
        ]
    )

    deleted = runtime.service.purge_expired_logs()

    assert deleted == 1
    assert runtime.repository.get_log_event("expired-log") is None
    assert runtime.repository.get_log_event("retained-log") is not None
    assert any(
        event.action == "logs.retention_purge"
        and event.details["deleted"] == 1
        for event in runtime.repository.list_audits()
    )


def test_celery_publishes_and_executes_task_through_redis(
    repository: SqlRepository,
    redis_client: Redis,
):
    now = utc_now()
    repository.save_log_events(
        [
            StructuredLogEvent(
                id="celery-expired-log",
                timestamp=now - timedelta(days=91),
                event_type="test",
                evidence_category="test",
                severity=Severity.INFO,
                status="succeeded",
            )
        ]
    )

    from sysadmin_api.tasks import celery_app, purge_logs

    get_runtime.cache_clear()
    celery_app.conf.task_always_eager = False
    with start_worker(
        celery_app,
        concurrency=1,
        pool="solo",
        perform_ping_check=False,
        shutdown_timeout=15,
    ):
        result = purge_logs.delay()
        payload = result.get(timeout=15)

    get_runtime.cache_clear()
    assert result.id
    assert payload == {"deleted": 1}
    assert repository.get_log_event("celery-expired-log") is None
