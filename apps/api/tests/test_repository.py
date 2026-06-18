from datetime import timedelta

from sysadmin_api.models import DurableJob, Severity, StructuredLogEvent, utc_now
from sysadmin_api.repository import SqlRepository


def test_sql_repository_claims_a_durable_job_once(tmp_path):
    repository = SqlRepository(
        "sqlite:///%s" % (tmp_path / "repository.db"),
        create_schema=True,
    )
    now = utc_now()
    job = DurableJob(
        id="job-1",
        job_type="scan",
        status="queued",
        host_id="host-1",
        scan_id="scan-1",
        idempotency_key="scan:host-1",
        created_at=now,
        updated_at=now,
    )
    repository.save_job(job)

    claimed = repository.claim_job(job.id, now)
    duplicate = repository.claim_job(job.id, now)

    assert claimed is not None
    assert claimed.status == "running"
    assert claimed.attempts == 1
    assert duplicate is None
    assert repository.get_job(job.id).status == "running"


def test_sql_repository_purges_only_expired_logs(tmp_path):
    repository = SqlRepository(
        "sqlite:///%s" % (tmp_path / "logs.db"),
        create_schema=True,
    )
    now = utc_now()
    repository.save_log_events(
        [
            StructuredLogEvent(
                id="old-log",
                timestamp=now - timedelta(days=91),
                event_type="test",
                evidence_category="test",
                severity=Severity.INFO,
                status="succeeded",
            ),
            StructuredLogEvent(
                id="current-log",
                timestamp=now - timedelta(days=89),
                event_type="test",
                evidence_category="test",
                severity=Severity.INFO,
                status="succeeded",
            ),
        ]
    )

    deleted = repository.purge_logs_before(now - timedelta(days=90))

    assert deleted == 1
    assert repository.get_log_event("old-log") is None
    assert repository.get_log_event("current-log") is not None
