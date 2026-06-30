from datetime import timedelta

from sysadmin_api.models import (
    CampaignHostPlan,
    CampaignStatus,
    DurableJob,
    PatchCampaign,
    Severity,
    StructuredLogEvent,
    utc_now,
)
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

    claimed = repository.claim_job(
        job.id,
        "worker-1",
        now,
        now + timedelta(seconds=60),
    )
    duplicate = repository.claim_job(
        job.id,
        "worker-2",
        now,
        now + timedelta(seconds=60),
    )

    assert claimed is not None
    assert claimed.status == "running"
    assert claimed.attempts == 1
    assert duplicate is None
    assert repository.get_job(job.id).status == "running"


def test_sql_recovery_preserves_the_interrupted_execution_phase(tmp_path):
    repository = SqlRepository(
        "sqlite:///%s" % (tmp_path / "recovery.db"),
        create_schema=True,
    )
    now = utc_now()
    job = DurableJob(
        id="job-remediation-recovery",
        job_type="remediation",
        status="queued",
        host_id="host-1",
        scan_id="scan-1",
        remediation_id="remediation-1",
        idempotency_key="remediation:recovery",
        created_at=now,
        updated_at=now,
    )
    repository.save_job(job)
    claimed = repository.claim_job(
        job.id,
        "worker-1",
        now,
        now + timedelta(seconds=5),
    )
    claimed.current_phase = "ansible_execution"
    claimed.updated_at = now + timedelta(seconds=1)
    repository.save_job(claimed, lease_owner="worker-1")

    recovered, exhausted = repository.recover_expired_jobs(
        now + timedelta(seconds=6)
    )

    assert exhausted == []
    assert [item.id for item in recovered] == [job.id]
    assert recovered[0].current_phase == "retry_scheduled"
    assert recovered[0].result["recovered_from_phase"] == "ansible_execution"


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


def test_sql_repository_persists_campaign_host_plan_binding(tmp_path):
    repository = SqlRepository(
        "sqlite:///%s" % (tmp_path / "campaigns.db"),
        create_schema=True,
    )
    now = utc_now()
    host_plan = CampaignHostPlan(
        id="campaign-host-1",
        campaign_id="campaign-1",
        host_id="host-1",
        hostname="web-1",
        state="awaiting_approval",
        remediation_id="remediation-1",
        plan_version=7,
        plan_hash="a" * 64,
        created_at=now,
        updated_at=now,
    )
    campaign = PatchCampaign(
        id="campaign-1",
        name="Production wave",
        host_ids=["host-1"],
        remediation_ids=["remediation-1"],
        hosts=[host_plan],
        status=CampaignStatus.AWAITING_APPROVAL,
        batch_size=1,
        total_batches=1,
        created_at=now,
        updated_at=now,
    )

    repository.save_campaign(campaign)
    loaded = repository.get_campaign(campaign.id)

    assert loaded is not None
    assert loaded.hosts[0].plan_version == 7
    assert loaded.hosts[0].plan_hash == "a" * 64
