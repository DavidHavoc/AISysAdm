from datetime import datetime, timedelta, timezone

import pytest

from sysadmin_api.collector import DemoCollector
from sysadmin_api.models import (
    AiDecision,
    ApprovalRequest,
    CampaignHostPlan,
    DurableJob,
    ExecutionResult,
    Host,
    HostInput,
    MaintenanceWindow,
    PatchCampaign,
    PatchPolicy,
    RebootAssessment,
    Remediation,
    RolloutPolicy,
    Severity,
    ScanRequest,
    utc_now,
)
from sysadmin_api.trusted_change import (
    GateCode,
    PostChangeAction,
    TrustedChangeGate,
)


def make_host(**overrides) -> Host:
    now = utc_now()
    values = {
        "id": "host-1",
        "name": "trusted-host",
        "address": "10.0.0.10",
        "username": "ubuntu",
        "patch_policy": PatchPolicy(),
        "created_at": now,
        "updated_at": now,
    }
    values.update(overrides)
    return Host(**values)


def make_remediation(host: Host, reboot_status: str = "unknown") -> Remediation:
    now = utc_now()
    remediation = Remediation(
        id="remediation-1",
        host_id=host.id,
        scan_id="scan-1",
        title="Patch trusted host",
        update_scope="security",
        risk_level=Severity.HIGH,
        ai_decision=AiDecision(
            update_scope="security",
            risk_level=Severity.HIGH,
            explanation="Verified package evidence supports the plan.",
            supporting_citations=["packageSummary.updates"],
            agent_assignments=[],
        ),
        reboot_assessment=RebootAssessment(
            status=reboot_status,
            rationale="Reboot state must be checked after patching.",
            evidence=[],
        ),
        rollout_policy=RolloutPolicy(
            strategy="one_at_a_time",
            batch_size=1,
            canary_count=1,
            rationale="Validate one host at a time.",
        ),
        execution_timing="immediate",
        created_at=now,
        updated_at=now,
    )
    remediation.plan_hash = TrustedChangeGate.plan_hash(remediation)
    return remediation


def request_for(host: Host, remediation: Remediation) -> ApprovalRequest:
    return ApprovalRequest(
        plan_version=remediation.plan_version,
        plan_hash=remediation.plan_hash,
        hostname_confirmation=host.name,
    )


def fully_approved(host: Host, reboot_status: str = "unknown") -> Remediation:
    remediation = make_remediation(host, reboot_status)
    approved = TrustedChangeGate.approve_plan(
        remediation,
        host,
        request_for(host, remediation),
        "admin",
        utc_now(),
    ).remediation
    if reboot_status != "not_expected":
        approved = TrustedChangeGate.approve_reboot(
            approved,
            host,
            request_for(host, approved),
            "admin",
            utc_now(),
        ).remediation
    return approved


def execution_job(remediation: Remediation, host: Host) -> DurableJob:
    now = utc_now()
    return DurableJob(
        id="job-1",
        job_type="remediation",
        status="queued",
        host_id=host.id,
        scan_id=remediation.scan_id,
        remediation_id=remediation.id,
        approved_plan_version=remediation.plan_version,
        approved_plan_hash=remediation.plan_hash,
        approval_scope=TrustedChangeGate.job_approval_scope(remediation),
        idempotency_key="remediation:1",
        created_at=now,
        updated_at=now,
    )


@pytest.mark.parametrize(
    ("field", "value", "code"),
    [
        ("plan_version", 99, GateCode.PLAN_VERSION_CHANGED),
        ("plan_hash", "stale-hash", GateCode.PLAN_HASH_CHANGED),
        ("hostname_confirmation", "wrong-host", GateCode.HOSTNAME_MISMATCH),
    ],
)
def test_approval_rejects_stale_binding_and_hostname(field, value, code):
    host = make_host()
    remediation = make_remediation(host)
    request = request_for(host, remediation).model_copy(update={field: value})

    decision = TrustedChangeGate.validate_approval_request(
        host,
        remediation,
        request,
    )

    assert decision.allowed is False
    assert decision.code == code


def test_changed_content_invalidates_exact_approval_binding():
    host = make_host()
    remediation = fully_approved(host)
    remediation.update_scope = "all"

    reconciliation = TrustedChangeGate.reconcile_plan(remediation, utc_now())

    assert reconciliation.changed is True
    assert reconciliation.content_changed is True
    assert reconciliation.decision.code == GateCode.PLAN_CONTENT_CHANGED
    assert reconciliation.remediation.plan_version == 2
    assert reconciliation.remediation.approval_state == "pending"
    assert reconciliation.remediation.reboot_approval_state == "pending"


def test_execution_rejects_changed_job_hash_and_version():
    host = make_host()
    remediation = fully_approved(host)
    job = execution_job(remediation, host)

    stale_version = TrustedChangeGate.execution_eligibility(
        remediation,
        host,
        job=job.model_copy(update={"approved_plan_version": 99}),
    )
    stale_hash = TrustedChangeGate.execution_eligibility(
        remediation,
        host,
        job=job.model_copy(update={"approved_plan_hash": "stale"}),
    )

    assert stale_version.code == GateCode.PLAN_VERSION_CHANGED
    assert stale_hash.code == GateCode.PLAN_HASH_CHANGED


def test_reboot_approval_is_separate_and_policy_can_deny_it():
    host = make_host()
    remediation = make_remediation(host)
    approved = TrustedChangeGate.approve_plan(
        remediation,
        host,
        request_for(host, remediation),
        "admin",
        utc_now(),
    ).remediation

    missing = TrustedChangeGate.execution_eligibility(approved, host)
    denied_host = host.model_copy(
        update={"patch_policy": PatchPolicy(reboot_policy="never")}
    )
    denied = TrustedChangeGate.approve_reboot(
        approved,
        denied_host,
        request_for(denied_host, approved),
        "admin",
        utc_now(),
    )

    assert missing.code == GateCode.REBOOT_APPROVAL_MISSING
    assert denied.decision.code == GateCode.REBOOT_POLICY_DENIED
    assert denied.remediation.reboot_approval_state == "blocked"
    assert denied.remediation.execution_state == "blocked"


@pytest.mark.asyncio
async def test_material_host_drift_is_denied():
    host = make_host()
    collected = await DemoCollector().collect(host)
    approved = collected.snapshot
    current = approved.model_copy(deep=True)
    current.package_summary.reboot_required_now = (
        not current.package_summary.reboot_required_now
    )

    decision = TrustedChangeGate.drift(approved, current)

    assert decision.code == GateCode.HOST_STATE_DRIFT
    assert decision.retryable is False


def test_duplicate_execution_and_maintenance_window_are_stable():
    host = make_host()
    remediation = fully_approved(host)
    job = execution_job(remediation, host)

    duplicate = TrustedChangeGate.duplicate_execution(job, "campaign-1")
    remediation.execution_timing = "maintenance_window"
    remediation.maintenance_window = MaintenanceWindow(
        timezone="UTC",
        weekdays=[0],
        start_time="02:00",
        duration_minutes=60,
    )
    closed = TrustedChangeGate.timing(
        remediation,
        datetime(2026, 6, 30, 3, 30, tzinfo=timezone.utc),
    )
    opened = TrustedChangeGate.timing(
        remediation,
        datetime(2026, 6, 29, 2, 30, tzinfo=timezone.utc),
    )

    assert duplicate.code == GateCode.DUPLICATE_EXECUTION
    assert closed.decision.code == GateCode.MAINTENANCE_WINDOW_CLOSED
    assert closed.job_status == "scheduled"
    assert opened.decision.allowed is True
    assert opened.job_status == "queued"


def test_snapshot_health_and_rollback_transitions_are_explicit():
    host = make_host(
        snapshot_platform="proxmox",
        snapshot_credential_id="credential-1",
        snapshot_target_id="vm-100",
    )
    remediation = fully_approved(host)
    remediation.pre_change_protection = {
        "supported": True,
        "status": "configured",
    }
    remediation.plan_hash = TrustedChangeGate.plan_hash(remediation)

    required = TrustedChangeGate.snapshot_requirement(host, remediation)
    create_failed = TrustedChangeGate.snapshot_creation(False, "provider failed")
    unhealthy = TrustedChangeGate.post_change_health(False)
    rolled_back = TrustedChangeGate.rollback_result(True)
    rollback_failed = TrustedChangeGate.rollback_result(False)

    assert required.required is True
    assert required.decision.allowed is True
    assert create_failed.code == GateCode.SNAPSHOT_CREATE_FAILED
    assert unhealthy.action == PostChangeAction.ROLLBACK
    assert unhealthy.snapshot_state == "rollback_started"
    assert rolled_back.snapshot_state == "rolled_back"
    assert rolled_back.remediation_state == "blocked"
    assert rollback_failed.snapshot_state == "rollback_failed"
    assert rollback_failed.decision.code == GateCode.ROLLBACK_FAILED


def test_snapshot_configuration_fails_closed():
    host = make_host(snapshot_platform="none")
    remediation = fully_approved(host)
    remediation.pre_change_protection = {
        "supported": True,
        "status": "configured",
    }

    decision = TrustedChangeGate.snapshot_requirement(host, remediation)

    assert decision.required is True
    assert decision.decision.code == GateCode.SNAPSHOT_CONFIGURATION_INCOMPLETE


def test_terminal_outcome_and_retry_classification_are_typed():
    transient = ExecutionResult(
        success=False,
        summary="Temporary package mirror failure",
        changed=False,
        reboot_performed=False,
        phases=[],
    )
    changed = transient.model_copy(
        update={"summary": "Upgrade failed", "changed": True}
    )
    success = transient.model_copy(
        update={"success": True, "summary": "Validation passed"}
    )

    retry = TrustedChangeGate.execution_outcome(transient)
    terminal = TrustedChangeGate.execution_outcome(changed)
    completed = TrustedChangeGate.execution_outcome(success)

    assert retry.decision.retryable is True
    assert retry.job_status == "queued"
    assert terminal.decision.code == GateCode.EXECUTION_CHANGED_FAILED
    assert terminal.decision.retryable is False
    assert completed.remediation_state == "succeeded"
    assert completed.job_status == "completed"


def test_stale_worker_recovery_blocks_uncertain_mutation_but_allows_preflight():
    host = make_host()
    remediation = fully_approved(host)
    job = execution_job(remediation, host)

    uncertain = TrustedChangeGate.stale_recovery(
        job.model_copy(update={"current_phase": "ansible_execution"}),
        exhausted=False,
    )
    safe = TrustedChangeGate.stale_recovery(
        job.model_copy(update={"current_phase": "state_drift_check"}),
        exhausted=False,
    )
    exhausted_uncertain = TrustedChangeGate.stale_recovery(
        job.model_copy(
            update={
                "current_phase": "failed",
                "result": {"recovered_from_phase": "ansible_execution"},
            }
        ),
        exhausted=True,
    )

    assert uncertain.decision.code == GateCode.STALE_EXECUTION_UNCERTAIN
    assert uncertain.remediation_state == "blocked"
    assert uncertain.dispatch is False
    assert safe.dispatch is True
    assert safe.remediation_state == "queued"
    assert exhausted_uncertain.remediation_state == "blocked"


def test_campaign_batch_fails_closed_when_plan_changes():
    host = make_host()
    remediation = fully_approved(host)
    now = utc_now()
    host_plan = CampaignHostPlan(
        id="campaign-host-1",
        campaign_id="campaign-1",
        host_id=host.id,
        hostname=host.name,
        state="approved",
        remediation_id=remediation.id,
        plan_version=remediation.plan_version,
        plan_hash=remediation.plan_hash,
        created_at=now,
        updated_at=now,
    )
    campaign = PatchCampaign(
        id="campaign-1",
        name="Trusted wave",
        host_ids=[host.id],
        remediation_ids=[remediation.id],
        hosts=[host_plan],
        status="ready",
        batch_size=1,
        total_batches=1,
        created_at=now,
        updated_at=now,
    )
    remediation.update_scope = "all"

    batch = TrustedChangeGate.campaign_batch(
        campaign,
        {remediation.id: remediation},
    )
    projected = TrustedChangeGate.project_campaign(
        campaign,
        {remediation.id: remediation},
        {},
        now,
    )

    assert batch.decision.code == GateCode.CAMPAIGN_NO_APPROVED_HOSTS
    assert batch.plan_changed_host_ids == [host.id]
    assert projected.hosts[0].state == "plan_changed"
    assert projected.status == "awaiting_approval"


def test_campaign_projection_keeps_blocked_execution_terminal():
    host = make_host()
    remediation = fully_approved(host)
    remediation.execution_state = "blocked"
    now = utc_now()
    host_plan = CampaignHostPlan(
        id="campaign-host-1",
        campaign_id="campaign-1",
        host_id=host.id,
        hostname=host.name,
        state="approved",
        remediation_id=remediation.id,
        plan_version=remediation.plan_version,
        plan_hash=remediation.plan_hash,
        created_at=now,
        updated_at=now,
    )
    campaign = PatchCampaign(
        id="campaign-1",
        name="Blocked wave",
        host_ids=[host.id],
        remediation_ids=[remediation.id],
        hosts=[host_plan],
        status="running",
        batch_size=1,
        total_batches=1,
        created_at=now,
        updated_at=now,
    )

    projected = TrustedChangeGate.project_campaign(
        campaign,
        {remediation.id: remediation},
        {},
        now,
    )

    assert projected.hosts[0].state == "blocked"
    assert projected.status == "failed"


def test_campaign_does_not_overlap_rollout_batches():
    host = make_host()
    remediation = fully_approved(host)
    now = utc_now()
    campaign = PatchCampaign(
        id="campaign-1",
        name="Active wave",
        host_ids=[host.id],
        remediation_ids=[remediation.id],
        hosts=[
            CampaignHostPlan(
                id="campaign-host-1",
                campaign_id="campaign-1",
                host_id=host.id,
                hostname=host.name,
                state="running",
                remediation_id=remediation.id,
                plan_version=remediation.plan_version,
                plan_hash=remediation.plan_hash,
                created_at=now,
                updated_at=now,
            )
        ],
        status="running",
        batch_size=1,
        current_batch=1,
        total_batches=1,
        created_at=now,
        updated_at=now,
    )

    decision = TrustedChangeGate.campaign_batch(
        campaign,
        {remediation.id: remediation},
    )

    assert decision.decision.code == GateCode.CAMPAIGN_BATCH_IN_PROGRESS
    assert decision.host_ids == []


@pytest.mark.asyncio
async def test_maintenance_release_revalidates_stale_approval(service):
    policy = PatchPolicy(
        execution_timing="maintenance_window",
        maintenance_window=MaintenanceWindow(
            timezone="UTC",
            weekdays=[0],
            start_time="02:00",
            duration_minutes=60,
        ),
    )
    host = service.create_host(
        HostInput(
            name="maintenance-host",
            address="10.0.0.30",
            username="ubuntu",
            patch_policy=policy,
        )
    )
    scan_job = service.create_scan_job(ScanRequest(host_id=host.id))
    completed = await service.process_scan(scan_job.id)
    scan = service.get_scan(completed.scan_id)
    remediation = service.repository.get_remediation(scan.remediation_ids[0])
    service.approve_remediation_plan(
        remediation.id,
        request_for(host, remediation),
        "admin",
    )
    service.approve_remediation_reboot(
        remediation.id,
        request_for(host, remediation),
        "admin",
    )
    job = service.prepare_remediation_job(remediation.id, "admin")
    stale = service.repository.get_remediation(remediation.id)
    stale.approval_state = "pending"
    service.repository.save_remediation(stale)

    released = service.release_scheduled_remediation_jobs(
        datetime(2026, 6, 29, 2, 30, tzinfo=timezone.utc)
    )

    assert released == []
    assert service.get_job(job.id).status == "failed"
    assert service.repository.get_remediation(remediation.id).execution_state == (
        "blocked"
    )


@pytest.mark.asyncio
async def test_stale_worker_after_mutation_phase_is_not_retried(service):
    host = service.create_host(
        HostInput(
            name="stale-worker-host",
            address="10.0.0.31",
            username="ubuntu",
        )
    )
    scan_job = service.create_scan_job(ScanRequest(host_id=host.id))
    completed = await service.process_scan(scan_job.id)
    scan = service.get_scan(completed.scan_id)
    remediation = service.repository.get_remediation(scan.remediation_ids[0])
    service.approve_remediation_plan(
        remediation.id,
        request_for(host, remediation),
        "admin",
    )
    service.approve_remediation_reboot(
        remediation.id,
        request_for(host, remediation),
        "admin",
    )
    queued = service.prepare_remediation_job(remediation.id, "admin")
    claimed_at = utc_now()
    claimed = service.repository.claim_job(
        queued.id,
        "crashed-worker",
        claimed_at,
        claimed_at + timedelta(seconds=5),
    )
    claimed.current_phase = "ansible_execution"
    claimed.updated_at = claimed_at + timedelta(seconds=1)
    service.repository.save_job(claimed, lease_owner="crashed-worker")

    recovered = service.recover_expired_jobs(
        claimed_at + timedelta(seconds=6)
    )

    failed = service.get_job(queued.id)
    assert recovered == []
    assert failed.status == "failed"
    assert failed.last_failure.category == "safety_validation"
    assert service.repository.get_remediation(remediation.id).execution_state == (
        "blocked"
    )
