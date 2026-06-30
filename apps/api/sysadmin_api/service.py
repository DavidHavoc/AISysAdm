from __future__ import annotations

import asyncio
import math
from datetime import datetime, timedelta
from typing import Any, Awaitable, Callable, Dict, List, Optional, Tuple, TypeVar
from uuid import uuid4
from zoneinfo import ZoneInfo

from croniter import croniter

from .agents import MultiAgentWorkflow
from .collector import HostCollector
from .credentials import SNAPSHOT_CREDENTIAL_TYPES
from .executor import RemediationExecutor
from .models import (
    AgentMessage,
    AgentRun,
    Alert,
    ApprovalRequest,
    AuditEvent,
    CampaignHostPlan,
    CampaignHostState,
    CampaignRequest,
    CampaignStatus,
    ConnectionTestResult,
    CredentialType,
    DurableJob,
    ExecutionPhase,
    Host,
    HostInput,
    HostSchedule,
    HostScheduleInput,
    JobFailure,
    LogPage,
    PatchCampaign,
    Remediation,
    RollbackSnapshot,
    RollbackSnapshotState,
    ScanJob,
    ScanRequest,
    Severity,
    SnapshotPlatform,
    StructuredLogEvent,
    utc_now,
)
from .redaction import redact_text, sanitize_audit_details, sanitize_log_event
from .repository import Repository, normalized_datetime
from .snapshots import SimulatedSnapshotProvider, SnapshotProvider
from .trusted_change import (
    GateDecision,
    GateDenied,
    GateCode,
    PlanReconciliation,
    PostChangeAction,
    TrustedChangeGate,
)


ResultT = TypeVar("ResultT")


class JobLeaseLost(RuntimeError):
    pass


class NonRetryableJobError(RuntimeError):
    def __init__(self, message: str, category: str = "safety_validation") -> None:
        super().__init__(message)
        self.category = category


def new_id(prefix: str) -> str:
    return "%s-%s" % (prefix, uuid4().hex[:12])


class SysadminService:
    def __init__(
        self,
        repository: Repository,
        collector: HostCollector,
        workflow: MultiAgentWorkflow,
        executor: RemediationExecutor,
        snapshot_provider: Optional[SnapshotProvider] = None,
        log_retention_days: int = 90,
        job_lease_seconds: int = 120,
        job_heartbeat_seconds: int = 30,
    ) -> None:
        self.repository = repository
        self.collector = collector
        self.workflow = workflow
        self.executor = executor
        self.snapshot_provider = snapshot_provider or SimulatedSnapshotProvider()
        self.log_retention_days = log_retention_days
        self.job_lease_seconds = job_lease_seconds
        self.job_heartbeat_seconds = min(
            job_heartbeat_seconds,
            max(1, job_lease_seconds // 2),
        )

    def list_hosts(self) -> List[Host]:
        return sorted(self.repository.list_hosts(), key=lambda item: item.name)

    def create_host(self, host_input: HostInput, actor: str = "system") -> Host:
        self._validate_host_input(host_input)
        now = utc_now()
        host = Host(
            **host_input.model_dump(),
            id=new_id("host"),
            connection_status="untested",
            created_at=now,
            updated_at=now,
        )
        self.repository.save_host(host)
        self.save_schedule(
            host.id,
            HostScheduleInput(),
            actor=actor,
        )
        self.audit(actor, "host.created", "host", host.id)
        return host

    def update_host(
        self,
        host_id: str,
        host_input: HostInput,
        actor: str,
    ) -> Host:
        current = self._host(host_id)
        self._validate_host_input(host_input)
        updated = Host(
            **host_input.model_dump(),
            id=current.id,
            connection_status=current.connection_status,
            created_at=current.created_at,
            updated_at=utc_now(),
        )
        self.repository.save_host(updated)
        self.audit(actor, "host.updated", "host", host_id)
        return updated

    def delete_host(self, host_id: str, actor: str) -> None:
        host = self._host(host_id)
        self.repository.delete_schedule(host_id)
        self.repository.delete_host(host_id)
        self.audit(actor, "host.deleted", "host", host_id)

    async def test_connection(
        self,
        host_id: str,
        confirm_fingerprint: Optional[str],
        actor: str,
    ) -> ConnectionTestResult:
        host = self._host(host_id)
        result = await self.collector.test_connection(host)
        if (
            result.host_key_fingerprint
            and confirm_fingerprint
            and confirm_fingerprint == result.host_key_fingerprint
        ):
            host.ssh_host_key_fingerprint = result.host_key_fingerprint
            host.connection_status = "ready" if result.success else "failed"
            host.updated_at = utc_now()
            self.repository.save_host(host)
        elif result.success and not host.ssh_host_key_fingerprint:
            result.success = False
            result.checks["host_key_confirmation"] = "required"
        self.audit(
            actor,
            "host.connection_tested",
            "host",
            host_id,
            {
                "success": result.success,
                "fingerprint_confirmed": bool(confirm_fingerprint),
            },
        )
        return result

    def list_findings(self, host_id: Optional[str] = None):
        if not host_id:
            return self.repository.list_findings()
        scans = [
            scan
            for scan in self.repository.list_scans(host_id)
            if scan.status == "completed"
        ]
        if not scans:
            return []
        latest = max(scans, key=lambda item: item.created_at)
        finding_ids = set(latest.finding_ids)
        return [
            item
            for item in self.repository.list_findings(host_id)
            if item.id in finding_ids
        ]

    def list_remediations(self) -> List[Remediation]:
        return sorted(
            self.repository.list_remediations(),
            key=lambda item: item.created_at,
            reverse=True,
        )

    def list_rollback_snapshots(
        self,
        host_id: Optional[str] = None,
        remediation_id: Optional[str] = None,
    ) -> List[RollbackSnapshot]:
        return sorted(
            self.repository.list_rollback_snapshots(
                host_id=host_id,
                remediation_id=remediation_id,
            ),
            key=lambda item: item.created_at,
            reverse=True,
        )

    def get_scan(self, scan_id: str) -> Optional[ScanJob]:
        return self.repository.get_scan(scan_id)

    def list_scans(self, host_id: Optional[str] = None) -> List[ScanJob]:
        return sorted(
            self.repository.list_scans(host_id),
            key=lambda item: item.created_at,
            reverse=True,
        )

    def create_scan_job(
        self,
        request: ScanRequest,
        actor: str = "system",
        campaign_id: Optional[str] = None,
    ) -> DurableJob:
        host = self._host(request.host_id)
        key = request.idempotency_key or "scan:%s:%s:%s" % (
            host.id,
            request.trigger,
            utc_now().strftime("%Y%m%d%H%M"),
        )
        existing = self.repository.get_job_by_idempotency(key)
        if existing:
            return existing
        if request.trigger == "scheduled" and self.repository.host_has_active_scan(host.id):
            raise ValueError("A scan is already queued or running for this host")
        now = utc_now()
        scan = ScanJob(
            id=new_id("scan"),
            host_id=host.id,
            trigger=request.trigger,
            status="queued",
            campaign_id=campaign_id,
            created_at=now,
            updated_at=now,
        )
        job = DurableJob(
            id=new_id("job"),
            job_type="scan",
            status="queued",
            host_id=host.id,
            scan_id=scan.id,
            campaign_id=campaign_id,
            idempotency_key=key,
            created_at=now,
            updated_at=now,
        )
        scan.durable_job_id = job.id
        self.repository.save_scan(scan)
        self.repository.save_job(job)
        self.audit(
            actor,
            "scan.queued",
            "scan",
            scan.id,
            {"job_id": job.id, "trigger": request.trigger},
        )
        return job

    async def process_scan(
        self,
        job_id: str,
        worker_id: Optional[str] = None,
    ) -> DurableJob:
        owner = worker_id or new_id("worker")
        claimed_at = utc_now()
        job = self.repository.claim_job(
            job_id,
            owner,
            claimed_at,
            claimed_at + timedelta(seconds=self.job_lease_seconds),
        )
        if not job:
            return self._job(job_id)
        scan = self._scan(job.scan_id)
        host = self._host(scan.host_id)
        try:
            return await self._run_with_heartbeat(
                job.id,
                owner,
                lambda: self._process_claimed_scan(job, scan, host, owner),
            )
        except JobLeaseLost:
            return self._job(job_id)
        except Exception as error:
            error_text = self._redact_text(str(error), host.id)
            failed = self.fail_job(
                job,
                error_text,
                host.id,
                lease_owner=owner,
                retryable=not isinstance(error, NonRetryableJobError),
                category=getattr(error, "category", "scan_execution"),
            )
            scan.status = "queued" if failed.status == "queued" else "failed"
            scan.error = error_text[:2000]
            scan.updated_at = utc_now()
            self.repository.save_scan(scan)
            if scan.campaign_id and failed.status == "failed":
                self._mark_campaign_proposal_failed(
                    scan.campaign_id,
                    host.id,
                    error_text,
                )
            return failed

    async def _process_claimed_scan(
        self,
        job: DurableJob,
        scan: ScanJob,
        host: Host,
        lease_owner: str,
    ) -> DurableJob:
        job.current_phase = "collecting_evidence"
        job.progress_percent = 10
        job.updated_at = utc_now()
        scan.status = "running"
        scan.updated_at = utc_now()
        self._save_claimed_job(job, lease_owner)
        self.repository.save_scan(scan)
        if scan.campaign_id:
            self._mark_campaign_proposal_running(scan.campaign_id, host.id)

        collected = await self.collector.collect(host, job.id, scan.id)
        self._assert_job_lease(job.id, lease_owner)
        self.repository.save_snapshot(collected.snapshot)
        self.repository.save_log_events(collected.events)
        scan.snapshot_id = collected.snapshot.id
        job.current_phase = "multi_agent_analysis"
        job.progress_percent = 35
        job.updated_at = utc_now()
        self._save_claimed_job(job, lease_owner)

        result = await self.workflow.run(scan.id, host, collected.snapshot)
        self._assert_job_lease(job.id, lease_owner)
        for finding in result.findings:
            finding.scan_id = scan.id
        self.repository.save_agent_runs(result.runs)
        self.repository.save_agent_messages(result.messages)
        self.repository.save_findings(result.findings)
        self.repository.save_log_events(
            agent_events(host, job.id, scan.id, result.runs, result.messages)
        )
        remediation_ids: List[str] = []
        if result.remediation:
            self.repository.save_remediation(result.remediation)
            remediation_ids.append(result.remediation.id)
        scan.status = "completed"
        scan.finding_ids = [item.id for item in result.findings]
        scan.remediation_ids = remediation_ids
        scan.agent_run_ids = [item.id for item in result.runs]
        scan.agent_reports = result.reports
        scan.error = None
        scan.updated_at = utc_now()
        self.repository.save_scan(scan)

        job.status = "completed"
        job.current_phase = "completed"
        job.progress_percent = 100
        job.result = {
            "scan_id": scan.id,
            "finding_count": len(result.findings),
            "remediation_ids": remediation_ids,
            "rejected_claims": result.rejected_claims,
        }
        job.completed_at = utc_now()
        job.updated_at = utc_now()
        job.lease_owner = None
        job.lease_expires_at = None
        self._save_claimed_job(job, lease_owner)
        if scan.campaign_id:
            self._attach_campaign_proposal(
                scan.campaign_id,
                host,
                result.remediation,
            )
        if scan.trigger == "scheduled":
            for finding in result.findings:
                if severity_text(finding.severity) in ("high", "critical"):
                    self.create_alert(
                        severity=Severity(severity_text(finding.severity)),
                        title="Scheduled scan found %s risk"
                        % severity_text(finding.severity),
                        message=finding.summary,
                        host_id=host.id,
                        job_id=job.id,
                    )
        self.audit(
            "scheduler" if scan.trigger == "scheduled" else "operator",
            "scan.completed",
            "scan",
            scan.id,
            {"job_id": job.id},
        )
        return job

    def approve_remediation_plan(
        self,
        remediation_id: str,
        request: ApprovalRequest,
        actor: str,
    ) -> Remediation:
        remediation = self._remediation(remediation_id)
        host = self._host(remediation.host_id)
        _, remediation = self._ensure_current_remediation_plan(remediation)
        now = utc_now()
        transition = TrustedChangeGate.approve_plan(
            remediation,
            host,
            request,
            actor,
            now,
        )
        self._raise_gate_denial(transition.decision)
        remediation = transition.remediation
        self.repository.save_remediation(remediation)
        self.audit(
            actor,
            "remediation.plan_approved",
            "remediation",
            remediation.id,
            {
                "plan_version": remediation.plan_version,
                "plan_hash": remediation.plan_hash,
            },
        )
        self._sync_campaigns_for_remediation(remediation.id)
        return remediation

    def approve_remediation_reboot(
        self,
        remediation_id: str,
        request: ApprovalRequest,
        actor: str,
    ) -> Remediation:
        remediation = self._remediation(remediation_id)
        host = self._host(remediation.host_id)
        _, remediation = self._ensure_current_remediation_plan(remediation)
        now = utc_now()
        transition = TrustedChangeGate.approve_reboot(
            remediation,
            host,
            request,
            actor,
            now,
        )
        remediation = transition.remediation
        if not transition.decision.allowed:
            if remediation != self._remediation(remediation_id):
                self.repository.save_remediation(remediation)
                self._sync_campaigns_for_remediation(remediation.id)
            self._raise_gate_denial(transition.decision)
        self.repository.save_remediation(remediation)
        self.audit(
            actor,
            "remediation.reboot_approved",
            "remediation",
            remediation.id,
            {
                "plan_version": remediation.plan_version,
                "plan_hash": remediation.plan_hash,
            },
        )
        self._sync_campaigns_for_remediation(remediation.id)
        return remediation

    def prepare_remediation_job(
        self,
        remediation_id: str,
        actor: str,
        campaign_id: Optional[str] = None,
        sync_campaigns: bool = True,
    ) -> DurableJob:
        with self.repository.transaction():
            remediation = self._remediation_for_update(remediation_id)
            host = self._host(remediation.host_id)
            eligibility, remediation = self._trusted_execution_decision(
                remediation,
                host,
            )
            self._raise_gate_denial(eligibility)
            now = utc_now()
            key = "remediation:%s:%s" % (
                remediation.id,
                remediation.plan_hash,
            )
            existing = self.repository.get_job_by_idempotency(key)
            if existing:
                duplicate = TrustedChangeGate.duplicate_execution(
                    existing,
                    campaign_id,
                )
                self._raise_gate_denial(duplicate)
                return existing
            timing = TrustedChangeGate.timing(remediation, now)
            job = DurableJob(
                id=new_id("job"),
                job_type="remediation",
                status=timing.job_status,
                host_id=host.id,
                scan_id=remediation.scan_id,
                remediation_id=remediation.id,
                campaign_id=campaign_id,
                approved_plan_version=remediation.plan_version,
                approved_plan_hash=remediation.plan_hash,
                approval_scope=TrustedChangeGate.job_approval_scope(remediation),
                idempotency_key=key,
                created_at=now,
                updated_at=now,
            )
            remediation.execution_state = timing.remediation_state
            self.repository.save_remediation(remediation)
            self.repository.save_job(job)
            self.audit(
                actor,
                "remediation.execution_queued",
                "remediation",
                remediation.id,
                {"job_id": job.id, "plan_hash": remediation.plan_hash},
            )
        if sync_campaigns:
            self._sync_campaigns_for_remediation(remediation.id)
        return job

    async def process_remediation(
        self,
        job_id: str,
        worker_id: Optional[str] = None,
    ) -> DurableJob:
        existing = self._job(job_id)
        remediation = self._remediation(existing.remediation_id)
        host = self._host(remediation.host_id)
        if existing.status == "queued" and existing.campaign_id:
            campaign = self._campaign(existing.campaign_id)
            if campaign.status == CampaignStatus.CANCELED:
                canceled = self.repository.cancel_job(
                    existing.id,
                    utc_now(),
                    allowed_statuses=("queued",),
                    phase="canceled",
                )
                if canceled and canceled.status == "canceled":
                    remediation.execution_state = "canceled"
                    remediation.updated_at = utc_now()
                    self.repository.save_remediation(remediation)
                    self._sync_campaigns_for_remediation(remediation.id)
                return canceled or self._job(job_id)
        timing = TrustedChangeGate.timing(remediation, utc_now())
        if existing.status == "queued" and not timing.decision.allowed:
            existing.status = "scheduled"
            existing.current_phase = "waiting_for_maintenance_window"
            existing.updated_at = utc_now()
            self.repository.save_job(existing)
            self._sync_campaigns_for_remediation(remediation.id)
            return existing
        owner = worker_id or new_id("worker")
        claimed_at = utc_now()
        job = self.repository.claim_job(
            job_id,
            owner,
            claimed_at,
            claimed_at + timedelta(seconds=self.job_lease_seconds),
        )
        if not job:
            return self._job(job_id)
        remediation = self._remediation(job.remediation_id)
        host = self._host(remediation.host_id)
        if (
            job.last_failure
            and job.last_failure.category == "worker_lease_expired"
        ):
            recovery = TrustedChangeGate.stale_recovery(job, exhausted=False)
            if not recovery.dispatch:
                remediation.execution_state = recovery.remediation_state
                remediation.updated_at = utc_now()
                self.repository.save_remediation(remediation)
                failed = self.fail_job(
                    job,
                    recovery.decision.message,
                    host.id,
                    lease_owner=owner,
                    retryable=False,
                    category=recovery.decision.category,
                )
                self._sync_campaigns_for_remediation(
                    remediation.id,
                    stop_remaining=True,
                )
                return failed
        eligibility, remediation = self._trusted_execution_decision(
            remediation,
            host,
            job,
        )
        if not eligibility.allowed:
            remediation.execution_state = "blocked"
            remediation.updated_at = utc_now()
            self.repository.save_remediation(remediation)
            failed = self.fail_job(
                job,
                eligibility.message,
                host.id,
                lease_owner=owner,
                retryable=False,
                category=eligibility.category,
            )
            self._sync_campaigns_for_remediation(remediation.id)
            return failed
        try:
            return await self._run_with_heartbeat(
                job.id,
                owner,
                lambda: self._process_claimed_remediation(
                    job,
                    remediation,
                    host,
                    owner,
                ),
            )
        except JobLeaseLost:
            return self._job(job_id)
        except Exception as error:
            retryable = not isinstance(error, NonRetryableJobError)
            category = getattr(error, "category", "remediation_execution")
            error_text = self._redact_text(str(error), host.id)
            failed = self.fail_job(
                job,
                error_text,
                host.id,
                lease_owner=owner,
                retryable=retryable,
                category=category,
            )
            remediation = self._remediation(remediation.id)
            remediation.execution_state = (
                "queued"
                if failed.status == "queued"
                else (
                    "blocked"
                    if category in ("approval_validation", "safety_validation")
                    else "failed"
                )
            )
            remediation.updated_at = utc_now()
            self.repository.save_remediation(remediation)
            self._sync_campaigns_for_remediation(
                remediation.id,
                stop_remaining=failed.status == "failed",
            )
            return failed

    async def _process_claimed_remediation(
        self,
        job: DurableJob,
        remediation: Remediation,
        host: Host,
        lease_owner: str,
    ) -> DurableJob:
        job.current_phase = "state_drift_check"
        job.progress_percent = 10
        job.updated_at = utc_now()
        remediation.execution_state = "running"
        remediation.updated_at = utc_now()
        self._save_claimed_job(job, lease_owner)
        self.repository.save_remediation(remediation)
        self._sync_campaigns_for_remediation(remediation.id)
        original_scan = self._scan(remediation.scan_id)
        original_snapshot = self.repository.get_snapshot(original_scan.snapshot_id or "")
        if not original_snapshot:
            decision = TrustedChangeGate.drift(None, None)
            raise NonRetryableJobError(decision.message, decision.category)
        current = await self.collector.collect(
            host,
            job.id,
            remediation.scan_id or "",
        )
        self._assert_job_lease(job.id, lease_owner)
        self.repository.save_snapshot(current.snapshot)
        self.repository.save_log_events(current.events)
        drift = TrustedChangeGate.drift(original_snapshot, current.snapshot)
        if not drift.allowed:
            raise NonRetryableJobError(drift.message, drift.category)

        remediation = self._remediation(job.remediation_id)
        host = self._host(remediation.host_id)
        eligibility, remediation = self._trusted_execution_decision(
            remediation,
            host,
            job,
        )
        if not eligibility.allowed:
            remediation.execution_state = "blocked"
            remediation.updated_at = utc_now()
            self.repository.save_remediation(remediation)
            raise NonRetryableJobError(
                eligibility.message,
                eligibility.category,
            )

        rollback_snapshot: Optional[RollbackSnapshot] = None
        snapshot_requirement = TrustedChangeGate.snapshot_requirement(
            host,
            remediation,
        )
        if not snapshot_requirement.decision.allowed:
            raise NonRetryableJobError(
                snapshot_requirement.decision.message,
                snapshot_requirement.decision.category,
            )
        if snapshot_requirement.required:
            job.current_phase = "snapshot_create"
            job.progress_percent = 25
            job.updated_at = utc_now()
            self._save_claimed_job(job, lease_owner)
            self._assert_job_lease(job.id, lease_owner)
            rollback_snapshot = await self._create_rollback_snapshot(
                job,
                remediation,
                host,
            )
            self._assert_job_lease(job.id, lease_owner)

        remediation = self._remediation(job.remediation_id)
        host = self._host(remediation.host_id)
        eligibility, remediation = self._trusted_execution_decision(
            remediation,
            host,
            job,
        )
        if not eligibility.allowed:
            remediation.execution_state = "blocked"
            remediation.updated_at = utc_now()
            self.repository.save_remediation(remediation)
            raise NonRetryableJobError(
                eligibility.message,
                eligibility.category,
            )

        job.current_phase = "ansible_execution"
        job.progress_percent = 30
        job.updated_at = utc_now()
        self._save_claimed_job(job, lease_owner)
        self._assert_job_lease(job.id, lease_owner)
        result = await self.executor.execute(host, remediation, job.id)
        self._assert_job_lease(job.id, lease_owner)
        if result.success and rollback_snapshot:
            result = await self._finish_snapshot_protected_execution(
                job,
                remediation,
                host,
                rollback_snapshot,
                result,
                lease_owner,
            )
            self._assert_job_lease(job.id, lease_owner)
        self.repository.save_log_events(result.events)
        remediation.result = result
        outcome = TrustedChangeGate.execution_outcome(
            result,
            rollback_snapshot.state if rollback_snapshot else None,
        )
        remediation.execution_state = outcome.remediation_state
        remediation.updated_at = utc_now()
        self.repository.save_remediation(remediation)
        if not result.success:
            if not outcome.decision.retryable:
                raise NonRetryableJobError(
                    outcome.decision.message,
                    outcome.decision.category,
                )
            raise RuntimeError(outcome.decision.message)

        job.status = "completed"
        job.current_phase = "completed"
        job.progress_percent = 100
        job.result = {"remediation_id": remediation.id, "success": True}
        job.completed_at = utc_now()
        job.updated_at = utc_now()
        job.lease_owner = None
        job.lease_expires_at = None
        self._save_claimed_job(job, lease_owner)
        self.audit(
            remediation.approved_by or "operator",
            "remediation.completed",
            "remediation",
            remediation.id,
            {"job_id": job.id, "reboot_performed": result.reboot_performed},
        )
        self._sync_campaigns_for_remediation(remediation.id)
        return job

    def reject_remediation(self, remediation_id: str, actor: str) -> Remediation:
        remediation = self._remediation(remediation_id)
        if remediation.approval_state != "pending":
            raise ValueError("Only pending remediations can be rejected")
        remediation.approval_state = "rejected"
        remediation.reboot_approval_state = "rejected"
        remediation.reboot_assessment.approved_if_required = False
        remediation.execution_state = "blocked"
        remediation.updated_at = utc_now()
        self.repository.save_remediation(remediation)
        self.audit(actor, "remediation.rejected", "remediation", remediation_id)
        self._sync_campaigns_for_remediation(remediation.id)
        return remediation

    def save_schedule(
        self,
        host_id: str,
        schedule_input: HostScheduleInput,
        actor: str,
    ) -> HostSchedule:
        self._host(host_id)
        now = utc_now()
        existing = self.repository.get_schedule(host_id)
        next_run = (
            next_cron_run(
                schedule_input.cron_expression,
                schedule_input.timezone,
                now,
            )
            if schedule_input.enabled
            else None
        )
        schedule = HostSchedule(
            **schedule_input.model_dump(),
            id=existing.id if existing else new_id("schedule"),
            host_id=host_id,
            previous_run_at=existing.previous_run_at if existing else None,
            next_run_at=next_run,
            created_at=existing.created_at if existing else now,
            updated_at=now,
        )
        self.repository.save_schedule(schedule)
        self.audit(
            actor,
            "schedule.updated",
            "host",
            host_id,
            {"enabled": schedule.enabled, "cron": schedule.cron_expression},
        )
        return schedule

    def get_schedule(self, host_id: str) -> HostSchedule:
        schedule = self.repository.get_schedule(host_id)
        if not schedule:
            raise ValueError("Host schedule not found")
        return schedule

    def list_schedules(self) -> List[HostSchedule]:
        return self.repository.list_schedules()

    def create_due_scan_jobs(self, now: Optional[datetime] = None) -> List[DurableJob]:
        current = now or utc_now()
        jobs: List[DurableJob] = []
        for schedule in self.repository.list_due_schedules(current):
            if schedule.overlap_policy == "skip_if_running" and self.repository.host_has_active_scan(
                schedule.host_id
            ):
                schedule.previous_run_at = current
                schedule.next_run_at = next_cron_run(
                    schedule.cron_expression,
                    schedule.timezone,
                    current,
                )
                schedule.updated_at = current
                self.repository.save_schedule(schedule)
                self.audit(
                    "scheduler",
                    "schedule.skipped_overlap",
                    "host",
                    schedule.host_id,
                )
                continue
            try:
                job = self.create_scan_job(
                    ScanRequest(
                        host_id=schedule.host_id,
                        trigger="scheduled",
                        idempotency_key="scheduled:%s:%s"
                        % (schedule.id, schedule.next_run_at.isoformat()),
                    ),
                    actor="scheduler",
                )
                jobs.append(job)
            finally:
                schedule.previous_run_at = current
                schedule.next_run_at = next_cron_run(
                    schedule.cron_expression,
                    schedule.timezone,
                    current,
                )
                schedule.updated_at = current
                self.repository.save_schedule(schedule)
        return jobs

    def release_scheduled_remediation_jobs(
        self,
        now: Optional[datetime] = None,
    ) -> List[DurableJob]:
        current = now or utc_now()
        released: List[DurableJob] = []
        for job in self.repository.list_jobs():
            if job.job_type != "remediation" or job.status != "scheduled":
                continue
            if job.campaign_id:
                campaign = self._campaign(job.campaign_id)
                if campaign.status == CampaignStatus.CANCELED:
                    job.status = "canceled"
                    job.current_phase = "canceled"
                    job.completed_at = current
                    job.updated_at = current
                    self.repository.save_job(job)
                    continue
            remediation = self._remediation(job.remediation_id)
            eligibility, remediation = self._trusted_execution_decision(
                remediation,
                self._host(remediation.host_id),
                job,
            )
            if not eligibility.allowed:
                remediation.execution_state = "blocked"
                remediation.updated_at = current
                self.repository.save_remediation(remediation)
                self.fail_job(
                    job,
                    eligibility.message,
                    remediation.host_id,
                    retryable=False,
                    category=eligibility.category,
                )
                self._sync_campaigns_for_remediation(remediation.id)
                continue
            timing = TrustedChangeGate.timing(remediation, current)
            if timing.decision.allowed:
                job.status = "queued"
                job.current_phase = None
                job.updated_at = current
                self.repository.save_job(job)
                self._sync_campaigns_for_remediation(remediation.id)
                released.append(job)
        return released

    def release_scheduled_snapshot_delete_jobs(
        self,
        now: Optional[datetime] = None,
    ) -> List[DurableJob]:
        current = now or utc_now()
        released: List[DurableJob] = []
        for job in self.repository.list_jobs():
            if job.job_type != "snapshot_delete" or job.status != "scheduled":
                continue
            snapshot_id = str(job.result.get("rollback_snapshot_id") or "")
            snapshot = self.repository.get_rollback_snapshot(snapshot_id)
            if not snapshot or not snapshot.delete_after:
                continue
            if normalized_datetime(snapshot.delete_after) <= normalized_datetime(current):
                job.status = "queued"
                job.current_phase = None
                job.updated_at = current
                self.repository.save_job(job)
                released.append(job)
        return released

    async def process_snapshot_delete(
        self,
        job_id: str,
        worker_id: Optional[str] = None,
    ) -> DurableJob:
        owner = worker_id or new_id("worker")
        claimed_at = utc_now()
        job = self.repository.claim_job(
            job_id,
            owner,
            claimed_at,
            claimed_at + timedelta(seconds=self.job_lease_seconds),
        )
        if not job:
            return self._job(job_id)
        snapshot_id = str(job.result.get("rollback_snapshot_id") or "")
        snapshot = self.repository.get_rollback_snapshot(snapshot_id)
        if not snapshot:
            return self.fail_job(
                job,
                "Rollback snapshot record not found",
                job.host_id or "",
                lease_owner=owner,
                retryable=False,
                category="snapshot_delete",
            )
        host = self._host(snapshot.host_id)
        try:
            return await self._run_with_heartbeat(
                job.id,
                owner,
                lambda: self._process_claimed_snapshot_delete(
                    job,
                    snapshot,
                    host,
                    owner,
                ),
            )
        except JobLeaseLost:
            return self._job(job_id)
        except Exception as error:
            error_text = self._redact_text(str(error), host.id)
            failed = self.fail_job(
                job,
                error_text,
                host.id,
                lease_owner=owner,
                retryable=False,
                category=getattr(error, "category", "snapshot_delete"),
            )
            snapshot.state = RollbackSnapshotState.DELETE_FAILED
            snapshot.failure_summary = error_text[:2000]
            snapshot.updated_at = utc_now()
            self.repository.save_rollback_snapshot(snapshot)
            return failed

    async def _process_claimed_snapshot_delete(
        self,
        job: DurableJob,
        snapshot: RollbackSnapshot,
        host: Host,
        lease_owner: str,
    ) -> DurableJob:
        job.current_phase = "snapshot_delete"
        job.progress_percent = 50
        job.updated_at = utc_now()
        self._save_claimed_job(job, lease_owner)
        result = await self.snapshot_provider.delete_snapshot(host, snapshot, job.id)
        self.repository.save_log_events(result.events)
        snapshot.updated_at = utc_now()
        if not result.success:
            snapshot.state = RollbackSnapshotState.DELETE_FAILED
            snapshot.failure_summary = self._redact_text(result.summary, host.id)
            self.repository.save_rollback_snapshot(snapshot)
            self.create_alert(
                severity=Severity.HIGH,
                title="Snapshot delete failed",
                message=result.summary,
                host_id=host.id,
                job_id=job.id,
            )
            raise NonRetryableJobError(result.summary, "snapshot_delete")
        snapshot.state = RollbackSnapshotState.DELETED
        snapshot.failure_summary = None
        self.repository.save_rollback_snapshot(snapshot)
        job.status = "completed"
        job.current_phase = "completed"
        job.progress_percent = 100
        job.result = {
            **job.result,
            "success": True,
            "rollback_snapshot_id": snapshot.id,
        }
        job.completed_at = utc_now()
        job.updated_at = utc_now()
        job.lease_owner = None
        job.lease_expires_at = None
        self._save_claimed_job(job, lease_owner)
        self.audit(
            "system",
            "snapshot.deleted",
            "rollback_snapshot",
            snapshot.id,
            {"job_id": job.id},
        )
        return job

    def recover_expired_jobs(
        self,
        now: Optional[datetime] = None,
    ) -> List[DurableJob]:
        current = now or utc_now()
        recovered, exhausted = self.repository.recover_expired_jobs(current)
        dispatchable: List[DurableJob] = []
        for job in recovered:
            if job.job_type == "scan":
                scan = self.repository.get_scan(job.scan_id or "")
                if scan:
                    scan.status = "queued"
                    scan.error = job.last_failure.message if job.last_failure else None
                    scan.updated_at = current
                    self.repository.save_scan(scan)
            elif job.job_type == "remediation":
                remediation = self.repository.get_remediation(job.remediation_id or "")
                if remediation:
                    recovery = TrustedChangeGate.stale_recovery(
                        job,
                        exhausted=False,
                    )
                    remediation.execution_state = recovery.remediation_state
                    remediation.updated_at = current
                    self.repository.save_remediation(remediation)
                    if not recovery.dispatch:
                        self.fail_job(
                            job,
                            recovery.decision.message,
                            remediation.host_id,
                            retryable=False,
                            category=recovery.decision.category,
                        )
                        self._sync_campaigns_for_remediation(
                            remediation.id,
                            stop_remaining=True,
                        )
                        continue
            elif job.job_type == "snapshot_delete":
                snapshot = self.repository.get_rollback_snapshot(
                    str(job.result.get("rollback_snapshot_id") or "")
                )
                if snapshot and snapshot.state == RollbackSnapshotState.DELETE_FAILED:
                    snapshot.state = RollbackSnapshotState.DELETE_SCHEDULED
                    snapshot.updated_at = current
                    self.repository.save_rollback_snapshot(snapshot)
            self.audit(
                "scheduler",
                "job.lease_recovered",
                "job",
                job.id,
                {"attempt": job.attempts},
            )
            dispatchable.append(job)
        for job in exhausted:
            if job.job_type == "scan":
                scan = self.repository.get_scan(job.scan_id or "")
                if scan:
                    scan.status = "failed"
                    scan.error = job.error
                    scan.updated_at = current
                    self.repository.save_scan(scan)
            elif job.job_type == "remediation":
                remediation = self.repository.get_remediation(job.remediation_id or "")
                if remediation:
                    recovery = TrustedChangeGate.stale_recovery(
                        job,
                        exhausted=True,
                    )
                    remediation.execution_state = recovery.remediation_state
                    remediation.updated_at = current
                    self.repository.save_remediation(remediation)
            elif job.job_type == "snapshot_delete":
                snapshot = self.repository.get_rollback_snapshot(
                    str(job.result.get("rollback_snapshot_id") or "")
                )
                if snapshot:
                    snapshot.state = RollbackSnapshotState.DELETE_FAILED
                    snapshot.failure_summary = job.error
                    snapshot.updated_at = current
                    self.repository.save_rollback_snapshot(snapshot)
            self._record_terminal_job_failure(job, job.host_id)
        return dispatchable

    def list_jobs(self) -> List[DurableJob]:
        return sorted(
            self.repository.list_jobs(),
            key=lambda item: item.created_at,
            reverse=True,
        )

    def get_job(self, job_id: str) -> Optional[DurableJob]:
        return self.repository.get_job(job_id)

    def list_agent_runs(self, scan_id: Optional[str] = None) -> List[AgentRun]:
        return self.repository.list_agent_runs(scan_id)

    def list_agent_messages(self, scan_id: str) -> List[AgentMessage]:
        return self.repository.list_agent_messages(scan_id)

    def list_logs(
        self,
        filters: Dict[str, Any],
        page: int,
        page_size: int,
    ) -> LogPage:
        items, total = self.repository.list_log_events(filters, page, page_size)
        return LogPage(items=items, total=total, page=page, page_size=page_size)

    def get_log(self, log_id: str) -> Optional[StructuredLogEvent]:
        return self.repository.get_log_event(log_id)

    def list_alerts(self) -> List[Alert]:
        return sorted(
            self.repository.list_alerts(),
            key=lambda item: item.created_at,
            reverse=True,
        )

    def acknowledge_alert(self, alert_id: str, actor: str) -> Alert:
        alert = self.repository.get_alert(alert_id)
        if not alert:
            raise ValueError("Alert not found")
        alert.acknowledged = True
        alert.acknowledged_at = utc_now()
        self.repository.save_alert(alert)
        self.audit(actor, "alert.acknowledged", "alert", alert_id)
        return alert

    def list_audits(self) -> List[AuditEvent]:
        return sorted(
            self.repository.list_audits(),
            key=lambda item: item.created_at,
            reverse=True,
        )

    def purge_expired_logs(self) -> int:
        cutoff = utc_now() - timedelta(days=self.log_retention_days)
        count = self.repository.purge_logs_before(cutoff)
        self.audit(
            "scheduler",
            "logs.retention_purge",
            "log_event",
            details={"deleted": count, "retention_days": self.log_retention_days},
        )
        return count

    def create_campaign(
        self,
        request: CampaignRequest,
        actor: str,
    ) -> PatchCampaign:
        host_ids = list(dict.fromkeys(request.host_ids))
        if len(host_ids) != len(request.host_ids):
            raise ValueError("Campaign host selection contains duplicates")
        hosts = [self._host(host_id) for host_id in host_ids]
        batch_size = TrustedChangeGate.campaign_rollout_limit(hosts)
        now = utc_now()
        campaign_id = new_id("campaign")
        campaign = PatchCampaign(
            id=campaign_id,
            name=request.name,
            host_ids=host_ids,
            remediation_ids=[],
            hosts=[
                CampaignHostPlan(
                    id=new_id("campaign-host"),
                    campaign_id=campaign_id,
                    host_id=host.id,
                    hostname=host.name,
                    created_at=now,
                    updated_at=now,
                )
                for host in hosts
            ],
            status=CampaignStatus.DRAFT,
            batch_size=batch_size,
            total_batches=int(math.ceil(len(hosts) / batch_size)),
            created_at=now,
            updated_at=now,
        )
        self.repository.save_campaign(campaign)
        self.audit(
            actor,
            "campaign.created",
            "campaign",
            campaign.id,
            {"host_ids": host_ids},
        )
        return campaign

    def list_campaigns(self) -> List[PatchCampaign]:
        return [
            self._sync_campaign(campaign)
            for campaign in self.repository.list_campaigns()
        ]

    def get_campaign(self, campaign_id: str) -> PatchCampaign:
        return self._sync_campaign(self._campaign(campaign_id))

    def queue_campaign_proposals(
        self,
        campaign_id: str,
        actor: str,
    ) -> Tuple[PatchCampaign, List[DurableJob]]:
        campaign = self._sync_campaign(self._campaign(campaign_id))
        if campaign.status in (
            CampaignStatus.CANCELLING,
            CampaignStatus.CANCELED,
            CampaignStatus.SUCCEEDED,
            CampaignStatus.FAILED,
        ):
            raise ValueError("Campaign cannot create proposals in its current state")
        jobs: List[DurableJob] = []
        now = utc_now()
        for host_plan in campaign.hosts:
            if (
                host_plan.remediation_id
                and host_plan.state != CampaignHostState.PLAN_CHANGED
            ):
                continue
            if host_plan.state in (
                CampaignHostState.PROPOSAL_QUEUED,
                CampaignHostState.PROPOSAL_RUNNING,
            ):
                continue
            job = self.create_scan_job(
                ScanRequest(
                    host_id=host_plan.host_id,
                    trigger="campaign",
                    idempotency_key="campaign-scan:%s:%s:%s"
                    % (campaign.id, host_plan.host_id, new_id("request")),
                ),
                actor=actor,
                campaign_id=campaign.id,
            )
            host_plan.state = CampaignHostState.PROPOSAL_QUEUED
            host_plan.scan_id = job.scan_id
            host_plan.failure_summary = None
            host_plan.job_id = job.id
            host_plan.updated_at = now
            jobs.append(job)
        if not jobs:
            raise ValueError("Campaign has no hosts awaiting proposals")
        campaign.status = CampaignStatus.PROPOSING
        campaign.updated_at = now
        self.repository.save_campaign(campaign)
        self.audit(
            actor,
            "campaign.proposals_queued",
            "campaign",
            campaign.id,
            {"job_ids": [job.id for job in jobs]},
        )
        return campaign, jobs

    def approve_campaign_host(
        self,
        campaign_id: str,
        host_id: str,
        request: ApprovalRequest,
        actor: str,
    ) -> PatchCampaign:
        campaign = self._sync_campaign(self._campaign(campaign_id))
        if campaign.status in (
            CampaignStatus.CANCELLING,
            CampaignStatus.CANCELED,
            CampaignStatus.SUCCEEDED,
            CampaignStatus.FAILED,
        ):
            raise ValueError("Campaign cannot approve hosts in its current state")
        host_plan = self._campaign_host(campaign, host_id)
        if not host_plan.remediation_id:
            raise ValueError("Campaign host has no remediation proposal")
        self._validate_campaign_plan_binding(
            host_plan,
            self._remediation(host_plan.remediation_id),
        )
        self.approve_remediation_plan(host_plan.remediation_id, request, actor)
        campaign = self._sync_campaign(self._campaign(campaign_id))
        self.audit(
            actor,
            "campaign.host_plan_approved",
            "campaign",
            campaign.id,
            {"host_id": host_id, "remediation_id": host_plan.remediation_id},
        )
        return campaign

    def approve_campaign_host_reboot(
        self,
        campaign_id: str,
        host_id: str,
        request: ApprovalRequest,
        actor: str,
    ) -> PatchCampaign:
        campaign = self._sync_campaign(self._campaign(campaign_id))
        if campaign.status in (
            CampaignStatus.CANCELLING,
            CampaignStatus.CANCELED,
            CampaignStatus.SUCCEEDED,
            CampaignStatus.FAILED,
        ):
            raise ValueError("Campaign cannot approve hosts in its current state")
        host_plan = self._campaign_host(campaign, host_id)
        if not host_plan.remediation_id:
            raise ValueError("Campaign host has no remediation proposal")
        self._validate_campaign_plan_binding(
            host_plan,
            self._remediation(host_plan.remediation_id),
        )
        self.approve_remediation_reboot(host_plan.remediation_id, request, actor)
        campaign = self._sync_campaign(self._campaign(campaign_id))
        self.audit(
            actor,
            "campaign.host_reboot_approved",
            "campaign",
            campaign.id,
            {"host_id": host_id, "remediation_id": host_plan.remediation_id},
        )
        return campaign

    def reject_campaign_host(
        self,
        campaign_id: str,
        host_id: str,
        actor: str,
    ) -> PatchCampaign:
        campaign = self._sync_campaign(self._campaign(campaign_id))
        if campaign.status in (
            CampaignStatus.CANCELLING,
            CampaignStatus.CANCELED,
            CampaignStatus.SUCCEEDED,
            CampaignStatus.FAILED,
        ):
            raise ValueError("Campaign cannot reject hosts in its current state")
        host_plan = self._campaign_host(campaign, host_id)
        if not host_plan.remediation_id:
            raise ValueError("Campaign host has no remediation proposal")
        self.reject_remediation(host_plan.remediation_id, actor)
        campaign = self._sync_campaign(self._campaign(campaign_id))
        self.audit(
            actor,
            "campaign.host_rejected",
            "campaign",
            campaign.id,
            {"host_id": host_id, "remediation_id": host_plan.remediation_id},
        )
        return campaign

    def prepare_campaign_execution(
        self,
        campaign_id: str,
        actor: str,
    ) -> Tuple[PatchCampaign, List[DurableJob]]:
        with self.repository.transaction():
            campaign = self._sync_campaign(self._campaign_for_update(campaign_id))
            remediations = {
                host_plan.remediation_id: self._remediation(
                    host_plan.remediation_id
                )
                for host_plan in campaign.hosts
                if host_plan.remediation_id
            }
            batch = TrustedChangeGate.campaign_batch(
                campaign,
                remediations,
            )
            for changed_host_id in batch.plan_changed_host_ids:
                changed_plan = self._campaign_host(campaign, changed_host_id)
                changed_plan.state = CampaignHostState.PLAN_CHANGED
                changed_plan.failure_summary = GateDecision.deny(
                    GateCode.CAMPAIGN_PLAN_CHANGED
                ).message
                changed_plan.updated_at = utc_now()
            self._raise_gate_denial(batch.decision)
            selected_host_ids = set(batch.host_ids)
            jobs: List[DurableJob] = []
            for host_plan in campaign.hosts:
                if host_plan.host_id not in selected_host_ids:
                    continue
                if not host_plan.remediation_id:
                    continue
                remediation = self._remediation(host_plan.remediation_id)
                try:
                    self._validate_campaign_plan_binding(host_plan, remediation)
                    job = self.prepare_remediation_job(
                        host_plan.remediation_id,
                        actor,
                        campaign_id=campaign.id,
                        sync_campaigns=False,
                    )
                except GateDenied as error:
                    host_plan.state = (
                        CampaignHostState.PLAN_CHANGED
                        if error.decision.category == "approval_validation"
                        else CampaignHostState.BLOCKED
                    )
                    host_plan.failure_summary = self._redact_text(
                        str(error),
                        host_plan.host_id,
                    )
                    host_plan.updated_at = utc_now()
                    continue
                jobs.append(job)
            if not jobs:
                self._refresh_campaign_state(campaign)
                self.repository.save_campaign(campaign)
                self._raise_gate_denial(
                    GateDecision.deny(
                        GateCode.CAMPAIGN_NO_APPROVED_HOSTS,
                    )
                )
            campaign = TrustedChangeGate.start_campaign_batch(
                campaign,
                {job.host_id: job for job in jobs if job.host_id},
                utc_now(),
            )
            self.repository.save_campaign(campaign)
            self.audit(
                actor,
                "campaign.execution_queued",
                "campaign",
                campaign.id,
                {"job_ids": [job.id for job in jobs]},
            )
        return campaign, jobs

    def cancel_campaign(self, campaign_id: str, actor: str) -> PatchCampaign:
        with self.repository.transaction():
            campaign = self._sync_campaign(self._campaign_for_update(campaign_id))
            if campaign.status in (
                CampaignStatus.SUCCEEDED,
                CampaignStatus.FAILED,
                CampaignStatus.CANCELED,
            ) or (
                campaign.status == CampaignStatus.PARTIALLY_SUCCEEDED
                and all(
                    host.state
                    in (
                        CampaignHostState.SUCCEEDED,
                        CampaignHostState.FAILED,
                        CampaignHostState.CANCELED,
                        CampaignHostState.REJECTED,
                        CampaignHostState.BLOCKED,
                        CampaignHostState.NO_ACTION,
                    )
                    for host in campaign.hosts
                )
            ):
                raise ValueError("Completed campaigns cannot be canceled")
            has_running = False
            now = utc_now()
            for host_plan in campaign.hosts:
                if host_plan.state in (
                    CampaignHostState.SUCCEEDED,
                    CampaignHostState.FAILED,
                    CampaignHostState.NO_ACTION,
                ):
                    continue
                job = (
                    self.repository.cancel_job(host_plan.job_id, now)
                    if host_plan.job_id
                    else None
                )
                if job and job.status == "running":
                    has_running = True
                    host_plan.state = CampaignHostState.RUNNING
                    host_plan.updated_at = now
                    continue
                if job and job.status not in ("canceled", "queued", "scheduled"):
                    host_plan.updated_at = now
                    continue
                if host_plan.remediation_id:
                    remediation = self._remediation_for_update(host_plan.remediation_id)
                    if remediation.execution_state in (
                        "not_started",
                        "queued",
                        "waiting_for_window",
                    ):
                        remediation.execution_state = "canceled"
                        remediation.updated_at = now
                        self.repository.save_remediation(remediation)
                host_plan.state = CampaignHostState.CANCELED
                host_plan.updated_at = now
            campaign.status = (
                CampaignStatus.CANCELLING
                if has_running
                else CampaignStatus.CANCELED
            )
            campaign.canceled_by = actor
            campaign.canceled_at = now
            campaign.updated_at = now
            self.repository.save_campaign(campaign)
            self.audit(actor, "campaign.canceled", "campaign", campaign.id)
        return campaign

    def fail_job(
        self,
        job: DurableJob,
        error: str,
        host_id: str,
        lease_owner: Optional[str] = None,
        retryable: bool = False,
        category: str = "job_execution",
    ) -> DurableJob:
        now = utc_now()
        safe_error = self._redact_text(error, host_id)
        will_retry = retryable and job.attempts < job.max_attempts
        job.last_failure = JobFailure(
            failed_at=now,
            attempt=job.attempts,
            category=category,
            message=safe_error[:2000],
            retryable=will_retry,
        )
        job.updated_at = now
        job.lease_owner = None
        job.lease_expires_at = None
        if will_retry:
            job.status = "queued"
            job.error = None
            job.current_phase = "retry_scheduled"
            job.completed_at = None
        else:
            job.status = "failed"
            job.error = safe_error[:2000]
            job.current_phase = "failed"
            job.completed_at = now
        saved = self.repository.save_job(job, lease_owner=lease_owner)
        if not saved:
            return self._job(job.id)
        if will_retry:
            self.audit(
                "system",
                "job.retry_scheduled",
                "job",
                job.id,
                {
                    "attempt": job.attempts,
                    "max_attempts": job.max_attempts,
                    "error": job.last_failure.message,
                },
            )
            return job
        self._record_terminal_job_failure(job, host_id)
        return job

    def _record_terminal_job_failure(
        self,
        job: DurableJob,
        host_id: Optional[str],
    ) -> None:
        self.create_alert(
            severity=Severity.CRITICAL,
            title="%s job failed" % job.job_type.title(),
            message=job.error or "Job failed",
            host_id=host_id,
            job_id=job.id,
        )
        self.audit(
            "system",
            "job.failed",
            "job",
            job.id,
            {
                "error": job.error,
                "attempts": job.attempts,
                "max_attempts": job.max_attempts,
            },
        )

    async def _create_rollback_snapshot(
        self,
        job: DurableJob,
        remediation: Remediation,
        host: Host,
    ) -> RollbackSnapshot:
        now = utc_now()
        snapshot = RollbackSnapshot(
            id=new_id("rollback-snapshot"),
            host_id=host.id,
            remediation_id=remediation.id,
            provider=SnapshotPlatform(host.snapshot_platform),
            state=RollbackSnapshotState.CREATING,
            created_at=now,
            updated_at=now,
        )
        self.repository.save_rollback_snapshot(snapshot)
        result = await self.snapshot_provider.create_snapshot(
            host,
            remediation,
            snapshot,
            job.id,
        )
        self.repository.save_log_events(result.events)
        snapshot.updated_at = utc_now()
        creation = TrustedChangeGate.snapshot_creation(
            result.success,
            self._redact_text(result.summary, host.id),
        )
        if not creation.allowed:
            snapshot.failure_summary = self._redact_text(result.summary, host.id)
            self.repository.save_rollback_snapshot(snapshot)
            raise NonRetryableJobError(
                creation.message,
                creation.category,
            )
        snapshot.external_snapshot_id = result.external_snapshot_id
        snapshot.state = RollbackSnapshotState.CREATED
        self.repository.save_rollback_snapshot(snapshot)
        self.audit(
            "system",
            "snapshot.created",
            "rollback_snapshot",
            snapshot.id,
            {
                "host_id": host.id,
                "remediation_id": remediation.id,
                "provider": snapshot.provider,
            },
        )
        return snapshot

    async def _finish_snapshot_protected_execution(
        self,
        job: DurableJob,
        remediation: Remediation,
        host: Host,
        snapshot: RollbackSnapshot,
        result: Any,
        lease_owner: str,
    ) -> Any:
        job.current_phase = "post_reboot_health_check"
        job.progress_percent = 80
        job.updated_at = utc_now()
        self._save_claimed_job(job, lease_owner)
        health = await self.snapshot_provider.run_health_checks(
            host,
            remediation,
            snapshot,
            job.id,
        )
        result.events.extend(health.events)
        result.phases.append(
            execution_phase(
                "post_reboot_health_check",
                "succeeded" if health.healthy else "failed",
                health.summary,
            )
        )
        snapshot.health_check_result = health.checks
        snapshot.updated_at = utc_now()
        health_decision = TrustedChangeGate.post_change_health(health.healthy)
        snapshot.state = health_decision.snapshot_state
        if health_decision.action == PostChangeAction.COMPLETE:
            snapshot.delete_after = utc_now() + timedelta(
                days=host.snapshot_retention_days
            )
            self.repository.save_rollback_snapshot(snapshot)
            delete_job = self._schedule_snapshot_delete_job(snapshot, host)
            result.phases.append(
                execution_phase(
                    "snapshot_delete_scheduled",
                    "succeeded",
                    "Snapshot deletion scheduled for %s."
                    % snapshot.delete_after.isoformat(),
                )
            )
            result.summary = (
                "%s Snapshot deletion job %s is scheduled."
                % (result.summary, delete_job.id)
            )
            return result

        snapshot.failure_summary = self._redact_text(health.summary, host.id)
        self.repository.save_rollback_snapshot(snapshot)
        rollback = await self.snapshot_provider.rollback_snapshot(
            host,
            remediation,
            snapshot,
            job.id,
        )
        result.events.extend(rollback.events)
        result.phases.append(
            execution_phase(
                "snapshot_rollback",
                "succeeded" if rollback.success else "failed",
                rollback.summary,
            )
        )
        snapshot.updated_at = utc_now()
        snapshot.failure_summary = self._redact_text(rollback.summary, host.id)
        rollback_decision = TrustedChangeGate.rollback_result(rollback.success)
        snapshot.state = rollback_decision.snapshot_state
        self.repository.save_rollback_snapshot(snapshot)
        if rollback.success:
            self.create_alert(
                severity=Severity.CRITICAL,
                title="Snapshot rollback completed",
                message=(
                    "Post-reboot health checks failed. Snapshot rollback completed "
                    "and human intervention is required."
                ),
                host_id=host.id,
                job_id=job.id,
            )
            result.success = False
            result.summary = rollback_decision.summary
        else:
            self.create_alert(
                severity=Severity.CRITICAL,
                title="Snapshot rollback failed",
                message=(
                    "Post-reboot health checks failed and snapshot rollback failed. "
                    "Block further execution until human intervention is complete."
                ),
                host_id=host.id,
                job_id=job.id,
            )
            result.success = False
            result.summary = rollback_decision.summary
        result.failure_actions_taken.extend(
            [
                "snapshot rollback attempted",
                "operator alert recorded",
                "human intervention required",
            ]
        )
        return result

    def _schedule_snapshot_delete_job(
        self,
        snapshot: RollbackSnapshot,
        host: Host,
    ) -> DurableJob:
        key = "snapshot-delete:%s" % snapshot.id
        existing = self.repository.get_job_by_idempotency(key)
        if existing:
            return existing
        now = utc_now()
        job = DurableJob(
            id=new_id("job"),
            job_type="snapshot_delete",
            status="scheduled",
            host_id=host.id,
            remediation_id=snapshot.remediation_id,
            idempotency_key=key,
            current_phase="waiting_for_retention",
            result={
                "rollback_snapshot_id": snapshot.id,
                "delete_after": snapshot.delete_after.isoformat()
                if snapshot.delete_after
                else None,
            },
            created_at=now,
            updated_at=now,
        )
        self.repository.save_job(job)
        self.audit(
            "system",
            "snapshot.delete_scheduled",
            "rollback_snapshot",
            snapshot.id,
            {"job_id": job.id, "delete_after": snapshot.delete_after},
        )
        return job

    async def _run_with_heartbeat(
        self,
        job_id: str,
        lease_owner: str,
        operation: Callable[[], Awaitable[ResultT]],
    ) -> ResultT:
        work = asyncio.create_task(operation())
        heartbeat = asyncio.create_task(
            self._heartbeat_loop(job_id, lease_owner)
        )
        done, _ = await asyncio.wait(
            {work, heartbeat},
            return_when=asyncio.FIRST_COMPLETED,
        )
        if work in done:
            heartbeat.cancel()
            await asyncio.gather(heartbeat, return_exceptions=True)
            return await work
        work.cancel()
        await asyncio.gather(work, return_exceptions=True)
        return await heartbeat

    async def _heartbeat_loop(self, job_id: str, lease_owner: str) -> None:
        while True:
            await asyncio.sleep(self.job_heartbeat_seconds)
            self._assert_job_lease(job_id, lease_owner)

    def _assert_job_lease(self, job_id: str, lease_owner: str) -> None:
        heartbeat_at = utc_now()
        job = self.repository.heartbeat_job(
            job_id,
            lease_owner,
            heartbeat_at,
            heartbeat_at + timedelta(seconds=self.job_lease_seconds),
        )
        if not job:
            raise JobLeaseLost("Job lease ownership was lost")

    def _save_claimed_job(self, job: DurableJob, lease_owner: str) -> None:
        if not self.repository.save_job(job, lease_owner=lease_owner):
            raise JobLeaseLost("Job lease ownership was lost")

    def create_alert(
        self,
        severity: Severity,
        title: str,
        message: str,
        host_id: Optional[str] = None,
        job_id: Optional[str] = None,
    ) -> Alert:
        safe_message = self._redact_text(message, host_id)
        alert = Alert(
            id=new_id("alert"),
            severity=severity,
            title=title,
            message=safe_message[:2000],
            host_id=host_id,
            job_id=job_id,
            created_at=utc_now(),
        )
        return self.repository.save_alert(alert)

    def audit(
        self,
        actor: str,
        action: str,
        target_type: str,
        target_id: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
    ) -> AuditEvent:
        event = AuditEvent(
            id=new_id("audit"),
            actor=actor,
            action=action,
            target_type=target_type,
            target_id=target_id,
            details=sanitize_audit_details(details),
            created_at=utc_now(),
        )
        return self.repository.save_audit(event)

    @staticmethod
    def _raise_gate_denial(decision: GateDecision) -> None:
        if not decision.allowed:
            raise GateDenied(decision)

    def _host(self, host_id: str) -> Host:
        host = self.repository.get_host(host_id)
        if not host:
            raise ValueError("Host not found")
        return host

    def _validate_host_input(self, host_input: HostInput) -> None:
        platform = SnapshotPlatform(host_input.snapshot_platform)
        if platform == SnapshotPlatform.NONE:
            return
        if not host_input.snapshot_credential_id:
            raise ValueError(
                "Snapshot credential is required when rollback protection is configured"
            )
        if not host_input.snapshot_target_id and not host_input.snapshot_provider_metadata:
            raise ValueError(
                "Snapshot target ID or provider metadata is required when rollback protection is configured"
            )
        record = self.repository.get_credential_record(
            host_input.snapshot_credential_id
        )
        if not record:
            raise ValueError("Snapshot credential not found")
        credential = record[0]
        allowed_types = SNAPSHOT_CREDENTIAL_TYPES.get(platform, set())
        credential_type = CredentialType(credential.credential_type)
        if credential_type not in allowed_types:
            allowed = ", ".join(sorted(item.value for item in allowed_types))
            raise ValueError(
                "Snapshot credential type must match %s. Allowed type(s): %s"
                % (platform.value, allowed)
            )
        if (
            platform == SnapshotPlatform.AWS
            and credential_type == CredentialType.AWS_ROLE
            and not (
                credential.metadata.get("roleArn")
                or credential.metadata.get("role_arn")
            )
        ):
            raise ValueError("AWS role credentials require roleArn metadata")

    def _host_has_active_rollback_failure(self, host_id: str) -> bool:
        return any(
            alert.host_id == host_id
            and not alert.acknowledged
            and severity_text(alert.severity) == "critical"
            and "rollback" in alert.title.lower()
            for alert in self.repository.list_alerts()
        )

    def _scan(self, scan_id: Optional[str]) -> ScanJob:
        scan = self.repository.get_scan(scan_id or "")
        if not scan:
            raise ValueError("Scan not found")
        return scan

    def _job(self, job_id: str) -> DurableJob:
        job = self.repository.get_job(job_id)
        if not job:
            raise ValueError("Job not found")
        return job

    def _redact_text(
        self,
        value: str,
        host_id: Optional[str] = None,
    ) -> str:
        host = self.repository.get_host(host_id or "") if host_id else None
        return redact_text(value, host)

    def _remediation(self, remediation_id: Optional[str]) -> Remediation:
        remediation = self.repository.get_remediation(remediation_id or "")
        if not remediation:
            raise ValueError("Remediation not found")
        return remediation

    def _remediation_for_update(self, remediation_id: Optional[str]) -> Remediation:
        remediation = self.repository.get_remediation_for_update(remediation_id or "")
        if not remediation:
            raise ValueError("Remediation not found")
        return remediation

    def _campaign(self, campaign_id: str) -> PatchCampaign:
        campaign = self.repository.get_campaign(campaign_id)
        if not campaign:
            raise ValueError("Campaign not found")
        return campaign

    def _campaign_for_update(self, campaign_id: str) -> PatchCampaign:
        campaign = self.repository.get_campaign_for_update(campaign_id)
        if not campaign:
            raise ValueError("Campaign not found")
        return campaign

    @staticmethod
    def _campaign_host(
        campaign: PatchCampaign,
        host_id: str,
    ) -> CampaignHostPlan:
        host_plan = next(
            (item for item in campaign.hosts if item.host_id == host_id),
            None,
        )
        if not host_plan:
            raise ValueError("Host is not selected for this campaign")
        return host_plan

    def _validate_campaign_plan_binding(
        self,
        host_plan: CampaignHostPlan,
        remediation: Remediation,
    ) -> None:
        _, remediation = self._ensure_current_remediation_plan(remediation)
        decision = TrustedChangeGate.campaign_plan_binding(
            host_plan,
            remediation,
        )
        if not decision.allowed:
            host_plan.state = CampaignHostState.PLAN_CHANGED
            host_plan.failure_summary = decision.message
            host_plan.updated_at = utc_now()
            campaign = self._campaign(host_plan.campaign_id)
            self._sync_campaign(campaign)
            self._raise_gate_denial(decision)

    def _ensure_current_remediation_plan(
        self,
        remediation: Remediation,
    ) -> Tuple[PlanReconciliation, Remediation]:
        reconciliation = TrustedChangeGate.reconcile_plan(
            remediation,
            utc_now(),
        )
        updated = reconciliation.remediation
        if not reconciliation.changed:
            return reconciliation, updated
        self.repository.save_remediation(updated)
        self.audit(
            "system",
            "remediation.approval_invalidated",
            "remediation",
            updated.id,
            {
                "previous_plan_version": reconciliation.previous_plan_version,
                "previous_plan_hash": reconciliation.previous_plan_hash,
                "plan_version": updated.plan_version,
                "plan_hash": updated.plan_hash,
            },
        )
        return reconciliation, updated

    def _trusted_execution_decision(
        self,
        remediation: Remediation,
        host: Host,
        job: Optional[DurableJob] = None,
    ) -> Tuple[GateDecision, Remediation]:
        reconciliation, updated = self._ensure_current_remediation_plan(
            remediation
        )
        if reconciliation.changed:
            return reconciliation.decision, updated
        return (
            TrustedChangeGate.execution_eligibility(
                updated,
                host,
                job=job,
                active_rollback_failure=self._host_has_active_rollback_failure(
                    host.id
                ),
            ),
            updated,
        )

    def _mark_campaign_proposal_running(
        self,
        campaign_id: str,
        host_id: str,
    ) -> None:
        campaign = self._campaign(campaign_id)
        host_plan = self._campaign_host(campaign, host_id)
        host_plan.state = CampaignHostState.PROPOSAL_RUNNING
        host_plan.updated_at = utc_now()
        campaign.status = CampaignStatus.PROPOSING
        campaign.updated_at = utc_now()
        self.repository.save_campaign(campaign)

    def _attach_campaign_proposal(
        self,
        campaign_id: str,
        host: Host,
        remediation: Optional[Remediation],
    ) -> None:
        campaign = self._campaign(campaign_id)
        host_plan = self._campaign_host(campaign, host.id)
        now = utc_now()
        host_plan.job_id = None
        host_plan.failure_summary = None
        if remediation:
            host_plan.scan_id = remediation.scan_id
            host_plan.remediation_id = remediation.id
            host_plan.plan_version = remediation.plan_version
            host_plan.plan_hash = remediation.plan_hash
            host_plan.approval_state = remediation.approval_state
            host_plan.reboot_approval_state = remediation.reboot_approval_state
            host_plan.state = CampaignHostState.AWAITING_APPROVAL
            if remediation.id not in campaign.remediation_ids:
                campaign.remediation_ids.append(remediation.id)
            campaign.batch_size = TrustedChangeGate.campaign_rollout_limit(
                [self._host(item.host_id) for item in campaign.hosts],
                [
                    item
                    for item in self.repository.list_remediations()
                    if item.id in campaign.remediation_ids
                ],
            )
            campaign.total_batches = int(
                math.ceil(len(campaign.hosts) / campaign.batch_size)
            )
        else:
            host_plan.state = CampaignHostState.NO_ACTION
            host_plan.approval_state = "not_required"
            host_plan.reboot_approval_state = "not_required"
        host_plan.updated_at = now
        campaign.updated_at = now
        self.repository.save_campaign(campaign)
        self._sync_campaign(campaign)

    def _mark_campaign_proposal_failed(
        self,
        campaign_id: str,
        host_id: str,
        error: str,
    ) -> None:
        campaign = self._campaign(campaign_id)
        host_plan = self._campaign_host(campaign, host_id)
        host_plan.state = CampaignHostState.FAILED
        host_plan.failure_summary = self._redact_text(error, host_id)[:2000]
        host_plan.updated_at = utc_now()
        campaign.updated_at = utc_now()
        self.repository.save_campaign(campaign)
        self._sync_campaign(campaign)

    def _sync_campaigns_for_remediation(
        self,
        remediation_id: str,
        stop_remaining: bool = False,
    ) -> None:
        for campaign in self.repository.list_campaigns():
            if remediation_id not in {
                item.remediation_id for item in campaign.hosts
            }:
                continue
            if stop_remaining:
                self._stop_remaining_campaign_hosts(campaign, remediation_id)
            self._sync_campaign(campaign)

    def _stop_remaining_campaign_hosts(
        self,
        campaign: PatchCampaign,
        failed_remediation_id: str,
    ) -> None:
        failed = self._remediation(failed_remediation_id)
        if not TrustedChangeGate.stop_campaign_after_failure(failed):
            return
        now = utc_now()
        for host_plan in campaign.hosts:
            if host_plan.remediation_id == failed_remediation_id:
                continue
            if host_plan.state in (
                CampaignHostState.SUCCEEDED,
                CampaignHostState.FAILED,
                CampaignHostState.NO_ACTION,
                CampaignHostState.RUNNING,
            ):
                continue
            job = (
                self.repository.cancel_job(
                    host_plan.job_id,
                    now,
                    phase="canceled_after_campaign_failure",
                )
                if host_plan.job_id
                else None
            )
            if job and job.status == "running":
                host_plan.state = CampaignHostState.RUNNING
                host_plan.updated_at = now
                continue
            if host_plan.remediation_id:
                remediation = self._remediation(host_plan.remediation_id)
                if remediation.execution_state in (
                    "not_started",
                    "queued",
                    "waiting_for_window",
                ):
                    remediation.execution_state = "canceled"
                    remediation.updated_at = now
                    self.repository.save_remediation(remediation)
            host_plan.state = CampaignHostState.CANCELED
            host_plan.failure_summary = (
                "Canceled because another campaign host failed"
            )
            host_plan.updated_at = now
        campaign.updated_at = now
        self.repository.save_campaign(campaign)

    def _sync_campaign(self, campaign: PatchCampaign) -> PatchCampaign:
        now = utc_now()
        if not campaign.hosts:
            remediation_by_host = {
                item.host_id: item
                for item in self.repository.list_remediations()
                if item.id in campaign.remediation_ids
            }
            campaign.hosts = [
                CampaignHostPlan(
                    id=new_id("campaign-host"),
                    campaign_id=campaign.id,
                    host_id=host_id,
                    hostname=self._host(host_id).name,
                    remediation_id=(
                        remediation_by_host[host_id].id
                        if host_id in remediation_by_host
                        else None
                    ),
                    plan_version=(
                        remediation_by_host[host_id].plan_version
                        if host_id in remediation_by_host
                        else None
                    ),
                    plan_hash=(
                        remediation_by_host[host_id].plan_hash
                        if host_id in remediation_by_host
                        else None
                    ),
                    state=(
                        CampaignHostState.AWAITING_APPROVAL
                        if host_id in remediation_by_host
                        else CampaignHostState.SELECTED
                    ),
                    created_at=campaign.created_at,
                    updated_at=now,
                )
                for host_id in campaign.host_ids
            ]
        remediations: Dict[str, Remediation] = {}
        jobs: Dict[str, DurableJob] = {}
        for host_plan in campaign.hosts:
            if host_plan.remediation_id:
                remediation = self.repository.get_remediation(
                    host_plan.remediation_id
                )
                if remediation:
                    _, remediation = self._ensure_current_remediation_plan(
                        remediation
                    )
                    remediations[remediation.id] = remediation
            if host_plan.job_id:
                job = self.repository.get_job(host_plan.job_id)
                if job:
                    jobs[job.id] = job
        projected = TrustedChangeGate.project_campaign(
            campaign,
            remediations,
            jobs,
            now,
        )
        self.repository.save_campaign(projected)
        return projected

    def _refresh_campaign_state(self, campaign: PatchCampaign) -> None:
        self._sync_campaign(campaign)



def next_cron_run(expression: str, timezone_name: str, after: datetime) -> datetime:
    parts = expression.split()
    if len(parts) != 5:
        raise ValueError("Cron expression must have exactly five fields")
    zone = ZoneInfo(timezone_name)
    local = after.astimezone(zone)
    return croniter(expression, local).get_next(datetime).astimezone(ZoneInfo("UTC"))


def execution_phase(name: str, state: str, summary: str) -> ExecutionPhase:
    return ExecutionPhase(name=name, state=state, summary=summary)


def severity_text(value: Any) -> str:
    return value.value if isinstance(value, Severity) else str(value)


def agent_events(
    host: Host,
    job_id: str,
    scan_id: str,
    runs: List[AgentRun],
    messages: List[AgentMessage],
) -> List[StructuredLogEvent]:
    events: List[StructuredLogEvent] = []
    for run in runs:
        events.append(
            sanitize_log_event(
                StructuredLogEvent(
                    id=new_id("log"),
                    timestamp=run.created_at,
                    duration_ms=run.latency_ms,
                    host_id=host.id,
                    job_id=job_id,
                    scan_id=scan_id,
                    agent_run_id=run.id,
                    event_type="agent_run",
                    evidence_category="ai_analysis",
                    severity=Severity.INFO,
                    status=run.status,
                    stdout=str(run.output)[:65536],
                    source="agent:%s" % run.agent.name,
                    externally_processed=run.externally_processed,
                    remediation_relevance="analysis",
                    correlation_ids={"scan_id": scan_id, "agent_run_id": run.id},
                ),
                host,
            )
        )
    for message in messages:
        events.append(
            sanitize_log_event(
                StructuredLogEvent(
                    id=new_id("log"),
                    timestamp=message.created_at,
                    host_id=host.id,
                    job_id=job_id,
                    scan_id=scan_id,
                    event_type="agent_message",
                    evidence_category="agent_conversation",
                    severity=Severity.INFO,
                    status=message.response,
                    stdout=message.reasoning,
                    source="%s->%s" % (message.from_agent, message.to_agent),
                    remediation_relevance="analysis",
                    correlation_ids={"scan_id": scan_id, "message_id": message.id},
                ),
                host,
            )
        )
    return events
