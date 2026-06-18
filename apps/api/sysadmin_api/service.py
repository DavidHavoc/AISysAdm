from __future__ import annotations

import asyncio
import math
from datetime import datetime, time, timedelta
from typing import Any, Awaitable, Callable, Dict, List, Optional, Tuple, TypeVar
from uuid import uuid4
from zoneinfo import ZoneInfo

from croniter import croniter

from .agents import MultiAgentWorkflow, remediation_plan_hash
from .collector import HostCollector
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
    DurableJob,
    Host,
    HostInput,
    HostSchedule,
    HostScheduleInput,
    JobFailure,
    LogPage,
    MaintenanceWindow,
    PatchCampaign,
    Remediation,
    ScanJob,
    ScanRequest,
    Severity,
    StructuredLogEvent,
    utc_now,
)
from .repository import Repository


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
        log_retention_days: int = 90,
        job_lease_seconds: int = 120,
        job_heartbeat_seconds: int = 30,
    ) -> None:
        self.repository = repository
        self.collector = collector
        self.workflow = workflow
        self.executor = executor
        self.log_retention_days = log_retention_days
        self.job_lease_seconds = job_lease_seconds
        self.job_heartbeat_seconds = min(
            job_heartbeat_seconds,
            max(1, job_lease_seconds // 2),
        )

    def list_hosts(self) -> List[Host]:
        return sorted(self.repository.list_hosts(), key=lambda item: item.name)

    def create_host(self, host_input: HostInput, actor: str = "system") -> Host:
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
        self.audit(actor, "host.created", "host", host.id, {"name": host.name})
        return host

    def update_host(
        self,
        host_id: str,
        host_input: HostInput,
        actor: str,
    ) -> Host:
        current = self._host(host_id)
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
        self.audit(actor, "host.deleted", "host", host_id, {"name": host.name})

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
            failed = self.fail_job(
                job,
                str(error),
                host.id,
                lease_owner=owner,
                retryable=not isinstance(error, NonRetryableJobError),
                category=getattr(error, "category", "scan_execution"),
            )
            scan.status = "queued" if failed.status == "queued" else "failed"
            scan.error = str(error)[:2000]
            scan.updated_at = utc_now()
            self.repository.save_scan(scan)
            if scan.campaign_id and failed.status == "failed":
                self._mark_campaign_proposal_failed(
                    scan.campaign_id,
                    host.id,
                    str(error),
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
            agent_events(host.id, job.id, scan.id, result.runs, result.messages)
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
        self._ensure_current_remediation_plan(remediation)
        if remediation.approval_state != "pending":
            raise ValueError("Only pending remediations can be approved")
        self._validate_approval_request(host, remediation, request)
        now = utc_now()
        remediation.approval_state = "approved"
        remediation.approved_by = actor
        remediation.approved_at = now
        remediation.approved_plan_version = remediation.plan_version
        remediation.approved_plan_hash = remediation.plan_hash
        remediation.reboot_approval_state = (
            "not_required"
            if remediation.reboot_assessment.status == "not_expected"
            else "pending"
        )
        remediation.reboot_approved_by = None
        remediation.reboot_approved_at = None
        remediation.reboot_approved_plan_version = None
        remediation.reboot_approved_plan_hash = None
        remediation.reboot_assessment.approved_if_required = False
        remediation.updated_at = now
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
        self._ensure_current_remediation_plan(remediation)
        if remediation.approval_state != "approved":
            raise ValueError("The remediation plan must be approved before reboot approval")
        self._validate_approval_request(host, remediation, request)
        if remediation.reboot_assessment.status == "not_expected":
            raise ValueError("This remediation does not require reboot approval")
        if host.patch_policy.reboot_policy == "never":
            remediation.reboot_approval_state = "blocked"
            remediation.execution_state = "blocked"
            remediation.updated_at = utc_now()
            self.repository.save_remediation(remediation)
            self._sync_campaigns_for_remediation(remediation.id)
            raise ValueError("Host policy forbids reboot risk that cannot be excluded")
        now = utc_now()
        remediation.reboot_approval_state = "approved"
        remediation.reboot_approved_by = actor
        remediation.reboot_approved_at = now
        remediation.reboot_approved_plan_version = remediation.plan_version
        remediation.reboot_approved_plan_hash = remediation.plan_hash
        remediation.reboot_assessment.approved_if_required = True
        remediation.updated_at = now
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
    ) -> DurableJob:
        remediation = self._remediation(remediation_id)
        host = self._host(remediation.host_id)
        self._ensure_current_remediation_plan(remediation)
        approval_error = self._remediation_approval_error(remediation, host)
        if approval_error:
            raise ValueError(approval_error)
        now = utc_now()
        key = "remediation:%s:%s" % (
            remediation.id,
            remediation.plan_hash,
        )
        existing = self.repository.get_job_by_idempotency(key)
        if existing:
            if existing.campaign_id != campaign_id:
                raise ValueError(
                    "This exact remediation plan already has an execution job"
                )
            return existing
        approval_scope = (
            "patch_only"
            if remediation.reboot_assessment.status == "not_expected"
            else "patch_and_reboot_if_required"
        )
        job = DurableJob(
            id=new_id("job"),
            job_type="remediation",
            status=(
                "queued"
                if self._timing_allows(remediation, now)
                else "scheduled"
            ),
            host_id=host.id,
            scan_id=remediation.scan_id,
            remediation_id=remediation.id,
            campaign_id=campaign_id,
            approved_plan_version=remediation.plan_version,
            approved_plan_hash=remediation.plan_hash,
            approval_scope=approval_scope,
            idempotency_key=key,
            created_at=now,
            updated_at=now,
        )
        remediation.execution_state = (
            "queued" if job.status == "queued" else "waiting_for_window"
        )
        self.repository.save_remediation(remediation)
        self.repository.save_job(job)
        self.audit(
            actor,
            "remediation.execution_queued",
            "remediation",
            remediation.id,
            {"job_id": job.id, "plan_hash": remediation.plan_hash},
        )
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
                existing.status = "canceled"
                existing.current_phase = "canceled"
                existing.completed_at = utc_now()
                existing.updated_at = utc_now()
                remediation.execution_state = "canceled"
                remediation.updated_at = utc_now()
                self.repository.save_job(existing)
                self.repository.save_remediation(remediation)
                self._sync_campaigns_for_remediation(remediation.id)
                return existing
        if existing.status == "queued" and not self._timing_allows(
            remediation,
            utc_now(),
        ):
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
        plan_changed = self._ensure_current_remediation_plan(remediation)
        binding_error = (
            "Remediation approved plan content changed after approval"
            if plan_changed
            else self._remediation_binding_error(job, remediation, host)
        )
        if binding_error:
            remediation.execution_state = "blocked"
            remediation.updated_at = utc_now()
            self.repository.save_remediation(remediation)
            failed = self.fail_job(
                job,
                binding_error,
                host.id,
                lease_owner=owner,
                retryable=False,
                category="approval_validation",
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
            failed = self.fail_job(
                job,
                str(error),
                host.id,
                lease_owner=owner,
                retryable=retryable,
                category=getattr(error, "category", "remediation_execution"),
            )
            remediation.execution_state = (
                "queued" if failed.status == "queued" else "failed"
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
            raise NonRetryableJobError(
                "Approved scan snapshot is unavailable",
                "approval_validation",
            )
        current = await self.collector.collect(
            host,
            job.id,
            remediation.scan_id or "",
        )
        self._assert_job_lease(job.id, lease_owner)
        self.repository.save_snapshot(current.snapshot)
        self.repository.save_log_events(current.events)
        if material_state_changed(original_snapshot, current.snapshot):
            raise NonRetryableJobError(
                "Host package, service, or reboot state changed after approval",
                "safety_validation",
            )

        remediation = self._remediation(job.remediation_id)
        host = self._host(remediation.host_id)
        self._ensure_current_remediation_plan(remediation)
        binding_error = self._remediation_binding_error(job, remediation, host)
        if binding_error:
            remediation.execution_state = "blocked"
            remediation.updated_at = utc_now()
            self.repository.save_remediation(remediation)
            raise NonRetryableJobError(binding_error, "approval_validation")

        job.current_phase = "ansible_execution"
        job.progress_percent = 30
        job.updated_at = utc_now()
        self._save_claimed_job(job, lease_owner)
        self._assert_job_lease(job.id, lease_owner)
        result = await self.executor.execute(host, remediation, job.id)
        self._assert_job_lease(job.id, lease_owner)
        self.repository.save_log_events(result.events)
        remediation.result = result
        remediation.execution_state = "succeeded" if result.success else "failed"
        remediation.updated_at = utc_now()
        self.repository.save_remediation(remediation)
        if not result.success:
            if execution_failure_is_non_retryable(result.summary, result.changed):
                raise NonRetryableJobError(
                    result.summary,
                    execution_failure_category(result.summary),
                )
            raise RuntimeError(result.summary)

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
            if self._timing_allows(remediation, current):
                job.status = "queued"
                job.current_phase = None
                job.updated_at = current
                self.repository.save_job(job)
                self._sync_campaigns_for_remediation(remediation.id)
                released.append(job)
        return released

    def recover_expired_jobs(
        self,
        now: Optional[datetime] = None,
    ) -> List[DurableJob]:
        current = now or utc_now()
        recovered, exhausted = self.repository.recover_expired_jobs(current)
        for job in recovered:
            if job.job_type == "scan":
                scan = self._scan(job.scan_id)
                scan.status = "queued"
                scan.error = job.last_failure.message if job.last_failure else None
                scan.updated_at = current
                self.repository.save_scan(scan)
            elif job.job_type == "remediation":
                remediation = self._remediation(job.remediation_id)
                remediation.execution_state = "queued"
                remediation.updated_at = current
                self.repository.save_remediation(remediation)
            self.audit(
                "scheduler",
                "job.lease_recovered",
                "job",
                job.id,
                {"attempt": job.attempts},
            )
        for job in exhausted:
            if job.job_type == "scan":
                scan = self._scan(job.scan_id)
                scan.status = "failed"
                scan.error = job.error
                scan.updated_at = current
                self.repository.save_scan(scan)
            elif job.job_type == "remediation":
                remediation = self._remediation(job.remediation_id)
                remediation.execution_state = "failed"
                remediation.updated_at = current
                self.repository.save_remediation(remediation)
            self._record_terminal_job_failure(job, job.host_id)
        return recovered

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
        batch_size = min(host.patch_policy.max_batch_size for host in hosts)
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
        campaign = self._sync_campaign(self._campaign(campaign_id))
        if campaign.status in (
            CampaignStatus.CANCELLING,
            CampaignStatus.CANCELED,
            CampaignStatus.SUCCEEDED,
            CampaignStatus.FAILED,
        ):
            raise ValueError("Campaign cannot execute in its current state")
        jobs: List[DurableJob] = []
        for host_plan in campaign.hosts:
            if len(jobs) >= campaign.batch_size:
                break
            if host_plan.state != CampaignHostState.APPROVED:
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
                )
            except ValueError as error:
                host_plan.state = CampaignHostState.PLAN_CHANGED
                host_plan.failure_summary = str(error)
                host_plan.updated_at = utc_now()
                continue
            host_plan.job_id = job.id
            host_plan.state = (
                CampaignHostState.QUEUED
                if job.status == "queued"
                else CampaignHostState.SCHEDULED
            )
            host_plan.updated_at = utc_now()
            jobs.append(job)
        if not jobs:
            self._refresh_campaign_state(campaign)
            self.repository.save_campaign(campaign)
            raise ValueError("Campaign has no approved host plans ready to execute")
        campaign.status = CampaignStatus.RUNNING
        campaign.current_batch = min(
            campaign.total_batches,
            campaign.current_batch + 1,
        )
        campaign.updated_at = utc_now()
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
        campaign = self._sync_campaign(self._campaign(campaign_id))
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
        active_jobs = [
            self.repository.get_job(host_plan.job_id or "")
            for host_plan in campaign.hosts
            if host_plan.job_id
        ]
        has_running = any(job and job.status == "running" for job in active_jobs)
        now = utc_now()
        for host_plan in campaign.hosts:
            if host_plan.state in (
                CampaignHostState.SUCCEEDED,
                CampaignHostState.FAILED,
                CampaignHostState.NO_ACTION,
                CampaignHostState.RUNNING,
            ):
                continue
            job = self.repository.get_job(host_plan.job_id or "")
            if job and job.status in ("queued", "scheduled"):
                job.status = "canceled"
                job.current_phase = "canceled"
                job.completed_at = now
                job.updated_at = now
                self.repository.save_job(job)
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
        will_retry = retryable and job.attempts < job.max_attempts
        job.last_failure = JobFailure(
            failed_at=now,
            attempt=job.attempts,
            category=category,
            message=error[:2000],
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
            job.error = error[:2000]
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
        alert = Alert(
            id=new_id("alert"),
            severity=severity,
            title=title,
            message=message[:2000],
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
            details=details or {},
            created_at=utc_now(),
        )
        return self.repository.save_audit(event)

    @staticmethod
    def _timing_allows(remediation: Remediation, current: datetime) -> bool:
        if remediation.execution_timing == "immediate":
            return True
        if not remediation.maintenance_window:
            return False
        return maintenance_window_is_open(remediation.maintenance_window, current)

    def _host(self, host_id: str) -> Host:
        host = self.repository.get_host(host_id)
        if not host:
            raise ValueError("Host not found")
        return host

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

    def _remediation(self, remediation_id: Optional[str]) -> Remediation:
        remediation = self.repository.get_remediation(remediation_id or "")
        if not remediation:
            raise ValueError("Remediation not found")
        return remediation

    def _campaign(self, campaign_id: str) -> PatchCampaign:
        campaign = self.repository.get_campaign(campaign_id)
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

    @staticmethod
    def _validate_approval_request(
        host: Host,
        remediation: Remediation,
        request: ApprovalRequest,
    ) -> None:
        if request.hostname_confirmation != host.name:
            raise ValueError("Typed hostname confirmation does not match")
        if (
            request.plan_version != remediation.plan_version
            or request.plan_hash != remediation.plan_hash
        ):
            raise ValueError("The remediation plan changed and must be reviewed again")

    def _validate_campaign_plan_binding(
        self,
        host_plan: CampaignHostPlan,
        remediation: Remediation,
    ) -> None:
        self._ensure_current_remediation_plan(remediation)
        if remediation.host_id != host_plan.host_id:
            raise ValueError("Campaign remediation host binding is invalid")
        if (
            host_plan.plan_version != remediation.plan_version
            or host_plan.plan_hash != remediation.plan_hash
        ):
            host_plan.state = CampaignHostState.PLAN_CHANGED
            host_plan.failure_summary = (
                "The campaign host plan changed and must be reviewed again"
            )
            host_plan.updated_at = utc_now()
            campaign = self._campaign(host_plan.campaign_id)
            self._sync_campaign(campaign)
            raise ValueError("The campaign host plan changed and must be reviewed again")

    def _ensure_current_remediation_plan(
        self,
        remediation: Remediation,
    ) -> bool:
        expected_hash = remediation_plan_hash(remediation)
        content_changed = remediation.plan_hash != expected_hash
        approval_binding_changed = (
            remediation.approval_state == "approved"
            and (
                remediation.approved_plan_version != remediation.plan_version
                or remediation.approved_plan_hash != remediation.plan_hash
            )
        )
        if not content_changed and not approval_binding_changed:
            return False
        previous_version = remediation.plan_version
        previous_hash = remediation.plan_hash
        if content_changed:
            remediation.plan_version += 1
            remediation.plan_hash = remediation_plan_hash(remediation)
        remediation.approval_state = "pending"
        remediation.approved_by = None
        remediation.approved_at = None
        remediation.approved_plan_version = None
        remediation.approved_plan_hash = None
        remediation.reboot_approval_state = (
            "not_required"
            if remediation.reboot_assessment.status == "not_expected"
            else "pending"
        )
        remediation.reboot_approved_by = None
        remediation.reboot_approved_at = None
        remediation.reboot_approved_plan_version = None
        remediation.reboot_approved_plan_hash = None
        remediation.reboot_assessment.approved_if_required = False
        if remediation.execution_state not in ("running", "succeeded", "failed"):
            remediation.execution_state = "blocked"
        remediation.updated_at = utc_now()
        self.repository.save_remediation(remediation)
        self.audit(
            "system",
            "remediation.approval_invalidated",
            "remediation",
            remediation.id,
            {
                "previous_plan_version": previous_version,
                "previous_plan_hash": previous_hash,
                "plan_version": remediation.plan_version,
                "plan_hash": remediation.plan_hash,
            },
        )
        return True

    @staticmethod
    def _remediation_approval_error(
        remediation: Remediation,
        host: Host,
    ) -> Optional[str]:
        if remediation.approval_state != "approved":
            return "Remediation execution requires an approved plan"
        if not remediation.approved_by or not remediation.approved_at:
            return "Remediation approval metadata is incomplete"
        if (
            remediation.approved_plan_version != remediation.plan_version
            or remediation.approved_plan_hash != remediation.plan_hash
        ):
            return "Remediation plan approval no longer matches the current plan"
        if remediation.reboot_assessment.status != "not_expected":
            if remediation.reboot_approval_state != "approved":
                return "Remediation execution requires separate reboot approval"
            if (
                not remediation.reboot_approved_by
                or not remediation.reboot_approved_at
                or remediation.reboot_approved_plan_version
                != remediation.plan_version
                or remediation.reboot_approved_plan_hash
                != remediation.plan_hash
                or not remediation.reboot_assessment.approved_if_required
            ):
                return "Remediation reboot approval metadata is incomplete"
            if host.patch_policy.reboot_policy == "never":
                return "Host policy forbids the approved reboot risk"
        return None

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
            campaign.batch_size = min(
                campaign.batch_size,
                remediation.rollout_policy.batch_size,
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
        host_plan.failure_summary = error[:2000]
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
        if not failed.failure_policy.stop_remaining_hosts:
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
            job = self.repository.get_job(host_plan.job_id or "")
            if job and job.status in ("queued", "scheduled"):
                job.status = "canceled"
                job.current_phase = "canceled_after_campaign_failure"
                job.completed_at = now
                job.updated_at = now
                self.repository.save_job(job)
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
        for host_plan in campaign.hosts:
            if not host_plan.remediation_id:
                continue
            remediation = self.repository.get_remediation(host_plan.remediation_id)
            if not remediation:
                host_plan.state = CampaignHostState.FAILED
                host_plan.failure_summary = "Remediation proposal no longer exists"
                host_plan.updated_at = now
                continue
            plan_changed = self._ensure_current_remediation_plan(remediation)
            if (
                host_plan.plan_version != remediation.plan_version
                or host_plan.plan_hash != remediation.plan_hash
            ):
                plan_changed = True
            host_plan.approval_state = remediation.approval_state
            host_plan.reboot_approval_state = remediation.reboot_approval_state
            host_plan.approved_plan_version = remediation.approved_plan_version
            host_plan.approved_plan_hash = remediation.approved_plan_hash
            host_plan.approved_by = remediation.approved_by
            host_plan.approved_at = remediation.approved_at
            host_plan.reboot_approved_by = remediation.reboot_approved_by
            host_plan.reboot_approved_at = remediation.reboot_approved_at
            host_plan.reboot_approved_plan_version = (
                remediation.reboot_approved_plan_version
            )
            host_plan.reboot_approved_plan_hash = (
                remediation.reboot_approved_plan_hash
            )
            host_plan.failure_summary = (
                remediation.result.summary
                if remediation.result and not remediation.result.success
                else host_plan.failure_summary
            )
            job = (
                self.repository.get_job(host_plan.job_id)
                if host_plan.job_id
                else None
            )
            if job and job.job_type == "remediation" and job.status == "running":
                host_plan.state = CampaignHostState.RUNNING
            elif job and job.job_type == "remediation" and job.status == "canceled":
                host_plan.state = CampaignHostState.CANCELED
            elif remediation.execution_state == "succeeded":
                host_plan.state = CampaignHostState.SUCCEEDED
            elif remediation.execution_state == "failed":
                host_plan.state = CampaignHostState.FAILED
            elif remediation.execution_state == "running":
                host_plan.state = CampaignHostState.RUNNING
            elif remediation.execution_state == "queued":
                host_plan.state = CampaignHostState.QUEUED
            elif remediation.execution_state == "waiting_for_window":
                host_plan.state = CampaignHostState.SCHEDULED
            elif remediation.execution_state == "canceled":
                host_plan.state = CampaignHostState.CANCELED
            elif plan_changed or (
                host_plan.state == CampaignHostState.PLAN_CHANGED
                and remediation.approval_state == "pending"
            ):
                host_plan.state = CampaignHostState.PLAN_CHANGED
            elif remediation.approval_state == "rejected":
                host_plan.state = CampaignHostState.REJECTED
            elif remediation.approval_state == "manual_review":
                host_plan.state = CampaignHostState.BLOCKED
            elif remediation.approval_state != "approved":
                host_plan.state = CampaignHostState.AWAITING_APPROVAL
            elif remediation.reboot_assessment.status != "not_expected":
                if remediation.reboot_approval_state == "approved":
                    host_plan.state = CampaignHostState.APPROVED
                elif remediation.reboot_approval_state in ("blocked", "rejected"):
                    host_plan.state = CampaignHostState.BLOCKED
                else:
                    host_plan.state = CampaignHostState.AWAITING_REBOOT_APPROVAL
            else:
                host_plan.state = CampaignHostState.APPROVED
            host_plan.updated_at = now
        if campaign.canceled_at:
            campaign.status = (
                CampaignStatus.CANCELLING
                if any(
                    item.state == CampaignHostState.RUNNING
                    for item in campaign.hosts
                )
                else CampaignStatus.CANCELED
            )
        elif campaign.status != CampaignStatus.CANCELED:
            states = {
                (
                    item.state.value
                    if isinstance(item.state, CampaignHostState)
                    else str(item.state)
                )
                for item in campaign.hosts
            }
            if states == {CampaignHostState.SELECTED.value}:
                campaign.status = CampaignStatus.DRAFT
            elif states & {
                CampaignHostState.PROPOSAL_QUEUED.value,
                CampaignHostState.PROPOSAL_RUNNING.value,
            }:
                campaign.status = CampaignStatus.PROPOSING
            elif states & {
                CampaignHostState.SCHEDULED.value,
                CampaignHostState.QUEUED.value,
                CampaignHostState.RUNNING.value,
            }:
                campaign.status = CampaignStatus.RUNNING
            else:
                succeeded = sum(
                    item.state == CampaignHostState.SUCCEEDED
                    for item in campaign.hosts
                )
                failed = sum(
                    item.state
                    in (
                        CampaignHostState.FAILED,
                        CampaignHostState.REJECTED,
                        CampaignHostState.BLOCKED,
                        CampaignHostState.CANCELED,
                    )
                    for item in campaign.hosts
                )
                awaiting = sum(
                    item.state
                    in (
                        CampaignHostState.AWAITING_APPROVAL,
                        CampaignHostState.AWAITING_REBOOT_APPROVAL,
                        CampaignHostState.PLAN_CHANGED,
                    )
                    for item in campaign.hosts
                )
                approved = sum(
                    item.state == CampaignHostState.APPROVED
                    for item in campaign.hosts
                )
                actionable = [
                    item
                    for item in campaign.hosts
                    if item.state != CampaignHostState.NO_ACTION
                ]
                if succeeded and (failed or awaiting or approved):
                    campaign.status = CampaignStatus.PARTIALLY_SUCCEEDED
                elif awaiting:
                    campaign.status = CampaignStatus.AWAITING_APPROVAL
                elif approved:
                    campaign.status = CampaignStatus.READY
                elif actionable and succeeded == len(actionable):
                    campaign.status = CampaignStatus.SUCCEEDED
                elif succeeded and failed:
                    campaign.status = CampaignStatus.PARTIALLY_SUCCEEDED
                elif failed and failed == len(actionable):
                    campaign.status = CampaignStatus.FAILED
                elif failed:
                    campaign.status = CampaignStatus.FAILED
                elif not actionable:
                    campaign.status = CampaignStatus.SUCCEEDED
                else:
                    campaign.status = CampaignStatus.DRAFT
            failures = [
                item.failure_summary
                for item in campaign.hosts
                if item.failure_summary
            ]
            campaign.failure_summary = "; ".join(failures)[:2000] or None
        campaign.remediation_ids = [
            item.remediation_id
            for item in campaign.hosts
            if item.remediation_id
        ]
        completed_count = sum(
            item.state
            in (
                CampaignHostState.SUCCEEDED,
                CampaignHostState.FAILED,
                CampaignHostState.CANCELED,
                CampaignHostState.NO_ACTION,
            )
            for item in campaign.hosts
        )
        completed_batches = (
            int(math.ceil(completed_count / campaign.batch_size))
            if completed_count
            else 0
        )
        campaign.current_batch = min(
            campaign.total_batches,
            max(campaign.current_batch, completed_batches),
        )
        campaign.updated_at = now
        self.repository.save_campaign(campaign)
        return campaign

    def _refresh_campaign_state(self, campaign: PatchCampaign) -> None:
        self._sync_campaign(campaign)

    @staticmethod
    def _remediation_binding_error(
        job: DurableJob,
        remediation: Remediation,
        host: Host,
    ) -> Optional[str]:
        approval_error = SysadminService._remediation_approval_error(
            remediation,
            host,
        )
        if approval_error:
            return approval_error
        expected_scope = (
            "patch_only"
            if remediation.reboot_assessment.status == "not_expected"
            else "patch_and_reboot_if_required"
        )
        if job.approval_scope != expected_scope:
            return "Durable job approval scope is invalid"
        if job.approved_plan_version != remediation.plan_version:
            return "Remediation plan version changed after approval"
        if job.approved_plan_hash != remediation.plan_hash:
            return "Remediation plan hash changed after approval"
        if (
            remediation.approved_plan_version is not None
            and remediation.approved_plan_version != job.approved_plan_version
        ):
            return "Approved remediation plan version binding changed"
        if (
            remediation.approved_plan_hash is not None
            and remediation.approved_plan_hash != job.approved_plan_hash
        ):
            return "Approved remediation plan hash binding changed"
        if remediation.plan_hash != remediation_plan_hash(remediation):
            return "Remediation content changed from the approved plan"
        return None


def next_cron_run(expression: str, timezone_name: str, after: datetime) -> datetime:
    parts = expression.split()
    if len(parts) != 5:
        raise ValueError("Cron expression must have exactly five fields")
    zone = ZoneInfo(timezone_name)
    local = after.astimezone(zone)
    return croniter(expression, local).get_next(datetime).astimezone(ZoneInfo("UTC"))


def maintenance_window_is_open(window: MaintenanceWindow, current: datetime) -> bool:
    zone = ZoneInfo(window.timezone)
    local = current.astimezone(zone)
    if local.weekday() not in window.weekdays:
        return False
    hour, minute = [int(part) for part in window.start_time.split(":", 1)]
    start = datetime.combine(local.date(), time(hour, minute), zone)
    end = start + timedelta(minutes=window.duration_minutes)
    return start <= local < end


def material_state_changed(previous, current) -> bool:
    previous_packages = sorted(
        (item.name, item.candidate_version)
        for item in previous.package_summary.updates
    )
    current_packages = sorted(
        (item.name, item.candidate_version)
        for item in current.package_summary.updates
    )
    return any(
        (
            previous_packages != current_packages,
            sorted(previous.service_summary.failed_units)
            != sorted(current.service_summary.failed_units),
            previous.package_summary.reboot_required_now
            != current.package_summary.reboot_required_now,
        )
    )


def severity_text(value: Any) -> str:
    return value.value if isinstance(value, Severity) else str(value)


def execution_failure_category(summary: str) -> str:
    lowered = summary.lower()
    if "approv" in lowered or "plan" in lowered:
        return "approval_validation"
    if "host key" in lowered or "blocked" in lowered:
        return "safety_validation"
    return "remediation_execution"


def execution_failure_is_non_retryable(summary: str, changed: bool) -> bool:
    lowered = summary.lower()
    return changed or any(
        marker in lowered
        for marker in (
            "approval",
            "approved",
            "plan changed",
            "host key",
            "execution blocked",
            "reboot scope",
            "policy forbids",
        )
    )


def agent_events(
    host_id: str,
    job_id: str,
    scan_id: str,
    runs: List[AgentRun],
    messages: List[AgentMessage],
) -> List[StructuredLogEvent]:
    events: List[StructuredLogEvent] = []
    for run in runs:
        events.append(
            StructuredLogEvent(
                id=new_id("log"),
                timestamp=run.created_at,
                duration_ms=run.latency_ms,
                host_id=host_id,
                job_id=job_id,
                scan_id=scan_id,
                agent_run_id=run.id,
                event_type="agent_run",
                evidence_category="ai_analysis",
                severity=Severity.INFO,
                status=run.status,
                stdout=str(run.output)[:65536],
                source="agent:%s" % run.agent.name,
                redacted=run.externally_processed,
                externally_processed=run.externally_processed,
                remediation_relevance="analysis",
                correlation_ids={"scan_id": scan_id, "agent_run_id": run.id},
            )
        )
    for message in messages:
        events.append(
            StructuredLogEvent(
                id=new_id("log"),
                timestamp=message.created_at,
                host_id=host_id,
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
            )
        )
    return events
