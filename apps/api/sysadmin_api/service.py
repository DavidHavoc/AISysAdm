from __future__ import annotations

import math
from datetime import datetime, time, timedelta
from typing import Any, Dict, List, Optional, Tuple
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
    CampaignRequest,
    ConnectionTestResult,
    DurableJob,
    Host,
    HostInput,
    HostSchedule,
    HostScheduleInput,
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
    ) -> None:
        self.repository = repository
        self.collector = collector
        self.workflow = workflow
        self.executor = executor
        self.log_retention_days = log_retention_days

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
            created_at=now,
            updated_at=now,
        )
        job = DurableJob(
            id=new_id("job"),
            job_type="scan",
            status="queued",
            host_id=host.id,
            scan_id=scan.id,
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

    async def process_scan(self, job_id: str) -> DurableJob:
        existing = self._job(job_id)
        if existing.status != "queued":
            return existing
        job = self.repository.claim_job(job_id, utc_now())
        if not job:
            return self._job(job_id)
        scan = self._scan(job.scan_id)
        host = self._host(scan.host_id)
        job.current_phase = "collecting_evidence"
        job.progress_percent = 10
        job.updated_at = utc_now()
        scan.status = "running"
        scan.updated_at = utc_now()
        self.repository.save_job(job)
        self.repository.save_scan(scan)
        try:
            collected = await self.collector.collect(host, job.id, scan.id)
            self.repository.save_snapshot(collected.snapshot)
            self.repository.save_log_events(collected.events)
            scan.snapshot_id = collected.snapshot.id
            job.current_phase = "multi_agent_analysis"
            job.progress_percent = 35
            job.updated_at = utc_now()
            self.repository.save_job(job)

            result = await self.workflow.run(scan.id, host, collected.snapshot)
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
            self.repository.save_job(job)
            if scan.trigger == "scheduled":
                for finding in result.findings:
                    if severity_text(finding.severity) in ("high", "critical"):
                        self.create_alert(
                            severity=Severity(severity_text(finding.severity)),
                            title="Scheduled scan found %s risk" % severity_text(finding.severity),
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
        except Exception as error:
            scan.status = "failed"
            scan.error = str(error)
            scan.updated_at = utc_now()
            self.repository.save_scan(scan)
            return self.fail_job(job, str(error), host.id)

    def prepare_remediation_job(
        self,
        remediation_id: str,
        request: ApprovalRequest,
        actor: str,
    ) -> DurableJob:
        remediation = self._remediation(remediation_id)
        host = self._host(remediation.host_id)
        if remediation.approval_state != "pending":
            raise ValueError("Only pending remediations can be approved")
        if request.hostname_confirmation != host.name:
            raise ValueError("Typed hostname confirmation does not match")
        if (
            request.plan_version != remediation.plan_version
            or request.plan_hash != remediation.plan_hash
        ):
            raise ValueError("The remediation plan changed and must be reviewed again")
        if (
            host.patch_policy.reboot_policy == "never"
            and remediation.reboot_assessment.status != "not_expected"
        ):
            remediation.approval_state = "manual_review"
            remediation.execution_state = "blocked"
            remediation.updated_at = utc_now()
            self.repository.save_remediation(remediation)
            raise ValueError("Host policy forbids reboot risk that cannot be excluded")
        now = utc_now()
        remediation.approval_state = "approved"
        remediation.approved_by = actor
        remediation.approved_at = now
        remediation.reboot_assessment.approved_if_required = True
        remediation.updated_at = now
        key = "remediation:%s:%s" % (remediation.id, remediation.plan_hash)
        existing = self.repository.get_job_by_idempotency(key)
        if existing:
            return existing
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
            approved_plan_version=remediation.plan_version,
            approved_plan_hash=remediation.plan_hash,
            approval_scope=remediation.approval_scope,
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
            "remediation.approved",
            "remediation",
            remediation.id,
            {"job_id": job.id, "plan_hash": remediation.plan_hash},
        )
        return job

    async def process_remediation(self, job_id: str) -> DurableJob:
        existing = self._job(job_id)
        remediation = self._remediation(existing.remediation_id)
        host = self._host(remediation.host_id)
        if existing.status != "queued":
            return existing
        if not self._timing_allows(remediation, utc_now()):
            existing.status = "scheduled"
            existing.current_phase = "waiting_for_maintenance_window"
            existing.updated_at = utc_now()
            self.repository.save_job(existing)
            return existing
        job = self.repository.claim_job(job_id, utc_now())
        if not job:
            return self._job(job_id)
        binding_error = self._remediation_binding_error(job, remediation, host)
        if binding_error:
            remediation.execution_state = "blocked"
            remediation.updated_at = utc_now()
            self.repository.save_remediation(remediation)
            return self.fail_job(job, binding_error, host.id)
        job.current_phase = "state_drift_check"
        job.progress_percent = 10
        job.updated_at = utc_now()
        remediation.execution_state = "running"
        remediation.updated_at = utc_now()
        self.repository.save_job(job)
        self.repository.save_remediation(remediation)
        try:
            original_scan = self._scan(remediation.scan_id)
            original_snapshot = self.repository.get_snapshot(original_scan.snapshot_id or "")
            if not original_snapshot:
                raise RuntimeError("Approved scan snapshot is unavailable")
            current = await self.collector.collect(host, job.id, remediation.scan_id or "")
            self.repository.save_snapshot(current.snapshot)
            self.repository.save_log_events(current.events)
            if material_state_changed(original_snapshot, current.snapshot):
                raise RuntimeError(
                    "Host package, service, or reboot state changed after approval"
                )
            job.current_phase = "ansible_execution"
            job.progress_percent = 30
            job.updated_at = utc_now()
            self.repository.save_job(job)
            result = await self.executor.execute(host, remediation, job.id)
            self.repository.save_log_events(result.events)
            remediation.result = result
            remediation.execution_state = "succeeded" if result.success else "failed"
            remediation.updated_at = utc_now()
            self.repository.save_remediation(remediation)
            if not result.success:
                return self.fail_job(job, result.summary, host.id)
            job.status = "completed"
            job.current_phase = "completed"
            job.progress_percent = 100
            job.result = {"remediation_id": remediation.id, "success": True}
            job.completed_at = utc_now()
            job.updated_at = utc_now()
            self.repository.save_job(job)
            self.audit(
                remediation.approved_by or "operator",
                "remediation.completed",
                "remediation",
                remediation.id,
                {"job_id": job.id, "reboot_performed": result.reboot_performed},
            )
            return job
        except Exception as error:
            remediation.execution_state = "failed"
            remediation.updated_at = utc_now()
            self.repository.save_remediation(remediation)
            return self.fail_job(job, str(error), host.id)

    def reject_remediation(self, remediation_id: str, actor: str) -> Remediation:
        remediation = self._remediation(remediation_id)
        if remediation.approval_state != "pending":
            raise ValueError("Only pending remediations can be rejected")
        remediation.approval_state = "rejected"
        remediation.execution_state = "blocked"
        remediation.updated_at = utc_now()
        self.repository.save_remediation(remediation)
        self.audit(actor, "remediation.rejected", "remediation", remediation_id)
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
            remediation = self._remediation(job.remediation_id)
            if self._timing_allows(remediation, current):
                job.status = "queued"
                job.current_phase = None
                job.updated_at = current
                self.repository.save_job(job)
                released.append(job)
        return released

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
        remediations = [
            item
            for item in self.repository.list_remediations()
            if item.host_id in request.host_ids and item.approval_state == "pending"
        ]
        if not remediations:
            raise ValueError("Campaign has no pending remediation plans")
        batch_size = min(item.rollout_policy.batch_size for item in remediations)
        now = utc_now()
        campaign = PatchCampaign(
            id=new_id("campaign"),
            name=request.name,
            host_ids=request.host_ids,
            remediation_ids=[item.id for item in remediations],
            status="pending_approval",
            batch_size=batch_size,
            total_batches=int(math.ceil(len(remediations) / batch_size)),
            created_at=now,
            updated_at=now,
        )
        self.repository.save_campaign(campaign)
        self.audit(actor, "campaign.created", "campaign", campaign.id)
        return campaign

    def list_campaigns(self) -> List[PatchCampaign]:
        return self.repository.list_campaigns()

    def fail_job(self, job: DurableJob, error: str, host_id: str) -> DurableJob:
        job.status = "failed"
        job.error = error[:2000]
        job.current_phase = "failed"
        job.completed_at = utc_now()
        job.updated_at = utc_now()
        self.repository.save_job(job)
        self.create_alert(
            severity=Severity.CRITICAL,
            title="%s job failed" % job.job_type.title(),
            message=job.error,
            host_id=host_id,
            job_id=job.id,
        )
        self.audit(
            "system",
            "job.failed",
            "job",
            job.id,
            {"error": job.error},
        )
        return job

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

    @staticmethod
    def _remediation_binding_error(
        job: DurableJob,
        remediation: Remediation,
        host: Host,
    ) -> Optional[str]:
        if remediation.approval_state != "approved":
            return "Remediation execution requires an approved plan"
        if not remediation.approved_by or not remediation.approved_at:
            return "Remediation approval metadata is incomplete"
        if job.approval_scope != "patch_and_reboot_if_required":
            return "Durable job approval scope is invalid"
        if remediation.approval_scope != job.approval_scope:
            return "Remediation approval scope changed after approval"
        if job.approved_plan_version != remediation.plan_version:
            return "Remediation plan version changed after approval"
        if job.approved_plan_hash != remediation.plan_hash:
            return "Remediation plan hash changed after approval"
        if remediation.plan_hash != remediation_plan_hash(remediation):
            return "Remediation plan content changed after approval"
        if (
            remediation.reboot_assessment.status != "not_expected"
            and not remediation.reboot_assessment.approved_if_required
        ):
            return "Required reboot scope was not approved"
        if (
            host.patch_policy.reboot_policy == "never"
            and remediation.reboot_assessment.status != "not_expected"
        ):
            return "Host policy forbids the approved reboot risk"
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
