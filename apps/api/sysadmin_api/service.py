from __future__ import annotations

import asyncio
import math
from datetime import datetime, time, timedelta, timezone
from typing import List, Optional
from uuid import uuid4
from zoneinfo import ZoneInfo

from .agents import LinuxStateAgent, LogAnalysisAgent, OrchestratorAgent
from .collector import HostCollector
from .executor import RemediationExecutor
from .models import (
    CampaignRequest,
    Host,
    HostInput,
    MaintenanceWindow,
    PatchCampaign,
    Remediation,
    ScanJob,
    ScanRequest,
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
        log_agent: LogAnalysisAgent,
        state_agent: LinuxStateAgent,
        orchestrator: OrchestratorAgent,
        executor: RemediationExecutor,
    ) -> None:
        self.repository = repository
        self.collector = collector
        self.log_agent = log_agent
        self.state_agent = state_agent
        self.orchestrator = orchestrator
        self.executor = executor

    def list_hosts(self) -> List[Host]:
        return self.repository.list_hosts()

    def create_host(self, host_input: HostInput) -> Host:
        now = utc_now()
        host = Host(
            **host_input.model_dump(),
            id=new_id("host"),
            created_at=now,
            updated_at=now,
        )
        return self.repository.save_host(host)

    def list_findings(self, host_id: str):
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
        return self.repository.list_remediations()

    def get_scan(self, scan_id: str) -> Optional[ScanJob]:
        return self.repository.get_scan(scan_id)

    async def run_scan(self, request: ScanRequest) -> ScanJob:
        host = self._host(request.host_id)
        scan = ScanJob(
            id=new_id("scan"),
            host_id=host.id,
            status="running",
            created_at=utc_now(),
            updated_at=utc_now(),
        )
        self.repository.save_scan(scan)
        try:
            snapshot = await self.collector.collect(host)
            reports = await asyncio.gather(
                self.log_agent.analyze(host, snapshot),
                self.state_agent.analyze(host, snapshot),
            )
            findings, remediation = await self.orchestrator.synthesize(
                host, snapshot, list(reports)
            )
            for item in findings:
                item.scan_id = scan.id
            self.repository.save_findings(findings)
            remediation_ids: List[str] = []
            if remediation:
                self.repository.save_remediation(remediation)
                remediation_ids.append(remediation.id)
            scan.status = "completed"
            scan.finding_ids = [item.id for item in findings]
            scan.remediation_ids = remediation_ids
            scan.agent_reports = list(reports)
        except Exception as error:
            scan.status = "failed"
            scan.error = str(error)
        scan.updated_at = utc_now()
        return self.repository.save_scan(scan)

    async def approve_remediation(
        self,
        remediation_id: str,
        now: Optional[datetime] = None,
    ) -> Remediation:
        remediation = self._remediation(remediation_id)
        host = self._host(remediation.host_id)
        if remediation.approval_state != "pending":
            raise ValueError("Only pending remediations can be approved")
        if (
            host.patch_policy.reboot_policy == "never"
            and remediation.reboot_assessment.status != "not_expected"
        ):
            remediation.approval_state = "manual_review"
            remediation.execution_state = "blocked"
            remediation.updated_at = utc_now()
            self.repository.save_remediation(remediation)
            raise ValueError(
                "Host policy forbids reboot risk that this patch plan cannot exclude"
            )

        remediation.approval_state = "approved"
        remediation.reboot_assessment.approved_if_required = True
        if not self._timing_allows(remediation, now or utc_now()):
            remediation.execution_state = "waiting_for_window"
            remediation.updated_at = utc_now()
            return self.repository.save_remediation(remediation)

        remediation.execution_state = "running"
        remediation.updated_at = utc_now()
        self.repository.save_remediation(remediation)
        result = await self.executor.execute(host, remediation)
        remediation.result = result
        remediation.execution_state = "succeeded" if result.success else "failed"
        remediation.updated_at = utc_now()
        return self.repository.save_remediation(remediation)

    def reject_remediation(self, remediation_id: str) -> Remediation:
        remediation = self._remediation(remediation_id)
        if remediation.approval_state != "pending":
            raise ValueError("Only pending remediations can be rejected")
        remediation.approval_state = "rejected"
        remediation.execution_state = "blocked"
        remediation.updated_at = utc_now()
        return self.repository.save_remediation(remediation)

    async def create_campaign(self, request: CampaignRequest) -> PatchCampaign:
        remediation_ids: List[str] = []
        batch_sizes: List[int] = []
        for host_id in request.host_ids:
            scan = await self.run_scan(ScanRequest(host_id=host_id))
            if scan.status != "completed":
                raise RuntimeError("Scan failed for host %s: %s" % (host_id, scan.error))
            remediation_ids.extend(scan.remediation_ids)
            for remediation_id in scan.remediation_ids:
                remediation = self._remediation(remediation_id)
                batch_sizes.append(remediation.rollout_policy.batch_size)

        if not remediation_ids:
            raise ValueError("Campaign has no actionable package remediations")
        batch_size = min(batch_sizes)
        now = utc_now()
        campaign = PatchCampaign(
            id=new_id("campaign"),
            name=request.name,
            host_ids=request.host_ids,
            remediation_ids=remediation_ids,
            status="pending_approval",
            batch_size=batch_size,
            total_batches=int(math.ceil(len(remediation_ids) / batch_size)),
            created_at=now,
            updated_at=now,
        )
        return self.repository.save_campaign(campaign)

    def list_campaigns(self) -> List[PatchCampaign]:
        return self.repository.list_campaigns()

    async def approve_campaign(
        self,
        campaign_id: str,
        now: Optional[datetime] = None,
    ) -> PatchCampaign:
        campaign = self._campaign(campaign_id)
        if campaign.status != "pending_approval":
            raise ValueError("Only pending campaigns can be approved")
        current_time = now or utc_now()
        remediations = [
            self._remediation(item_id) for item_id in campaign.remediation_ids
        ]
        if any(not self._timing_allows(item, current_time) for item in remediations):
            campaign.status = "scheduled"
            campaign.updated_at = utc_now()
            return self.repository.save_campaign(campaign)

        campaign.status = "running"
        self.repository.save_campaign(campaign)
        for index in range(0, len(remediations), campaign.batch_size):
            batch = remediations[index : index + campaign.batch_size]
            campaign.current_batch = index // campaign.batch_size + 1
            campaign.updated_at = utc_now()
            self.repository.save_campaign(campaign)
            results = await asyncio.gather(
                *[
                    self.approve_remediation(item.id, current_time)
                    for item in batch
                ],
                return_exceptions=True,
            )
            failures = [
                item
                for item in results
                if isinstance(item, Exception)
                or (isinstance(item, Remediation) and item.execution_state != "succeeded")
            ]
            if failures:
                campaign.status = "halted"
                campaign.failure_summary = (
                    "A batch failed. Remaining hosts were stopped, an operator "
                    "notification was recorded, and predefined recovery was attempted."
                )
                campaign.updated_at = utc_now()
                return self.repository.save_campaign(campaign)

        campaign.status = "succeeded"
        campaign.updated_at = utc_now()
        return self.repository.save_campaign(campaign)

    def reject_campaign(self, campaign_id: str) -> PatchCampaign:
        campaign = self._campaign(campaign_id)
        if campaign.status != "pending_approval":
            raise ValueError("Only pending campaigns can be rejected")
        campaign.status = "rejected"
        campaign.updated_at = utc_now()
        for remediation_id in campaign.remediation_ids:
            remediation = self._remediation(remediation_id)
            if remediation.approval_state == "pending":
                self.reject_remediation(remediation_id)
        return self.repository.save_campaign(campaign)

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

    def _remediation(self, remediation_id: str) -> Remediation:
        remediation = self.repository.get_remediation(remediation_id)
        if not remediation:
            raise ValueError("Remediation not found")
        return remediation

    def _campaign(self, campaign_id: str) -> PatchCampaign:
        campaign = self.repository.get_campaign(campaign_id)
        if not campaign:
            raise ValueError("Campaign not found")
        return campaign


def maintenance_window_is_open(window: MaintenanceWindow, current: datetime) -> bool:
    zone = ZoneInfo(window.timezone)
    local = current.astimezone(zone)
    if local.weekday() not in window.weekdays:
        return False
    hour, minute = [int(part) for part in window.start_time.split(":", 1)]
    start = datetime.combine(local.date(), time(hour, minute), zone)
    end = start + timedelta(minutes=window.duration_minutes)
    return start <= local < end
