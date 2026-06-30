from __future__ import annotations

import hashlib
import json
import math
from dataclasses import dataclass, field
from datetime import datetime, time
from enum import Enum
from typing import Any, Dict, List, Mapping, Optional, Sequence
from zoneinfo import ZoneInfo

from .models import (
    ApprovalRequest,
    CampaignHostPlan,
    CampaignHostState,
    CampaignStatus,
    DurableJob,
    ExecutionResult,
    Host,
    HostSnapshot,
    PatchCampaign,
    Remediation,
    RollbackSnapshotState,
    Severity,
    SnapshotPlatform,
)


SUPPORTED_ACTION_TYPES = frozenset({"package_upgrade"})
SUPPORTED_UPDATE_SCOPES = frozenset({"security", "all"})


class GateCode(str, Enum):
    ALLOWED = "allowed"
    PLAN_NOT_PENDING = "plan_not_pending"
    PLAN_NOT_APPROVED = "plan_not_approved"
    PLAN_CONTENT_CHANGED = "plan_content_changed"
    PLAN_VERSION_CHANGED = "plan_version_changed"
    PLAN_HASH_CHANGED = "plan_hash_changed"
    PLAN_BINDING_CHANGED = "plan_binding_changed"
    PLAN_METADATA_INCOMPLETE = "plan_metadata_incomplete"
    HOST_BINDING_INVALID = "host_binding_invalid"
    HOSTNAME_MISMATCH = "hostname_mismatch"
    EVIDENCE_INCOMPLETE = "evidence_incomplete"
    ACTION_NOT_CATALOGED = "action_not_cataloged"
    UPDATE_SCOPE_NOT_CATALOGED = "update_scope_not_cataloged"
    APPROVAL_SCOPE_INVALID = "approval_scope_invalid"
    APPROVAL_METADATA_INCOMPLETE = "approval_metadata_incomplete"
    REBOOT_NOT_REQUIRED = "reboot_not_required"
    REBOOT_APPROVAL_MISSING = "reboot_approval_missing"
    REBOOT_APPROVAL_INCOMPLETE = "reboot_approval_incomplete"
    REBOOT_POLICY_DENIED = "reboot_policy_denied"
    HOST_STATE_DRIFT = "host_state_drift"
    ACTIVE_ROLLBACK_FAILURE = "active_rollback_failure"
    DUPLICATE_EXECUTION = "duplicate_execution"
    MAINTENANCE_WINDOW_CLOSED = "maintenance_window_closed"
    CAMPAIGN_STATE_INVALID = "campaign_state_invalid"
    CAMPAIGN_BATCH_IN_PROGRESS = "campaign_batch_in_progress"
    CAMPAIGN_PLAN_CHANGED = "campaign_plan_changed"
    CAMPAIGN_NO_APPROVED_HOSTS = "campaign_no_approved_hosts"
    SNAPSHOT_CONFIGURATION_INCOMPLETE = "snapshot_configuration_incomplete"
    SNAPSHOT_CREATE_FAILED = "snapshot_create_failed"
    HEALTH_CHECK_FAILED = "health_check_failed"
    ROLLBACK_REQUIRED = "rollback_required"
    ROLLBACK_SUCCEEDED = "rollback_succeeded"
    ROLLBACK_FAILED = "rollback_failed"
    EXECUTION_FAILED = "execution_failed"
    EXECUTION_CHANGED_FAILED = "execution_changed_failed"
    STALE_EXECUTION_UNCERTAIN = "stale_execution_uncertain"


_REASONS: Dict[GateCode, str] = {
    GateCode.PLAN_NOT_PENDING: "Only pending remediations can be approved",
    GateCode.PLAN_NOT_APPROVED: "Execution blocked because the remediation is not approved",
    GateCode.PLAN_CONTENT_CHANGED: "Remediation content changed from the approved plan",
    GateCode.PLAN_VERSION_CHANGED: "Remediation plan version changed after approval",
    GateCode.PLAN_HASH_CHANGED: "Remediation plan hash changed after approval",
    GateCode.PLAN_BINDING_CHANGED: "Remediation plan approval no longer matches the current plan",
    GateCode.PLAN_METADATA_INCOMPLETE: "Remediation plan metadata is incomplete",
    GateCode.HOST_BINDING_INVALID: "Remediation host binding is invalid",
    GateCode.HOSTNAME_MISMATCH: "Typed hostname confirmation does not match",
    GateCode.EVIDENCE_INCOMPLETE: "Approved remediation evidence is incomplete",
    GateCode.ACTION_NOT_CATALOGED: "Execution blocked because the remediation action type is not cataloged",
    GateCode.UPDATE_SCOPE_NOT_CATALOGED: "Execution blocked because the remediation update scope is not cataloged",
    GateCode.APPROVAL_SCOPE_INVALID: "Execution blocked because the approval scope is invalid",
    GateCode.APPROVAL_METADATA_INCOMPLETE: "Remediation approval metadata is incomplete",
    GateCode.REBOOT_NOT_REQUIRED: "This remediation does not require reboot approval",
    GateCode.REBOOT_APPROVAL_MISSING: "Remediation execution requires separate reboot approval",
    GateCode.REBOOT_APPROVAL_INCOMPLETE: "Remediation reboot approval metadata is incomplete",
    GateCode.REBOOT_POLICY_DENIED: "Host policy forbids reboot risk that cannot be excluded",
    GateCode.HOST_STATE_DRIFT: "Host package, service, or reboot state changed after approval",
    GateCode.ACTIVE_ROLLBACK_FAILURE: "Host has an unresolved rollback failure alert and cannot execute remediations",
    GateCode.DUPLICATE_EXECUTION: "This exact remediation plan already has an execution job",
    GateCode.MAINTENANCE_WINDOW_CLOSED: "Remediation is waiting for its maintenance window",
    GateCode.CAMPAIGN_STATE_INVALID: "Campaign cannot execute in its current state",
    GateCode.CAMPAIGN_BATCH_IN_PROGRESS: "Campaign current batch must finish before another batch can start",
    GateCode.CAMPAIGN_PLAN_CHANGED: "The campaign host plan changed and must be reviewed again",
    GateCode.CAMPAIGN_NO_APPROVED_HOSTS: "Campaign has no approved host plans ready to execute",
    GateCode.SNAPSHOT_CONFIGURATION_INCOMPLETE: "Required snapshot protection is incompletely configured",
    GateCode.SNAPSHOT_CREATE_FAILED: "Snapshot creation failed before package changes",
    GateCode.HEALTH_CHECK_FAILED: "Post-change health checks failed",
    GateCode.ROLLBACK_REQUIRED: "Post-change health checks failed and rollback is required",
    GateCode.ROLLBACK_SUCCEEDED: "Post-reboot health checks failed; snapshot rollback completed and human intervention is required.",
    GateCode.ROLLBACK_FAILED: "Post-reboot health checks failed and snapshot rollback failed; human intervention is required.",
    GateCode.EXECUTION_FAILED: "Remediation execution failed",
    GateCode.EXECUTION_CHANGED_FAILED: "Remediation failed after changing host state",
    GateCode.STALE_EXECUTION_UNCERTAIN: "Worker lease expired after mutation may have started; automatic retry is blocked",
}


@dataclass(frozen=True)
class GateDecision:
    allowed: bool
    code: GateCode
    message: str = ""
    category: str = "safety_validation"
    retryable: bool = False

    @classmethod
    def allow(cls) -> "GateDecision":
        return cls(True, GateCode.ALLOWED)

    @classmethod
    def deny(
        cls,
        code: GateCode,
        *,
        message: Optional[str] = None,
        category: str = "safety_validation",
        retryable: bool = False,
    ) -> "GateDecision":
        return cls(
            False,
            code,
            message or _REASONS[code],
            category,
            retryable,
        )


class GateDenied(ValueError):
    def __init__(self, decision: GateDecision) -> None:
        super().__init__(decision.message)
        self.decision = decision


@dataclass(frozen=True)
class RemediationTransition:
    decision: GateDecision
    remediation: Remediation


@dataclass(frozen=True)
class PlanReconciliation:
    decision: GateDecision
    changed: bool
    content_changed: bool
    previous_plan_version: int
    previous_plan_hash: str
    remediation: Remediation


@dataclass(frozen=True)
class TimingDecision:
    decision: GateDecision
    job_status: str
    remediation_state: str


@dataclass(frozen=True)
class SnapshotDecision:
    decision: GateDecision
    required: bool


class PostChangeAction(str, Enum):
    COMPLETE = "complete"
    ROLLBACK = "rollback"


@dataclass(frozen=True)
class PostChangeDecision:
    decision: GateDecision
    action: PostChangeAction
    snapshot_state: RollbackSnapshotState


@dataclass(frozen=True)
class RollbackDecision:
    decision: GateDecision
    snapshot_state: RollbackSnapshotState
    remediation_state: str
    summary: str


@dataclass(frozen=True)
class ExecutionOutcome:
    decision: GateDecision
    remediation_state: str
    job_status: str
    stop_remaining_hosts: bool


@dataclass(frozen=True)
class RecoveryDecision:
    decision: GateDecision
    remediation_state: str
    dispatch: bool


@dataclass(frozen=True)
class CampaignBatchDecision:
    decision: GateDecision
    host_ids: List[str] = field(default_factory=list)
    plan_changed_host_ids: List[str] = field(default_factory=list)


def _severity_text(value: Any) -> str:
    return value.value if isinstance(value, Severity) else str(value)


def _stable_hash(value: Any) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def _reboot_risk(remediation: Remediation) -> bool:
    return remediation.reboot_assessment.status != "not_expected"


def _expected_job_scope(remediation: Remediation) -> str:
    return (
        "patch_and_reboot_if_required"
        if _reboot_risk(remediation)
        else "patch_only"
    )


def _plan_payload(remediation: Remediation) -> Dict[str, Any]:
    reboot = remediation.reboot_assessment.model_dump(mode="json")
    reboot.pop("approved_if_required", None)
    return {
        "plan_version": remediation.plan_version,
        "host_id": remediation.host_id,
        "scan_id": remediation.scan_id,
        "action_type": remediation.action_type,
        "update_scope": remediation.update_scope,
        "risk_level": _severity_text(remediation.risk_level),
        "decision": remediation.ai_decision.model_dump(mode="json"),
        "reboot": reboot,
        "rollout": remediation.rollout_policy.model_dump(mode="json"),
        "failure_policy": remediation.failure_policy.model_dump(mode="json"),
        "timing": remediation.execution_timing,
        "maintenance_window": (
            remediation.maintenance_window.model_dump(mode="json")
            if remediation.maintenance_window
            else None
        ),
        "approval_scope": remediation.approval_scope,
        "pre_change_protection": remediation.pre_change_protection,
    }


def _catalog_decision(remediation: Remediation) -> GateDecision:
    if remediation.approval_scope != "patch_only":
        return GateDecision.deny(
            GateCode.APPROVAL_SCOPE_INVALID,
            category="approval_validation",
        )
    if remediation.action_type not in SUPPORTED_ACTION_TYPES:
        return GateDecision.deny(
            GateCode.ACTION_NOT_CATALOGED,
            category="approval_validation",
        )
    if remediation.update_scope not in SUPPORTED_UPDATE_SCOPES:
        return GateDecision.deny(
            GateCode.UPDATE_SCOPE_NOT_CATALOGED,
            category="approval_validation",
        )
    return GateDecision.allow()


def _evidence_decision(remediation: Remediation) -> GateDecision:
    if (
        not remediation.scan_id
        or remediation.ai_decision.status != "plan_ready"
        or not remediation.ai_decision.supporting_citations
    ):
        return GateDecision.deny(
            GateCode.EVIDENCE_INCOMPLETE,
            category="approval_validation",
        )
    return GateDecision.allow()


def _approval_decision(remediation: Remediation, host: Host) -> GateDecision:
    if remediation.host_id != host.id:
        return GateDecision.deny(
            GateCode.HOST_BINDING_INVALID,
            category="approval_validation",
        )
    catalog = _catalog_decision(remediation)
    if not catalog.allowed:
        return catalog
    evidence = _evidence_decision(remediation)
    if not evidence.allowed:
        return evidence
    if not remediation.plan_hash or remediation.plan_version < 1:
        return GateDecision.deny(
            GateCode.PLAN_METADATA_INCOMPLETE,
            category="approval_validation",
        )
    if remediation.plan_hash != TrustedChangeGate.plan_hash(remediation):
        return GateDecision.deny(
            GateCode.PLAN_CONTENT_CHANGED,
            category="approval_validation",
        )
    if remediation.approval_state != "approved":
        return GateDecision.deny(
            GateCode.PLAN_NOT_APPROVED,
            category="approval_validation",
        )
    if not remediation.approved_by or not remediation.approved_at:
        return GateDecision.deny(
            GateCode.APPROVAL_METADATA_INCOMPLETE,
            category="approval_validation",
        )
    if (
        remediation.approved_plan_version != remediation.plan_version
        or remediation.approved_plan_hash != remediation.plan_hash
    ):
        return GateDecision.deny(
            GateCode.PLAN_BINDING_CHANGED,
            category="approval_validation",
        )
    if _reboot_risk(remediation):
        if remediation.reboot_approval_state != "approved":
            return GateDecision.deny(
                GateCode.REBOOT_APPROVAL_MISSING,
                category="approval_validation",
            )
        if (
            not remediation.reboot_approved_by
            or not remediation.reboot_approved_at
            or remediation.reboot_approved_plan_version
            != remediation.plan_version
            or remediation.reboot_approved_plan_hash != remediation.plan_hash
            or not remediation.reboot_assessment.approved_if_required
        ):
            return GateDecision.deny(
                GateCode.REBOOT_APPROVAL_INCOMPLETE,
                category="approval_validation",
            )
        if host.patch_policy.reboot_policy == "never":
            return GateDecision.deny(GateCode.REBOOT_POLICY_DENIED)
    return GateDecision.allow()


def _maintenance_window_is_open(remediation: Remediation, current: datetime) -> bool:
    if remediation.execution_timing == "immediate":
        return True
    window = remediation.maintenance_window
    if not window:
        return False
    zone = ZoneInfo(window.timezone)
    local = current.astimezone(zone)
    if local.weekday() not in window.weekdays:
        return False
    hour, minute = [int(part) for part in window.start_time.split(":", 1)]
    start = datetime.combine(local.date(), time(hour, minute), zone)
    end = start.timestamp() + (window.duration_minutes * 60)
    return start.timestamp() <= local.timestamp() < end


def _campaign_terminal(campaign: PatchCampaign) -> bool:
    return campaign.status in (
        CampaignStatus.CANCELLING,
        CampaignStatus.CANCELED,
        CampaignStatus.SUCCEEDED,
        CampaignStatus.FAILED,
    )


class TrustedChangeGate:
    """Pure trusted policy for approved changes and execution transitions."""

    @staticmethod
    def plan_hash(remediation: Remediation) -> str:
        return _stable_hash(_plan_payload(remediation))

    @staticmethod
    def job_approval_scope(remediation: Remediation) -> str:
        return _expected_job_scope(remediation)

    @staticmethod
    def reconcile_plan(
        remediation: Remediation,
        current: datetime,
    ) -> PlanReconciliation:
        updated = remediation.model_copy(deep=True)
        expected_hash = TrustedChangeGate.plan_hash(updated)
        content_changed = updated.plan_hash != expected_hash
        approval_binding_changed = (
            updated.approval_state == "approved"
            and (
                updated.approved_plan_version != updated.plan_version
                or updated.approved_plan_hash != updated.plan_hash
            )
        )
        if not content_changed and not approval_binding_changed:
            return PlanReconciliation(
                GateDecision.allow(),
                False,
                False,
                updated.plan_version,
                updated.plan_hash,
                updated,
            )
        previous_version = updated.plan_version
        previous_hash = updated.plan_hash
        if content_changed:
            updated.plan_version += 1
            updated.plan_hash = TrustedChangeGate.plan_hash(updated)
        updated.approval_state = "pending"
        updated.approved_by = None
        updated.approved_at = None
        updated.approved_plan_version = None
        updated.approved_plan_hash = None
        updated.reboot_approval_state = (
            "not_required" if not _reboot_risk(updated) else "pending"
        )
        updated.reboot_approved_by = None
        updated.reboot_approved_at = None
        updated.reboot_approved_plan_version = None
        updated.reboot_approved_plan_hash = None
        updated.reboot_assessment.approved_if_required = False
        if updated.execution_state not in ("running", "succeeded", "failed"):
            updated.execution_state = "blocked"
        updated.updated_at = current
        return PlanReconciliation(
            GateDecision.deny(
                (
                    GateCode.PLAN_CONTENT_CHANGED
                    if content_changed
                    else GateCode.PLAN_BINDING_CHANGED
                ),
                message=(
                    "Remediation approved plan content changed after approval"
                    if content_changed
                    else _REASONS[GateCode.PLAN_BINDING_CHANGED]
                ),
                category="approval_validation",
            ),
            True,
            content_changed,
            previous_version,
            previous_hash,
            updated,
        )

    @staticmethod
    def approve_plan(
        remediation: Remediation,
        host: Host,
        request: ApprovalRequest,
        actor: str,
        current: datetime,
    ) -> RemediationTransition:
        updated = remediation.model_copy(deep=True)
        if updated.approval_state != "pending":
            return RemediationTransition(
                GateDecision.deny(
                    GateCode.PLAN_NOT_PENDING,
                    category="approval_validation",
                ),
                updated,
            )
        request_decision = TrustedChangeGate.validate_approval_request(
            host,
            updated,
            request,
        )
        if not request_decision.allowed:
            return RemediationTransition(request_decision, updated)
        catalog = _catalog_decision(updated)
        if not catalog.allowed:
            return RemediationTransition(catalog, updated)
        evidence = _evidence_decision(updated)
        if not evidence.allowed:
            return RemediationTransition(evidence, updated)
        updated.approval_state = "approved"
        updated.approved_by = actor
        updated.approved_at = current
        updated.approved_plan_version = updated.plan_version
        updated.approved_plan_hash = updated.plan_hash
        updated.reboot_approval_state = (
            "pending" if _reboot_risk(updated) else "not_required"
        )
        updated.reboot_approved_by = None
        updated.reboot_approved_at = None
        updated.reboot_approved_plan_version = None
        updated.reboot_approved_plan_hash = None
        updated.reboot_assessment.approved_if_required = False
        updated.updated_at = current
        return RemediationTransition(GateDecision.allow(), updated)

    @staticmethod
    def approve_reboot(
        remediation: Remediation,
        host: Host,
        request: ApprovalRequest,
        actor: str,
        current: datetime,
    ) -> RemediationTransition:
        updated = remediation.model_copy(deep=True)
        if updated.approval_state != "approved":
            return RemediationTransition(
                GateDecision.deny(
                    GateCode.PLAN_NOT_APPROVED,
                    message="The remediation plan must be approved before reboot approval",
                    category="approval_validation",
                ),
                updated,
            )
        request_decision = TrustedChangeGate.validate_approval_request(
            host,
            updated,
            request,
        )
        if not request_decision.allowed:
            return RemediationTransition(request_decision, updated)
        if not _reboot_risk(updated):
            return RemediationTransition(
                GateDecision.deny(
                    GateCode.REBOOT_NOT_REQUIRED,
                    category="approval_validation",
                ),
                updated,
            )
        if host.patch_policy.reboot_policy == "never":
            updated.reboot_approval_state = "blocked"
            updated.execution_state = "blocked"
            updated.updated_at = current
            return RemediationTransition(
                GateDecision.deny(GateCode.REBOOT_POLICY_DENIED),
                updated,
            )
        updated.reboot_approval_state = "approved"
        updated.reboot_approved_by = actor
        updated.reboot_approved_at = current
        updated.reboot_approved_plan_version = updated.plan_version
        updated.reboot_approved_plan_hash = updated.plan_hash
        updated.reboot_assessment.approved_if_required = True
        updated.updated_at = current
        return RemediationTransition(GateDecision.allow(), updated)

    @staticmethod
    def validate_approval_request(
        host: Host,
        remediation: Remediation,
        request: ApprovalRequest,
    ) -> GateDecision:
        if remediation.host_id != host.id:
            return GateDecision.deny(
                GateCode.HOST_BINDING_INVALID,
                category="approval_validation",
            )
        if request.hostname_confirmation != host.name:
            return GateDecision.deny(
                GateCode.HOSTNAME_MISMATCH,
                category="approval_validation",
            )
        if request.plan_version != remediation.plan_version:
            return GateDecision.deny(
                GateCode.PLAN_VERSION_CHANGED,
                message="The remediation plan changed and must be reviewed again",
                category="approval_validation",
            )
        if request.plan_hash != remediation.plan_hash:
            return GateDecision.deny(
                GateCode.PLAN_HASH_CHANGED,
                message="The remediation plan changed and must be reviewed again",
                category="approval_validation",
            )
        if remediation.plan_hash != TrustedChangeGate.plan_hash(remediation):
            return GateDecision.deny(
                GateCode.PLAN_CONTENT_CHANGED,
                message="The remediation plan changed and must be reviewed again",
                category="approval_validation",
            )
        return GateDecision.allow()

    @staticmethod
    def execution_eligibility(
        remediation: Remediation,
        host: Host,
        *,
        job: Optional[DurableJob] = None,
        active_rollback_failure: bool = False,
    ) -> GateDecision:
        if active_rollback_failure:
            return GateDecision.deny(GateCode.ACTIVE_ROLLBACK_FAILURE)
        approval = _approval_decision(remediation, host)
        if not approval.allowed:
            return approval
        snapshot = TrustedChangeGate.snapshot_requirement(host, remediation)
        if not snapshot.decision.allowed:
            return snapshot.decision
        if job is None:
            return GateDecision.allow()
        if (
            job.remediation_id != remediation.id
            or job.host_id != host.id
            or job.scan_id != remediation.scan_id
        ):
            return GateDecision.deny(
                GateCode.HOST_BINDING_INVALID,
                category="approval_validation",
            )
        if job.approval_scope != _expected_job_scope(remediation):
            return GateDecision.deny(
                GateCode.APPROVAL_SCOPE_INVALID,
                message="Durable job approval scope is invalid",
                category="approval_validation",
            )
        if job.approved_plan_version != remediation.plan_version:
            return GateDecision.deny(
                GateCode.PLAN_VERSION_CHANGED,
                category="approval_validation",
            )
        if job.approved_plan_hash != remediation.plan_hash:
            return GateDecision.deny(
                GateCode.PLAN_HASH_CHANGED,
                category="approval_validation",
            )
        if remediation.approved_plan_version != job.approved_plan_version:
            return GateDecision.deny(
                GateCode.PLAN_BINDING_CHANGED,
                message="Approved remediation plan version binding changed",
                category="approval_validation",
            )
        if remediation.approved_plan_hash != job.approved_plan_hash:
            return GateDecision.deny(
                GateCode.PLAN_BINDING_CHANGED,
                message="Approved remediation plan hash binding changed",
                category="approval_validation",
            )
        return GateDecision.allow()

    @staticmethod
    def reboot_execution_eligibility(
        remediation: Remediation,
        host: Host,
        reboot_required: bool,
    ) -> GateDecision:
        if not reboot_required:
            return GateDecision.allow()
        return _approval_decision(remediation, host)

    @staticmethod
    def duplicate_execution(
        existing: DurableJob,
        campaign_id: Optional[str],
    ) -> GateDecision:
        if existing.campaign_id != campaign_id:
            return GateDecision.deny(
                GateCode.DUPLICATE_EXECUTION,
                category="approval_validation",
            )
        return GateDecision.allow()

    @staticmethod
    def timing(remediation: Remediation, current: datetime) -> TimingDecision:
        if _maintenance_window_is_open(remediation, current):
            return TimingDecision(
                GateDecision.allow(),
                "queued",
                "queued",
            )
        return TimingDecision(
            GateDecision.deny(
                GateCode.MAINTENANCE_WINDOW_CLOSED,
                category="scheduling",
            ),
            "scheduled",
            "waiting_for_window",
        )

    @staticmethod
    def drift(
        approved: Optional[HostSnapshot],
        current: Optional[HostSnapshot],
    ) -> GateDecision:
        if approved is None or current is None:
            return GateDecision.deny(
                GateCode.EVIDENCE_INCOMPLETE,
                message="Approved scan snapshot is unavailable",
                category="approval_validation",
            )
        previous_packages = sorted(
            (item.name, item.candidate_version)
            for item in approved.package_summary.updates
        )
        current_packages = sorted(
            (item.name, item.candidate_version)
            for item in current.package_summary.updates
        )
        changed = any(
            (
                previous_packages != current_packages,
                sorted(approved.service_summary.failed_units)
                != sorted(current.service_summary.failed_units),
                approved.package_summary.reboot_required_now
                != current.package_summary.reboot_required_now,
            )
        )
        return (
            GateDecision.deny(GateCode.HOST_STATE_DRIFT)
            if changed
            else GateDecision.allow()
        )

    @staticmethod
    def snapshot_requirement(
        host: Host,
        remediation: Remediation,
    ) -> SnapshotDecision:
        protection = remediation.pre_change_protection
        planned = bool(protection.get("supported")) or protection.get("status") == "configured"
        configured = SnapshotPlatform(host.snapshot_platform) != SnapshotPlatform.NONE
        if planned and not configured:
            return SnapshotDecision(
                GateDecision.deny(GateCode.SNAPSHOT_CONFIGURATION_INCOMPLETE),
                True,
            )
        if not _reboot_risk(remediation) or not (planned or configured):
            return SnapshotDecision(GateDecision.allow(), False)
        if (
            not host.snapshot_credential_id
            or not (host.snapshot_target_id or host.snapshot_provider_metadata)
        ):
            return SnapshotDecision(
                GateDecision.deny(GateCode.SNAPSHOT_CONFIGURATION_INCOMPLETE),
                True,
            )
        return SnapshotDecision(GateDecision.allow(), True)

    @staticmethod
    def snapshot_creation(success: bool, summary: str) -> GateDecision:
        if success:
            return GateDecision.allow()
        return GateDecision.deny(
            GateCode.SNAPSHOT_CREATE_FAILED,
            message="Snapshot creation failed before package changes: %s" % summary,
        )

    @staticmethod
    def post_change_health(healthy: bool) -> PostChangeDecision:
        if healthy:
            return PostChangeDecision(
                GateDecision.allow(),
                PostChangeAction.COMPLETE,
                RollbackSnapshotState.DELETE_SCHEDULED,
            )
        return PostChangeDecision(
            GateDecision.deny(GateCode.ROLLBACK_REQUIRED),
            PostChangeAction.ROLLBACK,
            RollbackSnapshotState.ROLLBACK_STARTED,
        )

    @staticmethod
    def rollback_result(success: bool) -> RollbackDecision:
        if success:
            return RollbackDecision(
                GateDecision.deny(GateCode.ROLLBACK_SUCCEEDED),
                RollbackSnapshotState.ROLLED_BACK,
                "blocked",
                _REASONS[GateCode.ROLLBACK_SUCCEEDED],
            )
        return RollbackDecision(
            GateDecision.deny(GateCode.ROLLBACK_FAILED),
            RollbackSnapshotState.ROLLBACK_FAILED,
            "blocked",
            _REASONS[GateCode.ROLLBACK_FAILED],
        )

    @staticmethod
    def execution_outcome(
        result: ExecutionResult,
        snapshot_state: Optional[RollbackSnapshotState] = None,
    ) -> ExecutionOutcome:
        if result.success:
            return ExecutionOutcome(
                GateDecision.allow(),
                "succeeded",
                "completed",
                False,
            )
        if snapshot_state in (
            RollbackSnapshotState.CREATED,
            RollbackSnapshotState.ROLLBACK_STARTED,
            RollbackSnapshotState.ROLLED_BACK,
            RollbackSnapshotState.ROLLBACK_FAILED,
        ):
            code = (
                GateCode.ROLLBACK_FAILED
                if snapshot_state == RollbackSnapshotState.ROLLBACK_FAILED
                else (
                    GateCode.ROLLBACK_SUCCEEDED
                    if snapshot_state == RollbackSnapshotState.ROLLED_BACK
                    else GateCode.EXECUTION_CHANGED_FAILED
                )
            )
            return ExecutionOutcome(
                GateDecision.deny(
                    code,
                    message=result.summary,
                    category="safety_validation",
                ),
                "blocked",
                "failed",
                True,
            )
        if result.changed:
            return ExecutionOutcome(
                GateDecision.deny(
                    GateCode.EXECUTION_CHANGED_FAILED,
                    message=result.summary,
                    category=TrustedChangeGate.failure_category(result.summary),
                ),
                "failed",
                "failed",
                True,
            )
        retryable = not TrustedChangeGate.failure_is_non_retryable(result.summary)
        decision = GateDecision.deny(
            GateCode.EXECUTION_FAILED,
            message=result.summary,
            category=TrustedChangeGate.failure_category(result.summary),
            retryable=retryable,
        )
        return ExecutionOutcome(
            decision,
            "queued" if retryable else "failed",
            "queued" if retryable else "failed",
            not retryable,
        )

    @staticmethod
    def failure_category(summary: str) -> str:
        lowered = summary.lower()
        if "approv" in lowered or "plan" in lowered:
            return "approval_validation"
        if any(
            marker in lowered
            for marker in (
                "host key",
                "blocked",
                "snapshot",
                "rollback",
                "health check",
                "human intervention",
            )
        ):
            return "safety_validation"
        return "remediation_execution"

    @staticmethod
    def failure_is_non_retryable(summary: str) -> bool:
        lowered = summary.lower()
        return any(
            marker in lowered
            for marker in (
                "approval",
                "approved",
                "plan changed",
                "host key",
                "execution blocked",
                "reboot scope",
                "policy forbids",
                "snapshot",
                "rollback",
                "health check",
                "human intervention",
            )
        )

    @staticmethod
    def stale_recovery(job: DurableJob, exhausted: bool) -> RecoveryDecision:
        recovered_phase = str(
            job.result.get("recovered_from_phase") or job.current_phase or ""
        )
        if recovered_phase in (
            "snapshot_create",
            "ansible_execution",
            "post_reboot_health_check",
            "snapshot_rollback",
        ):
            return RecoveryDecision(
                GateDecision.deny(
                    GateCode.STALE_EXECUTION_UNCERTAIN,
                    category="safety_validation",
                ),
                "blocked",
                False,
            )
        if exhausted:
            return RecoveryDecision(
                GateDecision.deny(
                    GateCode.EXECUTION_FAILED,
                    message=job.error or "Job retry attempts were exhausted",
                    category="worker_lease_expired",
                ),
                "failed",
                False,
            )
        return RecoveryDecision(
            GateDecision.allow(),
            "queued",
            True,
        )

    @staticmethod
    def campaign_plan_binding(
        host_plan: CampaignHostPlan,
        remediation: Remediation,
    ) -> GateDecision:
        if remediation.host_id != host_plan.host_id:
            return GateDecision.deny(
                GateCode.HOST_BINDING_INVALID,
                category="approval_validation",
            )
        if (
            host_plan.plan_version != remediation.plan_version
            or host_plan.plan_hash != remediation.plan_hash
            or remediation.plan_hash != TrustedChangeGate.plan_hash(remediation)
        ):
            return GateDecision.deny(
                GateCode.CAMPAIGN_PLAN_CHANGED,
                category="approval_validation",
            )
        return GateDecision.allow()

    @staticmethod
    def campaign_rollout_limit(
        hosts: Sequence[Host],
        remediations: Sequence[Remediation] = (),
    ) -> int:
        limits = [host.patch_policy.max_batch_size for host in hosts]
        limits.extend(
            remediation.rollout_policy.batch_size
            for remediation in remediations
        )
        return max(1, min(limits))

    @staticmethod
    def stop_campaign_after_failure(remediation: Remediation) -> bool:
        return remediation.failure_policy.stop_remaining_hosts

    @staticmethod
    def campaign_batch(
        campaign: PatchCampaign,
        remediations: Mapping[str, Remediation],
    ) -> CampaignBatchDecision:
        if _campaign_terminal(campaign):
            return CampaignBatchDecision(
                GateDecision.deny(GateCode.CAMPAIGN_STATE_INVALID)
            )
        if any(
            host.state
            in (
                CampaignHostState.SCHEDULED,
                CampaignHostState.QUEUED,
                CampaignHostState.RUNNING,
            )
            for host in campaign.hosts
        ):
            return CampaignBatchDecision(
                GateDecision.deny(GateCode.CAMPAIGN_BATCH_IN_PROGRESS)
            )
        approved: List[str] = []
        changed: List[str] = []
        limits = [campaign.batch_size]
        canary_limits: List[int] = []
        for host_plan in campaign.hosts:
            if host_plan.state != CampaignHostState.APPROVED:
                continue
            remediation = (
                remediations.get(host_plan.remediation_id)
                if host_plan.remediation_id
                else None
            )
            if not remediation:
                changed.append(host_plan.host_id)
                continue
            binding = TrustedChangeGate.campaign_plan_binding(
                host_plan,
                remediation,
            )
            if not binding.allowed:
                changed.append(host_plan.host_id)
                continue
            limits.append(remediation.rollout_policy.batch_size)
            canary_limits.append(remediation.rollout_policy.canary_count)
            approved.append(host_plan.host_id)
        if not approved:
            return CampaignBatchDecision(
                GateDecision.deny(GateCode.CAMPAIGN_NO_APPROVED_HOSTS),
                [],
                changed,
            )
        limit = max(1, min(limits))
        if campaign.current_batch == 0 and canary_limits:
            limit = min(limit, max(1, min(canary_limits)))
        return CampaignBatchDecision(
            GateDecision.allow(),
            approved[:limit],
            changed,
        )

    @staticmethod
    def start_campaign_batch(
        campaign: PatchCampaign,
        jobs_by_host: Mapping[str, DurableJob],
        current: datetime,
    ) -> PatchCampaign:
        updated = campaign.model_copy(deep=True)
        for host_plan in updated.hosts:
            job = jobs_by_host.get(host_plan.host_id)
            if not job:
                continue
            host_plan.job_id = job.id
            host_plan.state = (
                CampaignHostState.QUEUED
                if job.status == "queued"
                else CampaignHostState.SCHEDULED
            )
            host_plan.updated_at = current
        updated.status = CampaignStatus.RUNNING
        updated.current_batch = min(
            updated.total_batches,
            updated.current_batch + 1,
        )
        updated.updated_at = current
        return updated

    @staticmethod
    def project_campaign(
        campaign: PatchCampaign,
        remediations: Mapping[str, Remediation],
        jobs: Mapping[str, DurableJob],
        current: datetime,
    ) -> PatchCampaign:
        updated = campaign.model_copy(deep=True)
        for host_plan in updated.hosts:
            if not host_plan.remediation_id:
                continue
            remediation = remediations.get(host_plan.remediation_id)
            if not remediation:
                host_plan.state = CampaignHostState.FAILED
                host_plan.failure_summary = "Remediation proposal no longer exists"
                host_plan.updated_at = current
                continue
            binding = TrustedChangeGate.campaign_plan_binding(
                host_plan,
                remediation,
            )
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
            if remediation.result and not remediation.result.success:
                host_plan.failure_summary = remediation.result.summary
            job = jobs.get(host_plan.job_id) if host_plan.job_id else None
            host_plan.state = TrustedChangeGate._campaign_host_state(
                host_plan,
                remediation,
                job,
                binding,
            )
            if host_plan.state == CampaignHostState.PLAN_CHANGED:
                host_plan.failure_summary = _REASONS[GateCode.CAMPAIGN_PLAN_CHANGED]
            host_plan.updated_at = current
        TrustedChangeGate._project_campaign_status(updated)
        updated.remediation_ids = [
            item.remediation_id for item in updated.hosts if item.remediation_id
        ]
        completed_count = sum(
            item.state
            in (
                CampaignHostState.SUCCEEDED,
                CampaignHostState.FAILED,
                CampaignHostState.CANCELED,
                CampaignHostState.NO_ACTION,
            )
            for item in updated.hosts
        )
        completed_batches = (
            int(math.ceil(completed_count / updated.batch_size))
            if completed_count
            else 0
        )
        updated.current_batch = min(
            updated.total_batches,
            max(updated.current_batch, completed_batches),
        )
        updated.updated_at = current
        return updated

    @staticmethod
    def _campaign_host_state(
        host_plan: CampaignHostPlan,
        remediation: Remediation,
        job: Optional[DurableJob],
        binding: GateDecision,
    ) -> CampaignHostState:
        if job and job.job_type == "remediation" and job.status == "running":
            return CampaignHostState.RUNNING
        if job and job.job_type == "remediation" and job.status == "canceled":
            return CampaignHostState.CANCELED
        execution_states = {
            "succeeded": CampaignHostState.SUCCEEDED,
            "failed": CampaignHostState.FAILED,
            "running": CampaignHostState.RUNNING,
            "queued": CampaignHostState.QUEUED,
            "waiting_for_window": CampaignHostState.SCHEDULED,
            "canceled": CampaignHostState.CANCELED,
        }
        if remediation.execution_state in execution_states:
            return execution_states[remediation.execution_state]
        if (
            not binding.allowed
            or (
                host_plan.state == CampaignHostState.PLAN_CHANGED
                and remediation.approval_state == "pending"
            )
        ):
            return CampaignHostState.PLAN_CHANGED
        if remediation.approval_state == "rejected":
            return CampaignHostState.REJECTED
        if remediation.approval_state == "manual_review":
            return CampaignHostState.BLOCKED
        if remediation.execution_state == "blocked":
            return CampaignHostState.BLOCKED
        if remediation.approval_state != "approved":
            return CampaignHostState.AWAITING_APPROVAL
        if _reboot_risk(remediation):
            if remediation.reboot_approval_state == "approved":
                return CampaignHostState.APPROVED
            if remediation.reboot_approval_state in ("blocked", "rejected"):
                return CampaignHostState.BLOCKED
            return CampaignHostState.AWAITING_REBOOT_APPROVAL
        return CampaignHostState.APPROVED

    @staticmethod
    def _project_campaign_status(campaign: PatchCampaign) -> None:
        if campaign.canceled_at:
            campaign.status = (
                CampaignStatus.CANCELLING
                if any(
                    item.state == CampaignHostState.RUNNING
                    for item in campaign.hosts
                )
                else CampaignStatus.CANCELED
            )
            return
        if campaign.status == CampaignStatus.CANCELED:
            return
        states = {
            item.state.value
            if isinstance(item.state, CampaignHostState)
            else str(item.state)
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
            TrustedChangeGate._project_terminal_campaign_status(campaign)
        failures = [
            item.failure_summary for item in campaign.hosts if item.failure_summary
        ]
        campaign.failure_summary = "; ".join(failures)[:2000] or None

    @staticmethod
    def _project_terminal_campaign_status(campaign: PatchCampaign) -> None:
        succeeded = sum(
            item.state == CampaignHostState.SUCCEEDED for item in campaign.hosts
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
            item.state == CampaignHostState.APPROVED for item in campaign.hosts
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
        elif failed:
            campaign.status = CampaignStatus.FAILED
        elif not actionable:
            campaign.status = CampaignStatus.SUCCEEDED
        else:
            campaign.status = CampaignStatus.DRAFT
