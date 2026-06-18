from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, ConfigDict, Field


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def to_camel(value: str) -> str:
    parts = value.split("_")
    return parts[0] + "".join(part.capitalize() for part in parts[1:])


class ApiModel(BaseModel):
    model_config = ConfigDict(
        alias_generator=to_camel,
        populate_by_name=True,
        use_enum_values=True,
    )


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class AgentName(str, Enum):
    ORCHESTRATOR = "orchestrator"
    LOG_ANALYST = "log_analyst"
    LINUX_STATE_ANALYST = "linux_state_analyst"


class ModelTier(str, Enum):
    CAPABLE = "capable"
    ECONOMY = "economy"
    DETERMINISTIC = "deterministic"


class AgentIdentity(ApiModel):
    name: AgentName
    responsibility: str
    model_tier: ModelTier
    provider: str
    model: str
    selection_reason: str


class MaintenanceWindow(ApiModel):
    timezone: str = "UTC"
    weekdays: List[int] = Field(default_factory=lambda: [6], description="Monday is 0")
    start_time: str = "02:00"
    duration_minutes: int = Field(default=120, ge=15, le=1440)


class PatchPolicy(ApiModel):
    update_mode: str = Field(default="orchestrator_decides", pattern="^(orchestrator_decides|all|security)$")
    execution_timing: str = Field(default="immediate", pattern="^(immediate|maintenance_window)$")
    maintenance_window: Optional[MaintenanceWindow] = None
    max_batch_size: int = Field(default=5, ge=1, le=100)
    canary_count: int = Field(default=1, ge=1, le=20)
    reboot_policy: str = Field(default="if_required", pattern="^(if_required|never)$")


class HostInput(ApiModel):
    name: str
    address: str
    port: int = Field(default=22, ge=1, le=65535)
    username: str
    distro_family: str = Field(default="debian", pattern="^debian$")
    environment: str = "default"
    tags: List[str] = Field(default_factory=list)
    criticality: str = Field(default="normal", pattern="^(low|normal|high)$")
    availability_class: str = Field(default="standard", pattern="^(standard|high_availability)$")
    credential_id: Optional[str] = None
    patch_policy: PatchPolicy = Field(default_factory=PatchPolicy)


class Host(HostInput):
    id: str
    created_at: datetime
    updated_at: datetime


class SshCredential(ApiModel):
    id: str
    name: str
    fingerprint: str
    created_at: datetime


class PackageUpdate(ApiModel):
    name: str
    current_version: Optional[str] = None
    candidate_version: str
    security_update: bool = False
    reboot_hint: bool = False


class PackageSummary(ApiModel):
    pending_security_updates: int = 0
    pending_package_updates: int = 0
    reboot_required_now: bool = False
    updates: List[PackageUpdate] = Field(default_factory=list)


class ServiceSummary(ApiModel):
    failed_units: List[str] = Field(default_factory=list)


class SystemSummary(ApiModel):
    uptime_hours: float
    load_average: List[float]
    disk_usage_percent: float
    memory_usage_percent: float
    kernel_version: str


class HostLogs(ApiModel):
    journal: str = ""
    auth: str = ""
    apt_history: str = ""


class HostSnapshot(ApiModel):
    host_id: str
    collected_at: datetime
    commands: Dict[str, str]
    package_summary: PackageSummary
    service_summary: ServiceSummary
    system_summary: SystemSummary
    logs: HostLogs


class Evidence(ApiModel):
    source: str
    excerpt: str
    citation: str


class RecommendedAction(ApiModel):
    action_type: str
    title: str
    rationale: str


class Finding(ApiModel):
    id: str
    host_id: str
    source_agent: AgentName
    category: str
    severity: Severity
    summary: str
    explanation: str
    evidence: List[Evidence]
    recommended_action: Optional[RecommendedAction] = None
    requires_approval: bool
    confidence: float = Field(ge=0, le=1)
    status: str = "open"
    created_at: datetime


class AgentReport(ApiModel):
    agent: AgentIdentity
    overview: str
    findings: List[Finding]


class RebootAssessment(ApiModel):
    status: str = Field(pattern="^(required|likely|required_after_patch|not_expected|unknown)$")
    rationale: str
    evidence: List[Evidence]
    estimated_downtime_minutes: int = Field(default=5, ge=0, le=180)
    approved_if_required: bool = False


class RolloutPolicy(ApiModel):
    strategy: str = Field(pattern="^(one_at_a_time|canary_then_batches)$")
    batch_size: int = Field(ge=1)
    canary_count: int = Field(ge=1)
    rationale: str


class FailurePolicy(ApiModel):
    stop_remaining_hosts: bool = True
    notify_operator: bool = True
    attempt_predefined_recovery: bool = True
    recovery_actions: List[str] = Field(
        default_factory=lambda: [
            "collect_failed_services",
            "collect_package_manager_state",
            "mark_campaign_halted",
        ]
    )


class AiDecision(ApiModel):
    update_scope: str = Field(pattern="^(all|security|none)$")
    risk_level: Severity
    explanation: str
    agent_assignments: List[AgentIdentity]


class ExecutionPhase(ApiModel):
    name: str
    state: str
    summary: str
    output: str = ""
    changed: bool = False


class ExecutionResult(ApiModel):
    success: bool
    summary: str
    changed: bool
    reboot_performed: bool
    phases: List[ExecutionPhase]
    failure_actions_taken: List[str] = Field(default_factory=list)


class Remediation(ApiModel):
    id: str
    host_id: str
    title: str
    action_type: str = "package_upgrade"
    update_scope: str
    risk_level: Severity
    ai_decision: AiDecision
    reboot_assessment: RebootAssessment
    rollout_policy: RolloutPolicy
    failure_policy: FailurePolicy = Field(default_factory=FailurePolicy)
    execution_timing: str
    maintenance_window: Optional[MaintenanceWindow] = None
    approval_scope: str = "patch_and_reboot_if_required"
    approval_state: str = "pending"
    execution_state: str = "not_started"
    result: Optional[ExecutionResult] = None
    pre_change_protection: Dict[str, Any] = Field(
        default_factory=lambda: {"supported": False, "status": "deferred"}
    )
    created_at: datetime
    updated_at: datetime


class ScanRequest(ApiModel):
    host_id: str


class ScanJob(ApiModel):
    id: str
    host_id: str
    status: str
    finding_ids: List[str] = Field(default_factory=list)
    remediation_ids: List[str] = Field(default_factory=list)
    agent_reports: List[AgentReport] = Field(default_factory=list)
    error: Optional[str] = None
    created_at: datetime
    updated_at: datetime


class CampaignRequest(ApiModel):
    name: str
    host_ids: List[str] = Field(min_length=1)


class PatchCampaign(ApiModel):
    id: str
    name: str
    host_ids: List[str]
    remediation_ids: List[str]
    status: str
    batch_size: int
    current_batch: int = 0
    total_batches: int
    approval_scope: str = "patch_and_reboot_if_required"
    failure_summary: Optional[str] = None
    created_at: datetime
    updated_at: datetime


class ProviderDecision(ApiModel):
    update_scope: str
    explanation: str
    risk_level: str
