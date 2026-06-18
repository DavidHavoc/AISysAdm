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
        protected_namespaces=(),
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


class CampaignStatus(str, Enum):
    DRAFT = "draft"
    PROPOSING = "proposing"
    AWAITING_APPROVAL = "awaiting_approval"
    READY = "ready"
    RUNNING = "running"
    PARTIALLY_SUCCEEDED = "partially_succeeded"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    CANCELLING = "cancelling"
    CANCELED = "canceled"


class CampaignHostState(str, Enum):
    SELECTED = "selected"
    PROPOSAL_QUEUED = "proposal_queued"
    PROPOSAL_RUNNING = "proposal_running"
    AWAITING_APPROVAL = "awaiting_approval"
    AWAITING_REBOOT_APPROVAL = "awaiting_reboot_approval"
    APPROVED = "approved"
    SCHEDULED = "scheduled"
    QUEUED = "queued"
    RUNNING = "running"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    REJECTED = "rejected"
    BLOCKED = "blocked"
    CANCELED = "canceled"
    NO_ACTION = "no_action"
    PLAN_CHANGED = "plan_changed"


class AgentIdentity(ApiModel):
    name: AgentName
    responsibility: str
    model_tier: ModelTier
    provider: str
    model: str
    selection_reason: str
    contract_version: int = 1
    contract_hash: str = ""


class AgentMessage(ApiModel):
    id: str
    scan_id: str
    from_agent: AgentName
    to_agent: AgentName
    round: int = Field(default=1, ge=1, le=1)
    response: str = Field(
        pattern="^(report|confirm|challenge|request_evidence|not_applicable|synthesis)$"
    )
    claim_ids: List[str] = Field(default_factory=list)
    reasoning: str
    citations: List[str] = Field(default_factory=list)
    created_at: datetime


class AgentRun(ApiModel):
    id: str
    scan_id: str
    agent: AgentIdentity
    status: str
    input_hash: str
    output: Dict[str, Any]
    prompt_tokens: int = 0
    completion_tokens: int = 0
    latency_ms: int = 0
    cache_hit: bool = False
    fallback_reason: Optional[str] = None
    externally_processed: bool = False
    created_at: datetime


class MaintenanceWindow(ApiModel):
    timezone: str = "UTC"
    weekdays: List[int] = Field(default_factory=lambda: [6], description="Monday is 0")
    start_time: str = "02:00"
    duration_minutes: int = Field(default=120, ge=15, le=1440)


class PatchPolicy(ApiModel):
    update_mode: str = Field(
        default="orchestrator_decides",
        pattern="^(orchestrator_decides|all|security)$",
    )
    execution_timing: str = Field(
        default="immediate",
        pattern="^(immediate|maintenance_window)$",
    )
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
    availability_class: str = Field(
        default="standard",
        pattern="^(standard|high_availability)$",
    )
    credential_id: Optional[str] = None
    ssh_host_key_fingerprint: Optional[str] = None
    patch_policy: PatchPolicy = Field(default_factory=PatchPolicy)


class Host(HostInput):
    id: str
    connection_status: str = "untested"
    created_at: datetime
    updated_at: datetime


class HostScheduleInput(ApiModel):
    enabled: bool = False
    timezone: str = "UTC"
    cron_expression: str = "0 3 * * *"
    overlap_policy: str = Field(default="skip_if_running", pattern="^skip_if_running$")


class HostSchedule(HostScheduleInput):
    id: str
    host_id: str
    previous_run_at: Optional[datetime] = None
    next_run_at: Optional[datetime] = None
    created_at: datetime
    updated_at: datetime


class SshCredential(ApiModel):
    id: str
    name: str
    fingerprint: str
    created_at: datetime
    last_used_at: Optional[datetime] = None


class ConnectionTestResult(ApiModel):
    success: bool
    ssh_reachable: bool
    sudo_available: bool
    os_supported: bool
    ansible_compatible: bool
    host_key_fingerprint: Optional[str] = None
    checks: Dict[str, str] = Field(default_factory=dict)


class ConnectionTestRequest(ApiModel):
    confirm_fingerprint: Optional[str] = None


class EvidenceState(ApiModel):
    status: str = Field(
        default="available",
        pattern="^(available|missing|unavailable|permission_denied|truncated)$",
    )
    original_bytes: int = 0
    retained_bytes: int = 0
    truncated: bool = False
    reason: Optional[str] = None


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
    held_packages: List[str] = Field(default_factory=list)
    updates: List[PackageUpdate] = Field(default_factory=list)


class ServiceSummary(ApiModel):
    failed_units: List[str] = Field(default_factory=list)
    restarting_units: List[str] = Field(default_factory=list)
    degraded: bool = False


class SystemSummary(ApiModel):
    uptime_hours: float
    load_average: List[float]
    disk_usage_percent: float
    inode_usage_percent: float = 0
    memory_usage_percent: float
    kernel_version: str
    boot_id: str = "unknown"


class NetworkSummary(ApiModel):
    interfaces: List[str] = Field(default_factory=list)
    default_routes: List[str] = Field(default_factory=list)
    dns_servers: List[str] = Field(default_factory=list)
    listening_ports: List[str] = Field(default_factory=list)


class HostLogs(ApiModel):
    journal: str = ""
    kernel: str = ""
    auth: str = ""
    apt_history: str = ""
    reboot_history: str = ""


class HostSnapshot(ApiModel):
    id: str = ""
    host_id: str
    collected_at: datetime
    commands: Dict[str, str]
    evidence_states: Dict[str, EvidenceState] = Field(default_factory=dict)
    package_summary: PackageSummary
    service_summary: ServiceSummary
    system_summary: SystemSummary
    network_summary: NetworkSummary = Field(default_factory=NetworkSummary)
    logs: HostLogs
    snapshot_hash: str = ""


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
    scan_id: Optional[str] = None
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
    verifier_status: str = "pending"
    verifier_reason: Optional[str] = None
    created_at: datetime


class AgentReport(ApiModel):
    agent: AgentIdentity
    overview: str
    findings: List[Finding]


class RebootAssessment(ApiModel):
    status: str = Field(
        pattern="^(required|likely|required_after_patch|not_expected|unknown)$"
    )
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
    status: str = Field(default="plan_ready", pattern="^(plan_ready|insufficient_evidence)$")
    supporting_citations: List[str] = Field(default_factory=list)
    unresolved_conflicts: List[str] = Field(default_factory=list)
    agent_assignments: List[AgentIdentity]


class StructuredLogEvent(ApiModel):
    id: str
    schema_version: str = "1.0"
    timestamp: datetime
    duration_ms: int = 0
    host_id: Optional[str] = None
    job_id: Optional[str] = None
    scan_id: Optional[str] = None
    remediation_id: Optional[str] = None
    agent_run_id: Optional[str] = None
    playbook_id: Optional[str] = None
    phase_id: Optional[str] = None
    task_id: Optional[str] = None
    event_type: str
    evidence_category: str
    severity: Severity = Severity.INFO
    status: str
    changed: bool = False
    return_code: Optional[int] = None
    retry_count: int = 0
    failure_classification: Optional[str] = None
    command_description: Optional[str] = None
    before_value: Optional[Any] = None
    after_value: Optional[Any] = None
    stdout: str = ""
    stderr: str = ""
    raw_output: str = ""
    source: str = ""
    truncated: bool = False
    original_bytes: int = 0
    redacted: bool = False
    simulated: bool = False
    externally_processed: bool = False
    reboot_relevance: str = "none"
    remediation_relevance: str = "informational"
    correlation_ids: Dict[str, str] = Field(default_factory=dict)


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
    events: List[StructuredLogEvent] = Field(default_factory=list)
    failure_actions_taken: List[str] = Field(default_factory=list)


class Remediation(ApiModel):
    id: str
    host_id: str
    scan_id: Optional[str] = None
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
    approval_scope: str = "patch_only"
    approval_state: str = "pending"
    reboot_approval_state: str = "pending"
    execution_state: str = "not_started"
    plan_version: int = 1
    plan_hash: str = ""
    approved_by: Optional[str] = None
    approved_at: Optional[datetime] = None
    approved_plan_version: Optional[int] = None
    approved_plan_hash: Optional[str] = None
    reboot_approved_by: Optional[str] = None
    reboot_approved_at: Optional[datetime] = None
    reboot_approved_plan_version: Optional[int] = None
    reboot_approved_plan_hash: Optional[str] = None
    result: Optional[ExecutionResult] = None
    pre_change_protection: Dict[str, Any] = Field(
        default_factory=lambda: {"supported": False, "status": "deferred"}
    )
    created_at: datetime
    updated_at: datetime


class ScanRequest(ApiModel):
    host_id: str
    trigger: str = Field(default="manual", pattern="^(manual|scheduled|campaign)$")
    idempotency_key: Optional[str] = None


class ScanJob(ApiModel):
    id: str
    host_id: str
    durable_job_id: Optional[str] = None
    snapshot_id: Optional[str] = None
    trigger: str = "manual"
    status: str
    finding_ids: List[str] = Field(default_factory=list)
    remediation_ids: List[str] = Field(default_factory=list)
    agent_run_ids: List[str] = Field(default_factory=list)
    agent_reports: List[AgentReport] = Field(default_factory=list)
    campaign_id: Optional[str] = None
    error: Optional[str] = None
    created_at: datetime
    updated_at: datetime


class CampaignRequest(ApiModel):
    name: str
    host_ids: List[str] = Field(min_length=1)


class CampaignHostPlan(ApiModel):
    id: str
    campaign_id: str
    host_id: str
    hostname: str
    state: CampaignHostState = CampaignHostState.SELECTED
    scan_id: Optional[str] = None
    remediation_id: Optional[str] = None
    plan_version: Optional[int] = None
    plan_hash: Optional[str] = None
    approval_state: str = "pending"
    reboot_approval_state: str = "pending"
    approved_plan_version: Optional[int] = None
    approved_plan_hash: Optional[str] = None
    approved_by: Optional[str] = None
    approved_at: Optional[datetime] = None
    reboot_approved_by: Optional[str] = None
    reboot_approved_at: Optional[datetime] = None
    reboot_approved_plan_version: Optional[int] = None
    reboot_approved_plan_hash: Optional[str] = None
    job_id: Optional[str] = None
    failure_summary: Optional[str] = None
    created_at: datetime
    updated_at: datetime


class PatchCampaign(ApiModel):
    id: str
    name: str
    host_ids: List[str]
    remediation_ids: List[str]
    hosts: List[CampaignHostPlan] = Field(default_factory=list)
    status: CampaignStatus
    batch_size: int
    current_batch: int = 0
    total_batches: int
    failure_summary: Optional[str] = None
    canceled_by: Optional[str] = None
    canceled_at: Optional[datetime] = None
    created_at: datetime
    updated_at: datetime


class CampaignActionResponse(ApiModel):
    campaign: PatchCampaign
    jobs: List["DurableJob"] = Field(default_factory=list)


class JobFailure(ApiModel):
    failed_at: datetime
    attempt: int
    category: str
    message: str
    retryable: bool


class DurableJob(ApiModel):
    id: str
    job_type: str
    status: str
    host_id: Optional[str] = None
    scan_id: Optional[str] = None
    remediation_id: Optional[str] = None
    campaign_id: Optional[str] = None
    approved_plan_version: Optional[int] = None
    approved_plan_hash: Optional[str] = None
    approval_scope: Optional[str] = None
    idempotency_key: str
    progress_percent: int = 0
    current_phase: Optional[str] = None
    attempts: int = 0
    max_attempts: int = 3
    lease_owner: Optional[str] = None
    lease_expires_at: Optional[datetime] = None
    heartbeat_at: Optional[datetime] = None
    last_failure: Optional[JobFailure] = None
    error: Optional[str] = None
    result: Dict[str, Any] = Field(default_factory=dict)
    created_at: datetime
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    updated_at: datetime


class Alert(ApiModel):
    id: str
    severity: Severity
    title: str
    message: str
    host_id: Optional[str] = None
    job_id: Optional[str] = None
    acknowledged: bool = False
    acknowledged_at: Optional[datetime] = None
    created_at: datetime


class AuditEvent(ApiModel):
    id: str
    actor: str
    action: str
    target_type: str
    target_id: Optional[str] = None
    details: Dict[str, Any] = Field(default_factory=dict)
    created_at: datetime


class User(ApiModel):
    id: str
    username: str
    created_at: datetime


class LoginRequest(ApiModel):
    username: str
    password: str


class LoginResponse(ApiModel):
    user: User
    csrf_token: str


class ApprovalRequest(ApiModel):
    plan_version: int
    plan_hash: str
    hostname_confirmation: str


class RebootApprovalRequest(ApprovalRequest):
    pass


class LogPage(ApiModel):
    items: List[StructuredLogEvent]
    total: int
    page: int
    page_size: int
