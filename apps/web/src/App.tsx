import { useEffect, useMemo, useState } from "react";
import type { FormEvent, ReactNode } from "react";
import type {
  AgentMessage,
  AgentRun,
  Alert,
  AuditEvent,
  CampaignHostPlan,
  ConnectionTestResult,
  DurableJob,
  Finding,
  Host,
  HostInput,
  HostSchedule,
  LogPage,
  PatchCampaign,
  Remediation,
  RollbackSnapshot,
  SshCredential,
  StructuredLogEvent,
  User
} from "@ai-sysadm/shared";
import { api } from "./api.js";
import type { OperationsHealth } from "./api.js";

type HostFormState = {
  name: string;
  address: string;
  port: string;
  username: string;
  environment: string;
  tags: string;
  criticality: HostInput["criticality"];
  availabilityClass: HostInput["availabilityClass"];
  credentialId: string;
  sshHostKeyFingerprint: string;
  snapshotPlatform: HostInput["snapshotPlatform"];
  snapshotCredentialId: string;
  snapshotTargetId: string;
  snapshotProviderMetadata: string;
  criticalServiceName: string;
  healthCheckUrl: string;
  snapshotRetentionDays: string;
  maxBatchSize: string;
  canaryCount: string;
  updateMode: HostInput["patchPolicy"]["updateMode"];
  executionTiming: HostInput["patchPolicy"]["executionTiming"];
  rebootPolicy: HostInput["patchPolicy"]["rebootPolicy"];
};

type ScheduleFormState = Pick<HostSchedule, "enabled" | "timezone" | "cronExpression" | "overlapPolicy">;

type LogFilters = {
  hostId: string;
  jobId: string;
  scanId: string;
  remediationId: string;
  agentRunId: string;
  severity: string;
  source: string;
  phaseId: string;
  taskId: string;
  page: number;
  pageSize: number;
};

type DashboardView = "fleet" | "operations" | "campaigns" | "evidence";
type OperationsSection = "health" | "jobs" | "logs" | "alerts" | "audit" | "agents" | "remediations";

type JobFilters = {
  status: string;
  jobType: string;
  hostId: string;
  scanId: string;
  remediationId: string;
  campaignId: string;
};

const blankHostForm: HostFormState = {
  name: "",
  address: "",
  port: "22",
  username: "ubuntu",
  environment: "production",
  tags: "",
  criticality: "normal",
  availabilityClass: "standard",
  credentialId: "",
  sshHostKeyFingerprint: "",
  snapshotPlatform: "none",
  snapshotCredentialId: "",
  snapshotTargetId: "",
  snapshotProviderMetadata: "{}",
  criticalServiceName: "",
  healthCheckUrl: "",
  snapshotRetentionDays: "7",
  maxBatchSize: "5",
  canaryCount: "1",
  updateMode: "orchestrator_decides",
  executionTiming: "immediate",
  rebootPolicy: "if_required"
};

const defaultScheduleForm: ScheduleFormState = {
  enabled: false,
  timezone: "UTC",
  cronExpression: "0 3 * * *",
  overlapPolicy: "skip_if_running"
};

const emptyLogPage: LogPage = {
  items: [],
  total: 0,
  page: 1,
  pageSize: 25
};

const emptyOperationsHealth: OperationsHealth = {
  live: { ok: false },
  ready: {
    ok: false,
    checks: {
      database: false,
      redis: false,
      executionMode: "unknown",
      collectorMode: "unknown"
    }
  },
  ops: {
    ok: false,
    checks: {
      worker: { healthy: false, lastSeenAt: null },
      celeryBeat: { healthy: false, lastSeenAt: null }
    }
  }
};

export function canExecuteCampaign(campaign: PatchCampaign) {
  return campaign.hosts.some((host) => host.state === "approved");
}

export function canApproveCampaignHost(host: CampaignHostPlan) {
  return Boolean(
    host.state === "awaiting_approval"
    && host.planVersion !== null
    && host.planHash
  );
}

export function remediationRequiresReboot(remediation: Remediation) {
  return remediation.rebootAssessment.status !== "not_expected";
}

export function remediationExecutionBlockers(remediation: Remediation, host?: Host | null) {
  const blockers: string[] = [];
  if (remediation.approvalState !== "approved") {
    blockers.push("Patch plan approval is required.");
  }
  if (
    remediation.approvalState === "approved"
    && (
      !remediation.approvedBy
      || !remediation.approvedAt
      || remediation.approvedPlanVersion === null
      || !remediation.approvedPlanHash
    )
  ) {
    blockers.push("Patch approval metadata is incomplete.");
  }
  if (
    remediation.approvedPlanVersion !== null
    && remediation.approvedPlanVersion !== remediation.planVersion
  ) {
    blockers.push("Patch approval is bound to an older plan version.");
  }
  if (
    remediation.approvedPlanHash
    && remediation.approvedPlanHash !== remediation.planHash
  ) {
    blockers.push("Patch approval is bound to an older plan hash.");
  }
  if (remediationRequiresReboot(remediation)) {
    if (remediation.rebootApprovalState !== "approved") {
      blockers.push("Separate reboot approval is required.");
    }
    if (
      remediation.rebootApprovalState === "approved"
      && (
        !remediation.rebootApprovedBy
        || !remediation.rebootApprovedAt
        || remediation.rebootApprovedPlanVersion !== remediation.planVersion
        || remediation.rebootApprovedPlanHash !== remediation.planHash
        || !remediation.rebootAssessment.approvedIfRequired
      )
    ) {
      blockers.push("Reboot approval metadata is incomplete.");
    }
    if (host?.patchPolicy.rebootPolicy === "never") {
      blockers.push("Host policy forbids reboot risk.");
    }
  }
  if (["queued", "running", "waiting_for_window"].includes(remediation.executionState)) {
    blockers.push("Execution is already queued or running.");
  }
  if (["succeeded", "failed", "canceled"].includes(remediation.executionState)) {
    blockers.push(`Execution is already ${remediation.executionState} for this plan.`);
  }
  return blockers;
}

export function canQueueRemediationExecution(remediation: Remediation, host?: Host | null) {
  return remediationExecutionBlockers(remediation, host).length === 0;
}

export function hostFormFromHost(host: Host): HostFormState {
  return {
    name: host.name,
    address: host.address,
    port: String(host.port),
    username: host.username,
    environment: host.environment,
    tags: host.tags.join(", "),
    criticality: host.criticality,
    availabilityClass: host.availabilityClass,
    credentialId: host.credentialId ?? "",
    sshHostKeyFingerprint: host.sshHostKeyFingerprint ?? "",
    snapshotPlatform: host.snapshotPlatform ?? "none",
    snapshotCredentialId: host.snapshotCredentialId ?? "",
    snapshotTargetId: host.snapshotTargetId ?? "",
    snapshotProviderMetadata: JSON.stringify(host.snapshotProviderMetadata ?? {}, null, 2),
    criticalServiceName: host.criticalServiceName ?? "",
    healthCheckUrl: host.healthCheckUrl ?? "",
    snapshotRetentionDays: String(host.snapshotRetentionDays ?? 7),
    maxBatchSize: String(host.patchPolicy.maxBatchSize),
    canaryCount: String(host.patchPolicy.canaryCount),
    updateMode: host.patchPolicy.updateMode,
    executionTiming: host.patchPolicy.executionTiming,
    rebootPolicy: host.patchPolicy.rebootPolicy
  };
}

export function hostInputFromForm(form: HostFormState): HostInput {
  return {
    name: form.name.trim(),
    address: form.address.trim(),
    port: Number(form.port),
    username: form.username.trim(),
    distroFamily: "debian",
    environment: form.environment.trim() || "default",
    tags: form.tags
      .split(",")
      .map((tag) => tag.trim())
      .filter(Boolean),
    criticality: form.criticality,
    availabilityClass: form.availabilityClass,
    credentialId: form.credentialId || null,
    sshHostKeyFingerprint: form.sshHostKeyFingerprint || null,
    snapshotPlatform: form.snapshotPlatform,
    snapshotCredentialId: form.snapshotCredentialId || null,
    snapshotTargetId: form.snapshotTargetId || null,
    snapshotProviderMetadata: parseJsonObject(form.snapshotProviderMetadata),
    criticalServiceName: form.criticalServiceName || null,
    healthCheckUrl: form.healthCheckUrl || null,
    snapshotRetentionDays: Number(form.snapshotRetentionDays || 7),
    patchPolicy: {
      updateMode: form.updateMode,
      executionTiming: form.executionTiming,
      maxBatchSize: Number(form.maxBatchSize),
      canaryCount: Number(form.canaryCount),
      rebootPolicy: form.rebootPolicy
    }
  };
}

function formatDate(value?: string | null) {
  if (!value) return "Never";
  return new Date(value).toLocaleString();
}

function textValue(value: unknown) {
  if (value === null || value === undefined || value === "") return "None";
  if (typeof value === "string" || typeof value === "number" || typeof value === "boolean") {
    return String(value);
  }
  return JSON.stringify(value, null, 2);
}

function statusClass(value: string) {
  return `status-chip status-${value.replaceAll("_", "-")}`;
}

function hostLabel(hosts: Host[], hostId: string | null) {
  if (!hostId) return "None";
  return hosts.find((host) => host.id === hostId)?.name ?? hostId;
}

function credentialLabel(credentials: SshCredential[], credentialId?: string | null) {
  if (!credentialId) return "None";
  return credentials.find((credential) => credential.id === credentialId)?.name ?? credentialId;
}

function snapshotCredentialAllowed(
  platform: HostInput["snapshotPlatform"],
  credential: SshCredential,
) {
  const credentialType = credential.credentialType ?? "ssh_private_key";
  if (platform === "proxmox") return credentialType === "proxmox_token";
  if (platform === "aws") return credentialType === "aws_access_key" || credentialType === "aws_role";
  if (platform === "vmware") return credentialType === "vmware_secret";
  if (platform === "libvirt") return credentialType === "libvirt_ssh";
  return false;
}

function parseJsonObject(value: string) {
  const trimmed = value.trim();
  if (!trimmed) return {};
  const parsed = JSON.parse(trimmed) as unknown;
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw new Error("Provider metadata must be a JSON object.");
  }
  return parsed as Record<string, unknown>;
}

export function App() {
  const [user, setUser] = useState<User | null>(null);
  const [authChecked, setAuthChecked] = useState(false);
  const [username, setUsername] = useState("admin");
  const [password, setPassword] = useState("");
  const [credentials, setCredentials] = useState<SshCredential[]>([]);
  const [hosts, setHosts] = useState<Host[]>([]);
  const [selectedHostId, setSelectedHostId] = useState<string>("");
  const [hostForm, setHostForm] = useState<HostFormState>(blankHostForm);
  const [editingHostId, setEditingHostId] = useState<string | null>(null);
  const [credentialName, setCredentialName] = useState("");
  const [credentialFile, setCredentialFile] = useState<File | null>(null);
  const [credentialType, setCredentialType] = useState<SshCredential["credentialType"]>("ssh_private_key");
  const [credentialSecret, setCredentialSecret] = useState("");
  const [credentialMetadata, setCredentialMetadata] = useState("{}");
  const [findings, setFindings] = useState<Finding[]>([]);
  const [remediations, setRemediations] = useState<Remediation[]>([]);
  const [snapshots, setSnapshots] = useState<RollbackSnapshot[]>([]);
  const [selectedRemediationId, setSelectedRemediationId] = useState("");
  const [executionConfirmation, setExecutionConfirmation] = useState("");
  const [campaigns, setCampaigns] = useState<PatchCampaign[]>([]);
  const [selectedCampaignId, setSelectedCampaignId] = useState<string>("");
  const [campaignName, setCampaignName] = useState("Production patch wave");
  const [campaignHostIds, setCampaignHostIds] = useState<Set<string>>(new Set());
  const [schedules, setSchedules] = useState<HostSchedule[]>([]);
  const [scheduleForm, setScheduleForm] = useState<ScheduleFormState>(defaultScheduleForm);
  const [jobs, setJobs] = useState<DurableJob[]>([]);
  const [selectedJob, setSelectedJob] = useState<DurableJob | null>(null);
  const [jobFilters, setJobFilters] = useState<JobFilters>({
    status: "",
    jobType: "",
    hostId: "",
    scanId: "",
    remediationId: "",
    campaignId: ""
  });
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [auditEvents, setAuditEvents] = useState<AuditEvent[]>([]);
  const [agentRuns, setAgentRuns] = useState<AgentRun[]>([]);
  const [selectedAgentRun, setSelectedAgentRun] = useState<AgentRun | null>(null);
  const [agentMessages, setAgentMessages] = useState<AgentMessage[]>([]);
  const [agentScanId, setAgentScanId] = useState("");
  const [logs, setLogs] = useState<LogPage>(emptyLogPage);
  const [logFilters, setLogFilters] = useState<LogFilters>({
    hostId: "",
    jobId: "",
    scanId: "",
    remediationId: "",
    agentRunId: "",
    severity: "",
    source: "",
    phaseId: "",
    taskId: "",
    page: 1,
    pageSize: 25
  });
  const [selectedLog, setSelectedLog] = useState<StructuredLogEvent | null>(null);
  const [operationsHealth, setOperationsHealth] = useState<OperationsHealth>(emptyOperationsHealth);
  const [operationsSection, setOperationsSection] = useState<OperationsSection>("health");
  const [connectionResult, setConnectionResult] = useState<ConnectionTestResult | null>(null);
  const [pendingHostKey, setPendingHostKey] = useState<string | null>(null);
  const [activeView, setActiveView] = useState<DashboardView>("fleet");
  const [error, setError] = useState<string>("");
  const [busy, setBusy] = useState<string>("");

  const selectedHost = hosts.find((host) => host.id === selectedHostId) ?? null;
  const selectedSchedule = schedules.find((schedule) => schedule.hostId === selectedHostId) ?? null;
  const selectedCampaign = campaigns.find((campaign) => campaign.id === selectedCampaignId) ?? null;
  const selectedRemediation = remediations.find((remediation) => remediation.id === selectedRemediationId)
    ?? remediations[0]
    ?? null;
  const selectedRemediationHost = selectedRemediation
    ? hosts.find((host) => host.id === selectedRemediation.hostId) ?? null
    : null;
  const selectedRemediationSnapshots = selectedRemediation
    ? snapshots.filter((snapshot) => snapshot.remediationId === selectedRemediation.id)
    : [];
  const selectedRemediationBlockers = selectedRemediation
    ? remediationExecutionBlockers(selectedRemediation, selectedRemediationHost)
    : [];
  const filteredJobs = useMemo(
    () => jobs.filter((job) =>
      (!jobFilters.status || job.status === jobFilters.status)
      && (!jobFilters.jobType || job.jobType === jobFilters.jobType)
      && (!jobFilters.hostId || job.hostId === jobFilters.hostId)
      && (!jobFilters.scanId || job.scanId === jobFilters.scanId)
      && (!jobFilters.remediationId || job.remediationId === jobFilters.remediationId)
      && (!jobFilters.campaignId || job.campaignId === jobFilters.campaignId)
    ),
    [jobs, jobFilters]
  );
  const actionSummary = useMemo(() => {
    const runningJobs = jobs.filter((job) => job.status === "running").length;
    const failedJobs = jobs.filter((job) => job.status === "failed" || job.error || job.lastFailure).length;
    const queuedJobs = jobs.filter((job) =>
      ["queued", "pending", "scheduled", "waiting_for_window"].includes(job.status)
    ).length;
    const unhealthyHealthChecks = [
      operationsHealth.live.ok,
      operationsHealth.ready.checks.database,
      operationsHealth.ready.checks.redis,
      operationsHealth.ops.checks.worker.healthy,
      operationsHealth.ops.checks.celeryBeat.healthy
    ].filter((item) => !item).length;
    const failedOrExternalAgentRuns = agentRuns.filter((run) =>
      run.status === "failed" || run.externallyProcessed
    ).length;
    const recentHighCriticalLogs = logs.items.filter((log) =>
      log.severity === "high" || log.severity === "critical"
    ).length;
    return {
      runningJobs,
      failedJobs,
      queuedJobs,
      unacknowledgedAlerts: alerts.filter((alert) => !alert.acknowledged).length,
      unhealthyHealthChecks,
      failedOrExternalAgentRuns,
      recentHighCriticalLogs
    };
  }, [jobs, alerts, operationsHealth, agentRuns, logs.items]);

  const approvedCampaignCount = useMemo(
    () => selectedCampaign?.hosts.filter((host) => host.state === "approved").length ?? 0,
    [selectedCampaign]
  );
  const activeViewTitle = {
    fleet: "Fleet Setup",
    operations: "Operations",
    campaigns: "Campaigns",
    evidence: "Evidence"
  }[activeView];
  const activeViewStatus = {
    fleet: `${hosts.length} hosts`,
    operations: `${actionSummary.failedJobs} failed, ${actionSummary.unacknowledgedAlerts} alerts`,
    campaigns: `${campaigns.length} campaigns`,
    evidence: `${logs.total} logs`
  }[activeView];

  async function refresh() {
    try {
      const [
        nextOperationsHealth,
        nextCredentials,
        nextHosts,
        nextRemediations,
        nextSnapshots,
        nextCampaigns,
        nextSchedules,
        nextJobs,
        nextAlerts,
        nextAuditEvents,
        nextAgentRuns,
        nextLogs
      ] = await Promise.all([
        api.getOperationsHealth(),
        api.listCredentials(),
        api.listHosts(),
        api.listRemediations(),
        api.listSnapshots(),
        api.listCampaigns(),
        api.listSchedules(),
        api.listJobs(),
        api.listAlerts(),
        api.listAudit(),
        api.listAgentRuns(agentScanId || undefined),
        api.listLogs(logFilters)
      ]);
      setOperationsHealth(nextOperationsHealth);
      setCredentials(nextCredentials);
      setHosts(nextHosts);
      setRemediations(nextRemediations);
      setSnapshots(nextSnapshots);
      setCampaigns(nextCampaigns);
      setSchedules(nextSchedules);
      setJobs(nextJobs);
      setAlerts(nextAlerts);
      setAuditEvents(nextAuditEvents);
      setAgentRuns(nextAgentRuns);
      setLogs(nextLogs);

      const nextHostId = selectedHostId && nextHosts.some((host) => host.id === selectedHostId)
        ? selectedHostId
        : nextHosts[0]?.id ?? "";
      setSelectedHostId(nextHostId);
      if (nextHostId) {
        const nextHost = nextHosts.find((host) => host.id === nextHostId);
        if (nextHost && !editingHostId) setHostForm(hostFormFromHost(nextHost));
        setFindings(await api.listFindings(nextHostId));
      } else {
        setFindings([]);
        setHostForm(blankHostForm);
      }
      setSelectedCampaignId((current) =>
        current && nextCampaigns.some((campaign) => campaign.id === current)
          ? current
          : nextCampaigns[0]?.id ?? ""
      );
      setSelectedRemediationId((current) =>
        current && nextRemediations.some((remediation) => remediation.id === current)
          ? current
          : nextRemediations[0]?.id ?? ""
      );
    } catch (nextError) {
      setError(nextError instanceof Error ? nextError.message : "Unknown dashboard error");
    }
  }

  useEffect(() => {
    void api.me()
      .then(async (currentUser) => {
        setUser(currentUser);
        await refresh();
      })
      .catch(() => undefined)
      .finally(() => setAuthChecked(true));
  }, []);

  useEffect(() => {
    const schedule = schedules.find((item) => item.hostId === selectedHostId);
    setScheduleForm(schedule ? {
      enabled: schedule.enabled,
      timezone: schedule.timezone,
      cronExpression: schedule.cronExpression,
      overlapPolicy: schedule.overlapPolicy
    } : defaultScheduleForm);
  }, [schedules, selectedHostId]);

  useEffect(() => {
    if (!selectedHost || editingHostId) return;
    setHostForm(hostFormFromHost(selectedHost));
  }, [selectedHost, editingHostId]);

  useEffect(() => {
    setExecutionConfirmation("");
  }, [selectedRemediationId]);

  async function act(key: string, action: () => Promise<unknown>) {
    setBusy(key);
    setError("");
    try {
      await action();
      await refresh();
    } catch (nextError) {
      setError(nextError instanceof Error ? nextError.message : "Unknown operation error");
    } finally {
      setBusy("");
    }
  }

  async function login(event: FormEvent) {
    event.preventDefault();
    await act("login", async () => {
      const currentUser = await api.login(username, password);
      setUser(currentUser);
      setPassword("");
    });
  }

  async function logout() {
    await api.logout();
    setUser(null);
    setCredentials([]);
    setHosts([]);
    setFindings([]);
    setRemediations([]);
    setSnapshots([]);
    setCampaigns([]);
    setSchedules([]);
    setJobs([]);
    setAlerts([]);
    setAuditEvents([]);
    setAgentRuns([]);
    setSelectedAgentRun(null);
    setAgentMessages([]);
    setLogs(emptyLogPage);
    setOperationsHealth(emptyOperationsHealth);
  }

  async function chooseHost(hostId: string) {
    setSelectedHostId(hostId);
    setEditingHostId(null);
    setConnectionResult(null);
    setPendingHostKey(null);
    const host = hosts.find((item) => item.id === hostId);
    if (host) setHostForm(hostFormFromHost(host));
    setFindings(await api.listFindings(hostId));
  }

  async function submitHost(event: FormEvent) {
    event.preventDefault();
    let input: HostInput;
    try {
      input = hostInputFromForm(hostForm);
    } catch (nextError) {
      setError(nextError instanceof Error ? nextError.message : "Invalid host form");
      return;
    }
    await act(editingHostId ? `host-save-${editingHostId}` : "host-create", async () => {
      if (editingHostId) {
        await api.updateHost(editingHostId, input);
      } else {
        const host = await api.createHost(input);
        setSelectedHostId(host.id);
        setEditingHostId(null);
      }
    });
  }

  async function deleteHost(host: Host) {
    if (!window.confirm(`Delete host ${host.name}? This removes its schedule.`)) return;
    await act(`host-delete-${host.id}`, async () => {
      await api.deleteHost(host.id);
      if (selectedHostId === host.id) setSelectedHostId("");
      setEditingHostId(null);
    });
  }

  async function uploadCredential(event: FormEvent) {
    event.preventDefault();
    if (credentialType === "ssh_private_key" && !credentialFile) {
      setError("Choose a private key file before uploading a credential.");
      return;
    }
    let metadata: Record<string, unknown>;
    try {
      metadata = parseJsonObject(credentialMetadata);
    } catch (nextError) {
      setError(nextError instanceof Error ? nextError.message : "Invalid credential metadata");
      return;
    }
    await act("credential-upload", async () => {
      if (credentialType === "ssh_private_key") {
        await api.uploadCredential(credentialName.trim(), credentialFile as File);
      } else {
        await api.createPlatformCredential(
          credentialName.trim(),
          credentialType,
          credentialSecret,
          metadata,
        );
      }
      setCredentialName("");
      setCredentialFile(null);
      setCredentialSecret("");
      setCredentialMetadata("{}");
    });
  }

  async function deleteCredential(credential: SshCredential) {
    if (!window.confirm(`Delete credential ${credential.name}?`)) return;
    await act(`credential-delete-${credential.id}`, () => api.deleteCredential(credential.id));
  }

  async function testConnection(confirmFingerprint?: string) {
    if (!selectedHost) return;
    await act(`connection-${selectedHost.id}`, async () => {
      const result = await api.testConnection(selectedHost.id, confirmFingerprint);
      setConnectionResult(result);
      const needsHostKey = result.checks.host_key_confirmation === "required" && result.hostKeyFingerprint;
      setPendingHostKey(needsHostKey ? result.hostKeyFingerprint ?? null : null);
    });
  }

  async function runScan(hostId: string) {
    await act(`scan-${hostId}`, async () => {
      await api.runScan(hostId);
      setFindings(await api.listFindings(hostId));
    });
  }

  async function approveRemediation(remediation: Remediation) {
    const host = hosts.find((item) => item.id === remediation.hostId);
    if (!host) {
      setError("The remediation host is no longer available.");
      return;
    }
    const confirmation = window.prompt(`Type ${host.name} to approve this exact patch plan.`);
    if (confirmation === null) return;
    await act(`approve-${remediation.id}`, () =>
      api.approveRemediation(
        remediation.id,
        remediation.planVersion,
        remediation.planHash,
        confirmation
      )
    );
  }

  async function approveRemediationReboot(remediation: Remediation) {
    const host = hosts.find((item) => item.id === remediation.hostId);
    if (!host) {
      setError("The remediation host is no longer available.");
      return;
    }
    const confirmation = window.prompt(`Type ${host.name} to approve reboot for this plan.`);
    if (confirmation === null) return;
    await act(`reboot-${remediation.id}`, () =>
      api.approveRemediationReboot(
        remediation.id,
        remediation.planVersion,
        remediation.planHash,
        confirmation
      )
    );
  }

  async function queueRemediationExecution(remediation: Remediation) {
    const host = hosts.find((item) => item.id === remediation.hostId);
    const blockers = remediationExecutionBlockers(remediation, host);
    if (!host) {
      setError("The remediation host is no longer available.");
      return;
    }
    if (blockers.length > 0) {
      setError(blockers[0]);
      return;
    }
    if (executionConfirmation !== host.name) {
      setError(`Type ${host.name} before queueing execution.`);
      return;
    }
    await act(`execute-${remediation.id}`, async () => {
      const job = await api.executeRemediation(remediation.id);
      setSelectedJob(job);
      setExecutionConfirmation("");
    });
  }

  async function createCampaign(event: FormEvent) {
    event.preventDefault();
    await act("campaign-create", async () => {
      const campaign = await api.createCampaign(campaignName.trim(), Array.from(campaignHostIds));
      setSelectedCampaignId(campaign.id);
    });
  }

  async function campaignHostAction(
    campaign: PatchCampaign,
    hostPlan: CampaignHostPlan,
    kind: "approve" | "reboot" | "reject"
  ) {
    if (kind === "reject") {
      if (!window.confirm(`Reject patch plan for ${hostPlan.hostname}?`)) return;
      await act(`campaign-reject-${hostPlan.id}`, () =>
        api.rejectCampaignHost(campaign.id, hostPlan.hostId)
      );
      return;
    }
    if (hostPlan.planVersion === null || !hostPlan.planHash) {
      setError("This campaign host has no plan version and hash to approve.");
      return;
    }
    const verb = kind === "approve" ? "approve this patch plan" : "approve reboot";
    const confirmation = window.prompt(`Type ${hostPlan.hostname} to ${verb}.`);
    if (confirmation === null) return;
    await act(`campaign-${kind}-${hostPlan.id}`, () =>
      kind === "approve"
        ? api.approveCampaignHost(
          campaign.id,
          hostPlan.hostId,
          hostPlan.planVersion as number,
          hostPlan.planHash as string,
          confirmation
        )
        : api.approveCampaignHostReboot(
          campaign.id,
          hostPlan.hostId,
          hostPlan.planVersion as number,
          hostPlan.planHash as string,
          confirmation
        )
    );
  }

  async function loadJob(jobId: string) {
    await act(`job-${jobId}`, async () => {
      setSelectedJob(await api.getJob(jobId));
    });
  }

  async function loadLogs(page = logFilters.page) {
    await act("logs-load", async () => {
      setLogs(await api.listLogs({ ...logFilters, page }));
      setLogFilters((current) => ({ ...current, page }));
    });
  }

  async function applyLogFilters(nextFilters: Partial<LogFilters>) {
    const next = { ...logFilters, ...nextFilters, page: 1 };
    setLogFilters(next);
    setOperationsSection("logs");
    await act("logs-load", async () => {
      setLogs(await api.listLogs(next));
    });
  }

  async function applyAgentScan(scanId: string) {
    setAgentScanId(scanId);
    setOperationsSection("agents");
    await act("agent-load", async () => {
      const nextRuns = await api.listAgentRuns(scanId);
      setAgentRuns(nextRuns);
      setAgentMessages(await api.listAgentMessages(scanId));
      setSelectedAgentRun(nextRuns[0] ?? null);
    });
  }

  async function openLog(id: string) {
    await act(`log-${id}`, async () => {
      setSelectedLog(await api.getLog(id));
    });
  }

  async function loadAgentActivity(scanId = agentScanId) {
    await act("agent-load", async () => {
      const nextRuns = await api.listAgentRuns(scanId || undefined);
      setAgentRuns(nextRuns);
      setAgentMessages(scanId ? await api.listAgentMessages(scanId) : []);
      setSelectedAgentRun(nextRuns[0] ?? null);
    });
  }

  if (!authChecked) {
    return <main className="app-shell"><p>Loading operator session...</p></main>;
  }

  if (!user) {
    return (
      <main className="app-shell">
        <header className="topbar">
          <div>
            <p className="eyebrow">Internal Ops Console</p>
            <h1>AI Linux Sysadmin</h1>
          </div>
        </header>
        {error ? <section className="error-banner">{error}</section> : null}
        <form className="panel form-grid login-panel" onSubmit={(event) => void login(event)}>
          <label>
            Username
            <input value={username} onChange={(event) => setUsername(event.target.value)} />
          </label>
          <label>
            Password
            <input
              type="password"
              value={password}
              onChange={(event) => setPassword(event.target.value)}
            />
          </label>
          <button className="primary-button" disabled={busy === "login"} type="submit">
            {busy === "login" ? "Signing in..." : "Sign in"}
          </button>
        </form>
      </main>
    );
  }

  return (
    <main className="app-shell">
      <header className="topbar">
        <div>
          <p className="eyebrow">Private Alpha Operator Console</p>
          <h1>AI Linux Sysadmin</h1>
        </div>
        <div className="action-row">
          <button className="secondary-button" onClick={() => void refresh()}>
            Refresh
          </button>
          <button className="secondary-button" onClick={() => void logout()}>
            Sign out
          </button>
        </div>
      </header>

      {error ? <section className="error-banner">{error}</section> : null}

      <section className="summary-grid" aria-label="Dashboard summary">
        <Metric label="Hosts" value={hosts.length} detail={`${hosts.filter((host) => host.connectionStatus === "ready").length} ready`} />
        <Metric label="Credentials" value={credentials.length} detail="vault records" />
        <Metric label="Jobs" value={jobs.length} detail={`${jobs.filter((job) => job.status === "running").length} running`} />
        <Metric label="Alerts" value={alerts.filter((alert) => !alert.acknowledged).length} detail="unacknowledged" />
      </section>

      <section className="operator-layout">
        <nav className="workspace-nav" aria-label="Dashboard sections">
          <button
            className={activeView === "fleet" ? "nav-button active" : "nav-button"}
            onClick={() => setActiveView("fleet")}
          >
            <strong>Fleet Setup</strong>
            <small>{hosts.length} hosts, {credentials.length} credentials</small>
          </button>
          <button
            className={activeView === "operations" ? "nav-button active" : "nav-button"}
            onClick={() => setActiveView("operations")}
          >
            <strong>Operations</strong>
            <small>{jobs.length} jobs, {alerts.filter((alert) => !alert.acknowledged).length} alerts</small>
          </button>
          <button
            className={activeView === "campaigns" ? "nav-button active" : "nav-button"}
            onClick={() => setActiveView("campaigns")}
          >
            <strong>Campaigns</strong>
            <small>{campaigns.length} waves</small>
          </button>
          <button
            className={activeView === "evidence" ? "nav-button active" : "nav-button"}
            onClick={() => setActiveView("evidence")}
          >
            <strong>Evidence</strong>
            <small>{logs.total} logs, {alerts.length} alerts</small>
          </button>
        </nav>

        <section className="workspace-content">
          <header className="workspace-heading">
            <div>
              <p className="eyebrow">Workspace</p>
              <h2>{activeViewTitle}</h2>
            </div>
            <span className="status-chip">{activeViewStatus}</span>
          </header>

      <section className={`dashboard-grid dashboard-${activeView}`}>
        {activeView === "fleet" ? (
          <>
        <SecondaryPanel title="Credentials">
          <form className="inline-form" onSubmit={(event) => void uploadCredential(event)}>
            <input
              aria-label="Credential name"
              placeholder="credential name"
              value={credentialName}
              onChange={(event) => setCredentialName(event.target.value)}
            />
            <select
              aria-label="Credential type"
              value={credentialType}
              onChange={(event) => setCredentialType(event.target.value as SshCredential["credentialType"])}
            >
              <option value="ssh_private_key">ssh private key</option>
              <option value="proxmox_token">proxmox token</option>
              <option value="aws_access_key">aws access key</option>
              <option value="aws_role">aws role</option>
              <option value="vmware_secret">vmware secret</option>
              <option value="libvirt_ssh">libvirt ssh</option>
            </select>
            {credentialType === "ssh_private_key" ? (
              <input
                aria-label="Private key"
                type="file"
                onChange={(event) => setCredentialFile(event.target.files?.[0] ?? null)}
              />
            ) : (
              <>
                <input
                  aria-label="Credential secret"
                  placeholder={credentialType === "aws_role" ? "optional secret" : "credential secret"}
                  type="password"
                  value={credentialSecret}
                  onChange={(event) => setCredentialSecret(event.target.value)}
                />
                <input
                  aria-label="Credential metadata"
                  placeholder='{"endpoint":"https://example"}'
                  value={credentialMetadata}
                  onChange={(event) => setCredentialMetadata(event.target.value)}
                />
              </>
            )}
            <button className="primary-button" disabled={busy === "credential-upload"} type="submit">
              Add
            </button>
          </form>
          <div className="list-stack">
            {credentials.length === 0 ? <p>No credentials stored.</p> : null}
            {credentials.map((credential) => (
              <div key={credential.id} className="record-row">
                <div>
                  <strong>{credential.name}</strong>
                  <small>{(credential.credentialType ?? "ssh_private_key").replaceAll("_", " ")}</small>
                  <small>{credential.fingerprint}</small>
                  <small>Last used: {formatDate(credential.lastUsedAt)}</small>
                </div>
                <button
                  className="danger-button"
                  disabled={busy === `credential-delete-${credential.id}`}
                  onClick={() => void deleteCredential(credential)}
                >
                  Delete
                </button>
              </div>
            ))}
          </div>
        </SecondaryPanel>

        <Panel title="Hosts">
          <form className="form-grid" onSubmit={(event) => void submitHost(event)}>
            <label>
              Name
              <input value={hostForm.name} onChange={(event) => setHostForm({ ...hostForm, name: event.target.value })} />
            </label>
            <label>
              Address
              <input value={hostForm.address} onChange={(event) => setHostForm({ ...hostForm, address: event.target.value })} />
            </label>
            <label>
              Port
              <input type="number" min="1" max="65535" value={hostForm.port} onChange={(event) => setHostForm({ ...hostForm, port: event.target.value })} />
            </label>
            <label>
              Username
              <input value={hostForm.username} onChange={(event) => setHostForm({ ...hostForm, username: event.target.value })} />
            </label>
            <label>
              Environment
              <input value={hostForm.environment} onChange={(event) => setHostForm({ ...hostForm, environment: event.target.value })} />
            </label>
            <label>
              Tags
              <input value={hostForm.tags} onChange={(event) => setHostForm({ ...hostForm, tags: event.target.value })} />
            </label>
            <label>
              Credential
              <select value={hostForm.credentialId} onChange={(event) => setHostForm({ ...hostForm, credentialId: event.target.value })}>
                <option value="">None</option>
                {credentials.filter((credential) => (credential.credentialType ?? "ssh_private_key") === "ssh_private_key").map((credential) => (
                  <option key={credential.id} value={credential.id}>{credential.name}</option>
                ))}
              </select>
            </label>
            <label>
              Criticality
              <select value={hostForm.criticality} onChange={(event) => setHostForm({ ...hostForm, criticality: event.target.value as HostInput["criticality"] })}>
                <option value="low">low</option>
                <option value="normal">normal</option>
                <option value="high">high</option>
              </select>
            </label>
            <label>
              Availability
              <select value={hostForm.availabilityClass} onChange={(event) => setHostForm({ ...hostForm, availabilityClass: event.target.value as HostInput["availabilityClass"] })}>
                <option value="standard">standard</option>
                <option value="high_availability">high availability</option>
              </select>
            </label>
            <label>
              Update mode
              <select value={hostForm.updateMode} onChange={(event) => setHostForm({ ...hostForm, updateMode: event.target.value as HostInput["patchPolicy"]["updateMode"] })}>
                <option value="orchestrator_decides">orchestrator decides</option>
                <option value="all">all</option>
                <option value="security">security</option>
              </select>
            </label>
            <label>
              Timing
              <select value={hostForm.executionTiming} onChange={(event) => setHostForm({ ...hostForm, executionTiming: event.target.value as HostInput["patchPolicy"]["executionTiming"] })}>
                <option value="immediate">immediate</option>
                <option value="maintenance_window">maintenance window</option>
              </select>
            </label>
            <label>
              Reboot policy
              <select value={hostForm.rebootPolicy} onChange={(event) => setHostForm({ ...hostForm, rebootPolicy: event.target.value as HostInput["patchPolicy"]["rebootPolicy"] })}>
                <option value="if_required">if required</option>
                <option value="never">never</option>
              </select>
            </label>
            <label>
              Max batch
              <input type="number" min="1" value={hostForm.maxBatchSize} onChange={(event) => setHostForm({ ...hostForm, maxBatchSize: event.target.value })} />
            </label>
            <label>
              Canary count
              <input type="number" min="1" value={hostForm.canaryCount} onChange={(event) => setHostForm({ ...hostForm, canaryCount: event.target.value })} />
            </label>
            <label className="wide-field">
              SSH host key fingerprint
              <input value={hostForm.sshHostKeyFingerprint} onChange={(event) => setHostForm({ ...hostForm, sshHostKeyFingerprint: event.target.value })} />
            </label>
            <label>
              Snapshot platform
              <select value={hostForm.snapshotPlatform} onChange={(event) => setHostForm({ ...hostForm, snapshotPlatform: event.target.value as HostInput["snapshotPlatform"], snapshotCredentialId: "" })}>
                <option value="none">none</option>
                <option value="proxmox">proxmox</option>
                <option value="aws">aws</option>
                <option value="vmware">vmware</option>
                <option value="libvirt">libvirt</option>
              </select>
            </label>
            <label>
              Snapshot credential
              <select
                value={hostForm.snapshotCredentialId}
                disabled={hostForm.snapshotPlatform === "none"}
                onChange={(event) => setHostForm({ ...hostForm, snapshotCredentialId: event.target.value })}
              >
                <option value="">None</option>
                {credentials.filter((credential) => snapshotCredentialAllowed(hostForm.snapshotPlatform, credential)).map((credential) => (
                  <option key={credential.id} value={credential.id}>{credential.name}</option>
                ))}
              </select>
            </label>
            <label>
              Snapshot target
              <input value={hostForm.snapshotTargetId} onChange={(event) => setHostForm({ ...hostForm, snapshotTargetId: event.target.value })} />
            </label>
            <label>
              Critical service
              <input value={hostForm.criticalServiceName} onChange={(event) => setHostForm({ ...hostForm, criticalServiceName: event.target.value })} />
            </label>
            <label>
              Health URL
              <input value={hostForm.healthCheckUrl} onChange={(event) => setHostForm({ ...hostForm, healthCheckUrl: event.target.value })} />
            </label>
            <label>
              Retention days
              <input type="number" min="1" max="365" value={hostForm.snapshotRetentionDays} onChange={(event) => setHostForm({ ...hostForm, snapshotRetentionDays: event.target.value })} />
            </label>
            <label className="wide-field">
              Snapshot metadata
              <textarea value={hostForm.snapshotProviderMetadata} onChange={(event) => setHostForm({ ...hostForm, snapshotProviderMetadata: event.target.value })} />
            </label>
            <div className="action-row">
              <button className="primary-button" type="submit">
                {editingHostId ? "Save Host" : "Create Host"}
              </button>
              <button
                className="secondary-button"
                type="button"
                onClick={() => {
                  setEditingHostId(null);
                  setHostForm(blankHostForm);
                }}
              >
                New
              </button>
            </div>
          </form>
          <div className="list-stack">
            {hosts.map((host) => (
              <button
                key={host.id}
                className={`record-row host-selector ${host.id === selectedHostId ? "selected" : ""}`}
                onClick={() => void chooseHost(host.id)}
              >
                <span>
                  <strong>{host.name}</strong>
                  <small>{host.address}:{host.port} as {host.username}</small>
                  <small>{host.environment} / {host.availabilityClass.replaceAll("_", " ")}</small>
                </span>
                <span className={statusClass(host.connectionStatus)}>{host.connectionStatus}</span>
              </button>
            ))}
          </div>
          {selectedHost ? (
            <div className="action-row">
              <button
                className="secondary-button"
                onClick={() => {
                  setEditingHostId(selectedHost.id);
                  setHostForm(hostFormFromHost(selectedHost));
                }}
              >
                Edit Selected
              </button>
              <button className="danger-button" onClick={() => void deleteHost(selectedHost)}>
                Delete Selected
              </button>
            </div>
          ) : null}
        </Panel>

        <Panel title="Connection Test">
          {!selectedHost ? <p>Select a host first.</p> : null}
          {selectedHost ? (
            <>
              <div className="detail-grid">
                <div><dt>Host</dt><dd>{selectedHost.name}</dd></div>
                <div><dt>Status</dt><dd>{selectedHost.connectionStatus}</dd></div>
                <div><dt>Credential</dt><dd>{credentialLabel(credentials, selectedHost.credentialId)}</dd></div>
                <div><dt>Saved host key</dt><dd>{selectedHost.sshHostKeyFingerprint ?? "None"}</dd></div>
                <div><dt>Snapshot platform</dt><dd>{selectedHost.snapshotPlatform ?? "none"}</dd></div>
                <div><dt>Snapshot credential</dt><dd>{credentialLabel(credentials, selectedHost.snapshotCredentialId)}</dd></div>
                <div><dt>Snapshot target</dt><dd>{selectedHost.snapshotTargetId ?? "None"}</dd></div>
                <div><dt>Critical service</dt><dd>{selectedHost.criticalServiceName ?? "None"}</dd></div>
                <div><dt>Health URL</dt><dd>{selectedHost.healthCheckUrl ?? "None"}</dd></div>
                <div><dt>Retention</dt><dd>{selectedHost.snapshotRetentionDays ?? 7} days</dd></div>
              </div>
              <div className="action-row">
                <button className="primary-button" onClick={() => void testConnection()}>
                  Test Connection
                </button>
                {pendingHostKey ? (
                  <button className="danger-button" onClick={() => void testConnection(pendingHostKey)}>
                    Confirm Host Key
                  </button>
                ) : null}
              </div>
            </>
          ) : null}
          {connectionResult ? (
            <div className="result-block">
              <div className="detail-grid">
                <div><dt>SSH reachable</dt><dd>{String(connectionResult.sshReachable)}</dd></div>
                <div><dt>Sudo available</dt><dd>{String(connectionResult.sudoAvailable)}</dd></div>
                <div><dt>OS supported</dt><dd>{String(connectionResult.osSupported)}</dd></div>
                <div><dt>Ansible compatible</dt><dd>{String(connectionResult.ansibleCompatible)}</dd></div>
              </div>
              {connectionResult.hostKeyFingerprint ? (
                <p className="warning-text">Fingerprint: {connectionResult.hostKeyFingerprint}</p>
              ) : null}
              <pre>{JSON.stringify(connectionResult.checks, null, 2)}</pre>
            </div>
          ) : null}
        </Panel>

        <SecondaryPanel title="Scan Schedule">
          {!selectedHost ? <p>Select a host to edit its schedule.</p> : null}
          {selectedHost ? (
            <form className="form-grid" onSubmit={(event) => {
              event.preventDefault();
              void act("schedule-save", () => api.updateSchedule(selectedHost.id, scheduleForm));
            }}>
              <label className="checkbox-field">
                <input
                  type="checkbox"
                  checked={scheduleForm.enabled}
                  onChange={(event) => setScheduleForm({ ...scheduleForm, enabled: event.target.checked })}
                />
                Enabled
              </label>
              <label>
                Timezone
                <input value={scheduleForm.timezone} onChange={(event) => setScheduleForm({ ...scheduleForm, timezone: event.target.value })} />
              </label>
              <label>
                Cron
                <input value={scheduleForm.cronExpression} onChange={(event) => setScheduleForm({ ...scheduleForm, cronExpression: event.target.value })} />
              </label>
              <label>
                Overlap policy
                <select value={scheduleForm.overlapPolicy} onChange={(event) => setScheduleForm({ ...scheduleForm, overlapPolicy: event.target.value as "skip_if_running" })}>
                  <option value="skip_if_running">skip if running</option>
                </select>
              </label>
              <button className="primary-button" type="submit">Save Schedule</button>
            </form>
          ) : null}
          {selectedSchedule ? (
            <div className="detail-grid">
              <div><dt>Previous run</dt><dd>{formatDate(selectedSchedule.previousRunAt)}</dd></div>
              <div><dt>Next run</dt><dd>{formatDate(selectedSchedule.nextRunAt)}</dd></div>
            </div>
          ) : null}
          <div className="list-stack">
            {schedules.map((schedule) => (
              <div key={schedule.id} className="record-row">
                <div>
                  <strong>{hostLabel(hosts, schedule.hostId)}</strong>
                  <small>{schedule.enabled ? "enabled" : "disabled"} / {schedule.cronExpression} / {schedule.timezone}</small>
                  <small>Previous {formatDate(schedule.previousRunAt)} / Next {formatDate(schedule.nextRunAt)}</small>
                </div>
              </div>
            ))}
          </div>
        </SecondaryPanel>
          </>
        ) : null}

        {activeView === "operations" ? (
          <OperationsView
            health={operationsHealth}
            section={operationsSection}
            setSection={setOperationsSection}
            summary={actionSummary}
            jobs={filteredJobs}
            allJobs={jobs}
            jobFilters={jobFilters}
            setJobFilters={setJobFilters}
            selectedJob={selectedJob}
            loadJob={loadJob}
            logs={logs}
            logFilters={logFilters}
            setLogFilters={setLogFilters}
            loadLogs={loadLogs}
            applyLogFilters={applyLogFilters}
            selectedLog={selectedLog}
            openLog={openLog}
            alerts={alerts}
            acknowledgeAlert={(alertId) => act(`alert-${alertId}`, () => api.acknowledgeAlert(alertId))}
            auditEvents={auditEvents}
            agentRuns={agentRuns}
            agentMessages={agentMessages}
            agentScanId={agentScanId}
            setAgentScanId={setAgentScanId}
            selectedAgentRun={selectedAgentRun}
            setSelectedAgentRun={setSelectedAgentRun}
            loadAgentActivity={loadAgentActivity}
            applyAgentScan={applyAgentScan}
            findings={findings}
            selectedHost={selectedHost}
            runScan={runScan}
            busy={busy}
            remediations={remediations}
            snapshots={snapshots}
            hosts={hosts}
            selectedRemediation={selectedRemediation}
            selectedRemediationHost={selectedRemediationHost}
            selectedRemediationSnapshots={selectedRemediationSnapshots}
            selectedRemediationBlockers={selectedRemediationBlockers}
            setSelectedRemediationId={setSelectedRemediationId}
            executionConfirmation={executionConfirmation}
            setExecutionConfirmation={setExecutionConfirmation}
            approveRemediation={approveRemediation}
            approveRemediationReboot={approveRemediationReboot}
            rejectRemediation={(remediationId) => act(`reject-${remediationId}`, () => api.rejectRemediation(remediationId))}
            queueRemediationExecution={queueRemediationExecution}
          />
        ) : null}

        {activeView === "campaigns" ? (
          <>
        <Panel title="Campaigns">
          <form className="campaign-form" onSubmit={(event) => void createCampaign(event)}>
            <input
              aria-label="Campaign name"
              value={campaignName}
              onChange={(event) => setCampaignName(event.target.value)}
            />
            <div className="host-pick-list">
              {hosts.map((host) => (
                <label key={host.id} className="checkbox-field">
                  <input
                    type="checkbox"
                    checked={campaignHostIds.has(host.id)}
                    onChange={(event) => {
                      const next = new Set(campaignHostIds);
                      if (event.target.checked) next.add(host.id);
                      else next.delete(host.id);
                      setCampaignHostIds(next);
                    }}
                  />
                  {host.name}
                </label>
              ))}
            </div>
            <button className="primary-button" disabled={campaignHostIds.size === 0} type="submit">
              Create Draft
            </button>
          </form>
          <div className="split-grid">
            <div className="list-stack">
              {campaigns.map((campaign) => (
                <button
                  key={campaign.id}
                  className={`record-row host-selector ${campaign.id === selectedCampaignId ? "selected" : ""}`}
                  onClick={() => setSelectedCampaignId(campaign.id)}
                >
                  <span>
                    <strong>{campaign.name}</strong>
                    <small>{campaign.status} / batch {campaign.batchSize} / {campaign.totalBatches} wave(s)</small>
                    <small>{campaign.hosts.length} host(s)</small>
                  </span>
                </button>
              ))}
            </div>
            {selectedCampaign ? (
              <div className="record-block">
                <div className="chip-row">
                  <span className={statusClass(selectedCampaign.status)}>{selectedCampaign.status}</span>
                  <span className="status-chip">{approvedCampaignCount} approved</span>
                </div>
                <h3>{selectedCampaign.name}</h3>
                {selectedCampaign.failureSummary ? <p className="warning-text">{selectedCampaign.failureSummary}</p> : null}
                <div className="action-row">
                  <button
                    className="secondary-button"
                    onClick={() => void act("campaign-proposals", () => api.createCampaignProposals(selectedCampaign.id))}
                  >
                    Create Proposals
                  </button>
                  <button
                    className="primary-button"
                    disabled={!canExecuteCampaign(selectedCampaign)}
                    onClick={() => void act("campaign-execute", () => api.executeCampaign(selectedCampaign.id))}
                  >
                    Execute Approved
                  </button>
                  <button
                    className="danger-button"
                    onClick={() => void act("campaign-cancel", () => api.cancelCampaign(selectedCampaign.id))}
                  >
                    Cancel Work
                  </button>
                </div>
                <div className="list-stack">
                  {selectedCampaign.hosts.map((hostPlan) => {
                    const linkedRemediation = remediations.find((item) => item.id === hostPlan.remediationId);
                    return (
                      <div key={hostPlan.id} className="record-row campaign-host-row">
                        <div>
                          <div className="chip-row">
                            <strong>{hostPlan.hostname}</strong>
                            <span className={statusClass(hostPlan.state)}>{hostPlan.state}</span>
                            <span className={statusClass(hostPlan.approvalState)}>approval {hostPlan.approvalState}</span>
                            <span className={statusClass(hostPlan.rebootApprovalState)}>reboot {hostPlan.rebootApprovalState}</span>
                          </div>
                          <small>Plan v{textValue(hostPlan.planVersion)} / {textValue(hostPlan.planHash)}</small>
                          <small>Host {hostPlan.hostId} / scan {textValue(hostPlan.scanId)} / remediation {textValue(hostPlan.remediationId)}</small>
                          {linkedRemediation ? <small>{linkedRemediation.title}</small> : null}
                          {hostPlan.failureSummary ? <small className="warning-text">{hostPlan.failureSummary}</small> : null}
                          {hostPlan.state === "plan_changed" ? (
                            <small className="warning-text">Plan changed. Regenerate proposals before approval.</small>
                          ) : null}
                        </div>
                        <div className="action-row compact-actions">
                          <button
                            className="primary-button"
                            disabled={!canApproveCampaignHost(hostPlan)}
                            onClick={() => void campaignHostAction(selectedCampaign, hostPlan, "approve")}
                          >
                            Approve
                          </button>
                          <button
                            className="secondary-button"
                            disabled={hostPlan.state !== "awaiting_reboot_approval" || hostPlan.planVersion === null || !hostPlan.planHash}
                            onClick={() => void campaignHostAction(selectedCampaign, hostPlan, "reboot")}
                          >
                            Reboot
                          </button>
                          <button
                            className="secondary-button"
                            disabled={!["awaiting_approval", "awaiting_reboot_approval", "approved", "plan_changed"].includes(hostPlan.state)}
                            onClick={() => void campaignHostAction(selectedCampaign, hostPlan, "reject")}
                          >
                            Reject
                          </button>
                        </div>
                      </div>
                    );
                  })}
                </div>
              </div>
            ) : null}
          </div>
        </Panel>
          </>
        ) : null}

        {activeView === "evidence" ? (
          <>
        <Panel title="Logs">
          <form className="form-grid" onSubmit={(event) => {
            event.preventDefault();
            void loadLogs(1);
          }}>
            <input aria-label="Log host ID" placeholder="hostId" value={logFilters.hostId} onChange={(event) => setLogFilters({ ...logFilters, hostId: event.target.value })} />
            <input aria-label="Log job ID" placeholder="jobId" value={logFilters.jobId} onChange={(event) => setLogFilters({ ...logFilters, jobId: event.target.value })} />
            <input aria-label="Log scan ID" placeholder="scanId" value={logFilters.scanId} onChange={(event) => setLogFilters({ ...logFilters, scanId: event.target.value })} />
            <input aria-label="Log remediation ID" placeholder="remediationId" value={logFilters.remediationId} onChange={(event) => setLogFilters({ ...logFilters, remediationId: event.target.value })} />
            <input aria-label="Log agent run ID" placeholder="agentRunId" value={logFilters.agentRunId} onChange={(event) => setLogFilters({ ...logFilters, agentRunId: event.target.value })} />
            <select aria-label="Log severity" value={logFilters.severity} onChange={(event) => setLogFilters({ ...logFilters, severity: event.target.value })}>
              <option value="">any severity</option>
              <option value="info">info</option>
              <option value="low">low</option>
              <option value="medium">medium</option>
              <option value="high">high</option>
              <option value="critical">critical</option>
            </select>
            <input aria-label="Log source" placeholder="source" value={logFilters.source} onChange={(event) => setLogFilters({ ...logFilters, source: event.target.value })} />
            <select aria-label="Log page size" value={logFilters.pageSize} onChange={(event) => setLogFilters({ ...logFilters, pageSize: Number(event.target.value) })}>
              <option value={25}>25</option>
              <option value={50}>50</option>
              <option value={100}>100</option>
            </select>
            <button className="primary-button" type="submit">Filter Logs</button>
          </form>
          <div className="pager-row">
            <button className="secondary-button" disabled={logs.page <= 1} onClick={() => void loadLogs(logs.page - 1)}>Previous</button>
            <span>Page {logs.page} / {Math.max(1, Math.ceil(logs.total / logs.pageSize))}</span>
            <button className="secondary-button" disabled={logs.page * logs.pageSize >= logs.total} onClick={() => void loadLogs(logs.page + 1)}>Next</button>
          </div>
          <div className="list-stack">
            {logs.items.map((log) => (
              <button key={log.id} className="record-row host-selector" onClick={() => void openLog(log.id)}>
                <span>
                  <strong>{log.eventType}</strong>
                  <small>{log.timestamp} / {log.severity} / {log.source} / {log.status}</small>
                  <small>host {textValue(log.hostId)} / job {textValue(log.jobId)} / scan {textValue(log.scanId)}</small>
                </span>
              </button>
            ))}
          </div>
          {selectedLog ? <pre>{JSON.stringify(selectedLog, null, 2)}</pre> : null}
        </Panel>

        <SecondaryPanel title="Alerts And Audit">
          <div className="split-grid">
            <div className="list-stack">
              <h3>Alerts</h3>
              {alerts.map((alert) => (
                <div key={alert.id} className="record-row">
                  <div>
                    <div className="chip-row">
                      <span className={`severity severity-${alert.severity}`}>{alert.severity}</span>
                      <span className={statusClass(alert.acknowledged ? "acknowledged" : "open")}>
                        {alert.acknowledged ? "acknowledged" : "open"}
                      </span>
                    </div>
                    <strong>{alert.title}</strong>
                    <small>{alert.message}</small>
                    <small>{formatDate(alert.createdAt)}</small>
                  </div>
                  <button
                    className="secondary-button"
                    disabled={alert.acknowledged}
                    onClick={() => void act(`alert-${alert.id}`, () => api.acknowledgeAlert(alert.id))}
                  >
                    Acknowledge
                  </button>
                </div>
              ))}
            </div>
            <div className="list-stack">
              <h3>Audit</h3>
              {auditEvents.map((event) => (
                <div key={event.id} className="record-block">
                  <strong>{event.action}</strong>
                  <small>{event.actor} / {event.targetType} / {textValue(event.targetId)}</small>
                  <small>{formatDate(event.createdAt)}</small>
                  <pre>{JSON.stringify(event.details, null, 2)}</pre>
                </div>
              ))}
            </div>
          </div>
        </SecondaryPanel>

        <SecondaryPanel title="Agent Activity">
          <form className="inline-form" onSubmit={(event) => {
            event.preventDefault();
            void loadAgentActivity();
          }}>
            <input
              aria-label="Agent scan ID"
              placeholder="scanId"
              value={agentScanId}
              onChange={(event) => setAgentScanId(event.target.value)}
            />
            <button className="primary-button" type="submit">Load</button>
          </form>
          <div className="list-stack">
            {agentRuns.map((run) => (
              <button
                key={run.id}
                className="record-row host-selector"
                onClick={() => {
                  setAgentScanId(run.scanId);
                  void loadAgentActivity(run.scanId);
                }}
              >
                <span>
                  <strong>{run.agent.name.replaceAll("_", " ")}</strong>
                  <small>{run.agent.provider}/{run.agent.model} / {run.agent.modelTier} / {run.status}</small>
                  <small>Latency {run.latencyMs}ms / tokens {run.promptTokens + run.completionTokens} / fallback {run.fallbackReason ?? "none"}</small>
                  <small>{run.externallyProcessed ? "externally processed" : "local processing"} / scan {run.scanId}</small>
                </span>
              </button>
            ))}
          </div>
          {agentMessages.length ? (
            <div className="list-stack">
              <h3>Messages</h3>
              {agentMessages.map((message) => (
                <div key={message.id} className="record-block">
                  <strong>{message.fromAgent.replaceAll("_", " ")} to {message.toAgent.replaceAll("_", " ")}</strong>
                  <small>Round {message.round} / claims {message.claimIds.join(", ") || "none"}</small>
                  <p>{message.response}</p>
                  <pre>{message.reasoning}</pre>
                </div>
              ))}
            </div>
          ) : null}
        </SecondaryPanel>
          </>
        ) : null}
      </section>
        </section>
      </section>
    </main>
  );
}

function OperationsView(props: {
  health: OperationsHealth;
  section: OperationsSection;
  setSection: (section: OperationsSection) => void;
  summary: {
    runningJobs: number;
    failedJobs: number;
    queuedJobs: number;
    unacknowledgedAlerts: number;
    unhealthyHealthChecks: number;
    failedOrExternalAgentRuns: number;
    recentHighCriticalLogs: number;
  };
  jobs: DurableJob[];
  allJobs: DurableJob[];
  jobFilters: JobFilters;
  setJobFilters: (filters: JobFilters) => void;
  selectedJob: DurableJob | null;
  loadJob: (jobId: string) => Promise<void>;
  logs: LogPage;
  logFilters: LogFilters;
  setLogFilters: (filters: LogFilters) => void;
  loadLogs: (page?: number) => Promise<void>;
  applyLogFilters: (filters: Partial<LogFilters>) => Promise<void>;
  selectedLog: StructuredLogEvent | null;
  openLog: (logId: string) => Promise<void>;
  alerts: Alert[];
  acknowledgeAlert: (alertId: string) => Promise<unknown>;
  auditEvents: AuditEvent[];
  agentRuns: AgentRun[];
  agentMessages: AgentMessage[];
  agentScanId: string;
  setAgentScanId: (scanId: string) => void;
  selectedAgentRun: AgentRun | null;
  setSelectedAgentRun: (run: AgentRun | null) => void;
  loadAgentActivity: (scanId?: string) => Promise<void>;
  applyAgentScan: (scanId: string) => Promise<void>;
  findings: Finding[];
  selectedHost: Host | null;
  runScan: (hostId: string) => Promise<void>;
  busy: string;
  remediations: Remediation[];
  snapshots: RollbackSnapshot[];
  hosts: Host[];
  selectedRemediation: Remediation | null;
  selectedRemediationHost: Host | null;
  selectedRemediationSnapshots: RollbackSnapshot[];
  selectedRemediationBlockers: string[];
  setSelectedRemediationId: (remediationId: string) => void;
  executionConfirmation: string;
  setExecutionConfirmation: (value: string) => void;
  approveRemediation: (remediation: Remediation) => Promise<void>;
  approveRemediationReboot: (remediation: Remediation) => Promise<void>;
  rejectRemediation: (remediationId: string) => Promise<unknown>;
  queueRemediationExecution: (remediation: Remediation) => Promise<void>;
}) {
  const jobStatuses = Array.from(new Set(props.allJobs.map((job) => job.status))).sort();
  const jobTypes = Array.from(new Set(props.allJobs.map((job) => job.jobType))).sort();
  const pageCount = Math.max(1, Math.ceil(props.logs.total / props.logs.pageSize));

  async function pivotToScan(scanId: string | null | undefined) {
    if (!scanId) return;
    await props.applyLogFilters({ scanId });
    await props.applyAgentScan(scanId);
  }

  async function pivotToHost(hostId: string | null | undefined) {
    if (!hostId) return;
    props.setJobFilters({ ...props.jobFilters, hostId });
    await props.applyLogFilters({ hostId });
  }

  function linkButton(label: string, value: string | null | undefined, action: () => void) {
    if (!value) return <span>None</span>;
    return (
      <button className="link-button" type="button" onClick={action}>
        {label || value}
      </button>
    );
  }

  return (
    <div className="operations-shell">
      <section className="ops-summary" aria-label="Operations action summary">
        <Metric label="Running" value={props.summary.runningJobs} detail="jobs" />
        <Metric label="Failed" value={props.summary.failedJobs} detail="jobs" />
        <Metric label="Queued" value={props.summary.queuedJobs} detail="jobs" />
        <Metric label="Alerts" value={props.summary.unacknowledgedAlerts} detail="unacknowledged" />
        <Metric label="Unhealthy" value={props.summary.unhealthyHealthChecks} detail="checks" />
        <Metric label="Agents" value={props.summary.failedOrExternalAgentRuns} detail="failed or external" />
        <Metric label="High Logs" value={props.summary.recentHighCriticalLogs} detail="current page" />
      </section>

      <nav className="segmented-nav" aria-label="Operations panels">
        {[
          ["health", "Health"],
          ["jobs", "Jobs"],
          ["logs", "Logs"],
          ["alerts", "Alerts"],
          ["audit", "Audit"],
          ["agents", "Agents"],
          ["remediations", "Remediations"]
        ].map(([key, label]) => (
          <button
            key={key}
            className={props.section === key ? "segment-button active" : "segment-button"}
            onClick={() => props.setSection(key as OperationsSection)}
          >
            {label}
          </button>
        ))}
      </nav>

      {props.section === "health" ? (
        <Panel title="Health Overview">
          <div className="detail-grid">
            <HealthCell label="API live" healthy={props.health.live.ok} detail={props.health.live.ok ? "responding" : "not responding"} />
            <HealthCell label="Database" healthy={props.health.ready.checks.database} detail="readiness" />
            <HealthCell label="Redis" healthy={props.health.ready.checks.redis} detail="readiness" />
            <HealthCell label="Collector mode" healthy detail={props.health.ready.checks.collectorMode} />
            <HealthCell label="Execution mode" healthy detail={props.health.ready.checks.executionMode} />
            <HealthCell
              label="Worker heartbeat"
              healthy={props.health.ops.checks.worker.healthy}
              detail={`last seen ${formatDate(props.health.ops.checks.worker.lastSeenAt)}`}
            />
            <HealthCell
              label="Celery Beat heartbeat"
              healthy={props.health.ops.checks.celeryBeat.healthy}
              detail={`last seen ${formatDate(props.health.ops.checks.celeryBeat.lastSeenAt)}`}
            />
          </div>
        </Panel>
      ) : null}

      {props.section === "jobs" ? (
        <Panel title="Jobs">
          <form className="form-grid" onSubmit={(event) => event.preventDefault()}>
            <label>
              Status
              <select
                value={props.jobFilters.status}
                onChange={(event) => props.setJobFilters({ ...props.jobFilters, status: event.target.value })}
              >
                <option value="">any status</option>
                {jobStatuses.map((status) => <option key={status} value={status}>{status}</option>)}
              </select>
            </label>
            <label>
              Job type
              <select
                value={props.jobFilters.jobType}
                onChange={(event) => props.setJobFilters({ ...props.jobFilters, jobType: event.target.value })}
              >
                <option value="">any type</option>
                {jobTypes.map((type) => <option key={type} value={type}>{type}</option>)}
              </select>
            </label>
            <label>
              Host ID
              <input value={props.jobFilters.hostId} onChange={(event) => props.setJobFilters({ ...props.jobFilters, hostId: event.target.value })} />
            </label>
            <label>
              Scan ID
              <input value={props.jobFilters.scanId} onChange={(event) => props.setJobFilters({ ...props.jobFilters, scanId: event.target.value })} />
            </label>
            <label>
              Remediation ID
              <input value={props.jobFilters.remediationId} onChange={(event) => props.setJobFilters({ ...props.jobFilters, remediationId: event.target.value })} />
            </label>
            <label>
              Campaign ID
              <input value={props.jobFilters.campaignId} onChange={(event) => props.setJobFilters({ ...props.jobFilters, campaignId: event.target.value })} />
            </label>
            <button className="secondary-button" type="button" onClick={() => props.setJobFilters({ status: "", jobType: "", hostId: "", scanId: "", remediationId: "", campaignId: "" })}>
              Clear
            </button>
          </form>
          {props.jobs.length === 0 ? <p>No jobs match the current filters.</p> : null}
          <div className="table-scroll">
            <table className="ops-table">
              <thead>
                <tr>
                  <th>Job</th>
                  <th>Status</th>
                  <th>Related IDs</th>
                  <th>Progress</th>
                  <th>Lease</th>
                  <th>Failure</th>
                  <th>Times</th>
                </tr>
              </thead>
              <tbody>
                {props.jobs.map((job) => (
                  <tr key={job.id}>
                    <td>
                      <button className="link-button strong-link" onClick={() => void props.loadJob(job.id)}>{job.id}</button>
                      <small>{job.jobType}</small>
                    </td>
                    <td><span className={statusClass(job.status)}>{job.status}</span></td>
                    <td>
                      <small>host {linkButton(job.hostId ?? "", job.hostId, () => {
                        void pivotToHost(job.hostId);
                      })}</small>
                      <small>scan {linkButton(job.scanId ?? "", job.scanId, () => void pivotToScan(job.scanId))}</small>
                      <small>rem {linkButton(job.remediationId ?? "", job.remediationId, () => void props.applyLogFilters({ remediationId: job.remediationId ?? "" }))}</small>
                      <small>campaign {textValue(job.campaignId)}</small>
                    </td>
                    <td>
                      <strong>{job.progressPercent}%</strong>
                      <small>{job.currentPhase ?? "no phase"}</small>
                      <small>{job.attempts}/{job.maxAttempts} attempts</small>
                    </td>
                    <td>
                      <small>{textValue(job.leaseOwner)}</small>
                      <small>heartbeat {formatDate(job.heartbeatAt)}</small>
                      <small>expires {formatDate(job.leaseExpiresAt)}</small>
                    </td>
                    <td>
                      {job.lastFailure ? (
                        <>
                          <small className="warning-text">{job.lastFailure.category}</small>
                          <small>{job.lastFailure.message}</small>
                          <small>{job.lastFailure.retryable ? "retryable" : "not retryable"} / {formatDate(job.lastFailure.failedAt)}</small>
                        </>
                      ) : <small>None</small>}
                      {job.error ? <small className="warning-text">{job.error}</small> : null}
                    </td>
                    <td>
                      <small>created {formatDate(job.createdAt)}</small>
                      <small>updated {formatDate(job.updatedAt)}</small>
                      <small>completed {formatDate(job.completedAt)}</small>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          {props.selectedJob ? (
            <div className="detail-block">
              <div className="chip-row">
                <span className={statusClass(props.selectedJob.status)}>{props.selectedJob.status}</span>
                <span className="status-chip">{props.selectedJob.jobType}</span>
                {props.selectedJob.lastFailure ? <span className="status-chip status-failed">last failure</span> : null}
              </div>
              <div className="action-row">
                <button className="secondary-button" onClick={() => void props.applyLogFilters({ jobId: props.selectedJob?.id ?? "" })}>
                  Related Logs
                </button>
                {props.selectedJob.scanId ? (
                  <button className="secondary-button" onClick={() => void props.applyAgentScan(props.selectedJob?.scanId ?? "")}>
                    Scan Agents
                  </button>
                ) : null}
              </div>
              <pre>{JSON.stringify(props.selectedJob.result, null, 2)}</pre>
            </div>
          ) : null}
        </Panel>
      ) : null}

      {props.section === "logs" ? (
        <Panel title="Logs">
          <form className="form-grid" onSubmit={(event) => {
            event.preventDefault();
            void props.loadLogs(1);
          }}>
            <label>Host ID<input value={props.logFilters.hostId} onChange={(event) => props.setLogFilters({ ...props.logFilters, hostId: event.target.value })} /></label>
            <label>Job ID<input value={props.logFilters.jobId} onChange={(event) => props.setLogFilters({ ...props.logFilters, jobId: event.target.value })} /></label>
            <label>Scan ID<input value={props.logFilters.scanId} onChange={(event) => props.setLogFilters({ ...props.logFilters, scanId: event.target.value })} /></label>
            <label>Remediation ID<input value={props.logFilters.remediationId} onChange={(event) => props.setLogFilters({ ...props.logFilters, remediationId: event.target.value })} /></label>
            <label>Agent run ID<input value={props.logFilters.agentRunId} onChange={(event) => props.setLogFilters({ ...props.logFilters, agentRunId: event.target.value })} /></label>
            <label>Phase ID<input value={props.logFilters.phaseId} onChange={(event) => props.setLogFilters({ ...props.logFilters, phaseId: event.target.value })} /></label>
            <label>Task ID<input value={props.logFilters.taskId} onChange={(event) => props.setLogFilters({ ...props.logFilters, taskId: event.target.value })} /></label>
            <label>
              Severity
              <select value={props.logFilters.severity} onChange={(event) => props.setLogFilters({ ...props.logFilters, severity: event.target.value })}>
                <option value="">any severity</option>
                <option value="info">info</option>
                <option value="low">low</option>
                <option value="medium">medium</option>
                <option value="high">high</option>
                <option value="critical">critical</option>
              </select>
            </label>
            <label>Source<input value={props.logFilters.source} onChange={(event) => props.setLogFilters({ ...props.logFilters, source: event.target.value })} /></label>
            <label>
              Page size
              <select value={props.logFilters.pageSize} onChange={(event) => props.setLogFilters({ ...props.logFilters, pageSize: Number(event.target.value) })}>
                <option value={25}>25</option>
                <option value={50}>50</option>
                <option value={100}>100</option>
              </select>
            </label>
            <button className="primary-button" type="submit">Filter Logs</button>
            <button
              className="secondary-button"
              type="button"
              onClick={() => {
                props.setLogFilters({ hostId: "", jobId: "", scanId: "", remediationId: "", agentRunId: "", severity: "", source: "", phaseId: "", taskId: "", page: 1, pageSize: 25 });
              }}
            >
              Clear
            </button>
          </form>
          <div className="pager-row">
            <button className="secondary-button" disabled={props.logs.page <= 1} onClick={() => void props.loadLogs(props.logs.page - 1)}>Previous</button>
            <span>Page {props.logs.page} / {pageCount}</span>
            <button className="secondary-button" disabled={props.logs.page >= pageCount} onClick={() => void props.loadLogs(props.logs.page + 1)}>Next</button>
          </div>
          {props.logs.items.length === 0 ? <p>No logs match the current filters.</p> : null}
          <div className="table-scroll">
            <table className="ops-table">
              <thead>
                <tr>
                  <th>Timestamp</th>
                  <th>Severity</th>
                  <th>Event</th>
                  <th>Source</th>
                  <th>Related IDs</th>
                  <th>Output Flags</th>
                </tr>
              </thead>
              <tbody>
                {props.logs.items.map((log) => (
                  <tr key={log.id}>
                    <td><button className="link-button" onClick={() => void props.openLog(log.id)}>{formatDate(log.timestamp)}</button></td>
                    <td><span className={`severity severity-${log.severity}`}>{log.severity}</span></td>
                    <td>
                      <strong>{log.eventType}</strong>
                      <small>{log.evidenceCategory} / {log.status}</small>
                      <small>{log.commandDescription ?? "no command description"}</small>
                      <small>{log.failureClassification ?? "no failure classification"}</small>
                    </td>
                    <td>
                      <small>{log.source}</small>
                      <small>changed {String(log.changed)} / simulated {String(log.simulated)}</small>
                    </td>
                    <td>
                      <small>host {linkButton(log.hostId ?? "", log.hostId, () => void props.applyLogFilters({ hostId: log.hostId ?? "" }))}</small>
                      <small>job {linkButton(log.jobId ?? "", log.jobId, () => void props.applyLogFilters({ jobId: log.jobId ?? "" }))}</small>
                      <small>scan {linkButton(log.scanId ?? "", log.scanId, () => void pivotToScan(log.scanId))}</small>
                      <small>rem {linkButton(log.remediationId ?? "", log.remediationId, () => void props.applyLogFilters({ remediationId: log.remediationId ?? "" }))}</small>
                    </td>
                    <td>
                      <div className="chip-row">
                        {log.redacted ? <span className="status-chip status-pending">redacted</span> : null}
                        {log.truncated ? <span className="status-chip status-pending">truncated</span> : null}
                        {log.externallyProcessed ? <span className="status-chip status-open">external</span> : null}
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          {props.selectedLog ? (
            <div className="detail-block">
              <div className="detail-grid">
                <div><dt>Duration</dt><dd>{props.selectedLog.durationMs} ms</dd></div>
                <div><dt>Return code</dt><dd>{textValue(props.selectedLog.returnCode)}</dd></div>
                <div><dt>Retry count</dt><dd>{props.selectedLog.retryCount}</dd></div>
                <div><dt>Reboot relevance</dt><dd>{props.selectedLog.rebootRelevance}</dd></div>
                <div><dt>Remediation relevance</dt><dd>{props.selectedLog.remediationRelevance}</dd></div>
                <div><dt>Correlation IDs</dt><dd>{JSON.stringify(props.selectedLog.correlationIds)}</dd></div>
              </div>
              <div className="split-grid">
                <OutputBlock title="stdout" value={props.selectedLog.stdout} />
                <OutputBlock title="stderr" value={props.selectedLog.stderr} />
                <OutputBlock title="rawOutput" value={props.selectedLog.rawOutput} />
                <OutputBlock title="beforeValue" value={props.selectedLog.beforeValue} />
                <OutputBlock title="afterValue" value={props.selectedLog.afterValue} />
              </div>
            </div>
          ) : null}
        </Panel>
      ) : null}

      {props.section === "alerts" ? (
        <Panel title="Alerts">
          {props.alerts.length === 0 ? <p>No alerts.</p> : null}
          <div className="list-stack">
            {props.alerts.map((alert) => (
              <div key={alert.id} className="record-row">
                <div>
                  <div className="chip-row">
                    <span className={`severity severity-${alert.severity}`}>{alert.severity}</span>
                    <span className={statusClass(alert.acknowledged ? "acknowledged" : "open")}>{alert.acknowledged ? "acknowledged" : "open"}</span>
                  </div>
                  <strong>{alert.title}</strong>
                  <small>{alert.message}</small>
                  <small>host {linkButton(alert.hostId ?? "", alert.hostId, () => void pivotToHost(alert.hostId))} / job {linkButton(alert.jobId ?? "", alert.jobId, () => void props.applyLogFilters({ jobId: alert.jobId ?? "" }))}</small>
                  <small>created {formatDate(alert.createdAt)} / acknowledged {formatDate(alert.acknowledgedAt)}</small>
                </div>
                <button className="secondary-button" disabled={alert.acknowledged} onClick={() => void props.acknowledgeAlert(alert.id)}>
                  Acknowledge
                </button>
              </div>
            ))}
          </div>
        </Panel>
      ) : null}

      {props.section === "audit" ? (
        <Panel title="Audit">
          {props.auditEvents.length === 0 ? <p>No audit events.</p> : null}
          <div className="list-stack">
            {props.auditEvents.map((event) => (
              <div key={event.id} className="record-block">
                <div className="detail-grid">
                  <div><dt>Actor</dt><dd>{event.actor}</dd></div>
                  <div><dt>Action</dt><dd>{event.action}</dd></div>
                  <div><dt>Target</dt><dd>{event.targetType} / {textValue(event.targetId)}</dd></div>
                  <div><dt>Created</dt><dd>{formatDate(event.createdAt)}</dd></div>
                </div>
                <pre>{JSON.stringify(event.details, null, 2)}</pre>
              </div>
            ))}
          </div>
        </Panel>
      ) : null}

      {props.section === "agents" ? (
        <Panel title="Agent Activity">
          <form className="inline-form" onSubmit={(event) => {
            event.preventDefault();
            void props.loadAgentActivity();
          }}>
            <input aria-label="Agent scan ID" placeholder="scanId" value={props.agentScanId} onChange={(event) => props.setAgentScanId(event.target.value)} />
            <button className="primary-button" type="submit">Load</button>
          </form>
          {props.agentRuns.length === 0 ? <p>No agent runs match the current scan filter.</p> : null}
          <div className="table-scroll">
            <table className="ops-table">
              <thead>
                <tr>
                  <th>Scan</th>
                  <th>Agent</th>
                  <th>Model</th>
                  <th>Status</th>
                  <th>Tokens</th>
                  <th>Processing</th>
                </tr>
              </thead>
              <tbody>
                {props.agentRuns.map((run) => (
                  <tr key={run.id}>
                    <td><button className="link-button" onClick={() => void props.applyAgentScan(run.scanId)}>{run.scanId}</button></td>
                    <td>
                      <strong>{run.agent.name.replaceAll("_", " ")}</strong>
                      <small>{run.agent.responsibility}</small>
                    </td>
                    <td>
                      <small>{run.agent.provider}/{run.agent.model}</small>
                      <small>{run.agent.modelTier}</small>
                      <small>{run.inputHash}</small>
                    </td>
                    <td><span className={statusClass(run.status)}>{run.status}</span></td>
                    <td>
                      <small>prompt {run.promptTokens}</small>
                      <small>completion {run.completionTokens}</small>
                      <small>latency {run.latencyMs} ms</small>
                      <small>created {formatDate(run.createdAt)}</small>
                    </td>
                    <td>
                      <small>{run.cacheHit ? "cache hit" : "cache miss"}</small>
                      <small>{run.fallbackReason ?? "no fallback"}</small>
                      <small>{run.externallyProcessed ? "externally processed" : "local only"}</small>
                      <button className="link-button" onClick={() => props.setSelectedAgentRun(run)}>Output JSON</button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          {props.selectedAgentRun ? (
            <div className="detail-block">
              <div className="chip-row">
                <span className={statusClass(props.selectedAgentRun.status)}>{props.selectedAgentRun.status}</span>
                <span className="status-chip">{props.selectedAgentRun.agent.name}</span>
              </div>
              <pre>{JSON.stringify(props.selectedAgentRun.output, null, 2)}</pre>
            </div>
          ) : null}
          {props.agentMessages.length ? (
            <div className="list-stack">
              <h3>Messages</h3>
              {props.agentMessages.map((message) => (
                <div key={message.id} className="record-block">
                  <strong>{message.fromAgent.replaceAll("_", " ")} to {message.toAgent.replaceAll("_", " ")}</strong>
                  <small>{message.response} / {formatDate(message.createdAt)}</small>
                  <small>claims {message.claimIds.join(", ") || "none"}</small>
                  <small>citations {message.citations.join(", ") || "none"}</small>
                  <p>{message.reasoning}</p>
                </div>
              ))}
            </div>
          ) : null}
        </Panel>
      ) : null}

      {props.section === "remediations" ? (
        <>
          <SecondaryPanel title="Host Findings">
            <div className="panel-actions">
              {props.selectedHost ? (
                <button className="secondary-button" onClick={() => void props.runScan(props.selectedHost?.id ?? "")}>
                  {props.busy === `scan-${props.selectedHost.id}` ? "Scanning..." : "Run Scan"}
                </button>
              ) : null}
            </div>
            {props.findings.length === 0 ? <p>No findings for the selected host.</p> : null}
            <div className="list-stack">
              {props.findings.map((finding) => (
                <div key={finding.id} className="record-block">
                  <div className="chip-row">
                    <span className={`severity severity-${finding.severity}`}>{finding.severity}</span>
                    <span className="status-chip">{finding.sourceAgent.replaceAll("_", " ")}</span>
                    <span className="status-chip">{finding.verifierStatus}</span>
                  </div>
                  <h3>{finding.summary}</h3>
                  <p>{finding.explanation}</p>
                  {finding.evidence.map((item) => (
                    <blockquote key={item.citation}>
                      {item.excerpt}
                      <footer>{item.source}</footer>
                    </blockquote>
                  ))}
                </div>
              ))}
            </div>
          </SecondaryPanel>

          <Panel title="Remediation Execution">
            {props.remediations.length === 0 ? <p>No remediations queued.</p> : null}
            {props.remediations.length > 0 ? (
              <div className="remediation-workspace">
                <div className="remediation-list">
                  {props.remediations.map((remediation) => (
                    <button
                      key={remediation.id}
                      className={`remediation-picker ${props.selectedRemediation?.id === remediation.id ? "selected" : ""}`}
                      onClick={() => props.setSelectedRemediationId(remediation.id)}
                    >
                      <span>
                        <strong>{remediation.title}</strong>
                        <small>{hostLabel(props.hosts, remediation.hostId)} / plan v{remediation.planVersion}</small>
                      </span>
                      <span className={statusClass(remediation.executionState)}>{remediation.executionState}</span>
                    </button>
                  ))}
                </div>

                {props.selectedRemediation ? (
                  <div className="execution-flow">
                    <div className="chip-row">
                      <span className={`severity severity-${props.selectedRemediation.riskLevel}`}>{props.selectedRemediation.riskLevel}</span>
                      <span className={statusClass(props.selectedRemediation.approvalState)}>patch {props.selectedRemediation.approvalState}</span>
                      <span className={statusClass(props.selectedRemediation.rebootApprovalState)}>reboot {props.selectedRemediation.rebootApprovalState}</span>
                      <span className={statusClass(props.selectedRemediation.executionState)}>{props.selectedRemediation.executionState}</span>
                    </div>
                    <h3>{props.selectedRemediation.title}</h3>
                    <p>{props.selectedRemediation.aiDecision.explanation}</p>
                    <div className="execution-steps" aria-label="Remediation execution steps">
                      <div className="execution-step complete">
                        <strong>1. Review plan</strong>
                        <small>Plan v{props.selectedRemediation.planVersion} / {props.selectedRemediation.planHash}</small>
                      </div>
                      <div className={props.selectedRemediation.approvalState === "approved" ? "execution-step complete" : "execution-step pending"}>
                        <strong>2. Approve patch</strong>
                        <small>{props.selectedRemediation.approvalState}</small>
                      </div>
                      <div className={!remediationRequiresReboot(props.selectedRemediation) || props.selectedRemediation.rebootApprovalState === "approved" ? "execution-step complete" : "execution-step pending"}>
                        <strong>3. Approve reboot risk</strong>
                        <small>{remediationRequiresReboot(props.selectedRemediation) ? props.selectedRemediation.rebootApprovalState : "not required"}</small>
                      </div>
                      <div className={["queued", "running", "succeeded"].includes(props.selectedRemediation.executionState) ? "execution-step complete" : "execution-step pending"}>
                        <strong>4. Queue execution</strong>
                        <small>{props.selectedRemediation.executionState}</small>
                      </div>
                    </div>
                    <div className="detail-grid">
                      <div><dt>Host</dt><dd>{hostLabel(props.hosts, props.selectedRemediation.hostId)}</dd></div>
                      <div><dt>Update scope</dt><dd>{props.selectedRemediation.updateScope}</dd></div>
                      <div><dt>Reboot assessment</dt><dd>{props.selectedRemediation.rebootAssessment.status.replaceAll("_", " ")}</dd></div>
                      <div><dt>Downtime</dt><dd>{props.selectedRemediation.rebootAssessment.estimatedDowntimeMinutes} min</dd></div>
                      <div><dt>Execution timing</dt><dd>{props.selectedRemediation.executionTiming.replaceAll("_", " ")}</dd></div>
                      <div><dt>Failure policy</dt><dd>{props.selectedRemediation.failurePolicy.notifyOperator ? "notify operator" : "no notification"}</dd></div>
                      <div><dt>Snapshot protection</dt><dd>{props.selectedRemediationHost?.snapshotPlatform && props.selectedRemediationHost.snapshotPlatform !== "none" ? props.selectedRemediationHost.snapshotPlatform : "not configured"}</dd></div>
                      <div><dt>Snapshot status</dt><dd>{props.selectedRemediationSnapshots[0]?.state ?? "none"}</dd></div>
                    </div>
                    <p className="muted-text">{props.selectedRemediation.rebootAssessment.rationale}</p>
                    {props.selectedRemediationSnapshots.length > 0 ? (
                      <div className="list-stack">
                        {props.selectedRemediationSnapshots.map((snapshot) => (
                          <div key={snapshot.id} className="record-block">
                            <div className="chip-row">
                              <span className={statusClass(snapshot.state)}>{snapshot.state}</span>
                              <span className="status-chip">{snapshot.provider}</span>
                            </div>
                            <div className="detail-grid">
                              <div><dt>Snapshot</dt><dd>{snapshot.id}</dd></div>
                              <div><dt>External ID</dt><dd>{snapshot.externalSnapshotId ?? "None"}</dd></div>
                              <div><dt>Delete after</dt><dd>{formatDate(snapshot.deleteAfter)}</dd></div>
                              <div><dt>Updated</dt><dd>{formatDate(snapshot.updatedAt)}</dd></div>
                            </div>
                            {Object.keys(snapshot.healthCheckResult ?? {}).length ? (
                              <pre>{JSON.stringify(snapshot.healthCheckResult, null, 2)}</pre>
                            ) : null}
                            {snapshot.failureSummary ? <small className="warning-text">{snapshot.failureSummary}</small> : null}
                          </div>
                        ))}
                      </div>
                    ) : null}
                    {props.selectedRemediationBlockers.length > 0 ? (
                      <div className="execution-blockers">
                        <strong>Before execution</strong>
                        {props.selectedRemediationBlockers.map((blocker) => <small key={blocker}>{blocker}</small>)}
                      </div>
                    ) : (
                      <div className="ready-note">This plan is ready to queue. Type the hostname to enable execution.</div>
                    )}
                    <div className="action-row">
                      <button className="primary-button" disabled={props.selectedRemediation.approvalState !== "pending"} onClick={() => void props.approveRemediation(props.selectedRemediation as Remediation)}>Approve Patch</button>
                      <button className="secondary-button" disabled={props.selectedRemediation.rebootApprovalState !== "pending"} onClick={() => void props.approveRemediationReboot(props.selectedRemediation as Remediation)}>Approve Reboot</button>
                      <button className="secondary-button" disabled={props.selectedRemediation.approvalState !== "pending"} onClick={() => void props.rejectRemediation(props.selectedRemediation?.id ?? "")}>Reject</button>
                      <button className="secondary-button" onClick={() => void props.applyLogFilters({ remediationId: props.selectedRemediation?.id ?? "" })}>Related Logs</button>
                    </div>
                    <div className="execution-confirm">
                      <label>
                        Queue execution confirmation
                        <input
                          placeholder={props.selectedRemediationHost ? `type ${props.selectedRemediationHost.name}` : "host unavailable"}
                          value={props.executionConfirmation}
                          onChange={(event) => props.setExecutionConfirmation(event.target.value)}
                        />
                      </label>
                      <button
                        className="primary-button"
                        disabled={
                          !canQueueRemediationExecution(props.selectedRemediation, props.selectedRemediationHost)
                          || !props.selectedRemediationHost
                          || props.executionConfirmation !== props.selectedRemediationHost.name
                          || props.busy === `execute-${props.selectedRemediation.id}`
                        }
                        onClick={() => void props.queueRemediationExecution(props.selectedRemediation as Remediation)}
                      >
                        Queue Execution
                      </button>
                    </div>
                    <div className="model-list">
                      {props.selectedRemediation.aiDecision.agentAssignments.map((agent) => (
                        <span key={agent.name}>{agent.name.replaceAll("_", " ")}: {agent.provider}/{agent.model} ({agent.modelTier})</span>
                      ))}
                    </div>
                    {props.selectedRemediation.result ? <pre>{JSON.stringify(props.selectedRemediation.result, null, 2)}</pre> : null}
                  </div>
                ) : null}
              </div>
            ) : null}
          </Panel>
        </>
      ) : null}
    </div>
  );
}

function HealthCell(props: { label: string; healthy: boolean; detail: string }) {
  return (
    <div>
      <dt>{props.label}</dt>
      <dd>
        <span className={statusClass(props.healthy ? "ready" : "failed")}>
          {props.healthy ? "healthy" : "unhealthy"}
        </span>
      </dd>
      <small>{props.detail}</small>
    </div>
  );
}

function OutputBlock(props: { title: string; value: unknown }) {
  return (
    <div className="output-block">
      <dt>{props.title}</dt>
      <pre>{textValue(props.value)}</pre>
    </div>
  );
}

function Metric(props: { label: string; value: number; detail: string }) {
  return (
    <div className="metric">
      <span>{props.label}</span>
      <strong>{props.value}</strong>
      <small>{props.detail}</small>
    </div>
  );
}

function Panel(props: { title: string; children: ReactNode }) {
  return (
    <article className="panel">
      <div className="panel-header">
        <h2>{props.title}</h2>
      </div>
      <div className="panel-body">
        {props.children}
      </div>
    </article>
  );
}

function SecondaryPanel(props: { title: string; children: ReactNode }) {
  return (
    <details className="secondary-panel">
      <summary>{props.title}</summary>
      <div className="panel-body">
        {props.children}
      </div>
    </details>
  );
}
