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
  SshCredential,
  StructuredLogEvent,
  User
} from "@ai-sysadm/shared";
import { api } from "./api.js";

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
  page: number;
  pageSize: number;
};

type DashboardView = "fleet" | "operations" | "campaigns" | "evidence";

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
  const [findings, setFindings] = useState<Finding[]>([]);
  const [remediations, setRemediations] = useState<Remediation[]>([]);
  const [campaigns, setCampaigns] = useState<PatchCampaign[]>([]);
  const [selectedCampaignId, setSelectedCampaignId] = useState<string>("");
  const [campaignName, setCampaignName] = useState("Production patch wave");
  const [campaignHostIds, setCampaignHostIds] = useState<Set<string>>(new Set());
  const [schedules, setSchedules] = useState<HostSchedule[]>([]);
  const [scheduleForm, setScheduleForm] = useState<ScheduleFormState>(defaultScheduleForm);
  const [jobs, setJobs] = useState<DurableJob[]>([]);
  const [selectedJob, setSelectedJob] = useState<DurableJob | null>(null);
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [auditEvents, setAuditEvents] = useState<AuditEvent[]>([]);
  const [agentRuns, setAgentRuns] = useState<AgentRun[]>([]);
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
    page: 1,
    pageSize: 25
  });
  const [selectedLog, setSelectedLog] = useState<StructuredLogEvent | null>(null);
  const [connectionResult, setConnectionResult] = useState<ConnectionTestResult | null>(null);
  const [pendingHostKey, setPendingHostKey] = useState<string | null>(null);
  const [activeView, setActiveView] = useState<DashboardView>("fleet");
  const [error, setError] = useState<string>("");
  const [busy, setBusy] = useState<string>("");

  const selectedHost = hosts.find((host) => host.id === selectedHostId) ?? null;
  const selectedSchedule = schedules.find((schedule) => schedule.hostId === selectedHostId) ?? null;
  const selectedCampaign = campaigns.find((campaign) => campaign.id === selectedCampaignId) ?? null;

  const approvedCampaignCount = useMemo(
    () => selectedCampaign?.hosts.filter((host) => host.state === "approved").length ?? 0,
    [selectedCampaign]
  );

  async function refresh() {
    try {
      const [
        nextCredentials,
        nextHosts,
        nextRemediations,
        nextCampaigns,
        nextSchedules,
        nextJobs,
        nextAlerts,
        nextAuditEvents,
        nextAgentRuns,
        nextLogs
      ] = await Promise.all([
        api.listCredentials(),
        api.listHosts(),
        api.listRemediations(),
        api.listCampaigns(),
        api.listSchedules(),
        api.listJobs(),
        api.listAlerts(),
        api.listAudit(),
        api.listAgentRuns(agentScanId || undefined),
        api.listLogs(logFilters)
      ]);
      setCredentials(nextCredentials);
      setHosts(nextHosts);
      setRemediations(nextRemediations);
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
    setCampaigns([]);
    setSchedules([]);
    setJobs([]);
    setAlerts([]);
    setAuditEvents([]);
    setAgentRuns([]);
    setAgentMessages([]);
    setLogs(emptyLogPage);
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
    const input = hostInputFromForm(hostForm);
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
    if (!credentialFile) {
      setError("Choose a private key file before uploading a credential.");
      return;
    }
    await act("credential-upload", async () => {
      await api.uploadCredential(credentialName.trim(), credentialFile);
      setCredentialName("");
      setCredentialFile(null);
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

  async function openLog(id: string) {
    await act(`log-${id}`, async () => {
      setSelectedLog(await api.getLog(id));
    });
  }

  async function loadAgentActivity(scanId = agentScanId) {
    await act("agent-load", async () => {
      setAgentRuns(await api.listAgentRuns(scanId || undefined));
      setAgentMessages(scanId ? await api.listAgentMessages(scanId) : []);
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
        <Metric label="Credentials" value={credentials.length} detail="SSH keys" />
        <Metric label="Jobs" value={jobs.length} detail={`${jobs.filter((job) => job.status === "running").length} running`} />
        <Metric label="Alerts" value={alerts.filter((alert) => !alert.acknowledged).length} detail="unacknowledged" />
      </section>

      <nav className="workspace-tabs" aria-label="Dashboard sections">
        <button
          className={activeView === "fleet" ? "tab-button active" : "tab-button"}
          onClick={() => setActiveView("fleet")}
        >
          Fleet
        </button>
        <button
          className={activeView === "operations" ? "tab-button active" : "tab-button"}
          onClick={() => setActiveView("operations")}
        >
          Work Queue
        </button>
        <button
          className={activeView === "campaigns" ? "tab-button active" : "tab-button"}
          onClick={() => setActiveView("campaigns")}
        >
          Campaigns
        </button>
        <button
          className={activeView === "evidence" ? "tab-button active" : "tab-button"}
          onClick={() => setActiveView("evidence")}
        >
          Evidence
        </button>
      </nav>

      <section className="dashboard-grid">
        {activeView === "fleet" ? (
          <>
        <Panel title="SSH Credentials">
          <form className="inline-form" onSubmit={(event) => void uploadCredential(event)}>
            <input
              aria-label="Credential name"
              placeholder="credential name"
              value={credentialName}
              onChange={(event) => setCredentialName(event.target.value)}
            />
            <input
              aria-label="Private key"
              type="file"
              onChange={(event) => setCredentialFile(event.target.files?.[0] ?? null)}
            />
            <button className="primary-button" disabled={busy === "credential-upload"} type="submit">
              Upload
            </button>
          </form>
          <div className="list-stack">
            {credentials.length === 0 ? <p>No SSH credentials uploaded.</p> : null}
            {credentials.map((credential) => (
              <div key={credential.id} className="record-row">
                <div>
                  <strong>{credential.name}</strong>
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
        </Panel>

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
                {credentials.map((credential) => (
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

        <Panel title="Schedules">
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
        </Panel>
          </>
        ) : null}

        {activeView === "operations" ? (
          <>
        <Panel title="Findings">
          <div className="panel-actions">
            {selectedHost ? (
              <button className="secondary-button" onClick={() => void runScan(selectedHost.id)}>
                {busy === `scan-${selectedHost.id}` ? "Scanning..." : "Run Scan"}
              </button>
            ) : null}
          </div>
          {findings.length === 0 ? <p>No findings for the selected host.</p> : null}
          <div className="list-stack">
            {findings.map((finding) => (
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
        </Panel>

        <Panel title="Remediations">
          {remediations.length === 0 ? <p>No remediations queued.</p> : null}
          <div className="list-stack">
            {remediations.map((remediation) => (
              <div key={remediation.id} className="record-block">
                <div className="chip-row">
                  <span className={`severity severity-${remediation.riskLevel}`}>{remediation.riskLevel}</span>
                  <span className={statusClass(remediation.approvalState)}>approval {remediation.approvalState}</span>
                  <span className={statusClass(remediation.rebootApprovalState)}>reboot {remediation.rebootApprovalState}</span>
                  <span className={statusClass(remediation.executionState)}>{remediation.executionState}</span>
                </div>
                <h3>{remediation.title}</h3>
                <p>{remediation.aiDecision.explanation}</p>
                <div className="detail-grid">
                  <div><dt>Host</dt><dd>{hostLabel(hosts, remediation.hostId)}</dd></div>
                  <div><dt>Plan version</dt><dd>{remediation.planVersion}</dd></div>
                  <div><dt>Plan hash</dt><dd>{remediation.planHash}</dd></div>
                  <div><dt>Reboot</dt><dd>{remediation.rebootAssessment.status.replaceAll("_", " ")}</dd></div>
                  <div><dt>Downtime</dt><dd>{remediation.rebootAssessment.estimatedDowntimeMinutes} min</dd></div>
                  <div><dt>Rollout</dt><dd>{remediation.rolloutPolicy.strategy.replaceAll("_", " ")}</dd></div>
                </div>
                <p className="muted-text">{remediation.rebootAssessment.rationale}</p>
                <div className="model-list">
                  {remediation.aiDecision.agentAssignments.map((agent) => (
                    <span key={agent.name}>
                      {agent.name.replaceAll("_", " ")}: {agent.provider}/{agent.model} ({agent.modelTier})
                    </span>
                  ))}
                </div>
                <div className="action-row">
                  <button
                    className="primary-button"
                    disabled={remediation.approvalState !== "pending"}
                    onClick={() => void approveRemediation(remediation)}
                  >
                    Approve Patch
                  </button>
                  <button
                    className="secondary-button"
                    disabled={remediation.rebootApprovalState !== "pending"}
                    onClick={() => void approveRemediationReboot(remediation)}
                  >
                    Approve Reboot
                  </button>
                  <button
                    className="secondary-button"
                    disabled={remediation.approvalState !== "pending"}
                    onClick={() => void act(`reject-${remediation.id}`, () => api.rejectRemediation(remediation.id))}
                  >
                    Reject
                  </button>
                  <button
                    className="primary-button"
                    disabled={remediation.approvalState !== "approved" || remediation.executionState === "running"}
                    onClick={() => void act(`execute-${remediation.id}`, () => api.executeRemediation(remediation.id))}
                  >
                    Execute
                  </button>
                </div>
                {remediation.result ? (
                  <pre>{JSON.stringify(remediation.result, null, 2)}</pre>
                ) : null}
              </div>
            ))}
          </div>
        </Panel>
          </>
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

        {activeView === "operations" ? (
          <>
        <Panel title="Jobs">
          <div className="list-stack">
            {jobs.map((job) => (
              <button key={job.id} className="record-row host-selector" onClick={() => void loadJob(job.id)}>
                <span>
                  <strong>{job.jobType}</strong>
                  <small>{job.status} / {job.progressPercent}% / {job.currentPhase ?? "no phase"}</small>
                  <small>Attempts {job.attempts}/{job.maxAttempts} / host {hostLabel(hosts, job.hostId)}</small>
                  {job.lastFailure ? <small className="warning-text">{job.lastFailure.category}: {job.lastFailure.message}</small> : null}
                  {job.error ? <small className="warning-text">{job.error}</small> : null}
                </span>
              </button>
            ))}
          </div>
          {selectedJob ? <pre>{JSON.stringify(selectedJob, null, 2)}</pre> : null}
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

        <Panel title="Alerts And Audit">
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
        </Panel>

        <Panel title="Agent Activity">
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
        </Panel>
          </>
        ) : null}
      </section>
    </main>
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
