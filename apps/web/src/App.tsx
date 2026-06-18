import { useEffect, useState } from "react";
import type {
  Finding,
  Host,
  HostInput,
  PatchCampaign,
  Remediation,
  User
} from "@ai-sysadm/shared";
import { api } from "./api.js";

const defaultHost: HostInput = {
  name: "prod-web-1",
  address: "10.0.0.25",
  port: 22,
  username: "ubuntu",
  distroFamily: "debian",
  environment: "production",
  tags: ["web", "critical"],
  criticality: "high",
  availabilityClass: "high_availability",
  patchPolicy: {
    updateMode: "orchestrator_decides",
    executionTiming: "immediate",
    maxBatchSize: 5,
    canaryCount: 1,
    rebootPolicy: "if_required"
  }
};

export function App() {
  const [user, setUser] = useState<User | null>(null);
  const [authChecked, setAuthChecked] = useState(false);
  const [username, setUsername] = useState("admin");
  const [password, setPassword] = useState("");
  const [hosts, setHosts] = useState<Host[]>([]);
  const [selectedHostId, setSelectedHostId] = useState<string>("");
  const [findings, setFindings] = useState<Finding[]>([]);
  const [remediations, setRemediations] = useState<Remediation[]>([]);
  const [campaigns, setCampaigns] = useState<PatchCampaign[]>([]);
  const [error, setError] = useState<string>("");
  const [busy, setBusy] = useState<string>("");

  async function refresh() {
    try {
      const [nextHosts, nextRemediations, nextCampaigns] = await Promise.all([
        api.listHosts(),
        api.listRemediations(),
        api.listCampaigns()
      ]);
      setHosts(nextHosts);
      setRemediations(nextRemediations);
      setCampaigns(nextCampaigns);

      if (nextHosts.length > 0) {
        const hostId = selectedHostId || nextHosts[0].id;
        setSelectedHostId(hostId);
        setFindings(await api.listFindings(hostId));
      }
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

  async function login(event: React.FormEvent) {
    event.preventDefault();
    setBusy("login");
    setError("");
    try {
      const currentUser = await api.login(username, password);
      setUser(currentUser);
      setPassword("");
      await refresh();
    } catch (nextError) {
      setError(nextError instanceof Error ? nextError.message : "Login failed");
    } finally {
      setBusy("");
    }
  }

  async function logout() {
    await api.logout();
    setUser(null);
    setHosts([]);
    setFindings([]);
    setRemediations([]);
    setCampaigns([]);
  }

  async function addHost() {
    await act("add-host", async () => {
      await api.createHost({
        ...defaultHost,
        name: hosts.length ? `prod-web-${hosts.length + 1}` : defaultHost.name,
        address: `10.0.0.${25 + hosts.length}`
      });
    });
  }

  async function runScan(hostId: string) {
    await act(`scan-${hostId}`, async () => {
      await api.runScan(hostId);
      setFindings(await api.listFindings(hostId));
    });
  }

  async function approve(remediation: Remediation) {
    const host = hosts.find((item) => item.id === remediation.hostId);
    if (!host) {
      setError("The remediation host is no longer available.");
      return;
    }
    const confirmation = window.prompt(
      `Type ${host.name} to approve this exact plan.`
    );
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

  async function reject(remediationId: string) {
    await act(`reject-${remediationId}`, () => api.rejectRemediation(remediationId));
  }

  async function chooseHost(hostId: string) {
    setSelectedHostId(hostId);
    setFindings(await api.listFindings(hostId));
  }

  async function createCampaign() {
    await act("create-campaign", () =>
      api.createCampaign("Production patch wave", hosts.map((host) => host.id))
    );
  }

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

  const selectedHost = hosts.find((host) => host.id === selectedHostId);

  if (!authChecked) {
    return <main className="app-shell"><p>Loading operator session...</p></main>;
  }

  if (!user) {
    return (
      <main className="app-shell">
        <section className="hero">
          <div>
            <p className="eyebrow">Internal Ops Console</p>
            <h1>AI Linux Sysadmin</h1>
            <p className="hero-copy">Sign in to inspect hosts and approve exact remediation plans.</p>
          </div>
        </section>
        {error ? <section className="error-banner">{error}</section> : null}
        <form className="panel panel-body" onSubmit={(event) => void login(event)}>
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
      <section className="hero">
        <div>
          <p className="eyebrow">Internal Ops Console</p>
          <h1>AI Linux Sysadmin</h1>
          <p className="hero-copy">
            Two economy specialists inspect Linux state and logs. A capable orchestrator explains
            the risk, chooses patch scope, predicts reboot impact, and waits for your approval.
          </p>
        </div>
        <div className="action-row">
          <button className="primary-button" disabled={busy === "add-host"} onClick={() => void addHost()}>
            Add Demo Host
          </button>
          <button className="secondary-button" onClick={() => void logout()}>
            Sign out
          </button>
        </div>
      </section>

      {error ? <section className="error-banner">{error}</section> : null}

      <section className="agent-strip" aria-label="AI agent architecture">
        <div>
          <span className="agent-number">01</span>
          <strong>Orchestrator AI</strong>
          <small>Capable model / plans, explains, gates</small>
        </div>
        <div>
          <span className="agent-number">02</span>
          <strong>Linux State AI</strong>
          <small>Economy model / packages, kernel, capacity</small>
        </div>
        <div>
          <span className="agent-number">03</span>
          <strong>Log Analysis AI</strong>
          <small>Economy model / services, auth, boot events</small>
        </div>
      </section>

      <section className="dashboard-grid">
        <article className="panel">
          <div className="panel-header">
            <h2>Fleet</h2>
            {hosts.length ? (
              <button
                className="secondary-button"
                disabled={busy === "create-campaign"}
                onClick={() => void createCampaign()}
              >
                Plan Fleet Wave
              </button>
            ) : null}
          </div>
          <div className="panel-body fleet-list">
            {hosts.length === 0 ? <p>No hosts registered yet.</p> : null}
            {hosts.map((host) => (
              <button
                key={host.id}
                className={`host-card ${host.id === selectedHostId ? "selected" : ""}`}
                onClick={() => void chooseHost(host.id)}
              >
                <strong>{host.name}</strong>
                <span>{host.address}</span>
                <span>{host.environment} / {host.availabilityClass.replace("_", " ")}</span>
              </button>
            ))}
            {campaigns.map((campaign) => (
              <div key={campaign.id} className="campaign-card">
                <span className="eyebrow">Fleet Campaign</span>
                <strong>{campaign.name}</strong>
                <span>{campaign.status} / batch {campaign.batchSize} / {campaign.totalBatches} wave(s)</span>
                <small>
                  {campaign.hosts.filter((host) =>
                    host.state === "awaiting_approval"
                    || host.state === "awaiting_reboot_approval"
                    || host.state === "plan_changed"
                  ).length} host(s) still require individual review.
                </small>
              </div>
            ))}
          </div>
        </article>

        <article className="panel">
          <div className="panel-header">
            <h2>Host Findings</h2>
            {selectedHost ? (
              <button className="secondary-button" onClick={() => void runScan(selectedHost.id)}>
                {busy === `scan-${selectedHost.id}` ? "Scanning..." : "Run Scan"}
              </button>
            ) : null}
          </div>
          <div className="panel-body">
            {!selectedHost ? <p>Select a host to inspect findings.</p> : null}
            {findings.map((finding) => (
              <div key={finding.id} className="finding-card">
                <div className="finding-meta">
                  <span className={`severity severity-${finding.severity}`}>{finding.severity}</span>
                  <span>{finding.sourceAgent}</span>
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
        </article>

        <article className="panel">
          <div className="panel-header">
            <h2>Pending Remediations</h2>
          </div>
          <div className="panel-body">
            {remediations.length === 0 ? <p>No remediations queued yet.</p> : null}
            {remediations.map((remediation) => (
              <div key={remediation.id} className="remediation-card">
                <div className="finding-meta">
                  <span className={`severity severity-${remediation.riskLevel}`}>{remediation.riskLevel}</span>
                  <span>{remediation.approvalState}</span>
                  <span>reboot: {remediation.rebootApprovalState}</span>
                  <span>{remediation.executionState}</span>
                </div>
                <h3>{remediation.title}</h3>
                <p>{remediation.aiDecision.explanation}</p>
                <dl className="plan-grid">
                  <div>
                    <dt>Update scope</dt>
                    <dd>{remediation.updateScope}</dd>
                  </div>
                  <div>
                    <dt>Reboot</dt>
                    <dd>{remediation.rebootAssessment.status.replaceAll("_", " ")}</dd>
                  </div>
                  <div>
                    <dt>Downtime</dt>
                    <dd>~{remediation.rebootAssessment.estimatedDowntimeMinutes} min</dd>
                  </div>
                  <div>
                    <dt>Rollout</dt>
                    <dd>{remediation.rolloutPolicy.strategy.replaceAll("_", " ")}</dd>
                  </div>
                </dl>
                <p className="reboot-note">{remediation.rebootAssessment.rationale}</p>
                <p className="approval-note">
                  Patch approval is bound to this version and hash. Reboot approval is separate.
                </p>
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
                    disabled={remediation.approvalState !== "pending" || busy === `approve-${remediation.id}`}
                    onClick={() => void approve(remediation)}
                  >
                    Approve Patch Plan
                  </button>
                  <button
                    className="secondary-button"
                    disabled={remediation.approvalState !== "pending"}
                    onClick={() => void reject(remediation.id)}
                  >
                    Reject
                  </button>
                </div>
                {remediation.result ? (
                  <div className="phase-list">
                    <strong>{remediation.result.summary}</strong>
                    {remediation.result.phases.map((phase) => (
                      <span key={phase.name}>{phase.state} / {phase.summary}</span>
                    ))}
                  </div>
                ) : null}
              </div>
            ))}
          </div>
        </article>
      </section>
    </main>
  );
}
