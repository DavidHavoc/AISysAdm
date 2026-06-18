import { useEffect, useState } from "react";
import type { Finding, Host, HostInput, Remediation } from "@ai-sysadm/shared";
import { api } from "./api.js";

const defaultHost: HostInput = {
  name: "prod-web-1",
  address: "10.0.0.25",
  port: 22,
  username: "ubuntu",
  distroFamily: "debian",
  environment: "production",
  tags: ["web", "critical"]
};

export function App() {
  const [hosts, setHosts] = useState<Host[]>([]);
  const [selectedHostId, setSelectedHostId] = useState<string>("");
  const [findings, setFindings] = useState<Finding[]>([]);
  const [remediations, setRemediations] = useState<Remediation[]>([]);
  const [error, setError] = useState<string>("");

  async function refresh() {
    try {
      const [nextHosts, nextRemediations] = await Promise.all([
        api.listHosts(),
        api.listRemediations()
      ]);
      setHosts(nextHosts);
      setRemediations(nextRemediations);

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
    void refresh();
  }, []);

  async function addHost() {
    await api.createHost(defaultHost);
    await refresh();
  }

  async function runScan(hostId: string) {
    await api.runScan(hostId);
    const nextFindings = await api.listFindings(hostId);
    setFindings(nextFindings);
    await refresh();
  }

  async function approve(remediationId: string) {
    await api.approveRemediation(remediationId);
    await refresh();
  }

  async function reject(remediationId: string) {
    await api.rejectRemediation(remediationId);
    await refresh();
  }

  async function chooseHost(hostId: string) {
    setSelectedHostId(hostId);
    setFindings(await api.listFindings(hostId));
  }

  const selectedHost = hosts.find((host) => host.id === selectedHostId);

  return (
    <main className="app-shell">
      <section className="hero">
        <div>
          <p className="eyebrow">Internal Ops Console</p>
          <h1>AI Linux Sysadmin</h1>
          <p className="hero-copy">
            Inspect Ubuntu and Debian VMs over SSH, synthesize findings with specialist agents,
            and gate every remediation behind human approval.
          </p>
        </div>
        <button className="primary-button" onClick={() => void addHost()}>
          Add Demo Host
        </button>
      </section>

      {error ? <section className="error-banner">{error}</section> : null}

      <section className="dashboard-grid">
        <article className="panel">
          <div className="panel-header">
            <h2>Fleet</h2>
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
                <span>{host.environment}</span>
              </button>
            ))}
          </div>
        </article>

        <article className="panel">
          <div className="panel-header">
            <h2>Host Findings</h2>
            {selectedHost ? (
              <button className="secondary-button" onClick={() => void runScan(selectedHost.id)}>
                Run Scan
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
                <p>{finding.category}</p>
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
                  <span>{remediation.executionState}</span>
                </div>
                <h3>{remediation.actionType}</h3>
                <p>Playbook: {remediation.playbook}</p>
                <p>Snapshot hook: {remediation.preChangeProtection.status}</p>
                <div className="action-row">
                  <button
                    className="primary-button"
                    disabled={remediation.approvalState !== "pending"}
                    onClick={() => void approve(remediation.id)}
                  >
                    Approve
                  </button>
                  <button
                    className="secondary-button"
                    disabled={remediation.approvalState !== "pending"}
                    onClick={() => void reject(remediation.id)}
                  >
                    Reject
                  </button>
                </div>
                {remediation.result ? <pre>{remediation.result.output}</pre> : null}
              </div>
            ))}
          </div>
        </article>
      </section>
    </main>
  );
}

