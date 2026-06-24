import type {
  AgentMessage,
  AgentRun,
  Alert,
  AuditEvent,
  CampaignActionResponse,
  ConnectionTestResult,
  DurableJob,
  Finding,
  Host,
  HostInput,
  HostSchedule,
  LogPage,
  PatchCampaign,
  Remediation,
  ScanJob,
  SshCredential,
  StructuredLogEvent,
  User
} from "@ai-sysadm/shared";

const baseUrl = import.meta.env.VITE_API_URL ?? "http://localhost:4000";
let csrfToken = sessionStorage.getItem("ai-sysadm-csrf") ?? "";

export type LiveHealth = {
  ok: boolean;
};

export type ReadyHealth = {
  ok: boolean;
  checks: {
    database: boolean;
    redis: boolean;
    executionMode: string;
    collectorMode: string;
  };
};

export type OpsHealth = {
  ok: boolean;
  checks: {
    worker: {
      healthy: boolean;
      lastSeenAt: string | null;
    };
    celeryBeat: {
      healthy: boolean;
      lastSeenAt: string | null;
    };
  };
};

export type OperationsHealth = {
  live: LiveHealth;
  ready: ReadyHealth;
  ops: OpsHealth;
};

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const headers = new Headers(init?.headers);
  if (!(init?.body instanceof FormData)) {
    headers.set("Content-Type", "application/json");
  }
  if (init?.method && init.method !== "GET" && csrfToken) {
    headers.set("X-CSRF-Token", csrfToken);
  }
  const response = await fetch(`${baseUrl}${path}`, {
    credentials: "include",
    ...init,
    headers
  });
  if (!response.ok) {
    let detail = `Request failed: ${response.status}`;
    try {
      const payload = await response.json() as { detail?: string };
      detail = payload.detail ?? detail;
    } catch {
      // Keep the HTTP fallback when the response is not JSON.
    }
    throw new Error(detail);
  }
  if (response.status === 204) {
    return undefined as T;
  }
  return response.json() as Promise<T>;
}

function query(values: Record<string, string | number | undefined>) {
  const params = new URLSearchParams();
  Object.entries(values).forEach(([key, value]) => {
    if (value !== undefined && value !== "") params.set(key, String(value));
  });
  const rendered = params.toString();
  return rendered ? `?${rendered}` : "";
}

async function healthRequest<T>(path: string, fallback: T): Promise<T> {
  try {
    const response = await fetch(`${baseUrl}${path}`, { credentials: "include" });
    const payload = await response.json() as unknown;
    if (
      payload
      && typeof payload === "object"
      && "detail" in payload
      && (payload as { detail?: unknown }).detail
    ) {
      return (payload as { detail: T }).detail;
    }
    return payload as T;
  } catch {
    return fallback;
  }
}

export const api = {
  getOperationsHealth: async (): Promise<OperationsHealth> => {
    const [live, ready, ops] = await Promise.all([
      healthRequest<LiveHealth>("/health/live", { ok: false }),
      healthRequest<ReadyHealth>("/health/ready", {
        ok: false,
        checks: {
          database: false,
          redis: false,
          executionMode: "unknown",
          collectorMode: "unknown"
        }
      }),
      healthRequest<OpsHealth>("/health/ops", {
        ok: false,
        checks: {
          worker: { healthy: false, lastSeenAt: null },
          celeryBeat: { healthy: false, lastSeenAt: null }
        }
      })
    ]);
    return { live, ready, ops };
  },
  login: async (username: string, password: string) => {
    const response = await request<{ user: User; csrfToken: string }>("/auth/login", {
      method: "POST",
      body: JSON.stringify({ username, password })
    });
    csrfToken = response.csrfToken;
    sessionStorage.setItem("ai-sysadm-csrf", csrfToken);
    return response.user;
  },
  logout: async () => {
    await request<void>("/auth/logout", { method: "POST" });
    csrfToken = "";
    sessionStorage.removeItem("ai-sysadm-csrf");
  },
  me: () => request<User>("/auth/me"),
  listCredentials: () => request<SshCredential[]>("/credentials"),
  uploadCredential: (name: string, file: File) => {
    const form = new FormData();
    form.append("name", name);
    form.append("key", file);
    return request<SshCredential>("/credentials", { method: "POST", body: form });
  },
  deleteCredential: (credentialId: string) =>
    request<void>(`/credentials/${credentialId}`, { method: "DELETE" }),
  listHosts: () => request<Host[]>("/hosts"),
  createHost: (input: HostInput) => request<Host>("/hosts", {
    method: "POST",
    body: JSON.stringify(input)
  }),
  updateHost: (hostId: string, input: HostInput) => request<Host>(`/hosts/${hostId}`, {
    method: "PUT",
    body: JSON.stringify(input)
  }),
  deleteHost: (hostId: string) =>
    request<void>(`/hosts/${hostId}`, { method: "DELETE" }),
  testConnection: (hostId: string, confirmFingerprint?: string) =>
    request<ConnectionTestResult>(`/hosts/${hostId}/test-connection`, {
      method: "POST",
      body: JSON.stringify({ confirmFingerprint: confirmFingerprint ?? null })
    }),
  runScan: (hostId: string) => request<DurableJob>("/scans", {
    method: "POST",
    body: JSON.stringify({ hostId, trigger: "manual" })
  }),
  listScans: (hostId?: string) => request<ScanJob[]>(`/scans${query({ hostId })}`),
  listFindings: (hostId?: string) => request<Finding[]>(
    hostId ? `/hosts/${hostId}/findings` : "/findings"
  ),
  listRemediations: () => request<Remediation[]>("/remediations"),
  approveRemediation: (
    remediationId: string,
    planVersion: number,
    planHash: string,
    hostnameConfirmation: string
  ) => request<Remediation>(`/remediations/${remediationId}/approve`, {
    method: "POST",
    body: JSON.stringify({ planVersion, planHash, hostnameConfirmation })
  }),
  approveRemediationReboot: (
    remediationId: string,
    planVersion: number,
    planHash: string,
    hostnameConfirmation: string
  ) => request<Remediation>(`/remediations/${remediationId}/reboot-approval`, {
    method: "POST",
    body: JSON.stringify({ planVersion, planHash, hostnameConfirmation })
  }),
  executeRemediation: (remediationId: string) =>
    request<DurableJob>(`/remediations/${remediationId}/execute`, { method: "POST" }),
  rejectRemediation: (remediationId: string) =>
    request<Remediation>(`/remediations/${remediationId}/reject`, { method: "POST" }),
  listJobs: () => request<DurableJob[]>("/jobs"),
  getJob: (jobId: string) => request<DurableJob>(`/jobs/${jobId}`),
  listSchedules: () => request<HostSchedule[]>("/schedules"),
  updateSchedule: (
    hostId: string,
    input: Pick<HostSchedule, "enabled" | "timezone" | "cronExpression" | "overlapPolicy">
  ) => request<HostSchedule>(`/hosts/${hostId}/schedule`, {
    method: "PUT",
    body: JSON.stringify(input)
  }),
  listAgentRuns: (scanId?: string) =>
    request<AgentRun[]>(`/agent-runs${query({ scanId })}`),
  listAgentMessages: (scanId: string) =>
    request<AgentMessage[]>(`/agent-runs/${scanId}/messages`),
  listLogs: (filters: Record<string, string | number | undefined>) =>
    request<LogPage>(`/logs${query(filters)}`),
  getLog: (id: string) => request<StructuredLogEvent>(`/logs/${id}`),
  listAlerts: () => request<Alert[]>("/alerts"),
  acknowledgeAlert: (id: string) =>
    request<Alert>(`/alerts/${id}/acknowledge`, { method: "POST" }),
  listAudit: () => request<AuditEvent[]>("/audit-events"),
  listCampaigns: () => request<PatchCampaign[]>("/campaigns"),
  getCampaign: (campaignId: string) =>
    request<PatchCampaign>(`/campaigns/${campaignId}`),
  createCampaign: (name: string, hostIds: string[]) =>
    request<PatchCampaign>("/campaigns", {
      method: "POST",
      body: JSON.stringify({ name, hostIds })
    }),
  createCampaignProposals: (campaignId: string) =>
    request<CampaignActionResponse>(`/campaigns/${campaignId}/proposals`, {
      method: "POST"
    }),
  approveCampaignHost: (
    campaignId: string,
    hostId: string,
    planVersion: number,
    planHash: string,
    hostnameConfirmation: string
  ) => request<PatchCampaign>(`/campaigns/${campaignId}/hosts/${hostId}/approve`, {
    method: "POST",
    body: JSON.stringify({ planVersion, planHash, hostnameConfirmation })
  }),
  approveCampaignHostReboot: (
    campaignId: string,
    hostId: string,
    planVersion: number,
    planHash: string,
    hostnameConfirmation: string
  ) => request<PatchCampaign>(
    `/campaigns/${campaignId}/hosts/${hostId}/reboot-approval`,
    {
      method: "POST",
      body: JSON.stringify({ planVersion, planHash, hostnameConfirmation })
    }
  ),
  rejectCampaignHost: (campaignId: string, hostId: string) =>
    request<PatchCampaign>(`/campaigns/${campaignId}/hosts/${hostId}/reject`, {
      method: "POST"
    }),
  executeCampaign: (campaignId: string) =>
    request<CampaignActionResponse>(`/campaigns/${campaignId}/execute`, {
      method: "POST"
    }),
  cancelCampaign: (campaignId: string) =>
    request<PatchCampaign>(`/campaigns/${campaignId}/cancel`, {
      method: "POST"
    })
};
