import type {
  Finding,
  Host,
  HostInput,
  PatchCampaign,
  Remediation,
  ScanJob
} from "@ai-sysadm/shared";

const baseUrl = import.meta.env.VITE_API_URL ?? "http://localhost:4000";

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(`${baseUrl}${path}`, {
    headers: {
      "Content-Type": "application/json"
    },
    ...init
  });

  if (!response.ok) {
    throw new Error(`Request failed: ${response.status}`);
  }

  return response.json() as Promise<T>;
}

export const api = {
  listHosts: () => request<Host[]>("/hosts"),
  createHost: (input: HostInput) => request<Host>("/hosts", { method: "POST", body: JSON.stringify(input) }),
  runScan: (hostId: string) => request<ScanJob>("/scans", { method: "POST", body: JSON.stringify({ hostId }) }),
  listFindings: (hostId: string) => request<Finding[]>(`/hosts/${hostId}/findings`),
  listRemediations: () => request<Remediation[]>("/remediations"),
  approveRemediation: (remediationId: string) => request<Remediation>(`/remediations/${remediationId}/approve`, { method: "POST" }),
  rejectRemediation: (remediationId: string) => request<Remediation>(`/remediations/${remediationId}/reject`, { method: "POST" }),
  listCampaigns: () => request<PatchCampaign[]>("/campaigns"),
  createCampaign: (name: string, hostIds: string[]) => request<PatchCampaign>("/campaigns", {
    method: "POST",
    body: JSON.stringify({ name, hostIds })
  }),
  approveCampaign: (campaignId: string) => request<PatchCampaign>(`/campaigns/${campaignId}/approve`, { method: "POST" }),
  rejectCampaign: (campaignId: string) => request<PatchCampaign>(`/campaigns/${campaignId}/reject`, { method: "POST" })
};
