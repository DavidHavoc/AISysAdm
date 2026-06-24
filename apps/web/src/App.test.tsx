import { beforeEach, describe, expect, it, vi } from "vitest";
import type { CampaignHostPlan, Host, PatchCampaign, Remediation } from "@ai-sysadm/shared";

type FetchCall = [RequestInfo | URL, RequestInit | undefined];

function installStorage() {
  const values = new Map<string, string>();
  Object.defineProperty(globalThis, "sessionStorage", {
    configurable: true,
    value: {
      getItem: vi.fn((key: string) => values.get(key) ?? null),
      setItem: vi.fn((key: string, value: string) => values.set(key, value)),
      removeItem: vi.fn((key: string) => values.delete(key))
    }
  });
}

function okJson(payload: unknown, status = 200) {
  return {
    ok: status >= 200 && status < 300,
    status,
    json: async () => payload
  } as Response;
}

async function loadApi(fetchMock: ReturnType<typeof vi.fn>) {
  installStorage();
  vi.stubGlobal("fetch", fetchMock);
  vi.resetModules();
  return import("./api.js");
}

function lastRequest(fetchMock: ReturnType<typeof vi.fn>) {
  return fetchMock.mock.calls.at(-1) as FetchCall;
}

function requestBody(init: RequestInit | undefined) {
  return JSON.parse(String(init?.body)) as Record<string, unknown>;
}

describe("operator dashboard API workflows", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
    vi.unstubAllGlobals();
  });

  it("logs in, stores csrf, and loads dashboard collections", async () => {
    const fetchMock = vi.fn()
      .mockResolvedValueOnce(okJson({
        user: { id: "user-1", username: "admin", role: "admin", createdAt: "2026-01-01T00:00:00Z" },
        csrfToken: "csrf-1"
      }))
      .mockResolvedValue(okJson([]));
    const { api } = await loadApi(fetchMock);

    await api.login("admin", "secret");
    await Promise.all([
      api.listCredentials(),
      api.listHosts(),
      api.listSchedules(),
      api.listJobs(),
      api.listAlerts(),
      api.listAudit(),
      api.listCampaigns()
    ]);

    expect(fetchMock).toHaveBeenCalledWith(
      "http://localhost:4000/auth/login",
      expect.objectContaining({ method: "POST" })
    );
    expect(fetchMock.mock.calls.map(([url]) => String(url))).toEqual([
      "http://localhost:4000/auth/login",
      "http://localhost:4000/credentials",
      "http://localhost:4000/hosts",
      "http://localhost:4000/schedules",
      "http://localhost:4000/jobs",
      "http://localhost:4000/alerts",
      "http://localhost:4000/audit-events",
      "http://localhost:4000/campaigns"
    ]);
  });

  it("uploads, lists, and deletes ssh credentials with csrf protection", async () => {
    const fetchMock = vi.fn()
      .mockResolvedValueOnce(okJson({
        user: { id: "user-1", username: "admin", role: "admin", createdAt: "2026-01-01T00:00:00Z" },
        csrfToken: "csrf-credential"
      }))
      .mockResolvedValueOnce(okJson([{ id: "cred-1", name: "prod", fingerprint: "SHA256:x", createdAt: "2026-01-01T00:00:00Z" }]))
      .mockResolvedValueOnce(okJson({ id: "cred-2", name: "new", fingerprint: "SHA256:y", createdAt: "2026-01-01T00:00:00Z" }, 201))
      .mockResolvedValueOnce(okJson(undefined, 204));
    const { api } = await loadApi(fetchMock);

    await api.login("admin", "secret");
    await api.listCredentials();
    await api.uploadCredential("new", new File(["key"], "id_rsa"));
    await api.deleteCredential("cred-2");

    const upload = fetchMock.mock.calls[2] as FetchCall;
    expect(upload[0]).toBe("http://localhost:4000/credentials");
    expect(upload[1]?.body).toBeInstanceOf(FormData);

    const deleteCall = lastRequest(fetchMock);
    expect(deleteCall[0]).toBe("http://localhost:4000/credentials/cred-2");
    expect(deleteCall[1]?.method).toBe("DELETE");
    expect((deleteCall[1]?.headers as Headers).get("X-CSRF-Token")).toBe("csrf-credential");
  });

  it("edits and deletes hosts and supports host-key confirmation", async () => {
    const fetchMock = vi.fn()
      .mockResolvedValueOnce(okJson({
        user: { id: "user-1", username: "admin", role: "admin", createdAt: "2026-01-01T00:00:00Z" },
        csrfToken: "csrf-host"
      }))
      .mockResolvedValueOnce(okJson({ id: "host-1" }))
      .mockResolvedValueOnce(okJson(undefined, 204))
      .mockResolvedValueOnce(okJson({
        success: false,
        sshReachable: true,
        sudoAvailable: true,
        osSupported: true,
        ansibleCompatible: true,
        hostKeyFingerprint: "SHA256:host",
        checks: { host_key_confirmation: "required" }
      }))
      .mockResolvedValueOnce(okJson({
        success: true,
        sshReachable: true,
        sudoAvailable: true,
        osSupported: true,
        ansibleCompatible: true,
        hostKeyFingerprint: "SHA256:host",
        checks: {}
      }));
    const { api } = await loadApi(fetchMock);
    await api.login("admin", "secret");

    const hostInput = {
      name: "prod-1",
      address: "10.0.0.10",
      port: 22,
      username: "ubuntu",
      distroFamily: "debian" as const,
      environment: "prod",
      tags: ["web"],
      criticality: "high" as const,
      availabilityClass: "standard" as const,
      credentialId: "cred-1",
      sshHostKeyFingerprint: null,
      patchPolicy: {
        updateMode: "orchestrator_decides" as const,
        executionTiming: "immediate" as const,
        maxBatchSize: 5,
        canaryCount: 1,
        rebootPolicy: "if_required" as const
      }
    };

    await api.updateHost("host-1", hostInput);
    expect(lastRequest(fetchMock)[0]).toBe("http://localhost:4000/hosts/host-1");
    expect(requestBody(lastRequest(fetchMock)[1]).credentialId).toBe("cred-1");

    await api.deleteHost("host-1");
    expect(lastRequest(fetchMock)[1]?.method).toBe("DELETE");

    await api.testConnection("host-1");
    expect(requestBody(lastRequest(fetchMock)[1]).confirmFingerprint).toBeNull();

    await api.testConnection("host-1", "SHA256:host");
    expect(requestBody(lastRequest(fetchMock)[1]).confirmFingerprint).toBe("SHA256:host");
  });

  it("approves remediation patch, approves reboot, and executes", async () => {
    const fetchMock = vi.fn()
      .mockResolvedValueOnce(okJson({
        user: { id: "user-1", username: "admin", role: "admin", createdAt: "2026-01-01T00:00:00Z" },
        csrfToken: "csrf-remediation"
      }))
      .mockResolvedValue(okJson({ id: "ok" }));
    const { api } = await loadApi(fetchMock);
    await api.login("admin", "secret");

    await api.approveRemediation("rem-1", 3, "hash-3", "prod-1");
    expect(lastRequest(fetchMock)[0]).toBe("http://localhost:4000/remediations/rem-1/approve");
    expect(requestBody(lastRequest(fetchMock)[1])).toMatchObject({
      planVersion: 3,
      planHash: "hash-3",
      hostnameConfirmation: "prod-1"
    });

    await api.approveRemediationReboot("rem-1", 3, "hash-3", "prod-1");
    expect(lastRequest(fetchMock)[0]).toBe("http://localhost:4000/remediations/rem-1/reboot-approval");

    await api.executeRemediation("rem-1");
    expect(lastRequest(fetchMock)[0]).toBe("http://localhost:4000/remediations/rem-1/execute");

    const { canQueueRemediationExecution, remediationExecutionBlockers } = await import("./App.js");
    const host = {
      patchPolicy: { rebootPolicy: "if_required" }
    } as Host;
    const remediation = {
      approvalState: "approved",
      approvedBy: "admin",
      approvedAt: "2026-01-01T00:00:00Z",
      approvedPlanVersion: 3,
      approvedPlanHash: "hash-3",
      planVersion: 3,
      planHash: "hash-3",
      rebootAssessment: { status: "required", approvedIfRequired: true },
      rebootApprovalState: "approved",
      rebootApprovedBy: "admin",
      rebootApprovedAt: "2026-01-01T00:00:00Z",
      rebootApprovedPlanVersion: 3,
      rebootApprovedPlanHash: "hash-3",
      executionState: "not_started"
    } as unknown as Remediation;

    expect(canQueueRemediationExecution(remediation, host)).toBe(true);
    expect(remediationExecutionBlockers({
      ...remediation,
      rebootApprovalState: "pending"
    }, host)).toContain("Separate reboot approval is required.");
  });

  it("handles campaign proposal, per-host approvals, execution, cancel, and plan_changed gating", async () => {
    const fetchMock = vi.fn()
      .mockResolvedValueOnce(okJson({
        user: { id: "user-1", username: "admin", role: "admin", createdAt: "2026-01-01T00:00:00Z" },
        csrfToken: "csrf-campaign"
      }))
      .mockResolvedValue(okJson({ campaign: {}, jobs: [] }));
    const { api } = await loadApi(fetchMock);
    const { canApproveCampaignHost, canExecuteCampaign } = await import("./App.js");
    await api.login("admin", "secret");

    await api.createCampaign("wave", ["host-1"]);
    expect(lastRequest(fetchMock)[0]).toBe("http://localhost:4000/campaigns");
    expect(requestBody(lastRequest(fetchMock)[1])).toMatchObject({ name: "wave", hostIds: ["host-1"] });

    await api.createCampaignProposals("camp-1");
    expect(lastRequest(fetchMock)[0]).toBe("http://localhost:4000/campaigns/camp-1/proposals");

    await api.approveCampaignHost("camp-1", "host-1", 4, "hash-4", "prod-1");
    expect(lastRequest(fetchMock)[0]).toBe("http://localhost:4000/campaigns/camp-1/hosts/host-1/approve");
    expect(requestBody(lastRequest(fetchMock)[1]).hostnameConfirmation).toBe("prod-1");

    await api.approveCampaignHostReboot("camp-1", "host-1", 4, "hash-4", "prod-1");
    expect(lastRequest(fetchMock)[0]).toBe("http://localhost:4000/campaigns/camp-1/hosts/host-1/reboot-approval");

    await api.executeCampaign("camp-1");
    expect(lastRequest(fetchMock)[0]).toBe("http://localhost:4000/campaigns/camp-1/execute");

    await api.cancelCampaign("camp-1");
    expect(lastRequest(fetchMock)[0]).toBe("http://localhost:4000/campaigns/camp-1/cancel");

    const planChanged = {
      state: "plan_changed",
      planVersion: 4,
      planHash: "hash-4"
    } as CampaignHostPlan;
    const approvedCampaign = {
      hosts: [{ state: "approved" }]
    } as PatchCampaign;

    expect(canApproveCampaignHost(planChanged)).toBe(false);
    expect(canExecuteCampaign(approvedCampaign)).toBe(true);
  });
});
