import { describe, expect, it } from "vitest";
import { hostSnapshotSchema, remediationSchema } from "./index.js";

describe("shared schemas", () => {
  it("accepts a valid host snapshot", () => {
    const parsed = hostSnapshotSchema.parse({
      hostId: "host-1",
      collectedAt: new Date().toISOString(),
      commands: {
        uptime: "up 10 hours"
      },
      packageSummary: {
        pendingSecurityUpdates: 3,
        pendingPackageUpdates: 9,
        rebootRequired: false
      },
      serviceSummary: {
        failedUnits: ["nginx.service"]
      },
      systemSummary: {
        uptimeHours: 10,
        loadAverage: [0.1, 0.2, 0.3],
        diskUsagePercent: 44,
        memoryUsagePercent: 58,
        kernelVersion: "6.8.0"
      },
      logs: {
        journal: "sample",
        auth: "sample",
        aptHistory: "sample"
      }
    });

    expect(parsed.packageSummary.pendingSecurityUpdates).toBe(3);
  });

  it("requires deferred snapshot metadata in remediations", () => {
    const parsed = remediationSchema.parse({
      id: "rem-1",
      hostId: "host-1",
      actionType: "security_upgrade",
      playbook: "security-upgrade.yml",
      inputs: {},
      riskLevel: "high",
      approvalState: "pending",
      executionState: "not_started",
      result: null,
      preChangeProtection: {
        supported: false,
        status: "deferred"
      },
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString()
    });

    expect(parsed.preChangeProtection.status).toBe("deferred");
  });
});
