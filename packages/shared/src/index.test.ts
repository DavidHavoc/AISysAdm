import { describe, expect, it } from "vitest";
import { hostInputSchema, remediationSchema } from "./index.js";

describe("shared schemas", () => {
  it("applies safe host patch policy defaults", () => {
    const parsed = hostInputSchema.parse({
      name: "web-1",
      address: "10.0.0.10",
      port: 22,
      username: "ubuntu",
      distroFamily: "debian",
      environment: "production",
      tags: ["web"],
      criticality: "high",
      availabilityClass: "high_availability",
      patchPolicy: {}
    });

    expect(parsed.patchPolicy.updateMode).toBe("orchestrator_decides");
    expect(parsed.patchPolicy.rebootPolicy).toBe("if_required");
  });

  it("requires patch and reboot impact in remediation plans", () => {
    const now = new Date().toISOString();
    const parsed = remediationSchema.parse({
      id: "rem-1",
      hostId: "host-1",
      title: "Patch web-1",
      actionType: "package_upgrade",
      updateScope: "all",
      riskLevel: "high",
      aiDecision: {
        updateScope: "all",
        riskLevel: "high",
        explanation: "Apply and validate the complete package set.",
        status: "plan_ready",
        supportingCitations: [],
        unresolvedConflicts: [],
        agentAssignments: []
      },
      rebootAssessment: {
        status: "required_after_patch",
        rationale: "A kernel update is selected.",
        evidence: [],
        estimatedDowntimeMinutes: 5,
        approvedIfRequired: false
      },
      rolloutPolicy: {
        strategy: "one_at_a_time",
        batchSize: 1,
        canaryCount: 1,
        rationale: "High availability host."
      },
      failurePolicy: {
        stopRemainingHosts: true,
        notifyOperator: true,
        attemptPredefinedRecovery: true,
        recoveryActions: []
      },
      executionTiming: "immediate",
      approvalScope: "patch_and_reboot_if_required",
      approvalState: "pending",
      executionState: "not_started",
      planVersion: 1,
      planHash: "plan-hash",
      approvedBy: null,
      approvedAt: null,
      result: null,
      preChangeProtection: {
        supported: false,
        status: "deferred"
      },
      createdAt: now,
      updatedAt: now
    });

    expect(parsed.rebootAssessment.status).toBe("required_after_patch");
    expect(parsed.rolloutPolicy.batchSize).toBe(1);
  });
});
