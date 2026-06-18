import { z } from "zod";

export const severitySchema = z.enum(["info", "low", "medium", "high", "critical"]);
export type Severity = z.infer<typeof severitySchema>;

export const approvalStateSchema = z.enum(["pending", "approved", "rejected", "deferred", "manual_review"]);
export type ApprovalState = z.infer<typeof approvalStateSchema>;

export const executionStateSchema = z.enum(["not_started", "queued", "running", "succeeded", "failed", "blocked"]);
export type ExecutionState = z.infer<typeof executionStateSchema>;

export const findingStatusSchema = z.enum(["open", "acknowledged", "resolved", "blocked"]);
export type FindingStatus = z.infer<typeof findingStatusSchema>;

export const hostSchema = z.object({
  id: z.string(),
  name: z.string(),
  address: z.string(),
  port: z.number().int().positive().default(22),
  username: z.string(),
  distroFamily: z.enum(["debian"]),
  environment: z.string().default("default"),
  tags: z.array(z.string()).default([]),
  auth: z.object({
    privateKeyPath: z.string().optional(),
    passwordRef: z.string().optional()
  }).optional(),
  createdAt: z.string(),
  updatedAt: z.string()
});
export type Host = z.infer<typeof hostSchema>;

export const hostInputSchema = hostSchema.omit({ id: true, createdAt: true, updatedAt: true });
export type HostInput = z.infer<typeof hostInputSchema>;

export const evidenceSchema = z.object({
  source: z.string(),
  excerpt: z.string(),
  citation: z.string()
});
export type Evidence = z.infer<typeof evidenceSchema>;

export const recommendedActionSchema = z.object({
  actionType: z.enum(["refresh_package_metadata", "security_upgrade", "manual_review"]),
  title: z.string(),
  playbook: z.string().optional(),
  rationale: z.string()
});
export type RecommendedAction = z.infer<typeof recommendedActionSchema>;

export const findingSchema = z.object({
  id: z.string(),
  hostId: z.string(),
  sourceAgent: z.enum(["orchestrator", "log_agent", "linux_state_agent"]),
  category: z.string(),
  severity: severitySchema,
  summary: z.string(),
  evidence: z.array(evidenceSchema),
  recommendedAction: recommendedActionSchema.nullable(),
  requiresApproval: z.boolean(),
  confidence: z.number().min(0).max(1),
  status: findingStatusSchema,
  createdAt: z.string()
});
export type Finding = z.infer<typeof findingSchema>;

export const remediationInputSchema = z.object({
  hostId: z.string(),
  actionType: z.enum(["refresh_package_metadata", "security_upgrade"]),
  playbook: z.string(),
  inputs: z.record(z.string(), z.string()),
  riskLevel: severitySchema
});
export type RemediationInput = z.infer<typeof remediationInputSchema>;

export const remediationSchema = remediationInputSchema.extend({
  id: z.string(),
  approvalState: approvalStateSchema,
  executionState: executionStateSchema,
  result: z.object({
    summary: z.string(),
    output: z.string(),
    changed: z.boolean().default(false)
  }).nullable(),
  preChangeProtection: z.object({
    supported: z.boolean(),
    status: z.enum(["not_configured", "deferred", "ready"]).default("deferred")
  }),
  createdAt: z.string(),
  updatedAt: z.string()
});
export type Remediation = z.infer<typeof remediationSchema>;

export const hostSnapshotSchema = z.object({
  hostId: z.string(),
  collectedAt: z.string(),
  commands: z.record(z.string(), z.string()),
  packageSummary: z.object({
    pendingSecurityUpdates: z.number().int().nonnegative(),
    pendingPackageUpdates: z.number().int().nonnegative(),
    rebootRequired: z.boolean()
  }),
  serviceSummary: z.object({
    failedUnits: z.array(z.string())
  }),
  systemSummary: z.object({
    uptimeHours: z.number().nonnegative(),
    loadAverage: z.array(z.number()).length(3),
    diskUsagePercent: z.number().min(0).max(100),
    memoryUsagePercent: z.number().min(0).max(100),
    kernelVersion: z.string()
  }),
  logs: z.object({
    journal: z.string(),
    auth: z.string(),
    aptHistory: z.string()
  })
});
export type HostSnapshot = z.infer<typeof hostSnapshotSchema>;

export const scanStatusSchema = z.enum(["queued", "running", "completed", "failed"]);
export type ScanStatus = z.infer<typeof scanStatusSchema>;

export const scanJobSchema = z.object({
  id: z.string(),
  hostId: z.string(),
  status: scanStatusSchema,
  findingIds: z.array(z.string()),
  remediationIds: z.array(z.string()),
  error: z.string().nullable(),
  createdAt: z.string(),
  updatedAt: z.string()
});
export type ScanJob = z.infer<typeof scanJobSchema>;

export const scanRequestSchema = z.object({
  hostId: z.string()
});
export type ScanRequest = z.infer<typeof scanRequestSchema>;

export const executionResultSchema = z.object({
  remediationId: z.string(),
  summary: z.string(),
  output: z.string(),
  changed: z.boolean(),
  success: z.boolean()
});
export type ExecutionResult = z.infer<typeof executionResultSchema>;
