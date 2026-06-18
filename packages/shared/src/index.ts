import { z } from "zod";

export const severitySchema = z.enum(["info", "low", "medium", "high", "critical"]);
export type Severity = z.infer<typeof severitySchema>;

export const maintenanceWindowSchema = z.object({
  timezone: z.string(),
  weekdays: z.array(z.number().int().min(0).max(6)),
  startTime: z.string(),
  durationMinutes: z.number().int().positive()
});
export type MaintenanceWindow = z.infer<typeof maintenanceWindowSchema>;

export const patchPolicySchema = z.object({
  updateMode: z.enum(["orchestrator_decides", "all", "security"]).default("orchestrator_decides"),
  executionTiming: z.enum(["immediate", "maintenance_window"]).default("immediate"),
  maintenanceWindow: maintenanceWindowSchema.nullable().optional(),
  maxBatchSize: z.number().int().positive().default(5),
  canaryCount: z.number().int().positive().default(1),
  rebootPolicy: z.enum(["if_required", "never"]).default("if_required")
});
export type PatchPolicy = z.infer<typeof patchPolicySchema>;

export const hostSchema = z.object({
  id: z.string(),
  name: z.string(),
  address: z.string(),
  port: z.number().int().positive(),
  username: z.string(),
  distroFamily: z.literal("debian"),
  environment: z.string(),
  tags: z.array(z.string()),
  criticality: z.enum(["low", "normal", "high"]),
  availabilityClass: z.enum(["standard", "high_availability"]),
  credentialId: z.string().nullable().optional(),
  patchPolicy: patchPolicySchema,
  createdAt: z.string(),
  updatedAt: z.string()
});
export type Host = z.infer<typeof hostSchema>;

export const hostInputSchema = hostSchema.omit({
  id: true,
  createdAt: true,
  updatedAt: true
});
export type HostInput = z.infer<typeof hostInputSchema>;

export const evidenceSchema = z.object({
  source: z.string(),
  excerpt: z.string(),
  citation: z.string()
});
export type Evidence = z.infer<typeof evidenceSchema>;

export const agentIdentitySchema = z.object({
  name: z.enum(["orchestrator", "log_analyst", "linux_state_analyst"]),
  responsibility: z.string(),
  modelTier: z.enum(["capable", "economy", "deterministic"]),
  provider: z.string(),
  model: z.string(),
  selectionReason: z.string()
});
export type AgentIdentity = z.infer<typeof agentIdentitySchema>;

export const recommendedActionSchema = z.object({
  actionType: z.string(),
  title: z.string(),
  rationale: z.string()
});

export const findingSchema = z.object({
  id: z.string(),
  hostId: z.string(),
  scanId: z.string().nullable().optional(),
  sourceAgent: z.enum(["orchestrator", "log_analyst", "linux_state_analyst"]),
  category: z.string(),
  severity: severitySchema,
  summary: z.string(),
  explanation: z.string(),
  evidence: z.array(evidenceSchema),
  recommendedAction: recommendedActionSchema.nullable().optional(),
  requiresApproval: z.boolean(),
  confidence: z.number(),
  status: z.string(),
  createdAt: z.string()
});
export type Finding = z.infer<typeof findingSchema>;

export const rebootAssessmentSchema = z.object({
  status: z.enum(["required", "likely", "required_after_patch", "not_expected", "unknown"]),
  rationale: z.string(),
  evidence: z.array(evidenceSchema),
  estimatedDowntimeMinutes: z.number(),
  approvedIfRequired: z.boolean()
});

export const rolloutPolicySchema = z.object({
  strategy: z.enum(["one_at_a_time", "canary_then_batches"]),
  batchSize: z.number().int().positive(),
  canaryCount: z.number().int().positive(),
  rationale: z.string()
});

export const remediationSchema = z.object({
  id: z.string(),
  hostId: z.string(),
  title: z.string(),
  actionType: z.literal("package_upgrade"),
  updateScope: z.enum(["all", "security"]),
  riskLevel: severitySchema,
  aiDecision: z.object({
    updateScope: z.enum(["all", "security", "none"]),
    riskLevel: severitySchema,
    explanation: z.string(),
    agentAssignments: z.array(agentIdentitySchema)
  }),
  rebootAssessment: rebootAssessmentSchema,
  rolloutPolicy: rolloutPolicySchema,
  failurePolicy: z.object({
    stopRemainingHosts: z.boolean(),
    notifyOperator: z.boolean(),
    attemptPredefinedRecovery: z.boolean(),
    recoveryActions: z.array(z.string())
  }),
  executionTiming: z.enum(["immediate", "maintenance_window"]),
  maintenanceWindow: maintenanceWindowSchema.nullable().optional(),
  approvalScope: z.literal("patch_and_reboot_if_required"),
  approvalState: z.enum(["pending", "approved", "rejected", "manual_review"]),
  executionState: z.enum([
    "not_started",
    "waiting_for_window",
    "running",
    "succeeded",
    "failed",
    "blocked"
  ]),
  result: z.object({
    success: z.boolean(),
    summary: z.string(),
    changed: z.boolean(),
    rebootPerformed: z.boolean(),
    phases: z.array(z.object({
      name: z.string(),
      state: z.string(),
      summary: z.string(),
      output: z.string(),
      changed: z.boolean()
    })),
    failureActionsTaken: z.array(z.string())
  }).nullable(),
  preChangeProtection: z.object({
    supported: z.boolean(),
    status: z.string()
  }),
  createdAt: z.string(),
  updatedAt: z.string()
});
export type Remediation = z.infer<typeof remediationSchema>;

export const scanJobSchema = z.object({
  id: z.string(),
  hostId: z.string(),
  status: z.string(),
  findingIds: z.array(z.string()),
  remediationIds: z.array(z.string()),
  agentReports: z.array(z.object({
    agent: agentIdentitySchema,
    overview: z.string(),
    findings: z.array(findingSchema)
  })),
  error: z.string().nullable(),
  createdAt: z.string(),
  updatedAt: z.string()
});
export type ScanJob = z.infer<typeof scanJobSchema>;

export const patchCampaignSchema = z.object({
  id: z.string(),
  name: z.string(),
  hostIds: z.array(z.string()),
  remediationIds: z.array(z.string()),
  status: z.string(),
  batchSize: z.number().int().positive(),
  currentBatch: z.number().int(),
  totalBatches: z.number().int().positive(),
  approvalScope: z.literal("patch_and_reboot_if_required"),
  failureSummary: z.string().nullable(),
  createdAt: z.string(),
  updatedAt: z.string()
});
export type PatchCampaign = z.infer<typeof patchCampaignSchema>;
