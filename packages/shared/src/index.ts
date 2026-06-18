import { z } from "zod";

export const severitySchema = z.enum(["info", "low", "medium", "high", "critical"]);
export type Severity = z.infer<typeof severitySchema>;

export const userSchema = z.object({
  id: z.string(),
  username: z.string(),
  createdAt: z.string()
});
export type User = z.infer<typeof userSchema>;

export const maintenanceWindowSchema = z.object({
  timezone: z.string(),
  weekdays: z.array(z.number()),
  startTime: z.string(),
  durationMinutes: z.number()
});

export const patchPolicySchema = z.object({
  updateMode: z.enum(["orchestrator_decides", "all", "security"]).default("orchestrator_decides"),
  executionTiming: z.enum(["immediate", "maintenance_window"]).default("immediate"),
  maintenanceWindow: maintenanceWindowSchema.nullable().optional(),
  maxBatchSize: z.number().default(5),
  canaryCount: z.number().default(1),
  rebootPolicy: z.enum(["if_required", "never"]).default("if_required")
});

export const hostInputSchema = z.object({
  name: z.string(),
  address: z.string(),
  port: z.number(),
  username: z.string(),
  distroFamily: z.literal("debian"),
  environment: z.string(),
  tags: z.array(z.string()),
  criticality: z.enum(["low", "normal", "high"]),
  availabilityClass: z.enum(["standard", "high_availability"]),
  credentialId: z.string().nullable().optional(),
  sshHostKeyFingerprint: z.string().nullable().optional(),
  patchPolicy: patchPolicySchema
});
export type HostInput = z.infer<typeof hostInputSchema>;

export const hostSchema = hostInputSchema.extend({
  id: z.string(),
  connectionStatus: z.string(),
  createdAt: z.string(),
  updatedAt: z.string()
});
export type Host = z.infer<typeof hostSchema>;

export const credentialSchema = z.object({
  id: z.string(),
  name: z.string(),
  fingerprint: z.string(),
  createdAt: z.string(),
  lastUsedAt: z.string().nullable().optional()
});
export type SshCredential = z.infer<typeof credentialSchema>;

export const scheduleSchema = z.object({
  id: z.string(),
  hostId: z.string(),
  enabled: z.boolean(),
  timezone: z.string(),
  cronExpression: z.string(),
  overlapPolicy: z.literal("skip_if_running"),
  previousRunAt: z.string().nullable(),
  nextRunAt: z.string().nullable(),
  createdAt: z.string(),
  updatedAt: z.string()
});
export type HostSchedule = z.infer<typeof scheduleSchema>;

export const evidenceSchema = z.object({
  source: z.string(),
  excerpt: z.string(),
  citation: z.string()
});

export const agentIdentitySchema = z.object({
  name: z.enum(["orchestrator", "log_analyst", "linux_state_analyst"]),
  responsibility: z.string(),
  modelTier: z.enum(["capable", "economy", "deterministic"]),
  provider: z.string(),
  model: z.string(),
  selectionReason: z.string(),
  contractVersion: z.number(),
  contractHash: z.string()
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
  recommendedAction: z.object({
    actionType: z.string(),
    title: z.string(),
    rationale: z.string()
  }).nullable().optional(),
  requiresApproval: z.boolean(),
  confidence: z.number(),
  status: z.string(),
  verifierStatus: z.string(),
  verifierReason: z.string().nullable().optional(),
  createdAt: z.string()
});
export type Finding = z.infer<typeof findingSchema>;

export const agentRunSchema = z.object({
  id: z.string(),
  scanId: z.string(),
  agent: agentIdentitySchema,
  status: z.string(),
  inputHash: z.string(),
  output: z.record(z.string(), z.unknown()),
  promptTokens: z.number(),
  completionTokens: z.number(),
  latencyMs: z.number(),
  cacheHit: z.boolean(),
  fallbackReason: z.string().nullable(),
  externallyProcessed: z.boolean(),
  createdAt: z.string()
});
export type AgentRun = z.infer<typeof agentRunSchema>;

export const agentMessageSchema = z.object({
  id: z.string(),
  scanId: z.string(),
  fromAgent: z.enum(["orchestrator", "log_analyst", "linux_state_analyst"]),
  toAgent: z.enum(["orchestrator", "log_analyst", "linux_state_analyst"]),
  round: z.number(),
  response: z.string(),
  claimIds: z.array(z.string()),
  reasoning: z.string(),
  citations: z.array(z.string()),
  createdAt: z.string()
});
export type AgentMessage = z.infer<typeof agentMessageSchema>;

export const remediationSchema = z.object({
  id: z.string(),
  hostId: z.string(),
  scanId: z.string().nullable().optional(),
  title: z.string(),
  actionType: z.string(),
  updateScope: z.string(),
  riskLevel: severitySchema,
  aiDecision: z.object({
    updateScope: z.string(),
    riskLevel: severitySchema,
    explanation: z.string(),
    status: z.string(),
    supportingCitations: z.array(z.string()),
    unresolvedConflicts: z.array(z.string()),
    agentAssignments: z.array(agentIdentitySchema)
  }),
  rebootAssessment: z.object({
    status: z.string(),
    rationale: z.string(),
    evidence: z.array(evidenceSchema),
    estimatedDowntimeMinutes: z.number(),
    approvedIfRequired: z.boolean()
  }),
  rolloutPolicy: z.object({
    strategy: z.string(),
    batchSize: z.number(),
    canaryCount: z.number(),
    rationale: z.string()
  }),
  executionTiming: z.string(),
  approvalState: z.string(),
  executionState: z.string(),
  planVersion: z.number(),
  planHash: z.string(),
  approvedBy: z.string().nullable(),
  approvedAt: z.string().nullable(),
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
    }))
  }).nullable(),
  createdAt: z.string(),
  updatedAt: z.string()
});
export type Remediation = z.infer<typeof remediationSchema>;

export const jobSchema = z.object({
  id: z.string(),
  jobType: z.string(),
  status: z.string(),
  hostId: z.string().nullable(),
  scanId: z.string().nullable(),
  remediationId: z.string().nullable(),
  campaignId: z.string().nullable(),
  approvedPlanVersion: z.number().nullable(),
  approvedPlanHash: z.string().nullable(),
  approvalScope: z.string().nullable(),
  idempotencyKey: z.string(),
  progressPercent: z.number(),
  currentPhase: z.string().nullable(),
  attempts: z.number(),
  maxAttempts: z.number(),
  error: z.string().nullable(),
  result: z.record(z.string(), z.unknown()),
  createdAt: z.string(),
  startedAt: z.string().nullable(),
  completedAt: z.string().nullable(),
  updatedAt: z.string()
});
export type DurableJob = z.infer<typeof jobSchema>;

export const campaignSchema = z.object({
  id: z.string(),
  name: z.string(),
  hostIds: z.array(z.string()),
  remediationIds: z.array(z.string()),
  status: z.string(),
  batchSize: z.number(),
  currentBatch: z.number(),
  totalBatches: z.number(),
  approvalScope: z.string(),
  failureSummary: z.string().nullable(),
  createdAt: z.string(),
  updatedAt: z.string()
});
export type PatchCampaign = z.infer<typeof campaignSchema>;

export const scanSchema = z.object({
  id: z.string(),
  hostId: z.string(),
  durableJobId: z.string().nullable(),
  snapshotId: z.string().nullable(),
  trigger: z.string(),
  status: z.string(),
  findingIds: z.array(z.string()),
  remediationIds: z.array(z.string()),
  agentRunIds: z.array(z.string()),
  error: z.string().nullable(),
  createdAt: z.string(),
  updatedAt: z.string()
});
export type ScanJob = z.infer<typeof scanSchema>;

export const logEventSchema = z.object({
  id: z.string(),
  schemaVersion: z.string(),
  timestamp: z.string(),
  durationMs: z.number(),
  hostId: z.string().nullable(),
  jobId: z.string().nullable(),
  scanId: z.string().nullable(),
  remediationId: z.string().nullable(),
  agentRunId: z.string().nullable(),
  playbookId: z.string().nullable(),
  phaseId: z.string().nullable(),
  taskId: z.string().nullable(),
  eventType: z.string(),
  evidenceCategory: z.string(),
  severity: severitySchema,
  status: z.string(),
  changed: z.boolean(),
  returnCode: z.number().nullable(),
  retryCount: z.number(),
  failureClassification: z.string().nullable(),
  commandDescription: z.string().nullable(),
  beforeValue: z.unknown().nullable(),
  afterValue: z.unknown().nullable(),
  stdout: z.string(),
  stderr: z.string(),
  rawOutput: z.string(),
  source: z.string(),
  truncated: z.boolean(),
  originalBytes: z.number(),
  redacted: z.boolean(),
  simulated: z.boolean(),
  externallyProcessed: z.boolean(),
  rebootRelevance: z.string(),
  remediationRelevance: z.string(),
  correlationIds: z.record(z.string(), z.string())
});
export type StructuredLogEvent = z.infer<typeof logEventSchema>;

export type LogPage = {
  items: StructuredLogEvent[];
  total: number;
  page: number;
  pageSize: number;
};

export const alertSchema = z.object({
  id: z.string(),
  severity: severitySchema,
  title: z.string(),
  message: z.string(),
  hostId: z.string().nullable(),
  jobId: z.string().nullable(),
  acknowledged: z.boolean(),
  acknowledgedAt: z.string().nullable(),
  createdAt: z.string()
});
export type Alert = z.infer<typeof alertSchema>;

export const auditSchema = z.object({
  id: z.string(),
  actor: z.string(),
  action: z.string(),
  targetType: z.string(),
  targetId: z.string().nullable(),
  details: z.record(z.string(), z.unknown()),
  createdAt: z.string()
});
export type AuditEvent = z.infer<typeof auditSchema>;

export type ConnectionTestResult = {
  success: boolean;
  sshReachable: boolean;
  sudoAvailable: boolean;
  osSupported: boolean;
  ansibleCompatible: boolean;
  hostKeyFingerprint?: string | null;
  checks: Record<string, string>;
};
