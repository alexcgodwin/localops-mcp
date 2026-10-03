import { McpServer } from "@modelcontextprotocol/server";
import * as z from "zod/v4";
import {
  createRemediationWorkflow,
  executeApprovedRemediationStep,
  prepareRemediationStep,
  recordRemediationStepDecision,
  remediationWorkflowDetails,
  remediationWorkflowStatus
} from "./remediation.js";

const readOnlyAnnotations = {
  readOnlyHint: true,
  destructiveHint: false,
  idempotentHint: true,
  openWorldHint: false
} as const;

const stateAnnotations = {
  readOnlyHint: false,
  destructiveHint: false,
  idempotentHint: false,
  openWorldHint: false
} as const;

const executionAnnotations = {
  readOnlyHint: false,
  destructiveHint: true,
  idempotentHint: false,
  openWorldHint: false
} as const;

function toolResult(payload: Record<string, unknown>) {
  return {
    content: [
      {
        type: "text" as const,
        text: JSON.stringify(payload, null, 2)
      }
    ],
    structuredContent: payload
  };
}

const roleSchema = z.enum([
  "viewer",
  "operator",
  "maintainer",
  "admin"
]);

const controlledActionSchema = z.enum([
  "start_service",
  "restart_service",
  "refresh_dns",
  "clean_temp_files"
]);

const stepStatusSchema = z.enum([
  "pending",
  "blocked",
  "approval-pending",
  "completed",
  "skipped",
  "verified",
  "failed"
]);

const workflowStatusSchema = z.enum([
  "active",
  "awaiting-approval",
  "blocked",
  "failed",
  "completed",
  "expired"
]);

const leadingHypothesisSchema = z.object({
  category: z.string(),
  hypothesis: z.string(),
  confidence: z.number().min(0).max(100),
  confidenceBand: z.enum(["low", "medium", "high"])
}).nullable();

const workflowStepSchema = z.object({
  stepId: z.string(),
  order: z.number(),
  phase: z.enum(["validate", "controlled", "manual"]),
  riskTier: z.enum(["R0", "R1", "R2", "R3+"]),
  action: z.string(),
  reason: z.string(),
  controlledAction: controlledActionSchema.nullable(),
  targetType: z.literal("service").nullable(),
  targetHint: z.string().nullable(),
  targetSelectionRequired: z.boolean(),
  proposalAllowed: z.boolean(),
  executionAllowed: z.boolean(),
  requiresExplicitApproval: z.boolean(),
  automaticExecutionAllowed: z.literal(false),
  gateReasons: z.array(z.string()),
  status: stepStatusSchema,
  resolvedTarget: z.string().nullable(),
  proposalId: z.string().nullable(),
  approvalExpiresAt: z.string().nullable(),
  auditId: z.string().nullable(),
  lastError: z.string().nullable()
});

const workflowEventSchema = z.object({
  timestamp: z.string(),
  type: z.enum([
    "workflow-created",
    "step-completed",
    "step-skipped",
    "proposal-created",
    "execution-verified",
    "execution-failed",
    "execution-blocked"
  ]),
  stepId: z.string().nullable(),
  message: z.string()
});

const workflowSchema = z.object({
  workflowId: z.string(),
  createdAt: z.string(),
  expiresAt: z.string(),
  status: workflowStatusSchema,
  evidenceWindowHours: z.number(),
  evidenceLimit: z.number(),
  engineVersion: z.string(),
  leadingHypothesis: leadingHypothesisSchema,
  interpretation: z.string(),
  limitations: z.array(z.string()),
  steps: z.array(workflowStepSchema),
  events: z.array(workflowEventSchema)
});

const proposalSchema = z.object({
  proposalId: z.string(),
  approvalToken: z.string(),
  action: controlledActionSchema,
  target: z.string().nullable(),
  riskTier: z.literal("R2"),
  preflight: z.record(z.string(), z.unknown()),
  parameters: z.record(z.string(), z.unknown()),
  workflowId: z.string().nullable(),
  workflowStepId: z.string().nullable(),
  expiresAt: z.string(),
  confirmationRequired: z.literal("APPROVE"),
  rollback: z.string(),
  warning: z.string()
});

const executionResultSchema = z.object({
  action: controlledActionSchema,
  target: z.string().nullable(),
  approved: z.boolean(),
  executed: z.boolean(),
  verified: z.boolean(),
  result: z.unknown(),
  rollback: z.string(),
  workflowId: z.string().nullable(),
  workflowStepId: z.string().nullable(),
  auditId: z.string(),
  durableAudit: z.object({
    enabled: z.boolean(),
    persisted: z.boolean(),
    limitation: z.string().nullable()
  })
});

export function registerRemediationWorkflowTools(
  server: McpServer
) {
  server.registerTool(
    "remediation_workflow_status",
    {
      title: "Remediation Workflow Status",
      description:
        "Show the v1.4 remediation-workflow safety state, current process-bound role, durable-audit requirement, supported R2 actions and recent workflow metadata. No host change is performed.",
      annotations: readOnlyAnnotations,
      inputSchema: z.object({}),
      outputSchema: z.object({
        version: z.literal("1.4.0"),
        executionEnabled: z.boolean(),
        operatorId: z.string(),
        role: roleSchema,
        durableAuditEnabled: z.boolean(),
        workflowTtlSeconds: z.number(),
        approvalTtlSeconds: z.number(),
        supportedActions: z.array(controlledActionSchema),
        activeWorkflowCount: z.number(),
        retainedWorkflowCount: z.number(),
        recentWorkflows: z.array(z.object({
          workflowId: z.string(),
          createdAt: z.string(),
          expiresAt: z.string(),
          status: workflowStatusSchema,
          stepCount: z.number()
        })),
        safetyBoundary: z.string()
      })
    },
    async () => toolResult(remediationWorkflowStatus())
  );

  server.registerTool(
    "create_remediation_workflow",
    {
      title: "Create Remediation Workflow",
      description:
        "Collect bounded current evidence and ask the private intelligence core for a v1.4 remediation plan. This creates workflow state only; it does not create an approval token or execute a host change.",
      annotations: stateAnnotations,
      inputSchema: z.object({
        windowHours: z.number().int().min(1).max(720).optional(),
        limit: z.number().int().min(10).max(300).optional()
      }),
      outputSchema: workflowSchema
    },
    async ({ windowHours, limit }) =>
      toolResult(
        await createRemediationWorkflow({
          windowHours,
          limit
        })
      )
  );

  server.registerTool(
    "remediation_workflow_details",
    {
      title: "Remediation Workflow Details",
      description:
        "Read one retained remediation workflow including evidence-based steps, gates, status and token-free workflow events.",
      annotations: readOnlyAnnotations,
      inputSchema: z.object({
        workflowId: z.string().min(1).max(128)
      }),
      outputSchema: workflowSchema
    },
    async ({ workflowId }) =>
      toolResult(remediationWorkflowDetails(workflowId))
  );

  server.registerTool(
    "record_remediation_step",
    {
      title: "Record Remediation Step",
      description:
        "Record completion of a validation/manual workflow step or explicitly skip an eligible non-validation step. This changes workflow state only and never performs the remediation action.",
      annotations: stateAnnotations,
      inputSchema: z.object({
        workflowId: z.string().min(1).max(128),
        stepId: z.string().min(1).max(128),
        decision: z.enum(["completed", "skipped"]),
        note: z.string().max(500).optional()
      }),
      outputSchema: workflowSchema
    },
    async ({ workflowId, stepId, decision, note }) =>
      toolResult(
        recordRemediationStepDecision({
          workflowId,
          stepId,
          decision,
          note
        })
      )
  );

  server.registerTool(
    "prepare_remediation_step",
    {
      title: "Prepare Remediation Step",
      description:
        "Prepare one fixed controlled R2 workflow step after earlier validation steps are resolved. Requires execution enablement, proposal-capable RBAC, durable audit and existing action allowlists. Returns a five-minute one-time approval token but does not execute the action.",
      annotations: stateAnnotations,
      inputSchema: z.object({
        workflowId: z.string().min(1).max(128),
        stepId: z.string().min(1).max(128),
        serviceName: z.string().min(1).max(128).optional()
      }),
      outputSchema: z.object({
        workflowId: z.string(),
        stepId: z.string(),
        workflowStatus: workflowStatusSchema,
        stepStatus: stepStatusSchema,
        proposal: proposalSchema
      })
    },
    async ({ workflowId, stepId, serviceName }) =>
      toolResult(
        await prepareRemediationStep({
          workflowId,
          stepId,
          serviceName
        })
      )
  );

  server.registerTool(
    "execute_approved_remediation_step",
    {
      title: "Execute Approved Remediation Step",
      description:
        "Execute exactly one prepared v1.4 R2 workflow step using its matching one-time approval token and exact APPROVE confirmation. The existing controlled-execution gateway rechecks RBAC, enablement and allowlists; v1.4 additionally requires durable audit. R3+ actions remain unavailable.",
      annotations: executionAnnotations,
      inputSchema: z.object({
        workflowId: z.string().min(1).max(128),
        stepId: z.string().min(1).max(128),
        approvalToken: z.string().min(32).max(128),
        confirmation: z.literal("APPROVE")
      }),
      outputSchema: z.object({
        workflowId: z.string(),
        stepId: z.string(),
        workflowStatus: workflowStatusSchema,
        stepStatus: stepStatusSchema,
        execution: executionResultSchema
      })
    },
    async ({
      workflowId,
      stepId,
      approvalToken,
      confirmation
    }) =>
      toolResult(
        await executeApprovedRemediationStep({
          workflowId,
          stepId,
          approvalToken,
          confirmation
        })
      )
  );
}
