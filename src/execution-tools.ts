import { McpServer } from "@modelcontextprotocol/server";
import * as z from "zod/v4";
import {
  executeApprovedAction,
  executionStatus,
  proposeExecution,
  recentExecutionAudit
} from "./execution.js";

function toolResult(payload: Record<string, unknown>) {
  return {
    content: [{ type: "text" as const, text: JSON.stringify(payload, null, 2) }],
    structuredContent: payload
  };
}

const readOnlyAnnotations = {
  readOnlyHint: true,
  destructiveHint: false,
  idempotentHint: true,
  openWorldHint: false
} as const;

const proposalAnnotations = {
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

export function registerControlledExecutionTools(server: McpServer) {
  server.registerTool(
    "execution_status",
    {
      title: "Controlled Execution Status",
      description:
        "Show whether host mutation is enabled, the process-bound v1.0 role/operator identity, durable-audit state, service allowlist, approval TTL and execution risk boundary.",
      annotations: readOnlyAnnotations,
      inputSchema: z.object({}),
      outputSchema: z.object({
        enabled: z.boolean(),
        operatorId: z.string(),
        role: z.enum(["viewer", "operator", "maintainer", "admin"]),
        durableAuditEnabled: z.boolean(),
        approvalTtlSeconds: z.number(),
        allowedServices: z.array(z.string()),
        supportedActions: z.array(
          z.enum([
            "start_service",
            "restart_service",
            "refresh_dns",
            "clean_temp_files"
          ])
        ),
        defaultPolicy: z.string(),
        riskModel: z.object({
          R0: z.string(),
          R1: z.string(),
          R2: z.string(),
          R3Plus: z.string()
        })
      })
    },
    async () => toolResult(executionStatus())
  );

  server.registerTool(
    "propose_execution",
    {
      title: "Propose Controlled Execution",
      description:
        "Run preflight checks and create a five-minute one-time approval token for one bounded R2 action. v1.0 RBAC requires operator, maintainer or admin. This tool does not execute the action.",
      annotations: proposalAnnotations,
      inputSchema: z.object({
        action: z.enum([
          "start_service",
          "restart_service",
          "refresh_dns",
          "clean_temp_files"
        ]),
        serviceName: z.string().min(1).max(128).optional(),
        olderThanHours: z.number().int().min(24).max(2160).optional(),
        maxFiles: z.number().int().min(1).max(200).optional()
      }),
      outputSchema: z.object({
        proposalId: z.string(),
        approvalToken: z.string(),
        action: z.enum([
          "start_service",
          "restart_service",
          "refresh_dns",
          "clean_temp_files"
        ]),
        target: z.string().nullable(),
        riskTier: z.literal("R2"),
        preflight: z.record(z.string(), z.unknown()),
        parameters: z.record(z.string(), z.unknown()),
        expiresAt: z.string(),
        confirmationRequired: z.literal("APPROVE"),
        rollback: z.string(),
        warning: z.string()
      })
    },
    async ({ action, serviceName, olderThanHours, maxFiles }) =>
      toolResult(
        await proposeExecution({
          action,
          serviceName,
          olderThanHours,
          maxFiles
        })
      )
  );

  server.registerTool(
    "execute_approved_action",
    {
      title: "Execute Approved Action",
      description:
        "Consume one valid approval token and execute exactly the bound R2 action. v1.0 RBAC requires maintainer or admin, confirmation='APPROVE', and the existing enablement/allowlist checks.",
      annotations: executionAnnotations,
      inputSchema: z.object({
        approvalToken: z.string().min(32).max(128),
        confirmation: z.literal("APPROVE")
      }),
      outputSchema: z.object({
        action: z.enum([
          "start_service",
          "restart_service",
          "refresh_dns",
          "clean_temp_files"
        ]),
        target: z.string().nullable(),
        approved: z.boolean(),
        executed: z.boolean(),
        verified: z.boolean(),
        result: z.unknown(),
        rollback: z.string(),
        auditId: z.string(),
        durableAudit: z.object({
          enabled: z.boolean(),
          persisted: z.boolean(),
          limitation: z.string().nullable()
        })
      })
    },
    async ({ approvalToken, confirmation }) =>
      toolResult(
        await executeApprovedAction({
          approvalToken,
          confirmation
        })
      )
  );

  server.registerTool(
    "execution_audit_log",
    {
      title: "Controlled Execution Audit Log",
      description:
        "Return recent in-memory execution audit records with v1.0 operator/role metadata. Approval tokens are never included; durable metadata-only audit is available separately when enabled.",
      annotations: readOnlyAnnotations,
      inputSchema: z.object({
        limit: z.number().int().min(1).max(200).optional()
      }),
      outputSchema: z.object({
        records: z.array(
          z.object({
            id: z.string(),
            timestamp: z.string(),
            operatorId: z.string(),
            role: z.enum(["viewer", "operator", "maintainer", "admin"]),
            action: z.enum([
              "start_service",
              "restart_service",
              "refresh_dns",
              "clean_temp_files"
            ]),
            target: z.string().nullable(),
            riskTier: z.literal("R2"),
            approved: z.boolean(),
            executed: z.boolean(),
            verified: z.boolean(),
            result: z.string(),
            rollback: z.string()
          })
        ),
        persistence: z.string()
      })
    },
    async ({ limit }) => toolResult(recentExecutionAudit(limit))
  );
}
