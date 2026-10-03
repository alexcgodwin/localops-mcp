import { McpServer } from "@modelcontextprotocol/server";
import * as z from "zod/v4";
import { intelligenceStatus } from "./intelligence-client.js";
import {
  auditPersistenceEnabled,
  currentOperatorId,
  currentRole,
  durableAuditPath,
  evaluatePolicy,
  policyStatus,
  productionReadinessInput,
  readDurableAudit,
  type PolicyOperation,
  type RiskTier
} from "./platform.js";

const VERSION = "1.3.0";

const readOnlyAnnotations = {
  readOnlyHint: true,
  destructiveHint: false,
  idempotentHint: true,
  openWorldHint: false
} as const;

function toolResult(payload: Record<string, unknown>) {
  return {
    content: [{ type: "text" as const, text: JSON.stringify(payload, null, 2) }],
    structuredContent: payload
  };
}

const roleSchema = z.enum([
  "viewer",
  "operator",
  "maintainer",
  "admin"
]);

const operationSchema = z.enum([
  "inspect",
  "analyze",
  "propose_execution",
  "execute_r2"
]);

const riskSchema = z.enum(["R0", "R1", "R2", "R3+"]);

export function registerPlatformTools(server: McpServer) {
  server.registerTool(
    "platform_status",
    {
      title: "LocalOps Platform Status",
      description:
        "Show the v1.3 production control-plane state: process-bound RBAC identity, execution enablement, durable audit state, stdio transport and private intelligence reachability.",
      annotations: readOnlyAnnotations,
      inputSchema: z.object({}),
      outputSchema: z.object({
        version: z.literal("1.3.0"),
        transport: z.literal("stdio"),
        operatorId: z.string(),
        role: roleSchema,
        policyEnforcement: z.literal("enforced"),
        executionEnabled: z.boolean(),
        durableAuditEnabled: z.boolean(),
        durableAuditPath: z.string().nullable(),
        privateIntelligence: z.object({
          configured: z.boolean(),
          reachable: z.boolean(),
          url: z.string(),
          version: z.string().nullable(),
          limitation: z.string().nullable()
        }),
        boundary: z.string()
      })
    },
    async () => {
      const intelligence = await intelligenceStatus();
      return toolResult({
        version: VERSION,
        transport: "stdio",
        operatorId: currentOperatorId(),
        role: currentRole(),
        policyEnforcement: "enforced",
        executionEnabled:
          String(process.env.LOCALOPS_EXECUTION_ENABLED ?? "")
            .toLowerCase() === "true",
        durableAuditEnabled: auditPersistenceEnabled(),
        durableAuditPath: auditPersistenceEnabled()
          ? durableAuditPath()
          : null,
        privateIntelligence: intelligence,
        boundary:
          "The public MCP is local stdio. The private intelligence service remains authenticated and loopback-only. RBAC is bound to the LocalOps process configuration, not remote user login."
      });
    }
  );

  server.registerTool(
    "policy_status",
    {
      title: "LocalOps Policy Status",
      description:
        "Show the process-bound v1.0 RBAC role, permitted operation classes and R0-R3+ policy boundary.",
      annotations: readOnlyAnnotations,
      inputSchema: z.object({}),
      outputSchema: z.object({
        role: roleSchema,
        operatorId: z.string(),
        enforcement: z.literal("enforced"),
        permissions: z.array(operationSchema),
        roleMatrix: z.object({
          viewer: z.array(operationSchema),
          operator: z.array(operationSchema),
          maintainer: z.array(operationSchema),
          admin: z.array(operationSchema)
        }),
        riskBoundary: z.object({
          R0: z.string(),
          R1: z.string(),
          R2: z.string(),
          R3Plus: z.string()
        }),
        identityBoundary: z.string()
      })
    },
    async () => toolResult(policyStatus())
  );

  server.registerTool(
    "evaluate_policy",
    {
      title: "Evaluate LocalOps Policy",
      description:
        "Evaluate whether the configured process-bound role permits one operation/risk tier. This tool never executes an action.",
      annotations: readOnlyAnnotations,
      inputSchema: z.object({
        operation: operationSchema,
        riskTier: riskSchema
      }),
      outputSchema: z.object({
        allowed: z.boolean(),
        role: roleSchema,
        operatorId: z.string(),
        operation: operationSchema,
        riskTier: riskSchema,
        reason: z.string()
      })
    },
    async ({ operation, riskTier }) =>
      toolResult(
        evaluatePolicy(
          operation as PolicyOperation,
          riskTier as RiskTier
        )
      )
  );

  server.registerTool(
    "production_readiness",
    {
      title: "Production Readiness",
      description:
        "Run non-mutating v1.3 readiness checks for runtime version, RBAC, execution/audit coherence, data-directory safety, configured profile validity and private-core reachability.",
      annotations: readOnlyAnnotations,
      inputSchema: z.object({}),
      outputSchema: z.object({
        status: z.enum(["ready", "degraded", "blocked"]),
        passCount: z.number(),
        warnCount: z.number(),
        failCount: z.number(),
        checks: z.array(z.object({
          id: z.string(),
          status: z.enum(["pass", "warn", "fail"]),
          detail: z.string()
        }))
      })
    },
    async () => {
      const checks = productionReadinessInput();
      const core = await intelligenceStatus();

      checks.push({
        id: "private-intelligence-core",
        status: core.configured
          ? core.reachable
            ? "pass"
            : "fail"
          : "warn",
        detail: core.configured
          ? core.reachable
            ? "Private intelligence core is configured and reachable."
            : core.limitation ??
              "Private intelligence core is configured but unreachable."
          : "Private intelligence core is not configured; local collection remains available but private analysis features are degraded."
      });

      const passCount = checks.filter((item) => item.status === "pass").length;
      const warnCount = checks.filter((item) => item.status === "warn").length;
      const failCount = checks.filter((item) => item.status === "fail").length;
      const status =
        failCount > 0
          ? "blocked"
          : warnCount > 0
            ? "degraded"
            : "ready";

      return toolResult({
        status,
        passCount,
        warnCount,
        failCount,
        checks
      });
    }
  );

  server.registerTool(
    "production_audit_log",
    {
      title: "Production Execution Audit Log",
      description:
        "Read metadata-only durable v1.0 execution audit records when local JSONL audit persistence is enabled. Approval tokens and command output are not written to this durable log.",
      annotations: readOnlyAnnotations,
      inputSchema: z.object({
        limit: z.number().int().min(1).max(500).optional()
      }),
      outputSchema: z.object({
        enabled: z.boolean(),
        records: z.array(z.object({
          id: z.string(),
          timestamp: z.string(),
          operatorId: z.string(),
          role: roleSchema,
          action: z.string(),
          target: z.string().nullable(),
          riskTier: riskSchema,
          approved: z.boolean(),
          executed: z.boolean(),
          verified: z.boolean(),
          outcome: z.enum(["success", "failure"])
        })),
        path: z.string().nullable(),
        limitation: z.string().nullable()
      })
    },
    async ({ limit }) => toolResult(await readDurableAudit(limit))
  );
}
