import { McpServer } from "@modelcontextprotocol/server";
import * as z from "zod/v4";
import { collectCorrelationEvidence } from "./correlation.js";
import {
  callPrivateIntelligence,
  intelligenceStatus
} from "./intelligence-client.js";

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

const correlationInput = z.object({
  windowHours: z.number().int().min(1).max(720).optional(),
  limit: z.number().int().min(10).max(300).optional()
});

const signalSchema = z.object({
  id: z.string(),
  kind: z.string(),
  subjects: z.array(z.string()),
  evidenceCount: z.number(),
  firstSeen: z.string().nullable(),
  lastSeen: z.string().nullable(),
  relations: z.array(z.string()),
  summary: z.string()
});

const correlationOutput = z.object({
  engineVersion: z.string(),
  correlationType: z.string(),
  generatedAt: z.string(),
  signalCount: z.number(),
  signals: z.array(signalSchema),
  limitations: z.array(z.string())
});

const timelineEntrySchema = z.object({
  timestamp: z.string().nullable(),
  category: z.string(),
  source: z.string(),
  actor: z.string().nullable(),
  target: z.string().nullable(),
  detail: z.string()
});

const timelineOutput = z.object({
  engineVersion: z.string(),
  generatedAt: z.string(),
  entryCount: z.number(),
  entries: z.array(timelineEntrySchema),
  limitations: z.array(z.string())
});

async function runCorrelation(
  route: string,
  windowHours: number | undefined,
  limit: number | undefined
) {
  const bundle = await collectCorrelationEvidence(windowHours, limit);
  return callPrivateIntelligence(route, bundle);
}

export function registerCorrelationTools(server: McpServer) {
  server.registerTool(
    "intelligence_status",
    {
      title: "Private Intelligence Core Status",
      description:
        "Check whether the optional private OpsChugex LocalOps Intelligence Core is configured and reachable on the loopback-only interface. The bearer token is never returned.",
      annotations: readOnlyAnnotations,
      inputSchema: z.object({}),
      outputSchema: z.object({
        configured: z.boolean(),
        reachable: z.boolean(),
        url: z.string(),
        version: z.string().nullable(),
        limitation: z.string().nullable()
      })
    },
    async () => toolResult(await intelligenceStatus())
  );

  server.registerTool(
    "correlate_process_activity",
    {
      title: "Correlate Process Activity",
      description:
        "Collect bounded process, event and network evidence, then ask the private LocalOps Intelligence Core to correlate relationships. The public MCP does not contain the proprietary correlation rules.",
      annotations: readOnlyAnnotations,
      inputSchema: correlationInput,
      outputSchema: correlationOutput
    },
    async ({ windowHours, limit }) =>
      toolResult(
        await runCorrelation(
          "/v1/correlate/process",
          windowHours,
          limit
        )
      )
  );

  server.registerTool(
    "correlate_service_activity",
    {
      title: "Correlate Service Activity",
      description:
        "Collect bounded service, process, event and network evidence and correlate it through the private intelligence core without producing a root-cause verdict.",
      annotations: readOnlyAnnotations,
      inputSchema: correlationInput,
      outputSchema: correlationOutput
    },
    async ({ windowHours, limit }) =>
      toolResult(
        await runCorrelation(
          "/v1/correlate/service",
          windowHours,
          limit
        )
      )
  );

  server.registerTool(
    "correlate_identity_activity",
    {
      title: "Correlate Identity Activity",
      description:
        "Collect bounded local user, administrator and authentication/change evidence and correlate identity relationships through the private intelligence core.",
      annotations: readOnlyAnnotations,
      inputSchema: correlationInput,
      outputSchema: correlationOutput
    },
    async ({ windowHours, limit }) =>
      toolResult(
        await runCorrelation(
          "/v1/correlate/identity",
          windowHours,
          limit
        )
      )
  );

  server.registerTool(
    "correlate_network_activity",
    {
      title: "Correlate Network Activity",
      description:
        "Collect bounded local socket, process and event evidence and correlate process-to-remote-endpoint relationships through the private intelligence core. No packet capture or remote scan is performed.",
      annotations: readOnlyAnnotations,
      inputSchema: correlationInput,
      outputSchema: correlationOutput
    },
    async ({ windowHours, limit }) =>
      toolResult(
        await runCorrelation(
          "/v1/correlate/network",
          windowHours,
          limit
        )
      )
  );

  server.registerTool(
    "correlate_persistence_signals",
    {
      title: "Correlate Persistence Signals",
      description:
        "Collect bounded startup, scheduled-task, service, process and event evidence and correlate persistence-related relationships in the private core. Correlation does not mean malicious persistence.",
      annotations: readOnlyAnnotations,
      inputSchema: correlationInput,
      outputSchema: correlationOutput
    },
    async ({ windowHours, limit }) =>
      toolResult(
        await runCorrelation(
          "/v1/correlate/persistence",
          windowHours,
          limit
        )
      )
  );

  server.registerTool(
    "build_incident_timeline",
    {
      title: "Build Incident Timeline",
      description:
        "Collect bounded event evidence and ask the private core to construct a chronological evidence timeline. Missing audit sources remain explicit limitations and no root-cause conclusion is produced.",
      annotations: readOnlyAnnotations,
      inputSchema: correlationInput,
      outputSchema: timelineOutput
    },
    async ({ windowHours, limit }) =>
      toolResult(
        await runCorrelation("/v1/timeline", windowHours, limit)
      )
  );
}
