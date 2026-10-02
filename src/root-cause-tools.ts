import { McpServer } from "@modelcontextprotocol/server";
import * as z from "zod/v4";
import { collectCorrelationEvidence } from "./correlation.js";
import { callPrivateIntelligence } from "./intelligence-client.js";

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

const analysisInput = z.object({
  windowHours: z.number().int().min(1).max(720).optional(),
  limit: z.number().int().min(10).max(300).optional()
});

const evidenceRefSchema = z.object({
  id: z.string(),
  kind: z.string(),
  subject: z.string(),
  timestamp: z.string().nullable(),
  summary: z.string()
});

const candidateSchema = z.object({
  id: z.string(),
  category: z.string(),
  hypothesis: z.string(),
  confidence: z.number().min(0).max(100),
  confidenceBand: z.enum(["low", "medium", "high"]),
  evidenceCount: z.number(),
  sourceDiversity: z.number(),
  supportingEvidence: z.array(evidenceRefSchema),
  contradictingEvidence: z.array(evidenceRefSchema),
  affectedSubjects: z.array(z.string()),
  rationale: z.string()
});

const rankingSchema = z.object({
  engineVersion: z.string(),
  generatedAt: z.string(),
  candidateCount: z.number(),
  candidates: z.array(candidateSchema),
  interpretation: z.string(),
  limitations: z.array(z.string())
});

const confidenceSchema = z.object({
  engineVersion: z.string(),
  generatedAt: z.string(),
  evidenceConfidence: z.number().min(0).max(100),
  confidenceBand: z.enum(["low", "medium", "high"]),
  sourceCoverage: z.object({
    process: z.boolean(),
    service: z.boolean(),
    network: z.boolean(),
    event: z.boolean(),
    identity: z.boolean(),
    persistence: z.boolean(),
    systemHealth: z.boolean()
  }),
  missingOrLimitedSources: z.array(z.string()),
  interpretation: z.string()
});

const evidenceChainSchema = z.object({
  engineVersion: z.string(),
  generatedAt: z.string(),
  chainCount: z.number(),
  chains: z.array(z.object({
    id: z.string(),
    subjects: z.array(z.string()),
    steps: z.array(evidenceRefSchema),
    summary: z.string()
  })),
  limitations: z.array(z.string())
});

const investigationSchema = z.object({
  engineVersion: z.string(),
  generatedAt: z.string(),
  steps: z.array(z.object({
    order: z.number(),
    priority: z.enum(["low", "medium", "high"]),
    action: z.string(),
    reason: z.string(),
    readOnly: z.boolean()
  })),
  interpretation: z.string(),
  limitations: z.array(z.string())
});

const changeTriggerSchema = z.object({
  engineVersion: z.string(),
  generatedAt: z.string(),
  trigger: evidenceRefSchema.nullable(),
  relatedEvidence: z.array(evidenceRefSchema),
  interpretation: z.string(),
  limitations: z.array(z.string())
});

const blastRadiusSchema = z.object({
  engineVersion: z.string(),
  generatedAt: z.string(),
  subjects: z.array(z.object({
    type: z.enum([
      "process",
      "service",
      "identity",
      "network",
      "persistence",
      "host"
    ]),
    value: z.string(),
    evidenceCount: z.number()
  })),
  interpretation: z.string(),
  limitations: z.array(z.string())
});

const remediationSchema = z.object({
  engineVersion: z.string(),
  generatedAt: z.string(),
  recommendations: z.array(z.object({
    order: z.number(),
    riskTier: z.enum(["R0", "R1", "R2", "R3"]),
    action: z.string(),
    reason: z.string(),
    automaticExecutionAllowed: z.boolean()
  })),
  interpretation: z.string(),
  limitations: z.array(z.string())
});

async function run(
  route: string,
  windowHours: number | undefined,
  limit: number | undefined
) {
  const bundle = await collectCorrelationEvidence(windowHours, limit);
  return callPrivateIntelligence(route, bundle);
}

export function registerRootCauseTools(server: McpServer) {
  server.registerTool(
    "rank_probable_causes",
    {
      title: "Rank Probable Causes",
      description:
        "Ask the private LocalOps Intelligence Core to rank evidence-backed operational hypotheses. Confidence describes evidence alignment, not compromise probability or certainty.",
      annotations: readOnlyAnnotations,
      inputSchema: analysisInput,
      outputSchema: rankingSchema
    },
    async ({ windowHours, limit }) =>
      toolResult(await run("/v1/root-cause/rank", windowHours, limit))
  );

  server.registerTool(
    "calculate_confidence",
    {
      title: "Calculate Evidence Confidence",
      description:
        "Measure collection coverage and source limitations for root-cause analysis. The score is evidence confidence, not a probability that a host is compromised.",
      annotations: readOnlyAnnotations,
      inputSchema: analysisInput,
      outputSchema: confidenceSchema
    },
    async ({ windowHours, limit }) =>
      toolResult(await run("/v1/root-cause/confidence", windowHours, limit))
  );

  server.registerTool(
    "build_evidence_chain",
    {
      title: "Build Root-Cause Evidence Chain",
      description:
        "Build ordered evidence chains for the leading private-core hypotheses while preserving missing-source limitations.",
      annotations: readOnlyAnnotations,
      inputSchema: analysisInput,
      outputSchema: evidenceChainSchema
    },
    async ({ windowHours, limit }) =>
      toolResult(await run("/v1/root-cause/evidence-chain", windowHours, limit))
  );

  server.registerTool(
    "suggest_investigation_path",
    {
      title: "Suggest Investigation Path",
      description:
        "Generate an evidence-first, read-only investigation sequence from the private core. The output prioritizes validation before mutation.",
      annotations: readOnlyAnnotations,
      inputSchema: analysisInput,
      outputSchema: investigationSchema
    },
    async ({ windowHours, limit }) =>
      toolResult(await run("/v1/root-cause/investigation", windowHours, limit))
  );

  server.registerTool(
    "identify_change_trigger",
    {
      title: "Identify Change Trigger",
      description:
        "Identify the earliest supported timestamped change event and nearby evidence. The result is a temporal starting point, not proof of causation.",
      annotations: readOnlyAnnotations,
      inputSchema: analysisInput,
      outputSchema: changeTriggerSchema
    },
    async ({ windowHours, limit }) =>
      toolResult(await run("/v1/root-cause/change-trigger", windowHours, limit))
  );

  server.registerTool(
    "identify_blast_radius",
    {
      title: "Identify Evidence Blast Radius",
      description:
        "Summarize local entities and observed network relationships connected to leading hypotheses. It does not claim remote systems are affected or compromised.",
      annotations: readOnlyAnnotations,
      inputSchema: analysisInput,
      outputSchema: blastRadiusSchema
    },
    async ({ windowHours, limit }) =>
      toolResult(await run("/v1/root-cause/blast-radius", windowHours, limit))
  );

  server.registerTool(
    "recommend_remediation",
    {
      title: "Recommend Remediation",
      description:
        "Return advisory remediation options with risk tiers. Recommendations never authorize or directly execute a change; existing approval gates still apply.",
      annotations: readOnlyAnnotations,
      inputSchema: analysisInput,
      outputSchema: remediationSchema
    },
    async ({ windowHours, limit }) =>
      toolResult(await run("/v1/root-cause/remediation", windowHours, limit))
  );
}
