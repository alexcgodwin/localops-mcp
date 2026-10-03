import type { McpServer } from "@modelcontextprotocol/server";
import * as z from "zod/v4";
import {
  incidentCaseDetails,
  incidentMemoryBundle
} from "./incident-memory.js";
import { callPrivateIntelligence } from "./intelligence-client.js";

const readOnlyAnnotations = {
  readOnlyHint: true,
  destructiveHint: false,
  idempotentHint: true,
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

const entityKindSchema = z.enum([
  "signal",
  "tag",
  "cause",
  "outcome",
  "resolution"
]);

const nodeKindSchema = z.enum([
  "case",
  "signal",
  "tag",
  "cause",
  "outcome",
  "resolution"
]);

const relationSchema = z.enum([
  "has-signal",
  "has-tag",
  "has-cause",
  "has-outcome",
  "has-resolution",
  "similar-case"
]);

const graphNodeSchema = z.object({
  id: z.string(),
  kind: nodeKindSchema,
  label: z.string(),
  caseId: z.string().nullable()
});

const graphEdgeSchema = z.object({
  id: z.string(),
  from: z.string(),
  to: z.string(),
  relation: relationSchema,
  weight: z.number().min(0).max(100).nullable()
});
const graphSchema = z.object({
  engineVersion: z.literal("2.0.0"),
  generatedAt: z.string(),
  caseCount: z.number(),
  similarityThreshold: z.number().min(1).max(100),
  nodeCount: z.number(),
  edgeCount: z.number(),
  nodeCounts: z.object({
    case: z.number(),
    signal: z.number(),
    tag: z.number(),
    cause: z.number(),
    outcome: z.number(),
    resolution: z.number()
  }),
  truncated: z.boolean(),
  nodes: z.array(graphNodeSchema),
  edges: z.array(graphEdgeSchema),
  interpretation: z.string(),
  limitations: z.array(z.string())
});

const traceSchema = z.object({
  engineVersion: z.literal("2.0.0"),
  generatedAt: z.string(),
  targetCaseId: z.string(),
  similarityThreshold: z.number().min(1).max(100),
  maxDepth: z.number().min(1).max(4),
  pathCount: z.number(),
  paths: z.array(z.object({
    relatedCaseId: z.string(),
    depth: z.number(),
    nodes: z.array(graphNodeSchema),
    relations: z.array(relationSchema),
    weights: z.array(z.number().min(0).max(100).nullable())
  })),
  graphTruncated: z.boolean(),
  interpretation: z.string(),
  limitations: z.array(z.string())
});

const entityCasesSchema = z.object({
  engineVersion: z.literal("2.0.0"),
  generatedAt: z.string(),
  kind: entityKindSchema,
  value: z.string(),
  searchedCaseCount: z.number(),
  matchCount: z.number(),
  matches: z.array(z.object({
    caseId: z.string(),
    recordedAt: z.string(),
    title: z.string().nullable(),
    severity: z.string(),
    scope: z.string(),
    outcomeStatus: z.string().nullable(),
    resolutionCategory: z.string().nullable(),
    verified: z.boolean().nullable()
  })),
  interpretation: z.string(),
  limitations: z.array(z.string())
});
const guidedInvestigationSchema = z.object({
  engineVersion: z.literal("2.0.0"),
  generatedAt: z.string(),
  targetCaseId: z.string(),
  similarityThreshold: z.number().min(1).max(100),
  relatedCaseCount: z.number(),
  relatedCases: z.array(z.object({
    caseId: z.string(),
    recordedAt: z.string(),
    title: z.string().nullable(),
    similarityPercent: z.number().min(0).max(100),
    sharedSignalIds: z.array(z.string()),
    sharedTags: z.array(z.string()),
    sharedCauseCategories: z.array(z.string())
  })),
  historicalOutcomes: z.array(z.object({
    caseId: z.string(),
    similarityPercent: z.number().min(0).max(100),
    status: z.enum([
      "resolved",
      "mitigated",
      "unresolved",
      "false-positive"
    ]),
    resolutionCategory: z.enum([
      "service-recovery",
      "resource-relief",
      "configuration-correction",
      "dependency-recovery",
      "security-response",
      "rollback",
      "other"
    ]),
    verified: z.boolean(),
    durationMinutes: z.number().nullable()
  })),
  steps: z.array(z.object({
    order: z.number(),
    title: z.string(),
    purpose: z.string(),
    evidence: z.array(z.string()),
    nonMutating: z.literal(true)
  })),
  interpretation: z.string(),
  limitations: z.array(z.string())
});

function selectedCaseIds(caseIds: string[] | undefined) {
  if (caseIds === undefined) return undefined;
  return [...new Set(caseIds)].slice(0, 200);
}

export function registerKnowledgeGraphTools(server: McpServer) {
  server.registerTool(
    "operational_knowledge_graph",
    {
      title: "Operational Knowledge Graph",
      description:
        "Build a bounded graph linking retained incident cases to normalized signals, tags, cause categories, outcomes, resolutions and threshold-qualified similar cases. Graph relationships are descriptive evidence, not causal proof.",
      annotations: readOnlyAnnotations,
      inputSchema: z.object({
        caseIds: z.array(z.string().min(1).max(84)).max(200).optional(),
        similarityThreshold: z.number().int().min(1).max(100).optional(),
        maxNodes: z.number().int().min(1).max(1200).optional(),
        maxEdges: z.number().int().min(1).max(4000).optional()
      }),
      outputSchema: graphSchema
    },
    async ({ caseIds, similarityThreshold, maxNodes, maxEdges }) =>
      toolResult(
        await callPrivateIntelligence("/v2/knowledge/graph", {
          ...await incidentMemoryBundle(selectedCaseIds(caseIds)),
          similarityThreshold: similarityThreshold ?? 60,
          maxNodes: maxNodes ?? 1000,
          maxEdges: maxEdges ?? 3000
        })
      )
  );
  server.registerTool(
    "incident_knowledge_trace",
    {
      title: "Incident Knowledge Trace",
      description:
        "Trace bounded graph paths from one retained incident to related historical cases through shared normalized evidence or similarity links. Paths support investigation and do not prove causation.",
      annotations: readOnlyAnnotations,
      inputSchema: z.object({
        caseId: z.string().min(1).max(84),
        similarityThreshold: z.number().int().min(1).max(100).optional(),
        maxDepth: z.number().int().min(1).max(4).optional(),
        maxPaths: z.number().int().min(1).max(20).optional()
      }),
      outputSchema: traceSchema
    },
    async ({ caseId, similarityThreshold, maxDepth, maxPaths }) => {
      await incidentCaseDetails(caseId);
      return toolResult(
        await callPrivateIntelligence("/v2/knowledge/trace", {
          ...await incidentMemoryBundle(),
          caseId,
          similarityThreshold: similarityThreshold ?? 60,
          maxDepth: maxDepth ?? 3,
          maxPaths: maxPaths ?? 10
        })
      );
    }
  );

  server.registerTool(
    "incident_entity_cases",
    {
      title: "Incident Entity Cases",
      description:
        "Find retained incident cases with an exact normalized relationship to one signal, tag, cause, outcome or resolution entity.",
      annotations: readOnlyAnnotations,
      inputSchema: z.object({
        kind: entityKindSchema,
        value: z.string().min(1).max(128),
        caseIds: z.array(z.string().min(1).max(84)).max(200).optional(),
        limit: z.number().int().min(1).max(50).optional()
      }),
      outputSchema: entityCasesSchema
    },
    async ({ kind, value, caseIds, limit }) =>
      toolResult(
        await callPrivateIntelligence("/v2/knowledge/entity-cases", {
          ...await incidentMemoryBundle(selectedCaseIds(caseIds)),
          kind,
          value,
          limit: limit ?? 20
        })
      )
  );

  server.registerTool(
    "guided_incident_investigation",
    {
      title: "Guided Incident Investigation",
      description:
        "Build an ordered read-only investigation plan from the current incident and related historical cases. The plan contains evidence-review steps only and never authorizes or executes remediation.",
      annotations: readOnlyAnnotations,
      inputSchema: z.object({
        caseId: z.string().min(1).max(84),
        similarityThreshold: z.number().int().min(1).max(100).optional(),
        maxRelatedCases: z.number().int().min(1).max(20).optional()
      }),
      outputSchema: guidedInvestigationSchema
    },
    async ({ caseId, similarityThreshold, maxRelatedCases }) => {
      await incidentCaseDetails(caseId);
      return toolResult(
        await callPrivateIntelligence("/v2/knowledge/investigation", {
          ...await incidentMemoryBundle(),
          caseId,
          similarityThreshold: similarityThreshold ?? 50,
          maxRelatedCases: maxRelatedCases ?? 10
        })
      );
    }
  );
}
