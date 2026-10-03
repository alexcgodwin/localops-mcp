import type { McpServer } from "@modelcontextprotocol/server";
import * as z from "zod/v4";
import { fleetBundle } from "./fleet.js";
import { callPrivateIntelligence } from "./intelligence-client.js";
import {
  incidentCaseDetails,
  incidentMemoryBundle,
  incidentMemoryStatus,
  listIncidentCases,
  recordIncidentCase,
  recordIncidentOutcome
} from "./incident-memory.js";

const readOnlyAnnotations = {
  readOnlyHint: true,
  destructiveHint: false,
  idempotentHint: true,
  openWorldHint: false
} as const;

const registryWriteAnnotations = {
  readOnlyHint: false,
  destructiveHint: false,
  idempotentHint: false,
  openWorldHint: false
} as const;

function toolResult(payload: Record<string, unknown>) {
  return {
    content: [{ type: "text" as const, text: JSON.stringify(payload, null, 2) }],
    structuredContent: payload
  };
}
const fingerprintSchema = z.object({
  engineVersion: z.literal("1.7.0"),
  generatedAt: z.string(),
  sourceGeneratedAt: z.string(),
  signature: z.string(),
  severity: z.enum(["none", "low", "medium", "high"]),
  scope: z.enum(["none", "localized", "multi-node", "fleet-wide"]),
  nodeCount: z.number(),
  affectedNodeIds: z.array(z.string()),
  signalIds: z.array(z.string()),
  signalCategories: z.array(z.string()),
  commonAffectedTags: z.array(z.string()),
  causeCategories: z.array(z.string()),
  fingerprintTokens: z.array(z.string()),
  interpretation: z.string(),
  limitations: z.array(z.string())
});

const outcomeStatusSchema = z.enum([
  "resolved",
  "mitigated",
  "unresolved",
  "false-positive"
]);

const resolutionCategorySchema = z.enum([
  "service-recovery",
  "resource-relief",
  "configuration-correction",
  "dependency-recovery",
  "security-response",
  "rollback",
  "other"
]);

const outcomeSchema = z.object({
  status: outcomeStatusSchema,
  resolutionCategory: resolutionCategorySchema,
  verified: z.boolean(),
  durationMinutes: z.number().int().min(0).max(43200).nullable(),
  recordedAt: z.string(),
  operatorId: z.string()
});

const caseSchema = z.object({
  caseId: z.string(),
  recordedAt: z.string(),
  title: z.string().nullable(),
  fingerprint: fingerprintSchema,
  outcome: outcomeSchema.nullable()
});

const caseSummarySchema = z.object({
  caseId: z.string(),
  recordedAt: z.string(),
  title: z.string().nullable(),
  signature: z.string(),
  severity: z.enum(["none", "low", "medium", "high"]),
  scope: z.enum(["none", "localized", "multi-node", "fleet-wide"]),
  nodeCount: z.number(),
  affectedNodeCount: z.number(),
  signalCount: z.number(),
  outcomeStatus: outcomeStatusSchema.nullable(),
  outcomeVerified: z.boolean().nullable()
});
const compareSchema = z.object({
  engineVersion: z.literal("1.7.0"),
  generatedAt: z.string(),
  leftCaseId: z.string(),
  rightCaseId: z.string(),
  similarityPercent: z.number().min(0).max(100),
  recurrenceBand: z.enum(["none", "weak", "possible", "strong"]),
  sharedSignalIds: z.array(z.string()),
  leftOnlySignalIds: z.array(z.string()),
  rightOnlySignalIds: z.array(z.string()),
  sharedAffectedNodeIds: z.array(z.string()),
  sharedTags: z.array(z.string()),
  sharedCauseCategories: z.array(z.string()),
  interpretation: z.string(),
  limitations: z.array(z.string())
});

const recurrenceSchema = z.object({
  engineVersion: z.literal("1.7.0"),
  generatedAt: z.string(),
  caseCount: z.number(),
  matchCount: z.number(),
  recurringCaseCount: z.number(),
  recurringCaseIds: z.array(z.string()),
  matches: z.array(z.object({
    leftCaseId: z.string(),
    rightCaseId: z.string(),
    similarityPercent: z.number().min(0).max(100),
    recurrenceBand: z.enum(["possible", "strong"]),
    sharedSignalIds: z.array(z.string()),
    sharedTags: z.array(z.string())
  })),
  interpretation: z.string(),
  limitations: z.array(z.string())
});
const countSchema = z.object({
  value: z.string(),
  count: z.number()
});

const resolutionPatternSchema = z.object({
  resolutionCategory: resolutionCategorySchema,
  caseCount: z.number(),
  verifiedCount: z.number(),
  resolvedCount: z.number(),
  mitigatedCount: z.number(),
  averageDurationMinutes: z.number().nullable(),
  commonSignalIds: z.array(z.string()),
  commonTags: z.array(z.string()),
  commonCauseCategories: z.array(z.string())
});

const resolutionPatternsSchema = z.object({
  engineVersion: z.literal("1.8.0"),
  generatedAt: z.string(),
  caseCount: z.number(),
  outcomeCaseCount: z.number(),
  resolvedOrMitigatedCaseCount: z.number(),
  patternCount: z.number(),
  patterns: z.array(resolutionPatternSchema),
  interpretation: z.string(),
  limitations: z.array(z.string())
});

const resolutionHistorySchema = z.object({
  engineVersion: z.literal("1.8.0"),
  generatedAt: z.string(),
  targetCaseId: z.string(),
  historicalMatchCount: z.number(),
  matches: z.array(z.object({
    caseId: z.string(),
    recordedAt: z.string(),
    similarityPercent: z.number().min(0).max(100),
    recurrenceBand: z.enum(["none", "weak", "possible", "strong"]),
    outcomeStatus: outcomeStatusSchema,
    resolutionCategory: resolutionCategorySchema,
    verified: z.boolean(),
    durationMinutes: z.number().nullable(),
    sharedSignalIds: z.array(z.string()),
    sharedTags: z.array(z.string()),
    sharedCauseCategories: z.array(z.string())
  })),
  observedResolutionCategories: z.array(z.object({
    resolutionCategory: resolutionCategorySchema,
    caseCount: z.number()
  })),
  interpretation: z.string(),
  limitations: z.array(z.string())
});

const historySchema = z.object({
  engineVersion: z.literal("1.7.0"),
  generatedAt: z.string(),
  caseCount: z.number(),
  recurringCaseCount: z.number(),
  severities: z.object({
    none: z.number(),
    low: z.number(),
    medium: z.number(),
    high: z.number()
  }),
  scopes: z.object({
    none: z.number(),
    localized: z.number(),
    multiNode: z.number(),
    fleetWide: z.number()
  }),
  firstRecordedAt: z.string().nullable(),
  lastRecordedAt: z.string().nullable(),
  repeatedSignals: z.array(countSchema),
  repeatedTags: z.array(countSchema),
  repeatedCauseCategories: z.array(countSchema),
  interpretation: z.string(),
  limitations: z.array(z.string())
});

function selectedCaseIds(caseIds: string[] | undefined): string[] | undefined {
  if (caseIds === undefined) return undefined;
  return [...new Set(caseIds)].slice(0, 200);
}
export function registerIncidentMemoryTools(server: McpServer) {
  server.registerTool(
    "capture_incident_case",
    {
      title: "Capture Incident Case",
      description:
        "Create and retain a bounded normalized incident fingerprint from the current registered fleet. The case stores metadata only, not raw event logs, credentials, packet data or approval tokens.",
      annotations: registryWriteAnnotations,
      inputSchema: z.object({
        title: z.string().max(200).optional()
      }),
      outputSchema: caseSchema
    },
    async ({ title }) => {
      const bundle = fleetBundle();
      if (bundle.nodes.length === 0) {
        throw new Error(
          "At least one registered node is required to capture an incident case."
        );
      }
      const fingerprint = await callPrivateIntelligence(
        "/v1/incidents/fingerprint",
        bundle
      );
      return toolResult(await recordIncidentCase(fingerprint, title));
    }
  );

  server.registerTool(
    "list_incident_cases",
    {
      title: "List Incident Cases",
      description:
        "List bounded metadata for incident fingerprints retained in the current LocalOps process.",
      annotations: readOnlyAnnotations,
      inputSchema: z.object({
        limit: z.number().int().min(1).max(200).optional()
      }),
      outputSchema: z.object({
        caseCount: z.number(),
        cases: z.array(caseSummarySchema),
        persistence: z.string()
      })
    },
    async ({ limit }) => toolResult(await listIncidentCases(limit))
  );

  server.registerTool(
    "incident_case_details",
    {
      title: "Incident Case Details",
      description:
        "Read one stored normalized incident fingerprint by case ID without returning raw historical logs.",
      annotations: readOnlyAnnotations,
      inputSchema: z.object({
        caseId: z.string().min(1).max(84)
      }),
      outputSchema: caseSchema
    },
    async ({ caseId }) => toolResult(await incidentCaseDetails(caseId))
  );

  server.registerTool(
    "compare_incident_cases",
    {
      title: "Compare Incident Cases",
      description:
        "Compare two stored incident fingerprints through the private intelligence core. Similarity is evidence overlap, not recurrence probability or proof of a shared cause.",
      annotations: readOnlyAnnotations,
      inputSchema: z.object({
        leftCaseId: z.string().min(1).max(84),
        rightCaseId: z.string().min(1).max(84)
      }),
      outputSchema: compareSchema
    },
    async ({ leftCaseId, rightCaseId }) => {
      if (leftCaseId === rightCaseId) {
        throw new Error("Choose two different incident cases.");
      }
      return toolResult(await callPrivateIntelligence(
        "/v1/incidents/compare",
        await incidentMemoryBundle([leftCaseId, rightCaseId])
      ));
    }
  );

  server.registerTool(
    "incident_recurrence_analysis",
    {
      title: "Incident Recurrence Analysis",
      description:
        "Search stored incident fingerprints for possible or strong evidence-overlap recurrence patterns. Results do not establish repeated root cause.",
      annotations: readOnlyAnnotations,
      inputSchema: z.object({
        caseIds: z.array(z.string().min(1).max(84)).max(200).optional()
      }),
      outputSchema: recurrenceSchema
    },
    async ({ caseIds }) =>
      toolResult(await callPrivateIntelligence(
        "/v1/incidents/recurrence",
        await incidentMemoryBundle(selectedCaseIds(caseIds))
      ))
  );

  server.registerTool(
    "incident_history_summary",
    {
      title: "Incident History Summary",
      description:
        "Summarize bounded incident-case severity, scope, recurrence and repeated evidence patterns without reconstructing raw historical telemetry.",
      annotations: readOnlyAnnotations,
      inputSchema: z.object({
        caseIds: z.array(z.string().min(1).max(84)).max(200).optional()
      }),
      outputSchema: historySchema
    },
    async ({ caseIds }) =>
      toolResult(await callPrivateIntelligence(
        "/v1/incidents/history-summary",
        await incidentMemoryBundle(selectedCaseIds(caseIds))
      ))
  );

  server.registerTool(
    "incident_memory_status",
    {
      title: "Incident Memory Status",
      description:
        "Show v1.8 incident-memory capacity, outcome counts and whether optional local durable persistence is enabled.",
      annotations: readOnlyAnnotations,
      inputSchema: z.object({}),
      outputSchema: z.object({
        version: z.literal("1.8.0"),
        persistenceEnabled: z.boolean(),
        persistencePath: z.string().nullable(),
        caseCount: z.number(),
        outcomeCount: z.number(),
        maxCases: z.number(),
        storage: z.string()
      })
    },
    async () => toolResult(await incidentMemoryStatus())
  );

  server.registerTool(
    "record_incident_outcome",
    {
      title: "Record Incident Outcome",
      description:
        "Record structured operator-confirmed outcome metadata for one incident case. This stores no commands, free-form remediation text, credentials or approval tokens.",
      annotations: registryWriteAnnotations,
      inputSchema: z.object({
        caseId: z.string().min(1).max(84),
        status: outcomeStatusSchema,
        resolutionCategory: resolutionCategorySchema,
        verified: z.boolean(),
        durationMinutes: z.number().int().min(0).max(43200).optional()
      }),
      outputSchema: caseSchema
    },
    async ({
      caseId,
      status,
      resolutionCategory,
      verified,
      durationMinutes
    }) => toolResult(await recordIncidentOutcome(caseId, {
      status,
      resolutionCategory,
      verified,
      durationMinutes
    }))
  );

  server.registerTool(
    "incident_resolution_patterns",
    {
      title: "Incident Resolution Patterns",
      description:
        "Summarize operator-confirmed historical resolution categories and their repeated evidence patterns through the private intelligence core. Results are historical context, not remediation instructions.",
      annotations: readOnlyAnnotations,
      inputSchema: z.object({
        caseIds: z.array(z.string().min(1).max(84)).max(200).optional()
      }),
      outputSchema: resolutionPatternsSchema
    },
    async ({ caseIds }) =>
      toolResult(await callPrivateIntelligence(
        "/v1/incidents/resolution-patterns",
        await incidentMemoryBundle(selectedCaseIds(caseIds))
      ))
  );

  server.registerTool(
    "incident_resolution_history",
    {
      title: "Incident Resolution History",
      description:
        "Find prior resolved or mitigated cases with overlapping normalized evidence and show their recorded outcomes. Historical outcomes are not recommendations or execution authorization.",
      annotations: readOnlyAnnotations,
      inputSchema: z.object({
        caseId: z.string().min(1).max(84),
        maxMatches: z.number().int().min(1).max(20).optional()
      }),
      outputSchema: resolutionHistorySchema
    },
    async ({ caseId, maxMatches }) => {
      await incidentCaseDetails(caseId);
      return toolResult(await callPrivateIntelligence(
        "/v1/incidents/resolution-history",
        {
          ...await incidentMemoryBundle(),
          targetCaseId: caseId,
          maxMatches: maxMatches ?? 10
        }
      ));
    }
  );
}
