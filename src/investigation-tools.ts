import type { McpServer } from "@modelcontextprotocol/server";
import * as z from "zod/v4";
import { callPrivateIntelligence } from "./intelligence-client.js";
import { incidentMemoryBundle } from "./incident-memory.js";
import {
  addInvestigationQuestion,
  createInvestigationSession,
  investigationSessionDetails,
  investigationSessionStatus,
  listInvestigationSessions,
  recordInvestigationCheckpoint,
  setInvestigationSessionStatus,
  updateInvestigationQuestion
} from "./investigation-session.js";

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
    content: [
      {
        type: "text" as const,
        text: JSON.stringify(payload, null, 2)
      }
    ],
    structuredContent: payload
  };
}

const sessionStatusSchema = z.enum(["open", "paused", "completed"]);

const checkpointKindSchema = z.enum([
  "evidence-reviewed",
  "scope-reviewed",
  "hypothesis-reviewed",
  "historical-case-reviewed",
  "question-reviewed"
]);

const questionCategorySchema = z.enum([
  "scope",
  "signal",
  "cause",
  "historical",
  "verification",
  "other"
]);

const questionStatusSchema = z.enum([
  "open",
  "resolved",
  "deferred"
]);
const checkpointSchema = z.object({
  checkpointId: z.string(),
  recordedAt: z.string(),
  operatorId: z.string(),
  kind: checkpointKindSchema,
  evidenceRefs: z.array(z.string())
});

const questionSchema = z.object({
  questionId: z.string(),
  category: questionCategorySchema,
  prompt: z.string(),
  status: questionStatusSchema,
  createdAt: z.string(),
  updatedAt: z.string(),
  operatorId: z.string()
});

const sessionSchema = z.object({
  sessionId: z.string(),
  caseId: z.string(),
  title: z.string().nullable(),
  status: sessionStatusSchema,
  createdAt: z.string(),
  updatedAt: z.string(),
  operatorId: z.string(),
  checkpoints: z.array(checkpointSchema),
  questions: z.array(questionSchema)
});

const sessionSummarySchema = z.object({
  sessionId: z.string(),
  caseId: z.string(),
  title: z.string().nullable(),
  status: sessionStatusSchema,
  createdAt: z.string(),
  updatedAt: z.string(),
  checkpointCount: z.number(),
  openQuestionCount: z.number(),
  operatorId: z.string()
});

const progressSchema = z.object({
  engineVersion: z.literal("2.1.0"),
  generatedAt: z.string(),
  sessionId: z.string(),
  caseId: z.string(),
  sessionStatus: sessionStatusSchema,
  phase: z.enum([
    "not-started",
    "early",
    "developing",
    "well-documented",
    "closed"
  ]),
  reviewCoveragePercent: z.number().min(0).max(100),
  reviewedAreas: z.array(checkpointKindSchema),
  missingReviewAreas: z.array(checkpointKindSchema),
  checkpointCount: z.number(),
  checkpointCounts: z.record(checkpointKindSchema, z.number()),
  uniqueEvidenceReferenceCount: z.number(),
  questionCount: z.number(),
  questionCounts: z.object({
    open: z.number(),
    resolved: z.number(),
    deferred: z.number()
  }),
  openQuestionCategories: z.array(questionCategorySchema),
  historicalContext: z.object({
    similarityThreshold: z.number().min(1).max(100),
    relatedCaseCount: z.number(),
    relatedCases: z.array(z.object({
      caseId: z.string(),
      recordedAt: z.string(),
      similarityPercent: z.number().min(0).max(100),
      outcomeStatus: z.string().nullable(),
      resolutionCategory: z.string().nullable(),
      verified: z.boolean().nullable()
    }))
  }),
  suggestedEvidenceFocus: z.array(z.string()),
  interpretation: z.string(),
  limitations: z.array(z.string())
});
export function registerInvestigationTools(server: McpServer) {
  server.registerTool(
    "create_investigation_session",
    {
      title: "Create Investigation Session",
      description:
        "Create a bounded LocalOps investigation session for one stored incident case. This changes session metadata only and does not mutate the host.",
      annotations: registryWriteAnnotations,
      inputSchema: z.object({
        caseId: z.string().min(1).max(84),
        title: z.string().max(200).optional()
      }),
      outputSchema: sessionSchema
    },
    async ({ caseId, title }) =>
      toolResult(await createInvestigationSession(caseId, title))
  );

  server.registerTool(
    "list_investigation_sessions",
    {
      title: "List Investigation Sessions",
      description:
        "List bounded LocalOps investigation-session metadata, checkpoint counts and open-question counts.",
      annotations: readOnlyAnnotations,
      inputSchema: z.object({
        limit: z.number().int().min(1).max(50).optional()
      }),
      outputSchema: z.object({
        sessionCount: z.number(),
        sessions: z.array(sessionSummarySchema),
        persistence: z.string()
      })
    },
    async ({ limit }) =>
      toolResult(await listInvestigationSessions(limit))
  );

  server.registerTool(
    "investigation_session_details",
    {
      title: "Investigation Session Details",
      description:
        "Read one bounded investigation session including checkpoints and tracked questions.",
      annotations: readOnlyAnnotations,
      inputSchema: z.object({
        sessionId: z.string().min(1).max(84)
      }),
      outputSchema: sessionSchema
    },
    async ({ sessionId }) =>
      toolResult(await investigationSessionDetails(sessionId))
  );
  server.registerTool(
    "record_investigation_checkpoint",
    {
      title: "Record Investigation Checkpoint",
      description:
        "Record one normalized evidence-review checkpoint in an open or paused investigation session. Checkpoints store references only, not raw logs or command output.",
      annotations: registryWriteAnnotations,
      inputSchema: z.object({
        sessionId: z.string().min(1).max(84),
        kind: checkpointKindSchema,
        evidenceRefs: z.array(
          z.string().min(1).max(128)
        ).min(1).max(20)
      }),
      outputSchema: sessionSchema
    },
    async ({ sessionId, kind, evidenceRefs }) =>
      toolResult(await recordInvestigationCheckpoint(sessionId, {
        kind,
        evidenceRefs
      }))
  );

  server.registerTool(
    "add_investigation_question",
    {
      title: "Add Investigation Question",
      description:
        "Add one bounded investigation question to an open or paused session for later resolution or deferral.",
      annotations: registryWriteAnnotations,
      inputSchema: z.object({
        sessionId: z.string().min(1).max(84),
        category: questionCategorySchema,
        prompt: z.string().min(1).max(240)
      }),
      outputSchema: sessionSchema
    },
    async ({ sessionId, category, prompt }) =>
      toolResult(await addInvestigationQuestion(sessionId, {
        category,
        prompt
      }))
  );

  server.registerTool(
    "update_investigation_question",
    {
      title: "Update Investigation Question",
      description:
        "Mark a stored investigation question as open, resolved or deferred without changing host state.",
      annotations: registryWriteAnnotations,
      inputSchema: z.object({
        sessionId: z.string().min(1).max(84),
        questionId: z.string().min(1).max(82),
        status: questionStatusSchema
      }),
      outputSchema: sessionSchema
    },
    async ({ sessionId, questionId, status }) =>
      toolResult(
        await updateInvestigationQuestion(sessionId, questionId, status)
      )
  );
  server.registerTool(
    "set_investigation_session_status",
    {
      title: "Set Investigation Session Status",
      description:
        "Set an investigation session to open, paused or completed. Completion is blocked while questions remain open.",
      annotations: registryWriteAnnotations,
      inputSchema: z.object({
        sessionId: z.string().min(1).max(84),
        status: sessionStatusSchema
      }),
      outputSchema: sessionSchema
    },
    async ({ sessionId, status }) =>
      toolResult(
        await setInvestigationSessionStatus(sessionId, status)
      )
  );

  server.registerTool(
    "investigation_session_status",
    {
      title: "Investigation Session Memory Status",
      description:
        "Show v2.1 investigation-session bounds and whether optional local persistence is enabled.",
      annotations: readOnlyAnnotations,
      inputSchema: z.object({}),
      outputSchema: z.object({
        version: z.literal("2.1.0"),
        persistenceEnabled: z.boolean(),
        persistencePath: z.string().nullable(),
        sessionCount: z.number(),
        openSessionCount: z.number(),
        pausedSessionCount: z.number(),
        completedSessionCount: z.number(),
        maxSessions: z.number(),
        maxCheckpointsPerSession: z.number(),
        maxQuestionsPerSession: z.number(),
        storage: z.string()
      })
    },
    async () => toolResult(await investigationSessionStatus())
  );

  server.registerTool(
    "investigation_progress_analysis",
    {
      title: "Investigation Progress Analysis",
      description:
        "Analyze documented investigation coverage, tracked questions and similar historical cases through the private intelligence core. Coverage is documentation progress only, not confidence or remediation readiness.",
      annotations: readOnlyAnnotations,
      inputSchema: z.object({
        sessionId: z.string().min(1).max(84),
        similarityThreshold: z.number().int().min(1).max(100).optional(),
        maxRelatedCases: z.number().int().min(1).max(20).optional()
      }),
      outputSchema: progressSchema
    },
    async ({ sessionId, similarityThreshold, maxRelatedCases }) => {
      const session = await investigationSessionDetails(sessionId);
      return toolResult(
        await callPrivateIntelligence("/v2/investigations/progress", {
          ...await incidentMemoryBundle(),
          session,
          similarityThreshold: similarityThreshold ?? 50,
          maxRelatedCases: maxRelatedCases ?? 10
        })
      );
    }
  );
}
