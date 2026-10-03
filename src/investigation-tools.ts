import type { McpServer } from "@modelcontextprotocol/server";
import * as z from "zod/v4";
import { callPrivateIntelligence } from "./intelligence-client.js";
import { incidentMemoryBundle } from "./incident-memory.js";
import {
  addInvestigationHypothesis,
  addInvestigationQuestion,
  createInvestigationSession,
  investigationHypothesisDetails,
  investigationSessionDetails,
  investigationSessionStatus,
  linkHypothesisEvidence,
  listInvestigationHypotheses,
  listInvestigationSessions,
  recordInvestigationCheckpoint,
  setInvestigationSessionStatus,
  updateInvestigationHypothesis,
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

const hypothesisStatusSchema = z.enum([
  "proposed",
  "active",
  "supported",
  "weakened",
  "rejected",
  "retired"
]);

const evidenceStanceSchema = z.enum([
  "supporting",
  "contradicting",
  "context"
]);

const evidenceProvenanceSchema = z.enum([
  "current-case",
  "historical-case",
  "checkpoint-derived",
  "unverified-reference"
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

const hypothesisEvidenceSchema = z.object({
  evidenceId: z.string(),
  linkedAt: z.string(),
  operatorId: z.string(),
  stance: evidenceStanceSchema,
  provenance: evidenceProvenanceSchema,
  reference: z.string(),
  sourceCaseId: z.string().nullable(),
  sourceCheckpointId: z.string().nullable()
});

const hypothesisSchema = z.object({
  hypothesisId: z.string(),
  statement: z.string(),
  status: hypothesisStatusSchema,
  createdAt: z.string(),
  updatedAt: z.string(),
  operatorId: z.string(),
  evidenceLinks: z.array(hypothesisEvidenceSchema)
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
  questions: z.array(questionSchema),
  hypotheses: z.array(hypothesisSchema)
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
  hypothesisCount: z.number(),
  activeHypothesisCount: z.number(),
  operatorId: z.string()
});

const hypothesisSummarySchema = z.object({
  hypothesisId: z.string(),
  statement: z.string(),
  status: hypothesisStatusSchema,
  createdAt: z.string(),
  updatedAt: z.string(),
  operatorId: z.string(),
  evidenceLinkCount: z.number(),
  supportingEvidenceCount: z.number(),
  contradictingEvidenceCount: z.number(),
  contextEvidenceCount: z.number()
});

const progressSchema = z.object({
  engineVersion: z.literal("2.2.0"),
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

const hypothesisBalanceSchema = z.object({
  engineVersion: z.literal("2.2.0"),
  generatedAt: z.string(),
  sessionId: z.string(),
  caseId: z.string(),
  hypothesisCount: z.number(),
  conflictedHypothesisCount: z.number(),
  withoutEvidenceCount: z.number(),
  unverifiedEvidenceLinkCount: z.number(),
  hypotheses: z.array(z.object({
    hypothesisId: z.string(),
    statement: z.string(),
    status: hypothesisStatusSchema,
    evidenceLinkCount: z.number(),
    evidenceCounts: z.object({
      supporting: z.number(),
      contradicting: z.number(),
      context: z.number()
    }),
    provenanceCounts: z.object({
      currentCase: z.number(),
      historicalCase: z.number(),
      checkpointDerived: z.number(),
      unverifiedReference: z.number()
    }),
    validatedProvenanceCount: z.number(),
    unverifiedOrUnknownProvenanceCount: z.number(),
    evidenceBalance: z.enum([
      "no-evidence",
      "support-only",
      "contradiction-only",
      "context-only",
      "mixed"
    ]),
    conflictPresent: z.boolean(),
    evidenceGap: z.boolean(),
    interpretation: z.string()
  })),
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
        "List bounded LocalOps investigation-session metadata, checkpoint counts, open-question counts and hypothesis counts.",
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
        "Read one bounded investigation session including checkpoints, questions and the hypothesis ledger.",
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
    "add_investigation_hypothesis",
    {
      title: "Add Investigation Hypothesis",
      description:
        "Add one bounded operator-authored hypothesis to an open or paused investigation session. The hypothesis is a tracked statement, not a system verdict.",
      annotations: registryWriteAnnotations,
      inputSchema: z.object({
        sessionId: z.string().min(1).max(84),
        statement: z.string().min(1).max(240)
      }),
      outputSchema: sessionSchema
    },
    async ({ sessionId, statement }) =>
      toolResult(
        await addInvestigationHypothesis(sessionId, { statement })
      )
  );

  server.registerTool(
    "list_investigation_hypotheses",
    {
      title: "List Investigation Hypotheses",
      description:
        "List the bounded hypothesis ledger for one investigation session with evidence-link counts.",
      annotations: readOnlyAnnotations,
      inputSchema: z.object({
        sessionId: z.string().min(1).max(84)
      }),
      outputSchema: z.object({
        sessionId: z.string(),
        caseId: z.string(),
        hypothesisCount: z.number(),
        hypotheses: z.array(hypothesisSummarySchema)
      })
    },
    async ({ sessionId }) =>
      toolResult(await listInvestigationHypotheses(sessionId))
  );

  server.registerTool(
    "investigation_hypothesis_details",
    {
      title: "Investigation Hypothesis Details",
      description:
        "Read one hypothesis and its normalized supporting, contradicting and context evidence links.",
      annotations: readOnlyAnnotations,
      inputSchema: z.object({
        sessionId: z.string().min(1).max(84),
        hypothesisId: z.string().min(1).max(84)
      }),
      outputSchema: hypothesisSchema
    },
    async ({ sessionId, hypothesisId }) =>
      toolResult(
        await investigationHypothesisDetails(sessionId, hypothesisId)
      )
  );

  server.registerTool(
    "update_investigation_hypothesis",
    {
      title: "Update Investigation Hypothesis",
      description:
        "Update the operator-controlled lifecycle state of a stored hypothesis. LocalOps does not automatically promote a hypothesis to supported.",
      annotations: registryWriteAnnotations,
      inputSchema: z.object({
        sessionId: z.string().min(1).max(84),
        hypothesisId: z.string().min(1).max(84),
        status: hypothesisStatusSchema
      }),
      outputSchema: sessionSchema
    },
    async ({ sessionId, hypothesisId, status }) =>
      toolResult(
        await updateInvestigationHypothesis(
          sessionId,
          hypothesisId,
          status
        )
      )
  );

  server.registerTool(
    "link_hypothesis_evidence",
    {
      title: "Link Hypothesis Evidence",
      description:
        "Link one normalized evidence reference to a hypothesis as supporting, contradicting or context evidence with explicit provenance. No raw logs or command output are stored.",
      annotations: registryWriteAnnotations,
      inputSchema: z.object({
        sessionId: z.string().min(1).max(84),
        hypothesisId: z.string().min(1).max(84),
        stance: evidenceStanceSchema,
        provenance: evidenceProvenanceSchema,
        reference: z.string().min(1).max(128),
        sourceCaseId: z.string().min(1).max(84).optional(),
        sourceCheckpointId: z.string().min(1).max(84).optional()
      }),
      outputSchema: sessionSchema
    },
    async ({
      sessionId,
      hypothesisId,
      stance,
      provenance,
      reference,
      sourceCaseId,
      sourceCheckpointId
    }) =>
      toolResult(
        await linkHypothesisEvidence(sessionId, hypothesisId, {
          stance,
          provenance,
          reference,
          sourceCaseId,
          sourceCheckpointId
        })
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
        "Show v2.2 investigation-session, checkpoint, question and hypothesis-ledger bounds plus optional local persistence state.",
      annotations: readOnlyAnnotations,
      inputSchema: z.object({}),
      outputSchema: z.object({
        version: z.literal("2.2.0"),
        persistenceEnabled: z.boolean(),
        persistencePath: z.string().nullable(),
        sessionCount: z.number(),
        openSessionCount: z.number(),
        pausedSessionCount: z.number(),
        completedSessionCount: z.number(),
        maxSessions: z.number(),
        maxCheckpointsPerSession: z.number(),
        maxQuestionsPerSession: z.number(),
        maxHypothesesPerSession: z.number(),
        maxEvidenceLinksPerHypothesis: z.number(),
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

  server.registerTool(
    "investigation_hypothesis_analysis",
    {
      title: "Investigation Hypothesis Evidence Balance",
      description:
        "Analyze evidence balance and provenance across the bounded hypothesis ledger through the private intelligence core. Results describe evidence state only and never declare a hypothesis true or authorize remediation.",
      annotations: readOnlyAnnotations,
      inputSchema: z.object({
        sessionId: z.string().min(1).max(84)
      }),
      outputSchema: hypothesisBalanceSchema
    },
    async ({ sessionId }) => {
      const session = await investigationSessionDetails(sessionId);
      return toolResult(
        await callPrivateIntelligence(
          "/v2/investigations/hypothesis-balance",
          {
            ...await incidentMemoryBundle(),
            session
          }
        )
      );
    }
  );
}
