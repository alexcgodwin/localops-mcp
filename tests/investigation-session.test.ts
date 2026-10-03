import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import {
  addInvestigationQuestion,
  clearInvestigationSessionsForTests,
  createInvestigationSession,
  investigationSessionDetails,
  investigationSessionStatus,
  listInvestigationSessions,
  recordInvestigationCheckpoint,
  setInvestigationSessionStatus,
  updateInvestigationQuestion
} from "../src/investigation-session.js";
import {
  clearIncidentMemoryForTests,
  recordIncidentCase,
  type IncidentFingerprint
} from "../src/incident-memory.js";

let temporaryDirectory: string | null = null;

function fingerprint(): IncidentFingerprint {
  return {
    engineVersion: "1.7.0",
    generatedAt: "2026-10-03T16:00:00.000Z",
    sourceGeneratedAt: "2026-10-03T15:59:00.000Z",
    signature: "d".repeat(24),
    severity: "high",
    scope: "multi-node",
    nodeCount: 2,
    affectedNodeIds: ["node-a", "node-b"],
    signalIds: ["service-state:payments-api"],
    signalCategories: ["service-state"],
    commonAffectedTags: ["prod"],
    causeCategories: ["service-state"],
    fingerprintTokens: [
      "signal:service-state:payments-api",
      "tag:prod",
      "cause:service-state"
    ],
    interpretation: "bounded fingerprint",
    limitations: ["snapshot-only"]
  };
}

afterEach(async () => {
  clearInvestigationSessionsForTests();
  clearIncidentMemoryForTests();
  delete process.env.LOCALOPS_INVESTIGATION_PERSISTENCE;
  delete process.env.LOCALOPS_INCIDENT_PERSISTENCE;
  delete process.env.LOCALOPS_DATA_DIR;
  delete process.env.LOCALOPS_OPERATOR_ID;
  if (temporaryDirectory) {
    await rm(temporaryDirectory, { recursive: true, force: true });
    temporaryDirectory = null;
  }
});
describe("v2.1 investigation session memory", () => {
  it("tracks checkpoints, questions and completion guards", async () => {
    process.env.LOCALOPS_OPERATOR_ID = "investigator-1";
    const incident = await recordIncidentCase(
      fingerprint(),
      "Payments incident"
    );
    const session = await createInvestigationSession(
      incident.caseId,
      "Payments investigation"
    );

    expect(session.status).toBe("open");
    expect(session.caseId).toBe(incident.caseId);

    await recordInvestigationCheckpoint(session.sessionId, {
      kind: "evidence-reviewed",
      evidenceRefs: [
        "signal:service-state:payments-api",
        "scope:multi-node"
      ]
    });

    const withQuestion = await addInvestigationQuestion(
      session.sessionId,
      {
        category: "cause",
        prompt: "Is the service-state evidence shared across affected nodes?"
      }
    );
    expect(withQuestion.questions).toHaveLength(1);
    expect(withQuestion.questions[0].status).toBe("open");

    await expect(
      setInvestigationSessionStatus(session.sessionId, "completed")
    ).rejects.toThrow("Resolve or defer");

    await updateInvestigationQuestion(
      session.sessionId,
      withQuestion.questions[0].questionId,
      "resolved"
    );
    const completed = await setInvestigationSessionStatus(
      session.sessionId,
      "completed"
    );
    expect(completed.status).toBe("completed");

    await expect(
      recordInvestigationCheckpoint(session.sessionId, {
        kind: "scope-reviewed",
        evidenceRefs: ["scope:multi-node"]
      })
    ).rejects.toThrow("Completed investigation sessions");
  });
  it("lists bounded session summaries and memory status", async () => {
    const incident = await recordIncidentCase(fingerprint());
    const session = await createInvestigationSession(incident.caseId);
    await recordInvestigationCheckpoint(session.sessionId, {
      kind: "scope-reviewed",
      evidenceRefs: ["scope:multi-node"]
    });

    const listed = await listInvestigationSessions();
    expect(listed.sessionCount).toBe(1);
    expect(listed.sessions[0]).toMatchObject({
      sessionId: session.sessionId,
      caseId: incident.caseId,
      status: "open",
      checkpointCount: 1,
      openQuestionCount: 0
    });
    expect(listed.persistence).toContain("disabled");

    const status = await investigationSessionStatus();
    expect(status.version).toBe("2.1.0");
    expect(status.maxSessions).toBe(50);
    expect(status.maxCheckpointsPerSession).toBe(100);
    expect(status.maxQuestionsPerSession).toBe(50);
  });

  it("persists sessions across an in-memory restart when enabled", async () => {
    temporaryDirectory = await mkdtemp(
      join(tmpdir(), "localops-investigation-")
    );
    process.env.LOCALOPS_DATA_DIR = temporaryDirectory;
    process.env.LOCALOPS_INVESTIGATION_PERSISTENCE = "true";
    process.env.LOCALOPS_OPERATOR_ID = "restart-investigator";

    const incident = await recordIncidentCase(fingerprint());
    const session = await createInvestigationSession(
      incident.caseId,
      "Persistent investigation"
    );
    await recordInvestigationCheckpoint(session.sessionId, {
      kind: "historical-case-reviewed",
      evidenceRefs: ["case:inc_prior"]
    });
    await addInvestigationQuestion(session.sessionId, {
      category: "verification",
      prompt: "Has the current service state been revalidated?"
    });

    clearInvestigationSessionsForTests();

    const restored = await investigationSessionDetails(session.sessionId);
    expect(restored.title).toBe("Persistent investigation");
    expect(restored.operatorId).toBe("restart-investigator");
    expect(restored.checkpoints).toHaveLength(1);
    expect(restored.questions).toHaveLength(1);

    const status = await investigationSessionStatus();
    expect(status.persistenceEnabled).toBe(true);
    expect(status.persistencePath).toContain(
      "investigation-sessions.json"
    );
  });
  it("rejects unsupported checkpoint references and missing questions", async () => {
    const incident = await recordIncidentCase(fingerprint());
    const session = await createInvestigationSession(incident.caseId);

    await expect(
      recordInvestigationCheckpoint(session.sessionId, {
        kind: "evidence-reviewed",
        evidenceRefs: ["bad\nreference"]
      })
    ).rejects.toThrow("unsupported characters");

    await expect(
      updateInvestigationQuestion(
        session.sessionId,
        "q_missing",
        "resolved"
      )
    ).rejects.toThrow("not stored");
  });
});
