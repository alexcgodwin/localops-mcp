import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import {
  addInvestigationHypothesis,
  clearInvestigationSessionsForTests,
  createInvestigationSession,
  investigationHypothesisDetails,
  investigationSessionDetails,
  investigationSessionStatus,
  linkHypothesisEvidence,
  listInvestigationHypotheses,
  recordInvestigationCheckpoint,
  setInvestigationSessionStatus,
  updateInvestigationHypothesis
} from "../src/investigation-session.js";
import {
  clearIncidentMemoryForTests,
  recordIncidentCase,
  type IncidentFingerprint
} from "../src/incident-memory.js";

let temporaryDirectory: string | null = null;

function fingerprint(signal: string): IncidentFingerprint {
  return {
    engineVersion: "1.7.0",
    generatedAt: "2026-10-03T18:00:00.000Z",
    sourceGeneratedAt: "2026-10-03T17:59:00.000Z",
    signature: signal.includes("disk") ? "e".repeat(24) : "d".repeat(24),
    severity: "high",
    scope: "multi-node",
    nodeCount: 2,
    affectedNodeIds: ["node-a", "node-b"],
    signalIds: [signal],
    signalCategories: ["service-state"],
    commonAffectedTags: ["prod"],
    causeCategories: ["service-state"],
    fingerprintTokens: [
      "signal:" + signal,
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

describe("v2.2 investigation hypothesis ledger", () => {
  it("tracks bounded hypotheses and typed evidence provenance", async () => {
    process.env.LOCALOPS_OPERATOR_ID = "investigator-2";
    const target = await recordIncidentCase(
      fingerprint("service-state:payments-api"),
      "Payments incident"
    );
    const historical = await recordIncidentCase(
      fingerprint("service-state:payments-api"),
      "Earlier payments incident"
    );
    const session = await createInvestigationSession(
      target.caseId,
      "Payments investigation"
    );
    const withCheckpoint = await recordInvestigationCheckpoint(
      session.sessionId,
      {
        kind: "evidence-reviewed",
        evidenceRefs: ["signal:service-state:payments-api"]
      }
    );

    const withHypothesis = await addInvestigationHypothesis(
      session.sessionId,
      {
        statement: "A shared service-state dependency explains the incident."
      }
    );
    const hypothesisId = withHypothesis.hypotheses[0].hypothesisId;

    await linkHypothesisEvidence(session.sessionId, hypothesisId, {
      stance: "supporting",
      provenance: "current-case",
      reference: "signal:service-state:payments-api"
    });
    await linkHypothesisEvidence(session.sessionId, hypothesisId, {
      stance: "contradicting",
      provenance: "historical-case",
      reference: "case:earlier-payments",
      sourceCaseId: historical.caseId
    });
    await linkHypothesisEvidence(session.sessionId, hypothesisId, {
      stance: "context",
      provenance: "checkpoint-derived",
      reference: "review:current-signal",
      sourceCheckpointId: withCheckpoint.checkpoints[0].checkpointId
    });
    await linkHypothesisEvidence(session.sessionId, hypothesisId, {
      stance: "context",
      provenance: "unverified-reference",
      reference: "operator:external-observation"
    });

    await updateInvestigationHypothesis(
      session.sessionId,
      hypothesisId,
      "active"
    );

    const detail = await investigationHypothesisDetails(
      session.sessionId,
      hypothesisId
    );
    expect(detail.status).toBe("active");
    expect(detail.evidenceLinks).toHaveLength(4);
    expect(detail.evidenceLinks.map((item) => item.provenance)).toEqual([
      "current-case",
      "historical-case",
      "checkpoint-derived",
      "unverified-reference"
    ]);

    const listed = await listInvestigationHypotheses(session.sessionId);
    expect(listed.hypothesisCount).toBe(1);
    expect(listed.hypotheses[0]).toMatchObject({
      supportingEvidenceCount: 1,
      contradictingEvidenceCount: 1,
      contextEvidenceCount: 2
    });

    const status = await investigationSessionStatus();
    expect(status.version).toBe("2.2.0");
    expect(status.maxHypothesesPerSession).toBe(25);
    expect(status.maxEvidenceLinksPerHypothesis).toBe(50);
  });

  it("rejects invalid provenance claims and freezes a completed session", async () => {
    const target = await recordIncidentCase(
      fingerprint("service-state:payments-api")
    );
    const session = await createInvestigationSession(target.caseId);
    const withHypothesis = await addInvestigationHypothesis(
      session.sessionId,
      { statement: "The current service state is the primary lead." }
    );
    const hypothesisId = withHypothesis.hypotheses[0].hypothesisId;

    await expect(
      linkHypothesisEvidence(session.sessionId, hypothesisId, {
        stance: "supporting",
        provenance: "historical-case",
        reference: "case:missing"
      })
    ).rejects.toThrow("sourceCaseId");

    await setInvestigationSessionStatus(session.sessionId, "completed");
    await expect(
      updateInvestigationHypothesis(
        session.sessionId,
        hypothesisId,
        "supported"
      )
    ).rejects.toThrow("Completed investigation sessions");
  });

  it("loads persisted v2.1 sessions with an empty hypothesis ledger", async () => {
    temporaryDirectory = await mkdtemp(
      join(tmpdir(), "localops-v21-investigation-")
    );
    process.env.LOCALOPS_DATA_DIR = temporaryDirectory;
    process.env.LOCALOPS_INVESTIGATION_PERSISTENCE = "true";

    const sessionId = "inv_legacy-session";
    const legacy = {
      version: "2.1.0",
      updatedAt: "2026-10-03T18:00:00.000Z",
      sessions: [
        {
          sessionId,
          caseId: "inc_legacy-case",
          title: "Legacy investigation",
          status: "open",
          createdAt: "2026-10-03T17:00:00.000Z",
          updatedAt: "2026-10-03T17:30:00.000Z",
          operatorId: "legacy-operator",
          checkpoints: [],
          questions: []
        }
      ]
    };
    await writeFile(
      join(temporaryDirectory, "investigation-sessions.json"),
      JSON.stringify(legacy),
      "utf8"
    );

    clearInvestigationSessionsForTests();
    const restored = await investigationSessionDetails(sessionId);
    expect(restored.title).toBe("Legacy investigation");
    expect(restored.hypotheses).toEqual([]);
  });
});
