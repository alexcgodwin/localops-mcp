import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import {
  clearIncidentMemoryForTests,
  incidentCaseDetails,
  incidentMemoryBundle,
  incidentMemoryStatus,
  listIncidentCases,
  recordIncidentCase,
  recordIncidentOutcome,
  type IncidentFingerprint
} from "../src/incident-memory.js";
import { callPrivateIntelligence } from "../src/intelligence-client.js";

let temporaryDirectory: string | null = null;

function fingerprint(
  signature = "a".repeat(24),
  signalIds = ["resource-pressure:cpu"]
): IncidentFingerprint {
  return {
    engineVersion: "1.7.0",
    generatedAt: "2026-10-03T04:00:00.000Z",
    sourceGeneratedAt: "2026-10-03T03:59:00.000Z",
    signature,
    severity: "high",
    scope: "multi-node",
    nodeCount: 3,
    affectedNodeIds: ["node-a", "node-b"],
    signalIds,
    signalCategories: ["resource-pressure"],
    commonAffectedTags: ["prod"],
    causeCategories: ["resource-pressure"],
    fingerprintTokens: [
      "signal:resource-pressure:cpu",
      "category:resource-pressure",
      "tag:prod",
      "cause:resource-pressure"
    ],
    interpretation:
      "Normalized evidence fingerprint for recurrence comparison.",
    limitations: ["Fingerprint contains bounded metadata only."]
  };
}
afterEach(async () => {
  clearIncidentMemoryForTests();
  delete process.env.LOCALOPS_INTELLIGENCE_URL;
  delete process.env.LOCALOPS_INTELLIGENCE_TOKEN;
  delete process.env.LOCALOPS_INCIDENT_PERSISTENCE;
  delete process.env.LOCALOPS_DATA_DIR;
  delete process.env.LOCALOPS_OPERATOR_ID;
  if (temporaryDirectory) {
    await rm(temporaryDirectory, { recursive: true, force: true });
    temporaryDirectory = null;
  }
});

describe("v1.8 public durable incident knowledge", () => {
  it("records, lists and reads normalized incident cases", async () => {
    const first = await recordIncidentCase(
      fingerprint(),
      "Payments incident"
    );
    const second = await recordIncidentCase(
      fingerprint("b".repeat(24), ["service-state:payments-api"])
    );

    const listed = await listIncidentCases();
    expect(listed.caseCount).toBe(2);
    expect(listed.cases[0].caseId).toBe(second.caseId);
    expect(listed.cases[1].title).toBe("Payments incident");
    expect(listed.cases[0].outcomeStatus).toBeNull();

    const details = await incidentCaseDetails(first.caseId);
    expect(details.fingerprint.signature).toBe("a".repeat(24));
    expect(details.fingerprint.signalIds).toContain(
      "resource-pressure:cpu"
    );
    expect(listed.persistence).toContain("disabled");
  });

  it("records structured operator-confirmed outcomes", async () => {
    process.env.LOCALOPS_OPERATOR_ID = "test-operator";
    const incident = await recordIncidentCase(fingerprint());

    const updated = await recordIncidentOutcome(incident.caseId, {
      status: "resolved",
      resolutionCategory: "service-recovery",
      verified: true,
      durationMinutes: 18
    });

    expect(updated.outcome).toMatchObject({
      status: "resolved",
      resolutionCategory: "service-recovery",
      verified: true,
      durationMinutes: 18,
      operatorId: "test-operator"
    });

    const listed = await listIncidentCases();
    expect(listed.cases[0].outcomeStatus).toBe("resolved");
    expect(listed.cases[0].outcomeVerified).toBe(true);
  });
  it("persists bounded normalized cases across an in-memory restart", async () => {
    temporaryDirectory = await mkdtemp(
      join(tmpdir(), "localops-incident-memory-")
    );
    process.env.LOCALOPS_DATA_DIR = temporaryDirectory;
    process.env.LOCALOPS_INCIDENT_PERSISTENCE = "true";
    process.env.LOCALOPS_OPERATOR_ID = "restart-test";

    const incident = await recordIncidentCase(
      fingerprint(),
      "Persisted case"
    );
    await recordIncidentOutcome(incident.caseId, {
      status: "mitigated",
      resolutionCategory: "resource-relief",
      verified: true,
      durationMinutes: 42
    });

    clearIncidentMemoryForTests();

    const status = await incidentMemoryStatus();
    expect(status.persistenceEnabled).toBe(true);
    expect(status.caseCount).toBe(1);
    expect(status.outcomeCount).toBe(1);
    expect(status.persistencePath).toContain("incident-memory.json");

    const restored = await incidentCaseDetails(incident.caseId);
    expect(restored.title).toBe("Persisted case");
    expect(restored.outcome?.resolutionCategory).toBe("resource-relief");
    expect(restored.outcome?.operatorId).toBe("restart-test");
  });

  it("builds a selected bounded memory bundle in requested order", async () => {
    const first = await recordIncidentCase(fingerprint());
    const second = await recordIncidentCase(
      fingerprint("c".repeat(24))
    );
    const bundle = await incidentMemoryBundle([
      second.caseId,
      first.caseId
    ]);
    expect(bundle.cases.map((item) => item.caseId)).toEqual([
      second.caseId,
      first.caseId
    ]);
  });

  it("caps incident memory at 200 cases", async () => {
    for (let index = 0; index < 205; index += 1) {
      const signature = index
        .toString(16)
        .padStart(24, "0")
        .slice(-24);
      await recordIncidentCase(fingerprint(signature));
    }

    const listed = await listIncidentCases(200);
    expect(listed.caseCount).toBe(200);
    expect(listed.cases).toHaveLength(200);
  });
  it("allows only the fixed incident-analysis routes", async () => {
    process.env.LOCALOPS_INTELLIGENCE_URL =
      "http://127.0.0.1:43123";
    process.env.LOCALOPS_INTELLIGENCE_TOKEN = "q".repeat(32);

    const allowed = [
      ["/v1/incidents/fingerprint", "1.7.0"],
      ["/v1/incidents/compare", "1.7.0"],
      ["/v1/incidents/recurrence", "1.7.0"],
      ["/v1/incidents/history-summary", "1.7.0"],
      ["/v1/incidents/resolution-patterns", "1.8.0"],
      ["/v1/incidents/resolution-history", "1.8.0"],
      ["/v1/incidents/knowledge-search", "1.9.0"],
      ["/v1/incidents/neighbors", "1.9.0"],
      ["/v1/incidents/clusters", "1.9.0"],
      ["/v2/knowledge/graph", "2.0.0"],
      ["/v2/knowledge/trace", "2.0.0"],
      ["/v2/knowledge/entity-cases", "2.0.0"],
      ["/v2/knowledge/investigation", "2.0.0"],
      ["/v2/investigations/progress", "2.2.0"]
    ] as const;

    for (const [route, version] of allowed) {
      const result = await callPrivateIntelligence(
        route,
        {},
        (async () =>
          new Response(
            JSON.stringify({ engineVersion: version }),
            {
              status: 200,
              headers: { "content-type": "application/json" }
            }
          )) as typeof fetch
      );
      expect(result.engineVersion).toBe(version);
    }

    await expect(
      callPrivateIntelligence(
        "/v1/incidents/execute",
        {},
        (async () =>
          new Response("{}", { status: 200 })) as typeof fetch
      )
    ).rejects.toThrow("Unsupported private intelligence route");

    await expect(
      callPrivateIntelligence(
        "/v2/knowledge/execute",
        {},
        (async () =>
          new Response("{}", { status: 200 })) as typeof fetch
      )
    ).rejects.toThrow("Unsupported private intelligence route");

    await expect(
      callPrivateIntelligence(
        "/v2/investigations/execute",
        {},
        (async () =>
          new Response("{}", { status: 200 })) as typeof fetch
      )
    ).rejects.toThrow("Unsupported private intelligence route");
  });
});
