import { describe, expect, it, afterEach } from "vitest";
import {
  clearIncidentMemoryForTests,
  incidentCaseDetails,
  incidentMemoryBundle,
  listIncidentCases,
  recordIncidentCase,
  type IncidentFingerprint
} from "../src/incident-memory.js";
import { callPrivateIntelligence } from "../src/intelligence-client.js";

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
    limitations: [
      "Fingerprint contains bounded metadata only."
    ]
  };
}

afterEach(() => {
  clearIncidentMemoryForTests();
  delete process.env.LOCALOPS_INTELLIGENCE_URL;
  delete process.env.LOCALOPS_INTELLIGENCE_TOKEN;
});

describe("v1.7 public incident memory", () => {
  it("records, lists and reads normalized incident cases", () => {
    const first = recordIncidentCase(fingerprint(), "Payments incident");
    const second = recordIncidentCase(
      fingerprint("b".repeat(24), ["service-state:payments-api"])
    );

    const listed = listIncidentCases();
    expect(listed.caseCount).toBe(2);
    expect(listed.cases[0].caseId).toBe(second.caseId);
    expect(listed.cases[1].title).toBe("Payments incident");

    const details = incidentCaseDetails(first.caseId);
    expect(details.fingerprint.signature).toBe("a".repeat(24));
    expect(details.fingerprint.signalIds).toContain(
      "resource-pressure:cpu"
    );
    expect(listed.persistence).toContain("in-memory");
  });

  it("builds a selected bounded memory bundle in requested order", () => {
    const first = recordIncidentCase(fingerprint());
    const second = recordIncidentCase(fingerprint("c".repeat(24)));
    const bundle = incidentMemoryBundle([second.caseId, first.caseId]);
    expect(bundle.cases.map((item) => item.caseId)).toEqual([
      second.caseId,
      first.caseId
    ]);
  });

  it("caps incident memory at 200 cases", () => {
    for (let index = 0; index < 205; index += 1) {
      const signature = index.toString(16).padStart(24, "0").slice(-24);
      recordIncidentCase(fingerprint(signature));
    }

    const listed = listIncidentCases(200);
    expect(listed.caseCount).toBe(200);
    expect(listed.cases).toHaveLength(200);
  });

  it("allows only the fixed v1.7 incident-memory routes", async () => {
    process.env.LOCALOPS_INTELLIGENCE_URL =
      "http://127.0.0.1:43123";
    process.env.LOCALOPS_INTELLIGENCE_TOKEN = "q".repeat(32);

    const allowed = [
      "/v1/incidents/fingerprint",
      "/v1/incidents/compare",
      "/v1/incidents/recurrence",
      "/v1/incidents/history-summary"
    ];

    for (const route of allowed) {
      const result = await callPrivateIntelligence(
        route,
        {},
        (async () =>
          new Response(
            JSON.stringify({ engineVersion: "1.7.0" }),
            {
              status: 200,
              headers: { "content-type": "application/json" }
            }
          )) as typeof fetch
      );
      expect(result.engineVersion).toBe("1.7.0");
    }
    await expect(
      callPrivateIntelligence(
        "/v1/incidents/execute",
        {},
        (async () =>
          new Response("{}", { status: 200 })) as typeof fetch
      )
    ).rejects.toThrow("Unsupported private intelligence route");
  });
});
