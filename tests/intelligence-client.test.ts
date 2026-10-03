import { afterEach, describe, expect, it } from "vitest";
import {
  callPrivateIntelligence,
  intelligenceStatus
} from "../src/intelligence-client.js";

const originalUrl = process.env.LOCALOPS_INTELLIGENCE_URL;
const originalToken = process.env.LOCALOPS_INTELLIGENCE_TOKEN;

function restore() {
  if (originalUrl === undefined) {
    delete process.env.LOCALOPS_INTELLIGENCE_URL;
  } else {
    process.env.LOCALOPS_INTELLIGENCE_URL = originalUrl;
  }

  if (originalToken === undefined) {
    delete process.env.LOCALOPS_INTELLIGENCE_TOKEN;
  } else {
    process.env.LOCALOPS_INTELLIGENCE_TOKEN = originalToken;
  }
}

afterEach(() => restore());

describe("private intelligence client boundary", () => {
  it("requires local authentication configuration", async () => {
    process.env.LOCALOPS_INTELLIGENCE_URL = "http://127.0.0.1:43123";
    delete process.env.LOCALOPS_INTELLIGENCE_TOKEN;

    let called = false;
    const fakeFetch = async () => {
      called = true;
      return new Response("{}", { status: 200 });
    };

    const result = await intelligenceStatus(fakeFetch as typeof fetch);

    expect(result.configured).toBe(false);
    expect(result.reachable).toBe(false);
    expect(called).toBe(false);
  });

  it("rejects non-loopback intelligence URLs", async () => {
    process.env.LOCALOPS_INTELLIGENCE_URL = "https://example.com/core";
    process.env.LOCALOPS_INTELLIGENCE_TOKEN = "x".repeat(32);

    const result = await intelligenceStatus(
      (async () => new Response("{}", { status: 200 })) as typeof fetch
    );

    expect(result.configured).toBe(false);
    expect(result.reachable).toBe(false);
    expect(result.limitation).toContain("loopback");
  });

  it("accepts authenticated loopback health responses", async () => {
    process.env.LOCALOPS_INTELLIGENCE_URL = "http://127.0.0.1:43123";
    process.env.LOCALOPS_INTELLIGENCE_TOKEN = "y".repeat(32);

    const fakeFetch = async (
      _input: string | URL | Request,
      init?: RequestInit
    ) => {
      expect(init?.headers).toMatchObject({
        authorization: "Bearer " + "y".repeat(32)
      });
      return new Response(
        JSON.stringify({ status: "ok", version: "0.6.0" }),
        {
          status: 200,
          headers: { "content-type": "application/json" }
        }
      );
    };

    const result = await intelligenceStatus(fakeFetch as typeof fetch);

    expect(result).toMatchObject({
      configured: true,
      reachable: true,
      version: "0.6.0"
    });
  });
  it("only permits the fixed private route set", async () => {
    process.env.LOCALOPS_INTELLIGENCE_URL = "http://127.0.0.1:43123";
    process.env.LOCALOPS_INTELLIGENCE_TOKEN = "z".repeat(32);

    await expect(
      callPrivateIntelligence(
        "/v1/not-supported",
        {},
        (async () => new Response("{}", { status: 200 })) as typeof fetch
      )
    ).rejects.toThrow("Unsupported private intelligence route");
  });

  it("posts evidence to an allowed route with local authentication", async () => {
    process.env.LOCALOPS_INTELLIGENCE_URL = "http://127.0.0.1:43123";
    process.env.LOCALOPS_INTELLIGENCE_TOKEN = "a".repeat(32);

    let receivedBody = "";
    const fakeFetch = async (
      input: string | URL | Request,
      init?: RequestInit
    ) => {
      expect(String(input)).toBe(
        "http://127.0.0.1:43123/v1/correlate/process"
      );
      expect(init?.method).toBe("POST");
      expect(init?.headers).toMatchObject({
        authorization: "Bearer " + "a".repeat(32),
        "content-type": "application/json"
      });
      receivedBody = String(init?.body ?? "");
      return new Response(
        JSON.stringify({
          engineVersion: "0.6.0",
          correlationType: "process-activity",
          generatedAt: "2026-10-02T11:00:00.000Z",
          signalCount: 0,
          signals: [],
          limitations: []
        }),
        {
          status: 200,
          headers: { "content-type": "application/json" }
        }
      );
    };

    const result = await callPrivateIntelligence(
      "/v1/correlate/process",
      { collectedAt: "now" },
      fakeFetch as typeof fetch
    );

    expect(receivedBody).toContain("collectedAt");
    expect(result.correlationType).toBe("process-activity");
  });

  it("does not echo local authentication material in connection errors", async () => {
    const authValue = "k".repeat(40);
    process.env.LOCALOPS_INTELLIGENCE_URL = "http://127.0.0.1:43123";
    process.env.LOCALOPS_INTELLIGENCE_TOKEN = authValue;

    let message = "";
    try {
      await callPrivateIntelligence(
        "/v1/timeline",
        {},
        (async () => {
          throw new Error("network failure " + authValue);
        }) as typeof fetch
      );
    } catch (error) {
      message = error instanceof Error ? error.message : String(error);
    }

    expect(message).toContain("not reachable");
    expect(message).not.toContain(authValue);
  });
});


describe("v1.3 topology route allowlist", () => {
  it("permits only the explicit topology analysis routes", async () => {
    process.env.LOCALOPS_INTELLIGENCE_URL = "http://127.0.0.1:43123";
    process.env.LOCALOPS_INTELLIGENCE_TOKEN = "m".repeat(32);

    let requested = "";
    const fakeFetch = async (
      input: string | URL | Request
    ) => {
      requested = String(input);
      return new Response(
        JSON.stringify({
          engineVersion: "1.3.0",
          generatedAt: new Date().toISOString(),
          sourceId: "a",
          targetId: "b",
          found: false,
          hopCount: null,
          nodePath: [],
          linkPath: [],
          unknownLinkCount: 0,
          bottleneckSpeedMbps: null,
          interpretation: "test",
          limitations: []
        }),
        {
          status: 200,
          headers: { "content-type": "application/json" }
        }
      );
    };

    const result = await callPrivateIntelligence(
      "/v1/topology/dependency-path",
      {
        bundle: {
          generatedAt: new Date().toISOString(),
          devices: [],
          links: []
        },
        sourceId: "a",
        targetId: "b"
      },
      fakeFetch as typeof fetch
    );

    expect(requested).toBe(
      "http://127.0.0.1:43123/v1/topology/dependency-path"
    );
    expect(result.engineVersion).toBe("1.3.0");
  });
});


describe("v1.4 remediation private-route allowlist", () => {
  it("permits workflow planning but rejects private remediation execution routes", async () => {
    process.env.LOCALOPS_INTELLIGENCE_URL =
      "http://127.0.0.1:43123";
    process.env.LOCALOPS_INTELLIGENCE_TOKEN = "n".repeat(32);

    let requested = "";
    const fakeFetch = async (
      input: string | URL | Request
    ) => {
      requested = String(input);
      return new Response(
        JSON.stringify({
          engineVersion: "1.4.0",
          generatedAt: new Date().toISOString(),
          leadingHypothesis: null,
          stepCount: 0,
          controlledStepCount: 0,
          readyForProposalCount: 0,
          executionGateSatisfiedCount: 0,
          manualStepCount: 0,
          steps: [],
          interpretation: "planning only",
          limitations: []
        }),
        {
          status: 200,
          headers: {
            "content-type": "application/json"
          }
        }
      );
    };

    const result = await callPrivateIntelligence(
      "/v1/remediation/workflow-plan",
      {
        bundle: {},
        executionPolicy: {}
      },
      fakeFetch as typeof fetch
    );

    expect(requested).toBe(
      "http://127.0.0.1:43123/v1/remediation/workflow-plan"
    );
    expect(result.engineVersion).toBe("1.4.0");

    await expect(
      callPrivateIntelligence(
        "/v1/remediation/execute",
        {},
        fakeFetch as typeof fetch
      )
    ).rejects.toThrow(
      "Unsupported private intelligence route"
    );
  });
});


describe("v2.2 investigation hypothesis route allowlist", () => {
  it("permits hypothesis balance analysis and rejects investigation execution", async () => {
    process.env.LOCALOPS_INTELLIGENCE_URL = "http://127.0.0.1:43123";
    process.env.LOCALOPS_INTELLIGENCE_TOKEN = "v".repeat(32);

    let requested = "";
    const fakeFetch = async (input: string | URL | Request) => {
      requested = String(input);
      return new Response(
        JSON.stringify({
          engineVersion: "2.2.0",
          generatedAt: new Date().toISOString(),
          sessionId: "inv_test",
          caseId: "inc_test",
          hypothesisCount: 0,
          conflictedHypothesisCount: 0,
          withoutEvidenceCount: 0,
          unverifiedEvidenceLinkCount: 0,
          hypotheses: [],
          interpretation: "evidence balance only",
          limitations: []
        }),
        {
          status: 200,
          headers: { "content-type": "application/json" }
        }
      );
    };

    const result = await callPrivateIntelligence(
      "/v2/investigations/hypothesis-balance",
      { session: {} },
      fakeFetch as typeof fetch
    );

    expect(requested).toBe(
      "http://127.0.0.1:43123/v2/investigations/hypothesis-balance"
    );
    expect(result.engineVersion).toBe("2.2.0");

    await expect(
      callPrivateIntelligence(
        "/v2/investigations/execute",
        {},
        fakeFetch as typeof fetch
      )
    ).rejects.toThrow("Unsupported private intelligence route");
  });
});
