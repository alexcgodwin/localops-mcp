import { afterEach, describe, expect, it } from "vitest";
import { callPrivateIntelligence } from "../src/intelligence-client.js";

const originalUrl = process.env.LOCALOPS_INTELLIGENCE_URL;
const originalToken = process.env.LOCALOPS_INTELLIGENCE_TOKEN;

afterEach(() => {
  if (originalUrl === undefined) delete process.env.LOCALOPS_INTELLIGENCE_URL;
  else process.env.LOCALOPS_INTELLIGENCE_URL = originalUrl;

  if (originalToken === undefined) delete process.env.LOCALOPS_INTELLIGENCE_TOKEN;
  else process.env.LOCALOPS_INTELLIGENCE_TOKEN = originalToken;
});

describe("v0.7 private root-cause routes", () => {
  it("allows the fixed root-cause ranking route", async () => {
    process.env.LOCALOPS_INTELLIGENCE_URL = "http://127.0.0.1:43123";
    process.env.LOCALOPS_INTELLIGENCE_TOKEN = "r".repeat(32);

    const fakeFetch = async (
      input: string | URL | Request,
      init?: RequestInit
    ) => {
      expect(String(input)).toBe(
        "http://127.0.0.1:43123/v1/root-cause/rank"
      );
      expect(init?.method).toBe("POST");
      return new Response(JSON.stringify({
        engineVersion: "0.7.0",
        generatedAt: "2026-10-02T12:00:00.000Z",
        candidateCount: 0,
        candidates: [],
        interpretation: "No defensible hypothesis.",
        limitations: []
      }), {
        status: 200,
        headers: { "content-type": "application/json" }
      });
    };

    const result = await callPrivateIntelligence(
      "/v1/root-cause/rank",
      { collectedAt: "now" },
      fakeFetch as typeof fetch
    );

    expect(result.engineVersion).toBe("0.7.0");
  });

  it("allows all seven fixed v0.7 analysis routes", async () => {
    process.env.LOCALOPS_INTELLIGENCE_URL = "http://127.0.0.1:43123";
    process.env.LOCALOPS_INTELLIGENCE_TOKEN = "s".repeat(32);

    const routes = [
      "/v1/root-cause/rank",
      "/v1/root-cause/confidence",
      "/v1/root-cause/evidence-chain",
      "/v1/root-cause/investigation",
      "/v1/root-cause/change-trigger",
      "/v1/root-cause/blast-radius",
      "/v1/root-cause/remediation"
    ];

    for (const route of routes) {
      const response = await callPrivateIntelligence(
        route,
        {},
        (async () =>
          new Response(JSON.stringify({ route }), {
            status: 200,
            headers: { "content-type": "application/json" }
          })) as typeof fetch
      );
      expect(response.route).toBe(route);
    }
  });

  it("still rejects unregistered root-cause routes", async () => {
    process.env.LOCALOPS_INTELLIGENCE_URL = "http://127.0.0.1:43123";
    process.env.LOCALOPS_INTELLIGENCE_TOKEN = "t".repeat(32);

    await expect(
      callPrivateIntelligence(
        "/v1/root-cause/execute",
        {},
        (async () => new Response("{}", { status: 200 })) as typeof fetch
      )
    ).rejects.toThrow("Unsupported private intelligence route");
  });
});
