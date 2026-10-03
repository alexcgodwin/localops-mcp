import {
  afterEach,
  describe,
  expect,
  it
} from "vitest";
import {
  clearFleetRegistryForTests,
  nodeHealthHistory,
  predictiveHealthBundle,
  registerNode,
  type FleetSnapshot
} from "../src/fleet.js";
import {
  callPrivateIntelligence
} from "../src/intelligence-client.js";

function snapshot(
  capturedAt: string,
  cpu: number,
  memory: number,
  disk: number
): FleetSnapshot {
  return {
    nodeId: "node-a",
    label: "Node A",
    tags: ["predictive"],
    capturedAt,
    host: {
      hostname: "node-a",
      platform: "win32",
      operatingSystem: "Windows_NT",
      release: "10.0",
      version: "Windows",
      architecture: "x64",
      machine: "x86_64"
    },
    health: {
      health: cpu >= 80 ? "warning" : "healthy",
      uptimeSeconds: 1000,
      cpuUsagePercent: cpu,
      memoryUsagePercent: memory,
      maxDiskUsagePercent: disk,
      reasons: []
    },
    software: [],
    patches: [],
    certificates: [],
    services: [],
    admins: [],
    startupPrograms: [],
    scheduledTasks: [],
    securitySummary: {
      recentChangeCount: 0,
      categories: []
    },
    limitations: []
  };
}

afterEach(() => {
  clearFleetRegistryForTests();
  delete process.env.LOCALOPS_INTELLIGENCE_URL;
  delete process.env.LOCALOPS_INTELLIGENCE_TOKEN;
});

describe("v1.5 public predictive health history", () => {
  it("retains distinct health observations for a registered node", () => {
    registerNode(
      snapshot("2026-10-02T20:00:00Z", 40, 50, 60)
    );
    registerNode(
      snapshot("2026-10-02T22:00:00Z", 50, 52, 61)
    );
    registerNode(
      snapshot("2026-10-03T00:00:00Z", 60, 54, 62)
    );

    const history = nodeHealthHistory("node-a");
    expect(history.observationCount).toBe(3);
    expect(history.observations[2].cpuUsagePercent).toBe(60);
    expect(history.persistence).toContain("in-memory");
  });

  it("deduplicates identical capture timestamps", () => {
    registerNode(
      snapshot("2026-10-02T20:00:00Z", 40, 50, 60)
    );
    registerNode(
      snapshot("2026-10-02T20:00:00Z", 55, 51, 61)
    );

    const history = nodeHealthHistory("node-a");
    expect(history.observationCount).toBe(1);
    expect(history.observations[0].cpuUsagePercent).toBe(55);
  });

  it("caps retained history at 96 observations per node", () => {
    const start = Date.parse("2026-09-28T00:00:00Z");
    for (let index = 0; index < 100; index += 1) {
      registerNode(
        snapshot(
          new Date(start + index * 3_600_000).toISOString(),
          20 + (index % 20),
          40,
          50
        )
      );
    }

    const history = nodeHealthHistory("node-a");
    expect(history.observationCount).toBe(96);
    expect(nodeHealthHistory("node-a", 5).observations).toHaveLength(5);
  });

  it("builds a bounded predictive bundle and rejects an empty fleet", () => {
    expect(() => predictiveHealthBundle(24)).toThrow(
      "No registered nodes"
    );

    registerNode(
      snapshot("2026-10-02T20:00:00Z", 40, 50, 60)
    );
    const bundle = predictiveHealthBundle(999, "node-a");

    expect(bundle.horizonHours).toBe(168);
    expect(bundle.nodes).toHaveLength(1);
    expect(bundle.nodes[0].observations).toHaveLength(1);
  });
});

describe("v1.5 private predictive route boundary", () => {
  it("allows only the fixed predictive health route", async () => {
    process.env.LOCALOPS_INTELLIGENCE_URL =
      "http://127.0.0.1:43123";
    process.env.LOCALOPS_INTELLIGENCE_TOKEN =
      "p".repeat(32);

    const result = await callPrivateIntelligence(
      "/v1/predictive/health",
      {},
      (async () =>
        new Response(
          JSON.stringify({ engineVersion: "1.5.0" }),
          {
            status: 200,
            headers: {
              "content-type": "application/json"
            }
          }
        )) as typeof fetch
    );

    expect(result.engineVersion).toBe("1.5.0");

    await expect(
      callPrivateIntelligence(
        "/v1/predictive/execute",
        {},
        (async () =>
          new Response("{}", { status: 200 })) as typeof fetch
      )
    ).rejects.toThrow("Unsupported private intelligence route");
  });
});
