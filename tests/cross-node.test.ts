import { afterEach, describe, expect, it } from "vitest";
import {
  clearFleetRegistryForTests,
  fleetBundle,
  registerNode,
  type FleetSnapshot
} from "../src/fleet.js";
import { callPrivateIntelligence } from "../src/intelligence-client.js";

function snapshot(
  nodeId: string,
  health: "healthy" | "warning" | "critical"
): FleetSnapshot {
  return {
    nodeId,
    label: nodeId,
    tags: ["prod"],
    capturedAt: "2026-10-03T03:00:00.000Z",
    host: {
      hostname: nodeId,
      platform: "linux",
      operatingSystem: "Linux",
      release: "6.8",
      version: "Ubuntu",
      architecture: "x64",
      machine: "x86_64"
    },
    health: {
      health,
      uptimeSeconds: 1000,
      cpuUsagePercent: health === "healthy" ? 30 : 90,
      memoryUsagePercent: 60,
      maxDiskUsagePercent: 70,
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

describe("v1.6 public cross-node incident boundary", () => {
  it("builds a bounded registered fleet bundle for private analysis", () => {
    registerNode(snapshot("node-a", "warning"));
    registerNode(snapshot("node-b", "critical"));

    const bundle = fleetBundle();
    expect(bundle.nodes).toHaveLength(2);
    expect(bundle.nodes.map((node) => node.nodeId)).toEqual([
      "node-a",
      "node-b"
    ]);
  });

  it("allows only the fixed v1.6 cross-node routes", async () => {
    process.env.LOCALOPS_INTELLIGENCE_URL =
      "http://127.0.0.1:43123";
    process.env.LOCALOPS_INTELLIGENCE_TOKEN = "c".repeat(32);

    const allowed = [
      "/v1/fleet/incident-correlation",
      "/v1/fleet/incident-timeline",
      "/v1/fleet/shared-cause-analysis",
      "/v1/fleet/incident-scope"
    ];

    for (const route of allowed) {
      const result = await callPrivateIntelligence(
        route,
        { generatedAt: new Date().toISOString(), nodes: [] },
        (async () =>
          new Response(
            JSON.stringify({ engineVersion: "1.6.0" }),
            {
              status: 200,
              headers: { "content-type": "application/json" }
            }
          )) as typeof fetch
      );
      expect(result.engineVersion).toBe("1.6.0");
    }

    await expect(
      callPrivateIntelligence(
        "/v1/fleet/incident-execute",
        {},
        (async () =>
          new Response("{}", { status: 200 })) as typeof fetch
      )
    ).rejects.toThrow("Unsupported private intelligence route");
  });
});
