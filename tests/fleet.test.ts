import { afterEach, describe, expect, it } from "vitest";
import type { CommandRunner } from "../src/command.js";
import {
  clearFleetRegistryForTests,
  fleetHealth,
  fleetInventory,
  fleetPair,
  listNodes,
  nodeHealth,
  patchInventory,
  registerNode,
  type FleetSnapshot
} from "../src/fleet.js";
import { callPrivateIntelligence } from "../src/intelligence-client.js";

function snapshot(
  nodeId: string,
  health: "healthy" | "warning" | "critical" = "healthy"
): FleetSnapshot {
  return {
    nodeId,
    label: nodeId,
    tags: ["test"],
    capturedAt: new Date().toISOString(),
    host: {
      hostname: nodeId,
      platform: "win32",
      operatingSystem: "Windows_NT",
      release: "10.0.26100",
      version: "Windows 11",
      architecture: "x64",
      machine: "x86_64"
    },
    health: {
      health,
      uptimeSeconds: 1000,
      cpuUsagePercent: 20,
      memoryUsagePercent: 30,
      maxDiskUsagePercent: 40,
      reasons: []
    },
    software: [
      {
        name: "Demo",
        version: "1.0.0",
        publisher: "OpsChugex",
        source: "test"
      }
    ],
    patches: [
      {
        id: "KB5000001",
        installedAt: null,
        source: "windows-hotfix"
      }
    ],
    certificates: [],
    services: [
      {
        name: "DemoService",
        status: "Running",
        startType: "Automatic"
      }
    ],
    admins: [{ name: "HOST\\Owner" }],
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

describe("v0.8 public fleet registry", () => {
  it("registers and updates nodes in memory", () => {
    const first = registerNode(snapshot("node-a"));
    const second = registerNode(snapshot("node-a", "warning"));

    expect(first.registered).toBe(true);
    expect(second.updated).toBe(true);
    expect(listNodes()).toHaveLength(1);
    expect(listNodes()[0].health).toBe("warning");
  });

  it("summarizes node and fleet health without contacting endpoints", () => {
    registerNode(snapshot("node-a", "healthy"));
    registerNode(snapshot("node-b", "critical"));

    expect(nodeHealth("node-b").health).toBe("critical");
    const fleet = fleetHealth();
    expect(fleet.health).toBe("critical");
    expect(fleet.counts.total).toBe(2);
    expect(fleet.counts.critical).toBe(1);
  });

  it("returns bounded fleet metadata rather than raw snapshot contents", () => {
    registerNode(snapshot("node-a"));
    const result = fleetInventory();

    expect(result.nodeCount).toBe(1);
    expect(JSON.stringify(result)).not.toContain("DemoService");
    expect(result.persistence).toContain("in-memory");
  });

  it("requires different baseline and target nodes", () => {
    registerNode(snapshot("node-a"));

    expect(() => fleetPair("node-a", "node-a")).toThrow(
      "must refer to different nodes"
    );
  });

  it("rejects unsafe node identifiers", () => {
    const bad = snapshot("node-a");
    bad.nodeId = "node-a; whoami";

    expect(() => registerNode(bad)).toThrow("nodeId must be");
  });

  it("collects bounded Windows patch metadata with fixed PowerShell", async () => {
    let command = "";
    const runner: CommandRunner = async (_exe, args) => {
      command = args.at(-1) ?? "";
      return {
        stdout: JSON.stringify({
          HotFixID: "KB5000001",
          InstalledOn: "2026-09-01T00:00:00Z"
        }),
        stderr: "",
        exitCode: 0
      };
    };

    const patches = await patchInventory(10, runner, "win32");

    expect(command).toContain("Get-HotFix");
    expect(patches).toHaveLength(1);
    expect(patches[0].id).toBe("KB5000001");
  });
});

describe("v0.8 private fleet route boundary", () => {
  it("allows fixed fleet-analysis routes", async () => {
    process.env.LOCALOPS_INTELLIGENCE_URL = "http://127.0.0.1:43123";
    process.env.LOCALOPS_INTELLIGENCE_TOKEN = "f".repeat(32);

    const routes = [
      "/v1/fleet/compare",
      "/v1/fleet/configuration-drift",
      "/v1/fleet/software-drift",
      "/v1/fleet/patch-drift",
      "/v1/fleet/certificate-drift",
      "/v1/fleet/security-drift"
    ];

    for (const route of routes) {
      const result = await callPrivateIntelligence(
        route,
        {},
        (async () =>
          new Response(JSON.stringify({ route }), {
            status: 200,
            headers: { "content-type": "application/json" }
          })) as typeof fetch
      );
      expect(result.route).toBe(route);
    }
  });

  it("rejects remote-execution fleet routes", async () => {
    process.env.LOCALOPS_INTELLIGENCE_URL = "http://127.0.0.1:43123";
    process.env.LOCALOPS_INTELLIGENCE_TOKEN = "g".repeat(32);

    await expect(
      callPrivateIntelligence(
        "/v1/fleet/execute",
        {},
        (async () => new Response("{}", { status: 200 })) as typeof fetch
      )
    ).rejects.toThrow("Unsupported private intelligence route");
  });
});
