import { afterEach, describe, expect, it } from "vitest";
import type { CommandRunner } from "../src/command.js";
import {
  storageCapacity,
  storageHealth,
  upsHealth,
  virtualMachineInventory,
  vmHealth
} from "../src/infrastructure.js";
import { callPrivateIntelligence } from "../src/intelligence-client.js";

const originalUrl = process.env.LOCALOPS_INTELLIGENCE_URL;
const originalToken = process.env.LOCALOPS_INTELLIGENCE_TOKEN;

afterEach(() => {
  if (originalUrl === undefined) delete process.env.LOCALOPS_INTELLIGENCE_URL;
  else process.env.LOCALOPS_INTELLIGENCE_URL = originalUrl;

  if (originalToken === undefined) delete process.env.LOCALOPS_INTELLIGENCE_TOKEN;
  else process.env.LOCALOPS_INTELLIGENCE_TOKEN = originalToken;
});

describe("v0.9 virtualization adapters", () => {
  it("normalizes Windows Hyper-V inventory with fixed read-only PowerShell", async () => {
    const runner: CommandRunner = async (exe, args) => {
      if (exe === "powershell.exe") {
        expect(args.at(-1)).toContain("Get-VM");
        return {
          stdout: JSON.stringify({
            Name: "DemoVM",
            Id: "vm-1",
            State: "Running",
            CPUUsage: 12,
            MemoryAssigned: 4096
          }),
          stderr: "",
          exitCode: 0
        };
      }
      return { stdout: "", stderr: "", exitCode: 1 };
    };

    const result = await virtualMachineInventory(10, runner, "win32");

    expect(result.virtualMachines).toHaveLength(1);
    expect(result.virtualMachines[0]).toMatchObject({
      provider: "hyper-v",
      id: "vm-1",
      name: "DemoVM",
      state: "running"
    });
  });

  it("normalizes Proxmox qm inventory on Linux", async () => {
    const runner: CommandRunner = async (exe) => {
      if (exe === "qm") {
        return {
          stdout:
            " VMID NAME STATUS MEM(MB) BOOTDISK(GB) PID\n" +
            " 101 web01 running 2048 32.00 1000\n",
          stderr: "",
          exitCode: 0
        };
      }
      return { stdout: "", stderr: "", exitCode: 1 };
    };

    const result = await virtualMachineInventory(10, runner, "linux");

    expect(result.virtualMachines.some((vm) =>
      vm.provider === "proxmox" &&
      vm.id === "101" &&
      vm.name === "web01" &&
      vm.state === "running"
    )).toBe(true);
  });

  it("looks up VM health from local inventory without mutation", async () => {
    const runner: CommandRunner = async (exe) => {
      if (exe === "powershell.exe") {
        return {
          stdout: JSON.stringify({
            Name: "DemoVM",
            Id: "vm-1",
            State: "Off",
            CPUUsage: 0,
            MemoryAssigned: 0
          }),
          stderr: "",
          exitCode: 0
        };
      }
      return { stdout: "", stderr: "", exitCode: 1 };
    };

    const result = await vmHealth("DemoVM", runner, "win32");

    expect(result.running).toBe(false);
    expect(result.interpretation).toContain("not automatically unhealthy");
  });

  it("rejects unsafe VM identifiers before provider collection", async () => {
    let called = false;
    const runner: CommandRunner = async () => {
      called = true;
      return { stdout: "", stderr: "", exitCode: 0 };
    };

    await expect(
      vmHealth("DemoVM; command", runner, "win32")
    ).rejects.toThrow("unsupported characters");
    expect(called).toBe(false);
  });
});

describe("v0.9 storage and local power telemetry", () => {
  it("summarizes Windows storage capacity", async () => {
    const runner: CommandRunner = async (_exe, args) => {
      const script = args.at(-1) ?? "";
      if (script.includes("Win32_LogicalDisk")) {
        return {
          stdout: JSON.stringify({
            DeviceID: "C:",
            VolumeName: "System",
            Size: 1000,
            FreeSpace: 250
          }),
          stderr: "",
          exitCode: 0
        };
      }
      return { stdout: "", stderr: "", exitCode: 1 };
    };

    const result = await storageCapacity(runner, "win32");

    expect(result.totalBytes).toBe(1000);
    expect(result.usedBytes).toBe(750);
    expect(result.usagePercent).toBe(75);
  });

  it("combines volume utilization with Windows physical-disk health metadata", async () => {
    const runner: CommandRunner = async (_exe, args) => {
      const script = args.at(-1) ?? "";
      if (script.includes("Win32_LogicalDisk")) {
        return {
          stdout: JSON.stringify({
            DeviceID: "C:",
            VolumeName: "System",
            Size: 1000,
            FreeSpace: 100
          }),
          stderr: "",
          exitCode: 0
        };
      }
      if (script.includes("Get-PhysicalDisk")) {
        return {
          stdout: JSON.stringify({
            FriendlyName: "Disk 0",
            HealthStatus: "Healthy",
            OperationalStatus: "OK",
            MediaType: "SSD",
            Size: 1000
          }),
          stderr: "",
          exitCode: 0
        };
      }
      return { stdout: "", stderr: "", exitCode: 1 };
    };

    const result = await storageHealth(runner, "win32");

    expect(result.health).toBe("warning");
    expect(result.physicalDevices[0].health).toBe("Healthy");
    expect(result.reasons.some((reason) =>
      reason.includes("at least 85%")
    )).toBe(true);
  });

  it("reads local Windows battery/UPS telemetry without network polling", async () => {
    const runner: CommandRunner = async (_exe, args) => {
      expect(args.at(-1)).toContain("Win32_Battery");
      return {
        stdout: JSON.stringify({
          Name: "Local Power Device",
          Status: "OK",
          BatteryStatus: 2,
          EstimatedChargeRemaining: 15,
          EstimatedRunTime: 30
        }),
        stderr: "",
        exitCode: 0
      };
    };

    const result = await upsHealth(runner, "win32");

    expect(result.health).toBe("warning");
    expect(result.devices[0].chargePercent).toBe(15);
    expect(result.interpretation).toContain("does not claim device type");
  });
});

describe("v0.9 private infrastructure route boundary", () => {
  it("allows only the fixed infrastructure analysis routes", async () => {
    process.env.LOCALOPS_INTELLIGENCE_URL = "http://127.0.0.1:43123";
    process.env.LOCALOPS_INTELLIGENCE_TOKEN = "i".repeat(32);

    for (const route of [
      "/v1/infrastructure/device-health",
      "/v1/infrastructure/topology"
    ]) {
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

  it("rejects infrastructure scan or execution routes", async () => {
    process.env.LOCALOPS_INTELLIGENCE_URL = "http://127.0.0.1:43123";
    process.env.LOCALOPS_INTELLIGENCE_TOKEN = "j".repeat(32);

    for (const route of [
      "/v1/infrastructure/scan",
      "/v1/infrastructure/execute"
    ]) {
      await expect(
        callPrivateIntelligence(
          route,
          {},
          (async () => new Response("{}", { status: 200 })) as typeof fetch
        )
      ).rejects.toThrow("Unsupported private intelligence route");
    }
  });
});
