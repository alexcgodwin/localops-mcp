import { describe, expect, it } from "vitest";
import type { CommandRunner } from "../src/command.js";
import {
  diskStatus,
  inspectProcess,
  listProcesses,
  memoryStatus,
  networkInterfaces,
  serviceStatus,
  systemInfo,
  uptimeInfo
} from "../src/system.js";

function fakeRunner(stdout: string, exitCode = 0): CommandRunner {
  return async () => ({ stdout, stderr: "", exitCode });
}

describe("system discovery", () => {
  it("returns basic system metadata", () => {
    const result = systemInfo();
    expect(result.hostname.length).toBeGreaterThan(0);
    expect(result.logicalCpuCount).toBeGreaterThan(0);
    expect(result.uptimeSeconds).toBeGreaterThanOrEqual(0);
  });

  it("returns bounded memory utilization", () => {
    const result = memoryStatus();
    expect(result.totalBytes).toBeGreaterThan(0);
    expect(result.usagePercent).toBeGreaterThanOrEqual(0);
    expect(result.usagePercent).toBeLessThanOrEqual(100);
  });

  it("returns uptime values", () => {
    const result = uptimeInfo();
    expect(result.uptimeSeconds).toBeGreaterThanOrEqual(0);
    expect(result.uptimeHours).toBeGreaterThanOrEqual(0);
    expect(result.uptimeDays).toBeGreaterThanOrEqual(0);
  });

  it("returns normalized network interfaces", () => {
    const result = networkInterfaces();
    for (const item of result) {
      expect(item.name.length).toBeGreaterThan(0);
      expect(item.address.length).toBeGreaterThan(0);
    }
  });
});

describe("platform adapters", () => {
  it("normalizes Windows fixed disks", async () => {
    const runner = fakeRunner(JSON.stringify({
      DeviceID: "C:",
      VolumeName: "System",
      Size: 1000,
      FreeSpace: 250
    }));
    const disks = await diskStatus(runner, "win32");
    expect(disks).toHaveLength(1);
    expect(disks[0].filesystem).toBe("C:");
    expect(disks[0].usagePercent).toBe(75);
  });

  it("normalizes Linux df output", async () => {
    const runner = fakeRunner(
      "Filesystem 1024-blocks Used Available Capacity Mounted on\n/dev/sda1 1000 600 400 60% /"
    );
    const disks = await diskStatus(runner, "linux");
    expect(disks).toHaveLength(1);
    expect(disks[0].filesystem).toBe("/dev/sda1");
    expect(disks[0].usagePercent).toBe(60);
  });

  it("normalizes Windows process output", async () => {
    const runner = fakeRunner(JSON.stringify({
      Id: 123,
      ProcessName: "node",
      CPU: 2.5,
      WorkingSet64: 2048
    }));
    const processes = await listProcesses(10, runner, "win32");
    expect(processes[0]).toMatchObject({
      pid: 123,
      name: "node",
      cpuSeconds: 2.5,
      memoryBytes: 2048
    });
  });

  it("normalizes Linux service status", async () => {
    const runner = fakeRunner(
      "Id=ssh.service\nDescription=OpenSSH server\nLoadState=loaded\nActiveState=active\nSubState=running\nUnitFileState=enabled"
    );
    const service = await serviceStatus("ssh.service", runner, "linux");
    expect(service.name).toBe("ssh.service");
    expect(service.activeState).toBe("active");
  });
});

describe("input safety", () => {
  it("rejects unsafe service names before command execution", async () => {
    let called = false;
    const runner: CommandRunner = async () => {
      called = true;
      return { stdout: "", stderr: "", exitCode: 0 };
    };

    await expect(
      serviceStatus("ssh.service; rm -rf /", runner, "linux")
    ).rejects.toThrow("unsupported characters");
    expect(called).toBe(false);
  });

  it("rejects invalid process identifiers", async () => {
    await expect(inspectProcess(-1, fakeRunner(""), "linux"))
      .rejects.toThrow("positive integer");
  });
});
