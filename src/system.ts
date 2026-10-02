import os from "node:os";
import { setTimeout as delay } from "node:timers/promises";
import { CommandRunner, defaultCommandRunner } from "./command.js";

type Platform = NodeJS.Platform;

function asArray(value: unknown): any[] {
  if (value === null || value === undefined || value === "") return [];
  return Array.isArray(value) ? value : [value];
}

function parseJsonOutput(value: string): any[] {
  if (!value.trim()) return [];
  return asArray(JSON.parse(value));
}

function clampLimit(value: number | undefined, fallback: number, max: number): number {
  const number = Number.isInteger(value) ? Number(value) : fallback;
  return Math.max(1, Math.min(number, max));
}

function safeServiceName(name: string): string {
  const value = name.trim();
  if (!/^[A-Za-z0-9_.@:-]{1,128}$/.test(value)) {
    throw new Error("serviceName contains unsupported characters.");
  }
  return value;
}

function safePid(pid: number): number {
  if (!Number.isInteger(pid) || pid < 1 || pid > 2_147_483_647) {
    throw new Error("pid must be a positive integer.");
  }
  return pid;
}

export function systemInfo() {
  return {
    hostname: os.hostname(),
    platform: os.platform(),
    operatingSystem: os.type(),
    release: os.release(),
    version: os.version(),
    architecture: os.arch(),
    machine: os.machine(),
    logicalCpuCount: os.cpus().length,
    uptimeSeconds: Math.floor(os.uptime())
  };
}

export function uptimeInfo() {
  const uptimeSeconds = Math.floor(os.uptime());
  return {
    uptimeSeconds,
    uptimeHours: Number((uptimeSeconds / 3600).toFixed(2)),
    uptimeDays: Number((uptimeSeconds / 86400).toFixed(2))
  };
}

type CpuTimes = { idle: number; total: number };

function cpuSnapshot(): CpuTimes {
  let idle = 0;
  let total = 0;
  for (const cpu of os.cpus()) {
    idle += cpu.times.idle;
    total += Object.values(cpu.times).reduce((sum, value) => sum + value, 0);
  }
  return { idle, total };
}

export async function cpuStatus(sampleMs = 150) {
  const before = cpuSnapshot();
  await delay(Math.max(50, Math.min(sampleMs, 1000)));
  const after = cpuSnapshot();
  const idleDelta = after.idle - before.idle;
  const totalDelta = Math.max(1, after.total - before.total);
  const usagePercent = Number(((1 - idleDelta / totalDelta) * 100).toFixed(2));
  const cpus = os.cpus();
  return {
    usagePercent: Math.max(0, Math.min(100, usagePercent)),
    logicalCores: cpus.length,
    model: cpus[0]?.model ?? "unknown",
    speedMHz: cpus[0]?.speed ?? 0,
    loadAverage: os.loadavg().map((value) => Number(value.toFixed(2)))
  };
}

export function memoryStatus() {
  const totalBytes = os.totalmem();
  const freeBytes = os.freemem();
  const usedBytes = Math.max(0, totalBytes - freeBytes);
  return {
    totalBytes,
    usedBytes,
    freeBytes,
    usagePercent: Number(((usedBytes / Math.max(1, totalBytes)) * 100).toFixed(2))
  };
}

export function networkInterfaces() {
  const interfaces = os.networkInterfaces();
  return Object.entries(interfaces).flatMap(([name, entries]) =>
    (entries ?? []).map((entry) => ({
      name,
      address: entry.address,
      family: entry.family,
      cidr: entry.cidr ?? null,
      mac: entry.mac,
      internal: entry.internal
    }))
  );
}

export async function diskStatus(
  runner: CommandRunner = defaultCommandRunner,
  platform: Platform = process.platform
) {
  if (platform === "win32") {
    const script = "Get-CimInstance Win32_LogicalDisk -Filter \"DriveType=3\" | Select-Object DeviceID,VolumeName,Size,FreeSpace | ConvertTo-Json -Compress";
    const result = await runner("powershell.exe", ["-NoProfile", "-NonInteractive", "-Command", script]);
    return parseJsonOutput(result.stdout).map((disk) => {
      const totalBytes = Number(disk.Size ?? 0);
      const freeBytes = Number(disk.FreeSpace ?? 0);
      const usedBytes = Math.max(0, totalBytes - freeBytes);
      return {
        filesystem: String(disk.DeviceID ?? ""),
        label: disk.VolumeName ? String(disk.VolumeName) : null,
        mountPoint: String(disk.DeviceID ?? ""),
        totalBytes,
        usedBytes,
        freeBytes,
        usagePercent: Number(((usedBytes / Math.max(1, totalBytes)) * 100).toFixed(2))
      };
    });
  }

  const result = await runner("df", ["-Pk"]);
  return result.stdout.split(/\r?\n/).slice(1).filter(Boolean).map((line) => {
    const parts = line.trim().split(/\s+/);
    const blocks = Number(parts[1] ?? 0);
    const used = Number(parts[2] ?? 0);
    const available = Number(parts[3] ?? 0);
    return {
      filesystem: parts[0] ?? "",
      label: null,
      mountPoint: parts.slice(5).join(" "),
      totalBytes: blocks * 1024,
      usedBytes: used * 1024,
      freeBytes: available * 1024,
      usagePercent: Number(String(parts[4] ?? "0").replace("%", "")) || 0
    };
  });
}

export async function listProcesses(
  limit = 50,
  runner: CommandRunner = defaultCommandRunner,
  platform: Platform = process.platform
) {
  const safeLimit = clampLimit(limit, 50, 200);
  if (platform === "win32") {
    const script = `Get-Process | Sort-Object CPU -Descending | Select-Object -First ${safeLimit} Id,ProcessName,CPU,WorkingSet64 | ConvertTo-Json -Compress`;
    const result = await runner("powershell.exe", ["-NoProfile", "-NonInteractive", "-Command", script]);
    return parseJsonOutput(result.stdout).map((processInfo) => ({
      pid: Number(processInfo.Id),
      name: String(processInfo.ProcessName ?? ""),
      cpuSeconds: Number(processInfo.CPU ?? 0),
      memoryBytes: Number(processInfo.WorkingSet64 ?? 0)
    }));
  }

  const result = await runner("ps", ["-eo", "pid=,ppid=,user=,comm=,%cpu=,%mem=", "--sort=-%cpu"]);
  return result.stdout.split(/\r?\n/).filter(Boolean).slice(0, safeLimit).map((line) => {
    const parts = line.trim().split(/\s+/);
    return {
      pid: Number(parts[0]),
      parentPid: Number(parts[1]),
      user: parts[2] ?? "",
      name: parts[3] ?? "",
      cpuPercent: Number(parts[4] ?? 0),
      memoryPercent: Number(parts[5] ?? 0)
    };
  });
}

export async function inspectProcess(
  pid: number,
  runner: CommandRunner = defaultCommandRunner,
  platform: Platform = process.platform
) {
  const targetPid = safePid(pid);
  if (platform === "win32") {
    const script = `Get-Process -Id ${targetPid} -ErrorAction Stop | Select-Object Id,ProcessName,CPU,WorkingSet64,StartTime,Path | ConvertTo-Json -Compress`;
    const result = await runner("powershell.exe", ["-NoProfile", "-NonInteractive", "-Command", script]);
    const item = parseJsonOutput(result.stdout)[0];
    if (!item) throw new Error("Process not found.");
    return {
      pid: Number(item.Id),
      name: String(item.ProcessName ?? ""),
      cpuSeconds: Number(item.CPU ?? 0),
      memoryBytes: Number(item.WorkingSet64 ?? 0),
      startTime: item.StartTime ? String(item.StartTime) : null,
      executablePath: item.Path ? String(item.Path) : null
    };
  }

  const result = await runner("ps", ["-p", String(targetPid), "-o", "pid=,ppid=,user=,comm=,%cpu=,%mem=,etime="], true);
  if (result.exitCode !== 0 || !result.stdout.trim()) throw new Error("Process not found.");
  const parts = result.stdout.trim().split(/\s+/);
  return {
    pid: Number(parts[0]),
    parentPid: Number(parts[1]),
    user: parts[2] ?? "",
    name: parts[3] ?? "",
    cpuPercent: Number(parts[4] ?? 0),
    memoryPercent: Number(parts[5] ?? 0),
    elapsed: parts[6] ?? ""
  };
}

export async function listServices(
  limit = 100,
  runner: CommandRunner = defaultCommandRunner,
  platform: Platform = process.platform
) {
  const safeLimit = clampLimit(limit, 100, 300);
  if (platform === "win32") {
    const script = `Get-Service | Sort-Object Status,Name | Select-Object -First ${safeLimit} Name,DisplayName,Status,StartType | ConvertTo-Json -Compress`;
    const result = await runner("powershell.exe", ["-NoProfile", "-NonInteractive", "-Command", script]);
    return parseJsonOutput(result.stdout).map((service) => ({
      name: String(service.Name ?? ""),
      displayName: String(service.DisplayName ?? ""),
      status: String(service.Status ?? "Unknown"),
      startType: service.StartType ? String(service.StartType) : null
    }));
  }

  const result = await runner("systemctl", ["list-units", "--type=service", "--all", "--no-legend", "--no-pager", "--plain"]);
  return result.stdout.split(/\r?\n/).filter(Boolean).slice(0, safeLimit).map((line) => {
    const parts = line.trim().split(/\s+/);
    return {
      name: parts[0] ?? "",
      loadState: parts[1] ?? "",
      activeState: parts[2] ?? "",
      subState: parts[3] ?? "",
      description: parts.slice(4).join(" ")
    };
  });
}

export async function serviceStatus(
  serviceName: string,
  runner: CommandRunner = defaultCommandRunner,
  platform: Platform = process.platform
) {
  const name = safeServiceName(serviceName);
  if (platform === "win32") {
    const script = `Get-Service -Name '${name}' -ErrorAction Stop | Select-Object Name,DisplayName,Status,StartType | ConvertTo-Json -Compress`;
    const result = await runner("powershell.exe", ["-NoProfile", "-NonInteractive", "-Command", script]);
    const service = parseJsonOutput(result.stdout)[0];
    if (!service) throw new Error("Service not found.");
    return {
      name: String(service.Name ?? name),
      displayName: String(service.DisplayName ?? ""),
      status: String(service.Status ?? "Unknown"),
      startType: service.StartType ? String(service.StartType) : null
    };
  }

  const result = await runner("systemctl", [
    "show",
    name,
    "--no-pager",
    "--property=Id,Description,LoadState,ActiveState,SubState,UnitFileState"
  ], true);
  if (result.exitCode !== 0 || !result.stdout.trim()) throw new Error("Service not found.");
  const values = Object.fromEntries(
    result.stdout.split(/\r?\n/).filter(Boolean).map((line) => {
      const index = line.indexOf("=");
      return [line.slice(0, index), line.slice(index + 1)];
    })
  );
  return {
    name: values.Id ?? name,
    displayName: values.Description ?? "",
    loadState: values.LoadState ?? "",
    activeState: values.ActiveState ?? "",
    subState: values.SubState ?? "",
    startType: values.UnitFileState ?? ""
  };
}

export async function systemHealth(
  runner: CommandRunner = defaultCommandRunner,
  platform: Platform = process.platform
) {
  const [cpu, disks] = await Promise.all([cpuStatus(), diskStatus(runner, platform)]);
  const memory = memoryStatus();
  const maxDiskUsage = disks.reduce((max, disk) => Math.max(max, disk.usagePercent), 0);
  const reasons: string[] = [];
  let health: "healthy" | "warning" | "critical" = "healthy";

  if (cpu.usagePercent >= 95 || memory.usagePercent >= 95 || maxDiskUsage >= 98) {
    health = "critical";
  } else if (cpu.usagePercent >= 80 || memory.usagePercent >= 85 || maxDiskUsage >= 90) {
    health = "warning";
  }
  if (cpu.usagePercent >= 80) reasons.push(`CPU usage is ${cpu.usagePercent}%.`);
  if (memory.usagePercent >= 85) reasons.push(`Memory usage is ${memory.usagePercent}%.`);
  if (maxDiskUsage >= 90) reasons.push(`Highest disk usage is ${maxDiskUsage}%.`);

  return {
    health,
    hostname: os.hostname(),
    uptimeSeconds: Math.floor(os.uptime()),
    cpuUsagePercent: cpu.usagePercent,
    memoryUsagePercent: memory.usagePercent,
    maxDiskUsagePercent: maxDiskUsage,
    reasons
  };
}
