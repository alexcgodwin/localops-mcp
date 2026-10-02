import { basename } from "node:path";
import type { CommandRunner } from "./command.js";
import { defaultCommandRunner } from "./command.js";
import { diskStatus } from "./system.js";

type Platform = NodeJS.Platform;

export type VmProvider =
  | "hyper-v"
  | "virtualbox"
  | "proxmox"
  | "libvirt"
  | "vmware";

export type VirtualMachine = {
  provider: VmProvider;
  id: string;
  name: string;
  state: string;
  cpuUsagePercent: number | null;
  memoryBytes: number | null;
  source: string;
};

export type VirtualMachineInventory = {
  providers: VmProvider[];
  virtualMachines: VirtualMachine[];
  limitations: string[];
};

function asArray(value: unknown): any[] {
  if (value === null || value === undefined || value === "") return [];
  return Array.isArray(value) ? value : [value];
}

function parseJson(value: string): any[] {
  if (!value.trim()) return [];
  return asArray(JSON.parse(value));
}

function bounded(value: number | undefined, fallback: number, max: number) {
  const number = Number.isInteger(value) ? Number(value) : fallback;
  return Math.max(1, Math.min(number, max));
}

function normalizeState(value: unknown): string {
  return String(value ?? "unknown").trim().toLowerCase() || "unknown";
}

async function windowsHyperV(
  limit: number,
  runner: CommandRunner,
  limitations: string[]
): Promise<VirtualMachine[]> {
  const script =
    "if (-not (Get-Command Get-VM -ErrorAction SilentlyContinue)) { exit 3 }; " +
    "Get-VM | Select-Object -First " + limit +
    " Name,Id,State,CPUUsage,MemoryAssigned | ConvertTo-Json -Compress";
  const result = await runner(
    "powershell.exe",
    ["-NoProfile", "-NonInteractive", "-Command", script],
    true
  );

  if (result.exitCode !== 0) {
    limitations.push("Hyper-V PowerShell module is not available or accessible.");
    return [];
  }

  try {
    return parseJson(result.stdout).map((vm) => ({
      provider: "hyper-v" as const,
      id: String(vm.Id ?? vm.Name ?? "").slice(0, 200),
      name: String(vm.Name ?? "").slice(0, 200),
      state: normalizeState(vm.State),
      cpuUsagePercent: Number.isFinite(Number(vm.CPUUsage))
        ? Number(vm.CPUUsage)
        : null,
      memoryBytes: Number.isFinite(Number(vm.MemoryAssigned))
        ? Number(vm.MemoryAssigned)
        : null,
      source: "hyper-v-powershell"
    })).filter((vm) => vm.id && vm.name);
  } catch {
    limitations.push("Hyper-V inventory returned output that could not be normalized.");
    return [];
  }
}

async function virtualBoxInventory(
  limit: number,
  runner: CommandRunner,
  limitations: string[]
): Promise<VirtualMachine[]> {
  const all = await runner("VBoxManage", ["list", "vms"], true);
  if (all.exitCode !== 0) {
    limitations.push("VirtualBox CLI is not available or accessible.");
    return [];
  }

  const running = await runner("VBoxManage", ["list", "runningvms"], true);
  const runningIds = new Set(
    running.exitCode === 0
      ? [...running.stdout.matchAll(/\{([^}]+)\}/g)].map((match) =>
          String(match[1]).toLowerCase()
        )
      : []
  );

  const output: VirtualMachine[] = [];
  for (const line of all.stdout.split(/\r?\n/).filter(Boolean)) {
    if (output.length >= limit) break;
    const match = line.match(/^"(.+)"\s+\{([^}]+)\}$/);
    if (!match) continue;
    const id = match[2];
    output.push({
      provider: "virtualbox",
      id,
      name: match[1].slice(0, 200),
      state: runningIds.has(id.toLowerCase()) ? "running" : "powered-off-or-saved",
      cpuUsagePercent: null,
      memoryBytes: null,
      source: "virtualbox-cli"
    });
  }
  return output;
}

async function vmwareInventory(
  limit: number,
  runner: CommandRunner,
  limitations: string[]
): Promise<VirtualMachine[]> {
  const result = await runner("vmrun", ["list"], true);
  if (result.exitCode !== 0) {
    limitations.push("VMware vmrun CLI is not available or accessible.");
    return [];
  }

  const lines = result.stdout.split(/\r?\n/).filter(Boolean).slice(1, limit + 1);
  return lines.map((value, index) => ({
    provider: "vmware" as const,
    id: "running-" + (index + 1),
    name: basename(value).replace(/\.vmx$/i, "").slice(0, 200) || "vmware-vm",
    state: "running",
    cpuUsagePercent: null,
    memoryBytes: null,
    source: "vmware-vmrun-running-list"
  }));
}

async function proxmoxInventory(
  limit: number,
  runner: CommandRunner,
  limitations: string[]
): Promise<VirtualMachine[]> {
  const result = await runner("qm", ["list"], true);
  if (result.exitCode !== 0) {
    limitations.push("Proxmox qm CLI is not available or accessible.");
    return [];
  }

  const output: VirtualMachine[] = [];
  for (const line of result.stdout.split(/\r?\n/).slice(1).filter(Boolean)) {
    if (output.length >= limit) break;
    const parts = line.trim().split(/\s+/);
    if (parts.length < 3) continue;
    output.push({
      provider: "proxmox",
      id: String(parts[0]).slice(0, 100),
      name: String(parts[1]).slice(0, 200),
      state: normalizeState(parts[2]),
      cpuUsagePercent: null,
      memoryBytes: null,
      source: "proxmox-qm"
    });
  }
  return output;
}

async function libvirtInventory(
  limit: number,
  runner: CommandRunner,
  limitations: string[]
): Promise<VirtualMachine[]> {
  const result = await runner("virsh", ["list", "--all"], true);
  if (result.exitCode !== 0) {
    limitations.push("libvirt virsh CLI is not available or accessible.");
    return [];
  }

  const output: VirtualMachine[] = [];
  for (const line of result.stdout.split(/\r?\n/).slice(2).filter(Boolean)) {
    if (output.length >= limit) break;
    const match = line.match(/^\s*(\S+)\s+(\S.*?)\s{2,}(\S.*)$/);
    if (!match) continue;
    const id = match[1] === "-" ? match[2] : match[1];
    output.push({
      provider: "libvirt",
      id: String(id).slice(0, 200),
      name: String(match[2]).trim().slice(0, 200),
      state: normalizeState(match[3]),
      cpuUsagePercent: null,
      memoryBytes: null,
      source: "libvirt-virsh"
    });
  }
  return output;
}

export async function virtualMachineInventory(
  limit = 100,
  runner: CommandRunner = defaultCommandRunner,
  platform: Platform = process.platform
): Promise<VirtualMachineInventory> {
  const safeLimit = bounded(limit, 100, 300);
  const limitations: string[] = [];
  const groups =
    platform === "win32"
      ? await Promise.all([
          windowsHyperV(safeLimit, runner, limitations),
          virtualBoxInventory(safeLimit, runner, limitations),
          vmwareInventory(safeLimit, runner, limitations)
        ])
      : await Promise.all([
          proxmoxInventory(safeLimit, runner, limitations),
          libvirtInventory(safeLimit, runner, limitations),
          virtualBoxInventory(safeLimit, runner, limitations),
          vmwareInventory(safeLimit, runner, limitations)
        ]);

  const virtualMachines = groups.flat().slice(0, safeLimit);
  const providers = [
    ...new Set(virtualMachines.map((vm) => vm.provider))
  ] as VmProvider[];

  return {
    providers,
    virtualMachines,
    limitations: [...new Set(limitations)]
  };
}

export async function vmHealth(
  identifier: string,
  runner: CommandRunner = defaultCommandRunner,
  platform: Platform = process.platform
) {
  const value = identifier.trim();
  if (!/^[A-Za-z0-9_.:@()\[\] -]{1,200}$/.test(value)) {
    throw new Error("identifier contains unsupported characters.");
  }

  const inventory = await virtualMachineInventory(300, runner, platform);
  const vm = inventory.virtualMachines.find(
    (item) =>
      item.id.toLowerCase() === value.toLowerCase() ||
      item.name.toLowerCase() === value.toLowerCase()
  );
  if (!vm) throw new Error("Virtual machine was not found in local provider inventory.");

  const state = vm.state.toLowerCase();
  const running = /running|online|active|powered on/.test(state)
    ? true
    : /off|stopped|shut|saved|paused/.test(state)
      ? false
      : null;

  return {
    ...vm,
    running,
    interpretation:
      "VM state is an observed provider state. A stopped or paused VM is not automatically unhealthy because that may be intentional.",
    limitations: inventory.limitations
  };
}

export async function storageCapacity(
  runner: CommandRunner = defaultCommandRunner,
  platform: Platform = process.platform
) {
  const volumes = await diskStatus(runner, platform);
  const totalBytes = volumes.reduce((sum, item) => sum + item.totalBytes, 0);
  const usedBytes = volumes.reduce((sum, item) => sum + item.usedBytes, 0);
  const freeBytes = volumes.reduce((sum, item) => sum + item.freeBytes, 0);
  return {
    volumeCount: volumes.length,
    totalBytes,
    usedBytes,
    freeBytes,
    usagePercent: Number(
      ((usedBytes / Math.max(1, totalBytes)) * 100).toFixed(2)
    ),
    volumes
  };
}

export async function storageHealth(
  runner: CommandRunner = defaultCommandRunner,
  platform: Platform = process.platform
) {
  const capacity = await storageCapacity(runner, platform);
  const limitations: string[] = [];
  let physicalDevices: Array<{
    name: string;
    health: string;
    operationalState: string;
    mediaType: string | null;
    sizeBytes: number | null;
  }> = [];

  if (platform === "win32") {
    const script =
      "if (-not (Get-Command Get-PhysicalDisk -ErrorAction SilentlyContinue)) { exit 3 }; " +
      "Get-PhysicalDisk | Select-Object FriendlyName,HealthStatus,OperationalStatus,MediaType,Size | ConvertTo-Json -Compress";
    const result = await runner(
      "powershell.exe",
      ["-NoProfile", "-NonInteractive", "-Command", script],
      true
    );
    if (result.exitCode === 0) {
      try {
        physicalDevices = parseJson(result.stdout).map((item) => ({
          name: String(item.FriendlyName ?? "physical-disk").slice(0, 200),
          health: String(item.HealthStatus ?? "Unknown").slice(0, 100),
          operationalState: Array.isArray(item.OperationalStatus)
            ? item.OperationalStatus.map(String).join(", ").slice(0, 200)
            : String(item.OperationalStatus ?? "Unknown").slice(0, 200),
          mediaType: item.MediaType ? String(item.MediaType).slice(0, 100) : null,
          sizeBytes: Number.isFinite(Number(item.Size)) ? Number(item.Size) : null
        }));
      } catch {
        limitations.push("Windows physical-disk health output could not be normalized.");
      }
    } else {
      limitations.push("Windows physical-disk health is unavailable or inaccessible.");
    }
  } else {
    limitations.push(
      "Linux v0.9 storage health uses filesystem utilization only unless a future hardware-health adapter is configured."
    );
  }

  const reasons: string[] = [];
  let health: "healthy" | "warning" | "critical" | "unknown" =
    capacity.volumeCount ? "healthy" : "unknown";

  for (const volume of capacity.volumes) {
    if (volume.usagePercent >= 95) {
      health = "critical";
      reasons.push(volume.mountPoint + " usage is at least 95%.");
    } else if (volume.usagePercent >= 85 && health !== "critical") {
      health = "warning";
      reasons.push(volume.mountPoint + " usage is at least 85%.");
    }
  }

  for (const device of physicalDevices) {
    if (/unhealthy|failed|critical|lost/i.test(device.health + " " + device.operationalState)) {
      health = "critical";
      reasons.push(device.name + " reports a critical/unhealthy physical-disk state.");
    } else if (
      !/healthy|ok|online|unknown/i.test(device.health + " " + device.operationalState) &&
      health !== "critical"
    ) {
      health = "warning";
      reasons.push(device.name + " reports a non-normal physical-disk state.");
    }
  }

  return {
    health,
    reasons,
    capacity,
    physicalDevices,
    limitations
  };
}

export async function upsHealth(
  runner: CommandRunner = defaultCommandRunner,
  platform: Platform = process.platform
) {
  const limitations: string[] = [];

  if (platform === "win32") {
    const script =
      "Get-CimInstance Win32_Battery -ErrorAction SilentlyContinue | " +
      "Select-Object Name,Status,BatteryStatus,EstimatedChargeRemaining,EstimatedRunTime | ConvertTo-Json -Compress";
    const result = await runner(
      "powershell.exe",
      ["-NoProfile", "-NonInteractive", "-Command", script],
      true
    );

    if (result.exitCode !== 0 || !result.stdout.trim()) {
      return {
        devices: [],
        health: "unknown" as const,
        interpretation:
          "No locally visible battery/UPS device was reported by Win32_Battery.",
        limitations: ["No Windows battery/UPS telemetry is available through Win32_Battery."]
      };
    }

    const devices = parseJson(result.stdout).slice(0, 20).map((item) => ({
      name: String(item.Name ?? "power-device").slice(0, 200),
      status: String(item.Status ?? "Unknown").slice(0, 100),
      batteryStatus: String(item.BatteryStatus ?? "Unknown").slice(0, 100),
      chargePercent: Number.isFinite(Number(item.EstimatedChargeRemaining))
        ? Number(item.EstimatedChargeRemaining)
        : null,
      estimatedRunTimeMinutes: Number.isFinite(Number(item.EstimatedRunTime))
        ? Number(item.EstimatedRunTime)
        : null,
      source: "windows-win32-battery"
    }));

    const low = devices.some((device) =>
      device.chargePercent !== null && device.chargePercent <= 20
    );
    return {
      devices,
      health: low ? "warning" as const : "healthy" as const,
      interpretation:
        "Windows may expose laptop batteries and UPS devices through the same battery class; LocalOps does not claim device type beyond available metadata.",
      limitations
    };
  }

  const enumerate = await runner("upower", ["-e"], true);
  if (enumerate.exitCode !== 0) {
    return {
      devices: [],
      health: "unknown" as const,
      interpretation:
        "No locally available UPower telemetry was found.",
      limitations: ["UPower is not installed or accessible."]
    };
  }

  const devices = [];
  for (const path of enumerate.stdout.split(/\r?\n/).filter(Boolean).slice(0, 20)) {
    const info = await runner("upower", ["-i", path], true);
    if (info.exitCode !== 0) continue;
    const percentage = info.stdout.match(/^\s*percentage:\s*([0-9.]+)%/mi);
    const state = info.stdout.match(/^\s*state:\s*(.+)$/mi);
    const model = info.stdout.match(/^\s*model:\s*(.+)$/mi);
    devices.push({
      name: String(model?.[1] ?? path.split("/").at(-1) ?? "power-device").trim().slice(0, 200),
      status: String(state?.[1] ?? "unknown").trim().slice(0, 100),
      batteryStatus: "unknown",
      chargePercent: percentage ? Number(percentage[1]) : null,
      estimatedRunTimeMinutes: null,
      source: "linux-upower"
    });
  }

  const low = devices.some((device) =>
    device.chargePercent !== null && device.chargePercent <= 20
  );
  return {
    devices,
    health: devices.length ? (low ? "warning" as const : "healthy" as const) : "unknown" as const,
    interpretation:
      "UPower telemetry is local only. Device type and health are limited to what the operating system exposes.",
    limitations
  };
}
