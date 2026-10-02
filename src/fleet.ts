import type { CommandRunner } from "./command.js";
import { defaultCommandRunner } from "./command.js";
import {
  certificateInventory,
  installedSoftware,
  localAdmins,
  scheduledTasks,
  startupPrograms
} from "./endpoint.js";
import { recentSecurityChanges } from "./events.js";
import { listServices, systemHealth, systemInfo } from "./system.js";

type Platform = NodeJS.Platform;

export type FleetPatch = {
  id: string;
  installedAt: string | null;
  source: string;
};

export type FleetSnapshot = {
  nodeId: string;
  label: string;
  tags: string[];
  capturedAt: string;
  host: {
    hostname: string;
    platform: string;
    operatingSystem: string;
    release: string;
    version: string;
    architecture: string;
    machine: string;
  };
  health: {
    health: "healthy" | "warning" | "critical";
    uptimeSeconds: number;
    cpuUsagePercent: number;
    memoryUsagePercent: number;
    maxDiskUsagePercent: number;
    reasons: string[];
  } | null;
  software: Array<{
    name: string;
    version: string | null;
    publisher: string | null;
    source: string;
  }>;
  patches: FleetPatch[];
  certificates: Array<{
    store: string;
    thumbprint: string;
    subject: string;
    issuer: string;
    notAfter: string | null;
  }>;
  services: Array<{
    name: string;
    status: string | null;
    startType: string | null;
  }>;
  admins: Array<{ name: string }>;
  startupPrograms: Array<{
    name: string;
    source: string;
    state: string | null;
  }>;
  scheduledTasks: Array<{
    name: string;
    path: string;
    state: string;
    source: string;
  }>;
  securitySummary: {
    recentChangeCount: number;
    categories: string[];
  };
  limitations: string[];
};

type RegistryEntry = {
  snapshot: FleetSnapshot;
  registeredAt: string;
  updatedAt: string;
};

const registry = new Map<string, RegistryEntry>();
const MAX_NODES = 500;

function safeNodeId(value: string): string {
  const nodeId = value.trim();
  if (!/^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$/.test(nodeId)) {
    throw new Error(
      "nodeId must be 1-128 characters using letters, numbers, dot, underscore, colon or hyphen."
    );
  }
  return nodeId;
}

function safeLabel(value: string | undefined, fallback: string): string {
  const label = (value ?? fallback).trim().slice(0, 128);
  if (!label) throw new Error("label cannot be empty.");
  return label;
}

function safeTags(tags: string[] | undefined): string[] {
  return [...new Set(
    (tags ?? [])
      .map((tag) => tag.trim())
      .filter((tag) => /^[A-Za-z0-9_.:-]{1,64}$/.test(tag))
  )].slice(0, 20);
}

function safeLimit(value: number | undefined, fallback: number, max: number) {
  const number = Number.isInteger(value) ? Number(value) : fallback;
  return Math.max(1, Math.min(number, max));
}

function normalizeDate(value: unknown): string | null {
  if (!value) return null;
  const date = new Date(String(value));
  return Number.isNaN(date.getTime()) ? null : date.toISOString();
}

async function windowsPatchInventory(
  limit: number,
  runner: CommandRunner
): Promise<FleetPatch[]> {
  const script =
    "Get-HotFix | Sort-Object InstalledOn -Descending | " +
    "Select-Object -First " + limit + " HotFixID,InstalledOn | " +
    "ConvertTo-Json -Compress";
  const result = await runner(
    "powershell.exe",
    ["-NoProfile", "-NonInteractive", "-Command", script],
    true
  );
  if (result.exitCode !== 0 || !result.stdout.trim()) return [];

  const parsed = JSON.parse(result.stdout);
  const items = Array.isArray(parsed) ? parsed : [parsed];
  return items.map((item: any) => ({
    id: String(item.HotFixID ?? ""),
    installedAt: normalizeDate(item.InstalledOn),
    source: "windows-hotfix"
  })).filter((item: FleetPatch) => item.id);
}

async function linuxPatchInventory(
  limit: number,
  runner: CommandRunner
): Promise<FleetPatch[]> {
  const kernel = await runner("uname", ["-r"], true);
  const patches: FleetPatch[] = [];
  if (kernel.exitCode === 0 && kernel.stdout.trim()) {
    patches.push({
      id: "kernel:" + kernel.stdout.trim().slice(0, 200),
      installedAt: null,
      source: "linux-kernel"
    });
  }

  const format = "$" + "{binary:Package}\t$" + "{Version}\n";
  const dpkg = await runner(
    "dpkg-query",
    ["-W", "-f=" + format, "linux-image*", "linux-headers*", "linux-libc-dev"],
    true
  );
  if (dpkg.exitCode === 0) {
    for (const line of dpkg.stdout.split(/\r?\n/).filter(Boolean)) {
      if (patches.length >= limit) break;
      const [name = "", version = ""] = line.split("\t");
      if (!name || !version) continue;
      patches.push({
        id: name + ":" + version,
        installedAt: null,
        source: "dpkg-kernel-package"
      });
    }
  }

  return patches.slice(0, limit);
}

export async function patchInventory(
  limit = 200,
  runner: CommandRunner = defaultCommandRunner,
  platform: Platform = process.platform
): Promise<FleetPatch[]> {
  const bounded = safeLimit(limit, 200, 500);
  return platform === "win32"
    ? windowsPatchInventory(bounded, runner)
    : linuxPatchInventory(bounded, runner);
}

async function capture<T>(
  label: string,
  operation: () => Promise<T>,
  fallback: T,
  limitations: string[]
): Promise<T> {
  try {
    return await operation();
  } catch (error) {
    limitations.push(
      label + " unavailable: " +
      (error instanceof Error ? error.message : String(error))
    );
    return fallback;
  }
}

export async function captureLocalNodeSnapshot(input?: {
  nodeId?: string;
  label?: string;
  tags?: string[];
  limit?: number;
}): Promise<FleetSnapshot> {
  const info = systemInfo();
  const nodeId = safeNodeId(input?.nodeId ?? info.hostname);
  const label = safeLabel(input?.label, info.hostname);
  const tags = safeTags(input?.tags);
  const limit = safeLimit(input?.limit, 200, 300);
  const limitations: string[] = [];

  const [
    health,
    softwareResult,
    patches,
    certificates,
    services,
    admins,
    startup,
    tasks,
    security
  ] = await Promise.all([
    capture("system health", () => systemHealth(), null, limitations),
    capture(
      "software inventory",
      () => installedSoftware(limit),
      { packageManager: "unknown", packages: [] },
      limitations
    ),
    capture("patch inventory", () => patchInventory(limit), [], limitations),
    capture("certificate inventory", () => certificateInventory(limit), [], limitations),
    capture("service inventory", () => listServices(limit), [], limitations),
    capture("administrator inventory", () => localAdmins(), [], limitations),
    capture("startup inventory", () => startupPrograms(limit), [], limitations),
    capture("scheduled task inventory", () => scheduledTasks(limit), [], limitations),
    capture(
      "security change summary",
      () => recentSecurityChanges(24, limit),
      {
        events: [],
        categories: [],
        limitation: "Recent security-change evidence unavailable."
      },
      limitations
    )
  ]);

  if (security.limitation) limitations.push(security.limitation);

  return {
    nodeId,
    label,
    tags,
    capturedAt: new Date().toISOString(),
    host: {
      hostname: info.hostname,
      platform: info.platform,
      operatingSystem: info.operatingSystem,
      release: info.release,
      version: info.version,
      architecture: info.architecture,
      machine: info.machine
    },
    health: health
      ? {
          health: health.health,
          uptimeSeconds: health.uptimeSeconds,
          cpuUsagePercent: health.cpuUsagePercent,
          memoryUsagePercent: health.memoryUsagePercent,
          maxDiskUsagePercent: health.maxDiskUsagePercent,
          reasons: health.reasons
        }
      : null,
    software: softwareResult.packages.slice(0, limit).map((item) => ({
      name: String(item.name ?? "").slice(0, 200),
      version: item.version ? String(item.version).slice(0, 100) : null,
      publisher: item.publisher ? String(item.publisher).slice(0, 200) : null,
      source: String(item.source ?? "unknown").slice(0, 100)
    })),
    patches: patches.slice(0, limit),
    certificates: certificates.slice(0, limit).map((item) => ({
      store: item.store.slice(0, 300),
      thumbprint: item.thumbprint.slice(0, 200),
      subject: item.subject.slice(0, 500),
      issuer: item.issuer.slice(0, 500),
      notAfter: item.notAfter
    })),
    services: services.slice(0, limit).map((item: any) => ({
      name: String(item.name ?? "").slice(0, 200),
      status: item.status
        ? String(item.status).slice(0, 100)
        : item.activeState
          ? String(item.activeState).slice(0, 100)
          : null,
      startType: item.startType ? String(item.startType).slice(0, 100) : null
    })),
    admins: admins.slice(0, 100).map((item: any) => ({
      name: String(item.name ?? "").slice(0, 300)
    })),
    startupPrograms: startup.slice(0, limit).map((item: any) => ({
      name: String(item.name ?? "").slice(0, 300),
      source: String(item.source ?? "unknown").slice(0, 300),
      state: item.state ? String(item.state).slice(0, 100) : null
    })),
    scheduledTasks: tasks.slice(0, limit).map((item: any) => ({
      name: String(item.name ?? "").slice(0, 300),
      path: String(item.path ?? "").slice(0, 300),
      state: String(item.state ?? "unknown").slice(0, 100),
      source: String(item.source ?? "unknown").slice(0, 100)
    })),
    securitySummary: {
      recentChangeCount: security.events.length,
      categories: [...new Set(security.events.map((event: any) =>
        String(event.category ?? "unknown")
      ))].slice(0, 50)
    },
    limitations: [...new Set(limitations.filter(Boolean))]
  };
}

function validateSnapshot(snapshot: FleetSnapshot): FleetSnapshot {
  const nodeId = safeNodeId(snapshot.nodeId);
  if (!snapshot.host || !snapshot.capturedAt) {
    throw new Error("snapshot must include host metadata and capturedAt.");
  }
  const captured = new Date(snapshot.capturedAt);
  if (Number.isNaN(captured.getTime())) {
    throw new Error("snapshot.capturedAt must be a valid timestamp.");
  }

  return {
    ...snapshot,
    nodeId,
    label: safeLabel(snapshot.label, nodeId),
    tags: safeTags(snapshot.tags),
    capturedAt: captured.toISOString(),
    software: (snapshot.software ?? []).slice(0, 300),
    patches: (snapshot.patches ?? []).slice(0, 300),
    certificates: (snapshot.certificates ?? []).slice(0, 300),
    services: (snapshot.services ?? []).slice(0, 300),
    admins: (snapshot.admins ?? []).slice(0, 100),
    startupPrograms: (snapshot.startupPrograms ?? []).slice(0, 300),
    scheduledTasks: (snapshot.scheduledTasks ?? []).slice(0, 300),
    limitations: [...new Set((snapshot.limitations ?? []).slice(0, 100))]
  };
}

export function registerNode(snapshot: FleetSnapshot) {
  const normalized = validateSnapshot(snapshot);
  const existing = registry.get(normalized.nodeId);
  if (!existing && registry.size >= MAX_NODES) {
    throw new Error("Fleet registry limit of 500 nodes has been reached.");
  }

  const now = new Date().toISOString();
  registry.set(normalized.nodeId, {
    snapshot: normalized,
    registeredAt: existing?.registeredAt ?? now,
    updatedAt: now
  });

  return {
    nodeId: normalized.nodeId,
    registered: !existing,
    updated: Boolean(existing),
    registeredAt: existing?.registeredAt ?? now,
    updatedAt: now,
    persistence:
      "v0.8 fleet registry is in-memory only and is cleared when the LocalOps process exits."
  };
}

export function listNodes() {
  const now = Date.now();
  return [...registry.values()]
    .map((entry) => {
      const captured = new Date(entry.snapshot.capturedAt).getTime();
      const ageSeconds = Number.isFinite(captured)
        ? Math.max(0, Math.floor((now - captured) / 1000))
        : null;
      return {
        nodeId: entry.snapshot.nodeId,
        label: entry.snapshot.label,
        tags: entry.snapshot.tags,
        hostname: entry.snapshot.host.hostname,
        platform: entry.snapshot.host.platform,
        release: entry.snapshot.host.release,
        health: entry.snapshot.health?.health ?? "unknown",
        capturedAt: entry.snapshot.capturedAt,
        ageSeconds,
        stale: ageSeconds === null || ageSeconds > 86400,
        limitationCount: entry.snapshot.limitations.length
      };
    })
    .sort((a, b) => a.nodeId.localeCompare(b.nodeId));
}

export function getNode(nodeId: string): FleetSnapshot {
  const key = safeNodeId(nodeId);
  const entry = registry.get(key);
  if (!entry) throw new Error("Node is not registered.");
  return entry.snapshot;
}

export function nodeHealth(nodeId: string) {
  const snapshot = getNode(nodeId);
  const ageSeconds = Math.max(
    0,
    Math.floor((Date.now() - new Date(snapshot.capturedAt).getTime()) / 1000)
  );
  return {
    nodeId: snapshot.nodeId,
    label: snapshot.label,
    capturedAt: snapshot.capturedAt,
    ageSeconds,
    stale: ageSeconds > 86400,
    health: snapshot.health?.health ?? "unknown",
    metrics: snapshot.health
      ? {
          cpuUsagePercent: snapshot.health.cpuUsagePercent,
          memoryUsagePercent: snapshot.health.memoryUsagePercent,
          maxDiskUsagePercent: snapshot.health.maxDiskUsagePercent,
          uptimeSeconds: snapshot.health.uptimeSeconds
        }
      : null,
    reasons: snapshot.health?.reasons ?? [],
    limitations: snapshot.limitations
  };
}

export function fleetHealth() {
  const nodes = listNodes();
  const counts = {
    total: nodes.length,
    healthy: nodes.filter((node) => node.health === "healthy").length,
    warning: nodes.filter((node) => node.health === "warning").length,
    critical: nodes.filter((node) => node.health === "critical").length,
    unknown: nodes.filter((node) => node.health === "unknown").length,
    stale: nodes.filter((node) => node.stale).length
  };

  let health: "healthy" | "warning" | "critical" | "unknown" = "unknown";
  if (counts.total > 0) {
    if (counts.critical > 0) health = "critical";
    else if (counts.warning > 0 || counts.stale > 0 || counts.unknown > 0) {
      health = "warning";
    } else {
      health = "healthy";
    }
  }

  return { health, counts, nodes };
}

export function fleetInventory(limit = 500) {
  const safe = safeLimit(limit, 500, 500);
  const nodes = listNodes().slice(0, safe);
  return {
    nodeCount: nodes.length,
    nodes,
    persistence:
      "v0.8 fleet registry is in-memory only and stores bounded normalized snapshots, not raw event logs."
  };
}

export function fleetPair(
  baselineNodeId: string,
  targetNodeId: string
) {
  const baseline = getNode(baselineNodeId);
  const target = getNode(targetNodeId);
  if (baseline.nodeId === target.nodeId) {
    throw new Error(
      "baselineNodeId and targetNodeId must refer to different nodes."
    );
  }
  return { baseline, target };
}

export function fleetBundle() {
  return {
    generatedAt: new Date().toISOString(),
    nodes: [...registry.values()]
      .map((entry) => entry.snapshot)
      .slice(0, MAX_NODES)
  };
}

export function clearFleetRegistryForTests() {
  registry.clear();
}
