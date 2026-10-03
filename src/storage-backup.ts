import { open, readdir, stat, statfs } from "node:fs/promises";
import {
  basename,
  extname,
  isAbsolute,
  resolve
} from "node:path";

export type BackupKind =
  | "filesystem"
  | "database-dump"
  | "archive"
  | "snapshot-export"
  | "other";

export type BackupProfile = {
  id: string;
  rootPath: string;
  kind: BackupKind;
  extensions: string[];
  expectedIntervalHours: number | null;
  retentionDays: number | null;
  rpoHours: number | null;
  rtoMinutes: number | null;
  lastVerifiedRestoreAt: string | null;
  lastRestoreDurationMinutes: number | null;
};

export type BackupSnapshot = {
  profileId: string;
  kind: BackupKind;
  collectedAt: string;
  inventory: {
    fileCount: number;
    totalBytes: number;
    newestArtifact: string | null;
    newestModifiedAt: string | null;
    oldestModifiedAt: string | null;
    filesLast24Hours: number;
    bytesLast24Hours: number;
    filesLast7Days: number;
    bytesLast7Days: number;
    scanTruncated: boolean;
  };
  freshness: {
    expectedIntervalHours: number | null;
    latestAgeHours: number | null;
    withinExpectedInterval: boolean | null;
  };
  retention: {
    retentionDays: number | null;
    expiredFileCount: number | null;
    expiredBytes: number | null;
  };
  restorePoint: {
    status: "valid-metadata" | "invalid" | "unknown";
    artifact: string | null;
    sizeBytes: number | null;
    modifiedAt: string | null;
    readable: boolean | null;
    nonEmpty: boolean | null;
  };
  capacity: {
    totalBytes: number | null;
    freeBytes: number | null;
    usedPercent: number | null;
  };
  recoveryObjectives: {
    rpoHours: number | null;
    rpoMet: boolean | null;
    rtoMinutes: number | null;
    lastVerifiedRestoreAt: string | null;
    lastRestoreDurationMinutes: number | null;
    rtoMet: boolean | null;
  };
  limitations: string[];
};

export type BackupGrowthBaseline = {
  collectedAt: string;
  totalBytes: number;
  fileCount: number;
};

export type BackupGrowthEvidence = {
  profileId: string;
  collectedAt: string;
  baselineCollectedAt: string;
  elapsedHours: number;
  currentTotalBytes: number;
  baselineTotalBytes: number;
  byteDelta: number;
  percentDelta: number | null;
  currentFileCount: number;
  baselineFileCount: number;
  fileCountDelta: number;
  projectedByteDeltaPerDay: number | null;
  interpretation: string;
};

type ScannedFile = {
  path: string;
  name: string;
  size: number;
  mtimeMs: number;
};

const MAX_PROFILES = 50;
const MAX_FILES = 5000;
const MAX_DEPTH = 16;
const MAX_EXTENSIONS = 20;

function safeId(value: unknown): string {
  const id = String(value ?? "").trim();
  if (!/^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$/.test(id)) {
    throw new Error("Backup profile id contains unsupported characters.");
  }
  return id;
}

function numberOrNull(
  value: unknown,
  field: string,
  min: number,
  max: number
): number | null {
  if (value === undefined || value === null || value === "") return null;
  const number = Number(value);
  if (!Number.isFinite(number) || number < min || number > max) {
    throw new Error(field + " must be between " + min + " and " + max + ".");
  }
  return number;
}

function isoOrNull(value: unknown, field: string): string | null {
  if (value === undefined || value === null || value === "") return null;
  const text = String(value).trim();
  if (!Number.isFinite(new Date(text).getTime())) {
    throw new Error(field + " must be a valid ISO-compatible timestamp.");
  }
  return new Date(text).toISOString();
}

function normalizeExtensions(value: unknown): string[] {
  if (value === undefined || value === null) return [];
  if (!Array.isArray(value) || value.length > MAX_EXTENSIONS) {
    throw new Error("extensions must be an array of at most 20 values.");
  }

  const normalized = value.map((item) => {
    const raw = String(item).trim().toLowerCase();
    const extension = raw.startsWith(".") ? raw : "." + raw;
    if (!/^\.[a-z0-9][a-z0-9._-]{0,31}$/.test(extension)) {
      throw new Error("Backup profile extension contains unsupported characters.");
    }
    return extension;
  });

  return [...new Set(normalized)];
}

function safeRootPath(value: unknown): string {
  const raw = String(value ?? "").trim();
  if (!raw || raw.length > 1024 || raw.includes("\0") || !isAbsolute(raw)) {
    throw new Error("Backup profile rootPath must be an absolute local path.");
  }
  return resolve(raw);
}

export function backupProfiles(
  env: NodeJS.ProcessEnv = process.env
): BackupProfile[] {
  const raw = String(env.LOCALOPS_BACKUP_PROFILES ?? "").trim();
  if (!raw) return [];

  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    throw new Error("LOCALOPS_BACKUP_PROFILES must contain valid JSON.");
  }

  if (!Array.isArray(parsed) || parsed.length > MAX_PROFILES) {
    throw new Error(
      "LOCALOPS_BACKUP_PROFILES must be an array of at most 50 profiles."
    );
  }

  const ids = new Set<string>();
  return parsed.map((item) => {
    if (!item || typeof item !== "object") {
      throw new Error("Each backup profile must be an object.");
    }

    const input = item as Record<string, unknown>;
    const id = safeId(input.id);
    if (ids.has(id)) {
      throw new Error("Duplicate backup profile id: " + id);
    }
    ids.add(id);

    const kind = String(input.kind ?? "filesystem") as BackupKind;
    if (![
      "filesystem",
      "database-dump",
      "archive",
      "snapshot-export",
      "other"
    ].includes(kind)) {
      throw new Error("Unsupported backup kind for profile " + id + ".");
    }

    const rtoMinutes = numberOrNull(
      input.rtoMinutes,
      "rtoMinutes",
      1,
      525600
    );
    const lastRestoreDurationMinutes = numberOrNull(
      input.lastRestoreDurationMinutes,
      "lastRestoreDurationMinutes",
      0,
      525600
    );

    return {
      id,
      rootPath: safeRootPath(input.rootPath),
      kind,
      extensions: normalizeExtensions(input.extensions),
      expectedIntervalHours: numberOrNull(
        input.expectedIntervalHours,
        "expectedIntervalHours",
        0.01,
        87600
      ),
      retentionDays: numberOrNull(
        input.retentionDays,
        "retentionDays",
        0.01,
        36500
      ),
      rpoHours: numberOrNull(
        input.rpoHours,
        "rpoHours",
        0.01,
        87600
      ),
      rtoMinutes,
      lastVerifiedRestoreAt: isoOrNull(
        input.lastVerifiedRestoreAt,
        "lastVerifiedRestoreAt"
      ),
      lastRestoreDurationMinutes
    };
  });
}

export function backupProfileSummaries(
  env: NodeJS.ProcessEnv = process.env
) {
  return backupProfiles(env).map((profile) => ({
    id: profile.id,
    rootPath: profile.rootPath,
    kind: profile.kind,
    extensions: profile.extensions,
    expectedIntervalHours: profile.expectedIntervalHours,
    retentionDays: profile.retentionDays,
    rpoHours: profile.rpoHours,
    rtoMinutes: profile.rtoMinutes,
    lastVerifiedRestoreAt: profile.lastVerifiedRestoreAt,
    restoreDurationEvidenceConfigured:
      profile.lastRestoreDurationMinutes !== null
  }));
}

function getProfile(
  profileId: string,
  env: NodeJS.ProcessEnv
): BackupProfile {
  const id = safeId(profileId);
  const profile = backupProfiles(env).find((item) => item.id === id);
  if (!profile) throw new Error("Backup profile not found.");
  return profile;
}

function matchesExtensions(
  name: string,
  extensions: string[]
): boolean {
  if (extensions.length === 0) return true;
  return extensions.includes(extname(name).toLowerCase());
}

async function scanFiles(
  profile: BackupProfile
): Promise<{ files: ScannedFile[]; truncated: boolean; limitations: string[] }> {
  const files: ScannedFile[] = [];
  const limitations: string[] = [];
  const queue: Array<{ path: string; depth: number }> = [
    { path: profile.rootPath, depth: 0 }
  ];
  let truncated = false;
  let symlinkCount = 0;
  let depthLimited = false;

  while (queue.length > 0 && files.length < MAX_FILES) {
    const current = queue.shift()!;
    let entries;
    try {
      entries = await readdir(current.path, { withFileTypes: true });
    } catch {
      limitations.push(
        "A directory could not be read during the bounded backup scan."
      );
      continue;
    }

    for (const entry of entries) {
      if (entry.isSymbolicLink()) {
        symlinkCount += 1;
        continue;
      }

      const entryPath = resolve(current.path, entry.name);
      if (entry.isDirectory()) {
        if (current.depth < MAX_DEPTH) {
          queue.push({ path: entryPath, depth: current.depth + 1 });
        } else {
          depthLimited = true;
        }
        continue;
      }

      if (!entry.isFile() || !matchesExtensions(entry.name, profile.extensions)) {
        continue;
      }

      try {
        const fileStat = await stat(entryPath);
        files.push({
          path: entryPath,
          name: basename(entryPath),
          size: fileStat.size,
          mtimeMs: fileStat.mtimeMs
        });
      } catch {
        limitations.push(
          "A candidate backup artifact changed or became unreadable during collection."
        );
      }

      if (files.length >= MAX_FILES) {
        truncated = true;
        break;
      }
    }
  }

  if (queue.length > 0) truncated = true;
  if (truncated) {
    limitations.push(
      "Backup inventory reached the 5,000-file scan limit; totals are bounded evidence."
    );
  }
  if (depthLimited) {
    limitations.push(
      "Backup inventory reached the maximum directory depth of 16."
    );
  }
  if (symlinkCount > 0) {
    limitations.push(
      "Symbolic links are not followed by the backup inventory collector."
    );
  }

  return { files, truncated, limitations };
}

async function validateRestorePoint(
  newest: ScannedFile | null
): Promise<BackupSnapshot["restorePoint"]> {
  if (!newest) {
    return {
      status: "unknown",
      artifact: null,
      sizeBytes: null,
      modifiedAt: null,
      readable: null,
      nonEmpty: null
    };
  }

  const modifiedAt = new Date(newest.mtimeMs).toISOString();
  if (newest.size <= 0) {
    return {
      status: "invalid",
      artifact: newest.name,
      sizeBytes: newest.size,
      modifiedAt,
      readable: true,
      nonEmpty: false
    };
  }

  let handle: Awaited<ReturnType<typeof open>> | null = null;
  try {
    handle = await open(newest.path, "r");
    const buffer = Buffer.alloc(1);
    const result = await handle.read(buffer, 0, 1, 0);
    const readable = result.bytesRead === 1;
    return {
      status: readable ? "valid-metadata" : "invalid",
      artifact: newest.name,
      sizeBytes: newest.size,
      modifiedAt,
      readable,
      nonEmpty: true
    };
  } catch {
    return {
      status: "invalid",
      artifact: newest.name,
      sizeBytes: newest.size,
      modifiedAt,
      readable: false,
      nonEmpty: true
    };
  } finally {
    await handle?.close().catch(() => undefined);
  }
}

async function capacityForRoot(
  rootPath: string
): Promise<BackupSnapshot["capacity"]> {
  try {
    const fs = await statfs(rootPath);
    const blockSize = Number(fs.bsize);
    const totalBytes = Number(fs.blocks) * blockSize;
    const freeBytes = Number(fs.bavail) * blockSize;
    const usedPercent =
      totalBytes > 0
        ? Number((((totalBytes - freeBytes) / totalBytes) * 100).toFixed(2))
        : null;
    return { totalBytes, freeBytes, usedPercent };
  } catch {
    return { totalBytes: null, freeBytes: null, usedPercent: null };
  }
}

export async function collectBackupSnapshot(
  profileId: string,
  env: NodeJS.ProcessEnv = process.env,
  nowMs = Date.now()
): Promise<BackupSnapshot> {
  const profile = getProfile(profileId, env);

  const root = await stat(profile.rootPath).catch(() => null);
  if (!root?.isDirectory()) {
    throw new Error("Configured backup root is not an accessible directory.");
  }

  const scan = await scanFiles(profile);
  const sorted = [...scan.files].sort((a, b) => b.mtimeMs - a.mtimeMs);
  const newest = sorted[0] ?? null;
  const oldest = sorted.at(-1) ?? null;

  const dayMs = 24 * 60 * 60 * 1000;
  const recent24 = scan.files.filter((file) => nowMs - file.mtimeMs <= dayMs);
  const recent7d = scan.files.filter((file) => nowMs - file.mtimeMs <= 7 * dayMs);

  const latestAgeHours = newest
    ? Number(((nowMs - newest.mtimeMs) / (60 * 60 * 1000)).toFixed(3))
    : null;
  if (latestAgeHours !== null && latestAgeHours < -0.083) {
    scan.limitations.push(
      "Newest backup artifact is materially future-dated relative to the collector clock."
    );
  }

  const normalizedAge =
    latestAgeHours === null ? null : Math.max(0, latestAgeHours);
  const retentionCutoff =
    profile.retentionDays === null
      ? null
      : nowMs - profile.retentionDays * dayMs;
  const expired =
    retentionCutoff === null
      ? []
      : scan.files.filter((file) => file.mtimeMs < retentionCutoff);

  const restorePoint = await validateRestorePoint(newest);
  const capacity = await capacityForRoot(profile.rootPath);

  if (capacity.totalBytes === null) {
    scan.limitations.push(
      "Filesystem capacity evidence is unavailable for the configured backup root."
    );
  }
  return {
    profileId: profile.id,
    kind: profile.kind,
    collectedAt: new Date(nowMs).toISOString(),
    inventory: {
      fileCount: scan.files.length,
      totalBytes: scan.files.reduce((sum, file) => sum + file.size, 0),
      newestArtifact: newest?.name ?? null,
      newestModifiedAt: newest
        ? new Date(newest.mtimeMs).toISOString()
        : null,
      oldestModifiedAt: oldest
        ? new Date(oldest.mtimeMs).toISOString()
        : null,
      filesLast24Hours: recent24.length,
      bytesLast24Hours: recent24.reduce((sum, file) => sum + file.size, 0),
      filesLast7Days: recent7d.length,
      bytesLast7Days: recent7d.reduce((sum, file) => sum + file.size, 0),
      scanTruncated: scan.truncated
    },
    freshness: {
      expectedIntervalHours: profile.expectedIntervalHours,
      latestAgeHours: normalizedAge,
      withinExpectedInterval:
        profile.expectedIntervalHours === null || normalizedAge === null
          ? null
          : normalizedAge <= profile.expectedIntervalHours
    },
    retention: {
      retentionDays: profile.retentionDays,
      expiredFileCount:
        profile.retentionDays === null ? null : expired.length,
      expiredBytes:
        profile.retentionDays === null
          ? null
          : expired.reduce((sum, file) => sum + file.size, 0)
    },
    restorePoint,
    capacity,
    recoveryObjectives: {
      rpoHours: profile.rpoHours,
      rpoMet:
        profile.rpoHours === null || normalizedAge === null
          ? null
          : normalizedAge <= profile.rpoHours,
      rtoMinutes: profile.rtoMinutes,
      lastVerifiedRestoreAt: profile.lastVerifiedRestoreAt,
      lastRestoreDurationMinutes: profile.lastRestoreDurationMinutes,
      rtoMet:
        profile.rtoMinutes === null ||
        profile.lastRestoreDurationMinutes === null
          ? null
          : profile.lastRestoreDurationMinutes <= profile.rtoMinutes
    },
    limitations: [...new Set(scan.limitations)]
  };
}

export function compareBackupGrowth(
  snapshot: BackupSnapshot,
  baseline: BackupGrowthBaseline
): BackupGrowthEvidence {
  const baselineTime = new Date(baseline.collectedAt).getTime();
  const currentTime = new Date(snapshot.collectedAt).getTime();
  if (!Number.isFinite(baselineTime) || baselineTime >= currentTime) {
    throw new Error(
      "Growth baseline collectedAt must be a valid timestamp before the current snapshot."
    );
  }
  if (!Number.isFinite(baseline.totalBytes) || baseline.totalBytes < 0) {
    throw new Error("Growth baseline totalBytes must be a non-negative number.");
  }
  if (!Number.isInteger(baseline.fileCount) || baseline.fileCount < 0) {
    throw new Error("Growth baseline fileCount must be a non-negative integer.");
  }

  const elapsedHours = (currentTime - baselineTime) / (60 * 60 * 1000);
  const byteDelta = snapshot.inventory.totalBytes - baseline.totalBytes;
  const percentDelta =
    baseline.totalBytes > 0
      ? Number(((byteDelta / baseline.totalBytes) * 100).toFixed(2))
      : null;
  const projectedByteDeltaPerDay =
    elapsedHours > 0
      ? Math.round((byteDelta / elapsedHours) * 24)
      : null;

  return {
    profileId: snapshot.profileId,
    collectedAt: snapshot.collectedAt,
    baselineCollectedAt: new Date(baselineTime).toISOString(),
    elapsedHours: Number(elapsedHours.toFixed(3)),
    currentTotalBytes: snapshot.inventory.totalBytes,
    baselineTotalBytes: baseline.totalBytes,
    byteDelta,
    percentDelta,
    currentFileCount: snapshot.inventory.fileCount,
    baselineFileCount: baseline.fileCount,
    fileCountDelta: snapshot.inventory.fileCount - baseline.fileCount,
    projectedByteDeltaPerDay,
    interpretation:
      "Growth evidence compares two point-in-time inventory totals. It is not a durable trend forecast and does not account for artifacts deleted between samples."
  };
}
