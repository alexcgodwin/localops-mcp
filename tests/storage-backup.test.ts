import {
  afterEach,
  describe,
  expect,
  it
} from "vitest";
import {
  mkdtemp,
  rm,
  utimes,
  writeFile
} from "node:fs/promises";
import os from "node:os";
import { join } from "node:path";
import {
  backupProfiles,
  collectBackupSnapshot,
  compareBackupGrowth
} from "../src/storage-backup.js";

const originalProfiles = process.env.LOCALOPS_BACKUP_PROFILES;
const tempDirs: string[] = [];

afterEach(async () => {
  if (originalProfiles === undefined) {
    delete process.env.LOCALOPS_BACKUP_PROFILES;
  } else {
    process.env.LOCALOPS_BACKUP_PROFILES = originalProfiles;
  }

  await Promise.all(
    tempDirs.splice(0).map((directory) =>
      rm(directory, { recursive: true, force: true })
    )
  );
});

async function tempRoot() {
  const directory = await mkdtemp(
    join(os.tmpdir(), "localops-backup-test-")
  );
  tempDirs.push(directory);
  return directory;
}

describe("v1.2 backup profiles", () => {
  it("parses named absolute backup roots and recovery objectives", async () => {
    const root = await tempRoot();
    process.env.LOCALOPS_BACKUP_PROFILES = JSON.stringify([
      {
        id: "daily-db",
        rootPath: root,
        kind: "database-dump",
        extensions: ["bak", ".zip"],
        expectedIntervalHours: 24,
        retentionDays: 30,
        rpoHours: 24,
        rtoMinutes: 120,
        lastVerifiedRestoreAt: "2026-10-01T12:00:00Z",
        lastRestoreDurationMinutes: 45
      }
    ]);

    const profiles = backupProfiles();
    expect(profiles).toHaveLength(1);
    expect(profiles[0]).toMatchObject({
      id: "daily-db",
      kind: "database-dump",
      extensions: [".bak", ".zip"],
      rpoHours: 24,
      rtoMinutes: 120
    });
  });

  it("rejects malformed profile configuration", () => {
    process.env.LOCALOPS_BACKUP_PROFILES = "{not-json";
    expect(() => backupProfiles()).toThrow(
      "LOCALOPS_BACKUP_PROFILES must contain valid JSON"
    );
  });
});

describe("v1.2 backup snapshot collection", () => {
  it("collects bounded inventory, freshness, retention and recovery evidence", async () => {
    const root = await tempRoot();
    const now = new Date("2026-10-02T20:00:00.000Z");
    const fresh = join(root, "daily-20261002.bak");
    const old = join(root, "daily-20260920.bak");
    const ignored = join(root, "notes.txt");

    await writeFile(fresh, Buffer.alloc(1024, 1));
    await writeFile(old, Buffer.alloc(256, 2));
    await writeFile(ignored, "ignore");

    const freshTime = new Date(now.getTime() - 60 * 60 * 1000);
    const oldTime = new Date(now.getTime() - 12 * 24 * 60 * 60 * 1000);
    await utimes(fresh, freshTime, freshTime);
    await utimes(old, oldTime, oldTime);

    process.env.LOCALOPS_BACKUP_PROFILES = JSON.stringify([
      {
        id: "daily-db",
        rootPath: root,
        kind: "database-dump",
        extensions: [".bak"],
        expectedIntervalHours: 4,
        retentionDays: 7,
        rpoHours: 2,
        rtoMinutes: 60,
        lastVerifiedRestoreAt: "2026-10-01T20:00:00.000Z",
        lastRestoreDurationMinutes: 40
      }
    ]);

    const result = await collectBackupSnapshot(
      "daily-db",
      process.env,
      now.getTime()
    );

    expect(result.inventory.fileCount).toBe(2);
    expect(result.inventory.totalBytes).toBe(1280);
    expect(result.inventory.newestArtifact).toBe("daily-20261002.bak");
    expect(result.freshness.withinExpectedInterval).toBe(true);
    expect(result.retention.expiredFileCount).toBe(1);
    expect(result.restorePoint.status).toBe("valid-metadata");
    expect(result.recoveryObjectives.rpoMet).toBe(true);
    expect(result.recoveryObjectives.rtoMet).toBe(true);
  });

  it("marks an empty newest artifact invalid without attempting a restore", async () => {
    const root = await tempRoot();
    await writeFile(join(root, "empty.zip"), "");

    process.env.LOCALOPS_BACKUP_PROFILES = JSON.stringify([
      {
        id: "archive",
        rootPath: root,
        kind: "archive",
        extensions: [".zip"]
      }
    ]);

    const result = await collectBackupSnapshot("archive");
    expect(result.restorePoint).toMatchObject({
      status: "invalid",
      readable: true,
      nonEmpty: false
    });
  });

  it("rejects arbitrary profile ids that are not configured", async () => {
    const root = await tempRoot();
    process.env.LOCALOPS_BACKUP_PROFILES = JSON.stringify([
      { id: "known", rootPath: root }
    ]);

    await expect(
      collectBackupSnapshot("other")
    ).rejects.toThrow("Backup profile not found");
  });
});

describe("v1.2 backup growth evidence", () => {
  it("compares current totals with an explicit earlier baseline", () => {
    const result = compareBackupGrowth(
      {
        profileId: "daily",
        kind: "filesystem",
        collectedAt: "2026-10-02T20:00:00.000Z",
        inventory: {
          fileCount: 12,
          totalBytes: 1500,
          newestArtifact: "new.bak",
          newestModifiedAt: "2026-10-02T19:00:00.000Z",
          oldestModifiedAt: "2026-09-01T00:00:00.000Z",
          filesLast24Hours: 1,
          bytesLast24Hours: 500,
          filesLast7Days: 4,
          bytesLast7Days: 900,
          scanTruncated: false
        },
        freshness: {
          expectedIntervalHours: 24,
          latestAgeHours: 1,
          withinExpectedInterval: true
        },
        retention: {
          retentionDays: 30,
          expiredFileCount: 1,
          expiredBytes: 100
        },
        restorePoint: {
          status: "valid-metadata",
          artifact: "new.bak",
          sizeBytes: 500,
          modifiedAt: "2026-10-02T19:00:00.000Z",
          readable: true,
          nonEmpty: true
        },
        capacity: {
          totalBytes: 10000,
          freeBytes: 8000,
          usedPercent: 20
        },
        recoveryObjectives: {
          rpoHours: 24,
          rpoMet: true,
          rtoMinutes: null,
          lastVerifiedRestoreAt: null,
          lastRestoreDurationMinutes: null,
          rtoMet: null
        },
        limitations: []
      },
      {
        collectedAt: "2026-10-01T20:00:00.000Z",
        totalBytes: 1000,
        fileCount: 10
      }
    );

    expect(result.byteDelta).toBe(500);
    expect(result.percentDelta).toBe(50);
    expect(result.fileCountDelta).toBe(2);
    expect(result.projectedByteDeltaPerDay).toBe(500);
  });
});
