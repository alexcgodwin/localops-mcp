import { McpServer } from "@modelcontextprotocol/server";
import * as z from "zod/v4";
import {
  backupProfileSummaries,
  collectBackupSnapshot,
  compareBackupGrowth
} from "./storage-backup.js";
import { callPrivateIntelligence } from "./intelligence-client.js";

const readOnlyAnnotations = {
  readOnlyHint: true,
  destructiveHint: false,
  idempotentHint: true,
  openWorldHint: false
} as const;

function toolResult(payload: Record<string, unknown>) {
  return {
    content: [{ type: "text" as const, text: JSON.stringify(payload, null, 2) }],
    structuredContent: payload
  };
}

const kindSchema = z.enum([
  "filesystem",
  "database-dump",
  "archive",
  "snapshot-export",
  "other"
]);

const profileInput = z.object({
  profileId: z.string()
    .min(1)
    .max(128)
    .regex(/^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$/)
});

const freshnessSchema = z.object({
  expectedIntervalHours: z.number().nullable(),
  latestAgeHours: z.number().nullable(),
  withinExpectedInterval: z.boolean().nullable()
});

const retentionSchema = z.object({
  retentionDays: z.number().nullable(),
  expiredFileCount: z.number().nullable(),
  expiredBytes: z.number().nullable()
});

const restorePointSchema = z.object({
  status: z.enum(["valid-metadata", "invalid", "unknown"]),
  artifact: z.string().nullable(),
  sizeBytes: z.number().nullable(),
  modifiedAt: z.string().nullable(),
  readable: z.boolean().nullable(),
  nonEmpty: z.boolean().nullable()
});

const capacitySchema = z.object({
  totalBytes: z.number().nullable(),
  freeBytes: z.number().nullable(),
  usedPercent: z.number().nullable()
});

const recoveryObjectivesSchema = z.object({
  rpoHours: z.number().nullable(),
  rpoMet: z.boolean().nullable(),
  rtoMinutes: z.number().nullable(),
  lastVerifiedRestoreAt: z.string().nullable(),
  lastRestoreDurationMinutes: z.number().nullable(),
  rtoMet: z.boolean().nullable()
});

const inventorySchema = z.object({
  fileCount: z.number(),
  totalBytes: z.number(),
  newestArtifact: z.string().nullable(),
  newestModifiedAt: z.string().nullable(),
  oldestModifiedAt: z.string().nullable(),
  filesLast24Hours: z.number(),
  bytesLast24Hours: z.number(),
  filesLast7Days: z.number(),
  bytesLast7Days: z.number(),
  scanTruncated: z.boolean()
});

const snapshotSchema = z.object({
  profileId: z.string(),
  kind: kindSchema,
  collectedAt: z.string(),
  inventory: inventorySchema,
  freshness: freshnessSchema,
  retention: retentionSchema,
  restorePoint: restorePointSchema,
  capacity: capacitySchema,
  recoveryObjectives: recoveryObjectivesSchema,
  limitations: z.array(z.string())
});

const healthSchema = z.object({
  engineVersion: z.string(),
  generatedAt: z.string(),
  profileId: z.string(),
  health: z.enum(["healthy", "warning", "critical", "unknown"]),
  score: z.number().nullable(),
  stale: z.boolean(),
  reasons: z.array(z.string()),
  interpretation: z.string(),
  limitations: z.array(z.string())
});

const readinessSchema = z.object({
  engineVersion: z.string(),
  generatedAt: z.string(),
  profileId: z.string(),
  readiness: z.enum(["ready", "degraded", "not-ready", "unknown"]),
  rpoMet: z.boolean().nullable(),
  rtoMet: z.boolean().nullable(),
  restoreVerificationRecent: z.boolean().nullable(),
  reasons: z.array(z.string()),
  interpretation: z.string(),
  limitations: z.array(z.string())
});

const riskSchema = z.object({
  engineVersion: z.string(),
  generatedAt: z.string(),
  profileId: z.string(),
  risk: z.enum(["low", "medium", "high", "unknown"]),
  signalCount: z.number(),
  signals: z.array(z.object({
    category: z.enum([
      "freshness",
      "restore-point",
      "capacity",
      "retention",
      "rpo",
      "rto",
      "restore-verification",
      "evidence"
    ]),
    severity: z.enum(["info", "warning", "high"]),
    evidence: z.string()
  })),
  interpretation: z.string(),
  limitations: z.array(z.string())
});

async function snapshot(profileId: string) {
  return collectBackupSnapshot(profileId);
}

export function registerStorageBackupTools(server: McpServer) {
  server.registerTool(
    "backup_profiles",
    {
      title: "Backup Profiles",
      description:
        "List configured named backup-profile metadata. MCP callers select a profile ID and cannot supply arbitrary filesystem paths.",
      annotations: readOnlyAnnotations,
      inputSchema: z.object({}),
      outputSchema: z.object({
        profiles: z.array(z.object({
          id: z.string(),
          rootPath: z.string(),
          kind: kindSchema,
          extensions: z.array(z.string()),
          expectedIntervalHours: z.number().nullable(),
          retentionDays: z.number().nullable(),
          rpoHours: z.number().nullable(),
          rtoMinutes: z.number().nullable(),
          lastVerifiedRestoreAt: z.string().nullable(),
          restoreDurationEvidenceConfigured: z.boolean()
        }))
      })
    },
    async () => toolResult({ profiles: backupProfileSummaries() })
  );

  server.registerTool(
    "backup_snapshot",
    {
      title: "Backup Snapshot",
      description:
        "Collect bounded read-only backup inventory, freshness, retention, restore-point metadata, filesystem capacity and recovery-objective evidence for one named profile.",
      annotations: readOnlyAnnotations,
      inputSchema: profileInput,
      outputSchema: snapshotSchema
    },
    async ({ profileId }) => toolResult(await snapshot(profileId))
  );

  server.registerTool(
    "backup_inventory",
    {
      title: "Backup Inventory",
      description:
        "Return bounded file-count, size and artifact-age evidence for one configured backup root without reading backup contents.",
      annotations: readOnlyAnnotations,
      inputSchema: profileInput,
      outputSchema: z.object({
        profileId: z.string(),
        kind: kindSchema,
        collectedAt: z.string(),
        inventory: inventorySchema,
        limitations: z.array(z.string())
      })
    },
    async ({ profileId }) => {
      const evidence = await snapshot(profileId);
      return toolResult({
        profileId: evidence.profileId,
        kind: evidence.kind,
        collectedAt: evidence.collectedAt,
        inventory: evidence.inventory,
        limitations: evidence.limitations
      });
    }
  );

  server.registerTool(
    "backup_freshness",
    {
      title: "Backup Freshness",
      description:
        "Compare the newest observed backup artifact with the profile's configured expected interval and RPO target.",
      annotations: readOnlyAnnotations,
      inputSchema: profileInput,
      outputSchema: z.object({
        profileId: z.string(),
        collectedAt: z.string(),
        freshness: freshnessSchema,
        rpoHours: z.number().nullable(),
        rpoMet: z.boolean().nullable(),
        limitations: z.array(z.string())
      })
    },
    async ({ profileId }) => {
      const evidence = await snapshot(profileId);
      return toolResult({
        profileId: evidence.profileId,
        collectedAt: evidence.collectedAt,
        freshness: evidence.freshness,
        rpoHours: evidence.recoveryObjectives.rpoHours,
        rpoMet: evidence.recoveryObjectives.rpoMet,
        limitations: evidence.limitations
      });
    }
  );

  server.registerTool(
    "backup_restore_point_validation",
    {
      title: "Backup Restore-Point Validation",
      description:
        "Perform non-destructive metadata validation of the newest backup artifact: presence, non-zero size and read access. This does not perform a restore or prove application-level recoverability.",
      annotations: readOnlyAnnotations,
      inputSchema: profileInput,
      outputSchema: z.object({
        profileId: z.string(),
        collectedAt: z.string(),
        restorePoint: restorePointSchema,
        interpretation: z.string(),
        limitations: z.array(z.string())
      })
    },
    async ({ profileId }) => {
      const evidence = await snapshot(profileId);
      return toolResult({
        profileId: evidence.profileId,
        collectedAt: evidence.collectedAt,
        restorePoint: evidence.restorePoint,
        interpretation:
          "Validation is intentionally non-destructive and checks metadata/readability only. A successful result is not proof that a full restore will succeed.",
        limitations: evidence.limitations
      });
    }
  );

  server.registerTool(
    "backup_retention",
    {
      title: "Backup Retention Evidence",
      description:
        "Report how many bounded backup artifacts are older than the configured retention target. No files are deleted or modified.",
      annotations: readOnlyAnnotations,
      inputSchema: profileInput,
      outputSchema: z.object({
        profileId: z.string(),
        collectedAt: z.string(),
        retention: retentionSchema,
        limitations: z.array(z.string())
      })
    },
    async ({ profileId }) => {
      const evidence = await snapshot(profileId);
      return toolResult({
        profileId: evidence.profileId,
        collectedAt: evidence.collectedAt,
        retention: evidence.retention,
        limitations: evidence.limitations
      });
    }
  );

  server.registerTool(
    "backup_storage_growth",
    {
      title: "Backup Storage Growth",
      description:
        "Compare the current bounded backup inventory with caller-supplied prior totals to calculate point-in-time growth evidence. LocalOps does not persist or invent historical trend data.",
      annotations: readOnlyAnnotations,
      inputSchema: profileInput.extend({
        baseline: z.object({
          collectedAt: z.string(),
          totalBytes: z.number().nonnegative(),
          fileCount: z.number().int().nonnegative()
        })
      }),
      outputSchema: z.object({
        profileId: z.string(),
        collectedAt: z.string(),
        baselineCollectedAt: z.string(),
        elapsedHours: z.number(),
        currentTotalBytes: z.number(),
        baselineTotalBytes: z.number(),
        byteDelta: z.number(),
        percentDelta: z.number().nullable(),
        currentFileCount: z.number(),
        baselineFileCount: z.number(),
        fileCountDelta: z.number(),
        projectedByteDeltaPerDay: z.number().nullable(),
        interpretation: z.string()
      })
    },
    async ({ profileId, baseline }) =>
      toolResult(compareBackupGrowth(await snapshot(profileId), baseline))
  );

  server.registerTool(
    "backup_snapshot_health",
    {
      title: "Backup Snapshot Health",
      description:
        "Ask the private LocalOps Intelligence Core to assess normalized backup freshness, restore-point, capacity, retention and recovery-objective evidence.",
      annotations: readOnlyAnnotations,
      inputSchema: profileInput,
      outputSchema: healthSchema
    },
    async ({ profileId }) =>
      toolResult(
        await callPrivateIntelligence(
          "/v1/backup/snapshot-health",
          await snapshot(profileId)
        )
      )
  );

  server.registerTool(
    "backup_recovery_readiness",
    {
      title: "Backup Recovery Readiness",
      description:
        "Analyze whether the submitted backup evidence supports the configured RPO/RTO and restore-verification objectives. No restore is executed.",
      annotations: readOnlyAnnotations,
      inputSchema: profileInput,
      outputSchema: readinessSchema
    },
    async ({ profileId }) =>
      toolResult(
        await callPrivateIntelligence(
          "/v1/backup/recovery-readiness",
          await snapshot(profileId)
        )
      )
  );

  server.registerTool(
    "backup_risk_correlation",
    {
      title: "Backup Risk Correlation",
      description:
        "Correlate normalized backup freshness, capacity, retention, restore-point and recovery-objective signals through the private LocalOps Intelligence Core.",
      annotations: readOnlyAnnotations,
      inputSchema: profileInput,
      outputSchema: riskSchema
    },
    async ({ profileId }) =>
      toolResult(
        await callPrivateIntelligence(
          "/v1/backup/risk-correlation",
          await snapshot(profileId)
        )
      )
  );
}
