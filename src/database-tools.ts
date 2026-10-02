import { McpServer } from "@modelcontextprotocol/server";
import * as z from "zod/v4";
import {
  collectDatabaseSnapshot,
  databaseProfileSummaries
} from "./database.js";
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

const engineSchema = z.enum([
  "postgresql",
  "mysql",
  "sqlserver",
  "redis"
]);

const profileInput = z.object({
  profileId: z.string()
    .min(1)
    .max(128)
    .regex(/^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$/)
});

const snapshotSchema = z.object({
  profileId: z.string(),
  engine: engineSchema,
  collectedAt: z.string(),
  inventory: z.object({
    version: z.string().nullable(),
    database: z.string().nullable(),
    principal: z.string().nullable()
  }),
  connections: z.object({
    active: z.number().nullable(),
    total: z.number().nullable(),
    max: z.number().nullable(),
    blocked: z.number().nullable()
  }),
  capacity: z.object({
    databaseBytes: z.number().nullable(),
    memoryBytes: z.number().nullable(),
    maxMemoryBytes: z.number().nullable()
  }),
  replication: z.object({
    role: z.string().nullable(),
    replicaCount: z.number().nullable(),
    lagSeconds: z.number().nullable(),
    state: z.string().nullable()
  }),
  locks: z.object({
    waiting: z.number().nullable(),
    granted: z.number().nullable()
  }),
  queryPressure: z.object({
    longRunning: z.number().nullable(),
    oldestSeconds: z.number().nullable(),
    operationsPerSecond: z.number().nullable(),
    rejectedConnections: z.number().nullable()
  }),
  limitations: z.array(z.string())
});

async function snapshot(profileId: string) {
  return collectDatabaseSnapshot(profileId);
}

export function registerDatabaseTools(server: McpServer) {
  server.registerTool(
    "database_profiles",
    {
      title: "Database Profiles",
      description:
        "List configured read-only database profile metadata. Password values and secret environment-variable names are never returned.",
      annotations: readOnlyAnnotations,
      inputSchema: z.object({}),
      outputSchema: z.object({
        profiles: z.array(z.object({
          id: z.string(),
          engine: engineSchema,
          host: z.string(),
          port: z.number(),
          database: z.string().nullable(),
          user: z.string().nullable(),
          integratedAuth: z.boolean(),
          tls: z.boolean(),
          credentialConfigured: z.boolean()
        }))
      })
    },
    async () =>
      toolResult({
        profiles: databaseProfileSummaries()
      })
  );

  server.registerTool(
    "database_snapshot",
    {
      title: "Database Snapshot",
      description:
        "Collect a bounded normalized read-only telemetry snapshot for one configured database profile using fixed client queries. No arbitrary SQL or connection string is accepted.",
      annotations: readOnlyAnnotations,
      inputSchema: profileInput,
      outputSchema: snapshotSchema
    },
    async ({ profileId }) =>
      toolResult(await snapshot(profileId))
  );

  server.registerTool(
    "database_health",
    {
      title: "Database Health",
      description:
        "Collect a normalized database snapshot and ask the private LocalOps Intelligence Core for an evidence-based operational health summary. The result is not a data-integrity or security-compromise verdict.",
      annotations: readOnlyAnnotations,
      inputSchema: profileInput,
      outputSchema: z.object({
        engineVersion: z.string(),
        generatedAt: z.string(),
        profileId: z.string(),
        engine: engineSchema,
        health: z.enum(["healthy", "warning", "critical", "unknown"]),
        stale: z.boolean(),
        score: z.number().nullable(),
        reasons: z.array(z.string()),
        interpretation: z.string(),
        limitations: z.array(z.string())
      })
    },
    async ({ profileId }) => {
      const evidence = await snapshot(profileId);
      return toolResult(
        await callPrivateIntelligence("/v1/database/health", evidence)
      );
    }
  );

  server.registerTool(
    "database_capacity",
    {
      title: "Database Capacity Evidence",
      description:
        "Return bounded database-size or memory-capacity evidence available from the configured engine. LocalOps does not invent free-space or growth risk when the engine does not expose a quota.",
      annotations: readOnlyAnnotations,
      inputSchema: profileInput,
      outputSchema: z.object({
        profileId: z.string(),
        engine: engineSchema,
        collectedAt: z.string(),
        capacity: z.object({
          databaseBytes: z.number().nullable(),
          memoryBytes: z.number().nullable(),
          maxMemoryBytes: z.number().nullable()
        }),
        interpretation: z.string(),
        limitations: z.array(z.string())
      })
    },
    async ({ profileId }) => {
      const evidence = await snapshot(profileId);
      return toolResult({
        profileId: evidence.profileId,
        engine: evidence.engine,
        collectedAt: evidence.collectedAt,
        capacity: evidence.capacity,
        interpretation:
          "Capacity values are direct engine evidence. A size value alone does not establish remaining disk capacity, growth rate, or capacity risk.",
        limitations: evidence.limitations
      });
    }
  );

  server.registerTool(
    "database_connection_summary",
    {
      title: "Database Connection Summary",
      description:
        "Return bounded active/total/max/blocked connection evidence for one configured database profile.",
      annotations: readOnlyAnnotations,
      inputSchema: profileInput,
      outputSchema: z.object({
        profileId: z.string(),
        engine: engineSchema,
        collectedAt: z.string(),
        connections: z.object({
          active: z.number().nullable(),
          total: z.number().nullable(),
          max: z.number().nullable(),
          blocked: z.number().nullable()
        }),
        limitations: z.array(z.string())
      })
    },
    async ({ profileId }) => {
      const evidence = await snapshot(profileId);
      return toolResult({
        profileId: evidence.profileId,
        engine: evidence.engine,
        collectedAt: evidence.collectedAt,
        connections: evidence.connections,
        limitations: evidence.limitations
      });
    }
  );

  server.registerTool(
    "database_replication_health",
    {
      title: "Database Replication Health",
      description:
        "Analyze bounded replication role/state/lag evidence through the private core. Standalone or intentionally non-replicated databases are not automatically classified as unhealthy.",
      annotations: readOnlyAnnotations,
      inputSchema: profileInput,
      outputSchema: z.object({
        engineVersion: z.string(),
        generatedAt: z.string(),
        profileId: z.string(),
        engine: engineSchema,
        role: z.string().nullable(),
        state: z.string().nullable(),
        replicaCount: z.number().nullable(),
        lagSeconds: z.number().nullable(),
        health: z.enum(["healthy", "warning", "critical", "unknown"]),
        reasons: z.array(z.string()),
        interpretation: z.string(),
        limitations: z.array(z.string())
      })
    },
    async ({ profileId }) => {
      const evidence = await snapshot(profileId);
      return toolResult(
        await callPrivateIntelligence("/v1/database/replication", evidence)
      );
    }
  );

  server.registerTool(
    "database_lock_summary",
    {
      title: "Database Contention Summary",
      description:
        "Analyze bounded waiting-lock and blocked-connection evidence through the private core without identifying or terminating transactions.",
      annotations: readOnlyAnnotations,
      inputSchema: profileInput,
      outputSchema: z.object({
        engineVersion: z.string(),
        generatedAt: z.string(),
        profileId: z.string(),
        engine: engineSchema,
        waitingLocks: z.number().nullable(),
        blockedConnections: z.number().nullable(),
        severity: z.enum(["none", "low", "medium", "high", "unknown"]),
        reasons: z.array(z.string()),
        interpretation: z.string(),
        limitations: z.array(z.string())
      })
    },
    async ({ profileId }) => {
      const evidence = await snapshot(profileId);
      return toolResult(
        await callPrivateIntelligence("/v1/database/contention", evidence)
      );
    }
  );

  server.registerTool(
    "database_query_pressure",
    {
      title: "Database Query Pressure",
      description:
        "Analyze bounded connection utilization, long-running query evidence, Redis operation rate and rejected-connection evidence through the private core. No query text is collected.",
      annotations: readOnlyAnnotations,
      inputSchema: profileInput,
      outputSchema: z.object({
        engineVersion: z.string(),
        generatedAt: z.string(),
        profileId: z.string(),
        engine: engineSchema,
        connectionUtilizationPercent: z.number().nullable(),
        activeConnections: z.number().nullable(),
        totalConnections: z.number().nullable(),
        maxConnections: z.number().nullable(),
        longRunningQueries: z.number().nullable(),
        oldestQuerySeconds: z.number().nullable(),
        operationsPerSecond: z.number().nullable(),
        rejectedConnections: z.number().nullable(),
        severity: z.enum(["none", "low", "medium", "high", "unknown"]),
        reasons: z.array(z.string()),
        interpretation: z.string(),
        limitations: z.array(z.string())
      })
    },
    async ({ profileId }) => {
      const evidence = await snapshot(profileId);
      return toolResult(
        await callPrivateIntelligence("/v1/database/pressure", evidence)
      );
    }
  );
}
