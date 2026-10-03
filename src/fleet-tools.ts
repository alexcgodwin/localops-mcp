import { McpServer } from "@modelcontextprotocol/server";
import * as z from "zod/v4";
import {
  captureLocalNodeSnapshot,
  fleetBundle,
  fleetHealth,
  fleetInventory,
  fleetPair,
  getNode,
  listNodes,
  nodeHealth,
  nodeHealthHistory,
  predictiveHealthBundle,
  registerNode
} from "./fleet.js";
import { callPrivateIntelligence } from "./intelligence-client.js";

const readOnlyAnnotations = {
  readOnlyHint: true,
  destructiveHint: false,
  idempotentHint: true,
  openWorldHint: false
} as const;

const registryWriteAnnotations = {
  readOnlyHint: false,
  destructiveHint: false,
  idempotentHint: false,
  openWorldHint: false
} as const;

function toolResult(payload: Record<string, unknown>) {
  return {
    content: [{ type: "text" as const, text: JSON.stringify(payload, null, 2) }],
    structuredContent: payload
  };
}

const healthSchema = z.object({
  health: z.enum(["healthy", "warning", "critical"]),
  uptimeSeconds: z.number(),
  cpuUsagePercent: z.number(),
  memoryUsagePercent: z.number(),
  maxDiskUsagePercent: z.number(),
  reasons: z.array(z.string())
});

const snapshotSchema = z.object({
  nodeId: z.string().min(1).max(128),
  label: z.string().min(1).max(128),
  tags: z.array(z.string().max(64)).max(20),
  capturedAt: z.string(),
  host: z.object({
    hostname: z.string(),
    platform: z.string(),
    operatingSystem: z.string(),
    release: z.string(),
    version: z.string(),
    architecture: z.string(),
    machine: z.string()
  }),
  health: healthSchema.nullable(),
  software: z.array(z.object({
    name: z.string(),
    version: z.string().nullable(),
    publisher: z.string().nullable(),
    source: z.string()
  })).max(300),
  patches: z.array(z.object({
    id: z.string(),
    installedAt: z.string().nullable(),
    source: z.string()
  })).max(300),
  certificates: z.array(z.object({
    store: z.string(),
    thumbprint: z.string(),
    subject: z.string(),
    issuer: z.string(),
    notAfter: z.string().nullable()
  })).max(300),
  services: z.array(z.object({
    name: z.string(),
    status: z.string().nullable(),
    startType: z.string().nullable()
  })).max(300),
  admins: z.array(z.object({
    name: z.string()
  })).max(100),
  startupPrograms: z.array(z.object({
    name: z.string(),
    source: z.string(),
    state: z.string().nullable()
  })).max(300),
  scheduledTasks: z.array(z.object({
    name: z.string(),
    path: z.string(),
    state: z.string(),
    source: z.string()
  })).max(300),
  securitySummary: z.object({
    recentChangeCount: z.number().int().min(0),
    categories: z.array(z.string()).max(50)
  }),
  limitations: z.array(z.string()).max(100)
});

const nodeSummarySchema = z.object({
  nodeId: z.string(),
  label: z.string(),
  tags: z.array(z.string()),
  hostname: z.string(),
  platform: z.string(),
  release: z.string(),
  health: z.enum(["healthy", "warning", "critical", "unknown"]),
  capturedAt: z.string(),
  ageSeconds: z.number().nullable(),
  stale: z.boolean(),
  limitationCount: z.number()
});

const driftItemSchema = z.object({
  kind: z.string(),
  key: z.string(),
  baseline: z.string().nullable(),
  target: z.string().nullable(),
  severity: z.enum(["info", "warning", "high"]),
  summary: z.string()
});

const comparisonSchema = z.object({
  engineVersion: z.string(),
  generatedAt: z.string(),
  baselineNodeId: z.string(),
  targetNodeId: z.string(),
  driftCount: z.number(),
  drift: z.array(driftItemSchema),
  limitations: z.array(z.string())
});

const driftSchema = z.object({
  engineVersion: z.string(),
  generatedAt: z.string(),
  driftType: z.enum([
    "configuration",
    "software",
    "patch",
    "certificate",
    "security"
  ]),
  pairCount: z.number(),
  nodeCount: z.number(),
  findings: z.array(z.object({
    baselineNodeId: z.string(),
    targetNodeId: z.string(),
    driftCount: z.number(),
    drift: z.array(driftItemSchema)
  })),
  interpretation: z.string(),
  limitations: z.array(z.string())
});

const healthObservationSchema = z.object({
  capturedAt: z.string(),
  health: z.enum(["healthy", "warning", "critical"]),
  uptimeSeconds: z.number(),
  cpuUsagePercent: z.number(),
  memoryUsagePercent: z.number(),
  maxDiskUsagePercent: z.number()
});

const predictiveMetricSchema = z.object({
  metric: z.enum(["cpu", "memory", "disk"]),
  currentPercent: z.number().nullable(),
  slopePercentPerHour: z.number().nullable(),
  direction: z.enum(["decreasing", "stable", "increasing", "unknown"]),
  projectedPercentAtHorizon: z.number().nullable(),
  timeToWarningHours: z.number().nullable(),
  timeToCriticalHours: z.number().nullable()
});

const predictiveNodeSchema = z.object({
  nodeId: z.string(),
  label: z.string(),
  status: z.enum(["stable", "watch", "elevated", "insufficient-data"]),
  observationCount: z.number(),
  spanHours: z.number(),
  evidenceConfidence: z.number().min(0).max(100),
  confidenceBand: z.enum(["low", "medium", "high"]),
  metrics: z.array(predictiveMetricSchema),
  reasons: z.array(z.string()),
  limitations: z.array(z.string())
});

const predictiveResultSchema = z.object({
  engineVersion: z.literal("1.5.0"),
  generatedAt: z.string(),
  horizonHours: z.number(),
  nodeCount: z.number(),
  counts: z.object({
    stable: z.number(),
    watch: z.number(),
    elevated: z.number(),
    insufficientData: z.number()
  }),
  nodes: z.array(predictiveNodeSchema),
  interpretation: z.string(),
  limitations: z.array(z.string())
});

const incidentSignalSchema = z.object({
  id: z.string(),
  category: z.enum([
    "health-state",
    "resource-pressure",
    "service-state",
    "security-change"
  ]),
  severity: z.enum(["low", "medium", "high"]),
  nodeIds: z.array(z.string()),
  evidenceCount: z.number(),
  summary: z.string()
});

const incidentCorrelationSchema = z.object({
  engineVersion: z.literal("1.6.0"),
  generatedAt: z.string(),
  nodeCount: z.number(),
  correlatedNodeCount: z.number(),
  signalCount: z.number(),
  signals: z.array(incidentSignalSchema),
  interpretation: z.string(),
  limitations: z.array(z.string())
});

const incidentTimelineSchema = z.object({
  engineVersion: z.literal("1.6.0"),
  generatedAt: z.string(),
  nodeCount: z.number(),
  entryCount: z.number(),
  entries: z.array(z.object({
    timestamp: z.string(),
    nodeId: z.string(),
    category: z.enum(["health", "security-change", "service-state"]),
    severity: z.enum(["low", "medium", "high"]),
    summary: z.string()
  })),
  interpretation: z.string(),
  limitations: z.array(z.string())
});

const sharedCauseSchema = z.object({
  engineVersion: z.literal("1.6.0"),
  generatedAt: z.string(),
  nodeCount: z.number(),
  candidateCount: z.number(),
  candidates: z.array(z.object({
    id: z.string(),
    category: z.string(),
    hypothesis: z.string(),
    evidenceConfidence: z.number().min(0).max(100),
    confidenceBand: z.enum(["low", "medium", "high"]),
    affectedNodeIds: z.array(z.string()),
    supportingSignalIds: z.array(z.string()),
    rationale: z.string()
  })),
  interpretation: z.string(),
  limitations: z.array(z.string())
});

const incidentScopeSchema = z.object({
  engineVersion: z.literal("1.6.0"),
  generatedAt: z.string(),
  scope: z.enum(["none", "localized", "multi-node", "fleet-wide"]),
  nodeCount: z.number(),
  affectedNodeCount: z.number(),
  affectedNodeIds: z.array(z.string()),
  unaffectedNodeIds: z.array(z.string()),
  commonAffectedTags: z.array(z.object({
    tag: z.string(),
    affectedNodeCount: z.number()
  })),
  interpretation: z.string(),
  limitations: z.array(z.string())
});

async function runFleetDrift(route: string, baselineNodeId: string) {
  getNode(baselineNodeId);
  const bundle = {
    ...fleetBundle(),
    baselineNodeId
  };
  return callPrivateIntelligence(route, bundle);
}

export function registerFleetTools(server: McpServer) {
  server.registerTool(
    "capture_node_snapshot",
    {
      title: "Capture Local Fleet Snapshot",
      description:
        "Capture a bounded normalized snapshot of the current local host for fleet registration. Raw event messages are not stored in the snapshot.",
      annotations: readOnlyAnnotations,
      inputSchema: z.object({
        nodeId: z.string().min(1).max(128).optional(),
        label: z.string().min(1).max(128).optional(),
        tags: z.array(z.string().max(64)).max(20).optional(),
        limit: z.number().int().min(1).max(300).optional()
      }),
      outputSchema: snapshotSchema
    },
    async (input) => toolResult(await captureLocalNodeSnapshot(input))
  );

  server.registerTool(
    "register_node",
    {
      title: "Register Fleet Node Snapshot",
      description:
        "Upsert one bounded normalized node snapshot into the local in-memory fleet registry. This stores application state only and does not connect to or mutate the endpoint.",
      annotations: registryWriteAnnotations,
      inputSchema: z.object({
        snapshot: snapshotSchema
      }),
      outputSchema: z.object({
        nodeId: z.string(),
        registered: z.boolean(),
        updated: z.boolean(),
        registeredAt: z.string(),
        updatedAt: z.string(),
        healthObservationCount: z.number(),
        persistence: z.string()
      })
    },
    async ({ snapshot }) => toolResult(registerNode(snapshot))
  );

  server.registerTool(
    "list_nodes",
    {
      title: "List Fleet Nodes",
      description:
        "List bounded metadata for snapshots currently held in the in-memory fleet registry.",
      annotations: readOnlyAnnotations,
      inputSchema: z.object({}),
      outputSchema: z.object({
        nodes: z.array(nodeSummarySchema)
      })
    },
    async () => toolResult({ nodes: listNodes() })
  );

  server.registerTool(
    "node_health",
    {
      title: "Fleet Node Health",
      description:
        "Return health and snapshot freshness for one registered node without contacting that node.",
      annotations: readOnlyAnnotations,
      inputSchema: z.object({
        nodeId: z.string().min(1).max(128)
      }),
      outputSchema: z.object({
        nodeId: z.string(),
        label: z.string(),
        capturedAt: z.string(),
        ageSeconds: z.number(),
        stale: z.boolean(),
        health: z.enum(["healthy", "warning", "critical", "unknown"]),
        metrics: z.object({
          cpuUsagePercent: z.number(),
          memoryUsagePercent: z.number(),
          maxDiskUsagePercent: z.number(),
          uptimeSeconds: z.number()
        }).nullable(),
        reasons: z.array(z.string()),
        limitations: z.array(z.string())
      })
    },
    async ({ nodeId }) => toolResult(nodeHealth(nodeId))
  );

  server.registerTool(
    "node_health_history",
    {
      title: "Fleet Node Health History",
      description:
        "Return the bounded in-memory CPU, memory and disk health observations retained for one registered node. History is local process state only and is not durable telemetry.",
      annotations: readOnlyAnnotations,
      inputSchema: z.object({
        nodeId: z.string().min(1).max(128),
        limit: z.number().int().min(1).max(96).optional()
      }),
      outputSchema: z.object({
        nodeId: z.string(),
        label: z.string(),
        tags: z.array(z.string()),
        observationCount: z.number(),
        observations: z.array(healthObservationSchema).max(96),
        limitations: z.array(z.string()),
        persistence: z.string()
      })
    },
    async ({ nodeId, limit }) =>
      toolResult(nodeHealthHistory(nodeId, limit))
  );

  server.registerTool(
    "node_predictive_health",
    {
      title: "Node Predictive Health",
      description:
        "Analyze bounded retained health history for one registered node through the private intelligence core. Results are trend extrapolations with evidence-confidence limits, not failure probabilities or guarantees.",
      annotations: readOnlyAnnotations,
      inputSchema: z.object({
        nodeId: z.string().min(1).max(128),
        horizonHours: z.number().int().min(1).max(168).optional()
      }),
      outputSchema: predictiveResultSchema
    },
    async ({ nodeId, horizonHours }) =>
      toolResult(await callPrivateIntelligence(
        "/v1/predictive/health",
        predictiveHealthBundle(horizonHours, nodeId)
      ))
  );

  server.registerTool(
    "fleet_predictive_health",
    {
      title: "Fleet Predictive Health",
      description:
        "Analyze bounded in-memory health histories for registered nodes through the private intelligence core. Forecasts surface directional resource pressure and data limitations without triggering remediation.",
      annotations: readOnlyAnnotations,
      inputSchema: z.object({
        horizonHours: z.number().int().min(1).max(168).optional()
      }),
      outputSchema: predictiveResultSchema
    },
    async ({ horizonHours }) =>
      toolResult(await callPrivateIntelligence(
        "/v1/predictive/health",
        predictiveHealthBundle(horizonHours)
      ))
  );

  server.registerTool(
    "fleet_incident_correlation",
    {
      title: "Fleet Incident Correlation",
      description:
        "Correlate repeated health, resource, service and security-change evidence across registered node snapshots through the private intelligence core. Correlation is investigative evidence, not proof of causation.",
      annotations: readOnlyAnnotations,
      inputSchema: z.object({}),
      outputSchema: incidentCorrelationSchema
    },
    async () =>
      toolResult(await callPrivateIntelligence(
        "/v1/fleet/incident-correlation",
        fleetBundle()
      ))
  );

  server.registerTool(
    "fleet_incident_timeline",
    {
      title: "Fleet Incident Timeline",
      description:
        "Build a bounded chronological cross-node timeline from registered snapshot evidence. Entries are anchored to snapshot capture times rather than claiming original event timestamps.",
      annotations: readOnlyAnnotations,
      inputSchema: z.object({}),
      outputSchema: incidentTimelineSchema
    },
    async () =>
      toolResult(await callPrivateIntelligence(
        "/v1/fleet/incident-timeline",
        fleetBundle()
      ))
  );

  server.registerTool(
    "fleet_shared_cause_analysis",
    {
      title: "Fleet Shared Cause Analysis",
      description:
        "Rank evidence-backed shared-cause hypotheses across registered nodes. Evidence confidence measures cross-node coverage and is not a probability of causation.",
      annotations: readOnlyAnnotations,
      inputSchema: z.object({}),
      outputSchema: sharedCauseSchema
    },
    async () =>
      toolResult(await callPrivateIntelligence(
        "/v1/fleet/shared-cause-analysis",
        fleetBundle()
      ))
  );

  server.registerTool(
    "fleet_incident_scope",
    {
      title: "Fleet Incident Scope",
      description:
        "Classify the observed incident footprint as none, localized, multi-node or fleet-wide using bounded registered snapshot evidence and common node tags.",
      annotations: readOnlyAnnotations,
      inputSchema: z.object({}),
      outputSchema: incidentScopeSchema
    },
    async () =>
      toolResult(await callPrivateIntelligence(
        "/v1/fleet/incident-scope",
        fleetBundle()
      ))
  );

  server.registerTool(
    "fleet_health",
    {
      title: "Fleet Health",
      description:
        "Summarize health, stale snapshots and node states across the current in-memory registry.",
      annotations: readOnlyAnnotations,
      inputSchema: z.object({}),
      outputSchema: z.object({
        health: z.enum(["healthy", "warning", "critical", "unknown"]),
        counts: z.object({
          total: z.number(),
          healthy: z.number(),
          warning: z.number(),
          critical: z.number(),
          unknown: z.number(),
          stale: z.number()
        }),
        nodes: z.array(nodeSummarySchema)
      })
    },
    async () => toolResult(fleetHealth())
  );

  server.registerTool(
    "fleet_inventory",
    {
      title: "Fleet Inventory",
      description:
        "Return bounded metadata for registered node snapshots. Raw event messages are not part of the fleet registry.",
      annotations: readOnlyAnnotations,
      inputSchema: z.object({
        limit: z.number().int().min(1).max(500).optional()
      }),
      outputSchema: z.object({
        nodeCount: z.number(),
        nodes: z.array(nodeSummarySchema),
        persistence: z.string()
      })
    },
    async ({ limit }) => toolResult(fleetInventory(limit))
  );

  server.registerTool(
    "compare_nodes",
    {
      title: "Compare Fleet Nodes",
      description:
        "Compare two registered snapshots through the private intelligence core. Differences are observations, not automatic errors or compromise findings.",
      annotations: readOnlyAnnotations,
      inputSchema: z.object({
        baselineNodeId: z.string().min(1).max(128),
        targetNodeId: z.string().min(1).max(128)
      }),
      outputSchema: comparisonSchema
    },
    async ({ baselineNodeId, targetNodeId }) => {
      const pair = fleetPair(baselineNodeId, targetNodeId);
      return toolResult(await callPrivateIntelligence(
        "/v1/fleet/compare",
        {
          generatedAt: new Date().toISOString(),
          baselineNodeId,
          targetNodeId,
          nodes: [pair.baseline, pair.target]
        }
      ));
    }
  );

  const driftTools = [
    {
      name: "configuration_drift",
      title: "Fleet Configuration Drift",
      route: "/v1/fleet/configuration-drift",
      description:
        "Compare host, service, startup and scheduler state across registered nodes relative to an explicit baseline."
    },
    {
      name: "software_drift",
      title: "Fleet Software Drift",
      route: "/v1/fleet/software-drift",
      description:
        "Compare bounded installed-software presence and versions across registered nodes relative to an explicit baseline."
    },
    {
      name: "patch_drift",
      title: "Fleet Patch Drift",
      route: "/v1/fleet/patch-drift",
      description:
        "Compare bounded Windows hotfix or Linux kernel/package patch markers across registered nodes relative to an explicit baseline."
    },
    {
      name: "certificate_drift",
      title: "Fleet Certificate Drift",
      route: "/v1/fleet/certificate-drift",
      description:
        "Compare bounded certificate presence and expiry metadata across registered nodes relative to an explicit baseline."
    },
    {
      name: "security_drift",
      title: "Fleet Security Drift",
      route: "/v1/fleet/security-drift",
      description:
        "Compare local administrator membership and summarized recent security-change categories relative to an explicit baseline. Drift is not a compromise verdict."
    }
  ] as const;

  for (const tool of driftTools) {
    server.registerTool(
      tool.name,
      {
        title: tool.title,
        description: tool.description,
        annotations: readOnlyAnnotations,
        inputSchema: z.object({
          baselineNodeId: z.string().min(1).max(128)
        }),
        outputSchema: driftSchema
      },
      async ({ baselineNodeId }) =>
        toolResult(await runFleetDrift(tool.route, baselineNodeId))
    );
  }
}
