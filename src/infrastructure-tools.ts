import { McpServer } from "@modelcontextprotocol/server";
import * as z from "zod/v4";
import {
  storageCapacity,
  storageHealth,
  upsHealth,
  virtualMachineInventory,
  vmHealth
} from "./infrastructure.js";
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

const vmSchema = z.object({
  provider: z.enum([
    "hyper-v",
    "virtualbox",
    "proxmox",
    "libvirt",
    "vmware"
  ]),
  id: z.string(),
  name: z.string(),
  state: z.string(),
  cpuUsagePercent: z.number().nullable(),
  memoryBytes: z.number().nullable(),
  source: z.string()
});

const volumeSchema = z.object({
  filesystem: z.string(),
  label: z.string().nullable(),
  mountPoint: z.string(),
  totalBytes: z.number(),
  usedBytes: z.number(),
  freeBytes: z.number(),
  usagePercent: z.number()
});

const deviceKindSchema = z.enum([
  "router",
  "switch",
  "firewall",
  "dns",
  "dhcp",
  "access-point",
  "nas",
  "storage",
  "ups",
  "hypervisor",
  "server",
  "other"
]);

const infrastructureDeviceSchema = z.object({
  id: z.string()
    .min(1)
    .max(128)
    .regex(/^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$/),
  label: z.string().min(1).max(200),
  kind: deviceKindSchema,
  address: z.string().max(255).nullable().optional().default(null),
  status: z.enum(["online", "offline", "degraded", "unknown"]),
  observedAt: z.string(),
  metrics: z.object({
    cpuPercent: z.number().min(0).max(100).nullable().optional().default(null),
    memoryPercent: z.number().min(0).max(100).nullable().optional().default(null),
    temperatureC: z.number().min(-100).max(200).nullable().optional().default(null),
    packetLossPercent: z.number().min(0).max(100).nullable().optional().default(null),
    latencyMs: z.number().min(0).max(86_400_000).nullable().optional().default(null)
  }),
  interfaces: z.array(z.object({
    name: z.string().min(1).max(200),
    state: z.enum(["up", "down", "unknown"]),
    speedMbps: z.number().min(0).max(1_000_000_000).nullable().optional().default(null)
  })).max(200),
  tags: z.array(z.string().min(1).max(64)).max(50),
  limitations: z.array(z.string().max(500)).max(100)
});

const linkSchema = z.object({
  sourceId: z.string().min(1).max(128),
  targetId: z.string().min(1).max(128),
  kind: z.enum([
    "ethernet",
    "wifi",
    "vpn",
    "trunk",
    "dependency",
    "unknown"
  ]),
  state: z.enum(["up", "down", "unknown"]),
  speedMbps: z.number().min(0).max(1_000_000_000).nullable().optional().default(null),
  label: z.string().max(200).nullable().optional().default(null)
});

function infrastructureBundle(
  devices: z.infer<typeof infrastructureDeviceSchema>[],
  links: z.infer<typeof linkSchema>[] = []
) {
  return {
    generatedAt: new Date().toISOString(),
    devices,
    links
  };
}

export function registerInfrastructureTools(server: McpServer) {
  server.registerTool(
    "virtual_machine_inventory",
    {
      title: "Virtual Machine Inventory",
      description:
        "Inspect locally available Hyper-V, VirtualBox, Proxmox, libvirt or VMware CLI inventory using fixed read-only commands. No hypervisor mutation or remote login is performed.",
      annotations: readOnlyAnnotations,
      inputSchema: z.object({
        limit: z.number().int().min(1).max(300).optional()
      }),
      outputSchema: z.object({
        providers: z.array(z.enum([
          "hyper-v",
          "virtualbox",
          "proxmox",
          "libvirt",
          "vmware"
        ])),
        virtualMachines: z.array(vmSchema),
        limitations: z.array(z.string())
      })
    },
    async ({ limit }) => toolResult(await virtualMachineInventory(limit))
  );

  server.registerTool(
    "vm_health",
    {
      title: "Virtual Machine State",
      description:
        "Inspect one VM from local provider inventory by exact ID or name. A stopped or paused VM is reported as observed state, not automatically treated as unhealthy.",
      annotations: readOnlyAnnotations,
      inputSchema: z.object({
        identifier: z.string().min(1).max(200)
      }),
      outputSchema: vmSchema.extend({
        running: z.boolean().nullable(),
        interpretation: z.string(),
        limitations: z.array(z.string())
      })
    },
    async ({ identifier }) => toolResult(await vmHealth(identifier))
  );

  server.registerTool(
    "storage_capacity",
    {
      title: "Storage Capacity",
      description:
        "Summarize local fixed-filesystem capacity and utilization without changing disks, filesystems or storage configuration.",
      annotations: readOnlyAnnotations,
      inputSchema: z.object({}),
      outputSchema: z.object({
        volumeCount: z.number(),
        totalBytes: z.number(),
        usedBytes: z.number(),
        freeBytes: z.number(),
        usagePercent: z.number(),
        volumes: z.array(volumeSchema)
      })
    },
    async () => toolResult(await storageCapacity())
  );

  server.registerTool(
    "storage_health",
    {
      title: "Storage Health",
      description:
        "Summarize filesystem utilization and, on supported Windows hosts, read-only physical-disk health metadata. Linux v0.9 does not claim SMART health unless a future adapter is configured.",
      annotations: readOnlyAnnotations,
      inputSchema: z.object({}),
      outputSchema: z.object({
        health: z.enum(["healthy", "warning", "critical", "unknown"]),
        reasons: z.array(z.string()),
        capacity: z.object({
          volumeCount: z.number(),
          totalBytes: z.number(),
          usedBytes: z.number(),
          freeBytes: z.number(),
          usagePercent: z.number(),
          volumes: z.array(volumeSchema)
        }),
        physicalDevices: z.array(z.object({
          name: z.string(),
          health: z.string(),
          operationalState: z.string(),
          mediaType: z.string().nullable(),
          sizeBytes: z.number().nullable()
        })),
        limitations: z.array(z.string())
      })
    },
    async () => toolResult(await storageHealth())
  );

  server.registerTool(
    "ups_health",
    {
      title: "Local Power / UPS Health",
      description:
        "Read locally exposed battery or UPS telemetry through Windows battery APIs or Linux UPower. No network UPS polling or control is performed.",
      annotations: readOnlyAnnotations,
      inputSchema: z.object({}),
      outputSchema: z.object({
        devices: z.array(z.object({
          name: z.string(),
          status: z.string(),
          batteryStatus: z.string(),
          chargePercent: z.number().nullable(),
          estimatedRunTimeMinutes: z.number().nullable(),
          source: z.string()
        })),
        health: z.enum(["healthy", "warning", "critical", "unknown"]),
        interpretation: z.string(),
        limitations: z.array(z.string())
      })
    },
    async () => toolResult(await upsHealth())
  );

  server.registerTool(
    "network_device_health",
    {
      title: "Private Network Device Health",
      description:
        "Analyze bounded caller-supplied snapshots for routers, switches, firewalls, DNS/DHCP, APs, NAS, storage, UPS, hypervisors or servers through the private intelligence core. LocalOps does not scan or log in to devices.",
      annotations: readOnlyAnnotations,
      inputSchema: z.object({
        devices: z.array(infrastructureDeviceSchema).min(1).max(500)
      }),
      outputSchema: z.object({
        engineVersion: z.string(),
        generatedAt: z.string(),
        deviceCount: z.number(),
        counts: z.object({
          healthy: z.number(),
          warning: z.number(),
          critical: z.number(),
          unknown: z.number(),
          stale: z.number()
        }),
        devices: z.array(z.object({
          id: z.string(),
          label: z.string(),
          kind: deviceKindSchema,
          health: z.enum(["healthy", "warning", "critical", "unknown"]),
          stale: z.boolean(),
          reasons: z.array(z.string()),
          limitations: z.array(z.string())
        })),
        interpretation: z.string(),
        limitations: z.array(z.string())
      })
    },
    async ({ devices }) =>
      toolResult(await callPrivateIntelligence(
        "/v1/infrastructure/device-health",
        infrastructureBundle(devices)
      ))
  );

  server.registerTool(
    "private_network_topology",
    {
      title: "Private Network Topology",
      description:
        "Analyze a bounded caller-supplied graph of private-infrastructure devices and links through the private core. Reports components, isolated nodes, down links and articulation/dependency concentration without network discovery or probing.",
      annotations: readOnlyAnnotations,
      inputSchema: z.object({
        devices: z.array(infrastructureDeviceSchema).min(1).max(500),
        links: z.array(linkSchema).max(1000)
      }),
      outputSchema: z.object({
        engineVersion: z.string(),
        generatedAt: z.string(),
        nodeCount: z.number(),
        linkCount: z.number(),
        componentCount: z.number(),
        isolatedNodeIds: z.array(z.string()),
        downLinks: z.array(linkSchema),
        articulationNodeIds: z.array(z.string()),
        components: z.array(z.object({
          id: z.string(),
          nodeIds: z.array(z.string())
        })),
        interpretation: z.string(),
        limitations: z.array(z.string())
      })
    },
    async ({ devices, links }) =>
      toolResult(await callPrivateIntelligence(
        "/v1/infrastructure/topology",
        infrastructureBundle(devices, links)
      ))
  );

  server.registerTool(
    "network_dependency_path",
    {
      title: "Network Dependency Path",
      description:
        "Find the shortest hop-count dependency path between two explicitly named devices in a bounded caller-supplied topology. Unknown-state links may appear; no network probing or route discovery is performed.",
      annotations: readOnlyAnnotations,
      inputSchema: z.object({
        devices: z.array(infrastructureDeviceSchema).min(1).max(500),
        links: z.array(linkSchema).max(1000),
        sourceId: z.string().min(1).max(128),
        targetId: z.string().min(1).max(128)
      }),
      outputSchema: z.object({
        engineVersion: z.string(),
        generatedAt: z.string(),
        sourceId: z.string(),
        targetId: z.string(),
        found: z.boolean(),
        hopCount: z.number().nullable(),
        nodePath: z.array(z.string()),
        linkPath: z.array(linkSchema),
        unknownLinkCount: z.number(),
        bottleneckSpeedMbps: z.number().nullable(),
        interpretation: z.string(),
        limitations: z.array(z.string())
      })
    },
    async ({ devices, links, sourceId, targetId }) =>
      toolResult(await callPrivateIntelligence(
        "/v1/topology/dependency-path",
        {
          bundle: infrastructureBundle(devices, links),
          sourceId,
          targetId
        }
      ))
  );

  server.registerTool(
    "network_path_redundancy",
    {
      title: "Network Path Redundancy",
      description:
        "Test whether an explicitly selected source-to-target path remains connected after one primary-path link or intermediate-node loss at a time. This is submitted-graph analysis only and does not verify physical path diversity.",
      annotations: readOnlyAnnotations,
      inputSchema: z.object({
        devices: z.array(infrastructureDeviceSchema).min(1).max(500),
        links: z.array(linkSchema).max(1000),
        sourceId: z.string().min(1).max(128),
        targetId: z.string().min(1).max(128)
      }),
      outputSchema: z.object({
        engineVersion: z.string(),
        generatedAt: z.string(),
        sourceId: z.string(),
        targetId: z.string(),
        connected: z.boolean(),
        primaryPath: z.array(z.string()),
        alternatePath: z.array(z.string()),
        singleLinkFailureTolerant: z.boolean().nullable(),
        singleIntermediateNodeFailureTolerant: z.boolean().nullable(),
        linkFailureDependencies: z.array(z.object({
          sourceId: z.string(),
          targetId: z.string()
        })),
        nodeFailureDependencies: z.array(z.string()),
        interpretation: z.string(),
        limitations: z.array(z.string())
      })
    },
    async ({ devices, links, sourceId, targetId }) =>
      toolResult(await callPrivateIntelligence(
        "/v1/topology/path-redundancy",
        {
          bundle: infrastructureBundle(devices, links),
          sourceId,
          targetId
        }
      ))
  );

  server.registerTool(
    "network_failure_domains",
    {
      title: "Network Failure Domains",
      description:
        "Analyze the bounded submitted topology for node and non-parallel active-link failures that create additional pairwise connectivity loss. No device state is changed.",
      annotations: readOnlyAnnotations,
      inputSchema: z.object({
        devices: z.array(infrastructureDeviceSchema).min(1).max(500),
        links: z.array(linkSchema).max(1000)
      }),
      outputSchema: z.object({
        engineVersion: z.string(),
        generatedAt: z.string(),
        nodeCount: z.number(),
        activeLinkCount: z.number(),
        baselineComponentCount: z.number(),
        baselineReachablePairs: z.number(),
        articulationNodeCount: z.number(),
        bridgeLinkCount: z.number(),
        nodeImpacts: z.array(z.object({
          nodeId: z.string(),
          additionalUnreachablePairs: z.number(),
          componentIncrease: z.number()
        })),
        bridgeLinks: z.array(z.object({
          sourceId: z.string(),
          targetId: z.string(),
          additionalUnreachablePairs: z.number()
        })),
        interpretation: z.string(),
        limitations: z.array(z.string())
      })
    },
    async ({ devices, links }) =>
      toolResult(await callPrivateIntelligence(
        "/v1/topology/failure-domains",
        infrastructureBundle(devices, links)
      ))
  );

  server.registerTool(
    "network_change_impact",
    {
      title: "Network Change Impact",
      description:
        "Run a bounded what-if topology simulation for explicitly disabled nodes and endpoint-pair links. Reports connectivity impact only; it does not execute a network change, login, scan or remediation.",
      annotations: readOnlyAnnotations,
      inputSchema: z.object({
        devices: z.array(infrastructureDeviceSchema).min(1).max(500),
        links: z.array(linkSchema).max(1000),
        disabledNodeIds: z.array(
          z.string().min(1).max(128)
        ).max(50),
        disabledLinks: z.array(z.object({
          sourceId: z.string().min(1).max(128),
          targetId: z.string().min(1).max(128)
        })).max(100)
      }),
      outputSchema: z.object({
        engineVersion: z.string(),
        generatedAt: z.string(),
        disabledNodeIds: z.array(z.string()),
        disabledLinks: z.array(z.object({
          sourceId: z.string(),
          targetId: z.string()
        })),
        baselineComponentCount: z.number(),
        changedComponentCount: z.number(),
        baselineReachablePairs: z.number(),
        changedReachablePairs: z.number(),
        reachablePairLoss: z.number(),
        newlyIsolatedNodeIds: z.array(z.string()),
        affectedNodeIds: z.array(z.string()),
        interpretation: z.string(),
        limitations: z.array(z.string())
      })
    },
    async ({
      devices,
      links,
      disabledNodeIds,
      disabledLinks
    }) =>
      toolResult(await callPrivateIntelligence(
        "/v1/topology/change-impact",
        {
          bundle: infrastructureBundle(devices, links),
          disabledNodeIds,
          disabledLinks
        }
      ))
  );
}
