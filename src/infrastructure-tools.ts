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
}
