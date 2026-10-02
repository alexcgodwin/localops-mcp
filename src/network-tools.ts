import { McpServer } from "@modelcontextprotocol/server";
import * as z from "zod/v4";
import {
  arpNeighbors,
  dnsConfiguration,
  dnsResolution,
  firewallRules,
  firewallStatus,
  listeningPorts,
  networkAdapters,
  networkConnections,
  networkRoutes,
  openPorts,
  processNetworkMap,
  unexpectedListeningPorts,
  unusualOutboundConnections
} from "./network.js";

const readOnlyAnnotations = {
  readOnlyHint: true,
  destructiveHint: false,
  idempotentHint: true,
  openWorldHint: false
} as const;

const dnsAnnotations = {
  ...readOnlyAnnotations,
  openWorldHint: true
} as const;

function toolResult(payload: Record<string, unknown>) {
  return {
    content: [{ type: "text" as const, text: JSON.stringify(payload, null, 2) }],
    structuredContent: payload
  };
}

const connectionSchema = z.object({
  protocol: z.enum(["tcp", "udp"]),
  localAddress: z.string(),
  localPort: z.number(),
  remoteAddress: z.string().nullable(),
  remotePort: z.number().nullable(),
  state: z.string().nullable(),
  pid: z.number().nullable(),
  processName: z.string().nullable()
});

const routeSchema = z.object({
  destination: z.string(),
  gateway: z.string().nullable(),
  interface: z.string().nullable(),
  metric: z.number(),
  family: z.string().nullable(),
  state: z.string().nullable()
});

const dnsInterfaceSchema = z.object({
  interface: z.string(),
  family: z.string().nullable(),
  servers: z.array(z.string())
});

const firewallProfileSchema = z.object({
  name: z.string(),
  enabled: z.boolean(),
  defaultInboundAction: z.string(),
  defaultOutboundAction: z.string()
});

const windowsFirewallRuleSchema = z.object({
  name: z.string(),
  displayName: z.string(),
  enabled: z.boolean(),
  direction: z.string(),
  action: z.string(),
  profile: z.string()
});

const adapterSchema = z.object({
  name: z.string(),
  description: z.string(),
  status: z.string(),
  macAddress: z.string().nullable(),
  linkSpeed: z.string().nullable(),
  mediaType: z.string().nullable()
});

const neighborSchema = z.object({
  ipAddress: z.string(),
  macAddress: z.string().nullable(),
  state: z.string().nullable(),
  interface: z.string().nullable(),
  family: z.string().nullable()
});

export function registerNetworkIntelligenceTools(server: McpServer) {
  server.registerTool(
    "open_ports",
    {
      title: "Open Ports",
      description:
        "Return unique local TCP/UDP listening endpoints. This is local socket inspection only and does not scan remote hosts.",
      annotations: readOnlyAnnotations,
      inputSchema: z.object({
        limit: z.number().int().min(1).max(1000).optional()
      }),
      outputSchema: z.object({ ports: z.array(connectionSchema) })
    },
    async ({ limit }) => toolResult({ ports: await openPorts(limit) })
  );

  server.registerTool(
    "listening_ports",
    {
      title: "Listening Ports",
      description:
        "Return bounded local TCP listeners and UDP endpoints with owning PID/process metadata where the OS permits it.",
      annotations: readOnlyAnnotations,
      inputSchema: z.object({
        limit: z.number().int().min(1).max(1000).optional()
      }),
      outputSchema: z.object({ listeners: z.array(connectionSchema) })
    },
    async ({ limit }) =>
      toolResult({ listeners: await listeningPorts(limit) })
  );

  server.registerTool(
    "network_connections",
    {
      title: "Network Connections",
      description:
        "Return bounded local TCP connection and UDP endpoint state with owning process metadata where available. No packet contents are captured.",
      annotations: readOnlyAnnotations,
      inputSchema: z.object({
        limit: z.number().int().min(1).max(1500).optional()
      }),
      outputSchema: z.object({ connections: z.array(connectionSchema) })
    },
    async ({ limit }) =>
      toolResult({ connections: await networkConnections(limit) })
  );

  server.registerTool(
    "network_routes",
    {
      title: "Network Routes",
      description:
        "Return the local routing table using fixed platform-specific read commands.",
      annotations: readOnlyAnnotations,
      inputSchema: z.object({
        limit: z.number().int().min(1).max(1000).optional()
      }),
      outputSchema: z.object({ routes: z.array(routeSchema) })
    },
    async ({ limit }) => toolResult({ routes: await networkRoutes(limit) })
  );

  server.registerTool(
    "dns_configuration",
    {
      title: "DNS Configuration",
      description:
        "Return configured DNS servers and search domains without modifying resolver settings.",
      annotations: readOnlyAnnotations,
      inputSchema: z.object({}),
      outputSchema: z.object({
        source: z.string(),
        interfaces: z.array(dnsInterfaceSchema),
        searchDomains: z.array(z.string())
      })
    },
    async () => toolResult(await dnsConfiguration())
  );

  server.registerTool(
    "dns_resolution",
    {
      title: "DNS Resolution",
      description:
        "Resolve one validated hostname or IP through the operating system resolver. This may contact the host's configured DNS service but does not perform arbitrary HTTP requests.",
      annotations: dnsAnnotations,
      inputSchema: z.object({
        host: z.string().min(1).max(253)
      }),
      outputSchema: z.object({
        host: z.string(),
        answers: z.array(z.object({
          address: z.string(),
          family: z.number()
        }))
      })
    },
    async ({ host }) => toolResult(await dnsResolution(host))
  );

  server.registerTool(
    "firewall_status",
    {
      title: "Firewall Status",
      description:
        "Inspect Windows Defender Firewall profiles or detect readable Linux firewall state. Unavailable permissions are reported rather than bypassed.",
      annotations: readOnlyAnnotations,
      inputSchema: z.object({}),
      outputSchema: z.object({
        provider: z.string(),
        profiles: z.array(firewallProfileSchema),
        status: z.string()
      })
    },
    async () => toolResult(await firewallStatus())
  );

  server.registerTool(
    "firewall_rules",
    {
      title: "Firewall Rules",
      description:
        "Return a bounded local firewall-rule summary. The tool never adds, removes, enables or disables firewall rules.",
      annotations: readOnlyAnnotations,
      inputSchema: z.object({
        limit: z.number().int().min(1).max(500).optional()
      }),
      outputSchema: z.object({
        provider: z.string(),
        rules: z.array(z.union([windowsFirewallRuleSchema, z.string()]))
      })
    },
    async ({ limit }) => toolResult(await firewallRules(limit))
  );

  server.registerTool(
    "network_adapters",
    {
      title: "Network Adapters",
      description:
        "Inventory local network adapters, link state and hardware addresses where available.",
      annotations: readOnlyAnnotations,
      inputSchema: z.object({
        limit: z.number().int().min(1).max(500).optional()
      }),
      outputSchema: z.object({ adapters: z.array(adapterSchema) })
    },
    async ({ limit }) =>
      toolResult({ adapters: await networkAdapters(limit) })
  );

  server.registerTool(
    "arp_neighbors",
    {
      title: "ARP and Neighbor Cache",
      description:
        "Read the local ARP/neighbor cache. This does not actively probe neighboring devices.",
      annotations: readOnlyAnnotations,
      inputSchema: z.object({
        limit: z.number().int().min(1).max(1000).optional()
      }),
      outputSchema: z.object({ neighbors: z.array(neighborSchema) })
    },
    async ({ limit }) =>
      toolResult({ neighbors: await arpNeighbors(limit) })
  );

  server.registerTool(
    "process_network_map",
    {
      title: "Process Network Map",
      description:
        "Group observed local socket evidence by owning process. Packet contents and process command lines are excluded.",
      annotations: readOnlyAnnotations,
      inputSchema: z.object({
        limit: z.number().int().min(1).max(1500).optional()
      }),
      outputSchema: z.object({
        processes: z.array(z.object({
          pid: z.number().nullable(),
          processName: z.string().nullable(),
          connectionCount: z.number(),
          localPorts: z.array(z.number()),
          remoteAddresses: z.array(z.string())
        }))
      })
    },
    async ({ limit }) =>
      toolResult({ processes: await processNetworkMap(limit) })
  );

  server.registerTool(
    "unexpected_listening_ports",
    {
      title: "Unexpected Listening Ports",
      description:
        "Compare current local listeners with a caller-supplied protocol/port baseline. 'Unexpected' means absent from that baseline, not malicious.",
      annotations: readOnlyAnnotations,
      inputSchema: z.object({
        allowedPorts: z.array(z.object({
          protocol: z.enum(["tcp", "udp"]),
          port: z.number().int().min(1).max(65535)
        })).max(500),
        limit: z.number().int().min(1).max(1000).optional()
      }),
      outputSchema: z.object({
        baselineCount: z.number(),
        listenerCount: z.number(),
        unexpectedCount: z.number(),
        unexpected: z.array(connectionSchema),
        interpretation: z.string()
      })
    },
    async ({ allowedPorts, limit }) =>
      toolResult(await unexpectedListeningPorts(allowedPorts, limit))
  );

  server.registerTool(
    "unusual_outbound_connections",
    {
      title: "Outbound Connections Outside Baseline",
      description:
        "Compare active TCP remote endpoints with caller-supplied allowed ports and/or exact remote addresses. Results indicate baseline mismatch only, never malware or compromise.",
      annotations: readOnlyAnnotations,
      inputSchema: z.object({
        allowedRemotePorts: z.array(
          z.number().int().min(1).max(65535)
        ).max(500).default([]),
        allowedRemoteAddresses: z.array(
          z.string().min(1).max(64)
        ).max(500).default([]),
        limit: z.number().int().min(1).max(1500).optional()
      }).refine(
        (value) =>
          value.allowedRemotePorts.length > 0 ||
          value.allowedRemoteAddresses.length > 0,
        {
          message:
            "Provide at least one allowed remote port or allowed remote address."
        }
      ),
      outputSchema: z.object({
        outboundCount: z.number(),
        outsideBaselineCount: z.number(),
        outsideBaseline: z.array(connectionSchema),
        interpretation: z.string()
      })
    },
    async ({ allowedRemotePorts, allowedRemoteAddresses, limit }) =>
      toolResult(
        await unusualOutboundConnections(
          allowedRemotePorts,
          allowedRemoteAddresses,
          limit
        )
      )
  );
}
