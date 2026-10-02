#!/usr/bin/env node
import { pathToFileURL } from "node:url";
import { McpServer } from "@modelcontextprotocol/server";
import { serveStdio } from "@modelcontextprotocol/server/stdio";
import * as z from "zod/v4";
import {
  cpuStatus,
  diskStatus,
  inspectProcess,
  listProcesses,
  listServices,
  memoryStatus,
  networkInterfaces,
  serviceStatus,
  systemHealth,
  systemInfo,
  uptimeInfo
} from "./system.js";
import { registerEndpointInventoryTools } from "./endpoint-tools.js";
import { registerNetworkIntelligenceTools } from "./network-tools.js";
import { registerEventEvidenceTools } from "./event-tools.js";

const VERSION = "0.4.0";

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

const diskSchema = z.object({
  filesystem: z.string(),
  label: z.string().nullable(),
  mountPoint: z.string(),
  totalBytes: z.number(),
  usedBytes: z.number(),
  freeBytes: z.number(),
  usagePercent: z.number()
});

const processSchema = z.object({
  pid: z.number(),
  name: z.string(),
  parentPid: z.number().optional(),
  user: z.string().optional(),
  cpuSeconds: z.number().optional(),
  cpuPercent: z.number().optional(),
  memoryBytes: z.number().optional(),
  memoryPercent: z.number().optional(),
  startTime: z.string().nullable().optional(),
  executablePath: z.string().nullable().optional(),
  elapsed: z.string().optional()
});

const serviceSchema = z.object({
  name: z.string(),
  displayName: z.string().optional(),
  status: z.string().optional(),
  startType: z.string().nullable().optional(),
  loadState: z.string().optional(),
  activeState: z.string().optional(),
  subState: z.string().optional(),
  description: z.string().optional()
});

export function createServer() {
  const server = new McpServer(
    { name: "opschugex-localops-mcp", version: VERSION },
    {
      instructions:
        "Use LocalOps tools to inspect the local Windows or Linux host. v0.4 is read-only: it includes system discovery, endpoint inventory, local network intelligence, and bounded event/security evidence collection. Never expose secret values, private-key contents, packet payloads, arbitrary shell execution, mutation or remediation. Baseline and evidence tools report observable facts and caller-baseline deviations; they must not infer compromise or root cause."
    }
  );

  server.registerTool(
    "system_info",
    {
      title: "System Information",
      description: "Return bounded operating-system and host metadata using Node.js system APIs.",
      annotations: readOnlyAnnotations,
      inputSchema: z.object({}),
      outputSchema: z.object({
        hostname: z.string(),
        platform: z.string(),
        operatingSystem: z.string(),
        release: z.string(),
        version: z.string(),
        architecture: z.string(),
        machine: z.string(),
        logicalCpuCount: z.number(),
        uptimeSeconds: z.number()
      })
    },
    async () => toolResult(systemInfo())
  );

  server.registerTool(
    "system_health",
    {
      title: "System Health",
      description: "Summarize CPU, memory and fixed-disk pressure without changing the host.",
      annotations: readOnlyAnnotations,
      inputSchema: z.object({}),
      outputSchema: z.object({
        health: z.enum(["healthy", "warning", "critical"]),
        hostname: z.string(),
        uptimeSeconds: z.number(),
        cpuUsagePercent: z.number(),
        memoryUsagePercent: z.number(),
        maxDiskUsagePercent: z.number(),
        reasons: z.array(z.string())
      })
    },
    async () => toolResult(await systemHealth())
  );

  server.registerTool(
    "cpu_status",
    {
      title: "CPU Status",
      description: "Sample CPU utilization and return processor metadata and load averages.",
      annotations: readOnlyAnnotations,
      inputSchema: z.object({
        sampleMs: z.number().int().min(50).max(1000).optional()
      }),
      outputSchema: z.object({
        usagePercent: z.number(),
        logicalCores: z.number(),
        model: z.string(),
        speedMHz: z.number(),
        loadAverage: z.array(z.number())
      })
    },
    async ({ sampleMs }) => toolResult(await cpuStatus(sampleMs))
  );

  server.registerTool(
    "memory_status",
    {
      title: "Memory Status",
      description: "Return total, used and available physical memory.",
      annotations: readOnlyAnnotations,
      inputSchema: z.object({}),
      outputSchema: z.object({
        totalBytes: z.number(),
        usedBytes: z.number(),
        freeBytes: z.number(),
        usagePercent: z.number()
      })
    },
    async () => toolResult(memoryStatus())
  );

  server.registerTool(
    "disk_status",
    {
      title: "Disk Status",
      description: "Inspect fixed local disk capacity and utilization using a bounded platform-specific command.",
      annotations: readOnlyAnnotations,
      inputSchema: z.object({}),
      outputSchema: z.object({ disks: z.array(diskSchema) })
    },
    async () => toolResult({ disks: await diskStatus() })
  );

  server.registerTool(
    "network_interfaces",
    {
      title: "Network Interfaces",
      description: "List local network interfaces and assigned addresses. No network probing is performed.",
      annotations: readOnlyAnnotations,
      inputSchema: z.object({}),
      outputSchema: z.object({
        interfaces: z.array(z.object({
          name: z.string(),
          address: z.string(),
          family: z.string(),
          cidr: z.string().nullable(),
          mac: z.string(),
          internal: z.boolean()
        }))
      })
    },
    async () => toolResult({ interfaces: networkInterfaces() })
  );

  server.registerTool(
    "list_processes",
    {
      title: "List Processes",
      description: "List a bounded number of local processes with basic resource metadata. Command lines and environment variables are not returned.",
      annotations: readOnlyAnnotations,
      inputSchema: z.object({
        limit: z.number().int().min(1).max(200).optional()
      }),
      outputSchema: z.object({ processes: z.array(processSchema) })
    },
    async ({ limit }) => toolResult({ processes: await listProcesses(limit) })
  );

  server.registerTool(
    "inspect_process",
    {
      title: "Inspect Process",
      description: "Inspect one local process by numeric PID without returning its environment or command-line arguments.",
      annotations: readOnlyAnnotations,
      inputSchema: z.object({
        pid: z.number().int().positive()
      }),
      outputSchema: z.object({ process: processSchema })
    },
    async ({ pid }) => toolResult({ process: await inspectProcess(pid) })
  );

  server.registerTool(
    "list_services",
    {
      title: "List Services",
      description: "List a bounded number of Windows services or systemd services and their states.",
      annotations: readOnlyAnnotations,
      inputSchema: z.object({
        limit: z.number().int().min(1).max(300).optional()
      }),
      outputSchema: z.object({ services: z.array(serviceSchema) })
    },
    async ({ limit }) => toolResult({ services: await listServices(limit) })
  );

  server.registerTool(
    "service_status",
    {
      title: "Service Status",
      description: "Inspect one Windows or systemd service. Service names are strictly validated before use.",
      annotations: readOnlyAnnotations,
      inputSchema: z.object({
        serviceName: z.string().min(1).max(128)
      }),
      outputSchema: z.object({ service: serviceSchema })
    },
    async ({ serviceName }) => toolResult({ service: await serviceStatus(serviceName) })
  );

  server.registerTool(
    "uptime",
    {
      title: "System Uptime",
      description: "Return system uptime in seconds, hours and days.",
      annotations: readOnlyAnnotations,
      inputSchema: z.object({}),
      outputSchema: z.object({
        uptimeSeconds: z.number(),
        uptimeHours: z.number(),
        uptimeDays: z.number()
      })
    },
    async () => toolResult(uptimeInfo())
  );

  registerEndpointInventoryTools(server);
  registerNetworkIntelligenceTools(server);
  registerEventEvidenceTools(server);

  return server;
}

const invokedPath = process.argv[1] ? pathToFileURL(process.argv[1]).href : undefined;
if (invokedPath === import.meta.url) {
  void serveStdio(createServer);
  console.error(`opschugex-localops-mcp v${VERSION} running on stdio`);
}
