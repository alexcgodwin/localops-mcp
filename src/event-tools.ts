import { McpServer } from "@modelcontextprotocol/server";
import * as z from "zod/v4";
import {
  accountCreationEvents,
  adminGroupChanges,
  defenderEvents,
  detectNewServices,
  failedLogins,
  linuxJournalLogs,
  loginEvents,
  processCreationEvents,
  recentSecurityChanges,
  recentSystemChanges,
  securityEvents,
  serviceInstallEvents,
  taskSchedulerEvents,
  windowsEventLogs
} from "./events.js";

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

const eventSchema = z.object({
  timestamp: z.string().nullable(),
  platform: z.enum(["windows", "linux"]),
  source: z.string(),
  eventId: z.number().nullable(),
  severity: z.string(),
  category: z.string(),
  actor: z.string().nullable(),
  target: z.string().nullable(),
  detail: z.string()
});

const windowInput = z.object({
  sinceHours: z.number().int().min(1).max(720).optional(),
  limit: z.number().int().min(1).max(500).optional()
});

const eventListOutput = z.object({
  events: z.array(eventSchema),
  limitation: z.string().nullable()
});

export function registerEventEvidenceTools(server: McpServer) {
  server.registerTool(
    "windows_event_logs",
    {
      title: "Windows Event Logs",
      description:
        "Read a bounded set of Windows Application, System, Security, Task Scheduler, or Defender event records. Event messages are normalized, secret-like values are redacted, and no log settings are changed.",
      annotations: readOnlyAnnotations,
      inputSchema: z.object({
        logName: z.enum([
          "Application",
          "System",
          "Security",
          "Microsoft-Windows-TaskScheduler/Operational",
          "Microsoft-Windows-Windows Defender/Operational"
        ]),
        eventIds: z.array(z.number().int().min(1).max(65535)).max(50).optional(),
        sinceHours: z.number().int().min(1).max(720).optional(),
        limit: z.number().int().min(1).max(500).optional()
      }),
      outputSchema: z.object({
        logName: z.string(),
        sinceHours: z.number(),
        events: z.array(eventSchema),
        accessible: z.boolean(),
        limitation: z.string().nullable()
      })
    },
    async ({ logName, eventIds, sinceHours, limit }) =>
      toolResult(
        await windowsEventLogs({
          logName,
          ids: eventIds,
          sinceHours,
          limit
        })
      )
  );

  server.registerTool(
    "linux_journal_logs",
    {
      title: "Linux Journal Logs",
      description:
        "Read bounded Linux journal evidence for an optional fixed systemd unit set and priority. It does not modify journald, audit policy or log retention.",
      annotations: readOnlyAnnotations,
      inputSchema: z.object({
        sinceHours: z.number().int().min(1).max(720).optional(),
        limit: z.number().int().min(1).max(500).optional(),
        priority: z.union([
          z.literal(0),
          z.literal(1),
          z.literal(2),
          z.literal(3),
          z.literal(4),
          z.literal(5),
          z.literal(6),
          z.literal(7)
        ]).optional(),
        units: z.array(z.string().min(1).max(128)).max(10).optional()
      }),
      outputSchema: z.object({
        sinceHours: z.number(),
        events: z.array(eventSchema),
        accessible: z.boolean(),
        limitation: z.string().nullable()
      })
    },
    async ({ sinceHours, limit, priority, units }) =>
      toolResult(
        await linuxJournalLogs({
          sinceHours,
          limit,
          priority,
          units
        })
      )
  );

  server.registerTool(
    "security_events",
    {
      title: "Security Events",
      description:
        "Return bounded security-relevant event evidence available from Windows Security logging or readable Linux journal entries. Missing audit coverage is reported as a limitation rather than inferred as safe.",
      annotations: readOnlyAnnotations,
      inputSchema: windowInput,
      outputSchema: z.object({
        events: z.array(eventSchema),
        limitation: z.string()
      })
    },
    async ({ sinceHours, limit }) =>
      toolResult(await securityEvents(sinceHours, limit))
  );

  server.registerTool(
    "login_events",
    {
      title: "Login Events",
      description:
        "Return successful login/session evidence from supported local OS logs. Visibility depends on the host's audit configuration.",
      annotations: readOnlyAnnotations,
      inputSchema: windowInput,
      outputSchema: eventListOutput
    },
    async ({ sinceHours, limit }) =>
      toolResult(await loginEvents(sinceHours, limit))
  );

  server.registerTool(
    "failed_logins",
    {
      title: "Failed Logins",
      description:
        "Return failed authentication evidence from supported local OS logs without attempting authentication or changing account state.",
      annotations: readOnlyAnnotations,
      inputSchema: windowInput,
      outputSchema: eventListOutput
    },
    async ({ sinceHours, limit }) =>
      toolResult(await failedLogins(sinceHours, limit))
  );

  server.registerTool(
    "service_install_events",
    {
      title: "Service Install Events",
      description:
        "Return Windows service-install evidence or bounded Linux service-change journal evidence. Linux results are best-effort and are not a complete package/service audit trail.",
      annotations: readOnlyAnnotations,
      inputSchema: windowInput,
      outputSchema: eventListOutput
    },
    async ({ sinceHours, limit }) =>
      toolResult(await serviceInstallEvents(sinceHours, limit))
  );

  server.registerTool(
    "account_creation_events",
    {
      title: "Account Creation Events",
      description:
        "Return local account-creation evidence from supported OS event sources. It never creates, enables, disables or changes an account.",
      annotations: readOnlyAnnotations,
      inputSchema: windowInput,
      outputSchema: eventListOutput
    },
    async ({ sinceHours, limit }) =>
      toolResult(await accountCreationEvents(sinceHours, limit))
  );

  server.registerTool(
    "admin_group_changes",
    {
      title: "Administrator Group Changes",
      description:
        "Return evidence of supported administrator/privileged-group membership changes. It does not modify group membership.",
      annotations: readOnlyAnnotations,
      inputSchema: windowInput,
      outputSchema: eventListOutput
    },
    async ({ sinceHours, limit }) =>
      toolResult(await adminGroupChanges(sinceHours, limit))
  );

  server.registerTool(
    "process_creation_events",
    {
      title: "Process Creation Events",
      description:
        "Return audited Windows process-creation events when Audit Process Creation is enabled. Linux process-creation evidence is left unknown unless an explicit audit source exists.",
      annotations: readOnlyAnnotations,
      inputSchema: windowInput,
      outputSchema: z.object({
        events: z.array(eventSchema),
        limitation: z.string()
      })
    },
    async ({ sinceHours, limit }) =>
      toolResult(await processCreationEvents(sinceHours, limit))
  );

  server.registerTool(
    "task_scheduler_events",
    {
      title: "Task Scheduler Events",
      description:
        "Return Windows scheduled-task change/operational evidence or bounded Linux scheduler/timer journal evidence. It does not expose arbitrary task actions or mutate schedules.",
      annotations: readOnlyAnnotations,
      inputSchema: windowInput,
      outputSchema: eventListOutput
    },
    async ({ sinceHours, limit }) =>
      toolResult(await taskSchedulerEvents(sinceHours, limit))
  );

  server.registerTool(
    "defender_events",
    {
      title: "Microsoft Defender Events",
      description:
        "Return bounded Microsoft Defender Operational events on Windows. This tool does not change Defender settings, exclusions or quarantine state.",
      annotations: readOnlyAnnotations,
      inputSchema: windowInput,
      outputSchema: z.object({
        events: z.array(eventSchema),
        limitation: z.string().nullable()
      })
    },
    async ({ sinceHours, limit }) =>
      toolResult(await defenderEvents(sinceHours, limit))
  );

  server.registerTool(
    "recent_system_changes",
    {
      title: "Recent System Changes",
      description:
        "Deterministically aggregate supported service-install and scheduler-change evidence into one recent-change view. This is evidence aggregation, not root-cause analysis.",
      annotations: readOnlyAnnotations,
      inputSchema: windowInput,
      outputSchema: z.object({
        events: z.array(eventSchema),
        categories: z.array(z.string()),
        limitation: z.string()
      })
    },
    async ({ sinceHours, limit }) =>
      toolResult(await recentSystemChanges(sinceHours, limit))
  );

  server.registerTool(
    "recent_security_changes",
    {
      title: "Recent Security Changes",
      description:
        "Deterministically aggregate supported account, privileged-group and Defender change evidence. It does not decide whether a host is compromised.",
      annotations: readOnlyAnnotations,
      inputSchema: windowInput,
      outputSchema: z.object({
        events: z.array(eventSchema),
        categories: z.array(z.string()),
        limitation: z.string()
      })
    },
    async ({ sinceHours, limit }) =>
      toolResult(await recentSecurityChanges(sinceHours, limit))
  );

  server.registerTool(
    "detect_new_services",
    {
      title: "Services Outside Baseline",
      description:
        "Compare current service names with a caller-supplied baseline. New means absent from that baseline, not malicious or unauthorized.",
      annotations: readOnlyAnnotations,
      inputSchema: z.object({
        baselineServiceNames: z.array(z.string().min(1).max(128)).max(500),
        limit: z.number().int().min(1).max(500).optional()
      }),
      outputSchema: z.object({
        baselineCount: z.number(),
        currentCount: z.number(),
        addedCount: z.number(),
        added: z.array(z.object({
          name: z.string(),
          status: z.string(),
          displayName: z.string()
        })),
        interpretation: z.string()
      })
    },
    async ({ baselineServiceNames, limit }) =>
      toolResult(await detectNewServices(baselineServiceNames, limit))
  );
}
