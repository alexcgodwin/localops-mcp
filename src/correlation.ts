import { localAdmins, localUsers, scheduledTasks, startupPrograms } from "./endpoint.js";
import {
  failedLogins,
  loginEvents,
  processCreationEvents,
  recentSecurityChanges,
  recentSystemChanges
} from "./events.js";
import { networkConnections } from "./network.js";
import { listProcesses, listServices } from "./system.js";

type EvidenceEvent = {
  timestamp: string | null;
  platform: "windows" | "linux";
  source: string;
  eventId: number | null;
  severity: string;
  category: string;
  actor: string | null;
  target: string | null;
  detail: string;
};

function boundedLimit(value: number | undefined): number {
  const number = Number.isInteger(value) ? Number(value) : 100;
  return Math.max(10, Math.min(number, 300));
}

function boundedWindow(value: number | undefined): number {
  const number = Number.isInteger(value) ? Number(value) : 24;
  return Math.max(1, Math.min(number, 720));
}

async function capture<T>(
  label: string,
  operation: () => Promise<T>,
  fallback: T,
  limitations: string[]
): Promise<T> {
  try {
    return await operation();
  } catch (error) {
    limitations.push(
      label +
        " unavailable: " +
        (error instanceof Error ? error.message : String(error))
    );
    return fallback;
  }
}

function addLimitation(
  limitations: string[],
  value: string | null | undefined
) {
  if (value && value.trim()) limitations.push(value.trim());
}

function dedupeEvents(events: EvidenceEvent[], limit: number): EvidenceEvent[] {
  const seen = new Set<string>();
  const output: EvidenceEvent[] = [];

  for (const event of events) {
    const key = [
      event.timestamp ?? "",
      event.source,
      event.eventId ?? "",
      event.category,
      event.actor ?? "",
      event.target ?? "",
      event.detail
    ].join("|");

    if (seen.has(key)) continue;
    seen.add(key);
    output.push(event);
    if (output.length >= limit * 4) break;
  }

  return output;
}

export async function collectCorrelationEvidence(
  windowHours = 24,
  limit = 100
) {
  const safeWindow = boundedWindow(windowHours);
  const safeLimit = boundedLimit(limit);
  const limitations: string[] = [];

  const [
    processes,
    services,
    connections,
    startup,
    tasks,
    users,
    admins,
    systemChanges,
    securityChanges,
    successfulLogins,
    loginFailures,
    processEvents
  ] = await Promise.all([
    capture(
      "process inventory",
      () => listProcesses(safeLimit),
      [],
      limitations
    ),
    capture(
      "service inventory",
      () => listServices(safeLimit),
      [],
      limitations
    ),
    capture(
      "network connection inventory",
      () => networkConnections(safeLimit * 2),
      [],
      limitations
    ),
    capture(
      "startup program inventory",
      () => startupPrograms(safeLimit),
      [],
      limitations
    ),
    capture(
      "scheduled task inventory",
      () => scheduledTasks(safeLimit),
      [],
      limitations
    ),
    capture(
      "local user inventory",
      () => localUsers(safeLimit),
      [],
      limitations
    ),
    capture(
      "local administrator inventory",
      () => localAdmins(),
      [],
      limitations
    ),
    capture(
      "recent system-change evidence",
      () => recentSystemChanges(safeWindow, safeLimit),
      {
        events: [] as EvidenceEvent[],
        categories: [] as string[],
        limitation: "Recent system-change evidence unavailable."
      },
      limitations
    ),
    capture(
      "recent security-change evidence",
      () => recentSecurityChanges(safeWindow, safeLimit),
      {
        events: [] as EvidenceEvent[],
        categories: [] as string[],
        limitation: "Recent security-change evidence unavailable."
      },
      limitations
    ),
    capture(
      "successful login evidence",
      () => loginEvents(safeWindow, safeLimit),
      {
        events: [] as EvidenceEvent[],
        limitation: "Successful login evidence unavailable."
      },
      limitations
    ),
    capture(
      "failed login evidence",
      () => failedLogins(safeWindow, safeLimit),
      {
        events: [] as EvidenceEvent[],
        limitation: "Failed login evidence unavailable."
      },
      limitations
    ),
    capture(
      "process creation evidence",
      () => processCreationEvents(safeWindow, safeLimit),
      {
        events: [] as EvidenceEvent[],
        limitation: "Process creation evidence unavailable."
      },
      limitations
    )
  ]);

  addLimitation(limitations, systemChanges.limitation);
  addLimitation(limitations, securityChanges.limitation);
  addLimitation(limitations, successfulLogins.limitation);
  addLimitation(limitations, loginFailures.limitation);
  addLimitation(limitations, processEvents.limitation);

  const events = dedupeEvents(
    [
      ...systemChanges.events,
      ...securityChanges.events,
      ...successfulLogins.events,
      ...loginFailures.events,
      ...processEvents.events
    ],
    safeLimit
  );

  const uniqueLimitations = [...new Set(limitations.filter(Boolean))];

  return {
    collectedAt: new Date().toISOString(),
    windowHours: safeWindow,
    processes: processes.slice(0, safeLimit).map((process: any) => ({
      pid: Number(process.pid),
      name: String(process.name ?? ""),
      ...(Number.isFinite(Number(process.parentPid))
        ? { parentPid: Number(process.parentPid) }
        : {}),
      ...(process.user ? { user: String(process.user) } : {})
    })),
    services: services.slice(0, safeLimit).map((service: any) => ({
      name: String(service.name ?? ""),
      ...(service.displayName
        ? { displayName: String(service.displayName) }
        : {}),
      ...(service.status ? { status: String(service.status) } : {}),
      ...(service.activeState
        ? { activeState: String(service.activeState) }
        : {}),
      ...(service.description
        ? { description: String(service.description) }
        : {})
    })),
    connections: connections.slice(0, safeLimit * 2),
    events,
    startupPrograms: startup.slice(0, safeLimit),
    scheduledTasks: tasks.slice(0, safeLimit),
    users: users.slice(0, safeLimit).map((user: any) => ({
      name: String(user.name ?? "")
    })),
    admins: admins.slice(0, safeLimit).map((admin: any) => ({
      name: String(admin.name ?? "")
    })),
    limitations: uniqueLimitations
  };
}
