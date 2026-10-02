import { CommandRunner, defaultCommandRunner } from "./command.js";
import { listServices } from "./system.js";

type Platform = NodeJS.Platform;

export type EventEvidence = {
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

type WindowsLogName =
  | "Application"
  | "System"
  | "Security"
  | "Microsoft-Windows-TaskScheduler/Operational"
  | "Microsoft-Windows-Windows Defender/Operational";

const SECRET_PATTERN =
  /(token|password|passwd|secret|client_secret|authorization)\s*[=:]\s*[^\s,;]+/gi;

function clampLimit(value: number | undefined, fallback = 100, max = 500): number {
  const number = Number.isInteger(value) ? Number(value) : fallback;
  return Math.max(1, Math.min(number, max));
}

function clampHours(value: number | undefined): number {
  const number = Number.isFinite(value) ? Number(value) : 24;
  return Math.max(1, Math.min(Math.trunc(number), 24 * 30));
}

function sanitizeDetail(value: unknown, max = 1200): string {
  return String(value ?? "")
    .replace(SECRET_PATTERN, "$1=[REDACTED]")
    .replace(/[\r\n\t]+/g, " ")
    .replace(/\s{2,}/g, " ")
    .trim()
    .slice(0, max);
}

function asArray(value: unknown): any[] {
  if (value === null || value === undefined || value === "") return [];
  return Array.isArray(value) ? value : [value];
}

function isoDate(value: unknown): string | null {
  if (!value) return null;
  const date = new Date(String(value));
  return Number.isNaN(date.getTime()) ? null : date.toISOString();
}

function eventActor(detail: string): string | null {
  const patterns = [
    /Account Name:\s*([^\s]+)/i,
    /SubjectUserName[=:]\s*([^\s,;]+)/i,
    /User Name:\s*([^\s]+)/i,
    /user[=:]\s*([^\s,;]+)/i
  ];
  for (const pattern of patterns) {
    const match = detail.match(pattern);
    if (match?.[1] && match[1] !== "-") return match[1].slice(0, 200);
  }
  return null;
}

function eventTarget(detail: string): string | null {
  const patterns = [
    /Target Account Name:\s*([^\s]+)/i,
    /TargetUserName[=:]\s*([^\s,;]+)/i,
    /Service Name:\s*([^\r\n]+)/i,
    /Task Name:\s*([^\r\n]+)/i
  ];
  for (const pattern of patterns) {
    const match = detail.match(pattern);
    if (match?.[1] && match[1] !== "-") return sanitizeDetail(match[1], 200);
  }
  return null;
}

function normalizeWindowsEvent(item: any, category: string): EventEvidence {
  const detail = sanitizeDetail(item.Message);
  return {
    timestamp: isoDate(item.TimeCreated),
    platform: "windows",
    source: String(item.ProviderName ?? "Windows Event Log"),
    eventId: Number.isFinite(Number(item.Id)) ? Number(item.Id) : null,
    severity: String(item.LevelDisplayName ?? "Information"),
    category,
    actor: eventActor(detail),
    target: eventTarget(detail),
    detail
  };
}

function priorityName(priority: unknown): string {
  const value = Number(priority);
  const names = [
    "emergency",
    "alert",
    "critical",
    "error",
    "warning",
    "notice",
    "info",
    "debug"
  ];
  return Number.isInteger(value) && value >= 0 && value <= 7
    ? names[value]
    : "unknown";
}

function normalizeJournalEvent(item: any, category: string): EventEvidence {
  const micros = Number(item.__REALTIME_TIMESTAMP ?? 0);
  const timestamp =
    Number.isFinite(micros) && micros > 0
      ? new Date(Math.floor(micros / 1000)).toISOString()
      : null;
  const detail = sanitizeDetail(item.MESSAGE);
  return {
    timestamp,
    platform: "linux",
    source: String(
      item.SYSLOG_IDENTIFIER ??
        item._SYSTEMD_UNIT ??
        item._COMM ??
        "journal"
    ),
    eventId: null,
    severity: priorityName(item.PRIORITY),
    category,
    actor: eventActor(detail),
    target: eventTarget(detail),
    detail
  };
}

export async function windowsEventLogs(
  input: {
    logName: WindowsLogName;
    ids?: number[];
    sinceHours?: number;
    limit?: number;
    category?: string;
  },
  runner: CommandRunner = defaultCommandRunner
) {
  const sinceHours = clampHours(input.sinceHours);
  const limit = clampLimit(input.limit);
  const ids = (input.ids ?? [])
    .filter((value) => Number.isInteger(value) && value > 0)
    .slice(0, 50);
  const idExpression = ids.length > 0 ? "; Id=@(" + ids.join(",") + ")" : "";
  const script =
    "$filter = @{LogName='" +
    input.logName +
    "'; StartTime=(Get-Date).AddHours(-" +
    sinceHours +
    ")" +
    idExpression +
    "}; Get-WinEvent -FilterHashtable $filter -MaxEvents " +
    limit +
    " -ErrorAction Stop | Select-Object TimeCreated,Id,LevelDisplayName,ProviderName,Message | ConvertTo-Json -Compress";

  const result = await runner(
    "powershell.exe",
    ["-NoProfile", "-NonInteractive", "-Command", script],
    true
  );

  if (result.exitCode !== 0) {
    return {
      logName: input.logName,
      sinceHours,
      events: [] as EventEvidence[],
      accessible: false,
      limitation: sanitizeDetail(
        result.stderr || result.stdout || "Event log unavailable.",
        500
      )
    };
  }

  let parsed: any[] = [];
  try {
    parsed = asArray(JSON.parse(result.stdout || "[]"));
  } catch {
    return {
      logName: input.logName,
      sinceHours,
      events: [] as EventEvidence[],
      accessible: false,
      limitation: "Windows event output could not be parsed."
    };
  }

  return {
    logName: input.logName,
    sinceHours,
    events: parsed.map((item) =>
      normalizeWindowsEvent(item, input.category ?? "windows-event")
    ),
    accessible: true,
    limitation: null as string | null
  };
}

function safeUnit(unit: string): string {
  const value = unit.trim();
  if (!/^[A-Za-z0-9_.@:-]{1,128}$/.test(value)) {
    throw new Error("journal unit contains unsupported characters.");
  }
  return value;
}

export async function linuxJournalLogs(
  input: {
    sinceHours?: number;
    limit?: number;
    priority?: 0 | 1 | 2 | 3 | 4 | 5 | 6 | 7;
    units?: string[];
    category?: string;
  } = {},
  runner: CommandRunner = defaultCommandRunner
) {
  const sinceHours = clampHours(input.sinceHours);
  const limit = clampLimit(input.limit);
  const args = [
    "--since",
    "-" + sinceHours + "h",
    "--no-pager",
    "--output=json",
    "-n",
    String(limit)
  ];

  if (input.priority !== undefined) {
    args.push("--priority", String(input.priority));
  }

  for (const unit of (input.units ?? []).slice(0, 10)) {
    args.push("--unit", safeUnit(unit));
  }

  const result = await runner("journalctl", args, true);
  if (result.exitCode !== 0) {
    return {
      sinceHours,
      events: [] as EventEvidence[],
      accessible: false,
      limitation: sanitizeDetail(
        result.stderr || result.stdout || "Journal unavailable.",
        500
      )
    };
  }

  const events = result.stdout
    .split(/\r?\n/)
    .filter(Boolean)
    .flatMap((line) => {
      try {
        return [
          normalizeJournalEvent(
            JSON.parse(line),
            input.category ?? "journal"
          )
        ];
      } catch {
        return [];
      }
    });

  return {
    sinceHours,
    events,
    accessible: true,
    limitation: null as string | null
  };
}

function sortEvents(events: EventEvidence[], limit: number): EventEvidence[] {
  return [...events]
    .sort((a, b) => {
      const left = a.timestamp ? new Date(a.timestamp).getTime() : 0;
      const right = b.timestamp ? new Date(b.timestamp).getTime() : 0;
      return right - left;
    })
    .slice(0, limit);
}

async function windowsFixedEvents(
  logName: WindowsLogName,
  ids: number[],
  category: string,
  sinceHours: number,
  limit: number,
  runner: CommandRunner
): Promise<{ events: EventEvidence[]; limitation: string | null }> {
  const result = await windowsEventLogs(
    { logName, ids, sinceHours, limit, category },
    runner
  );
  return {
    events: result.events,
    limitation: result.accessible ? null : result.limitation
  };
}

async function linuxAuthJournal(
  category: string,
  sinceHours: number,
  limit: number,
  runner: CommandRunner
): Promise<{ events: EventEvidence[]; limitation: string | null }> {
  const result = await linuxJournalLogs(
    {
      sinceHours,
      limit: Math.min(limit * 4, 500),
      units: ["ssh.service", "sshd.service"],
      category
    },
    runner
  );
  return {
    events: result.events,
    limitation: result.accessible ? null : result.limitation
  };
}

export async function loginEvents(
  sinceHours = 24,
  limit = 100,
  runner: CommandRunner = defaultCommandRunner,
  platform: Platform = process.platform
) {
  const safeHours = clampHours(sinceHours);
  const safeLimit = clampLimit(limit);

  if (platform === "win32") {
    return windowsFixedEvents(
      "Security",
      [4624],
      "login-success",
      safeHours,
      safeLimit,
      runner
    );
  }

  const result = await linuxAuthJournal(
    "login-success",
    safeHours,
    safeLimit,
    runner
  );
  return {
    events: result.events
      .filter((event) =>
        /(accepted|session opened|successful login|logged in)/i.test(event.detail)
      )
      .slice(0, safeLimit),
    limitation: result.limitation
  };
}

export async function failedLogins(
  sinceHours = 24,
  limit = 100,
  runner: CommandRunner = defaultCommandRunner,
  platform: Platform = process.platform
) {
  const safeHours = clampHours(sinceHours);
  const safeLimit = clampLimit(limit);

  if (platform === "win32") {
    return windowsFixedEvents(
      "Security",
      [4625],
      "login-failure",
      safeHours,
      safeLimit,
      runner
    );
  }

  const result = await linuxAuthJournal(
    "login-failure",
    safeHours,
    safeLimit,
    runner
  );
  return {
    events: result.events
      .filter((event) =>
        /(failed password|authentication failure|failed login|invalid user)/i.test(
          event.detail
        )
      )
      .slice(0, safeLimit),
    limitation: result.limitation
  };
}

export async function serviceInstallEvents(
  sinceHours = 24,
  limit = 100,
  runner: CommandRunner = defaultCommandRunner,
  platform: Platform = process.platform
) {
  const safeHours = clampHours(sinceHours);
  const safeLimit = clampLimit(limit);

  if (platform === "win32") {
    return windowsFixedEvents(
      "System",
      [7045],
      "service-install",
      safeHours,
      safeLimit,
      runner
    );
  }

  const result = await linuxJournalLogs(
    {
      sinceHours: safeHours,
      limit: Math.min(safeLimit * 5, 500),
      category: "service-change"
    },
    runner
  );
  return {
    events: result.events
      .filter((event) =>
        /(created symlink|unit file|daemon-reload|reloading systemd|enabled .*service|installed .*service)/i.test(
          event.detail
        )
      )
      .slice(0, safeLimit),
    limitation: result.accessible ? null : result.limitation
  };
}

export async function accountCreationEvents(
  sinceHours = 24,
  limit = 100,
  runner: CommandRunner = defaultCommandRunner,
  platform: Platform = process.platform
) {
  const safeHours = clampHours(sinceHours);
  const safeLimit = clampLimit(limit);

  if (platform === "win32") {
    return windowsFixedEvents(
      "Security",
      [4720],
      "account-created",
      safeHours,
      safeLimit,
      runner
    );
  }

  const result = await linuxJournalLogs(
    {
      sinceHours: safeHours,
      limit: Math.min(safeLimit * 5, 500),
      category: "account-created"
    },
    runner
  );
  return {
    events: result.events
      .filter((event) =>
        /(new user|useradd|adduser|created user|new account)/i.test(event.detail)
      )
      .slice(0, safeLimit),
    limitation: result.accessible ? null : result.limitation
  };
}

export async function adminGroupChanges(
  sinceHours = 24,
  limit = 100,
  runner: CommandRunner = defaultCommandRunner,
  platform: Platform = process.platform
) {
  const safeHours = clampHours(sinceHours);
  const safeLimit = clampLimit(limit);

  if (platform === "win32") {
    return windowsFixedEvents(
      "Security",
      [4728, 4729, 4732, 4733, 4756, 4757],
      "admin-group-change",
      safeHours,
      safeLimit,
      runner
    );
  }

  const result = await linuxJournalLogs(
    {
      sinceHours: safeHours,
      limit: Math.min(safeLimit * 5, 500),
      category: "admin-group-change"
    },
    runner
  );
  return {
    events: result.events
      .filter((event) =>
        /(sudo|wheel|admin).*(added|removed|member|group)|usermod.*-a.*-g/i.test(
          event.detail
        )
      )
      .slice(0, safeLimit),
    limitation: result.accessible ? null : result.limitation
  };
}

export async function processCreationEvents(
  sinceHours = 24,
  limit = 100,
  runner: CommandRunner = defaultCommandRunner,
  platform: Platform = process.platform
) {
  const safeHours = clampHours(sinceHours);
  const safeLimit = clampLimit(limit);

  if (platform === "win32") {
    const result = await windowsFixedEvents(
      "Security",
      [4688],
      "process-created",
      safeHours,
      safeLimit,
      runner
    );
    return {
      events: result.events,
      limitation:
        result.limitation ??
        "Windows process-creation evidence depends on Audit Process Creation policy."
    };
  }

  return {
    events: [] as EventEvidence[],
    limitation:
      "Generic Linux process-creation auditing is not assumed. Configure auditd, eBPF telemetry or an equivalent source before exposing process-creation evidence."
  };
}

export async function taskSchedulerEvents(
  sinceHours = 24,
  limit = 100,
  runner: CommandRunner = defaultCommandRunner,
  platform: Platform = process.platform
) {
  const safeHours = clampHours(sinceHours);
  const safeLimit = clampLimit(limit);

  if (platform === "win32") {
    const security = await windowsFixedEvents(
      "Security",
      [4698, 4699, 4700, 4701, 4702],
      "scheduled-task-change",
      safeHours,
      safeLimit,
      runner
    );
    const operational = await windowsFixedEvents(
      "Microsoft-Windows-TaskScheduler/Operational",
      [106, 140, 141, 200, 201],
      "scheduled-task-event",
      safeHours,
      safeLimit,
      runner
    );
    const limitations = [security.limitation, operational.limitation].filter(Boolean);
    return {
      events: sortEvents([...security.events, ...operational.events], safeLimit),
      limitation: limitations.length ? limitations.join(" | ") : null
    };
  }

  const result = await linuxJournalLogs(
    {
      sinceHours: safeHours,
      limit: Math.min(safeLimit * 5, 500),
      category: "scheduler-event"
    },
    runner
  );
  return {
    events: result.events
      .filter((event) =>
        /(cron|crond|systemd.*timer|timer unit)/i.test(
          event.source + " " + event.detail
        )
      )
      .slice(0, safeLimit),
    limitation: result.accessible ? null : result.limitation
  };
}

export async function defenderEvents(
  sinceHours = 24,
  limit = 100,
  runner: CommandRunner = defaultCommandRunner,
  platform: Platform = process.platform
) {
  const safeHours = clampHours(sinceHours);
  const safeLimit = clampLimit(limit);

  if (platform !== "win32") {
    return {
      events: [] as EventEvidence[],
      limitation: "Microsoft Defender Operational log is Windows-specific."
    };
  }

  return windowsFixedEvents(
    "Microsoft-Windows-Windows Defender/Operational",
    [1116, 1117, 1118, 5001, 5007, 5010, 5012],
    "defender-event",
    safeHours,
    safeLimit,
    runner
  );
}

export async function securityEvents(
  sinceHours = 24,
  limit = 200,
  runner: CommandRunner = defaultCommandRunner,
  platform: Platform = process.platform
) {
  const safeHours = clampHours(sinceHours);
  const safeLimit = clampLimit(limit, 200, 500);

  if (platform === "win32") {
    const result = await windowsFixedEvents(
      "Security",
      [4624, 4625, 4688, 4720, 4728, 4729, 4732, 4733, 4756, 4757],
      "security-event",
      safeHours,
      safeLimit,
      runner
    );
    return {
      events: result.events,
      limitation:
        result.limitation ??
        "Security log visibility depends on local audit policy and LocalOps process permissions."
    };
  }

  const result = await linuxJournalLogs(
    {
      sinceHours: safeHours,
      limit: safeLimit,
      priority: 4,
      category: "security-event"
    },
    runner
  );
  return {
    events: result.events,
    limitation:
      result.limitation ??
      "Linux security evidence is bounded to readable journal entries; auditd or eBPF sources are not assumed."
  };
}

export async function recentSystemChanges(
  sinceHours = 24,
  limit = 200,
  runner: CommandRunner = defaultCommandRunner,
  platform: Platform = process.platform
) {
  const safeLimit = clampLimit(limit, 200, 500);
  const [services, tasks] = await Promise.all([
    serviceInstallEvents(sinceHours, safeLimit, runner, platform),
    taskSchedulerEvents(sinceHours, safeLimit, runner, platform)
  ]);
  const sourceLimitations = [services.limitation, tasks.limitation].filter(Boolean);
  return {
    events: sortEvents([...services.events, ...tasks.events], safeLimit),
    categories: [
      "service-install",
      "scheduled-task-change",
      "scheduled-task-event"
    ],
    limitation:
      [
        "This is deterministic aggregation of supported event sources, not root-cause analysis.",
        ...sourceLimitations
      ].join(" | ")
  };
}

export async function recentSecurityChanges(
  sinceHours = 24,
  limit = 200,
  runner: CommandRunner = defaultCommandRunner,
  platform: Platform = process.platform
) {
  const safeLimit = clampLimit(limit, 200, 500);
  const [accounts, groups, defender] = await Promise.all([
    accountCreationEvents(sinceHours, safeLimit, runner, platform),
    adminGroupChanges(sinceHours, safeLimit, runner, platform),
    defenderEvents(sinceHours, safeLimit, runner, platform)
  ]);
  const sourceLimitations = [
    accounts.limitation,
    groups.limitation,
    defender.limitation
  ].filter(Boolean);
  return {
    events: sortEvents(
      [...accounts.events, ...groups.events, ...defender.events],
      safeLimit
    ),
    categories: ["account-created", "admin-group-change", "defender-event"],
    limitation:
      [
        "This is deterministic aggregation of supported security-change evidence, not a compromise determination.",
        ...sourceLimitations
      ].join(" | ")
  };
}

export async function detectNewServices(
  baselineServiceNames: string[],
  limit = 300,
  runner: CommandRunner = defaultCommandRunner,
  platform: Platform = process.platform
) {
  const safeLimit = clampLimit(limit, 300, 500);
  const baseline = new Set(
    baselineServiceNames
      .slice(0, 500)
      .map((name) => name.trim().toLowerCase())
      .filter(Boolean)
  );
  const current = await listServices(safeLimit, runner, platform);
  const normalized = current.map((service: any) => ({
    name: String(service.name ?? ""),
    status: String(
      service.status ??
        service.activeState ??
        service.subState ??
        "unknown"
    ),
    displayName: String(
      service.displayName ??
        service.description ??
        ""
    )
  }));
  const added = normalized.filter(
    (service) => !baseline.has(service.name.toLowerCase())
  );
  return {
    baselineCount: Math.min(baselineServiceNames.length, 500),
    currentCount: normalized.length,
    addedCount: added.length,
    added,
    interpretation:
      "New means absent from the caller-supplied service-name baseline. It does not mean malicious or unauthorized."
  };
}
