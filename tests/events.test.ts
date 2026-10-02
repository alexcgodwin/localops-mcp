import { describe, expect, it } from "vitest";
import type { CommandRunner } from "../src/command.js";
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
} from "../src/events.js";

function output(stdout: string, exitCode = 0, stderr = "") {
  return { stdout, stderr, exitCode };
}

function windowsEventRunner(payload: unknown): CommandRunner {
  return async () => output(JSON.stringify(payload));
}

function journalRunner(lines: unknown[]): CommandRunner {
  return async () => output(lines.map((line) => JSON.stringify(line)).join("\n"));
}

describe("Windows event evidence", () => {
  it("normalizes and redacts bounded Windows event messages", async () => {
    const result = await windowsEventLogs(
      {
        logName: "System",
        ids: [7045],
        sinceHours: 12,
        limit: 20,
        category: "service-install"
      },
      windowsEventRunner({
        TimeCreated: "2026-10-02T08:00:00Z",
        Id: 7045,
        LevelDisplayName: "Information",
        ProviderName: "Service Control Manager",
        Message: "Service Name: DemoService token=super-secret"
      })
    );

    expect(result.accessible).toBe(true);
    expect(result.events[0]).toMatchObject({
      eventId: 7045,
      category: "service-install",
      source: "Service Control Manager"
    });
    expect(result.events[0].detail).not.toContain("super-secret");
    expect(result.events[0].detail).toContain("token=[REDACTED]");
  });

  it("reports inaccessible Windows logs instead of bypassing permissions", async () => {
    const runner: CommandRunner = async () =>
      output("", 1, "Access is denied");

    const result = await windowsEventLogs(
      { logName: "Security", limit: 10 },
      runner
    );

    expect(result.accessible).toBe(false);
    expect(result.events).toEqual([]);
    expect(result.limitation).toContain("Access is denied");
  });

  it("uses the fixed service-install event id on Windows", async () => {
    let command = "";
    const runner: CommandRunner = async (_exe, args) => {
      command = args.at(-1) ?? "";
      return output("[]");
    };

    await serviceInstallEvents(24, 10, runner, "win32");
    expect(command).toContain("Id=@(7045)");
  });

  it("uses Windows audit ids for account and admin-group changes", async () => {
    const commands: string[] = [];
    const runner: CommandRunner = async (_exe, args) => {
      commands.push(args.at(-1) ?? "");
      return output("[]");
    };

    await accountCreationEvents(24, 10, runner, "win32");
    await adminGroupChanges(24, 10, runner, "win32");

    expect(commands[0]).toContain("4720");
    expect(commands[1]).toContain("4732");
    expect(commands[1]).toContain("4756");
  });

  it("preserves permission failures in high-level Windows evidence tools", async () => {
    const runner: CommandRunner = async () =>
      output("", 1, "Access is denied");

    const result = await loginEvents(24, 10, runner, "win32");

    expect(result.events).toEqual([]);
    expect(result.limitation).toContain("Access is denied");
  });
});

describe("Linux journal evidence", () => {
  it("normalizes JSON journal records", async () => {
    const result = await linuxJournalLogs(
      { sinceHours: 6, limit: 20, category: "test" },
      journalRunner([
        {
          __REALTIME_TIMESTAMP: "1790928000000000",
          SYSLOG_IDENTIFIER: "sshd",
          PRIORITY: "4",
          MESSAGE: "Failed password for invalid user demo"
        }
      ])
    );

    expect(result.accessible).toBe(true);
    expect(result.events[0]).toMatchObject({
      platform: "linux",
      source: "sshd",
      severity: "warning",
      category: "test"
    });
  });

  it("filters successful and failed SSH evidence separately", async () => {
    const runner = journalRunner([
      {
        __REALTIME_TIMESTAMP: "1790928000000000",
        SYSLOG_IDENTIFIER: "sshd",
        PRIORITY: "6",
        MESSAGE: "Accepted publickey for alex from 192.0.2.10"
      },
      {
        __REALTIME_TIMESTAMP: "1790927900000000",
        SYSLOG_IDENTIFIER: "sshd",
        PRIORITY: "4",
        MESSAGE: "Failed password for invalid user demo from 192.0.2.20"
      }
    ]);

    const success = await loginEvents(24, 20, runner, "linux");
    const failed = await failedLogins(24, 20, runner, "linux");

    expect(success.events).toHaveLength(1);
    expect(success.events[0].detail).toContain("Accepted publickey");
    expect(success.limitation).toBeNull();
    expect(failed.events).toHaveLength(1);
    expect(failed.events[0].detail).toContain("Failed password");
    expect(failed.limitation).toBeNull();
  });

  it("does not pretend generic Linux process auditing exists", async () => {
    const result = await processCreationEvents(
      24,
      20,
      journalRunner([]),
      "linux"
    );

    expect(result.events).toEqual([]);
    expect(result.limitation).toContain("auditd");
  });
});

describe("fixed security evidence categories", () => {
  it("returns Windows login and process audit evidence", async () => {
    const commands: string[] = [];
    const runner: CommandRunner = async (_exe, args) => {
      commands.push(args.at(-1) ?? "");
      return output("[]");
    };

    await loginEvents(24, 10, runner, "win32");
    await failedLogins(24, 10, runner, "win32");
    await processCreationEvents(24, 10, runner, "win32");

    expect(commands[0]).toContain("4624");
    expect(commands[1]).toContain("4625");
    expect(commands[2]).toContain("4688");
  });

  it("uses supported task-scheduler evidence sources", async () => {
    const commands: string[] = [];
    const runner: CommandRunner = async (_exe, args) => {
      commands.push(args.at(-1) ?? "");
      return output("[]");
    };

    await taskSchedulerEvents(24, 20, runner, "win32");

    expect(commands).toHaveLength(2);
    expect(commands[0]).toContain("4698");
    expect(commands[1]).toContain("TaskScheduler/Operational");
    expect(commands[1]).toContain("106");
  });

  it("uses bounded Defender operational event ids", async () => {
    let command = "";
    const runner: CommandRunner = async (_exe, args) => {
      command = args.at(-1) ?? "";
      return output("[]");
    };

    const result = await defenderEvents(24, 20, runner, "win32");

    expect(result.limitation).toBeNull();
    expect(command).toContain("Windows Defender/Operational");
    expect(command).toContain("1116");
    expect(command).toContain("5007");
  });

  it("documents Windows security-log audit dependence", async () => {
    const result = await securityEvents(
      24,
      20,
      windowsEventRunner([]),
      "win32"
    );

    expect(result.events).toEqual([]);
    expect(result.limitation).toContain("audit policy");
  });
});

describe("bounded aggregation and baselines", () => {
  it("aggregates recent system-change evidence without root-cause claims", async () => {
    const runner: CommandRunner = async (_exe, args) => {
      const command = args.at(-1) ?? "";
      if (command.includes("7045")) {
        return output(JSON.stringify({
          TimeCreated: "2026-10-02T08:00:00Z",
          Id: 7045,
          LevelDisplayName: "Information",
          ProviderName: "Service Control Manager",
          Message: "Service Name: DemoService"
        }));
      }
      return output("[]");
    };

    const result = await recentSystemChanges(24, 20, runner, "win32");

    expect(result.events).toHaveLength(1);
    expect(result.events[0].category).toBe("service-install");
    expect(result.limitation).toContain("not root-cause analysis");
  });

  it("aggregates recent security changes without compromise claims", async () => {
    const runner: CommandRunner = async (_exe, args) => {
      const command = args.at(-1) ?? "";
      if (command.includes("4720")) {
        return output(JSON.stringify({
          TimeCreated: "2026-10-02T07:00:00Z",
          Id: 4720,
          LevelDisplayName: "Information",
          ProviderName: "Microsoft-Windows-Security-Auditing",
          Message: "Target Account Name: demo"
        }));
      }
      return output("[]");
    };

    const result = await recentSecurityChanges(24, 20, runner, "win32");

    expect(result.events).toHaveLength(1);
    expect(result.events[0].category).toBe("account-created");
    expect(result.limitation).toContain("not a compromise determination");
  });

  it("detects services only relative to a caller-supplied baseline", async () => {
    const runner: CommandRunner = async () =>
      output(JSON.stringify([
        {
          Name: "KnownService",
          DisplayName: "Known",
          Status: "Running",
          StartType: "Automatic"
        },
        {
          Name: "NewService",
          DisplayName: "New",
          Status: "Stopped",
          StartType: "Manual"
        }
      ]));

    const result = await detectNewServices(
      ["KnownService"],
      20,
      runner,
      "win32"
    );

    expect(result.addedCount).toBe(1);
    expect(result.added[0].name).toBe("NewService");
    expect(result.interpretation).toContain("does not mean malicious");
  });
});
