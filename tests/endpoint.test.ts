import { afterEach, describe, expect, it } from "vitest";
import type { CommandRunner } from "../src/command.js";
import {
  certificateExpiry,
  certificateInventory,
  environmentVariablesSummary,
  installedSoftware,
  localAdmins,
  localGroups,
  localUsers,
  scheduledTasks,
  softwareChanges,
  softwareVersions,
  startupPrograms
} from "../src/endpoint.js";

function output(stdout: string, exitCode = 0) {
  return { stdout, stderr: "", exitCode };
}

function windowsRunner(payload: unknown): CommandRunner {
  return async () => output(JSON.stringify(payload));
}

describe("installed software inventory", () => {
  it("normalizes Windows uninstall registry metadata", async () => {
    const inventory = await installedSoftware(
      20,
      windowsRunner({
        DisplayName: "Example App",
        DisplayVersion: "2.4.1",
        Publisher: "Example Corp",
        InstallDate: "20261001"
      }),
      "win32"
    );

    expect(inventory.packageManager).toBe("windows-registry");
    expect(inventory.packages[0]).toMatchObject({
      name: "Example App",
      version: "2.4.1",
      publisher: "Example Corp",
      installDate: "2026-10-01"
    });
  });

  it("uses dpkg metadata on Debian-family Linux", async () => {
    const runner: CommandRunner = async (executable) => {
      if (executable === "dpkg-query") {
        return output("curl\t8.0\tDebian\nopenssl\t3.0\tDebian");
      }
      return output("", 1);
    };

    const inventory = await installedSoftware(20, runner, "linux");
    expect(inventory.packageManager).toBe("dpkg");
    expect(inventory.packages).toHaveLength(2);
    expect(inventory.packages[0].name).toBe("curl");
  });

  it("looks up requested software versions", async () => {
    const matches = await softwareVersions(
      ["example"],
      windowsRunner([
        {
          DisplayName: "Example App",
          DisplayVersion: "3.0",
          Publisher: "Example Corp",
          InstallDate: null
        },
        {
          DisplayName: "Other Tool",
          DisplayVersion: "1.0",
          Publisher: "Other",
          InstallDate: null
        }
      ]),
      "win32"
    );

    expect(matches.matches).toHaveLength(1);
    expect(matches.matches[0].version).toBe("3.0");
  });

  it("compares current software against a supplied baseline", async () => {
    const result = await softwareChanges(
      [
        { name: "Example App", version: "1.0" },
        { name: "Removed App", version: "5.0" }
      ],
      windowsRunner([
        {
          DisplayName: "Example App",
          DisplayVersion: "2.0",
          Publisher: "Example",
          InstallDate: null
        },
        {
          DisplayName: "New App",
          DisplayVersion: "1.0",
          Publisher: "New",
          InstallDate: null
        }
      ]),
      "win32"
    );

    expect(result.added.map((item) => item.name)).toContain("New App");
    expect(result.removed.map((item) => item.name)).toContain("Removed App");
    expect(result.versionChanged[0]).toMatchObject({
      name: "Example App",
      previousVersion: "1.0",
      currentVersion: "2.0"
    });
  });
});

describe("identity inventory", () => {
  it("returns Windows local users without credential material", async () => {
    const users = await localUsers(
      20,
      windowsRunner({
        Name: "Owner",
        Enabled: true,
        LastLogon: "2026-10-01T10:00:00Z",
        PasswordRequired: true,
        UserMayChangePassword: true
      }),
      "win32"
    );

    expect(users[0].name).toBe("Owner");
    expect(JSON.stringify(users)).not.toMatch(/passwordhash|credential|secret/i);
  });

  it("parses Linux groups", async () => {
    const runner: CommandRunner = async () =>
      output("sudo:x:27:alex,bob\ndevelopers:x:1001:alex");

    const groups = await localGroups(20, runner, "linux");
    expect(groups[0]).toMatchObject({
      name: "sudo",
      gid: 27,
      members: ["alex", "bob"]
    });
  });

  it("returns Windows administrator membership metadata", async () => {
    const admins = await localAdmins(
      windowsRunner({
        Name: "HOST\\Owner",
        ObjectClass: "User",
        PrincipalSource: "Local"
      }),
      "win32"
    );

    expect(admins[0]).toMatchObject({
      name: "HOST\\Owner",
      objectClass: "User"
    });
  });

  it("derives Linux local administrators from local account files", async () => {
    const runner: CommandRunner = async (_executable, args) => {
      if (args[0] === "/etc/passwd") {
        return output("root:x:0:0:root:/root:/bin/bash\nalex:x:1000:1000::/home/alex:/bin/bash");
      }
      return output("sudo:x:27:alex\nusers:x:100:alex");
    };

    const admins = await localAdmins(runner, "linux");
    expect(admins.map((item) => item.name)).toEqual(["alex", "root"]);
  });
});

describe("startup and scheduling inventory", () => {
  it("does not return Windows startup command lines", async () => {
    const items = await startupPrograms(
      20,
      windowsRunner({
        Name: "Example",
        Location: "HKCU\\Run",
        User: "Owner",
        Command: "example.exe --token super-secret"
      }),
      "win32"
    );

    expect(items[0]).toEqual({
      name: "Example",
      source: "HKCU\\Run",
      user: "Owner"
    });
    expect(JSON.stringify(items)).not.toContain("super-secret");
  });

  it("does not return scheduled task action commands", async () => {
    const tasks = await scheduledTasks(
      20,
      windowsRunner({
        TaskName: "Backup",
        TaskPath: "\\Ops\\",
        State: "Ready",
        Author: "Ops",
        Actions: "powershell.exe -token secret-value"
      }),
      "win32"
    );

    expect(tasks[0]).toMatchObject({
      name: "Backup",
      path: "\\Ops\\",
      state: "Ready",
      source: "windows-task-scheduler"
    });
    expect(JSON.stringify(tasks)).not.toContain("secret-value");
  });
});

describe("certificate inventory", () => {
  it("returns certificate metadata without private key material", async () => {
    const certificates = await certificateInventory(
      20,
      windowsRunner({
        Store: "Cert:\\CurrentUser\\My",
        Thumbprint: "ABC123",
        Subject: "CN=example.test",
        Issuer: "CN=Test CA",
        NotBefore: "2026-01-01T00:00:00Z",
        NotAfter: "2027-01-01T00:00:00Z",
        HasPrivateKey: true,
        PrivateKey: "must-not-return"
      }),
      "win32"
    );

    expect(certificates[0].hasPrivateKey).toBe(true);
    expect(JSON.stringify(certificates)).not.toContain("must-not-return");
  });

  it("finds expired certificates", async () => {
    const expired = await certificateExpiry(
      30,
      20,
      windowsRunner({
        Store: "Cert:\\CurrentUser\\My",
        Thumbprint: "OLD",
        Subject: "CN=old.test",
        Issuer: "CN=Test CA",
        NotBefore: "2020-01-01T00:00:00Z",
        NotAfter: "2021-01-01T00:00:00Z",
        HasPrivateKey: false
      }),
      "win32"
    );

    expect(expired).toHaveLength(1);
    expect(expired[0].daysUntilExpiry).toBeLessThan(0);
  });
});

describe("environment variable privacy", () => {
  const variableName = "LOCALOPS_TEST_SECRET";
  const secretValue = "this-value-must-never-be-returned";

  afterEach(() => {
    delete process.env[variableName];
  });

  it("returns names and presence only, never values", () => {
    process.env[variableName] = secretValue;
    const summary = environmentVariablesSummary(300);
    const item = summary.variables.find((variable) => variable.name === variableName);

    expect(summary.valuesExposed).toBe(false);
    expect(item).toMatchObject({
      name: variableName,
      present: true,
      sensitiveName: true
    });
    expect(JSON.stringify(summary)).not.toContain(secretValue);
  });
});
