import { X509Certificate } from "node:crypto";
import { access, readdir, readFile, stat } from "node:fs/promises";
import os from "node:os";
import { join } from "node:path";
import { CommandRunner, defaultCommandRunner } from "./command.js";

type Platform = NodeJS.Platform;

export type SoftwareEntry = {
  name: string;
  version: string | null;
  publisher: string | null;
  installDate: string | null;
  source: string;
};

function asArray(value: unknown): any[] {
  if (value === null || value === undefined || value === "") return [];
  return Array.isArray(value) ? value : [value];
}

function parseJsonOutput(value: string): any[] {
  if (!value.trim()) return [];
  return asArray(JSON.parse(value));
}

function clampLimit(value: number | undefined, fallback: number, max: number): number {
  const number = Number.isInteger(value) ? Number(value) : fallback;
  return Math.max(1, Math.min(number, max));
}

function normalizeDate(value: unknown): string | null {
  if (!value) return null;
  const text = String(value);
  if (/^\d{8}$/.test(text)) {
    return `${text.slice(0, 4)}-${text.slice(4, 6)}-${text.slice(6, 8)}`;
  }
  const date = new Date(text);
  return Number.isNaN(date.getTime()) ? text.slice(0, 100) : date.toISOString();
}

async function linuxPackageInventory(
  limit: number,
  runner: CommandRunner
): Promise<{ packageManager: string; packages: SoftwareEntry[] }> {
  const dpkg = await runner(
    "dpkg-query",
    ["-W", "-f=${binary:Package}\t${Version}\t${Maintainer}\n"],
    true
  );
  if (dpkg.exitCode === 0) {
    const packages = dpkg.stdout.split(/\r?\n/).filter(Boolean).slice(0, limit).map((line) => {
      const [name = "", version = "", publisher = ""] = line.split("\t");
      return {
        name,
        version: version || null,
        publisher: publisher || null,
        installDate: null,
        source: "dpkg"
      };
    });
    return { packageManager: "dpkg", packages };
  }

  const rpm = await runner(
    "rpm",
    ["-qa", "--qf", "%{NAME}\t%{VERSION}-%{RELEASE}\t%{VENDOR}\n"],
    true
  );
  if (rpm.exitCode === 0) {
    const packages = rpm.stdout.split(/\r?\n/).filter(Boolean).slice(0, limit).map((line) => {
      const [name = "", version = "", publisher = ""] = line.split("\t");
      return {
        name,
        version: version || null,
        publisher: publisher || null,
        installDate: null,
        source: "rpm"
      };
    });
    return { packageManager: "rpm", packages };
  }

  const apk = await runner("apk", ["info", "-v"], true);
  if (apk.exitCode === 0) {
    const packages = apk.stdout.split(/\r?\n/).filter(Boolean).slice(0, limit).map((line) => {
      const match = line.match(/^(.*?)-(\d[^]*)$/);
      return {
        name: match?.[1] ?? line,
        version: match?.[2] ?? null,
        publisher: null,
        installDate: null,
        source: "apk"
      };
    });
    return { packageManager: "apk", packages };
  }

  return { packageManager: "unknown", packages: [] };
}

export async function installedSoftware(
  limit = 200,
  runner: CommandRunner = defaultCommandRunner,
  platform: Platform = process.platform
) {
  const safeLimit = clampLimit(limit, 200, 500);
  if (platform !== "win32") {
    return linuxPackageInventory(safeLimit, runner);
  }

  const script = `
$paths = @(
  'HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*',
  'HKLM:\\Software\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*',
  'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*'
)
Get-ItemProperty $paths -ErrorAction SilentlyContinue |
  Where-Object { $_.DisplayName } |
  Sort-Object DisplayName,DisplayVersion -Unique |
  Select-Object -First ${safeLimit} DisplayName,DisplayVersion,Publisher,InstallDate |
  ConvertTo-Json -Compress
`.trim();
  const result = await runner(
    "powershell.exe",
    ["-NoProfile", "-NonInteractive", "-Command", script]
  );
  const packages = parseJsonOutput(result.stdout).map((item) => ({
    name: String(item.DisplayName ?? ""),
    version: item.DisplayVersion ? String(item.DisplayVersion) : null,
    publisher: item.Publisher ? String(item.Publisher) : null,
    installDate: normalizeDate(item.InstallDate),
    source: "windows-uninstall-registry"
  }));
  return { packageManager: "windows-registry", packages };
}

export async function softwareVersions(
  names: string[],
  runner: CommandRunner = defaultCommandRunner,
  platform: Platform = process.platform
) {
  const wanted = names.map((name) => name.trim().toLowerCase()).filter(Boolean).slice(0, 50);
  const inventory = await installedSoftware(500, runner, platform);
  const matches = inventory.packages.filter((item) =>
    wanted.some((name) => item.name.toLowerCase() === name || item.name.toLowerCase().includes(name))
  );
  return {
    requested: names.slice(0, 50),
    matches,
    packageManager: inventory.packageManager
  };
}

export async function softwareChanges(
  previousInventory: Array<{ name: string; version?: string | null }>,
  runner: CommandRunner = defaultCommandRunner,
  platform: Platform = process.platform
) {
  const current = await installedSoftware(500, runner, platform);
  const previousMap = new Map(
    previousInventory.slice(0, 500).map((item) => [
      item.name.trim().toLowerCase(),
      item.version ?? null
    ])
  );
  const currentMap = new Map(
    current.packages.map((item) => [item.name.trim().toLowerCase(), item])
  );

  const added = current.packages.filter((item) => !previousMap.has(item.name.toLowerCase()));
  const removed = previousInventory.slice(0, 500)
    .filter((item) => !currentMap.has(item.name.trim().toLowerCase()))
    .map((item) => ({ name: item.name, version: item.version ?? null }));

  const versionChanged = current.packages.flatMap((item) => {
    const before = previousMap.get(item.name.toLowerCase());
    if (before === undefined || before === item.version) return [];
    return [{
      name: item.name,
      previousVersion: before,
      currentVersion: item.version
    }];
  });

  return {
    baselineCount: Math.min(previousInventory.length, 500),
    currentCount: current.packages.length,
    added,
    removed,
    versionChanged,
    limitation:
      "Comparison uses a bounded inventory of up to 500 packages and depends on the caller-supplied baseline."
  };
}

export async function localUsers(
  limit = 200,
  runner: CommandRunner = defaultCommandRunner,
  platform: Platform = process.platform
) {
  const safeLimit = clampLimit(limit, 200, 300);
  if (platform === "win32") {
    const script = `
Get-LocalUser |
  Sort-Object Name |
  Select-Object -First ${safeLimit} Name,Enabled,LastLogon,PasswordRequired,UserMayChangePassword |
  ConvertTo-Json -Compress
`.trim();
    const result = await runner(
      "powershell.exe",
      ["-NoProfile", "-NonInteractive", "-Command", script]
    );
    return parseJsonOutput(result.stdout).map((item) => ({
      name: String(item.Name ?? ""),
      enabled: Boolean(item.Enabled),
      lastLogon: normalizeDate(item.LastLogon),
      passwordRequired: Boolean(item.PasswordRequired),
      userMayChangePassword: Boolean(item.UserMayChangePassword)
    }));
  }

  const result = await runner("cat", ["/etc/passwd"]);
  return result.stdout.split(/\r?\n/).filter(Boolean).slice(0, safeLimit).map((line) => {
    const parts = line.split(":");
    const uid = Number(parts[2] ?? -1);
    return {
      name: parts[0] ?? "",
      uid,
      gid: Number(parts[3] ?? -1),
      home: parts[5] ?? "",
      shell: parts[6] ?? "",
      isSystemAccount: uid >= 0 && uid < 1000 && uid !== 0
    };
  });
}

export async function localGroups(
  limit = 200,
  runner: CommandRunner = defaultCommandRunner,
  platform: Platform = process.platform
) {
  const safeLimit = clampLimit(limit, 200, 300);
  if (platform === "win32") {
    const script = `
Get-LocalGroup |
  Sort-Object Name |
  Select-Object -First ${safeLimit} Name,Description |
  ConvertTo-Json -Compress
`.trim();
    const result = await runner(
      "powershell.exe",
      ["-NoProfile", "-NonInteractive", "-Command", script]
    );
    return parseJsonOutput(result.stdout).map((item) => ({
      name: String(item.Name ?? ""),
      description: item.Description ? String(item.Description) : null
    }));
  }

  const result = await runner("cat", ["/etc/group"]);
  return result.stdout.split(/\r?\n/).filter(Boolean).slice(0, safeLimit).map((line) => {
    const parts = line.split(":");
    return {
      name: parts[0] ?? "",
      gid: Number(parts[2] ?? -1),
      members: (parts[3] ?? "").split(",").filter(Boolean).slice(0, 100)
    };
  });
}

export async function localAdmins(
  runner: CommandRunner = defaultCommandRunner,
  platform: Platform = process.platform
) {
  if (platform === "win32") {
    const script = `
$group = Get-LocalGroup -SID 'S-1-5-32-544'
Get-LocalGroupMember -Group $group |
  Select-Object Name,ObjectClass,PrincipalSource |
  ConvertTo-Json -Compress
`.trim();
    const result = await runner(
      "powershell.exe",
      ["-NoProfile", "-NonInteractive", "-Command", script],
      true
    );
    if (result.exitCode !== 0) return [];
    return parseJsonOutput(result.stdout).map((item) => ({
      name: String(item.Name ?? ""),
      objectClass: item.ObjectClass ? String(item.ObjectClass) : null,
      principalSource: item.PrincipalSource ? String(item.PrincipalSource) : null
    }));
  }

  const [passwd, groups] = await Promise.all([
    runner("cat", ["/etc/passwd"]),
    runner("cat", ["/etc/group"])
  ]);
  const adminNames = new Set<string>();
  for (const line of passwd.stdout.split(/\r?\n/).filter(Boolean)) {
    const parts = line.split(":");
    if (Number(parts[2] ?? -1) === 0) adminNames.add(parts[0] ?? "");
  }
  for (const line of groups.stdout.split(/\r?\n/).filter(Boolean)) {
    const parts = line.split(":");
    if (!["sudo", "wheel", "admin"].includes(parts[0] ?? "")) continue;
    for (const member of (parts[3] ?? "").split(",").filter(Boolean)) {
      adminNames.add(member);
    }
  }
  return [...adminNames].filter(Boolean).sort().map((name) => ({ name }));
}

export async function startupPrograms(
  limit = 200,
  runner: CommandRunner = defaultCommandRunner,
  platform: Platform = process.platform
) {
  const safeLimit = clampLimit(limit, 200, 300);
  if (platform === "win32") {
    const script = `
Get-CimInstance Win32_StartupCommand |
  Sort-Object Name |
  Select-Object -First ${safeLimit} Name,Location,User |
  ConvertTo-Json -Compress
`.trim();
    const result = await runner(
      "powershell.exe",
      ["-NoProfile", "-NonInteractive", "-Command", script]
    );
    return parseJsonOutput(result.stdout).map((item) => ({
      name: String(item.Name ?? ""),
      source: item.Location ? String(item.Location) : "Windows startup",
      user: item.User ? String(item.User) : null
    }));
  }

  const result = await runner(
    "systemctl",
    ["list-unit-files", "--type=service", "--state=enabled", "--no-legend", "--no-pager"],
    true
  );
  const items = result.exitCode === 0
    ? result.stdout.split(/\r?\n/).filter(Boolean).slice(0, safeLimit).map((line) => {
        const parts = line.trim().split(/\s+/);
        return {
          name: parts[0] ?? "",
          source: "systemd",
          state: parts[1] ?? "enabled"
        };
      })
    : [];

  const autostart = join(os.homedir(), ".config", "autostart");
  try {
    const files = (await readdir(autostart)).filter((name) => name.endsWith(".desktop"));
    for (const name of files.slice(0, Math.max(0, safeLimit - items.length))) {
      items.push({ name, source: "xdg-autostart", state: "present" });
    }
  } catch {
  }
  return items;
}

export async function scheduledTasks(
  limit = 200,
  runner: CommandRunner = defaultCommandRunner,
  platform: Platform = process.platform
) {
  const safeLimit = clampLimit(limit, 200, 300);
  if (platform === "win32") {
    const script = `
Get-ScheduledTask |
  Sort-Object TaskPath,TaskName |
  Select-Object -First ${safeLimit} TaskName,TaskPath,State,Author |
  ConvertTo-Json -Compress
`.trim();
    const result = await runner(
      "powershell.exe",
      ["-NoProfile", "-NonInteractive", "-Command", script]
    );
    return parseJsonOutput(result.stdout).map((item) => ({
      name: String(item.TaskName ?? ""),
      path: String(item.TaskPath ?? ""),
      state: String(item.State ?? "Unknown"),
      author: item.Author ? String(item.Author) : null,
      source: "windows-task-scheduler"
    }));
  }

  const result = await runner(
    "systemctl",
    ["list-unit-files", "--type=timer", "--no-legend", "--no-pager"],
    true
  );
  const tasks = result.exitCode === 0
    ? result.stdout.split(/\r?\n/).filter(Boolean).slice(0, safeLimit).map((line) => {
        const parts = line.trim().split(/\s+/);
        return {
          name: parts[0] ?? "",
          path: "",
          state: parts[1] ?? "unknown",
          author: null,
          source: "systemd-timer"
        };
      })
    : [];

  const cronDirs = ["/etc/cron.d", "/etc/cron.daily", "/etc/cron.hourly", "/etc/cron.weekly", "/etc/cron.monthly"];
  for (const directory of cronDirs) {
    if (tasks.length >= safeLimit) break;
    try {
      const files = await readdir(directory);
      for (const name of files.filter((entry) => !entry.startsWith(".")).slice(0, safeLimit - tasks.length)) {
        tasks.push({
          name,
          path: directory,
          state: "present",
          author: null,
          source: "cron-directory"
        });
      }
    } catch {
    }
  }
  return tasks;
}

type CertificateEntry = {
  store: string;
  thumbprint: string;
  subject: string;
  issuer: string;
  notBefore: string | null;
  notAfter: string | null;
  hasPrivateKey: boolean | null;
};

async function linuxCertificates(limit: number): Promise<CertificateEntry[]> {
  const directories = ["/etc/ssl/certs", "/usr/local/share/ca-certificates"];
  const output: CertificateEntry[] = [];
  for (const directory of directories) {
    if (output.length >= limit) break;
    let names: string[];
    try {
      names = await readdir(directory);
    } catch {
      continue;
    }
    for (const name of names) {
      if (output.length >= limit) break;
      if (!/\.(pem|crt)$/i.test(name) && !/^[a-f0-9]{8}\.[0-9]+$/i.test(name)) continue;
      try {
        const certificate = new X509Certificate(await readFile(join(directory, name)));
        output.push({
          store: directory,
          thumbprint: certificate.fingerprint256.replace(/:/g, ""),
          subject: certificate.subject,
          issuer: certificate.issuer,
          notBefore: normalizeDate(certificate.validFrom),
          notAfter: normalizeDate(certificate.validTo),
          hasPrivateKey: null
        });
      } catch {
      }
    }
  }
  return output;
}

export async function certificateInventory(
  limit = 200,
  runner: CommandRunner = defaultCommandRunner,
  platform: Platform = process.platform
): Promise<CertificateEntry[]> {
  const safeLimit = clampLimit(limit, 200, 300);
  if (platform !== "win32") return linuxCertificates(safeLimit);

  const script = `
$stores = @('Cert:\\CurrentUser\\My','Cert:\\LocalMachine\\My')
$result = foreach ($store in $stores) {
  Get-ChildItem $store -ErrorAction SilentlyContinue |
    Select-Object @{Name='Store';Expression={$store}},
      Thumbprint,Subject,Issuer,
      @{Name='NotBefore';Expression={$_.NotBefore.ToUniversalTime().ToString('o')}},
      @{Name='NotAfter';Expression={$_.NotAfter.ToUniversalTime().ToString('o')}},
      HasPrivateKey
}
$result | Select-Object -First ${safeLimit} | ConvertTo-Json -Compress
`.trim();
  const result = await runner(
    "powershell.exe",
    ["-NoProfile", "-NonInteractive", "-Command", script]
  );
  return parseJsonOutput(result.stdout).map((item) => ({
    store: String(item.Store ?? ""),
    thumbprint: String(item.Thumbprint ?? ""),
    subject: String(item.Subject ?? ""),
    issuer: String(item.Issuer ?? ""),
    notBefore: normalizeDate(item.NotBefore),
    notAfter: normalizeDate(item.NotAfter),
    hasPrivateKey: typeof item.HasPrivateKey === "boolean" ? item.HasPrivateKey : null
  }));
}

export async function certificateExpiry(
  withinDays = 30,
  limit = 200,
  runner: CommandRunner = defaultCommandRunner,
  platform: Platform = process.platform
) {
  const safeDays = Math.max(0, Math.min(Math.trunc(withinDays), 3650));
  const certificates = await certificateInventory(limit, runner, platform);
  const now = Date.now();
  return certificates.flatMap((certificate) => {
    if (!certificate.notAfter) return [];
    const expires = new Date(certificate.notAfter).getTime();
    if (Number.isNaN(expires)) return [];
    const daysUntilExpiry = Math.ceil((expires - now) / 86_400_000);
    if (daysUntilExpiry > safeDays) return [];
    return [{ ...certificate, daysUntilExpiry }];
  }).sort((a, b) => a.daysUntilExpiry - b.daysUntilExpiry);
}

export async function sshKeyInventory(limit = 100) {
  const safeLimit = clampLimit(limit, 100, 200);
  const directory = join(os.homedir(), ".ssh");
  try {
    await access(directory);
  } catch {
    return { directory, keys: [] };
  }

  const entries = await readdir(directory, { withFileTypes: true });
  const keys = [];
  for (const entry of entries.slice(0, safeLimit)) {
    if (!entry.isFile()) continue;
    const info = await stat(join(directory, entry.name));
    let kind = "other";
    if (entry.name.endsWith(".pub")) kind = "public-key";
    else if (/^id_(rsa|dsa|ecdsa|ed25519)(_sk)?$/i.test(entry.name)) kind = "private-key";
    else if (entry.name === "authorized_keys") kind = "authorized-keys";
    else if (entry.name.startsWith("known_hosts")) kind = "known-hosts";
    else if (entry.name === "config") kind = "ssh-config";
    keys.push({
      name: entry.name,
      kind,
      sizeBytes: info.size,
      modifiedAt: info.mtime.toISOString(),
      permissions: process.platform === "win32"
        ? null
        : (info.mode & 0o777).toString(8).padStart(3, "0")
    });
  }
  return { directory, keys };
}

export function environmentVariablesSummary(limit = 200) {
  const safeLimit = clampLimit(limit, 200, 300);
  const sensitivePattern = /(secret|token|password|passwd|pwd|credential|private|key|auth)/i;
  const variables = Object.keys(process.env)
    .sort((a, b) => a.localeCompare(b))
    .slice(0, safeLimit)
    .map((name) => ({
      name,
      present: true,
      sensitiveName: sensitivePattern.test(name)
    }));
  return {
    variableCount: Object.keys(process.env).length,
    returnedCount: variables.length,
    valuesExposed: false,
    variables
  };
}
