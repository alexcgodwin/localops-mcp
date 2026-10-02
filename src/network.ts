import { promises as dns } from "node:dns";
import { readFile } from "node:fs/promises";
import net from "node:net";
import { CommandRunner, defaultCommandRunner } from "./command.js";

type Platform = NodeJS.Platform;

export type NetworkConnection = {
  protocol: "tcp" | "udp";
  localAddress: string;
  localPort: number;
  remoteAddress: string | null;
  remotePort: number | null;
  state: string | null;
  pid: number | null;
  processName: string | null;
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

function safeHost(host: string): string {
  const value = host.trim();
  if (value.length < 1 || value.length > 253) {
    throw new Error("host must be between 1 and 253 characters.");
  }
  if (net.isIP(value)) return value;
  if (!/^(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)*[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$/.test(value)) {
    throw new Error("host must be a valid hostname or IP address.");
  }
  return value;
}

function endpoint(value: string): { address: string; port: number | null } {
  const text = value.trim();
  if (!text) return { address: "", port: null };

  if (text.startsWith("[") && text.includes("]:")) {
    const closing = text.lastIndexOf("]:");
    const address = text.slice(1, closing);
    const rawPort = text.slice(closing + 2);
    return { address, port: /^\d+$/.test(rawPort) ? Number(rawPort) : null };
  }

  const index = text.lastIndexOf(":");
  if (index < 0) return { address: text, port: null };
  const address = text.slice(0, index) || "*";
  const rawPort = text.slice(index + 1);
  return {
    address: address === "[::]" ? "::" : address,
    port: /^\d+$/.test(rawPort) ? Number(rawPort) : null
  };
}

function parseLinuxSocketLine(line: string): NetworkConnection | null {
  const parts = line.trim().split(/\s+/);
  if (parts.length < 5) return null;

  const protocol = parts[0]?.toLowerCase().startsWith("udp") ? "udp" : "tcp";
  const state = parts[1] ?? null;
  const local = endpoint(parts[4] ?? "");
  const remote = endpoint(parts[5] ?? "");
  if (local.port === null) return null;

  const processText = parts.slice(6).join(" ");
  const pidMatch = processText.match(/pid=(\d+)/);
  const nameMatch = processText.match(/users:\(\("([^"]+)"/);

  return {
    protocol,
    localAddress: local.address,
    localPort: local.port,
    remoteAddress: remote.address && remote.address !== "*" ? remote.address : null,
    remotePort: remote.port,
    state,
    pid: pidMatch ? Number(pidMatch[1]) : null,
    processName: nameMatch?.[1] ?? null
  };
}

function normalizeWindowsConnection(item: any, protocol: "tcp" | "udp"): NetworkConnection {
  return {
    protocol,
    localAddress: String(item.LocalAddress ?? ""),
    localPort: Number(item.LocalPort ?? 0),
    remoteAddress:
      protocol === "tcp" && item.RemoteAddress && !["0.0.0.0", "::"].includes(String(item.RemoteAddress))
        ? String(item.RemoteAddress)
        : null,
    remotePort:
      protocol === "tcp" && Number(item.RemotePort ?? 0) > 0
        ? Number(item.RemotePort)
        : null,
    state: protocol === "tcp" && item.State ? String(item.State) : null,
    pid: Number(item.OwningProcess ?? 0) > 0 ? Number(item.OwningProcess) : null,
    processName: item.ProcessName ? String(item.ProcessName) : null
  };
}

export async function listeningPorts(
  limit = 300,
  runner: CommandRunner = defaultCommandRunner,
  platform: Platform = process.platform
): Promise<NetworkConnection[]> {
  const safeLimit = clampLimit(limit, 300, 1000);

  if (platform === "win32") {
    const script = `
$tcp = Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue |
  Select-Object LocalAddress,LocalPort,State,OwningProcess,
    @{Name='ProcessName';Expression={(Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).ProcessName}}
$udp = Get-NetUDPEndpoint -ErrorAction SilentlyContinue |
  Select-Object LocalAddress,LocalPort,OwningProcess,
    @{Name='ProcessName';Expression={(Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).ProcessName}}
[pscustomobject]@{Tcp=$tcp;Udp=$udp} | ConvertTo-Json -Depth 5 -Compress
`.trim();
    const result = await runner(
      "powershell.exe",
      ["-NoProfile", "-NonInteractive", "-Command", script]
    );
    const parsed = JSON.parse(result.stdout || "{}");
    return [
      ...asArray(parsed.Tcp).map((item) => normalizeWindowsConnection(item, "tcp")),
      ...asArray(parsed.Udp).map((item) => normalizeWindowsConnection(item, "udp"))
    ].slice(0, safeLimit);
  }

  const result = await runner("ss", ["-H", "-lntup"], true);
  if (result.exitCode !== 0) return [];
  return result.stdout
    .split(/\r?\n/)
    .filter(Boolean)
    .map(parseLinuxSocketLine)
    .filter((item): item is NetworkConnection => Boolean(item))
    .slice(0, safeLimit);
}

export async function openPorts(
  limit = 300,
  runner: CommandRunner = defaultCommandRunner,
  platform: Platform = process.platform
) {
  const listeners = await listeningPorts(limit, runner, platform);
  const seen = new Set<string>();
  return listeners.filter((item) => {
    const key = `${item.protocol}:${item.localAddress}:${item.localPort}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

export async function networkConnections(
  limit = 500,
  runner: CommandRunner = defaultCommandRunner,
  platform: Platform = process.platform
): Promise<NetworkConnection[]> {
  const safeLimit = clampLimit(limit, 500, 1500);

  if (platform === "win32") {
    const script = `
$tcp = Get-NetTCPConnection -ErrorAction SilentlyContinue |
  Select-Object LocalAddress,LocalPort,RemoteAddress,RemotePort,State,OwningProcess,
    @{Name='ProcessName';Expression={(Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).ProcessName}}
$udp = Get-NetUDPEndpoint -ErrorAction SilentlyContinue |
  Select-Object LocalAddress,LocalPort,OwningProcess,
    @{Name='ProcessName';Expression={(Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).ProcessName}}
[pscustomobject]@{Tcp=$tcp;Udp=$udp} | ConvertTo-Json -Depth 5 -Compress
`.trim();
    const result = await runner(
      "powershell.exe",
      ["-NoProfile", "-NonInteractive", "-Command", script]
    );
    const parsed = JSON.parse(result.stdout || "{}");
    return [
      ...asArray(parsed.Tcp).map((item) => normalizeWindowsConnection(item, "tcp")),
      ...asArray(parsed.Udp).map((item) => normalizeWindowsConnection(item, "udp"))
    ].slice(0, safeLimit);
  }

  const result = await runner("ss", ["-H", "-tunap"], true);
  if (result.exitCode !== 0) return [];
  return result.stdout
    .split(/\r?\n/)
    .filter(Boolean)
    .map(parseLinuxSocketLine)
    .filter((item): item is NetworkConnection => Boolean(item))
    .slice(0, safeLimit);
}

export async function networkRoutes(
  limit = 300,
  runner: CommandRunner = defaultCommandRunner,
  platform: Platform = process.platform
) {
  const safeLimit = clampLimit(limit, 300, 1000);
  if (platform === "win32") {
    const script = `
Get-NetRoute -ErrorAction SilentlyContinue |
  Sort-Object RouteMetric,DestinationPrefix |
  Select-Object -First ${safeLimit} DestinationPrefix,NextHop,InterfaceAlias,RouteMetric,AddressFamily,State |
  ConvertTo-Json -Compress
`.trim();
    const result = await runner(
      "powershell.exe",
      ["-NoProfile", "-NonInteractive", "-Command", script]
    );
    return parseJsonOutput(result.stdout).map((item) => ({
      destination: String(item.DestinationPrefix ?? ""),
      gateway: item.NextHop ? String(item.NextHop) : null,
      interface: item.InterfaceAlias ? String(item.InterfaceAlias) : null,
      metric: Number(item.RouteMetric ?? 0),
      family: item.AddressFamily ? String(item.AddressFamily) : null,
      state: item.State ? String(item.State) : null
    }));
  }

  const result = await runner("ip", ["-j", "route", "show"], true);
  if (result.exitCode === 0 && result.stdout.trim().startsWith("[")) {
    return asArray(JSON.parse(result.stdout)).slice(0, safeLimit).map((item) => ({
      destination: String(item.dst ?? "default"),
      gateway: item.gateway ? String(item.gateway) : null,
      interface: item.dev ? String(item.dev) : null,
      metric: Number(item.metric ?? 0),
      family: null,
      state: null
    }));
  }

  const fallback = await runner("ip", ["route", "show"], true);
  if (fallback.exitCode !== 0) return [];
  return fallback.stdout.split(/\r?\n/).filter(Boolean).slice(0, safeLimit).map((line) => ({
    destination: line,
    gateway: null,
    interface: null,
    metric: 0,
    family: null,
    state: null
  }));
}

export async function dnsConfiguration(
  runner: CommandRunner = defaultCommandRunner,
  platform: Platform = process.platform
) {
  if (platform === "win32") {
    const script = `
Get-DnsClientServerAddress -ErrorAction SilentlyContinue |
  Where-Object { $_.ServerAddresses.Count -gt 0 } |
  Select-Object InterfaceAlias,AddressFamily,ServerAddresses |
  ConvertTo-Json -Compress
`.trim();
    const result = await runner(
      "powershell.exe",
      ["-NoProfile", "-NonInteractive", "-Command", script]
    );
    return {
      source: "windows-dns-client",
      interfaces: parseJsonOutput(result.stdout).map((item) => ({
        interface: String(item.InterfaceAlias ?? ""),
        family: item.AddressFamily ? String(item.AddressFamily) : null,
        servers: asArray(item.ServerAddresses).map(String)
      })),
      searchDomains: [] as string[]
    };
  }

  let content = "";
  try {
    content = await readFile("/etc/resolv.conf", "utf8");
  } catch {
    return { source: "/etc/resolv.conf", interfaces: [], searchDomains: [] as string[] };
  }
  const servers: string[] = [];
  const searchDomains: string[] = [];
  for (const line of content.split(/\r?\n/)) {
    const clean = line.replace(/#.*/, "").trim();
    if (!clean) continue;
    const [key, ...values] = clean.split(/\s+/);
    if (key === "nameserver" && values[0]) servers.push(values[0]);
    if ((key === "search" || key === "domain") && values.length) {
      searchDomains.push(...values);
    }
  }
  return {
    source: "/etc/resolv.conf",
    interfaces: [{ interface: "system", family: null, servers }],
    searchDomains: [...new Set(searchDomains)]
  };
}

export async function dnsResolution(host: string) {
  const target = safeHost(host);
  const answers = await dns.lookup(target, { all: true, verbatim: true });
  return {
    host: target,
    answers: answers.map((answer) => ({
      address: answer.address,
      family: answer.family
    }))
  };
}

export async function firewallStatus(
  runner: CommandRunner = defaultCommandRunner,
  platform: Platform = process.platform
) {
  if (platform === "win32") {
    const script = `
Get-NetFirewallProfile -ErrorAction SilentlyContinue |
  Select-Object Name,Enabled,DefaultInboundAction,DefaultOutboundAction |
  ConvertTo-Json -Compress
`.trim();
    const result = await runner(
      "powershell.exe",
      ["-NoProfile", "-NonInteractive", "-Command", script]
    );
    return {
      provider: "windows-defender-firewall",
      profiles: parseJsonOutput(result.stdout).map((item) => ({
        name: String(item.Name ?? ""),
        enabled: Boolean(item.Enabled),
        defaultInboundAction: String(item.DefaultInboundAction ?? "NotConfigured"),
        defaultOutboundAction: String(item.DefaultOutboundAction ?? "NotConfigured")
      })),
      status: "available"
    };
  }

  const ufw = await runner("ufw", ["status"], true);
  if (ufw.exitCode === 0 && ufw.stdout.trim()) {
    return {
      provider: "ufw",
      profiles: [],
      status: ufw.stdout.split(/\r?\n/)[0]?.trim() || "available"
    };
  }

  const firewalld = await runner("firewall-cmd", ["--state"], true);
  if (firewalld.exitCode === 0 && firewalld.stdout.trim()) {
    return {
      provider: "firewalld",
      profiles: [],
      status: firewalld.stdout.trim()
    };
  }

  const nft = await runner("nft", ["list", "ruleset"], true);
  if (nft.exitCode === 0) {
    return {
      provider: "nftables",
      profiles: [],
      status: nft.stdout.trim() ? "ruleset-readable" : "empty-ruleset"
    };
  }

  return {
    provider: "unknown",
    profiles: [],
    status: "unavailable-or-insufficient-permission"
  };
}

export async function firewallRules(
  limit = 200,
  runner: CommandRunner = defaultCommandRunner,
  platform: Platform = process.platform
) {
  const safeLimit = clampLimit(limit, 200, 500);
  if (platform === "win32") {
    const script = `
Get-NetFirewallRule -ErrorAction SilentlyContinue |
  Sort-Object DisplayName |
  Select-Object -First ${safeLimit} Name,DisplayName,Enabled,Direction,Action,Profile |
  ConvertTo-Json -Compress
`.trim();
    const result = await runner(
      "powershell.exe",
      ["-NoProfile", "-NonInteractive", "-Command", script]
    );
    return {
      provider: "windows-defender-firewall",
      rules: parseJsonOutput(result.stdout).map((item) => ({
        name: String(item.Name ?? ""),
        displayName: String(item.DisplayName ?? ""),
        enabled: Boolean(item.Enabled),
        direction: String(item.Direction ?? ""),
        action: String(item.Action ?? ""),
        profile: String(item.Profile ?? "")
      }))
    };
  }

  const ufw = await runner("ufw", ["status", "numbered"], true);
  if (ufw.exitCode === 0 && ufw.stdout.trim()) {
    return {
      provider: "ufw",
      rules: ufw.stdout.split(/\r?\n/).filter(Boolean).slice(0, safeLimit)
    };
  }

  const firewalld = await runner("firewall-cmd", ["--list-all"], true);
  if (firewalld.exitCode === 0 && firewalld.stdout.trim()) {
    return {
      provider: "firewalld",
      rules: firewalld.stdout.split(/\r?\n/).filter(Boolean).slice(0, safeLimit)
    };
  }

  const nft = await runner("nft", ["list", "ruleset"], true);
  return {
    provider: nft.exitCode === 0 ? "nftables" : "unknown",
    rules:
      nft.exitCode === 0
        ? nft.stdout.split(/\r?\n/).filter(Boolean).slice(0, safeLimit)
        : []
  };
}

export async function networkAdapters(
  limit = 200,
  runner: CommandRunner = defaultCommandRunner,
  platform: Platform = process.platform
) {
  const safeLimit = clampLimit(limit, 200, 500);
  if (platform === "win32") {
    const script = `
Get-NetAdapter -ErrorAction SilentlyContinue |
  Sort-Object Name |
  Select-Object -First ${safeLimit} Name,InterfaceDescription,Status,MacAddress,LinkSpeed,MediaType |
  ConvertTo-Json -Compress
`.trim();
    const result = await runner(
      "powershell.exe",
      ["-NoProfile", "-NonInteractive", "-Command", script]
    );
    return parseJsonOutput(result.stdout).map((item) => ({
      name: String(item.Name ?? ""),
      description: String(item.InterfaceDescription ?? ""),
      status: String(item.Status ?? ""),
      macAddress: item.MacAddress ? String(item.MacAddress) : null,
      linkSpeed: item.LinkSpeed ? String(item.LinkSpeed) : null,
      mediaType: item.MediaType ? String(item.MediaType) : null
    }));
  }

  const result = await runner("ip", ["-j", "link", "show"], true);
  if (result.exitCode !== 0 || !result.stdout.trim().startsWith("[")) return [];
  return asArray(JSON.parse(result.stdout)).slice(0, safeLimit).map((item) => ({
    name: String(item.ifname ?? ""),
    description: "",
    status: String(item.operstate ?? "UNKNOWN"),
    macAddress: item.address ? String(item.address) : null,
    linkSpeed: null,
    mediaType: item.link_type ? String(item.link_type) : null
  }));
}

export async function arpNeighbors(
  limit = 300,
  runner: CommandRunner = defaultCommandRunner,
  platform: Platform = process.platform
) {
  const safeLimit = clampLimit(limit, 300, 1000);
  if (platform === "win32") {
    const script = `
Get-NetNeighbor -ErrorAction SilentlyContinue |
  Sort-Object InterfaceAlias,IPAddress |
  Select-Object -First ${safeLimit} IPAddress,LinkLayerAddress,State,InterfaceAlias,AddressFamily |
  ConvertTo-Json -Compress
`.trim();
    const result = await runner(
      "powershell.exe",
      ["-NoProfile", "-NonInteractive", "-Command", script]
    );
    return parseJsonOutput(result.stdout).map((item) => ({
      ipAddress: String(item.IPAddress ?? ""),
      macAddress: item.LinkLayerAddress ? String(item.LinkLayerAddress) : null,
      state: item.State ? String(item.State) : null,
      interface: item.InterfaceAlias ? String(item.InterfaceAlias) : null,
      family: item.AddressFamily ? String(item.AddressFamily) : null
    }));
  }

  const result = await runner("ip", ["neigh", "show"], true);
  if (result.exitCode !== 0) return [];
  return result.stdout.split(/\r?\n/).filter(Boolean).slice(0, safeLimit).map((line) => {
    const parts = line.trim().split(/\s+/);
    const devIndex = parts.indexOf("dev");
    const lladdrIndex = parts.indexOf("lladdr");
    return {
      ipAddress: parts[0] ?? "",
      macAddress: lladdrIndex >= 0 ? parts[lladdrIndex + 1] ?? null : null,
      state: parts.at(-1) ?? null,
      interface: devIndex >= 0 ? parts[devIndex + 1] ?? null : null,
      family: null
    };
  });
}

export async function processNetworkMap(
  limit = 500,
  runner: CommandRunner = defaultCommandRunner,
  platform: Platform = process.platform
) {
  const connections = await networkConnections(limit, runner, platform);
  const grouped = new Map<string, {
    pid: number | null;
    processName: string | null;
    connectionCount: number;
    localPorts: Set<number>;
    remoteAddresses: Set<string>;
  }>();

  for (const connection of connections) {
    const key = connection.pid !== null
      ? `pid:${connection.pid}`
      : `unknown:${connection.processName ?? "unknown"}`;
    const existing = grouped.get(key) ?? {
      pid: connection.pid,
      processName: connection.processName,
      connectionCount: 0,
      localPorts: new Set<number>(),
      remoteAddresses: new Set<string>()
    };
    existing.connectionCount += 1;
    existing.localPorts.add(connection.localPort);
    if (connection.remoteAddress) existing.remoteAddresses.add(connection.remoteAddress);
    grouped.set(key, existing);
  }

  return [...grouped.values()]
    .map((item) => ({
      pid: item.pid,
      processName: item.processName,
      connectionCount: item.connectionCount,
      localPorts: [...item.localPorts].sort((a, b) => a - b),
      remoteAddresses: [...item.remoteAddresses].sort().slice(0, 100)
    }))
    .sort((a, b) => b.connectionCount - a.connectionCount);
}

export async function unexpectedListeningPorts(
  allowedPorts: Array<{ protocol: "tcp" | "udp"; port: number }>,
  limit = 300,
  runner: CommandRunner = defaultCommandRunner,
  platform: Platform = process.platform
) {
  const allowed = new Set(
    allowedPorts.slice(0, 500).map((item) => `${item.protocol}:${item.port}`)
  );
  const listeners = await listeningPorts(limit, runner, platform);
  const unexpected = listeners.filter(
    (item) => !allowed.has(`${item.protocol}:${item.localPort}`)
  );
  return {
    baselineCount: Math.min(allowedPorts.length, 500),
    listenerCount: listeners.length,
    unexpectedCount: unexpected.length,
    unexpected,
    interpretation:
      "Unexpected means absent from the caller-supplied port baseline. It does not mean malicious."
  };
}

export async function unusualOutboundConnections(
  allowedRemotePorts: number[],
  allowedRemoteAddresses: string[],
  limit = 500,
  runner: CommandRunner = defaultCommandRunner,
  platform: Platform = process.platform
) {
  if (allowedRemotePorts.length === 0 && allowedRemoteAddresses.length === 0) {
    throw new Error("Provide at least one allowed remote port or allowed remote address.");
  }

  const ports = new Set(allowedRemotePorts.slice(0, 500));
  const addresses = new Set(allowedRemoteAddresses.slice(0, 500));
  const connections = await networkConnections(limit, runner, platform);
  const outbound = connections.filter(
    (item) =>
      item.protocol === "tcp" &&
      item.remoteAddress &&
      item.remotePort &&
      !["Listen", "Bound"].includes(item.state ?? "")
  );

  const outsideBaseline = outbound.filter((item) => {
    const portAllowed = ports.size === 0 || (item.remotePort !== null && ports.has(item.remotePort));
    const addressAllowed =
      addresses.size === 0 || (item.remoteAddress !== null && addresses.has(item.remoteAddress));
    return !(portAllowed && addressAllowed);
  });

  return {
    outboundCount: outbound.length,
    outsideBaselineCount: outsideBaseline.length,
    outsideBaseline,
    interpretation:
      "Outside-baseline means the connection does not match the caller-supplied remote port/address expectations. It is not a malware or compromise determination."
  };
}
