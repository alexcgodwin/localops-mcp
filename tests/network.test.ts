import { describe, expect, it } from "vitest";
import type { CommandRunner } from "../src/command.js";
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
} from "../src/network.js";

function output(stdout: string, exitCode = 0) {
  return { stdout, stderr: "", exitCode };
}

function jsonRunner(payload: unknown): CommandRunner {
  return async () => output(JSON.stringify(payload));
}

describe("socket inventory", () => {
  it("normalizes Windows TCP listeners and UDP endpoints", async () => {
    const runner = jsonRunner({
      Tcp: [{
        LocalAddress: "0.0.0.0",
        LocalPort: 443,
        State: "Listen",
        OwningProcess: 100,
        ProcessName: "web"
      }],
      Udp: [{
        LocalAddress: "0.0.0.0",
        LocalPort: 53,
        OwningProcess: 200,
        ProcessName: "dns"
      }]
    });

    const listeners = await listeningPorts(20, runner, "win32");
    expect(listeners).toHaveLength(2);
    expect(listeners[0]).toMatchObject({
      protocol: "tcp",
      localPort: 443,
      pid: 100,
      processName: "web"
    });
    expect(listeners[1]).toMatchObject({
      protocol: "udp",
      localPort: 53,
      pid: 200
    });
  });

  it("normalizes Linux ss connection output", async () => {
    const runner: CommandRunner = async () =>
      output(
        'tcp ESTAB 0 0 10.0.0.5:50000 203.0.113.10:443 users:(("node",pid=123,fd=12))'
      );

    const connections = await networkConnections(20, runner, "linux");
    expect(connections[0]).toMatchObject({
      protocol: "tcp",
      localAddress: "10.0.0.5",
      localPort: 50000,
      remoteAddress: "203.0.113.10",
      remotePort: 443,
      state: "ESTAB",
      pid: 123,
      processName: "node"
    });
  });

  it("deduplicates open local endpoints", async () => {
    const runner = jsonRunner({
      Tcp: [
        {
          LocalAddress: "0.0.0.0",
          LocalPort: 443,
          State: "Listen",
          OwningProcess: 100,
          ProcessName: "web"
        },
        {
          LocalAddress: "0.0.0.0",
          LocalPort: 443,
          State: "Listen",
          OwningProcess: 100,
          ProcessName: "web"
        }
      ],
      Udp: []
    });

    const ports = await openPorts(20, runner, "win32");
    expect(ports).toHaveLength(1);
  });
});

describe("network configuration", () => {
  it("normalizes Windows routes", async () => {
    const routes = await networkRoutes(
      20,
      jsonRunner({
        DestinationPrefix: "0.0.0.0/0",
        NextHop: "192.168.1.1",
        InterfaceAlias: "Wi-Fi",
        RouteMetric: 25,
        AddressFamily: "IPv4",
        State: "Alive"
      }),
      "win32"
    );

    expect(routes[0]).toMatchObject({
      destination: "0.0.0.0/0",
      gateway: "192.168.1.1",
      interface: "Wi-Fi",
      metric: 25
    });
  });

  it("normalizes Windows DNS configuration", async () => {
    const config = await dnsConfiguration(
      jsonRunner({
        InterfaceAlias: "Wi-Fi",
        AddressFamily: "IPv4",
        ServerAddresses: ["192.168.1.1", "1.1.1.1"]
      }),
      "win32"
    );

    expect(config.interfaces[0]).toMatchObject({
      interface: "Wi-Fi",
      servers: ["192.168.1.1", "1.1.1.1"]
    });
  });

  it("rejects unsafe DNS host input before resolution", async () => {
    await expect(dnsResolution("example.com; whoami"))
      .rejects.toThrow("valid hostname or IP address");
  });

  it("normalizes Windows adapter metadata", async () => {
    const adapters = await networkAdapters(
      20,
      jsonRunner({
        Name: "Ethernet",
        InterfaceDescription: "Intel Adapter",
        Status: "Up",
        MacAddress: "AA-BB-CC-DD-EE-FF",
        LinkSpeed: "1 Gbps",
        MediaType: "802.3"
      }),
      "win32"
    );

    expect(adapters[0]).toMatchObject({
      name: "Ethernet",
      status: "Up",
      macAddress: "AA-BB-CC-DD-EE-FF"
    });
  });

  it("normalizes Windows neighbor-cache metadata", async () => {
    const neighbors = await arpNeighbors(
      20,
      jsonRunner({
        IPAddress: "192.168.1.1",
        LinkLayerAddress: "11-22-33-44-55-66",
        State: "Reachable",
        InterfaceAlias: "Wi-Fi",
        AddressFamily: "IPv4"
      }),
      "win32"
    );

    expect(neighbors[0]).toMatchObject({
      ipAddress: "192.168.1.1",
      state: "Reachable",
      interface: "Wi-Fi"
    });
  });
});

describe("firewall inspection", () => {
  it("returns Windows firewall profile state", async () => {
    const status = await firewallStatus(
      jsonRunner({
        Name: "Public",
        Enabled: true,
        DefaultInboundAction: "Block",
        DefaultOutboundAction: "Allow"
      }),
      "win32"
    );

    expect(status.provider).toBe("windows-defender-firewall");
    expect(status.profiles[0]).toMatchObject({
      name: "Public",
      enabled: true
    });
  });

  it("returns bounded Windows firewall-rule metadata", async () => {
    const result = await firewallRules(
      20,
      jsonRunner({
        Name: "Rule-1",
        DisplayName: "Allow HTTPS",
        Enabled: true,
        Direction: "Inbound",
        Action: "Allow",
        Profile: "Any"
      }),
      "win32"
    );

    expect(result.rules[0]).toMatchObject({
      displayName: "Allow HTTPS",
      direction: "Inbound",
      action: "Allow"
    });
  });
});

describe("evidence correlation without security claims", () => {
  it("groups connections by owning process", async () => {
    const runner = jsonRunner({
      Tcp: [
        {
          LocalAddress: "10.0.0.5",
          LocalPort: 50000,
          RemoteAddress: "203.0.113.10",
          RemotePort: 443,
          State: "Established",
          OwningProcess: 123,
          ProcessName: "node"
        },
        {
          LocalAddress: "10.0.0.5",
          LocalPort: 50001,
          RemoteAddress: "203.0.113.11",
          RemotePort: 443,
          State: "Established",
          OwningProcess: 123,
          ProcessName: "node"
        }
      ],
      Udp: []
    });

    const map = await processNetworkMap(20, runner, "win32");
    expect(map[0]).toMatchObject({
      pid: 123,
      processName: "node",
      connectionCount: 2,
      localPorts: [50000, 50001]
    });
  });

  it("defines unexpected ports only against the caller baseline", async () => {
    const runner = jsonRunner({
      Tcp: [
        {
          LocalAddress: "0.0.0.0",
          LocalPort: 22,
          State: "Listen",
          OwningProcess: 10,
          ProcessName: "ssh"
        },
        {
          LocalAddress: "0.0.0.0",
          LocalPort: 8443,
          State: "Listen",
          OwningProcess: 11,
          ProcessName: "app"
        }
      ],
      Udp: []
    });

    const result = await unexpectedListeningPorts(
      [{ protocol: "tcp", port: 22 }],
      20,
      runner,
      "win32"
    );

    expect(result.unexpectedCount).toBe(1);
    expect(result.unexpected[0].localPort).toBe(8443);
    expect(result.interpretation).toContain("does not mean malicious");
  });

  it("reports outbound baseline mismatches without compromise claims", async () => {
    const runner = jsonRunner({
      Tcp: [
        {
          LocalAddress: "10.0.0.5",
          LocalPort: 51000,
          RemoteAddress: "203.0.113.10",
          RemotePort: 443,
          State: "Established",
          OwningProcess: 123,
          ProcessName: "browser"
        },
        {
          LocalAddress: "10.0.0.5",
          LocalPort: 51001,
          RemoteAddress: "203.0.113.20",
          RemotePort: 8080,
          State: "Established",
          OwningProcess: 124,
          ProcessName: "app"
        }
      ],
      Udp: []
    });

    const result = await unusualOutboundConnections(
      [443],
      [],
      20,
      runner,
      "win32"
    );

    expect(result.outsideBaselineCount).toBe(1);
    expect(result.outsideBaseline[0].remotePort).toBe(8080);
    expect(result.interpretation).toContain("not a malware or compromise determination");
  });

  it("requires a caller baseline for outbound deviation analysis", async () => {
    await expect(
      unusualOutboundConnections([], [], 20, jsonRunner({ Tcp: [], Udp: [] }), "win32")
    ).rejects.toThrow("Provide at least one allowed remote port");
  });
});
