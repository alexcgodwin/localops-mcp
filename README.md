# OpsChugex LocalOps MCP

<!-- mcp-name: io.github.alexcgodwin/localops-mcp -->

[![CI](https://github.com/alexcgodwin/localops-mcp/actions/workflows/ci.yml/badge.svg)](https://github.com/alexcgodwin/localops-mcp/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![MCP](https://img.shields.io/badge/MCP-LocalOps-blue)](server.json)

**Local Infrastructure, Endpoint & Systems Intelligence**

OpsChugex LocalOps MCP is a cross-platform Model Context Protocol server for safely inspecting local Windows and Linux systems. It is designed as the local/private-infrastructure counterpart to the Cloud DevOps MCP Server.

Version 0.7.0 adds private root-cause intelligence on top of the v0.6 evidence-correlation layer. The public MCP still owns bounded evidence collection and safe MCP contracts, while the private OpsChugex LocalOps Intelligence Core owns cause ranking, evidence confidence, evidence chains, investigation sequencing, change-trigger selection, blast-radius reasoning and remediation recommendations. These outputs are evidence-backed hypotheses, not proof of compromise or certainty, and they never authorize execution.

## Why this exists

Cloud operations tools can see cloud resources, deployments and managed services. They often cannot explain what is happening inside a workstation, private server or endpoint.

LocalOps starts at the operating-system layer:

- host and operating-system discovery
- CPU, memory and disk pressure
- network interface inventory
- bounded process inspection
- Windows service and systemd service inspection
- installed software and version inventory
- local users, groups and administrator membership
- startup program and scheduled-task metadata
- certificate and certificate-expiry inventory
- SSH key metadata without key contents
- environment-variable names without values
- local listening ports and active connection evidence
- routing, DNS and firewall configuration summaries
- adapter and ARP/neighbor-cache inventory
- process-to-network mapping without packet contents
- caller-baseline checks for unexpected listeners and outbound endpoints
- bounded Windows Event Log and Linux journal evidence
- login success/failure evidence where the host audit source permits it
- service, account, privileged-group and scheduler change evidence
- Microsoft Defender operational evidence on Windows
- explicit evidence-gap reporting when permissions or audit configuration are insufficient
- caller-baseline service-change detection
- disabled-by-default controlled execution gateway
- exact service allowlisting for service mutations
- five-minute one-time approval tokens
- post-action verification and in-memory audit records
- bounded evidence bundles for private correlation
- authenticated loopback-only private intelligence interface
- process, service, identity, network and persistence correlation
- chronological incident evidence timelines
- evidence-backed probable-cause ranking
- evidence-confidence scoring with source-limit penalties
- root-cause evidence chains
- read-only investigation paths
- temporal change-trigger identification
- local/evidence-based blast-radius analysis
- advisory remediation recommendations with risk tiers
- normalized Windows/Linux outputs
- explicit R0-R2 safety boundaries with R3+ blocked

The long-term goal is evidence correlation across endpoints, private infrastructure, networking, storage and virtualization while keeping advanced OpsChugex intelligence proprietary.

## v0.7 tools

| Tool | Purpose |
| --- | --- |
| `system_info` | Host, OS, architecture, CPU count and uptime |
| `system_health` | CPU, memory and disk pressure summary |
| `cpu_status` | Sample CPU utilization and processor metadata |
| `memory_status` | Physical memory usage |
| `disk_status` | Fixed-disk capacity and utilization |
| `network_interfaces` | Local adapters and assigned addresses |
| `list_processes` | Bounded process inventory without command lines |
| `inspect_process` | Inspect one process by PID |
| `list_services` | Windows services or systemd units |
| `service_status` | Inspect one validated service name |
| `uptime` | System uptime in seconds, hours and days |
| `installed_software` | Bounded installed-software inventory with versions |
| `software_versions` | Look up versions for requested installed software |
| `software_changes` | Compare current software with a caller-supplied baseline |
| `local_users` | Local account metadata without credentials |
| `local_groups` | Local group metadata and Linux group membership |
| `local_admins` | Built-in Windows administrators or common Linux admin groups |
| `startup_programs` | Startup registration metadata without command lines |
| `scheduled_tasks` | Scheduled-task/timer metadata without action commands |
| `certificate_inventory` | Certificate metadata without private key material |
| `certificate_expiry` | Expired or soon-to-expire certificate evidence |
| `ssh_key_inventory` | SSH-directory file metadata without key contents |
| `environment_variables_summary` | Environment-variable names and sensitivity flags without values |
| `open_ports` | Unique local TCP/UDP listening endpoints without remote scanning |
| `listening_ports` | Local TCP listeners and UDP endpoints with owner metadata |
| `network_connections` | Bounded local TCP/UDP socket state without packet capture |
| `network_routes` | Local routing table |
| `dns_configuration` | Configured DNS servers and search domains |
| `dns_resolution` | Resolve one validated host through the OS resolver |
| `firewall_status` | Local firewall provider/profile state |
| `firewall_rules` | Bounded read-only firewall-rule summary |
| `network_adapters` | Local adapter and link-state inventory |
| `arp_neighbors` | Local ARP/neighbor-cache evidence without active probing |
| `process_network_map` | Group observed sockets by owning process |
| `unexpected_listening_ports` | Compare listeners with a caller-supplied port baseline |
| `unusual_outbound_connections` | Compare active TCP remotes with caller-supplied expectations |
| `windows_event_logs` | Bounded Windows event evidence from an allowlisted log set |
| `linux_journal_logs` | Bounded Linux journal evidence with optional unit/priority filters |
| `security_events` | Supported security-relevant event evidence with audit limitations |
| `login_events` | Successful login/session evidence where available |
| `failed_logins` | Failed authentication evidence where available |
| `service_install_events` | Windows service-install or bounded Linux service-change evidence |
| `account_creation_events` | Local account-creation evidence |
| `admin_group_changes` | Privileged-group membership change evidence |
| `process_creation_events` | Audited Windows process-creation evidence; Linux remains unknown without an explicit audit source |
| `task_scheduler_events` | Scheduled-task/timer event evidence |
| `defender_events` | Microsoft Defender Operational evidence on Windows |
| `recent_system_changes` | Deterministic aggregation of supported system-change evidence |
| `recent_security_changes` | Deterministic aggregation of supported security-change evidence |
| `detect_new_services` | Compare current service names with a caller-supplied baseline |
| `execution_status` | Show execution enablement, allowlist and v0.5 risk-policy state |
| `propose_execution` | Run preflight and issue a five-minute one-time approval token without executing |
| `execute_approved_action` | Execute exactly the action bound to a valid approval token |
| `execution_audit_log` | Read recent in-memory execution audit records without approval tokens |
| `intelligence_status` | Check whether the private loopback intelligence core is configured and reachable |
| `correlate_process_activity` | Correlate bounded process, event and network evidence through the private core |
| `correlate_service_activity` | Correlate service, process, event and network relationships |
| `correlate_identity_activity` | Correlate local identity, admin and authentication/change evidence |
| `correlate_network_activity` | Correlate process-to-remote-endpoint relationships without packet capture |
| `correlate_persistence_signals` | Correlate startup, scheduled-task, service, process and event evidence |
| `build_incident_timeline` | Build a chronological evidence timeline while preserving source limitations |
| `rank_probable_causes` | Rank evidence-backed operational hypotheses through the private core |
| `calculate_confidence` | Measure evidence coverage/confidence without treating it as compromise probability |
| `build_evidence_chain` | Build ordered supporting evidence chains for leading hypotheses |
| `suggest_investigation_path` | Generate an evidence-first, read-only investigation sequence |
| `identify_change_trigger` | Identify the earliest supported timestamped change as a temporal starting point |
| `identify_blast_radius` | Summarize local entities and observed network relationships tied to leading hypotheses |
| `recommend_remediation` | Return advisory risk-tiered remediation options without authorizing execution |

## Architecture

```mermaid
flowchart TD
    Client["MCP Client"] --> Server["OpsChugex LocalOps MCP"]
    Server --> Safe["Read-only tool boundary"]
    Safe --> Node["Node.js system APIs"]
    Safe --> Win["Windows adapter"]
    Safe --> Linux["Linux adapter"]
    Win --> PS["Fixed PowerShell/CIM reads"]
    Linux --> Proc["Fixed ps/df/systemctl reads"]
    Server --> Client2["Loopback Intelligence Client"]
    Client2 --> Core["Private OpsChugex LocalOps Intelligence Core"]
```

The public MCP owns protocol handling, safe collectors, normalization, evidence packaging, the loopback client and community-visible integrations. The private OpsChugex intelligence core owns correlation, root-cause ranking, confidence scoring, evidence-chain construction, investigation sequencing, trigger selection, blast-radius reasoning and remediation recommendation logic.

## Quickstart

Requirements:

- Node.js 20 or newer
- Windows 10/11 or a modern Linux distribution
- PowerShell on Windows
- `ps`, `df` and systemd tools for the relevant Linux collectors

Clone and run:

```bash
git clone https://github.com/alexcgodwin/localops-mcp.git
cd localops-mcp
npm install
npm run build
npm test
npm start
```

For development:

```bash
npm run dev
```

### Optional private intelligence core

The v0.6 correlation tools and v0.7 root-cause tools require the private OpsChugex LocalOps Intelligence Core to be running locally. Configure the public MCP process with:

```text
LOCALOPS_INTELLIGENCE_URL=http://127.0.0.1:43123
LOCALOPS_INTELLIGENCE_TOKEN=<private token of at least 32 characters>
```

The public client rejects non-loopback intelligence URLs. If the private core is not configured or running, all v0.1-v0.5 local collection/execution capabilities continue to work and `intelligence_status` reports the limitation.

## Safety model

v0.7 keeps the v0.5 read-first execution model and extends the private analysis boundary:

```text
R0 READ                     allowed
R1 ANALYZE / EVIDENCE       allowed
R2 BOUNDED EXECUTION         disabled by default; explicit approval required
R3+ HIGHER-RISK EXECUTION    not exposed
PRIVATE INTELLIGENCE          loopback-only, authenticated, analysis-only
```

Important controls:

- no arbitrary command tool
- no arbitrary PowerShell or shell input
- no environment-variable values
- no SSH key contents or private-key reads
- no scheduled-task action commands
- no startup command lines
- no process command-line collection
- no remote port scanning
- no packet capture or packet payload inspection
- no firewall changes
- "unexpected", "outside baseline" and "new" mean only that caller-supplied expectations did not match
- no event-log clearing or retention changes
- no audit-policy changes
- event messages are bounded and secret-like values are redacted
- inaccessible logs and missing audit coverage are reported as evidence limitations rather than interpreted as clean
- execution is disabled unless `LOCALOPS_EXECUTION_ENABLED=true`
- service actions require the exact service name in `LOCALOPS_ALLOWED_SERVICES`
- proposals perform preflight but do not execute
- approval tokens expire after five minutes and are one-time use
- execution requires `confirmation="APPROVE"`
- service allowlisting is checked again immediately before execution
- temporary cleanup is restricted to old regular files inside the OS temp directory, with bounded age/count controls
- R3+ actions are intentionally absent from the public server
- private intelligence URL is restricted to explicit loopback addresses
- private-core authentication requires a token of at least 32 characters
- private API routes are allowlisted in the public client
- correlation requests contain bounded normalized evidence, not arbitrary commands
- private-core connection errors do not echo authentication material
- correlation reports relationships and evidence gaps
- root-cause rankings are hypotheses, not definitive verdicts
- evidence confidence measures collection coverage/alignment, not compromise probability
- change triggers are temporal starting points, not proof of causation
- blast radius is bounded to observed local entities and network relationships
- remediation recommendations never authorize execution
- bounded list sizes
- strict PID validation
- strict service-name validation
- fixed executable/argument paths
- token/password/secret redaction in command errors and output
- no administrator/root requirement for normal Node.js collectors

Some platform collectors may require local permission to inspect specific processes or services. Permission failures are returned as errors rather than bypassed.

## Public/private boundary

This repository is the public implementation and portfolio-facing gateway.

The separate private **OpsChugex LocalOps Intelligence Core** now implements v0.6 evidence correlation plus v0.7 root-cause ranking, confidence, evidence chains, investigation paths, change triggers, blast-radius analysis and remediation recommendations. Future private capabilities include anomaly detection, predictive health, fleet-level reasoning and orchestration.

The public repository contains only evidence collection, schemas and the loopback client. Proprietary correlation, ranking, confidence and remediation algorithms are not included in this MIT repository.

## Roadmap

| Version | Focus |
| --- | --- |
| 0.1 | System discovery, completed |
| 0.2 | Endpoint inventory, completed |
| 0.3 | Network intelligence, completed |
| 0.4 | Event and security evidence, completed |
| 0.5 | Approval-gated controlled execution, completed |
| 0.6 | Evidence correlation, completed |
| 0.7 | Root-cause intelligence, completed |
| 0.8 | Fleet intelligence |
| 0.9 | Private infrastructure and virtualization |
| 1.0 | Production LocalOps platform |

## Development principles

1. Prefer native OS APIs and fixed commands over generic shell execution.
2. Treat missing evidence as unknown, not as proof of safety or failure.
3. Keep collection separate from intelligence and remediation.
4. Normalize Windows and Linux responses into stable MCP schemas.
5. Require explicit policy and approval gates before future mutation features.
6. Keep proprietary intelligence outside the public repository.

## Relationship to Cloud DevOps MCP

**Cloud DevOps MCP Server** focuses on cloud infrastructure, Kubernetes, Terraform, CI/CD, observability and cloud operations.

**OpsChugex LocalOps MCP** focuses on the operating systems, endpoints, local servers and private infrastructure underneath them.

Together they form two separate operational planes rather than overlapping wrappers around the same services.

## Author

Built and maintained by **Alex C. Godwin** under the **OpsChugex** product brand.

## License

MIT. See [LICENSE](LICENSE).
