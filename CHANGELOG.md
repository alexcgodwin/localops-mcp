# Changelog

## 0.6.0

- Added seven evidence-correlation MCP tools: `intelligence_status`, `correlate_process_activity`, `correlate_service_activity`, `correlate_identity_activity`, `correlate_network_activity`, `correlate_persistence_signals` and `build_incident_timeline`.
- Added bounded cross-source evidence packaging for processes, services, network connections, startup programs, scheduled tasks, local identities and recent event evidence.
- Preserves source permission/audit limitations in every correlation bundle.
- Added an authenticated loopback-only client for the separate private OpsChugex LocalOps Intelligence Core.
- Public client rejects non-loopback intelligence URLs and unsupported private routes.
- Private authentication material is never returned in MCP responses or connection errors.
- Proprietary correlation rules remain outside the public MIT repository.
- v0.6 correlation reports evidence relationships and timelines only; root-cause, compromise and remediation decisions remain future private-core capabilities.
- End-to-end Windows verification confirmed the public MCP can collect bounded evidence and receive correlation results from the private core over loopback.

## 0.5.0

- Added a disabled-by-default Controlled Execution Gateway.
- Added `execution_status`, `propose_execution`, `execute_approved_action` and `execution_audit_log`.
- Added bounded R2 actions for starting an allowlisted service, restarting an allowlisted service, refreshing the local DNS cache and deleting bounded old regular files from the operating-system temporary directory.
- Execution requires `LOCALOPS_EXECUTION_ENABLED=true`.
- Service mutations additionally require exact allowlisting through `LOCALOPS_ALLOWED_SERVICES`.
- Every action follows preflight -> proposal -> five-minute one-time approval token -> exact `APPROVE` confirmation -> execution -> verification -> audit -> rollback guidance.
- Service allowlisting is rechecked immediately before execution.
- Approval tokens are never written to the execution audit log.
- v0.5 audit records are intentionally in-memory only.
- R3+ actions such as process termination, account disabling, firewall mutation, quarantine and arbitrary file deletion are not exposed.
- Live development verification used read-only status checks only; execution behavior was validated with mocks rather than mutating the development host.

## 0.4.0

- Added bounded Windows Event Log and Linux journal evidence collectors.
- Added supported successful-login and failed-login evidence tools.
- Added Windows service-install, account-creation, privileged-group and process-audit evidence.
- Added scheduled-task/timer and Microsoft Defender Operational evidence.
- Added deterministic recent-system-change and recent-security-change aggregation.
- Added caller-baseline service detection without malicious or unauthorized labels.
- Event messages are bounded and secret-like values are redacted.
- Permission and audit-policy gaps are preserved as explicit evidence limitations rather than treated as zero events.
- Linux process-creation evidence remains unknown unless an explicit audit source such as auditd or eBPF telemetry is configured.
- v0.4 remains read-only and exposes no log clearing, audit-policy mutation, remediation or arbitrary shell tool.

## 0.3.0

- Added local TCP/UDP listener and active connection inventory for Windows and Linux.
- Added local routing-table, DNS configuration and validated DNS-resolution tools.
- Added read-only firewall status and bounded firewall-rule inspection.
- Added network adapter and ARP/neighbor-cache inventory.
- Added process-to-network mapping without packet capture or process command-line collection.
- Added caller-baseline comparison for unexpected listening ports and outbound TCP endpoints.
- Baseline deviations are explicitly not treated as malware or compromise determinations.
- Added Linux/Windows normalization and regression coverage for the network layer.
- v0.3 remains read-only and exposes no remote port scanning, packet capture, firewall mutation or arbitrary shell tool.

## 0.2.0

- Added installed software and version inventory for Windows and Linux package databases.
- Added caller-supplied software baseline comparison without local persistence.
- Added local user, group and administrator inventory.
- Added startup program and scheduled-task metadata while excluding command/action contents.
- Added certificate inventory and expiry checks without private-key reads.
- Added SSH key file metadata without reading key contents.
- Added environment-variable name inventory without exposing values.
- Expanded privacy and safety regression coverage.
- v0.2 remains read-only and exposes no mutation or arbitrary shell tool.

## 0.1.0

- Initial OpsChugex LocalOps MCP release.
- Read-only Windows and Linux system discovery.
- System, CPU, memory, disk, network, process and service inspection.
- No mutation, remediation or arbitrary shell tool is exposed.
