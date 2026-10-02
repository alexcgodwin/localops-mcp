# Changelog

## 0.9.0

- Added `virtual_machine_inventory` for locally available Hyper-V, VirtualBox, Proxmox, libvirt and VMware CLI inventory using fixed read-only commands.
- Added `vm_health` for exact local VM ID/name state lookup without mutation.
- Added `storage_capacity` and `storage_health` for bounded local filesystem capacity plus supported Windows physical-disk health metadata.
- Added `ups_health` for locally exposed Windows battery/UPS or Linux UPower telemetry.
- Added `network_device_health` for private-core analysis of bounded caller-supplied router, switch, firewall, DNS/DHCP, AP, NAS, storage, UPS, hypervisor and server snapshots.
- Added `private_network_topology` for component, isolated-node, down-link and articulation/dependency analysis of caller-supplied topology.
- Added strict private API validation for device IDs, timestamps, metrics, interfaces, links and per-request bounds.
- v0.9 performs no subnet discovery, remote login, SNMP writes, remote credential collection, hypervisor mutation, storage mutation, lateral execution or cross-device remediation.
- Submitted infrastructure snapshots are evidence only and do not authenticate or attest device identity.

## 0.8.0

- Added snapshot-based Fleet Intelligence with no SSH, WinRM, remote shell, credential storage or lateral execution.
- Added `capture_node_snapshot` and `register_node` for bounded normalized fleet snapshots.
- Added `list_nodes`, `node_health`, `fleet_health` and `fleet_inventory`.
- Added private-core `compare_nodes`, `configuration_drift`, `software_drift`, `patch_drift`, `certificate_drift` and `security_drift`.
- Fleet drift requires an explicitly selected baseline node.
- Fleet snapshots store summarized security-change categories/counts, not raw event messages.
- Added bounded Windows hotfix and Linux kernel/package patch markers for patch drift.
- Fleet registry is in-memory only and stores at most 500 nodes.
- Snapshot registration does not authenticate or attest node identity.
- Stale snapshots and large capture-time skew are surfaced as analysis limitations.
- Drift findings describe differences and do not automatically mean error, unauthorized change or compromise.
- Cross-node automatic remediation remains unavailable; existing controlled execution remains local and approval-gated.

## 0.7.0

- Added seven root-cause intelligence MCP tools: `rank_probable_causes`, `calculate_confidence`, `build_evidence_chain`, `suggest_investigation_path`, `identify_change_trigger`, `identify_blast_radius` and `recommend_remediation`.
- Extended bounded evidence bundles with current host-health measurements and process resource metrics.
- Added public schemas and allowlisted private routes for v0.7 analysis without exposing proprietary ranking logic.
- Probable causes are explicitly ranked hypotheses rather than definitive verdicts.
- Evidence confidence represents source coverage/alignment and is reduced by audit/permission limitations; it is not compromise probability.
- Change-trigger output is explicitly temporal evidence rather than proof of causation.
- Blast-radius output is bounded to observed local entities and network relationships and does not declare remote systems affected.
- Remediation recommendations are advisory, risk-tiered and never authorize execution.
- Proprietary ranking, confidence, evidence-chain, investigation, blast-radius and remediation algorithms remain in the private OpsChugex LocalOps Intelligence Core.

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
