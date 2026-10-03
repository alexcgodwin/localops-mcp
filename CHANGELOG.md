# Changelog

## 1.9.0

- Added Incident Knowledge Search & Case Clustering on top of durable v1.8 incident knowledge.
- Added `incident_knowledge_search`, `incident_case_neighbors` and `incident_case_clusters`.
- Structured search supports bounded signal IDs, tags, cause categories, severity, scope, outcome status and resolution category criteria.
- Search ranking measures supplied-query coverage and returns at most 50 results; it is not probability or causal confidence.
- Nearest-case matching uses normalized fingerprint-token Jaccard overlap and returns at most 20 cases.
- Case clustering uses a caller-selected 1-100 similarity threshold across at most 200 supplied cases and returns at most 50 cluster summaries.
- Cluster summaries include case IDs, average similarity, common signals/tags/cause categories and recorded outcome categories.
- Search/clustering stays inside the authenticated loopback private core and uses no external embeddings, vector database or arbitrary raw-log query.
- No incident-search, clustering or similarity result authorizes execution or remediation.

## 1.8.0

- Added Durable Incident Knowledge & Resolution Intelligence on top of v1.7 incident memory and recurrence analysis.
- Added optional local incident persistence through `LOCALOPS_INCIDENT_PERSISTENCE=true`, using the existing LocalOps data directory and a bounded 200-case `incident-memory.json`.
- Durable incident writes use atomic replacement and restrictive filesystem permissions where supported.
- Added structured operator-confirmed outcomes with fixed status/category fields, verification state and optional bounded duration.
- Added `incident_memory_status`, `record_incident_outcome`, `incident_resolution_patterns` and `incident_resolution_history`.
- Added private resolution-pattern analysis across resolved/mitigated cases and historical resolution matching by normalized evidence overlap.
- Resolution history is bounded to 20 matches from at most 200 supplied cases.
- Incident persistence and outcomes exclude raw event logs, packet data, credentials, command output, approval tokens and arbitrary remediation commands/notes.
- Historical outcomes are investigation context only and never authorize or prescribe remediation.

## 1.7.0

- Added Incident Memory & Recurrence Intelligence on top of v1.6 Cross-Node Incident Correlation.
- Added `capture_incident_case`, `list_incident_cases`, `incident_case_details`, `compare_incident_cases`, `incident_recurrence_analysis` and `incident_history_summary`.
- Added a bounded 200-case in-memory incident registry containing normalized fingerprints rather than raw event logs.
- Incident fingerprints contain bounded signal IDs/categories, affected node IDs, common tags, cause categories, scope, severity and a stable private-core signature.
- Added private evidence-overlap comparison with none/weak/possible/strong recurrence bands.
- Added bounded recurrence analysis and history summaries for repeated signals, tags and cause categories.
- Incident similarity is investigative evidence, not recurrence probability or proof of a shared root cause.
- Incident memory excludes raw event logs, packet data, credentials, command output and approval tokens.
- Added fixed authenticated loopback routes under `/v1/incidents/*`; no incident execution or remediation route exists.

## 1.6.0

- Added Cross-Node Incident Correlation across bounded registered fleet snapshots.
- Added `fleet_incident_correlation` for repeated health, resource-pressure, service-state and security-change evidence across nodes.
- Added `fleet_incident_timeline` for a bounded chronological snapshot timeline with explicit timestamp limitations.
- Added `fleet_shared_cause_analysis` for evidence-backed shared-cause hypotheses with evidence-confidence scoring that is not a causation probability.
- Added `fleet_incident_scope` to classify observed impact as none, localized, multi-node or fleet-wide and surface common affected tags.
- Cross-node analysis is performed by the private loopback intelligence core; the public MCP exposes only bounded registered snapshot contracts.
- Correlation does not prove causation and never authorizes remediation or host mutation.
- Private cross-node routes remain authenticated, loopback-only and analysis-only.

## 1.5.0

- Added Predictive Health Intelligence for bounded CPU, memory and disk trend analysis.
- Added bounded in-memory per-node health history with up to 96 distinct observations.
- Added `node_health_history`, `node_predictive_health` and `fleet_predictive_health`.
- Predictive requests are limited to a 1-168 hour horizon and registered LocalOps node histories.
- Private forecasts report directional slope, projected utilization, warning/critical threshold ETA and evidence-confidence coverage.
- Forecasts return `insufficient-data` when history is too short instead of inventing a trend.
- Evidence confidence describes observation coverage, not failure probability.
- Predictive output never authorizes or triggers remediation.
- Fixed v1.4 workflow status to use the same injected clock as workflow creation/expiry checks, removing a time-dependent regression.
- Private predictive analysis remains loopback-only and authenticated.

## 1.4.0

- Added Automated Remediation Workflows backed by private evidence-based remediation planning and the existing controlled-execution gateway.
- Added `remediation_workflow_status`, `create_remediation_workflow`, `remediation_workflow_details`, `record_remediation_step`, `prepare_remediation_step` and `execute_approved_remediation_step`.
- Added ordered workflow gates so validation steps must be completed before later controlled R2 steps can be prepared.
- Added a 30-minute bounded in-memory workflow lifetime and a 100-workflow retention cap.
- Workflow state never stores raw approval tokens; it stores only a SHA-256 token binding for matching the later execution request.
- Workflow-bound approval tokens cannot be consumed through the generic `execute_approved_action` path and must match the originating workflow and step.
- v1.4 workflow execution additionally requires durable audit persistence even though generic v1.0 R2 execution remains backward compatible.
- Execution audit records now carry optional workflow and workflow-step identifiers without storing approval tokens.
- R3+ remediation remains manual and unavailable through execution tools.
- No workflow automatically authorizes or silently executes a host change.

## 1.3.0

- Added Network Topology Intelligence on top of the existing private-infrastructure graph model.
- Added `network_dependency_path`, `network_path_redundancy`, `network_failure_domains` and `network_change_impact`.
- Dependency-path analysis returns the shortest submitted non-down path, hop count, unknown-link count and bounded bottleneck-speed evidence.
- Path-redundancy analysis checks one primary-path link or intermediate-node loss at a time without probing or changing the network.
- Failure-domain analysis measures additional pairwise connectivity loss for submitted nodes and non-parallel active links.
- Change-impact analysis performs bounded what-if simulations for explicitly selected unavailable nodes or endpoint-pair links.
- Added authenticated private topology routes under `/v1/topology/*`.
- Existing `network_device_health` and `private_network_topology` now report the v1.3 private topology engine version while keeping their existing contracts.
- No subnet scanning, remote login, SSH/WinRM control, SNMP writes, route/firewall mutation, remote credentials, lateral execution or automatic remediation is exposed.

## 1.2.0

- Added Storage & Backup Intelligence through named profiles configured with `LOCALOPS_BACKUP_PROFILES`; MCP tools accept profile IDs rather than arbitrary filesystem paths.
- Added `backup_profiles`, `backup_snapshot`, `backup_inventory`, `backup_freshness`, `backup_restore_point_validation`, `backup_retention`, `backup_storage_growth`, `backup_snapshot_health`, `backup_recovery_readiness` and `backup_risk_correlation`.
- Added bounded local backup inventory with a 5,000-file limit, maximum directory depth of 16, extension filtering and no symbolic-link traversal.
- Added backup freshness, retention, filesystem-capacity, RPO and operator-supplied RTO/restore-verification evidence.
- Added non-destructive restore-point metadata validation for presence, non-zero size and read access; LocalOps does not execute restores or claim application-level recoverability.
- Added caller-supplied point-in-time backup growth comparison without persisting or inventing historical trend data.
- Added private-core snapshot-health, recovery-readiness and multi-signal backup-risk correlation.
- Added backup-profile validation to `production_readiness`.
- Restore, delete, prune, format and storage-mutation operations remain unavailable.

## 1.1.0

- Added Database Intelligence for PostgreSQL, MySQL/MariaDB, SQL Server and Redis.
- Added named database profiles through `LOCALOPS_DATABASE_PROFILES`; MCP tools accept profile IDs only.
- Added `database_profiles`, `database_snapshot`, `database_health`, `database_capacity`, `database_connection_summary`, `database_replication_health`, `database_lock_summary` and `database_query_pressure`.
- Database credentials are referenced through separate environment variables and are never returned in profile metadata or passed as MCP arguments.
- Added fixed read-only engine telemetry queries for version/inventory, connections, capacity, replication, locks/contention and workload pressure.
- Added private-core database health, replication, contention and pressure analysis.
- Added database-profile validation to `production_readiness`.
- No arbitrary SQL, connection strings, query text, write statements, DDL, transaction termination, failover or database-configuration mutation is exposed.
- Missing permissions or unsupported engine telemetry are preserved as explicit limitations rather than treated as healthy/zero state.

## 1.0.0

- Added process-bound RBAC roles: `viewer`, `operator`, `maintainer`, and `admin`.
- Added enforced R0/R1/R2/R3+ policy evaluation; R3+ execution remains unavailable.
- Added `platform_status`, `policy_status`, `evaluate_policy`, `production_readiness`, and `production_audit_log`.
- Enforced RBAC at both execution proposal and R2 execution boundaries.
- Default role is least-privileged `viewer`.
- Added optional metadata-only durable JSONL execution auditing through `LOCALOPS_AUDIT_PERSISTENCE=true`.
- Durable audit records exclude approval tokens and command output.
- Added production readiness checks for Node.js, RBAC, execution/audit coherence, data-directory safety, and private-core reachability.
- Existing local controlled execution still requires feature enablement, exact service allowlisting, one-time approval, exact `APPROVE` confirmation, verification, and rollback guidance.
- v1.0 adds no R3+ actions, remote shell, SSH/WinRM fleet control, hypervisor/storage mutation, lateral execution, or cross-device remediation.

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
