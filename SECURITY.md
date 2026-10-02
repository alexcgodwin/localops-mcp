# Security Policy

## v0.9 security boundary

OpsChugex LocalOps MCP v0.9 combines read-only local collection, a disabled-by-default R2 local execution gateway, private correlation/root-cause/fleet analysis, and read-only Private Infrastructure Intelligence.

It does **not** expose:

- arbitrary shell or arbitrary PowerShell execution
- subnet discovery or remote port scanning
- SSH, WinRM, remote shell or remote credential storage
- SNMP writes or device-configuration mutation
- hypervisor VM start/stop/create/delete actions
- storage formatting, mounting changes or filesystem mutation
- lateral command execution
- process termination, account disabling or credential changes
- firewall mutation or quarantine
- packet capture
- R3+ automatic execution
- automatic cross-node or cross-device remediation
- public or LAN access to the private intelligence core

## Private infrastructure collection

Local infrastructure tools use fixed read-only local commands/APIs:

- Hyper-V PowerShell `Get-VM`
- VirtualBox `VBoxManage list`
- Proxmox `qm list`
- libvirt `virsh list --all`
- VMware `vmrun list`
- local filesystem capacity
- supported Windows physical-disk health metadata
- Windows `Win32_Battery` or Linux UPower telemetry

Unavailable providers are reported as limitations. LocalOps does not fall back to arbitrary shell execution.

## Network-device and topology analysis

`network_device_health` and `private_network_topology` consume bounded caller-supplied snapshots. They do not discover, probe, authenticate to or configure infrastructure devices.

Submitted snapshots do not authenticate, enroll, attest or establish trust in a device.

The private API validates:

- unique bounded device identifiers
- valid timestamps
- bounded metric ranges
- bounded interface/tag/limitation arrays
- link endpoints that reference submitted devices
- bounded link counts

Topology articulation results indicate dependency concentration in the submitted graph. They are not guaranteed production single points of failure.

## Fleet and execution boundaries

The v0.8 fleet registry remains in-memory only and capped at 500 nodes. Fleet snapshot registration does not authenticate node identity.

The v0.5 local execution gateway remains separate. Execution is disabled unless `LOCALOPS_EXECUTION_ENABLED=true`; service actions require exact allowlisting and short-lived explicit approval. Infrastructure/fleet analysis cannot create, reuse or bypass those approvals.

## Private intelligence core

The public client accepts only literal loopback IP endpoints, requires `LOCALOPS_INTELLIGENCE_TOKEN` with at least 32 characters, calls only allowlisted private API routes, and does not echo authentication material in connection errors.

## Reporting a vulnerability

Use GitHub private security reporting / Security Advisories. Do not publish credentials, sensitive host/fleet/infrastructure data, customer evidence or proprietary intelligence behavior in a public issue.
