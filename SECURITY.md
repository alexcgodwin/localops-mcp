# Security Policy

## v0.8 security boundary

OpsChugex LocalOps MCP v0.8 combines read-only local collection, a disabled-by-default R2 local execution gateway, optional private correlation/root-cause analysis, and snapshot-based Fleet Intelligence.

It does **not** expose:

- arbitrary shell or arbitrary PowerShell execution
- SSH or WinRM fleet control
- remote credential storage
- lateral command execution
- process termination
- account disabling or credential changes
- firewall mutation
- quarantine operations
- arbitrary file deletion
- event-log clearing or audit-policy mutation
- packet capture or remote port scanning
- R3+ automatic execution
- automatic cross-node remediation
- public or LAN access to the private intelligence core

## Fleet data minimization

Fleet snapshots contain bounded normalized metadata only:

- host metadata and health
- software names/versions
- patch/kernel markers
- certificate metadata
- service state
- local administrator membership
- startup registrations
- scheduled task/timer metadata
- summarized recent security-change counts/categories

Raw event messages are not stored in the fleet registry.

The registry is in-memory only, capped at 500 nodes, and cleared when the LocalOps process exits.

Registering a snapshot stores caller-supplied evidence. Registration by itself does not authenticate, attest, enroll, or establish trust in a remote endpoint.

## Fleet analysis semantics

- every drift operation requires an explicit baseline node
- stale snapshots and large capture-time skew are reported as limitations rather than silently compared as equally current
- drift means difference, not automatically error, unauthorized change or compromise
- a missing baseline patch on a target is surfaced as high-severity drift, but still requires operator validation
- network or security metadata never authorizes remote action
- the private fleet engine performs analysis only
- cross-node remediation is not implemented in v0.8

## Controlled execution

The existing v0.5 local execution boundary remains unchanged. Execution is disabled unless `LOCALOPS_EXECUTION_ENABLED=true`, service actions require exact allowlisting, and every R2 action requires a short-lived one-time approval token plus exact `APPROVE` confirmation.

Fleet tools cannot create, reuse or bypass execution approvals for another node.

## Private intelligence core

The public client accepts only literal loopback IP endpoints, requires `LOCALOPS_INTELLIGENCE_TOKEN` with at least 32 characters, calls only allowlisted private API routes, and does not echo authentication material in connection errors.

## Reporting a vulnerability

Use GitHub private security reporting / Security Advisories. Do not publish credentials, sensitive host/fleet data, customer evidence or proprietary intelligence behavior in a public issue.
