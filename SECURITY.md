# Security Policy

## v0.7 security boundary

OpsChugex LocalOps MCP v0.7 combines read-only collection, a disabled-by-default R2 controlled-execution gateway, and optional private evidence-correlation/root-cause analysis over an authenticated loopback interface.

It does **not** expose:

- arbitrary shell or arbitrary PowerShell execution
- process termination
- account disabling or credential changes
- firewall mutation
- quarantine operations
- arbitrary file deletion
- event-log clearing or retention changes
- audit-policy mutation
- Defender configuration mutation
- remote port scanning
- packet capture or packet payload inspection
- credential, secret, SSH private-key or certificate private-key contents
- R3+ automatic execution
- public or LAN access to the private intelligence core

The only automatic mutation actions remain the bounded v0.5 R2 set: start/restart explicitly allowlisted services, local DNS cache refresh, and bounded cleanup of old regular files inside the operating-system temporary directory.

## Data minimization

LocalOps follows these minimization rules:

- process command lines are excluded
- environment-variable names may be returned, values are never returned
- SSH key files are inventoried by metadata only
- scheduled-task action commands are excluded
- startup command lines are excluded
- certificate private-key material is never read
- event messages are bounded and secret-like key/value patterns are redacted
- packet contents are never captured
- caller-baseline deviations are not treated as malicious
- inaccessible logs and missing audit coverage remain explicit evidence limitations
- v0.7 evidence bundles add only bounded host-health and process-resource metrics

## Controlled execution

Execution is disabled unless `LOCALOPS_EXECUTION_ENABLED=true`.

Service actions also require exact names in `LOCALOPS_ALLOWED_SERVICES`.

The execution path remains:

1. validate feature enablement
2. validate target and allowlist
3. run preflight
4. create a five-minute one-time approval token
5. require exact `confirmation="APPROVE"`
6. re-check service allowlisting
7. execute the approved R2 action
8. verify the result
9. write an in-memory audit record
10. return rollback/recovery guidance

Approval tokens are never included in audit records.

## Private intelligence core

v0.6 correlation and v0.7 root-cause tools use the separate private OpsChugex LocalOps Intelligence Core.

The public client:

- accepts only literal loopback IP endpoints
- requires `LOCALOPS_INTELLIGENCE_TOKEN` with at least 32 characters
- calls only a fixed allowlist of private API routes
- sends bounded normalized evidence
- does not send arbitrary commands
- does not echo authentication material in connection errors

The private service binds only to `127.0.0.1`.

## Root-cause semantics

v0.7 analysis is deliberately non-authoritative:

- ranked causes are evidence-backed hypotheses, not definitive verdicts
- confidence measures evidence coverage/alignment, not compromise probability
- source limitations reduce confidence
- change triggers are temporal starting points, not proof of causation
- blast radius is limited to observed local entities and network relationships
- remote endpoints are not declared affected merely because a connection exists
- remediation recommendations are advisory only
- no recommendation authorizes or bypasses the controlled-execution gateway

## Reporting a vulnerability

Please use GitHub private security reporting / Security Advisories for this repository. Do not publish credentials, exploit details, sensitive host data, private intelligence behavior or customer evidence in a public issue.
