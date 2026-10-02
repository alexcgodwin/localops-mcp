# Security Policy

## v0.6 security boundary

OpsChugex LocalOps MCP v0.6 combines read-only collection, a disabled-by-default R2 execution gateway, and an optional private evidence-correlation service.

It does **not** expose:

- arbitrary shell or arbitrary PowerShell execution
- process termination
- account disabling or account mutation
- firewall mutation
- quarantine operations
- arbitrary file deletion
- event-log clearing or retention changes
- audit-policy mutation
- Defender configuration mutation
- remote port scanning
- packet capture or packet payload inspection
- credential, secret, SSH private-key or certificate private-key contents
- R3+ execution actions
- public or LAN access to the private intelligence core

The only v0.5/v0.6 mutation actions are start/restart of explicitly allowlisted services, local DNS cache refresh, and bounded cleanup of old regular files inside the operating-system temporary directory.

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

## Controlled execution

Execution is disabled unless `LOCALOPS_EXECUTION_ENABLED=true`.

Service actions also require exact names in `LOCALOPS_ALLOWED_SERVICES`.

The v0.6 execution path is:

1. validate feature enablement
2. validate target and allowlist
3. run preflight
4. create a five-minute one-time approval token
5. require exact `confirmation="APPROVE"`
6. re-check service allowlisting
7. execute the action
8. verify the result
9. write an in-memory audit record
10. return rollback/recovery guidance

Approval tokens are never included in audit records.

## Private intelligence core

Evidence-correlation tools use the separate private OpsChugex LocalOps Intelligence Core.

The public client:

- accepts only `http` loopback endpoints
- rejects non-loopback hostnames
- requires `LOCALOPS_INTELLIGENCE_TOKEN` with at least 32 characters
- calls only a fixed allowlist of private API routes
- sends bounded normalized evidence
- does not send arbitrary commands
- does not echo authentication material in connection errors

The private service binds only to `127.0.0.1` in v0.6.

Correlation output describes evidence relationships. It does not claim root cause, compromise or remediation decisions.

## Reporting a vulnerability

Please use GitHub private security reporting / Security Advisories for this repository. Do not publish credentials, exploit details, sensitive host data, private intelligence logic or customer evidence in a public issue.
