# Security Policy

## v1.0 production boundary

OpsChugex LocalOps MCP v1.0 remains a local stdio MCP server. It adds process-bound RBAC, enforced policy evaluation, production readiness checks, and optional metadata-only durable execution auditing.

It does **not** expose arbitrary shell/PowerShell, SSH/WinRM fleet control, remote credential storage, subnet discovery, SNMP writes, hypervisor/storage mutation, lateral execution, cross-device remediation, or R3+ automatic execution.

## RBAC

Supported roles:

- `viewer`: R0/R1 inspection and analysis
- `operator`: R0/R1 plus R2 proposal creation
- `maintainer`: R0/R1 plus R2 proposal and approved execution
- `admin`: same R2 execution boundary as maintainer; R3+ remains unavailable

The default role is `viewer`.

RBAC identity is process-bound configuration for the local stdio process. It is not a remote multi-user authentication system.

## Controlled execution

Execution still requires all of the following:

1. `LOCALOPS_EXECUTION_ENABLED=true`
2. sufficient RBAC role
3. exact service allowlisting where applicable
4. preflight
5. five-minute one-time approval token
6. exact `confirmation="APPROVE"`
7. execution verification
8. audit record
9. rollback/recovery guidance

## Durable audit

When `LOCALOPS_AUDIT_PERSISTENCE=true`, LocalOps appends metadata-only JSONL records under `LOCALOPS_DATA_DIR` or the default local application directory.

Durable records include operator ID, role, action, target, risk tier, approval/execution/verification state, and outcome. They do not contain approval tokens or command output.

Production readiness reports execution without durable audit as blocked.

## Private intelligence

The separate intelligence core remains bearer-authenticated and loopback-only. Public client routes are allowlisted and non-loopback private-core URLs are rejected.

## Data minimization

Existing data-minimization rules remain: no environment values, no private-key contents, no process command lines, no startup/scheduled-task commands, no packet payloads, bounded event text, and explicit evidence limitations.

## Reporting

Use GitHub private security reporting / Security Advisories. Do not publish credentials, sensitive host/fleet data, customer evidence, or proprietary intelligence behavior in a public issue.
