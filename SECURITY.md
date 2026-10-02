# Security Policy

## v1.1 production boundary

OpsChugex LocalOps MCP v1.1 remains a local stdio MCP server. It preserves the v1.0 process-bound RBAC, policy evaluation, production readiness and optional metadata-only durable execution audit, and adds read-only Database Intelligence.

It does **not** expose arbitrary shell/PowerShell, SSH/WinRM fleet control, subnet discovery, SNMP writes, hypervisor/storage mutation, lateral execution, cross-device remediation, R3+ automatic execution, arbitrary SQL, database write operations, transaction termination, failover, or database configuration mutation.

## Database credential boundary

Database tools accept a validated profile ID only.

Profiles are defined in `LOCALOPS_DATABASE_PROFILES` and may reference a separate password environment variable using `passwordEnv`.

The database layer:

- never accepts password values as MCP arguments
- never accepts connection strings as MCP arguments
- never returns password values
- never returns secret environment-variable names through `database_profiles`
- passes supported client credentials through child-process environment variables rather than command-line password arguments
- redacts configured credential values from database client stdout/stderr before errors are returned
- rejects malformed profile IDs, host metadata, ports and credential-environment names
- caps profile count at 50

Supported engines are PostgreSQL, MySQL/MariaDB, SQL Server and Redis.

## Database query boundary

All database telemetry statements are fixed in code.

LocalOps does not expose:

- arbitrary SQL
- application query text
- INSERT, UPDATE, DELETE or DDL
- KILL/terminate session or transaction operations
- backup/restore commands
- failover or replication-control commands
- database user/role mutation

Permission failures and unsupported telemetry are returned as limitations.

## RBAC and controlled execution

The v1.0 role model remains unchanged:

- `viewer`: R0/R1 inspection and analysis
- `operator`: R0/R1 plus R2 proposal creation
- `maintainer`: R0/R1 plus R2 proposal and approved execution
- `admin`: same R2 execution boundary as maintainer

R3+ remains unavailable.

Database Intelligence is read-only R0/R1 analysis and cannot create or consume local execution approvals.

## Durable audit

When `LOCALOPS_AUDIT_PERSISTENCE=true`, LocalOps writes metadata-only JSONL execution audit records. Database credentials, query output and approval tokens are not written to the durable execution audit.

## Private intelligence

The private intelligence core remains bearer-authenticated and loopback-only. Public client routes are allowlisted and non-loopback private-core URLs are rejected.

Database health, replication, contention and pressure outputs are operational evidence summaries. They are not proof of data integrity, application correctness or compromise.

## Data minimization

Existing minimization rules remain: no environment values, private-key contents, process command lines, startup/scheduled-task commands or packet payloads. Database collection does not return application query text.

## Reporting

Use GitHub private security reporting / Security Advisories. Do not publish credentials, database snapshots, customer evidence, or proprietary intelligence behavior in a public issue.
