# Security Policy

## v0.1 security boundary

OpsChugex LocalOps MCP v0.1 is read-only.

It does not expose:
- arbitrary shell execution
- arbitrary PowerShell input
- process termination
- service start/stop/restart
- file deletion or quarantine
- firewall mutation
- account mutation
- credential or secret retrieval

Platform commands are fixed by the server. User-controlled PIDs are numeric-only and service names are restricted to a narrow character set before any platform command is called.

## Sensitive data

Process command lines and environment variables are intentionally excluded from v0.1 because they commonly contain credentials and tokens.

Command output and errors pass through basic secret redaction before they are returned.

## Reporting a vulnerability

Please use GitHub's private security reporting / Security Advisories for this repository. Do not publish credentials, exploit details, or sensitive host data in a public issue.

## Future execution features

Mutation and remediation are planned only behind explicit enablement, allowlists, risk classification, approval, verification, rollback where practical, and audit logging.
