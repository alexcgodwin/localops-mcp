# Security Policy

## v0.2 security boundary

OpsChugex LocalOps MCP v0.2 is read-only.

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

Process command lines remain excluded because they commonly contain credentials and tokens.

Endpoint inventory in v0.2 follows additional minimization rules:

- environment-variable names may be returned, but values are never returned
- SSH key files are inventoried by metadata only; key contents are not read
- scheduled-task action commands are not returned
- startup command lines are not returned
- certificate metadata may report whether a private key exists, but private key material is never read or returned
- software-change detection uses a caller-supplied baseline and does not persist inventory locally

Command output and errors pass through basic secret redaction before they are returned.

## Reporting a vulnerability

Please use GitHub's private security reporting / Security Advisories for this repository. Do not publish credentials, exploit details, or sensitive host data in a public issue.

## Future execution features

Mutation and remediation are planned only behind explicit enablement, allowlists, risk classification, approval, verification, rollback where practical, and audit logging.
