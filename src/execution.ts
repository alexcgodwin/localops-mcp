import { randomBytes } from "node:crypto";
import { readdir, stat, unlink } from "node:fs/promises";
import os from "node:os";
import { join, resolve } from "node:path";
import { CommandRunner, defaultCommandRunner } from "./command.js";
import { serviceStatus } from "./system.js";

type Platform = NodeJS.Platform;

export type ControlledAction =
  | "start_service"
  | "restart_service"
  | "refresh_dns"
  | "clean_temp_files";

type ApprovalRecord = {
  token: string;
  action: ControlledAction;
  target: string | null;
  parameters: Record<string, unknown>;
  createdAt: string;
  expiresAt: string;
  consumed: boolean;
};

export type AuditRecord = {
  id: string;
  timestamp: string;
  action: ControlledAction;
  target: string | null;
  riskTier: "R2";
  approved: boolean;
  executed: boolean;
  verified: boolean;
  result: string;
  rollback: string;
};

const approvals = new Map<string, ApprovalRecord>();
const auditRecords: AuditRecord[] = [];

const APPROVAL_TTL_MS = 5 * 60 * 1000;
const MAX_AUDIT_RECORDS = 200;

function isExecutionEnabled(): boolean {
  return String(process.env.LOCALOPS_EXECUTION_ENABLED ?? "").toLowerCase() === "true";
}

function allowedServices(): Set<string> {
  return new Set(
    String(process.env.LOCALOPS_ALLOWED_SERVICES ?? "")
      .split(",")
      .map((value) => value.trim().toLowerCase())
      .filter(Boolean)
  );
}

function safeServiceName(name: string): string {
  const value = name.trim();
  if (!/^[A-Za-z0-9_.@:-]{1,128}$/.test(value)) {
    throw new Error("serviceName contains unsupported characters.");
  }
  return value;
}

function serviceIsAllowed(name: string): boolean {
  return allowedServices().has(name.toLowerCase());
}

function approvalToken(): string {
  return randomBytes(24).toString("hex");
}

function auditId(): string {
  return randomBytes(12).toString("hex");
}

function cleanupExpiredApprovals(now = Date.now()): void {
  for (const [token, approval] of approvals) {
    if (approval.consumed || new Date(approval.expiresAt).getTime() <= now) {
      approvals.delete(token);
    }
  }
}

function addAudit(record: AuditRecord): AuditRecord {
  auditRecords.unshift(record);
  if (auditRecords.length > MAX_AUDIT_RECORDS) {
    auditRecords.splice(MAX_AUDIT_RECORDS);
  }
  return record;
}

function actionRollback(action: ControlledAction, target: string | null): string {
  if (action === "start_service") {
    return target
      ? "If starting the service caused an issue, stop it using an administrator-approved operating-system procedure."
      : "Stop the service using an administrator-approved operating-system procedure.";
  }
  if (action === "restart_service") {
    return "A restart cannot be automatically reversed. Verify the service and dependent applications; use the service's documented recovery procedure if needed.";
  }
  if (action === "refresh_dns") {
    return "DNS cache flush is not reversible. The cache will repopulate from configured resolvers.";
  }
  return "Deleted temporary files cannot be restored automatically. Only bounded old regular files from the operating-system temporary directory are eligible.";
}

export function executionStatus() {
  return {
    enabled: isExecutionEnabled(),
    approvalTtlSeconds: APPROVAL_TTL_MS / 1000,
    allowedServices: [...allowedServices()].sort(),
    supportedActions: [
      "start_service",
      "restart_service",
      "refresh_dns",
      "clean_temp_files"
    ] as ControlledAction[],
    defaultPolicy:
      "Execution is disabled unless LOCALOPS_EXECUTION_ENABLED=true. Service actions additionally require the exact service name in LOCALOPS_ALLOWED_SERVICES.",
    riskModel: {
      R0: "read-only local inspection",
      R1: "analysis and evidence aggregation",
      R2: "bounded reversible-or-low-impact execution with explicit approval",
      R3Plus: "not exposed in v0.5"
    }
  };
}

export async function proposeExecution(
  input: {
    action: ControlledAction;
    serviceName?: string;
    olderThanHours?: number;
    maxFiles?: number;
  },
  runner: CommandRunner = defaultCommandRunner,
  platform: Platform = process.platform
) {
  cleanupExpiredApprovals();

  if (!isExecutionEnabled()) {
    throw new Error(
      "Controlled execution is disabled. Set LOCALOPS_EXECUTION_ENABLED=true before requesting an execution proposal."
    );
  }

  let target: string | null = null;
  const parameters: Record<string, unknown> = {};
  const preflight: Record<string, unknown> = {};

  if (input.action === "start_service" || input.action === "restart_service") {
    const serviceName = safeServiceName(input.serviceName ?? "");
    if (!serviceIsAllowed(serviceName)) {
      throw new Error(
        "Service is not allowlisted. Add the exact service name to LOCALOPS_ALLOWED_SERVICES before proposing this action."
      );
    }
    target = serviceName;
    preflight.service = await serviceStatus(serviceName, runner, platform);
  }

  if (input.action === "clean_temp_files") {
    const olderThanHours = Math.max(24, Math.min(Math.trunc(input.olderThanHours ?? 168), 24 * 90));
    const maxFiles = Math.max(1, Math.min(Math.trunc(input.maxFiles ?? 50), 200));
    parameters.olderThanHours = olderThanHours;
    parameters.maxFiles = maxFiles;
    preflight.tempDirectory = os.tmpdir();
    preflight.scope = "regular files only; directories and symbolic links are excluded";
  }

  if (input.action === "refresh_dns") {
    preflight.scope =
      platform === "win32"
        ? "Windows DNS resolver cache only"
        : "systemd-resolved DNS cache where available";
  }

  const token = approvalToken();
  const createdAt = new Date();
  const expiresAt = new Date(createdAt.getTime() + APPROVAL_TTL_MS);

  const approval: ApprovalRecord = {
    token,
    action: input.action,
    target,
    parameters,
    createdAt: createdAt.toISOString(),
    expiresAt: expiresAt.toISOString(),
    consumed: false
  };
  approvals.set(token, approval);

  return {
    proposalId: token.slice(0, 12),
    approvalToken: token,
    action: input.action,
    target,
    riskTier: "R2" as const,
    preflight,
    parameters,
    expiresAt: approval.expiresAt,
    confirmationRequired: "APPROVE",
    rollback: actionRollback(input.action, target),
    warning:
      "Execution requires a separate tool call with this one-time token and confirmation='APPROVE'. The token expires after five minutes."
  };
}

async function executeServiceAction(
  action: "start_service" | "restart_service",
  serviceName: string,
  runner: CommandRunner,
  platform: Platform
) {
  if (platform === "win32") {
    const verb = action === "start_service" ? "Start-Service" : "Restart-Service";
    const script =
      verb +
      " -Name '" +
      serviceName +
      "' -ErrorAction Stop; " +
      "Get-Service -Name '" +
      serviceName +
      "' | Select-Object Name,Status | ConvertTo-Json -Compress";
    const result = await runner(
      "powershell.exe",
      ["-NoProfile", "-NonInteractive", "-Command", script]
    );
    return {
      command: verb,
      output: result.stdout
    };
  }

  const systemctlAction = action === "start_service" ? "start" : "restart";
  await runner("systemctl", [systemctlAction, serviceName]);
  const verify = await runner(
    "systemctl",
    ["show", serviceName, "--property=ActiveState,SubState", "--no-pager"]
  );
  return {
    command: "systemctl " + systemctlAction,
    output: verify.stdout
  };
}

async function executeDnsRefresh(
  runner: CommandRunner,
  platform: Platform
) {
  if (platform === "win32") {
    const result = await runner("ipconfig.exe", ["/flushdns"]);
    return {
      command: "ipconfig /flushdns",
      output: result.stdout
    };
  }

  const resolvectl = await runner("resolvectl", ["flush-caches"], true);
  if (resolvectl.exitCode === 0) {
    return { command: "resolvectl flush-caches", output: resolvectl.stdout };
  }

  const fallback = await runner("systemd-resolve", ["--flush-caches"], true);
  if (fallback.exitCode === 0) {
    return {
      command: "systemd-resolve --flush-caches",
      output: fallback.stdout
    };
  }

  throw new Error(
    "No supported Linux DNS-cache refresh command succeeded. LocalOps did not attempt any broader network mutation."
  );
}

async function executeTempCleanup(
  parameters: Record<string, unknown>
) {
  const olderThanHours = Number(parameters.olderThanHours ?? 168);
  const maxFiles = Number(parameters.maxFiles ?? 50);
  const directory = resolve(os.tmpdir());
  const cutoff = Date.now() - olderThanHours * 60 * 60 * 1000;
  const deleted: Array<{ name: string; sizeBytes: number }> = [];
  let scanned = 0;

  const entries = await readdir(directory, { withFileTypes: true });
  for (const entry of entries) {
    if (deleted.length >= maxFiles) break;
    if (!entry.isFile() || entry.isSymbolicLink()) continue;

    const fullPath = resolve(join(directory, entry.name));
    if (fullPath === directory || !fullPath.startsWith(directory + "\\") && !fullPath.startsWith(directory + "/")) {
      continue;
    }

    scanned += 1;
    try {
      const info = await stat(fullPath);
      if (!info.isFile() || info.mtimeMs > cutoff) continue;
      await unlink(fullPath);
      deleted.push({ name: entry.name, sizeBytes: info.size });
    } catch {
      // Files that become locked or disappear are skipped.
    }
  }

  return {
    command: "bounded temp-file cleanup",
    directory,
    scanned,
    deletedCount: deleted.length,
    deleted
  };
}

export async function executeApprovedAction(
  input: {
    approvalToken: string;
    confirmation: string;
  },
  runner: CommandRunner = defaultCommandRunner,
  platform: Platform = process.platform
) {
  cleanupExpiredApprovals();

  if (!isExecutionEnabled()) {
    throw new Error("Controlled execution is disabled.");
  }
  if (input.confirmation !== "APPROVE") {
    throw new Error("confirmation must exactly equal APPROVE.");
  }

  const approval = approvals.get(input.approvalToken);
  if (!approval) {
    throw new Error("Approval token is invalid, expired, or already consumed.");
  }
  if (approval.consumed) {
    throw new Error("Approval token has already been consumed.");
  }
  if (new Date(approval.expiresAt).getTime() <= Date.now()) {
    approvals.delete(input.approvalToken);
    throw new Error("Approval token has expired.");
  }

  if (
    (approval.action === "start_service" || approval.action === "restart_service") &&
    approval.target &&
    !serviceIsAllowed(approval.target)
  ) {
    throw new Error("Service is no longer allowlisted. Execution was blocked.");
  }

  approval.consumed = true;
  approvals.delete(input.approvalToken);

  let result: unknown;
  let verified = false;
  let executionAttempted = false;

  try {
    executionAttempted = true;
    if (approval.action === "start_service" || approval.action === "restart_service") {
      if (!approval.target) throw new Error("Approved service target is missing.");
      result = await executeServiceAction(
        approval.action,
        approval.target,
        runner,
        platform
      );
      const verification = await serviceStatus(approval.target, runner, platform);
      const state = String(
        (verification as any).status ??
          (verification as any).activeState ??
          ""
      ).toLowerCase();
      verified = state === "running" || state === "active";
      result = { execution: result, verification };
    } else if (approval.action === "refresh_dns") {
      result = await executeDnsRefresh(runner, platform);
      verified = true;
    } else {
      result = await executeTempCleanup(approval.parameters);
      verified = true;
    }

    const audit = addAudit({
      id: auditId(),
      timestamp: new Date().toISOString(),
      action: approval.action,
      target: approval.target,
      riskTier: "R2",
      approved: true,
      executed: true,
      verified,
      result: JSON.stringify(result).slice(0, 2000),
      rollback: actionRollback(approval.action, approval.target)
    });

    return {
      action: approval.action,
      target: approval.target,
      approved: true,
      executed: true,
      verified,
      result,
      rollback: audit.rollback,
      auditId: audit.id
    };
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    const audit = addAudit({
      id: auditId(),
      timestamp: new Date().toISOString(),
      action: approval.action,
      target: approval.target,
      riskTier: "R2",
      approved: true,
      executed: executionAttempted,
      verified: false,
      result: message.slice(0, 2000),
      rollback: actionRollback(approval.action, approval.target)
    });
    throw new Error("Approved action failed: " + message + " | auditId=" + audit.id);
  }
}

export function recentExecutionAudit(limit = 50) {
  const safeLimit = Math.max(1, Math.min(Math.trunc(limit), 200));
  return {
    records: auditRecords.slice(0, safeLimit),
    persistence:
      "v0.5 audit records are in-memory only and are cleared when the LocalOps process exits."
  };
}
