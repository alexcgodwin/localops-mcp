import { appendFile, chmod, mkdir, readFile } from "node:fs/promises";
import os from "node:os";
import { isAbsolute, join, parse, resolve } from "node:path";
import { databaseProfiles } from "./database.js";
import { backupProfiles } from "./storage-backup.js";

export type LocalOpsRole =
  | "viewer"
  | "operator"
  | "maintainer"
  | "admin";

export type PolicyOperation =
  | "inspect"
  | "analyze"
  | "propose_execution"
  | "execute_r2";

export type RiskTier = "R0" | "R1" | "R2" | "R3+";

export type DurableAuditEvent = {
  id: string;
  timestamp: string;
  operatorId: string;
  role: LocalOpsRole;
  action: string;
  target: string | null;
  riskTier: RiskTier;
  approved: boolean;
  executed: boolean;
  verified: boolean;
  outcome: "success" | "failure";
  workflowId?: string | null;
  workflowStepId?: string | null;
};

const ROLE_PERMISSIONS: Record<LocalOpsRole, PolicyOperation[]> = {
  viewer: ["inspect", "analyze"],
  operator: ["inspect", "analyze", "propose_execution"],
  maintainer: [
    "inspect",
    "analyze",
    "propose_execution",
    "execute_r2"
  ],
  admin: [
    "inspect",
    "analyze",
    "propose_execution",
    "execute_r2"
  ]
};

function boolEnv(name: string): boolean {
  return String(process.env[name] ?? "").toLowerCase() === "true";
}

export function currentRole(): LocalOpsRole {
  const value = String(process.env.LOCALOPS_ROLE ?? "viewer")
    .trim()
    .toLowerCase();
  if (
    value !== "viewer" &&
    value !== "operator" &&
    value !== "maintainer" &&
    value !== "admin"
  ) {
    throw new Error(
      "LOCALOPS_ROLE must be viewer, operator, maintainer, or admin."
    );
  }
  return value;
}

export function currentOperatorId(): string {
  const value = String(
    process.env.LOCALOPS_OPERATOR_ID ?? "local-process"
  ).trim();
  if (!/^[A-Za-z0-9][A-Za-z0-9_.:@ -]{0,127}$/.test(value)) {
    throw new Error(
      "LOCALOPS_OPERATOR_ID contains unsupported characters or is too long."
    );
  }
  return value;
}

export function evaluatePolicy(
  operation: PolicyOperation,
  riskTier: RiskTier
) {
  const role = currentRole();
  const permissions = ROLE_PERMISSIONS[role];
  const allowed =
    riskTier !== "R3+" &&
    permissions.includes(operation);

  let reason = "Allowed by the configured LocalOps role.";
  if (riskTier === "R3+") {
    reason =
      "R3+ execution is not exposed by the LocalOps production policy.";
  } else if (!allowed) {
    reason =
      "The configured LocalOps role does not permit this operation.";
  }

  return {
    allowed,
    role,
    operatorId: currentOperatorId(),
    operation,
    riskTier,
    reason
  };
}

export function requirePolicy(
  operation: PolicyOperation,
  riskTier: RiskTier
) {
  const decision = evaluatePolicy(operation, riskTier);
  if (!decision.allowed) {
    throw new Error(
      "LocalOps policy blocked " +
        operation +
        " for role " +
        decision.role +
        ": " +
        decision.reason
    );
  }
  return decision;
}

export function policyStatus() {
  const role = currentRole();
  return {
    role,
    operatorId: currentOperatorId(),
    enforcement: "enforced" as const,
    permissions: ROLE_PERMISSIONS[role],
    roleMatrix: {
      viewer: ROLE_PERMISSIONS.viewer,
      operator: ROLE_PERMISSIONS.operator,
      maintainer: ROLE_PERMISSIONS.maintainer,
      admin: ROLE_PERMISSIONS.admin
    },
    riskBoundary: {
      R0: "read-only inspection",
      R1: "analysis and evidence aggregation",
      R2: "bounded execution with explicit approval",
      R3Plus: "not exposed"
    },
    identityBoundary:
      "RBAC identity is process-bound configuration for the local stdio MCP process; it is not a remote user-authentication system."
  };
}

export function auditPersistenceEnabled(): boolean {
  return boolEnv("LOCALOPS_AUDIT_PERSISTENCE");
}

export function localOpsDataDirectory(): string {
  const configured = String(process.env.LOCALOPS_DATA_DIR ?? "").trim();
  const candidate = configured
    ? resolve(configured)
    : join(os.homedir(), ".opschugex", "localops");

  if (!isAbsolute(candidate)) {
    throw new Error("LOCALOPS_DATA_DIR must resolve to an absolute path.");
  }

  const root = parse(candidate).root;
  if (resolve(candidate) === resolve(root)) {
    throw new Error("LOCALOPS_DATA_DIR cannot be a filesystem root.");
  }

  return candidate;
}

export function durableAuditPath(): string {
  return join(localOpsDataDirectory(), "execution-audit.jsonl");
}

export async function appendDurableAudit(
  event: DurableAuditEvent
): Promise<void> {
  if (!auditPersistenceEnabled()) return;

  const directory = localOpsDataDirectory();
  const path = durableAuditPath();
  await mkdir(directory, { recursive: true, mode: 0o700 });
  await appendFile(path, JSON.stringify(event) + "\n", {
    encoding: "utf8",
    mode: 0o600
  });

  if (process.platform !== "win32") {
    await chmod(directory, 0o700).catch(() => undefined);
    await chmod(path, 0o600).catch(() => undefined);
  }
}

export async function readDurableAudit(limit = 100) {
  const safeLimit = Math.max(1, Math.min(Math.trunc(limit), 500));
  if (!auditPersistenceEnabled()) {
    return {
      enabled: false,
      records: [] as DurableAuditEvent[],
      path: null,
      limitation:
        "Durable audit persistence is disabled. Set LOCALOPS_AUDIT_PERSISTENCE=true to enable local JSONL audit storage."
    };
  }

  const path = durableAuditPath();
  try {
    const text = await readFile(path, "utf8");
    const records = text
      .split(/\r?\n/)
      .filter(Boolean)
      .slice(-safeLimit)
      .reverse()
      .flatMap((line) => {
        try {
          return [JSON.parse(line) as DurableAuditEvent];
        } catch {
          return [];
        }
      });

    return {
      enabled: true,
      records,
      path,
      limitation: null
    };
  } catch (error: any) {
    if (error?.code === "ENOENT") {
      return {
        enabled: true,
        records: [] as DurableAuditEvent[],
        path,
        limitation: null
      };
    }
    throw error;
  }
}

export function productionReadinessInput() {
  const checks: Array<{
    id: string;
    status: "pass" | "warn" | "fail";
    detail: string;
  }> = [];

  const major = Number(process.versions.node.split(".")[0] ?? 0);
  checks.push({
    id: "node-version",
    status: major >= 20 ? "pass" : "fail",
    detail:
      major >= 20
        ? "Node.js 20+ requirement is satisfied."
        : "Node.js 20 or newer is required."
  });

  let role: LocalOpsRole | null = null;
  try {
    role = currentRole();
    checks.push({
      id: "rbac-role",
      status: "pass",
      detail: "Process-bound RBAC role is " + role + "."
    });
  } catch (error) {
    checks.push({
      id: "rbac-role",
      status: "fail",
      detail: error instanceof Error ? error.message : String(error)
    });
  }

  const executionEnabled = boolEnv("LOCALOPS_EXECUTION_ENABLED");
  const durable = auditPersistenceEnabled();

  checks.push({
    id: "execution-default",
    status: executionEnabled ? "warn" : "pass",
    detail: executionEnabled
      ? "Controlled execution is enabled and still requires allowlisting plus one-time approval."
      : "Controlled execution is disabled."
  });

  checks.push({
    id: "durable-audit",
    status:
      executionEnabled && !durable
        ? "fail"
        : durable
          ? "pass"
          : "warn",
    detail:
      executionEnabled && !durable
        ? "Production execution is enabled without durable audit persistence."
        : durable
          ? "Durable local JSONL execution audit is enabled."
          : "Durable audit is disabled; acceptable for read-only use but recommended for production operations."
  });

  try {
    localOpsDataDirectory();
    checks.push({
      id: "data-directory",
      status: "pass",
      detail: "LocalOps data directory resolves to a non-root absolute path."
    });
  } catch (error) {
    checks.push({
      id: "data-directory",
      status: "fail",
      detail: error instanceof Error ? error.message : String(error)
    });
  }

  const incidentPersistence = boolEnv("LOCALOPS_INCIDENT_PERSISTENCE");
  checks.push({
    id: "incident-persistence",
    status: incidentPersistence ? "pass" : "warn",
    detail: incidentPersistence
      ? "Durable normalized incident memory is enabled with a 200-case bound under the LocalOps data directory."
      : "Durable incident memory is disabled; incident cases will be process-local only."
  });

  const investigationPersistence = boolEnv(
    "LOCALOPS_INVESTIGATION_PERSISTENCE"
  );
  checks.push({
    id: "investigation-persistence",
    status: investigationPersistence ? "pass" : "warn",
    detail: investigationPersistence
      ? "Durable investigation-session metadata is enabled with a 50-session bound under the LocalOps data directory."
      : "Durable investigation-session persistence is disabled; sessions will be process-local only."
  });

  try {
    const profiles = databaseProfiles();
    checks.push({
      id: "database-profiles",
      status: profiles.length > 0 ? "pass" : "warn",
      detail:
        profiles.length > 0
          ? profiles.length +
            " database profile(s) parsed successfully without embedding credentials in MCP configuration."
          : "No database profiles are configured; v1.1 database tools remain unavailable until LOCALOPS_DATABASE_PROFILES is configured."
    });
  } catch (error) {
    checks.push({
      id: "database-profiles",
      status: "fail",
      detail:
        error instanceof Error
          ? error.message
          : String(error)
    });
  }

  try {
    const profiles = backupProfiles();
    checks.push({
      id: "backup-profiles",
      status: profiles.length > 0 ? "pass" : "warn",
      detail:
        profiles.length > 0
          ? profiles.length +
            " backup profile(s) parsed successfully with named local roots and no MCP-supplied arbitrary paths."
          : "No backup profiles are configured; v1.2 backup tools remain unavailable until LOCALOPS_BACKUP_PROFILES is configured."
    });
  } catch (error) {
    checks.push({
      id: "backup-profiles",
      status: "fail",
      detail:
        error instanceof Error
          ? error.message
          : String(error)
    });
  }

  if (
    executionEnabled &&
    role !== null &&
    role !== "maintainer" &&
    role !== "admin"
  ) {
    checks.push({
      id: "execution-role",
      status: "warn",
      detail:
        "Execution is enabled, but the configured role cannot execute R2 actions."
    });
  } else {
    checks.push({
      id: "execution-role",
      status: "pass",
      detail:
        "Execution enablement and RBAC role do not create an unauthorized R2 execution path."
    });
  }

  return checks;
}
