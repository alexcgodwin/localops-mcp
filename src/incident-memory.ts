import { randomUUID } from "node:crypto";
import { currentOperatorId } from "./platform.js";
import {
  incidentMemoryPath,
  incidentPersistenceEnabled,
  readPersistedIncidentCases,
  writePersistedIncidentCases
} from "./incident-persistence.js";

const MAX_CASES = 200;

export type IncidentFingerprint = {
  engineVersion: "1.7.0";
  generatedAt: string;
  sourceGeneratedAt: string;
  signature: string;
  severity: "none" | "low" | "medium" | "high";
  scope: "none" | "localized" | "multi-node" | "fleet-wide";
  nodeCount: number;
  affectedNodeIds: string[];
  signalIds: string[];
  signalCategories: string[];
  commonAffectedTags: string[];
  causeCategories: string[];
  fingerprintTokens: string[];
  interpretation: string;
  limitations: string[];
};

export type IncidentOutcomeStatus =
  | "resolved"
  | "mitigated"
  | "unresolved"
  | "false-positive";

export type IncidentResolutionCategory =
  | "service-recovery"
  | "resource-relief"
  | "configuration-correction"
  | "dependency-recovery"
  | "security-response"
  | "rollback"
  | "other";

export type IncidentOutcome = {
  status: IncidentOutcomeStatus;
  resolutionCategory: IncidentResolutionCategory;
  verified: boolean;
  durationMinutes: number | null;
  recordedAt: string;
  operatorId: string;
};

export type IncidentCaseRecord = {
  caseId: string;
  recordedAt: string;
  title: string | null;
  fingerprint: IncidentFingerprint;
  outcome: IncidentOutcome | null;
};

const cases: IncidentCaseRecord[] = [];
let loaded = false;
function safeCaseId(value: string): string {
  const caseId = value.trim();
  if (!/^inc_[A-Za-z0-9_-]{1,80}$/.test(caseId)) {
    throw new Error("Invalid incident case ID.");
  }
  return caseId;
}

function safeTitle(value: string | undefined): string | null {
  if (value === undefined) return null;
  const title = value.trim();
  if (!title) return null;
  return title.slice(0, 200);
}

function safeLimit(value: number | undefined, fallback = 50): number {
  const number = Number.isInteger(value) ? Number(value) : fallback;
  return Math.max(1, Math.min(number, MAX_CASES));
}

function assertStringArray(
  value: unknown,
  max: number,
  label: string
): asserts value is string[] {
  if (
    !Array.isArray(value) ||
    value.length > max ||
    !value.every((item) => typeof item === "string")
  ) {
    throw new Error("Invalid incident fingerprint " + label + ".");
  }
}

function validateFingerprint(value: unknown): IncidentFingerprint {
  if (!value || typeof value !== "object") {
    throw new Error("Invalid incident fingerprint.");
  }
  const item = value as Partial<IncidentFingerprint>;
  if (
    item.engineVersion !== "1.7.0" ||
    typeof item.generatedAt !== "string" ||
    !Number.isFinite(new Date(item.generatedAt).getTime()) ||
    typeof item.sourceGeneratedAt !== "string" ||
    !Number.isFinite(new Date(item.sourceGeneratedAt).getTime()) ||
    typeof item.signature !== "string" ||
    !/^[a-f0-9]{24}$/.test(item.signature) ||
    !["none", "low", "medium", "high"].includes(String(item.severity)) ||
    !["none", "localized", "multi-node", "fleet-wide"].includes(String(item.scope)) ||
    typeof item.nodeCount !== "number" ||
    !Number.isInteger(item.nodeCount) ||
    item.nodeCount < 0 ||
    item.nodeCount > 500 ||
    typeof item.interpretation !== "string"
  ) {
    throw new Error("Invalid incident fingerprint metadata.");
  }

  assertStringArray(item.affectedNodeIds, 500, "affected nodes");
  assertStringArray(item.signalIds, 100, "signals");
  assertStringArray(item.signalCategories, 20, "signal categories");
  assertStringArray(item.commonAffectedTags, 20, "tags");
  assertStringArray(item.causeCategories, 20, "cause categories");
  assertStringArray(item.fingerprintTokens, 200, "tokens");
  assertStringArray(item.limitations, 100, "limitations");
  return {
    engineVersion: "1.7.0",
    generatedAt: item.generatedAt,
    sourceGeneratedAt: item.sourceGeneratedAt,
    signature: item.signature,
    severity: item.severity as IncidentFingerprint["severity"],
    scope: item.scope as IncidentFingerprint["scope"],
    nodeCount: item.nodeCount,
    affectedNodeIds: [...item.affectedNodeIds],
    signalIds: [...item.signalIds],
    signalCategories: [...item.signalCategories],
    commonAffectedTags: [...item.commonAffectedTags],
    causeCategories: [...item.causeCategories],
    fingerprintTokens: [...item.fingerprintTokens],
    interpretation: item.interpretation,
    limitations: [...item.limitations]
  };
}

function validateOutcome(value: unknown): IncidentOutcome | null {
  if (value === null || value === undefined) return null;
  if (!value || typeof value !== "object") {
    throw new Error("Invalid incident outcome.");
  }
  const item = value as Partial<IncidentOutcome>;
  if (
    !["resolved", "mitigated", "unresolved", "false-positive"].includes(
      String(item.status)
    ) ||
    ![
      "service-recovery",
      "resource-relief",
      "configuration-correction",
      "dependency-recovery",
      "security-response",
      "rollback",
      "other"
    ].includes(String(item.resolutionCategory)) ||
    typeof item.verified !== "boolean" ||
    !(
      item.durationMinutes === null ||
      (
        typeof item.durationMinutes === "number" &&
        Number.isInteger(item.durationMinutes) &&
        item.durationMinutes >= 0 &&
        item.durationMinutes <= 43200
      )
    ) ||
    typeof item.recordedAt !== "string" ||
    !Number.isFinite(new Date(item.recordedAt).getTime()) ||
    typeof item.operatorId !== "string" ||
    !/^[A-Za-z0-9][A-Za-z0-9_.:@ -]{0,127}$/.test(item.operatorId)
  ) {
    throw new Error("Invalid incident outcome metadata.");
  }

  return {
    status: item.status as IncidentOutcomeStatus,
    resolutionCategory:
      item.resolutionCategory as IncidentResolutionCategory,
    verified: item.verified,
    durationMinutes: item.durationMinutes,
    recordedAt: item.recordedAt,
    operatorId: item.operatorId
  };
}
function validateStoredCase(value: unknown): IncidentCaseRecord {
  if (!value || typeof value !== "object") {
    throw new Error("Invalid stored incident case.");
  }
  const item = value as Partial<IncidentCaseRecord>;
  if (
    typeof item.caseId !== "string" ||
    !/^inc_[A-Za-z0-9_-]{1,80}$/.test(item.caseId) ||
    typeof item.recordedAt !== "string" ||
    !Number.isFinite(new Date(item.recordedAt).getTime()) ||
    !(
      item.title === null ||
      (typeof item.title === "string" && item.title.length <= 200)
    )
  ) {
    throw new Error("Invalid stored incident case metadata.");
  }
  return {
    caseId: item.caseId,
    recordedAt: item.recordedAt,
    title: item.title ?? null,
    fingerprint: validateFingerprint(item.fingerprint),
    outcome: validateOutcome(item.outcome)
  };
}

async function ensureLoaded(): Promise<void> {
  if (loaded) return;
  const persisted = await readPersistedIncidentCases();
  cases.splice(
    0,
    cases.length,
    ...persisted.map(validateStoredCase).slice(-MAX_CASES)
  );
  loaded = true;
}

async function persist(): Promise<void> {
  await writePersistedIncidentCases(cases);
}

export async function recordIncidentCase(
  fingerprint: unknown,
  title?: string
): Promise<IncidentCaseRecord> {
  await ensureLoaded();
  const incident: IncidentCaseRecord = {
    caseId: "inc_" + randomUUID(),
    recordedAt: new Date().toISOString(),
    title: safeTitle(title),
    fingerprint: validateFingerprint(fingerprint),
    outcome: null
  };
  cases.push(incident);
  if (cases.length > MAX_CASES) {
    cases.splice(0, cases.length - MAX_CASES);
  }
  await persist();
  return incident;
}
export async function recordIncidentOutcome(
  caseId: string,
  input: {
    status: IncidentOutcomeStatus;
    resolutionCategory: IncidentResolutionCategory;
    verified: boolean;
    durationMinutes?: number;
  }
): Promise<IncidentCaseRecord> {
  await ensureLoaded();
  const incident = await incidentCaseDetails(caseId);
  const durationMinutes =
    input.durationMinutes === undefined ? null : input.durationMinutes;
  if (
    durationMinutes !== null &&
    (
      !Number.isInteger(durationMinutes) ||
      durationMinutes < 0 ||
      durationMinutes > 43200
    )
  ) {
    throw new Error("durationMinutes must be an integer from 0 to 43200.");
  }

  incident.outcome = validateOutcome({
    status: input.status,
    resolutionCategory: input.resolutionCategory,
    verified: input.verified,
    durationMinutes,
    recordedAt: new Date().toISOString(),
    operatorId: currentOperatorId()
  });
  await persist();
  return incident;
}

export async function listIncidentCases(limit = 50) {
  await ensureLoaded();
  const safe = safeLimit(limit);
  return {
    caseCount: cases.length,
    cases: cases.slice(-safe).reverse().map((incident) => ({
      caseId: incident.caseId,
      recordedAt: incident.recordedAt,
      title: incident.title,
      signature: incident.fingerprint.signature,
      severity: incident.fingerprint.severity,
      scope: incident.fingerprint.scope,
      nodeCount: incident.fingerprint.nodeCount,
      affectedNodeCount: incident.fingerprint.affectedNodeIds.length,
      signalCount: incident.fingerprint.signalIds.length,
      outcomeStatus: incident.outcome?.status ?? null,
      outcomeVerified: incident.outcome?.verified ?? null
    })),
    persistence: incidentPersistenceEnabled()
      ? "v1.8 incident memory is persisted locally with a 200-case bound."
      : "Incident persistence is disabled; cases remain in memory until the LocalOps process exits."
  };
}
export async function incidentCaseDetails(
  caseId: string
): Promise<IncidentCaseRecord> {
  await ensureLoaded();
  const safe = safeCaseId(caseId);
  const incident = cases.find((item) => item.caseId === safe);
  if (!incident) throw new Error("Incident case is not stored.");
  return incident;
}

export async function incidentMemoryBundle(caseIds?: string[]) {
  await ensureLoaded();
  const selected =
    caseIds === undefined
      ? [...cases]
      : await Promise.all(
          caseIds.map((caseId) => incidentCaseDetails(caseId))
        );

  if (selected.length > MAX_CASES) {
    throw new Error("Incident memory request exceeds 200 cases.");
  }
  return {
    generatedAt: new Date().toISOString(),
    cases: selected
  };
}

export async function incidentMemoryStatus() {
  await ensureLoaded();
  return {
    version: "1.8.0" as const,
    persistenceEnabled: incidentPersistenceEnabled(),
    persistencePath: incidentPersistenceEnabled()
      ? incidentMemoryPath()
      : null,
    caseCount: cases.length,
    outcomeCount: cases.filter((incident) => incident.outcome !== null).length,
    maxCases: MAX_CASES,
    storage:
      "Normalized incident metadata only; no raw event logs, packet data, credentials, command output or approval tokens."
  };
}

export async function incidentMemoryCount(): Promise<number> {
  await ensureLoaded();
  return cases.length;
}

export function clearIncidentMemoryForTests() {
  cases.splice(0, cases.length);
  loaded = false;
}
