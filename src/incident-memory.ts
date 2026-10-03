import { randomUUID } from "node:crypto";

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

export type IncidentCaseRecord = {
  caseId: string;
  recordedAt: string;
  title: string | null;
  fingerprint: IncidentFingerprint;
};

const cases: IncidentCaseRecord[] = [];
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

export function recordIncidentCase(
  fingerprint: unknown,
  title?: string
): IncidentCaseRecord {
  const validated = validateFingerprint(fingerprint);
  const incident: IncidentCaseRecord = {
    caseId: "inc_" + randomUUID(),
    recordedAt: new Date().toISOString(),
    title: safeTitle(title),
    fingerprint: validated
  };
  cases.push(incident);
  if (cases.length > MAX_CASES) {
    cases.splice(0, cases.length - MAX_CASES);
  }
  return incident;
}
export function listIncidentCases(limit = 50) {
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
      signalCount: incident.fingerprint.signalIds.length
    })),
    persistence:
      "v1.7 incident memory is bounded to 200 normalized in-memory cases and is cleared when the LocalOps process exits."
  };
}

export function incidentCaseDetails(caseId: string): IncidentCaseRecord {
  const safe = safeCaseId(caseId);
  const incident = cases.find((item) => item.caseId === safe);
  if (!incident) throw new Error("Incident case is not stored.");
  return incident;
}

export function incidentMemoryBundle(caseIds?: string[]) {
  const selected =
    caseIds === undefined
      ? [...cases]
      : caseIds.map((caseId) => incidentCaseDetails(caseId));

  if (selected.length > MAX_CASES) {
    throw new Error("Incident memory request exceeds 200 cases.");
  }
  return {
    generatedAt: new Date().toISOString(),
    cases: selected
  };
}

export function incidentMemoryCount(): number {
  return cases.length;
}

export function clearIncidentMemoryForTests() {
  cases.splice(0, cases.length);
}
