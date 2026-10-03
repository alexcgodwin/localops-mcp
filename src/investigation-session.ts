import { randomUUID } from "node:crypto";
import { currentOperatorId } from "./platform.js";
import {
  investigationPersistenceEnabled,
  investigationSessionsPath,
  readPersistedInvestigationSessions,
  writePersistedInvestigationSessions
} from "./investigation-persistence.js";
import { incidentCaseDetails } from "./incident-memory.js";

const MAX_SESSIONS = 50;
const MAX_CHECKPOINTS = 100;
const MAX_QUESTIONS = 50;
const MAX_EVIDENCE_REFS = 20;

export type InvestigationSessionStatus =
  | "open"
  | "paused"
  | "completed";

export type InvestigationCheckpointKind =
  | "evidence-reviewed"
  | "scope-reviewed"
  | "hypothesis-reviewed"
  | "historical-case-reviewed"
  | "question-reviewed";

export type InvestigationQuestionCategory =
  | "scope"
  | "signal"
  | "cause"
  | "historical"
  | "verification"
  | "other";

export type InvestigationQuestionStatus =
  | "open"
  | "resolved"
  | "deferred";

export type InvestigationCheckpoint = {
  checkpointId: string;
  recordedAt: string;
  operatorId: string;
  kind: InvestigationCheckpointKind;
  evidenceRefs: string[];
};

export type InvestigationQuestion = {
  questionId: string;
  category: InvestigationQuestionCategory;
  prompt: string;
  status: InvestigationQuestionStatus;
  createdAt: string;
  updatedAt: string;
  operatorId: string;
};

export type InvestigationSessionRecord = {
  sessionId: string;
  caseId: string;
  title: string | null;
  status: InvestigationSessionStatus;
  createdAt: string;
  updatedAt: string;
  operatorId: string;
  checkpoints: InvestigationCheckpoint[];
  questions: InvestigationQuestion[];
};

const sessions: InvestigationSessionRecord[] = [];
let loaded = false;
function safeSessionId(value: string): string {
  const sessionId = value.trim();
  if (!/^inv_[A-Za-z0-9_-]{1,80}$/.test(sessionId)) {
    throw new Error("Invalid investigation session ID.");
  }
  return sessionId;
}

function safeQuestionId(value: string): string {
  const questionId = value.trim();
  if (!/^q_[A-Za-z0-9_-]{1,80}$/.test(questionId)) {
    throw new Error("Invalid investigation question ID.");
  }
  return questionId;
}

function safeTitle(value: string | undefined): string | null {
  if (value === undefined) return null;
  const title = value.replace(/\s+/g, " ").trim();
  if (!title) return null;
  return title.slice(0, 200);
}

function safePrompt(value: string): string {
  const prompt = value.replace(/\s+/g, " ").trim();
  if (!prompt) {
    throw new Error("Investigation question prompt is required.");
  }
  if (prompt.length > 240) {
    throw new Error("Investigation question prompt exceeds 240 characters.");
  }
  return prompt;
}

function safeEvidenceRefs(values: string[]): string[] {
  if (!Array.isArray(values) || values.length > MAX_EVIDENCE_REFS) {
    throw new Error("An investigation checkpoint supports at most 20 evidence references.");
  }
  const normalized = values.map((value) => value.trim()).filter(Boolean);
  if (
    !normalized.every(
      (value) =>
        value.length <= 128 &&
        /^[A-Za-z0-9][A-Za-z0-9_.:/@ -]{0,127}$/.test(value)
    )
  ) {
    throw new Error("Investigation evidence references contain unsupported characters.");
  }
  return [...new Set(normalized)];
}

function safeLimit(value: number | undefined, fallback = 25): number {
  const limit = Number.isInteger(value) ? Number(value) : fallback;
  return Math.max(1, Math.min(limit, MAX_SESSIONS));
}
function validateCheckpoint(value: unknown): InvestigationCheckpoint {
  if (!value || typeof value !== "object") {
    throw new Error("Invalid investigation checkpoint.");
  }
  const item = value as Partial<InvestigationCheckpoint>;
  if (
    typeof item.checkpointId !== "string" ||
    !/^chk_[A-Za-z0-9_-]{1,80}$/.test(item.checkpointId) ||
    typeof item.recordedAt !== "string" ||
    !Number.isFinite(new Date(item.recordedAt).getTime()) ||
    typeof item.operatorId !== "string" ||
    !/^[A-Za-z0-9][A-Za-z0-9_.:@ -]{0,127}$/.test(item.operatorId) ||
    ![
      "evidence-reviewed",
      "scope-reviewed",
      "hypothesis-reviewed",
      "historical-case-reviewed",
      "question-reviewed"
    ].includes(String(item.kind)) ||
    !Array.isArray(item.evidenceRefs)
  ) {
    throw new Error("Invalid investigation checkpoint metadata.");
  }
  return {
    checkpointId: item.checkpointId,
    recordedAt: item.recordedAt,
    operatorId: item.operatorId,
    kind: item.kind as InvestigationCheckpointKind,
    evidenceRefs: safeEvidenceRefs(item.evidenceRefs)
  };
}

function validateQuestion(value: unknown): InvestigationQuestion {
  if (!value || typeof value !== "object") {
    throw new Error("Invalid investigation question.");
  }
  const item = value as Partial<InvestigationQuestion>;
  if (
    typeof item.questionId !== "string" ||
    !/^q_[A-Za-z0-9_-]{1,80}$/.test(item.questionId) ||
    !["scope", "signal", "cause", "historical", "verification", "other"].includes(
      String(item.category)
    ) ||
    typeof item.prompt !== "string" ||
    !["open", "resolved", "deferred"].includes(String(item.status)) ||
    typeof item.createdAt !== "string" ||
    !Number.isFinite(new Date(item.createdAt).getTime()) ||
    typeof item.updatedAt !== "string" ||
    !Number.isFinite(new Date(item.updatedAt).getTime()) ||
    typeof item.operatorId !== "string" ||
    !/^[A-Za-z0-9][A-Za-z0-9_.:@ -]{0,127}$/.test(item.operatorId)
  ) {
    throw new Error("Invalid investigation question metadata.");
  }
  return {
    questionId: item.questionId,
    category: item.category as InvestigationQuestionCategory,
    prompt: safePrompt(item.prompt),
    status: item.status as InvestigationQuestionStatus,
    createdAt: item.createdAt,
    updatedAt: item.updatedAt,
    operatorId: item.operatorId
  };
}
function validateStoredSession(value: unknown): InvestigationSessionRecord {
  if (!value || typeof value !== "object") {
    throw new Error("Invalid stored investigation session.");
  }
  const item = value as Partial<InvestigationSessionRecord>;
  if (
    typeof item.sessionId !== "string" ||
    !/^inv_[A-Za-z0-9_-]{1,80}$/.test(item.sessionId) ||
    typeof item.caseId !== "string" ||
    !/^inc_[A-Za-z0-9_-]{1,80}$/.test(item.caseId) ||
    !["open", "paused", "completed"].includes(String(item.status)) ||
    typeof item.createdAt !== "string" ||
    !Number.isFinite(new Date(item.createdAt).getTime()) ||
    typeof item.updatedAt !== "string" ||
    !Number.isFinite(new Date(item.updatedAt).getTime()) ||
    typeof item.operatorId !== "string" ||
    !/^[A-Za-z0-9][A-Za-z0-9_.:@ -]{0,127}$/.test(item.operatorId) ||
    !Array.isArray(item.checkpoints) ||
    item.checkpoints.length > MAX_CHECKPOINTS ||
    !Array.isArray(item.questions) ||
    item.questions.length > MAX_QUESTIONS
  ) {
    throw new Error("Invalid stored investigation session metadata.");
  }

  return {
    sessionId: item.sessionId,
    caseId: item.caseId,
    title:
      item.title === null || item.title === undefined
        ? null
        : safeTitle(String(item.title)),
    status: item.status as InvestigationSessionStatus,
    createdAt: item.createdAt,
    updatedAt: item.updatedAt,
    operatorId: item.operatorId,
    checkpoints: item.checkpoints.map(validateCheckpoint),
    questions: item.questions.map(validateQuestion)
  };
}

async function ensureLoaded(): Promise<void> {
  if (loaded) return;
  const persisted = await readPersistedInvestigationSessions();
  sessions.splice(
    0,
    sessions.length,
    ...persisted.map(validateStoredSession).slice(-MAX_SESSIONS)
  );
  loaded = true;
}

async function persist(): Promise<void> {
  await writePersistedInvestigationSessions(sessions);
}
export async function createInvestigationSession(
  caseId: string,
  title?: string
): Promise<InvestigationSessionRecord> {
  await ensureLoaded();
  const incident = await incidentCaseDetails(caseId);
  const now = new Date().toISOString();
  const session: InvestigationSessionRecord = {
    sessionId: "inv_" + randomUUID(),
    caseId: incident.caseId,
    title: safeTitle(title),
    status: "open",
    createdAt: now,
    updatedAt: now,
    operatorId: currentOperatorId(),
    checkpoints: [],
    questions: []
  };
  sessions.push(session);
  if (sessions.length > MAX_SESSIONS) {
    sessions.splice(0, sessions.length - MAX_SESSIONS);
  }
  await persist();
  return session;
}

export async function listInvestigationSessions(limit = 25) {
  await ensureLoaded();
  const safe = safeLimit(limit);
  return {
    sessionCount: sessions.length,
    sessions: sessions.slice(-safe).reverse().map((session) => ({
      sessionId: session.sessionId,
      caseId: session.caseId,
      title: session.title,
      status: session.status,
      createdAt: session.createdAt,
      updatedAt: session.updatedAt,
      checkpointCount: session.checkpoints.length,
      openQuestionCount: session.questions.filter(
        (question) => question.status === "open"
      ).length,
      operatorId: session.operatorId
    })),
    persistence: investigationPersistenceEnabled()
      ? "Investigation sessions are persisted locally with a 50-session bound."
      : "Investigation persistence is disabled; sessions remain in memory until the LocalOps process exits."
  };
}

export async function investigationSessionDetails(
  sessionId: string
): Promise<InvestigationSessionRecord> {
  await ensureLoaded();
  const safe = safeSessionId(sessionId);
  const session = sessions.find((item) => item.sessionId === safe);
  if (!session) throw new Error("Investigation session is not stored.");
  return session;
}
export async function recordInvestigationCheckpoint(
  sessionId: string,
  input: {
    kind: InvestigationCheckpointKind;
    evidenceRefs: string[];
  }
): Promise<InvestigationSessionRecord> {
  const session = await investigationSessionDetails(sessionId);
  if (session.status === "completed") {
    throw new Error("Completed investigation sessions cannot accept checkpoints.");
  }
  if (session.checkpoints.length >= MAX_CHECKPOINTS) {
    throw new Error("Investigation session checkpoint limit reached.");
  }
  const now = new Date().toISOString();
  session.checkpoints.push({
    checkpointId: "chk_" + randomUUID(),
    recordedAt: now,
    operatorId: currentOperatorId(),
    kind: input.kind,
    evidenceRefs: safeEvidenceRefs(input.evidenceRefs)
  });
  session.updatedAt = now;
  await persist();
  return session;
}

export async function addInvestigationQuestion(
  sessionId: string,
  input: {
    category: InvestigationQuestionCategory;
    prompt: string;
  }
): Promise<InvestigationSessionRecord> {
  const session = await investigationSessionDetails(sessionId);
  if (session.status === "completed") {
    throw new Error("Completed investigation sessions cannot accept questions.");
  }
  if (session.questions.length >= MAX_QUESTIONS) {
    throw new Error("Investigation session question limit reached.");
  }
  const now = new Date().toISOString();
  session.questions.push({
    questionId: "q_" + randomUUID(),
    category: input.category,
    prompt: safePrompt(input.prompt),
    status: "open",
    createdAt: now,
    updatedAt: now,
    operatorId: currentOperatorId()
  });
  session.updatedAt = now;
  await persist();
  return session;
}

export async function updateInvestigationQuestion(
  sessionId: string,
  questionId: string,
  status: InvestigationQuestionStatus
): Promise<InvestigationSessionRecord> {
  const session = await investigationSessionDetails(sessionId);
  const safeQuestion = safeQuestionId(questionId);
  const question = session.questions.find(
    (item) => item.questionId === safeQuestion
  );
  if (!question) throw new Error("Investigation question is not stored.");
  const now = new Date().toISOString();
  question.status = status;
  question.updatedAt = now;
  session.updatedAt = now;
  await persist();
  return session;
}
export async function setInvestigationSessionStatus(
  sessionId: string,
  status: InvestigationSessionStatus
): Promise<InvestigationSessionRecord> {
  const session = await investigationSessionDetails(sessionId);
  if (
    status === "completed" &&
    session.questions.some((question) => question.status === "open")
  ) {
    throw new Error(
      "Resolve or defer all open investigation questions before completing the session."
    );
  }
  session.status = status;
  session.updatedAt = new Date().toISOString();
  await persist();
  return session;
}

export async function investigationSessionStatus() {
  await ensureLoaded();
  return {
    version: "2.1.0" as const,
    persistenceEnabled: investigationPersistenceEnabled(),
    persistencePath: investigationPersistenceEnabled()
      ? investigationSessionsPath()
      : null,
    sessionCount: sessions.length,
    openSessionCount: sessions.filter((session) => session.status === "open").length,
    pausedSessionCount: sessions.filter((session) => session.status === "paused").length,
    completedSessionCount: sessions.filter(
      (session) => session.status === "completed"
    ).length,
    maxSessions: MAX_SESSIONS,
    maxCheckpointsPerSession: MAX_CHECKPOINTS,
    maxQuestionsPerSession: MAX_QUESTIONS,
    storage:
      "Bounded investigation metadata only; no raw event logs, packet data, credentials, command output, approval tokens or remediation scripts."
  };
}

export function clearInvestigationSessionsForTests() {
  sessions.splice(0, sessions.length);
  loaded = false;
}
