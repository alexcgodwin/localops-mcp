import {
  createHash,
  randomBytes,
  timingSafeEqual
} from "node:crypto";
import {
  collectCorrelationEvidence
} from "./correlation.js";
import {
  executeApprovedAction,
  executionStatus,
  proposeExecution,
  type ControlledAction
} from "./execution.js";
import {
  callPrivateIntelligence
} from "./intelligence-client.js";

const WORKFLOW_TTL_MS = 30 * 60 * 1000;
const MAX_WORKFLOWS = 100;
const MAX_EVENTS = 200;

type LocalOpsRole =
  | "viewer"
  | "operator"
  | "maintainer"
  | "admin";

type WorkflowPlanStep = {
  stepId: string;
  order: number;
  phase: "validate" | "controlled" | "manual";
  riskTier: "R0" | "R1" | "R2" | "R3+";
  action: string;
  reason: string;
  controlledAction: ControlledAction | null;
  targetType: "service" | null;
  targetHint: string | null;
  targetSelectionRequired: boolean;
  proposalAllowed: boolean;
  executionAllowed: boolean;
  requiresExplicitApproval: boolean;
  automaticExecutionAllowed: false;
  gateReasons: string[];
};

type WorkflowPlan = {
  engineVersion: string;
  generatedAt: string;
  leadingHypothesis: {
    category: string;
    hypothesis: string;
    confidence: number;
    confidenceBand: "low" | "medium" | "high";
  } | null;
  stepCount: number;
  controlledStepCount: number;
  readyForProposalCount: number;
  executionGateSatisfiedCount: number;
  manualStepCount: number;
  steps: WorkflowPlanStep[];
  interpretation: string;
  limitations: string[];
};

export type RemediationStepStatus =
  | "pending"
  | "blocked"
  | "approval-pending"
  | "completed"
  | "skipped"
  | "verified"
  | "failed";

type WorkflowStep = WorkflowPlanStep & {
  status: RemediationStepStatus;
  resolvedTarget: string | null;
  proposalId: string | null;
  approvalExpiresAt: string | null;
  approvalTokenHash: string | null;
  auditId: string | null;
  lastError: string | null;
};

type WorkflowEvent = {
  timestamp: string;
  type:
    | "workflow-created"
    | "step-completed"
    | "step-skipped"
    | "proposal-created"
    | "execution-verified"
    | "execution-failed"
    | "execution-blocked";
  stepId: string | null;
  message: string;
};

type RemediationWorkflow = {
  workflowId: string;
  createdAt: string;
  expiresAt: string;
  evidenceWindowHours: number;
  evidenceLimit: number;
  engineVersion: string;
  leadingHypothesis: WorkflowPlan["leadingHypothesis"];
  interpretation: string;
  limitations: string[];
  steps: WorkflowStep[];
  events: WorkflowEvent[];
};

type PrivateCaller = (
  path: string,
  payload: Record<string, unknown>
) => Promise<Record<string, unknown>>;

type WorkflowDependencies = {
  collectEvidence?: typeof collectCorrelationEvidence;
  privateCall?: PrivateCaller;
  getExecutionStatus?: typeof executionStatus;
  propose?: typeof proposeExecution;
  execute?: typeof executeApprovedAction;
  now?: () => number;
};

const workflows = new Map<string, RemediationWorkflow>();

function nowMs(deps: WorkflowDependencies): number {
  return deps.now ? deps.now() : Date.now();
}

function workflowId(): string {
  return "rwf-" + randomBytes(10).toString("hex");
}

function tokenHash(token: string): string {
  return createHash("sha256").update(token).digest("hex");
}

function sameToken(token: string, expectedHash: string): boolean {
  const actual = Buffer.from(tokenHash(token), "hex");
  const expected = Buffer.from(expectedHash, "hex");
  return (
    actual.length === expected.length &&
    timingSafeEqual(actual, expected)
  );
}

function validStep(value: unknown): value is WorkflowPlanStep {
  if (!value || typeof value !== "object") return false;
  const step = value as Partial<WorkflowPlanStep>;
  return (
    typeof step.stepId === "string" &&
    /^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$/.test(step.stepId) &&
    typeof step.order === "number" &&
    Number.isInteger(step.order) &&
    step.order >= 1 &&
    ["validate", "controlled", "manual"].includes(String(step.phase)) &&
    ["R0", "R1", "R2", "R3+"].includes(String(step.riskTier)) &&
    typeof step.action === "string" &&
    step.action.length <= 2000 &&
    typeof step.reason === "string" &&
    step.reason.length <= 2000 &&
    (
      step.controlledAction === null ||
      [
        "start_service",
        "restart_service",
        "refresh_dns",
        "clean_temp_files"
      ].includes(String(step.controlledAction))
    ) &&
    (step.targetType === null || step.targetType === "service") &&
    (step.targetHint === null || typeof step.targetHint === "string") &&
    typeof step.targetSelectionRequired === "boolean" &&
    typeof step.proposalAllowed === "boolean" &&
    typeof step.executionAllowed === "boolean" &&
    typeof step.requiresExplicitApproval === "boolean" &&
    step.automaticExecutionAllowed === false &&
    Array.isArray(step.gateReasons) &&
    step.gateReasons.length <= 50 &&
    step.gateReasons.every((item) =>
      typeof item === "string" && item.length <= 1000
    )
  );
}

function parsePlan(value: Record<string, unknown>): WorkflowPlan {
  const plan = value as Partial<WorkflowPlan>;
  if (
    plan.engineVersion !== "1.4.0" ||
    typeof plan.generatedAt !== "string" ||
    !Array.isArray(plan.steps) ||
    plan.steps.length > 100 ||
    !plan.steps.every(validStep) ||
    typeof plan.interpretation !== "string" ||
    !Array.isArray(plan.limitations)
  ) {
    throw new Error(
      "Private intelligence core returned an invalid v1.4 remediation workflow plan."
    );
  }
  return plan as WorkflowPlan;
}

function addEvent(
  workflow: RemediationWorkflow,
  event: Omit<WorkflowEvent, "timestamp">
) {
  workflow.events.unshift({
    timestamp: new Date().toISOString(),
    ...event
  });
  if (workflow.events.length > MAX_EVENTS) {
    workflow.events.splice(MAX_EVENTS);
  }
}

function evictOldestWorkflow() {
  if (workflows.size < MAX_WORKFLOWS) return;
  const oldest = [...workflows.values()]
    .sort((left, right) =>
      new Date(left.createdAt).getTime() -
      new Date(right.createdAt).getTime()
    )[0];
  if (oldest) workflows.delete(oldest.workflowId);
}

function requireWorkflow(
  id: string,
  deps: WorkflowDependencies = {}
): RemediationWorkflow {
  const workflow = workflows.get(id);
  if (!workflow) {
    throw new Error("Remediation workflow was not found.");
  }
  if (
    new Date(workflow.expiresAt).getTime() <= nowMs(deps)
  ) {
    throw new Error(
      "Remediation workflow has expired. Create a new workflow from fresh evidence."
    );
  }
  return workflow;
}

function workflowOverallStatus(
  workflow: RemediationWorkflow,
  now = Date.now()
):
  | "active"
  | "awaiting-approval"
  | "blocked"
  | "failed"
  | "completed"
  | "expired" {
  if (new Date(workflow.expiresAt).getTime() <= now) {
    return "expired";
  }
  if (workflow.steps.some((step) => step.status === "failed")) {
    return "failed";
  }
  if (
    workflow.steps.every((step) =>
      ["completed", "skipped", "verified"].includes(step.status)
    )
  ) {
    return "completed";
  }
  if (
    workflow.steps.some(
      (step) => step.status === "approval-pending"
    )
  ) {
    return "awaiting-approval";
  }

  const firstOpen = [...workflow.steps]
    .sort((left, right) => left.order - right.order)
    .find(
      (step) =>
        !["completed", "skipped", "verified"].includes(step.status)
    );

  if (firstOpen?.status === "blocked") return "blocked";
  return "active";
}

function publicWorkflow(workflow: RemediationWorkflow) {
  const now = Date.now();
  return {
    workflowId: workflow.workflowId,
    createdAt: workflow.createdAt,
    expiresAt: workflow.expiresAt,
    status: workflowOverallStatus(workflow, now),
    evidenceWindowHours: workflow.evidenceWindowHours,
    evidenceLimit: workflow.evidenceLimit,
    engineVersion: workflow.engineVersion,
    leadingHypothesis: workflow.leadingHypothesis,
    interpretation: workflow.interpretation,
    limitations: [...workflow.limitations],
    steps: workflow.steps
      .slice()
      .sort((left, right) => left.order - right.order)
      .map((step) => ({
        stepId: step.stepId,
        order: step.order,
        phase: step.phase,
        riskTier: step.riskTier,
        action: step.action,
        reason: step.reason,
        controlledAction: step.controlledAction,
        targetType: step.targetType,
        targetHint: step.targetHint,
        targetSelectionRequired: step.targetSelectionRequired,
        proposalAllowed: step.proposalAllowed,
        executionAllowed: step.executionAllowed,
        requiresExplicitApproval: step.requiresExplicitApproval,
        automaticExecutionAllowed: false as const,
        gateReasons: [...step.gateReasons],
        status: step.status,
        resolvedTarget: step.resolvedTarget,
        proposalId: step.proposalId,
        approvalExpiresAt: step.approvalExpiresAt,
        auditId: step.auditId,
        lastError: step.lastError
      })),
    events: workflow.events.map((event) => ({ ...event }))
  };
}

function currentPolicy(
  deps: WorkflowDependencies = {}
) {
  const status = (deps.getExecutionStatus ?? executionStatus)();
  return {
    executionEnabled: status.enabled,
    role: status.role as LocalOpsRole,
    durableAuditEnabled: status.durableAuditEnabled,
    allowedServices: [...status.allowedServices],
    supportedActions: [...status.supportedActions]
  };
}

function previousStepsSatisfied(
  workflow: RemediationWorkflow,
  step: WorkflowStep
): boolean {
  return workflow.steps
    .filter((candidate) => candidate.order < step.order)
    .every((candidate) =>
      ["completed", "skipped", "verified"].includes(candidate.status)
    );
}

export function remediationWorkflowStatus(
  deps: WorkflowDependencies = {}
) {
  const status = (deps.getExecutionStatus ?? executionStatus)();
  const now = nowMs(deps);
  const retained = [...workflows.values()]
    .sort((left, right) =>
      new Date(right.createdAt).getTime() -
      new Date(left.createdAt).getTime()
    )
    .slice(0, 20)
    .map((workflow) => ({
      workflowId: workflow.workflowId,
      createdAt: workflow.createdAt,
      expiresAt: workflow.expiresAt,
      status: workflowOverallStatus(workflow, now),
      stepCount: workflow.steps.length
    }));

  return {
    version: "1.4.0",
    executionEnabled: status.enabled,
    operatorId: status.operatorId,
    role: status.role,
    durableAuditEnabled: status.durableAuditEnabled,
    workflowTtlSeconds: WORKFLOW_TTL_MS / 1000,
    approvalTtlSeconds: status.approvalTtlSeconds,
    supportedActions: [...status.supportedActions],
    activeWorkflowCount: [...workflows.values()].filter(
      (workflow) =>
        !["completed", "expired"].includes(
          workflowOverallStatus(workflow, now)
        )
    ).length,
    retainedWorkflowCount: workflows.size,
    recentWorkflows: retained,
    safetyBoundary:
      "v1.4 automates evidence-based planning and approval orchestration only. Host mutation remains disabled by default; every controlled R2 step requires current RBAC, allowlisting where applicable, durable audit, a one-time approval token, exact APPROVE confirmation and post-action verification. R3+ execution is unavailable."
  };
}

export async function createRemediationWorkflow(
  input: {
    windowHours?: number;
    limit?: number;
  },
  deps: WorkflowDependencies = {}
) {
  const collect = deps.collectEvidence ?? collectCorrelationEvidence;
  const privateCall = deps.privateCall ?? callPrivateIntelligence;
  const windowHours = Math.max(
    1,
    Math.min(Math.trunc(input.windowHours ?? 24), 720)
  );
  const limit = Math.max(
    10,
    Math.min(Math.trunc(input.limit ?? 100), 300)
  );

  const evidence = await collect(windowHours, limit);
  const policy = currentPolicy(deps);
  const plan = parsePlan(
    await privateCall(
      "/v1/remediation/workflow-plan",
      {
        bundle: evidence,
        executionPolicy: policy
      }
    )
  );

  evictOldestWorkflow();
  const created = new Date(nowMs(deps));
  const workflow: RemediationWorkflow = {
    workflowId: workflowId(),
    createdAt: created.toISOString(),
    expiresAt: new Date(
      created.getTime() + WORKFLOW_TTL_MS
    ).toISOString(),
    evidenceWindowHours: windowHours,
    evidenceLimit: limit,
    engineVersion: plan.engineVersion,
    leadingHypothesis: plan.leadingHypothesis,
    interpretation: plan.interpretation,
    limitations: [...plan.limitations],
    steps: plan.steps.map((step) => ({
      ...step,
      status:
        step.phase === "controlled" && !step.proposalAllowed
          ? "blocked"
          : "pending",
      resolvedTarget: null,
      proposalId: null,
      approvalExpiresAt: null,
      approvalTokenHash: null,
      auditId: null,
      lastError: null
    })),
    events: []
  };

  addEvent(workflow, {
    type: "workflow-created",
    stepId: null,
    message:
      "Workflow created from bounded current evidence. No execution approval was created."
  });
  workflows.set(workflow.workflowId, workflow);

  return publicWorkflow(workflow);
}

export function remediationWorkflowDetails(
  id: string,
  deps: WorkflowDependencies = {}
) {
  return publicWorkflow(requireWorkflow(id, deps));
}

export function recordRemediationStepDecision(
  input: {
    workflowId: string;
    stepId: string;
    decision: "completed" | "skipped";
    note?: string;
  },
  deps: WorkflowDependencies = {}
) {
  const workflow = requireWorkflow(input.workflowId, deps);
  const step = workflow.steps.find(
    (candidate) => candidate.stepId === input.stepId
  );
  if (!step) throw new Error("Remediation workflow step was not found.");

  if (
    ["verified", "completed", "skipped"].includes(step.status)
  ) {
    throw new Error("Remediation workflow step is already terminal.");
  }
  if (step.status === "approval-pending") {
    throw new Error(
      "A step with a live approval proposal cannot be completed or skipped through workflow state."
    );
  }
  if (
    step.phase === "validate" &&
    input.decision !== "completed"
  ) {
    throw new Error(
      "Validation steps cannot be skipped before a later controlled step."
    );
  }
  if (
    step.phase === "controlled" &&
    input.decision !== "skipped"
  ) {
    throw new Error(
      "Controlled steps can only be verified through the approved execution path or explicitly skipped."
    );
  }

  step.status = input.decision;
  step.lastError = null;
  const note = String(input.note ?? "").trim().slice(0, 500);
  addEvent(workflow, {
    type:
      input.decision === "completed"
        ? "step-completed"
        : "step-skipped",
    stepId: step.stepId,
    message:
      input.decision === "completed"
        ? step.phase === "manual"
          ? "Operator recorded external/manual completion. LocalOps did not execute this step." +
            (note ? " Note: " + note : "")
          : "Operator recorded validation completion." +
            (note ? " Note: " + note : "")
        : "Operator explicitly skipped this workflow step." +
          (note ? " Note: " + note : "")
  });

  return publicWorkflow(workflow);
}

export async function prepareRemediationStep(
  input: {
    workflowId: string;
    stepId: string;
    serviceName?: string;
  },
  deps: WorkflowDependencies = {}
) {
  const workflow = requireWorkflow(input.workflowId, deps);
  const step = workflow.steps.find(
    (candidate) => candidate.stepId === input.stepId
  );
  if (!step) throw new Error("Remediation workflow step was not found.");
  if (step.phase !== "controlled" || !step.controlledAction) {
    throw new Error(
      "Only a fixed controlled R2 workflow step can create an execution proposal."
    );
  }
  if (!previousStepsSatisfied(workflow, step)) {
    throw new Error(
      "Earlier remediation workflow steps must be completed or explicitly resolved before this controlled step can be prepared."
    );
  }
  if (
    ["verified", "completed", "skipped"].includes(step.status)
  ) {
    throw new Error("Remediation workflow step is already terminal.");
  }
  if (step.status === "approval-pending") {
    throw new Error(
      "This remediation step already has a pending one-time approval proposal."
    );
  }

  const status = (deps.getExecutionStatus ?? executionStatus)();
  if (!status.enabled) {
    throw new Error(
      "Controlled execution is disabled. The remediation workflow remains analysis-only."
    );
  }
  if (!status.durableAuditEnabled) {
    throw new Error(
      "v1.4 remediation workflow execution requires durable audit persistence."
    );
  }
  if (
    status.role !== "operator" &&
    status.role !== "maintainer" &&
    status.role !== "admin"
  ) {
    throw new Error(
      "The configured LocalOps role cannot create an R2 remediation proposal."
    );
  }

  let serviceName: string | undefined;
  if (step.targetType === "service") {
    const supplied = String(input.serviceName ?? "").trim();
    if (
      step.targetHint !== null &&
      supplied &&
      supplied.toLowerCase() !== step.targetHint.toLowerCase()
    ) {
      throw new Error(
        "serviceName does not match the evidence-derived workflow target."
      );
    }
    serviceName = step.targetHint ?? supplied;
    if (!serviceName) {
      throw new Error(
        "This workflow step requires an explicit allowlisted serviceName before proposal creation."
      );
    }
  }

  const proposal = await (deps.propose ?? proposeExecution)({
    action: step.controlledAction,
    serviceName,
    workflowContext: {
      workflowId: workflow.workflowId,
      workflowStepId: step.stepId
    }
  });

  step.status = "approval-pending";
  step.resolvedTarget = proposal.target;
  step.proposalId = proposal.proposalId;
  step.approvalExpiresAt = proposal.expiresAt;
  step.approvalTokenHash = tokenHash(proposal.approvalToken);
  step.lastError = null;
  addEvent(workflow, {
    type: "proposal-created",
    stepId: step.stepId,
    message:
      "A one-time approval proposal was created. The approval token itself is not stored in workflow state."
  });

  return {
    workflowId: workflow.workflowId,
    stepId: step.stepId,
    workflowStatus: workflowOverallStatus(
      workflow,
      nowMs(deps)
    ),
    stepStatus: step.status,
    proposal
  };
}

export async function executeApprovedRemediationStep(
  input: {
    workflowId: string;
    stepId: string;
    approvalToken: string;
    confirmation: "APPROVE";
  },
  deps: WorkflowDependencies = {}
) {
  const workflow = requireWorkflow(input.workflowId, deps);
  const step = workflow.steps.find(
    (candidate) => candidate.stepId === input.stepId
  );
  if (!step) throw new Error("Remediation workflow step was not found.");
  if (
    step.status !== "approval-pending" ||
    !step.approvalTokenHash
  ) {
    throw new Error(
      "This remediation step does not have a pending approval proposal."
    );
  }
  if (!previousStepsSatisfied(workflow, step)) {
    throw new Error(
      "Earlier remediation workflow steps are no longer satisfied."
    );
  }
  if (!sameToken(input.approvalToken, step.approvalTokenHash)) {
    throw new Error(
      "Approval token does not belong to this remediation workflow step."
    );
  }
  if (
    step.approvalExpiresAt === null ||
    new Date(step.approvalExpiresAt).getTime() <= nowMs(deps)
  ) {
    step.status = "blocked";
    step.approvalTokenHash = null;
    throw new Error(
      "The remediation approval proposal has expired. Prepare the step again."
    );
  }

  const status = (deps.getExecutionStatus ?? executionStatus)();
  if (!status.enabled) {
    throw new Error(
      "Controlled execution is disabled. No remediation action was executed."
    );
  }
  if (!status.durableAuditEnabled) {
    throw new Error(
      "Durable audit persistence is no longer enabled. v1.4 blocked execution."
    );
  }
  if (
    status.role !== "maintainer" &&
    status.role !== "admin"
  ) {
    throw new Error(
      "The configured LocalOps role cannot execute approved R2 remediation steps."
    );
  }

  try {
    const result = await (deps.execute ?? executeApprovedAction)({
      approvalToken: input.approvalToken,
      confirmation: input.confirmation,
      workflowContext: {
        workflowId: workflow.workflowId,
        workflowStepId: step.stepId
      }
    });

    step.approvalTokenHash = null;
    step.approvalExpiresAt = null;
    step.auditId = result.auditId;
    step.lastError = result.verified
      ? null
      : "Execution completed but post-action verification did not confirm the requested state.";
    step.status = result.verified ? "verified" : "failed";

    addEvent(workflow, {
      type: result.verified
        ? "execution-verified"
        : "execution-failed",
      stepId: step.stepId,
      message: result.verified
        ? "Approved R2 action executed and passed post-action verification. Audit ID: " +
          result.auditId
        : "Approved R2 action executed but verification did not confirm success. Audit ID: " +
          result.auditId
    });

    return {
      workflowId: workflow.workflowId,
      stepId: step.stepId,
      workflowStatus: workflowOverallStatus(
        workflow,
        nowMs(deps)
      ),
      stepStatus: step.status,
      execution: result
    };
  } catch (error) {
    const message =
      error instanceof Error ? error.message : String(error);
    step.lastError = message.slice(0, 1000);

    if (message.startsWith("Approved action failed:")) {
      step.status = "failed";
      step.approvalTokenHash = null;
      step.approvalExpiresAt = null;
      const match = message.match(/auditId=([A-Za-z0-9]+)/);
      step.auditId = match?.[1] ?? null;
      addEvent(workflow, {
        type: "execution-failed",
        stepId: step.stepId,
        message:
          "Approved remediation execution failed. " +
          (step.auditId
            ? "Audit ID: " + step.auditId
            : "See controlled-execution audit for details.")
      });
    } else {
      addEvent(workflow, {
        type: "execution-blocked",
        stepId: step.stepId,
        message:
          "Execution was blocked before a verified workflow completion: " +
          message.slice(0, 500)
      });
    }

    throw error;
  }
}

export function resetRemediationWorkflowsForTests() {
  workflows.clear();
}
