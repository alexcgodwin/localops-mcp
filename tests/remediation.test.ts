import {
  afterEach,
  describe,
  expect,
  it
} from "vitest";
import {
  createRemediationWorkflow,
  executeApprovedRemediationStep,
  prepareRemediationStep,
  recordRemediationStepDecision,
  remediationWorkflowDetails,
  resetRemediationWorkflowsForTests
} from "../src/remediation.js";

afterEach(() => {
  resetRemediationWorkflowsForTests();
});

function plan() {
  return {
    engineVersion: "1.4.0",
    generatedAt: new Date().toISOString(),
    leadingHypothesis: {
      category: "resource-pressure",
      hypothesis: "Service pressure may contribute to symptoms.",
      confidence: 80,
      confidenceBand: "high"
    },
    stepCount: 2,
    controlledStepCount: 1,
    readyForProposalCount: 1,
    executionGateSatisfiedCount: 1,
    manualStepCount: 0,
    steps: [
      {
        stepId: "step-1",
        order: 1,
        phase: "validate",
        riskTier: "R1",
        action: "Validate the service and evidence.",
        reason: "Validation must precede mutation.",
        controlledAction: null,
        targetType: null,
        targetHint: null,
        targetSelectionRequired: false,
        proposalAllowed: false,
        executionAllowed: false,
        requiresExplicitApproval: false,
        automaticExecutionAllowed: false,
        gateReasons: []
      },
      {
        stepId: "step-2",
        order: 2,
        phase: "controlled",
        riskTier: "R2",
        action: "Consider the approval-gated restart workflow.",
        reason: "A bounded restart may restore service.",
        controlledAction: "restart_service",
        targetType: "service",
        targetHint: null,
        targetSelectionRequired: true,
        proposalAllowed: true,
        executionAllowed: true,
        requiresExplicitApproval: true,
        automaticExecutionAllowed: false,
        gateReasons: []
      }
    ],
    interpretation:
      "Planning and approval orchestration only; no automatic authorization.",
    limitations: []
  };
}

function status(
  overrides: Record<string, unknown> = {}
) {
  return {
    enabled: true,
    operatorId: "tester",
    role: "maintainer",
    durableAuditEnabled: true,
    approvalTtlSeconds: 300,
    allowedServices: ["AppWorker"],
    supportedActions: [
      "start_service",
      "restart_service",
      "refresh_dns",
      "clean_temp_files"
    ],
    defaultPolicy: "test",
    riskModel: {
      R0: "read",
      R1: "analyze",
      R2: "controlled",
      R3Plus: "not exposed"
    },
    ...overrides
  };
}

function deps(
  overrides: Record<string, unknown> = {}
): any {
  return {
    collectEvidence: async () => ({
      collectedAt: new Date().toISOString(),
      windowHours: 24,
      systemHealth: null,
      processes: [],
      services: [],
      connections: [],
      events: [],
      startupPrograms: [],
      scheduledTasks: [],
      users: [],
      admins: [],
      limitations: []
    }),
    privateCall: async () => plan(),
    getExecutionStatus: () => status(),
    now: () => Date.parse("2026-10-03T02:00:00.000Z"),
    ...overrides
  };
}

describe("v1.4 remediation workflow controller", () => {
  it("creates workflow state without creating an approval token", async () => {
    const workflow = await createRemediationWorkflow(
      {},
      deps()
    );

    expect(workflow.engineVersion).toBe("1.4.0");
    expect(workflow.status).toBe("active");
    expect(workflow.steps[0].status).toBe("pending");
    expect(workflow.steps[1].status).toBe("pending");
    expect(JSON.stringify(workflow)).not.toContain(
      "approvalTokenHash"
    );
  });

  it("requires validation completion before preparing a controlled step", async () => {
    const workflow = await createRemediationWorkflow(
      {},
      deps()
    );

    await expect(
      prepareRemediationStep(
        {
          workflowId: workflow.workflowId,
          stepId: "step-2",
          serviceName: "AppWorker"
        },
        deps()
      )
    ).rejects.toThrow("Earlier remediation workflow steps");
  });

  it("creates a token-bound proposal only after validation is recorded", async () => {
    const workflow = await createRemediationWorkflow(
      {},
      deps()
    );
    recordRemediationStepDecision(
      {
        workflowId: workflow.workflowId,
        stepId: "step-1",
        decision: "completed"
      },
      deps()
    );

    const token = "p".repeat(48);
    const prepared = await prepareRemediationStep(
      {
        workflowId: workflow.workflowId,
        stepId: "step-2",
        serviceName: "AppWorker"
      },
      deps({
        propose: async (input: any) => ({
          proposalId: "proposal-1",
          approvalToken: token,
          action: input.action,
          target: input.serviceName ?? null,
          riskTier: "R2",
          preflight: {},
          parameters: {},
          workflowId: input.workflowContext.workflowId,
          workflowStepId: input.workflowContext.workflowStepId,
          expiresAt: "2026-10-03T02:05:00.000Z",
          confirmationRequired: "APPROVE",
          rollback: "Restart recovery guidance.",
          warning: "Explicit approval required."
        })
      })
    );

    expect(prepared.stepStatus).toBe("approval-pending");
    expect(prepared.proposal.approvalToken).toBe(token);

    const details = remediationWorkflowDetails(
      workflow.workflowId,
      deps()
    );
    expect(JSON.stringify(details)).not.toContain(token);
    expect(JSON.stringify(details)).not.toContain(
      "approvalTokenHash"
    );
  });

  it("rejects an approval token that belongs to a different workflow step", async () => {
    const workflow = await createRemediationWorkflow(
      {},
      deps()
    );
    recordRemediationStepDecision(
      {
        workflowId: workflow.workflowId,
        stepId: "step-1",
        decision: "completed"
      },
      deps()
    );

    const token = "q".repeat(48);
    await prepareRemediationStep(
      {
        workflowId: workflow.workflowId,
        stepId: "step-2",
        serviceName: "AppWorker"
      },
      deps({
        propose: async (input: any) => ({
          proposalId: "proposal-2",
          approvalToken: token,
          action: input.action,
          target: input.serviceName ?? null,
          riskTier: "R2",
          preflight: {},
          parameters: {},
          workflowId: input.workflowContext.workflowId,
          workflowStepId: input.workflowContext.workflowStepId,
          expiresAt: "2026-10-03T02:05:00.000Z",
          confirmationRequired: "APPROVE",
          rollback: "Restart recovery guidance.",
          warning: "Explicit approval required."
        })
      })
    );

    await expect(
      executeApprovedRemediationStep(
        {
          workflowId: workflow.workflowId,
          stepId: "step-2",
          approvalToken: "x".repeat(48),
          confirmation: "APPROVE"
        },
        deps()
      )
    ).rejects.toThrow("does not belong");
  });

  it("marks a controlled step verified only through the approved execution gateway", async () => {
    const workflow = await createRemediationWorkflow(
      {},
      deps()
    );
    recordRemediationStepDecision(
      {
        workflowId: workflow.workflowId,
        stepId: "step-1",
        decision: "completed"
      },
      deps()
    );

    const token = "z".repeat(48);
    const sharedDeps = deps({
      propose: async (input: any) => ({
        proposalId: "proposal-3",
        approvalToken: token,
        action: input.action,
        target: input.serviceName ?? null,
        riskTier: "R2",
        preflight: {},
        parameters: {},
        workflowId: input.workflowContext.workflowId,
        workflowStepId: input.workflowContext.workflowStepId,
        expiresAt: "2026-10-03T02:05:00.000Z",
        confirmationRequired: "APPROVE",
        rollback: "Restart recovery guidance.",
        warning: "Explicit approval required."
      }),
      execute: async () => ({
        action: "restart_service",
        target: "AppWorker",
        approved: true,
        executed: true,
        verified: true,
        result: { verification: "running" },
        rollback: "Restart recovery guidance.",
        workflowId: workflow.workflowId,
        workflowStepId: "step-2",
        auditId: "audit-123",
        durableAudit: {
          enabled: true,
          persisted: true,
          limitation: null
        }
      })
    });

    await prepareRemediationStep(
      {
        workflowId: workflow.workflowId,
        stepId: "step-2",
        serviceName: "AppWorker"
      },
      sharedDeps
    );

    const result = await executeApprovedRemediationStep(
      {
        workflowId: workflow.workflowId,
        stepId: "step-2",
        approvalToken: token,
        confirmation: "APPROVE"
      },
      sharedDeps
    );

    expect(result.stepStatus).toBe("verified");
    expect(result.workflowStatus).toBe("completed");
    expect(result.execution.auditId).toBe("audit-123");
  });

  it("blocks workflow execution when durable audit is no longer enabled", async () => {
    const workflow = await createRemediationWorkflow(
      {},
      deps()
    );
    recordRemediationStepDecision(
      {
        workflowId: workflow.workflowId,
        stepId: "step-1",
        decision: "completed"
      },
      deps()
    );

    const token = "y".repeat(48);
    await prepareRemediationStep(
      {
        workflowId: workflow.workflowId,
        stepId: "step-2",
        serviceName: "AppWorker"
      },
      deps({
        propose: async (input: any) => ({
          proposalId: "proposal-4",
          approvalToken: token,
          action: input.action,
          target: input.serviceName ?? null,
          riskTier: "R2",
          preflight: {},
          parameters: {},
          workflowId: input.workflowContext.workflowId,
          workflowStepId: input.workflowContext.workflowStepId,
          expiresAt: "2026-10-03T02:05:00.000Z",
          confirmationRequired: "APPROVE",
          rollback: "Restart recovery guidance.",
          warning: "Explicit approval required."
        })
      })
    );

    await expect(
      executeApprovedRemediationStep(
        {
          workflowId: workflow.workflowId,
          stepId: "step-2",
          approvalToken: token,
          confirmation: "APPROVE"
        },
        deps({
          getExecutionStatus: () =>
            status({ durableAuditEnabled: false })
        })
      )
    ).rejects.toThrow("Durable audit persistence");
  });
});
