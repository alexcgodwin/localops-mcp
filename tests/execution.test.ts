import { afterEach, beforeEach, describe, expect, it } from "vitest";
import type { CommandRunner } from "../src/command.js";
import {
  executeApprovedAction,
  executionStatus,
  proposeExecution,
  recentExecutionAudit
} from "../src/execution.js";

const previousExecution = process.env.LOCALOPS_EXECUTION_ENABLED;
const previousServices = process.env.LOCALOPS_ALLOWED_SERVICES;
const previousRole = process.env.LOCALOPS_ROLE;
const previousOperator = process.env.LOCALOPS_OPERATOR_ID;
const previousAudit = process.env.LOCALOPS_AUDIT_PERSISTENCE;

function restoreEnv() {
  if (previousExecution === undefined) {
    delete process.env.LOCALOPS_EXECUTION_ENABLED;
  } else {
    process.env.LOCALOPS_EXECUTION_ENABLED = previousExecution;
  }

  if (previousServices === undefined) {
    delete process.env.LOCALOPS_ALLOWED_SERVICES;
  } else {
    process.env.LOCALOPS_ALLOWED_SERVICES = previousServices;
  }

  if (previousRole === undefined) delete process.env.LOCALOPS_ROLE;
  else process.env.LOCALOPS_ROLE = previousRole;

  if (previousOperator === undefined) delete process.env.LOCALOPS_OPERATOR_ID;
  else process.env.LOCALOPS_OPERATOR_ID = previousOperator;

  if (previousAudit === undefined) delete process.env.LOCALOPS_AUDIT_PERSISTENCE;
  else process.env.LOCALOPS_AUDIT_PERSISTENCE = previousAudit;
}

function windowsServiceRunner(): CommandRunner {
  return async (_executable, args) => {
    const command = args.at(-1) ?? "";

    if (command.includes("Restart-Service") || command.includes("Start-Service")) {
      return {
        stdout: JSON.stringify({
          Name: "DemoService",
          Status: "Running"
        }),
        stderr: "",
        exitCode: 0
      };
    }

    if (command.includes("Get-Service")) {
      return {
        stdout: JSON.stringify({
          Name: "DemoService",
          DisplayName: "Demo Service",
          Status: "Running",
          StartType: "Automatic"
        }),
        stderr: "",
        exitCode: 0
      };
    }

    return { stdout: "", stderr: "", exitCode: 0 };
  };
}

describe("controlled execution policy", () => {
  beforeEach(() => {
    delete process.env.LOCALOPS_EXECUTION_ENABLED;
    delete process.env.LOCALOPS_ALLOWED_SERVICES;
    process.env.LOCALOPS_ROLE = "maintainer";
    process.env.LOCALOPS_OPERATOR_ID = "test-maintainer";
    delete process.env.LOCALOPS_AUDIT_PERSISTENCE;
  });

  afterEach(() => {
    restoreEnv();
  });

  it("is disabled by default", () => {
    const status = executionStatus();
    expect(status.enabled).toBe(false);
    expect(status.riskModel.R3Plus).toContain("not exposed");
  });

  it("refuses to create an approval while execution is disabled", async () => {
    await expect(
      proposeExecution(
        { action: "refresh_dns" },
        async () => ({ stdout: "", stderr: "", exitCode: 0 }),
        "win32"
      )
    ).rejects.toThrow("Controlled execution is disabled");
  });

  it("requires exact service allowlisting", async () => {
    process.env.LOCALOPS_EXECUTION_ENABLED = "true";
    process.env.LOCALOPS_ALLOWED_SERVICES = "AllowedService";

    await expect(
      proposeExecution(
        {
          action: "restart_service",
          serviceName: "DemoService"
        },
        windowsServiceRunner(),
        "win32"
      )
    ).rejects.toThrow("not allowlisted");
  });

  it("rejects unsafe service names before execution", async () => {
    process.env.LOCALOPS_EXECUTION_ENABLED = "true";
    process.env.LOCALOPS_ALLOWED_SERVICES = "DemoService";

    await expect(
      proposeExecution(
        {
          action: "restart_service",
          serviceName: "DemoService; whoami"
        },
        windowsServiceRunner(),
        "win32"
      )
    ).rejects.toThrow("unsupported characters");
  });
});

describe("approval-gated execution", () => {
  beforeEach(() => {
    process.env.LOCALOPS_EXECUTION_ENABLED = "true";
    process.env.LOCALOPS_ALLOWED_SERVICES = "DemoService";
    process.env.LOCALOPS_ROLE = "maintainer";
    process.env.LOCALOPS_OPERATOR_ID = "test-maintainer";
    delete process.env.LOCALOPS_AUDIT_PERSISTENCE;
  });

  afterEach(() => {
    restoreEnv();
  });

  it("creates a bounded one-time restart proposal with preflight evidence", async () => {
    const proposal = await proposeExecution(
      {
        action: "restart_service",
        serviceName: "DemoService"
      },
      windowsServiceRunner(),
      "win32"
    );

    expect(proposal.action).toBe("restart_service");
    expect(proposal.target).toBe("DemoService");
    expect(proposal.riskTier).toBe("R2");
    expect(proposal.confirmationRequired).toBe("APPROVE");
    expect(proposal.approvalToken.length).toBeGreaterThanOrEqual(32);
    expect(proposal.preflight.service).toBeTruthy();
  });

  it("executes exactly the approved service action and verifies it", async () => {
    const proposal = await proposeExecution(
      {
        action: "restart_service",
        serviceName: "DemoService"
      },
      windowsServiceRunner(),
      "win32"
    );

    const result = await executeApprovedAction(
      {
        approvalToken: proposal.approvalToken,
        confirmation: "APPROVE"
      },
      windowsServiceRunner(),
      "win32"
    );

    expect(result).toMatchObject({
      action: "restart_service",
      target: "DemoService",
      approved: true,
      executed: true,
      verified: true
    });
    expect(result.auditId.length).toBeGreaterThan(0);
  });

  it("consumes approval tokens exactly once", async () => {
    const proposal = await proposeExecution(
      {
        action: "start_service",
        serviceName: "DemoService"
      },
      windowsServiceRunner(),
      "win32"
    );

    await executeApprovedAction(
      {
        approvalToken: proposal.approvalToken,
        confirmation: "APPROVE"
      },
      windowsServiceRunner(),
      "win32"
    );

    await expect(
      executeApprovedAction(
        {
          approvalToken: proposal.approvalToken,
          confirmation: "APPROVE"
        },
        windowsServiceRunner(),
        "win32"
      )
    ).rejects.toThrow("invalid, expired, or already consumed");
  });

  it("requires the exact approval confirmation", async () => {
    const proposal = await proposeExecution(
      { action: "refresh_dns" },
      async () => ({ stdout: "", stderr: "", exitCode: 0 }),
      "win32"
    );

    await expect(
      executeApprovedAction(
        {
          approvalToken: proposal.approvalToken,
          confirmation: "approve"
        },
        async () => ({ stdout: "", stderr: "", exitCode: 0 }),
        "win32"
      )
    ).rejects.toThrow("exactly equal APPROVE");
  });

  it("rechecks service allowlisting immediately before execution", async () => {
    const proposal = await proposeExecution(
      {
        action: "restart_service",
        serviceName: "DemoService"
      },
      windowsServiceRunner(),
      "win32"
    );

    process.env.LOCALOPS_ALLOWED_SERVICES = "OtherService";

    await expect(
      executeApprovedAction(
        {
          approvalToken: proposal.approvalToken,
          confirmation: "APPROVE"
        },
        windowsServiceRunner(),
        "win32"
      )
    ).rejects.toThrow("no longer allowlisted");
  });

  it("executes a separately approved Windows DNS refresh", async () => {
    const calls: Array<{ executable: string; args: string[] }> = [];
    const runner: CommandRunner = async (executable, args) => {
      calls.push({ executable, args });
      return {
        stdout: "Successfully flushed the DNS Resolver Cache.",
        stderr: "",
        exitCode: 0
      };
    };

    const proposal = await proposeExecution(
      { action: "refresh_dns" },
      runner,
      "win32"
    );
    const result = await executeApprovedAction(
      {
        approvalToken: proposal.approvalToken,
        confirmation: "APPROVE"
      },
      runner,
      "win32"
    );

    expect(result.executed).toBe(true);
    expect(result.verified).toBe(true);
    expect(calls.some((call) =>
      call.executable === "ipconfig.exe" &&
      call.args.includes("/flushdns")
    )).toBe(true);
  });

  it("bounds temporary-file cleanup proposals without deleting during proposal", async () => {
    const proposal = await proposeExecution(
      {
        action: "clean_temp_files",
        olderThanHours: 1,
        maxFiles: 999
      },
      async () => ({ stdout: "", stderr: "", exitCode: 0 }),
      "win32"
    );

    expect(proposal.parameters.olderThanHours).toBe(24);
    expect(proposal.parameters.maxFiles).toBe(200);
    expect(String(proposal.preflight.scope)).toContain("regular files only");
  });

  it("keeps approval tokens out of audit records", async () => {
    const proposal = await proposeExecution(
      { action: "refresh_dns" },
      async () => ({ stdout: "", stderr: "", exitCode: 0 }),
      "win32"
    );

    await executeApprovedAction(
      {
        approvalToken: proposal.approvalToken,
        confirmation: "APPROVE"
      },
      async () => ({
        stdout: "Successfully flushed the DNS Resolver Cache.",
        stderr: "",
        exitCode: 0
      }),
      "win32"
    );

    const audit = recentExecutionAudit(20);
    expect(audit.records.length).toBeGreaterThan(0);
    expect(JSON.stringify(audit)).not.toContain(proposal.approvalToken);
    expect(audit.persistence).toContain("in-memory");
  });

  it("records a failed command as attempted but unverified", async () => {
    const proposal = await proposeExecution(
      { action: "refresh_dns" },
      async () => ({ stdout: "", stderr: "", exitCode: 0 }),
      "win32"
    );

    await expect(
      executeApprovedAction(
        {
          approvalToken: proposal.approvalToken,
          confirmation: "APPROVE"
        },
        async () => {
          throw new Error("simulated execution failure");
        },
        "win32"
      )
    ).rejects.toThrow("Approved action failed");

    const audit = recentExecutionAudit(1);
    expect(audit.records[0]).toMatchObject({
      action: "refresh_dns",
      approved: true,
      executed: true,
      verified: false
    });
  });
});
