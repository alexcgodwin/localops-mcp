import { afterEach, describe, expect, it } from "vitest";
import { mkdtemp, rm } from "node:fs/promises";
import os from "node:os";
import { join } from "node:path";
import { proposeExecution } from "../src/execution.js";
import {
  appendDurableAudit,
  currentRole,
  evaluatePolicy,
  policyStatus,
  productionReadinessInput,
  readDurableAudit
} from "../src/platform.js";

const saved = {
  role: process.env.LOCALOPS_ROLE,
  operator: process.env.LOCALOPS_OPERATOR_ID,
  execution: process.env.LOCALOPS_EXECUTION_ENABLED,
  services: process.env.LOCALOPS_ALLOWED_SERVICES,
  audit: process.env.LOCALOPS_AUDIT_PERSISTENCE,
  dataDir: process.env.LOCALOPS_DATA_DIR
};

const tempDirs: string[] = [];

function restore(name: keyof typeof saved, envName: string) {
  const value = saved[name];
  if (value === undefined) delete process.env[envName];
  else process.env[envName] = value;
}

afterEach(async () => {
  restore("role", "LOCALOPS_ROLE");
  restore("operator", "LOCALOPS_OPERATOR_ID");
  restore("execution", "LOCALOPS_EXECUTION_ENABLED");
  restore("services", "LOCALOPS_ALLOWED_SERVICES");
  restore("audit", "LOCALOPS_AUDIT_PERSISTENCE");
  restore("dataDir", "LOCALOPS_DATA_DIR");

  await Promise.all(
    tempDirs.splice(0).map((directory) =>
      rm(directory, { recursive: true, force: true })
    )
  );
});

describe("v1.0 process-bound RBAC", () => {
  it("defaults to the least-privileged viewer role", () => {
    delete process.env.LOCALOPS_ROLE;
    expect(currentRole()).toBe("viewer");
    expect(policyStatus().permissions).toEqual([
      "inspect",
      "analyze"
    ]);
  });

  it("blocks R2 proposal for viewer", () => {
    process.env.LOCALOPS_ROLE = "viewer";
    const decision = evaluatePolicy("propose_execution", "R2");

    expect(decision.allowed).toBe(false);
  });

  it("allows operator to propose but not execute R2", () => {
    process.env.LOCALOPS_ROLE = "operator";

    expect(
      evaluatePolicy("propose_execution", "R2").allowed
    ).toBe(true);
    expect(
      evaluatePolicy("execute_r2", "R2").allowed
    ).toBe(false);
  });

  it("allows maintainer to execute R2 but never exposes R3+", () => {
    process.env.LOCALOPS_ROLE = "maintainer";

    expect(evaluatePolicy("execute_r2", "R2").allowed).toBe(true);
    expect(evaluatePolicy("execute_r2", "R3+").allowed).toBe(false);
  });

  it("enforces RBAC at the execution proposal boundary", async () => {
    process.env.LOCALOPS_EXECUTION_ENABLED = "true";
    process.env.LOCALOPS_ROLE = "viewer";

    await expect(
      proposeExecution(
        { action: "refresh_dns" },
        async () => ({ stdout: "", stderr: "", exitCode: 0 }),
        "win32"
      )
    ).rejects.toThrow("LocalOps policy blocked");
  });
});

describe("v1.0 production readiness", () => {
  it("blocks production readiness when execution lacks durable audit", () => {
    process.env.LOCALOPS_ROLE = "maintainer";
    process.env.LOCALOPS_EXECUTION_ENABLED = "true";
    delete process.env.LOCALOPS_AUDIT_PERSISTENCE;

    const checks = productionReadinessInput();
    const durable = checks.find((item) => item.id === "durable-audit");

    expect(durable?.status).toBe("fail");
  });

  it("accepts execution plus durable audit as coherent", async () => {
    const directory = await mkdtemp(
      join(os.tmpdir(), "localops-v1-test-")
    );
    tempDirs.push(directory);

    process.env.LOCALOPS_ROLE = "maintainer";
    process.env.LOCALOPS_EXECUTION_ENABLED = "true";
    process.env.LOCALOPS_AUDIT_PERSISTENCE = "true";
    process.env.LOCALOPS_DATA_DIR = directory;

    const checks = productionReadinessInput();
    expect(
      checks.find((item) => item.id === "durable-audit")?.status
    ).toBe("pass");
  });
});

describe("v1.0 durable audit", () => {
  it("writes metadata-only JSONL audit records", async () => {
    const directory = await mkdtemp(
      join(os.tmpdir(), "localops-v1-audit-")
    );
    tempDirs.push(directory);

    process.env.LOCALOPS_ROLE = "maintainer";
    process.env.LOCALOPS_OPERATOR_ID = "integration-operator";
    process.env.LOCALOPS_AUDIT_PERSISTENCE = "true";
    process.env.LOCALOPS_DATA_DIR = directory;

    await appendDurableAudit({
      id: "audit-1",
      timestamp: "2026-10-02T13:00:00.000Z",
      operatorId: "integration-operator",
      role: "maintainer",
      action: "refresh_dns",
      target: null,
      riskTier: "R2",
      approved: true,
      executed: true,
      verified: true,
      outcome: "success"
    });

    const result = await readDurableAudit(10);

    expect(result.enabled).toBe(true);
    expect(result.records).toHaveLength(1);
    expect(result.records[0].operatorId).toBe(
      "integration-operator"
    );
    expect(JSON.stringify(result)).not.toContain("approvalToken");
    expect(JSON.stringify(result)).not.toContain("commandOutput");
  });
});
