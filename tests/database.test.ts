import { afterEach, describe, expect, it } from "vitest";
import {
  collectDatabaseSnapshot,
  databaseProfileSummaries,
  databaseProfiles,
  type DatabaseCommandRunner
} from "../src/database.js";
import { callPrivateIntelligence } from "../src/intelligence-client.js";

const originalProfiles = process.env.LOCALOPS_DATABASE_PROFILES;
const originalSecret = process.env.TEST_DB_SECRET;
const originalUrl = process.env.LOCALOPS_INTELLIGENCE_URL;
const originalToken = process.env.LOCALOPS_INTELLIGENCE_TOKEN;

function restore(name: string, value: string | undefined) {
  if (value === undefined) delete process.env[name];
  else process.env[name] = value;
}

afterEach(() => {
  restore("LOCALOPS_DATABASE_PROFILES", originalProfiles);
  restore("TEST_DB_SECRET", originalSecret);
  restore("LOCALOPS_INTELLIGENCE_URL", originalUrl);
  restore("LOCALOPS_INTELLIGENCE_TOKEN", originalToken);
});

function setProfile(profile: Record<string, unknown>) {
  process.env.LOCALOPS_DATABASE_PROFILES = JSON.stringify([profile]);
}

describe("v1.1 database profiles", () => {
  it("returns metadata without exposing password values or password environment names", () => {
    process.env.TEST_DB_SECRET = "do-not-return-this-value";
    setProfile({
      id: "pg-main",
      engine: "postgresql",
      host: "127.0.0.1",
      port: 5432,
      database: "app",
      user: "reader",
      passwordEnv: "TEST_DB_SECRET",
      tls: true
    });

    const summaries = databaseProfileSummaries();

    expect(summaries).toHaveLength(1);
    expect(summaries[0]).toMatchObject({
      id: "pg-main",
      engine: "postgresql",
      credentialConfigured: true
    });
    expect(JSON.stringify(summaries)).not.toContain("do-not-return-this-value");
    expect(JSON.stringify(summaries)).not.toContain("TEST_DB_SECRET");
  });

  it("rejects duplicate profile identifiers", () => {
    process.env.LOCALOPS_DATABASE_PROFILES = JSON.stringify([
      { id: "db-a", engine: "redis", host: "127.0.0.1" },
      { id: "db-a", engine: "redis", host: "127.0.0.1" }
    ]);

    expect(() => databaseProfiles()).toThrow("Duplicate database profile id");
  });

  it("rejects unsupported profile fields before client execution", () => {
    setProfile({
      id: "db-a",
      engine: "postgresql",
      host: "host;bad",
      database: "app"
    });

    expect(() => databaseProfiles()).toThrow("host contains unsupported characters");
  });
});

describe("v1.1 PostgreSQL collector", () => {
  it("uses fixed psql queries and keeps the password out of arguments", async () => {
    process.env.TEST_DB_SECRET = "pg-secret-value";
    setProfile({
      id: "pg-main",
      engine: "postgresql",
      host: "db.internal",
      port: 5432,
      database: "app",
      user: "reader",
      passwordEnv: "TEST_DB_SECRET"
    });

    const runner: DatabaseCommandRunner = async (exe, args, env) => {
      expect(exe).toBe("psql");
      expect(args.join(" ")).not.toContain("pg-secret-value");
      expect(env.PGPASSWORD).toBe("pg-secret-value");
      const sql = args.at(-1) ?? "";

      if (sql.includes("server_version")) {
        return {
          stdout: JSON.stringify({
            version: "16.4",
            database: "app",
            principal: "reader"
          }),
          stderr: "",
          exitCode: 0
        };
      }
      if (sql.includes("max_connections")) {
        return {
          stdout: JSON.stringify({
            active: 4,
            total: 12,
            max: 100,
            blocked: 1
          }),
          stderr: "",
          exitCode: 0
        };
      }
      if (sql.includes("pg_database_size")) {
        return {
          stdout: JSON.stringify({ databaseBytes: 1048576 }),
          stderr: "",
          exitCode: 0
        };
      }
      if (sql.includes("pg_is_in_recovery")) {
        return {
          stdout: JSON.stringify({
            role: "primary",
            replicaCount: 1,
            lagSeconds: 0,
            state: "available"
          }),
          stderr: "",
          exitCode: 0
        };
      }
      if (sql.includes("pg_locks")) {
        return {
          stdout: JSON.stringify({ waiting: 2, granted: 20 }),
          stderr: "",
          exitCode: 0
        };
      }
      return {
        stdout: JSON.stringify({
          longRunning: 1,
          oldestSeconds: 45
        }),
        stderr: "",
        exitCode: 0
      };
    };

    const result = await collectDatabaseSnapshot("pg-main", runner);

    expect(result.inventory.version).toBe("16.4");
    expect(result.connections.max).toBe(100);
    expect(result.locks.waiting).toBe(2);
    expect(result.queryPressure.longRunning).toBe(1);
  });
});

describe("v1.1 MySQL/MariaDB collector", () => {
  it("normalizes fixed read-only mysql telemetry", async () => {
    process.env.TEST_DB_SECRET = "mysql-secret";
    setProfile({
      id: "mysql-main",
      engine: "mysql",
      host: "127.0.0.1",
      database: "app",
      user: "reader",
      passwordEnv: "TEST_DB_SECRET"
    });

    const runner: DatabaseCommandRunner = async (exe, args, env) => {
      expect(exe).toBe("mysql");
      expect(args.join(" ")).not.toContain("mysql-secret");
      expect(env.MYSQL_PWD).toBe("mysql-secret");
      const sql = args.at(-1) ?? "";

      if (sql.includes("VERSION()")) {
        return { stdout: "8.4.0\tapp\treader@%", stderr: "", exitCode: 0 };
      }
      if (sql.includes("Threads_running")) {
        return { stdout: "2\t10\t151", stderr: "", exitCode: 0 };
      }
      if (sql.includes("data_length")) {
        return { stdout: "2048", stderr: "", exitCode: 0 };
      }
      if (sql.includes("data_lock_waits")) {
        return { stdout: "1", stderr: "", exitCode: 0 };
      }
      if (sql.includes("PROCESSLIST")) {
        return { stdout: "3\t90", stderr: "", exitCode: 0 };
      }
      return { stdout: "0\t0", stderr: "", exitCode: 0 };
    };

    const result = await collectDatabaseSnapshot("mysql-main", runner);

    expect(result.inventory.version).toBe("8.4.0");
    expect(result.connections.total).toBe(10);
    expect(result.capacity.databaseBytes).toBe(2048);
    expect(result.queryPressure.oldestSeconds).toBe(90);
  });
});

describe("v1.1 SQL Server collector", () => {
  it("supports Windows/integrated authentication without accepting a password", async () => {
    setProfile({
      id: "sql-main",
      engine: "sqlserver",
      host: "localhost",
      database: "app",
      integratedAuth: true
    });

    const runner: DatabaseCommandRunner = async (exe, args) => {
      expect(exe).toBe("sqlcmd");
      expect(args).toContain("-E");
      expect(args).not.toContain("-P");
      const sql = args.at(-1) ?? "";

      if (sql.includes("ProductVersion")) {
        return { stdout: "16.0.1000\tapp\tDOMAIN\\reader", stderr: "", exitCode: 0 };
      }
      if (sql.includes("user connections")) {
        return { stdout: "8\t100\t2", stderr: "", exitCode: 0 };
      }
      if (sql.includes("database_files")) {
        return { stdout: "4096", stderr: "", exitCode: 0 };
      }
      if (sql.includes("dm_tran_locks")) {
        return { stdout: "0\t12", stderr: "", exitCode: 0 };
      }
      if (sql.includes("dm_exec_requests")) {
        return { stdout: "1\t10", stderr: "", exitCode: 0 };
      }
      return { stdout: "1\t2", stderr: "", exitCode: 0 };
    };

    const result = await collectDatabaseSnapshot("sql-main", runner);

    expect(result.inventory.version).toBe("16.0.1000");
    expect(result.connections.total).toBe(8);
    expect(result.replication.replicaCount).toBe(2);
  });
});

describe("v1.1 Redis collector", () => {
  it("uses Redis INFO only and keeps auth material in the environment", async () => {
    process.env.TEST_DB_SECRET = "redis-secret";
    setProfile({
      id: "redis-main",
      engine: "redis",
      host: "127.0.0.1",
      database: "0",
      user: "reader",
      passwordEnv: "TEST_DB_SECRET"
    });

    const runner: DatabaseCommandRunner = async (exe, args, env) => {
      expect(exe).toBe("redis-cli");
      expect(args.join(" ")).not.toContain("redis-secret");
      expect(env.REDISCLI_AUTH).toBe("redis-secret");
      expect(args).toContain("INFO");

      const section = args.at(-1);
      if (section === "server") {
        return { stdout: "redis_version:7.4.0", stderr: "", exitCode: 0 };
      }
      if (section === "clients") {
        return { stdout: "connected_clients:6\nblocked_clients:1", stderr: "", exitCode: 0 };
      }
      if (section === "memory") {
        return { stdout: "used_memory:1000\nmaxmemory:5000", stderr: "", exitCode: 0 };
      }
      if (section === "replication") {
        return {
          stdout: "role:slave\nmaster_link_status:up\nmaster_last_io_seconds_ago:2",
          stderr: "",
          exitCode: 0
        };
      }
      return {
        stdout: "instantaneous_ops_per_sec:120\nrejected_connections:0",
        stderr: "",
        exitCode: 0
      };
    };

    const result = await collectDatabaseSnapshot("redis-main", runner);

    expect(result.inventory.version).toBe("7.4.0");
    expect(result.capacity.memoryBytes).toBe(1000);
    expect(result.replication.state).toBe("up");
    expect(result.queryPressure.operationsPerSecond).toBe(120);
  });
});

describe("v1.1 private database route boundary", () => {
  it("allows only the fixed analysis routes", async () => {
    process.env.LOCALOPS_INTELLIGENCE_URL = "http://127.0.0.1:43123";
    process.env.LOCALOPS_INTELLIGENCE_TOKEN = "d".repeat(32);

    for (const route of [
      "/v1/database/health",
      "/v1/database/replication",
      "/v1/database/contention",
      "/v1/database/pressure"
    ]) {
      const result = await callPrivateIntelligence(
        route,
        {},
        (async () =>
          new Response(JSON.stringify({ route }), {
            status: 200,
            headers: { "content-type": "application/json" }
          })) as typeof fetch
      );
      expect(result.route).toBe(route);
    }
  });

  it("rejects arbitrary database query and execution routes", async () => {
    process.env.LOCALOPS_INTELLIGENCE_URL = "http://127.0.0.1:43123";
    process.env.LOCALOPS_INTELLIGENCE_TOKEN = "e".repeat(32);

    for (const route of [
      "/v1/database/query",
      "/v1/database/execute"
    ]) {
      await expect(
        callPrivateIntelligence(
          route,
          {},
          (async () => new Response("{}", { status: 200 })) as typeof fetch
        )
      ).rejects.toThrow("Unsupported private intelligence route");
    }
  });
});
