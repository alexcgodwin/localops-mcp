import { execFile } from "node:child_process";

export type DatabaseEngine =
  | "postgresql"
  | "mysql"
  | "sqlserver"
  | "redis";

export type DatabaseProfile = {
  id: string;
  engine: DatabaseEngine;
  host: string;
  port: number;
  database: string | null;
  user: string | null;
  passwordEnv: string | null;
  integratedAuth: boolean;
  tls: boolean;
};

export type DatabaseSnapshot = {
  profileId: string;
  engine: DatabaseEngine;
  collectedAt: string;
  inventory: {
    version: string | null;
    database: string | null;
    principal: string | null;
  };
  connections: {
    active: number | null;
    total: number | null;
    max: number | null;
    blocked: number | null;
  };
  capacity: {
    databaseBytes: number | null;
    memoryBytes: number | null;
    maxMemoryBytes: number | null;
  };
  replication: {
    role: string | null;
    replicaCount: number | null;
    lagSeconds: number | null;
    state: string | null;
  };
  locks: {
    waiting: number | null;
    granted: number | null;
  };
  queryPressure: {
    longRunning: number | null;
    oldestSeconds: number | null;
    operationsPerSecond: number | null;
    rejectedConnections: number | null;
  };
  limitations: string[];
};

export type DatabaseCommandRunner = (
  executable: string,
  args: string[],
  env: NodeJS.ProcessEnv,
  allowFailure?: boolean
) => Promise<{ stdout: string; stderr: string; exitCode: number }>;

function redact(value: string, secrets: string[]): string {
  let result = value
    .replace(/(password|passwd|pwd|secret|token)\s*[=:]\s*[^\s,;]+/gi, "$1=[REDACTED]");
  for (const secret of secrets) {
    if (secret) result = result.split(secret).join("[REDACTED]");
  }
  return result;
}

export const defaultDatabaseCommandRunner: DatabaseCommandRunner = (
  executable,
  args,
  env,
  allowFailure = false
) =>
  new Promise((resolve, reject) => {
    const secrets = [
      env.PGPASSWORD,
      env.MYSQL_PWD,
      env.SQLCMDPASSWORD,
      env.REDISCLI_AUTH
    ].filter((value): value is string => Boolean(value));

    execFile(
      executable,
      args,
      {
        timeout: 15_000,
        maxBuffer: 1024 * 1024,
        windowsHide: true,
        env: { ...env, LANG: "C" }
      },
      (error, stdout, stderr) => {
        const result = {
          stdout: redact(stdout ?? "", secrets).trim(),
          stderr: redact(stderr ?? "", secrets).trim(),
          exitCode:
            error && typeof (error as NodeJS.ErrnoException).code === "number"
              ? Number((error as NodeJS.ErrnoException).code)
              : error
                ? 1
                : 0
        };

        if (error && !allowFailure) {
          reject(new Error(
            result.stderr || result.stdout || "Database client command failed."
          ));
          return;
        }
        resolve(result);
      }
    );
  });

function defaultPort(engine: DatabaseEngine): number {
  switch (engine) {
    case "postgresql":
      return 5432;
    case "mysql":
      return 3306;
    case "sqlserver":
      return 1433;
    case "redis":
      return 6379;
  }
}

function safeId(value: unknown): string {
  const id = String(value ?? "").trim();
  if (!/^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$/.test(id)) {
    throw new Error("Database profile id contains unsupported characters.");
  }
  return id;
}

function safeHost(value: unknown): string {
  const host = String(value ?? "127.0.0.1").trim();
  if (!/^[A-Za-z0-9][A-Za-z0-9_.:\[\]-]{0,254}$/.test(host)) {
    throw new Error("Database profile host contains unsupported characters.");
  }
  return host;
}

function optionalName(value: unknown, field: string): string | null {
  if (value === undefined || value === null || value === "") return null;
  const text = String(value).trim();
  if (
    text.length > 128 ||
    !/^[A-Za-z0-9][A-Za-z0-9_.@:$ -]{0,127}$/.test(text) ||
    text.startsWith("-")
  ) {
    throw new Error(field + " contains unsupported characters.");
  }
  return text;
}

function passwordEnvName(value: unknown): string | null {
  if (value === undefined || value === null || value === "") return null;
  const name = String(value).trim();
  if (!/^[A-Za-z_][A-Za-z0-9_]{0,127}$/.test(name)) {
    throw new Error("passwordEnv must be a valid environment-variable name.");
  }
  return name;
}

export function databaseProfiles(
  env: NodeJS.ProcessEnv = process.env
): DatabaseProfile[] {
  const raw = String(env.LOCALOPS_DATABASE_PROFILES ?? "").trim();
  if (!raw) return [];

  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    throw new Error("LOCALOPS_DATABASE_PROFILES must contain valid JSON.");
  }
  if (!Array.isArray(parsed) || parsed.length > 50) {
    throw new Error("LOCALOPS_DATABASE_PROFILES must be an array of at most 50 profiles.");
  }

  const ids = new Set<string>();
  return parsed.map((item) => {
    if (!item || typeof item !== "object") {
      throw new Error("Each database profile must be an object.");
    }
    const input = item as Record<string, unknown>;
    const id = safeId(input.id);
    if (ids.has(id)) {
      throw new Error("Duplicate database profile id: " + id);
    }
    ids.add(id);

    const engine = String(input.engine ?? "") as DatabaseEngine;
    if (!["postgresql", "mysql", "sqlserver", "redis"].includes(engine)) {
      throw new Error("Unsupported database engine for profile " + id + ".");
    }

    const portValue = input.port === undefined
      ? defaultPort(engine)
      : Number(input.port);
    if (!Number.isInteger(portValue) || portValue < 1 || portValue > 65535) {
      throw new Error("Database profile port must be between 1 and 65535.");
    }

    const integratedAuth = Boolean(input.integratedAuth);
    if (integratedAuth && engine !== "sqlserver") {
      throw new Error("integratedAuth is supported only for sqlserver profiles.");
    }

    const profile: DatabaseProfile = {
      id,
      engine,
      host: safeHost(input.host),
      port: portValue,
      database: optionalName(input.database, "database"),
      user: optionalName(input.user, "user"),
      passwordEnv: passwordEnvName(input.passwordEnv),
      integratedAuth,
      tls: Boolean(input.tls)
    };

    if (engine === "redis" && profile.database) {
      const index = Number(profile.database);
      if (!Number.isInteger(index) || index < 0 || index > 1024) {
        throw new Error("Redis database must be a numeric index between 0 and 1024.");
      }
    }

    return profile;
  });
}

export function databaseProfileSummaries(
  env: NodeJS.ProcessEnv = process.env
) {
  return databaseProfiles(env).map((profile) => ({
    id: profile.id,
    engine: profile.engine,
    host: profile.host,
    port: profile.port,
    database: profile.database,
    user: profile.user,
    integratedAuth: profile.integratedAuth,
    tls: profile.tls,
    credentialConfigured: Boolean(
      profile.integratedAuth ||
      (profile.passwordEnv && env[profile.passwordEnv])
    )
  }));
}

function getProfile(
  profileId: string,
  env: NodeJS.ProcessEnv
): DatabaseProfile {
  const id = safeId(profileId);
  const profile = databaseProfiles(env).find((item) => item.id === id);
  if (!profile) throw new Error("Database profile not found.");
  return profile;
}

function environmentForProfile(
  profile: DatabaseProfile,
  env: NodeJS.ProcessEnv
): NodeJS.ProcessEnv {
  const next = { ...env };
  if (profile.passwordEnv) {
    const secret = env[profile.passwordEnv];
    if (!secret) {
      throw new Error(
        "Database credential environment variable is not configured for profile " +
          profile.id +
          "."
      );
    }
    if (profile.engine === "postgresql") next.PGPASSWORD = secret;
    if (profile.engine === "mysql") next.MYSQL_PWD = secret;
    if (profile.engine === "sqlserver") next.SQLCMDPASSWORD = secret;
    if (profile.engine === "redis") next.REDISCLI_AUTH = secret;
  }
  return next;
}

function emptySnapshot(profile: DatabaseProfile): DatabaseSnapshot {
  return {
    profileId: profile.id,
    engine: profile.engine,
    collectedAt: new Date().toISOString(),
    inventory: {
      version: null,
      database: profile.database,
      principal: profile.user
    },
    connections: {
      active: null,
      total: null,
      max: null,
      blocked: null
    },
    capacity: {
      databaseBytes: null,
      memoryBytes: null,
      maxMemoryBytes: null
    },
    replication: {
      role: null,
      replicaCount: null,
      lagSeconds: null,
      state: null
    },
    locks: {
      waiting: null,
      granted: null
    },
    queryPressure: {
      longRunning: null,
      oldestSeconds: null,
      operationsPerSecond: null,
      rejectedConnections: null
    },
    limitations: []
  };
}

function numberOrNull(value: unknown): number | null {
  if (value === null || value === undefined || value === "") return null;
  const number = Number(value);
  return Number.isFinite(number) ? number : null;
}

async function postgresQuery(
  profile: DatabaseProfile,
  sql: string,
  runner: DatabaseCommandRunner,
  env: NodeJS.ProcessEnv
) {
  const args = [
    "-X",
    "-A",
    "-t",
    "-h",
    profile.host,
    "-p",
    String(profile.port)
  ];
  if (profile.user) args.push("-U", profile.user);
  if (profile.database) args.push("-d", profile.database);
  if (profile.tls) env.PGSSLMODE = "require";
  args.push("-c", sql);
  return runner("psql", args, env, true);
}

async function collectPostgres(
  profile: DatabaseProfile,
  runner: DatabaseCommandRunner,
  env: NodeJS.ProcessEnv
): Promise<DatabaseSnapshot> {
  const snapshot = emptySnapshot(profile);

  const queries = {
    inventory:
      "SELECT json_build_object('version',current_setting('server_version'),'database',current_database(),'principal',current_user)::text;",
    connections:
      "SELECT json_build_object('active',count(*) FILTER (WHERE state='active'),'total',count(*),'max',current_setting('max_connections')::int,'blocked',count(*) FILTER (WHERE wait_event_type='Lock'))::text FROM pg_stat_activity;",
    capacity:
      "SELECT json_build_object('databaseBytes',pg_database_size(current_database()))::text;",
    replication:
      "SELECT json_build_object('role',CASE WHEN pg_is_in_recovery() THEN 'standby' ELSE 'primary' END,'replicaCount',(SELECT count(*) FROM pg_stat_replication),'lagSeconds',CASE WHEN pg_is_in_recovery() THEN COALESCE(EXTRACT(EPOCH FROM now()-pg_last_xact_replay_timestamp()),0) ELSE 0 END,'state','available')::text;",
    locks:
      "SELECT json_build_object('waiting',count(*) FILTER (WHERE NOT granted),'granted',count(*) FILTER (WHERE granted))::text FROM pg_locks;",
    pressure:
      "SELECT json_build_object('longRunning',count(*) FILTER (WHERE state='active' AND query_start < now()-interval '30 seconds'),'oldestSeconds',COALESCE(max(EXTRACT(EPOCH FROM now()-query_start)) FILTER (WHERE state='active'),0))::text FROM pg_stat_activity;"
  };

  for (const [key, sql] of Object.entries(queries)) {
    const result = await postgresQuery(profile, sql, runner, { ...env });
    if (result.exitCode !== 0 || !result.stdout.trim()) {
      snapshot.limitations.push(
        "PostgreSQL " + key + " evidence unavailable: " +
          (result.stderr || "query returned no output.")
      );
      continue;
    }
    try {
      const data = JSON.parse(result.stdout.split(/\r?\n/).at(-1) ?? "{}");
      if (key === "inventory") {
        snapshot.inventory.version = String(data.version ?? "") || null;
        snapshot.inventory.database = String(data.database ?? "") || null;
        snapshot.inventory.principal = String(data.principal ?? "") || null;
      } else if (key === "connections") {
        snapshot.connections.active = numberOrNull(data.active);
        snapshot.connections.total = numberOrNull(data.total);
        snapshot.connections.max = numberOrNull(data.max);
        snapshot.connections.blocked = numberOrNull(data.blocked);
      } else if (key === "capacity") {
        snapshot.capacity.databaseBytes = numberOrNull(data.databaseBytes);
      } else if (key === "replication") {
        snapshot.replication.role = String(data.role ?? "") || null;
        snapshot.replication.replicaCount = numberOrNull(data.replicaCount);
        snapshot.replication.lagSeconds = numberOrNull(data.lagSeconds);
        snapshot.replication.state = String(data.state ?? "") || null;
      } else if (key === "locks") {
        snapshot.locks.waiting = numberOrNull(data.waiting);
        snapshot.locks.granted = numberOrNull(data.granted);
      } else if (key === "pressure") {
        snapshot.queryPressure.longRunning = numberOrNull(data.longRunning);
        snapshot.queryPressure.oldestSeconds = numberOrNull(data.oldestSeconds);
      }
    } catch {
      snapshot.limitations.push(
        "PostgreSQL " + key + " output could not be normalized."
      );
    }
  }

  return snapshot;
}

function tsvLine(stdout: string): string[] {
  const line = stdout.split(/\r?\n/).find((value) => value.trim());
  return line ? line.split("\t").map((value) => value.trim()) : [];
}

async function mysqlQuery(
  profile: DatabaseProfile,
  sql: string,
  runner: DatabaseCommandRunner,
  env: NodeJS.ProcessEnv
) {
  const args = [
    "--batch",
    "--raw",
    "--skip-column-names",
    "-h",
    profile.host,
    "-P",
    String(profile.port)
  ];
  if (profile.user) args.push("-u", profile.user);
  if (profile.database) args.push("-D", profile.database);
  if (profile.tls) args.push("--ssl-mode=REQUIRED");
  args.push("--execute", sql);
  return runner("mysql", args, env, true);
}

async function collectMysql(
  profile: DatabaseProfile,
  runner: DatabaseCommandRunner,
  env: NodeJS.ProcessEnv
): Promise<DatabaseSnapshot> {
  const snapshot = emptySnapshot(profile);
  const queries: Array<[string, string]> = [
    ["inventory", "SELECT VERSION(),DATABASE(),CURRENT_USER();"],
    ["connections", "SELECT (SELECT VARIABLE_VALUE FROM performance_schema.global_status WHERE VARIABLE_NAME='Threads_running'),(SELECT VARIABLE_VALUE FROM performance_schema.global_status WHERE VARIABLE_NAME='Threads_connected'),@@max_connections;"],
    ["capacity", "SELECT COALESCE(SUM(data_length+index_length),0) FROM information_schema.tables WHERE table_schema=DATABASE();"],
    ["locks", "SELECT COUNT(*) FROM performance_schema.data_lock_waits;"],
    ["pressure", "SELECT COUNT(*),COALESCE(MAX(TIME),0) FROM information_schema.PROCESSLIST WHERE COMMAND<>'Sleep' AND TIME>=30;"],
    ["replication", "SELECT @@read_only,@@super_read_only;"]
  ];

  for (const [key, sql] of queries) {
    const result = await mysqlQuery(profile, sql, runner, { ...env });
    if (result.exitCode !== 0 || !result.stdout.trim()) {
      snapshot.limitations.push(
        "MySQL/MariaDB " + key + " evidence unavailable: " +
          (result.stderr || "query returned no output.")
      );
      continue;
    }

    const values = tsvLine(result.stdout);
    if (key === "inventory") {
      snapshot.inventory.version = values[0] || null;
      snapshot.inventory.database = values[1] || profile.database;
      snapshot.inventory.principal = values[2] || profile.user;
    } else if (key === "connections") {
      snapshot.connections.active = numberOrNull(values[0]);
      snapshot.connections.total = numberOrNull(values[1]);
      snapshot.connections.max = numberOrNull(values[2]);
    } else if (key === "capacity") {
      snapshot.capacity.databaseBytes = numberOrNull(values[0]);
    } else if (key === "locks") {
      snapshot.locks.waiting = numberOrNull(values[0]);
    } else if (key === "pressure") {
      snapshot.queryPressure.longRunning = numberOrNull(values[0]);
      snapshot.queryPressure.oldestSeconds = numberOrNull(values[1]);
    } else if (key === "replication") {
      const readOnly = values[0] === "1" || values[0]?.toLowerCase() === "on";
      snapshot.replication.role = readOnly ? "replica-or-read-only" : "primary-or-writable";
      snapshot.replication.state = "role-inferred-from-read-only";
    }
  }

  return snapshot;
}

async function sqlServerQuery(
  profile: DatabaseProfile,
  sql: string,
  runner: DatabaseCommandRunner,
  env: NodeJS.ProcessEnv
) {
  const server = profile.host + "," + profile.port;
  const args = ["-S", server, "-h", "-1", "-W", "-s", "\t"];
  if (profile.database) args.push("-d", profile.database);
  if (profile.integratedAuth) {
    args.push("-E");
  } else if (profile.user) {
    args.push("-U", profile.user);
  }
  if (profile.tls) args.push("-N");
  args.push("-Q", "SET NOCOUNT ON; " + sql);
  return runner("sqlcmd", args, env, true);
}

async function collectSqlServer(
  profile: DatabaseProfile,
  runner: DatabaseCommandRunner,
  env: NodeJS.ProcessEnv
): Promise<DatabaseSnapshot> {
  const snapshot = emptySnapshot(profile);
  const queries: Array<[string, string]> = [
    ["inventory", "SELECT CAST(SERVERPROPERTY('ProductVersion') AS nvarchar(128)),DB_NAME(),SUSER_SNAME();"],
    ["connections", "SELECT COUNT(*),(SELECT CAST(value_in_use AS int) FROM sys.configurations WHERE name='user connections'),SUM(CASE WHEN status='running' THEN 1 ELSE 0 END) FROM sys.dm_exec_sessions WHERE is_user_process=1;"],
    ["capacity", "SELECT COALESCE(SUM(CAST(size AS bigint))*8192,0) FROM sys.database_files;"],
    ["locks", "SELECT SUM(CASE WHEN request_status='WAIT' THEN 1 ELSE 0 END),SUM(CASE WHEN request_status='GRANT' THEN 1 ELSE 0 END) FROM sys.dm_tran_locks;"],
    ["pressure", "SELECT COUNT(*),COALESCE(MAX(DATEDIFF(second,start_time,SYSDATETIME())),0) FROM sys.dm_exec_requests WHERE session_id<>@@SPID;"],
    ["replication", "SELECT CAST(SERVERPROPERTY('IsHadrEnabled') AS int),COUNT(*) FROM sys.dm_hadr_database_replica_states;"]
  ];

  for (const [key, sql] of queries) {
    const result = await sqlServerQuery(profile, sql, runner, { ...env });
    if (result.exitCode !== 0 || !result.stdout.trim()) {
      snapshot.limitations.push(
        "SQL Server " + key + " evidence unavailable: " +
          (result.stderr || "query returned no output.")
      );
      continue;
    }
    const values = tsvLine(result.stdout);
    if (key === "inventory") {
      snapshot.inventory.version = values[0] || null;
      snapshot.inventory.database = values[1] || profile.database;
      snapshot.inventory.principal = values[2] || profile.user;
    } else if (key === "connections") {
      snapshot.connections.total = numberOrNull(values[0]);
      snapshot.connections.max = numberOrNull(values[1]);
      snapshot.connections.active = numberOrNull(values[2]);
    } else if (key === "capacity") {
      snapshot.capacity.databaseBytes = numberOrNull(values[0]);
    } else if (key === "locks") {
      snapshot.locks.waiting = numberOrNull(values[0]);
      snapshot.locks.granted = numberOrNull(values[1]);
    } else if (key === "pressure") {
      snapshot.queryPressure.longRunning = numberOrNull(values[0]);
      snapshot.queryPressure.oldestSeconds = numberOrNull(values[1]);
    } else if (key === "replication") {
      const enabled = values[0] === "1";
      snapshot.replication.role = enabled ? "availability-group-enabled" : "standalone-or-disabled";
      snapshot.replication.replicaCount = numberOrNull(values[1]);
      snapshot.replication.state = enabled ? "hadr-enabled" : "hadr-disabled";
    }
  }

  return snapshot;
}

function parseRedisInfo(stdout: string) {
  const map = new Map<string, string>();
  for (const raw of stdout.split(/\r?\n/)) {
    const line = raw.trim();
    if (!line || line.startsWith("#")) continue;
    const index = line.indexOf(":");
    if (index < 1) continue;
    map.set(line.slice(0, index), line.slice(index + 1));
  }
  return map;
}

async function redisInfo(
  profile: DatabaseProfile,
  section: string,
  runner: DatabaseCommandRunner,
  env: NodeJS.ProcessEnv
) {
  const args = [
    "-h",
    profile.host,
    "-p",
    String(profile.port),
    "--no-auth-warning",
    "--raw"
  ];
  if (profile.user) args.push("--user", profile.user);
  if (profile.database) args.push("-n", profile.database);
  if (profile.tls) args.push("--tls");
  args.push("INFO", section);
  return runner("redis-cli", args, env, true);
}

async function collectRedis(
  profile: DatabaseProfile,
  runner: DatabaseCommandRunner,
  env: NodeJS.ProcessEnv
): Promise<DatabaseSnapshot> {
  const snapshot = emptySnapshot(profile);
  const sections = ["server", "clients", "memory", "replication", "stats"];

  for (const section of sections) {
    const result = await redisInfo(profile, section, runner, { ...env });
    if (result.exitCode !== 0 || !result.stdout.trim()) {
      snapshot.limitations.push(
        "Redis " + section + " evidence unavailable: " +
          (result.stderr || "INFO returned no output.")
      );
      continue;
    }

    const info = parseRedisInfo(result.stdout);
    if (section === "server") {
      snapshot.inventory.version = info.get("redis_version") ?? null;
      snapshot.inventory.database = profile.database ?? "0";
      snapshot.inventory.principal = profile.user;
    } else if (section === "clients") {
      snapshot.connections.total = numberOrNull(info.get("connected_clients"));
      snapshot.connections.blocked = numberOrNull(info.get("blocked_clients"));
    } else if (section === "memory") {
      snapshot.capacity.memoryBytes = numberOrNull(info.get("used_memory"));
      snapshot.capacity.maxMemoryBytes = numberOrNull(info.get("maxmemory"));
    } else if (section === "replication") {
      snapshot.replication.role = info.get("role") ?? null;
      snapshot.replication.replicaCount = numberOrNull(
        info.get("connected_slaves") ?? info.get("connected_replicas")
      );
      snapshot.replication.state =
        info.get("master_link_status") ??
        (snapshot.replication.role === "master" ? "primary" : null);
      const lag = info.get("master_last_io_seconds_ago");
      snapshot.replication.lagSeconds = numberOrNull(lag);
    } else if (section === "stats") {
      snapshot.queryPressure.operationsPerSecond = numberOrNull(
        info.get("instantaneous_ops_per_sec")
      );
      snapshot.queryPressure.rejectedConnections = numberOrNull(
        info.get("rejected_connections")
      );
    }
  }

  snapshot.limitations.push(
    "Redis does not expose relational lock or long-running-query metrics through this v1.1 INFO-only collector."
  );
  return snapshot;
}

export async function collectDatabaseSnapshot(
  profileId: string,
  runner: DatabaseCommandRunner = defaultDatabaseCommandRunner,
  env: NodeJS.ProcessEnv = process.env
): Promise<DatabaseSnapshot> {
  const profile = getProfile(profileId, env);
  const commandEnv = environmentForProfile(profile, env);

  if (profile.engine === "postgresql") {
    return collectPostgres(profile, runner, commandEnv);
  }
  if (profile.engine === "mysql") {
    return collectMysql(profile, runner, commandEnv);
  }
  if (profile.engine === "sqlserver") {
    return collectSqlServer(profile, runner, commandEnv);
  }
  return collectRedis(profile, runner, commandEnv);
}
