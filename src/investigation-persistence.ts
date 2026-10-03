import { chmod, mkdir, readFile, rename, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { localOpsDataDirectory } from "./platform.js";

const FILE_VERSION = "2.2.0";
const LEGACY_FILE_VERSION = "2.1.0";
const MAX_SESSIONS = 50;

export function investigationPersistenceEnabled(): boolean {
  return String(process.env.LOCALOPS_INVESTIGATION_PERSISTENCE ?? "")
    .trim()
    .toLowerCase() === "true";
}

export function investigationSessionsPath(): string {
  return join(localOpsDataDirectory(), "investigation-sessions.json");
}

export async function readPersistedInvestigationSessions(): Promise<unknown[]> {
  if (!investigationPersistenceEnabled()) return [];
  const path = investigationSessionsPath();
  try {
    const text = await readFile(path, "utf8");
    const parsed = JSON.parse(text) as {
      version?: unknown;
      sessions?: unknown;
    };
    if (
      ![FILE_VERSION, LEGACY_FILE_VERSION].includes(String(parsed.version)) ||
      !Array.isArray(parsed.sessions)
    ) {
      throw new Error("Investigation session file has an unsupported format.");
    }
    return parsed.sessions.slice(-MAX_SESSIONS);
  } catch (error: any) {
    if (error?.code === "ENOENT") return [];
    throw error;
  }
}

export async function writePersistedInvestigationSessions(
  sessions: unknown[]
): Promise<void> {
  if (!investigationPersistenceEnabled()) return;
  const directory = localOpsDataDirectory();
  const path = investigationSessionsPath();
  const temporary = path + ".tmp-" + process.pid;

  await mkdir(directory, { recursive: true, mode: 0o700 });
  const body =
    JSON.stringify(
      {
        version: FILE_VERSION,
        updatedAt: new Date().toISOString(),
        sessions: sessions.slice(-MAX_SESSIONS)
      },
      null,
      2
    ) + "\n";

  await writeFile(temporary, body, {
    encoding: "utf8",
    mode: 0o600
  });
  await rename(temporary, path);

  if (process.platform !== "win32") {
    await chmod(directory, 0o700).catch(() => undefined);
    await chmod(path, 0o600).catch(() => undefined);
  }
}
