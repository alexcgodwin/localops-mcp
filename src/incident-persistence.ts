import { chmod, mkdir, readFile, rename, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { localOpsDataDirectory } from "./platform.js";

const FILE_VERSION = "1.8.0";
const MAX_CASES = 200;

export function incidentPersistenceEnabled(): boolean {
  return String(process.env.LOCALOPS_INCIDENT_PERSISTENCE ?? "")
    .trim()
    .toLowerCase() === "true";
}

export function incidentMemoryPath(): string {
  return join(localOpsDataDirectory(), "incident-memory.json");
}

export async function readPersistedIncidentCases(): Promise<unknown[]> {
  if (!incidentPersistenceEnabled()) return [];
  const path = incidentMemoryPath();
  try {
    const text = await readFile(path, "utf8");
    const parsed = JSON.parse(text) as {
      version?: unknown;
      cases?: unknown;
    };
    if (parsed.version !== FILE_VERSION || !Array.isArray(parsed.cases)) {
      throw new Error("Incident memory file has an unsupported format.");
    }
    return parsed.cases.slice(-MAX_CASES);
  } catch (error: any) {
    if (error?.code === "ENOENT") return [];
    throw error;
  }
}
export async function writePersistedIncidentCases(
  cases: unknown[]
): Promise<void> {
  if (!incidentPersistenceEnabled()) return;
  const directory = localOpsDataDirectory();
  const path = incidentMemoryPath();
  const temporary = path + ".tmp-" + process.pid;

  await mkdir(directory, { recursive: true, mode: 0o700 });
  const body = JSON.stringify(
    {
      version: FILE_VERSION,
      updatedAt: new Date().toISOString(),
      cases: cases.slice(-MAX_CASES)
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
