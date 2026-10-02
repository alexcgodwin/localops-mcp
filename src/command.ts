import { execFile } from "node:child_process";

export type CommandResult = {
  stdout: string;
  stderr: string;
  exitCode: number;
};

export type CommandRunner = (
  executable: string,
  args: string[],
  allowFailure?: boolean
) => Promise<CommandResult>;

function redact(value: string): string {
  return value
    .replace(/gh[pousr]_[A-Za-z0-9_]{20,}/g, "[REDACTED_TOKEN]")
    .replace(/github_pat_[A-Za-z0-9_]{20,}/g, "[REDACTED_TOKEN]")
    .replace(/(token|password|secret|client_secret)\s*[=:]\s*[^\s,;]+/gi, "$1=[REDACTED]");
}

export const defaultCommandRunner: CommandRunner = (
  executable,
  args,
  allowFailure = false
) => new Promise((resolve, reject) => {  execFile(
    executable,
    args,
    {
      timeout: 15_000,
      maxBuffer: 2 * 1024 * 1024,
      windowsHide: true,
      env: { ...process.env, LANG: "C" }
    },
    (error, stdout, stderr) => {
      const result = {
        stdout: redact(stdout ?? "").trim(),
        stderr: redact(stderr ?? "").trim(),
        exitCode:
          error && typeof (error as NodeJS.ErrnoException).code === "number"
            ? Number((error as NodeJS.ErrnoException).code)
            : error ? 1 : 0
      };
      if (error && !allowFailure) {
        reject(new Error(result.stderr || result.stdout || error.message));
        return;
      }
      resolve(result);
    }
  );
});
