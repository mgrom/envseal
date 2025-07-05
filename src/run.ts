import { spawn } from "child_process";

export function runCommand(command: string[], extraEnv: Record<string, string>): Promise<number> {
  return new Promise((resolve, reject) => {
    const merged: Record<string, string> = {};
    for (const [k, v] of Object.entries(process.env)) {
      if (v !== undefined) merged[k] = v;
    }
    Object.assign(merged, extraEnv);

    const child = spawn(command[0], command.slice(1), {
      stdio: "inherit",
      env: merged,
    });
    child.on("error", reject);
    child.on("close", (code) => resolve(code ?? 1));
  });
}
