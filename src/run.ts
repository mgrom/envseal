import { spawn } from "child_process";

export function runCommand(command: string[], env: Record<string, string>): Promise<number> {
  return new Promise((resolve, reject) => {
    const child = spawn(command[0], command.slice(1), {
      stdio: "inherit",
      env: { ...env },
    });
    child.on("error", reject);
    child.on("close", (code) => resolve(code ?? 1));
  });
}
