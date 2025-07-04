import * as fs from "fs";
import * as readline from "readline";

export function readPassphrase(prompt: string = "passphrase: "): Promise<string> {
  const envPass = process.env.ENVSEAL_PASSPHRASE;
  if (envPass) return Promise.resolve(envPass);

  return new Promise((resolve, reject) => {
    let ttyFd: number;
    try {
      ttyFd = fs.openSync("/dev/tty", "r");
    } catch {
      reject(new Error("cannot open /dev/tty — set ENVSEAL_PASSPHRASE env var"));
      return;
    }
    const ttyStream = fs.createReadStream("", { fd: ttyFd });
    const rl = readline.createInterface({ input: ttyStream, output: process.stderr });
    rl.question(prompt, (answer) => {
      rl.close();
      ttyStream.destroy();
      resolve(answer);
    });
  });
}
