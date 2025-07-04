#!/usr/bin/env node
import { findVault, createVault, setSecret, getSecret, listKeys, removeKey, getAllSecrets } from "./vault";
import { readPassphrase } from "./prompt";
import { runCommand } from "./run";
import * as fs from "fs";

function requireVault(): string {
  const vp = findVault();
  if (!vp) {
    console.error("no vault found. run `envseal init` first.");
    process.exit(1);
  }
  return vp;
}

async function main(): Promise<void> {
  const args = process.argv.slice(2);
  const cmd = args[0];

  switch (cmd) {
    case "init": {
      const p = createVault();
      console.log(`created ${p}`);
      break;
    }
    case "set": {
      const vp = requireVault();
      const key = args[1];
      const val = args[2];
      if (!key || val === undefined) {
        console.error("usage: envseal set KEY VALUE");
        process.exit(1);
      }
      const pass = await readPassphrase();
      setSecret(vp, key, val, pass);
      console.log(`set ${key}`);
      break;
    }
    case "get": {
      const vp = requireVault();
      const key = args[1];
      if (!key) {
        console.error("usage: envseal get KEY");
        process.exit(1);
      }
      const pass = await readPassphrase();
      console.log(getSecret(vp, key, pass));
      break;
    }
    case "list": {
      const vp = requireVault();
      for (const k of listKeys(vp)) console.log(k);
      break;
    }
    case "rm": {
      const vp = requireVault();
      const key = args[1];
      if (!key) {
        console.error("usage: envseal rm KEY");
        process.exit(1);
      }
      removeKey(vp, key);
      console.log(`removed ${key}`);
      break;
    }
    case "export": {
      const vp = requireVault();
      const pass = await readPassphrase();
      const secrets = getAllSecrets(vp, pass);
      for (const [k, v] of Object.entries(secrets)) {
        console.log(`${k}=${v}`);
      }
      break;
    }
    case "import": {
      const vp = requireVault();
      const file = args[1];
      if (!file) {
        console.error("usage: envseal import FILE");
        process.exit(1);
      }
      const pass = await readPassphrase();
      const lines = fs.readFileSync(file, "utf8").split("\n");
      let count = 0;
      for (const line of lines) {
        const trimmed = line.trim();
        if (!trimmed || trimmed.startsWith("#")) continue;
        const eq = trimmed.indexOf("=");
        if (eq === -1) continue;
        const key = trimmed.slice(0, eq).trim();
        const val = trimmed.slice(eq + 1).trim();
        setSecret(vp, key, val, pass);
        count++;
      }
      console.log(`imported ${count} secrets`);
      break;
    }
    case "run": {
      const vp = requireVault();
      const dashIdx = args.indexOf("--");
      if (dashIdx === -1 || dashIdx === args.length - 1) {
        console.error("usage: envseal run -- COMMAND [ARGS...]");
        process.exit(1);
      }
      const pass = await readPassphrase();
      const secrets = getAllSecrets(vp, pass);
      const childArgs = args.slice(dashIdx + 1);
      const code = await runCommand(childArgs, { ...process.env as Record<string, string>, ...secrets });
      process.exit(code);
      break;
    }
    default:
      console.error("usage: envseal <init|set|get|list|rm|export|import|run>");
      process.exit(1);
  }
}

main().catch((err) => {
  console.error(err.message);
  process.exit(1);
});
