#!/usr/bin/env node
import { findVault, createVault, setSecret, getSecret, listKeys } from "./vault";

function requireVault(): string {
  const vp = findVault();
  if (!vp) {
    console.error("no vault found. run `envseal init` first.");
    process.exit(1);
  }
  return vp;
}

function getPassphrase(): string {
  const env = process.env.ENVSEAL_PASSPHRASE;
  if (env) return env;
  // TODO: read from TTY
  console.error("set ENVSEAL_PASSPHRASE for now");
  process.exit(1);
}

function main(): void {
  const args = process.argv.slice(2);
  const cmd = args[0];

  switch (cmd) {
    case "init": {
      const p = createVault();
      console.log(`created vault: ${p}`);
      break;
    }
    case "set": {
      const vp = requireVault();
      const key = args[1];
      const val = args[2];
      if (!key || !val) {
        console.error("usage: envseal set KEY VALUE");
        process.exit(1);
      }
      const pass = getPassphrase();
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
      const pass = getPassphrase();
      console.log(getSecret(vp, key, pass));
      break;
    }
    case "list": {
      const vp = requireVault();
      for (const k of listKeys(vp)) console.log(k);
      break;
    }
    default:
      console.error("usage: envseal <init|set|get|list>");
      process.exit(1);
  }
}

main();
