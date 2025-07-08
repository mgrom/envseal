#!/usr/bin/env node
import { findVault, createVault, setSecret, getSecret, listKeys, removeKey, getAllSecrets, getVaultMode } from "./vault";
import { readPassphrase } from "./prompt";
import { runCommand } from "./run";
import { generateKeyFile } from "./crypto";
import * as fs from "fs";
import * as path from "path";

function requireVault(): string {
  const vp = findVault();
  if (!vp) {
    console.error("no vault found. run `envseal init` first.");
    process.exit(1);
  }
  return vp;
}

function resolveKeyFile(): Buffer | null {
  // 1. ENVSEAL_KEY — raw base64 key in env
  const envKey = process.env.ENVSEAL_KEY;
  if (envKey) return Buffer.from(envKey, "base64");

  // 2. ENVSEAL_KEY_FILE — path to key file
  const envKeyFile = process.env.ENVSEAL_KEY_FILE;
  if (envKeyFile) {
    if (!fs.existsSync(envKeyFile)) {
      console.error(`key file not found: ${envKeyFile}`);
      process.exit(1);
    }
    return Buffer.from(fs.readFileSync(envKeyFile, "utf8").trim(), "base64");
  }

  // 3. .envseal.key in cwd or parent dirs
  let dir: string;
  try {
    dir = process.cwd();
  } catch {
    return null;
  }
  while (true) {
    const candidate = path.join(dir, ".envseal.key");
    if (fs.existsSync(candidate)) {
      return Buffer.from(fs.readFileSync(candidate, "utf8").trim(), "base64");
    }
    const parent = path.dirname(dir);
    if (parent === dir) break;
    dir = parent;
  }

  return null;
}

async function getCredentials(vaultPath: string): Promise<{ passphrase?: string; keyBuf?: Buffer }> {
  const mode = getVaultMode(vaultPath);
  if (mode === "keyfile") {
    const keyBuf = resolveKeyFile();
    if (!keyBuf) {
      console.error("keyfile mode but no key found. set ENVSEAL_KEY, ENVSEAL_KEY_FILE, or place .envseal.key");
      process.exit(1);
    }
    return { keyBuf };
  }
  // passphrase mode — check for keyfile first (override), then prompt
  const keyBuf = resolveKeyFile();
  if (keyBuf) return { keyBuf };
  const passphrase = await readPassphrase();
  return { passphrase };
}

async function main(): Promise<void> {
  const args = process.argv.slice(2);
  const cmd = args[0];

  switch (cmd) {
    case "init": {
      const useKeyfile = args.includes("--keyfile");
      const p = createVault(undefined, useKeyfile ? "keyfile" : "passphrase");
      console.log(`created ${p} (${useKeyfile ? "keyfile" : "passphrase"} mode)`);
      break;
    }
    case "keygen": {
      const outIdx = args.indexOf("--out");
      const outPath = outIdx !== -1 ? args[outIdx + 1] : ".envseal.key";
      if (!outPath) {
        console.error("usage: envseal keygen [--out PATH]");
        process.exit(1);
      }
      const key = generateKeyFile();
      const dir = path.dirname(outPath);
      if (dir && !fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
      fs.writeFileSync(outPath, key.toString("base64") + "\n", { mode: 0o400 });
      console.log(`key written to ${outPath} (0400)`);
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
      const creds = await getCredentials(vp);
      setSecret(vp, key, val, creds.passphrase, creds.keyBuf);
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
      const creds = await getCredentials(vp);
      console.log(getSecret(vp, key, creds.passphrase, creds.keyBuf));
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
      const creds = await getCredentials(vp);
      const secrets = getAllSecrets(vp, creds.passphrase, creds.keyBuf);
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
      const creds = await getCredentials(vp);
      const lines = fs.readFileSync(file, "utf8").split("\n");
      let count = 0;
      for (const line of lines) {
        const trimmed = line.trim();
        if (!trimmed || trimmed.startsWith("#")) continue;
        const eq = trimmed.indexOf("=");
        if (eq === -1) continue;
        const key = trimmed.slice(0, eq).trim();
        const val = trimmed.slice(eq + 1).trim();
        setSecret(vp, key, val, creds.passphrase, creds.keyBuf);
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
      const creds = await getCredentials(vp);
      const secrets = getAllSecrets(vp, creds.passphrase, creds.keyBuf);
      const childArgs = args.slice(dashIdx + 1);
      const code = await runCommand(childArgs, secrets);
      process.exit(code);
      break;
    }
    default:
      console.error("usage: envseal <init|keygen|set|get|list|rm|export|import|run>");
      console.error("");
      console.error("  init [--keyfile]         create vault (passphrase or keyfile mode)");
      console.error("  keygen [--out PATH]      generate random key file");
      console.error("  set KEY VALUE            add or update a secret");
      console.error("  get KEY                  decrypt and print a secret");
      console.error("  list                     show secret names");
      console.error("  rm KEY                   remove a secret");
      console.error("  export                   decrypt all as KEY=VALUE");
      console.error("  import FILE              bulk import from .env file");
      console.error("  run -- CMD [ARGS]        run command with secrets in env");
      process.exit(1);
  }
}

main().catch((err) => {
  console.error(err.message);
  process.exit(1);
});
