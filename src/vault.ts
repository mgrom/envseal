import * as fs from "fs";
import * as path from "path";
import { generateSalt, deriveKey, encrypt, decrypt, EncryptedValue } from "./crypto";

const VAULT_FILE = ".envseal.vault";

export interface Vault {
  version: number;
  keyMode: "passphrase" | "keyfile";
  salt?: string;
  secrets: Record<string, EncryptedValue>;
}

export function findVault(from?: string): string | null {
  let dir: string;
  try {
    dir = from || process.cwd();
  } catch {
    return null;
  }
  while (true) {
    const candidate = path.join(dir, VAULT_FILE);
    if (fs.existsSync(candidate)) return candidate;
    const parent = path.dirname(dir);
    if (parent === dir) return null;
    dir = parent;
  }
}

export function createVault(dir?: string, keyMode: "passphrase" | "keyfile" = "passphrase"): string {
  const target = path.join(dir || process.cwd(), VAULT_FILE);
  if (fs.existsSync(target)) {
    throw new Error("vault already exists at " + target);
  }
  const vault: Vault = {
    version: 2,
    keyMode,
    secrets: {},
  };
  if (keyMode === "passphrase") {
    vault.salt = generateSalt().toString("base64");
  }
  fs.writeFileSync(target, JSON.stringify(vault, null, 2) + "\n");
  return target;
}

function readVault(vaultPath: string): Vault {
  const raw = fs.readFileSync(vaultPath, "utf8");
  const parsed = JSON.parse(raw);
  // migrate v1 vaults
  if (parsed.version === 1) {
    parsed.version = 2;
    parsed.keyMode = "passphrase";
  }
  if (parsed.version !== 2) {
    throw new Error("unsupported vault version: " + parsed.version);
  }
  return parsed as Vault;
}

function writeVault(vaultPath: string, vault: Vault): void {
  fs.writeFileSync(vaultPath, JSON.stringify(vault, null, 2) + "\n");
}

export function resolveKey(vault: Vault, passphrase?: string, keyBuf?: Buffer): Buffer {
  if (vault.keyMode === "keyfile") {
    if (!keyBuf) throw new Error("keyfile required but not provided");
    return keyBuf;
  }
  // passphrase mode
  if (!passphrase) throw new Error("passphrase required");
  if (!vault.salt) throw new Error("vault missing salt");
  return deriveKey(passphrase, Buffer.from(vault.salt, "base64"));
}

export function getVaultMode(vaultPath: string): "passphrase" | "keyfile" {
  return readVault(vaultPath).keyMode;
}

export function setSecret(vaultPath: string, key: string, value: string, passphrase?: string, keyBuf?: Buffer): void {
  const vault = readVault(vaultPath);
  const dk = resolveKey(vault, passphrase, keyBuf);
  vault.secrets[key] = encrypt(value, dk);
  writeVault(vaultPath, vault);
}

export function getSecret(vaultPath: string, key: string, passphrase?: string, keyBuf?: Buffer): string {
  const vault = readVault(vaultPath);
  const enc = vault.secrets[key];
  if (!enc) throw new Error("secret not found: " + key);
  const dk = resolveKey(vault, passphrase, keyBuf);
  return decrypt(enc, dk);
}

export function listKeys(vaultPath: string): string[] {
  return Object.keys(readVault(vaultPath).secrets);
}

export function removeKey(vaultPath: string, key: string): void {
  const vault = readVault(vaultPath);
  if (!vault.secrets[key]) throw new Error("secret not found: " + key);
  delete vault.secrets[key];
  writeVault(vaultPath, vault);
}

export function getAllSecrets(vaultPath: string, passphrase?: string, keyBuf?: Buffer): Record<string, string> {
  const vault = readVault(vaultPath);
  const dk = resolveKey(vault, passphrase, keyBuf);
  const result: Record<string, string> = {};
  for (const [k, enc] of Object.entries(vault.secrets)) {
    result[k] = decrypt(enc, dk);
  }
  return result;
}
