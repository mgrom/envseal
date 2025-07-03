import * as fs from "fs";
import * as path from "path";
import { generateSalt, deriveKey, encrypt, decrypt } from "./crypto";

const VAULT_FILE = ".envseal.vault";

export function findVault(from?: string): string | null {
  let dir = from || process.cwd();
  while (true) {
    const p = path.join(dir, VAULT_FILE);
    if (fs.existsSync(p)) return p;
    const parent = path.dirname(dir);
    if (parent === dir) return null;
    dir = parent;
  }
}

export function createVault(dir?: string): string {
  const target = path.join(dir || process.cwd(), VAULT_FILE);
  if (fs.existsSync(target)) {
    throw new Error("vault already exists");
  }
  const salt = generateSalt();
  const vault: any = {
    version: 1,
    salt: salt.toString("base64"),
    secrets: {},
  };
  fs.writeFileSync(target, JSON.stringify(vault, null, 2));
  return target;
}

export function readVault(vaultPath: string): any {
  const raw = fs.readFileSync(vaultPath, "utf8");
  return JSON.parse(raw);
}

export function writeVault(vaultPath: string, vault: any): void {
  fs.writeFileSync(vaultPath, JSON.stringify(vault, null, 2));
}

export function setSecret(vaultPath: string, key: string, value: string, passphrase: string): void {
  const vault = readVault(vaultPath);
  const salt = Buffer.from(vault.salt, "base64");
  const dk = deriveKey(passphrase, salt);
  vault.secrets[key] = encrypt(value, dk);
  writeVault(vaultPath, vault);
}

export function getSecret(vaultPath: string, key: string, passphrase: string): string {
  const vault = readVault(vaultPath);
  if (!vault.secrets[key]) throw new Error(`key not found: ${key}`);
  const salt = Buffer.from(vault.salt, "base64");
  const dk = deriveKey(passphrase, salt);
  return decrypt(vault.secrets[key], dk);
}

export function listKeys(vaultPath: string): string[] {
  const vault = readVault(vaultPath);
  return Object.keys(vault.secrets);
}

export function removeKey(vaultPath: string, key: string): void {
  const vault = readVault(vaultPath);
  if (!vault.secrets[key]) throw new Error(`key not found: ${key}`);
  delete vault.secrets[key];
  writeVault(vaultPath, vault);
}

export function getAllSecrets(vaultPath: string, passphrase: string): Record<string, string> {
  const vault = readVault(vaultPath);
  const salt = Buffer.from(vault.salt, "base64");
  const dk = deriveKey(passphrase, salt);
  const result: Record<string, string> = {};
  for (const [k, v] of Object.entries(vault.secrets)) {
    result[k] = decrypt(v as any, dk);
  }
  return result;
}
