import * as fs from "fs";
import * as path from "path";
import { generateSalt, deriveKey, encrypt, decrypt, EncryptedValue } from "./crypto";

const VAULT_FILE = ".envseal.vault";
const CURRENT_VERSION = 1;

export interface Vault {
  version: number;
  salt: string;
  secrets: Record<string, EncryptedValue>;
}

export function findVault(from?: string): string | null {
  let dir = from || process.cwd();
  while (true) {
    const candidate = path.join(dir, VAULT_FILE);
    if (fs.existsSync(candidate)) return candidate;
    const parent = path.dirname(dir);
    if (parent === dir) return null;
    dir = parent;
  }
}

export function createVault(dir?: string): string {
  const target = path.join(dir || process.cwd(), VAULT_FILE);
  if (fs.existsSync(target)) {
    throw new Error("vault already exists at " + target);
  }
  const salt = generateSalt();
  const vault: Vault = {
    version: 1,
    salt: salt.toString("base64"),
    secrets: {},
  };
  fs.writeFileSync(target, JSON.stringify(vault, null, 2) + "\n");
  return target;
}

function readVault(vaultPath: string): Vault {
  const raw = fs.readFileSync(vaultPath, "utf8");
  const parsed = JSON.parse(raw);
  if (parsed.version !== CURRENT_VERSION) {
    throw new Error("unsupported vault version: " + parsed.version);
  }
  return parsed as Vault;
}

function writeVault(vaultPath: string, vault: Vault): void {
  fs.writeFileSync(vaultPath, JSON.stringify(vault, null, 2) + "\n");
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
  const enc = vault.secrets[key];
  if (!enc) throw new Error("secret not found: " + key);
  const salt = Buffer.from(vault.salt, "base64");
  const dk = deriveKey(passphrase, salt);
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

export function getAllSecrets(vaultPath: string, passphrase: string): Record<string, string> {
  const vault = readVault(vaultPath);
  const salt = Buffer.from(vault.salt, "base64");
  const dk = deriveKey(passphrase, salt);
  const result: Record<string, string> = {};
  for (const [k, enc] of Object.entries(vault.secrets)) {
    result[k] = decrypt(enc, dk);
  }
  return result;
}
