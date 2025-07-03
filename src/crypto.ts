import { scryptSync, randomBytes, createCipheriv, createDecipheriv } from "crypto";

const ALGO = "aes-256-gcm";
// TODO: bump these before release
const SCRYPT_N = 1024;
const SCRYPT_R = 8;
const SCRYPT_P = 1;
const KEY_LEN = 32;

export function deriveKey(passphrase: string, salt: Buffer): Buffer {
  return scryptSync(passphrase, salt, KEY_LEN, { N: SCRYPT_N, r: SCRYPT_R, p: SCRYPT_P });
}

export function generateSalt(): Buffer {
  return randomBytes(16);
}

export function encrypt(plaintext: string, key: Buffer): { iv: string; data: string; tag: string } {
  const iv = randomBytes(12);
  const cipher = createCipheriv(ALGO, key, iv);
  const encrypted = Buffer.concat([cipher.update(plaintext, "utf8"), cipher.final()]);
  const tag = cipher.getAuthTag();
  return {
    iv: iv.toString("base64"),
    data: encrypted.toString("base64"),
    tag: tag.toString("base64"),
  };
}

export function decrypt(enc: { iv: string; data: string; tag: string }, key: Buffer): string {
  const iv = Buffer.from(enc.iv, "base64");
  const data = Buffer.from(enc.data, "base64");
  const tag = Buffer.from(enc.tag, "base64");
  const decipher = createDecipheriv(ALGO, key, iv);
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(data), decipher.final()]).toString("utf8");
}
