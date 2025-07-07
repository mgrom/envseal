import { scryptSync, randomBytes, createCipheriv, createDecipheriv } from "crypto";

const ALGO = "aes-256-gcm";
const SCRYPT_N = 2 ** 15;
const SCRYPT_R = 8;
const SCRYPT_P = 1;
const KEY_LEN = 32;
const IV_LEN = 12;
const SALT_LEN = 16; // 128 bits

export interface EncryptedValue {
  iv: string;
  data: string;
  tag: string;
}

export function deriveKey(passphrase: string, salt: Buffer): Buffer {
  return scryptSync(passphrase, salt, KEY_LEN, {
    N: SCRYPT_N,
    r: SCRYPT_R,
    p: SCRYPT_P,
    maxmem: 128 * SCRYPT_N * SCRYPT_R,
  });
}

export function generateSalt(): Buffer {
  return randomBytes(SALT_LEN);
}

export function encrypt(plaintext: string, key: Buffer): EncryptedValue {
  const iv = randomBytes(IV_LEN);
  const cipher = createCipheriv(ALGO, key, iv);
  const encrypted = Buffer.concat([cipher.update(plaintext, "utf8"), cipher.final()]);
  const tag = cipher.getAuthTag();
  return {
    iv: iv.toString("base64"),
    data: encrypted.toString("base64"),
    tag: tag.toString("base64"),
  };
}

export function decrypt(enc: EncryptedValue, key: Buffer): string {
  const iv = Buffer.from(enc.iv, "base64");
  const data = Buffer.from(enc.data, "base64");
  const tag = Buffer.from(enc.tag, "base64");
  const decipher = createDecipheriv(ALGO, key, iv);
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(data), decipher.final()]).toString("utf8");
}
