import crypto from 'node:crypto';
import argon2 from 'argon2';
import { config } from './config.js';
const dataKey = Buffer.from(config.CONTACT_DATA_KEY, 'base64');
if (dataKey.length !== 32) throw new Error('CONTACT_DATA_KEY must be a base64-encoded 32-byte key');

export function hmac(value, pepper) { return crypto.createHmac('sha256', pepper).update(value).digest('hex'); }
export function otpCode() { return String(crypto.randomInt(0, 1_000_000)).padStart(6, '0'); }
export function recoverySecret() {
  const alphabet = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
  // 26 base-32 symbols carry 130 bits of entropy; rejection sampling avoids modulo bias.
  const bytes = crypto.randomBytes(26);
  let body = '';
  for (const b of bytes) body += alphabet[b & 31];
  return `CR-${body.match(/.{1,6}/g).join('-')}`;
}
export function opaqueToken() { return crypto.randomBytes(32).toString('base64url'); }
export async function hashSecret(secret) { return argon2.hash(secret, { type: argon2.argon2id, memoryCost: config.ARGON2_MEMORY_KIB, timeCost: config.ARGON2_TIME_COST, parallelism: config.ARGON2_PARALLELISM, secret: Buffer.from(config.RECOVERY_SECRET_PEPPER) }); }
export async function verifySecret(verifier, secret) { try { return await argon2.verify(verifier, secret, { secret: Buffer.from(config.RECOVERY_SECRET_PEPPER) }); } catch { return false; } }
export function hashSession(token) { return hmac(token, config.SESSION_PEPPER); }
export function hashOtp(code) { return hmac(code, config.OTP_PEPPER); }
export function lookupHash(value) { return hmac(value.trim().toLowerCase(), config.LOOKUP_PEPPER); }
export function encryptData(value) {
  const iv = crypto.randomBytes(12), cipher = crypto.createCipheriv('aes-256-gcm', dataKey, iv);
  const ciphertext = Buffer.concat([cipher.update(value, 'utf8'), cipher.final()]);
  return Buffer.concat([iv, cipher.getAuthTag(), ciphertext]).toString('base64');
}
export function decryptData(value) {
  const packed = Buffer.from(value, 'base64'), iv = packed.subarray(0, 12), tag = packed.subarray(12, 28), ciphertext = packed.subarray(28);
  const decipher = crypto.createDecipheriv('aes-256-gcm', dataKey, iv); decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(ciphertext), decipher.final()]).toString('utf8');
}
