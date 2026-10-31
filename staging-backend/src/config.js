import 'dotenv/config';
import { z } from 'zod';

const schema = z.object({
  NODE_ENV: z.enum(['development', 'test', 'production']).default('development'),
  PORT: z.coerce.number().int().positive().default(3000),
  TRUST_PROXY_HOPS: z.coerce.number().int().nonnegative().default(0),
  RECOVERY_DATABASE_URL: z.string().min(1),
  DB_SCHEMA: z.string()
    .regex(/^[a-z_][a-z0-9_]*$/, 'must be a lowercase PostgreSQL identifier')
    .refine(name => name !== 'public' && name !== 'pg_catalog' && name !== 'information_schema', 'must be a dedicated application schema')
    .default('corvon_recovery'),
  DATABASE_SSL: z.string().default('false'),
  CORS_ORIGINS: z.string().default('http://localhost:5173'),
  OTP_TTL_SECONDS: z.coerce.number().int().positive().default(300),
  OTP_MAX_ATTEMPTS: z.coerce.number().int().positive().default(5),
  LOGIN_MAX_FAILURES: z.coerce.number().int().positive().default(5),
  LOGIN_LOCK_SECONDS: z.coerce.number().int().positive().default(900),
  RECOVERY_SESSION_SECONDS: z.coerce.number().int().positive().default(1800),
  RECOVERY_REQUEST_SECONDS: z.coerce.number().int().positive().default(1800),
  LOCATION_INTERVAL_SECONDS: z.coerce.number().int().positive().default(60),
  LOCATION_STALE_SECONDS: z.coerce.number().int().positive().default(180),
  LOCATION_RETENTION_DAYS: z.coerce.number().int().positive().default(30),
  SESSION_TTL_SECONDS: z.coerce.number().int().positive().default(86400),
  REFRESH_TTL_SECONDS: z.coerce.number().int().positive().default(2592000),
  ARGON2_MEMORY_KIB: z.coerce.number().int().positive().default(19456),
  ARGON2_TIME_COST: z.coerce.number().int().positive().default(2),
  ARGON2_PARALLELISM: z.coerce.number().int().positive().default(1),
  OTP_PEPPER: z.string().min(32),
  LOOKUP_PEPPER: z.string().min(32),
  RECOVERY_SECRET_PEPPER: z.string().min(32),
  SESSION_PEPPER: z.string().min(32),
  CONTACT_DATA_KEY: z.string().min(43),
  TWILIO_ACCOUNT_SID: z.string().optional(), TWILIO_AUTH_TOKEN: z.string().optional(),
  TWILIO_FROM_NUMBER: z.string().optional(), RESEND_API_KEY: z.string().optional(), EMAIL_FROM: z.string().optional(),
  FIREBASE_SERVICE_ACCOUNT_JSON: z.string().optional(),
  RESEND_API_URL: z.string().url().default('https://api.resend.com/emails')
});

export function parseConfig(env) {
  const parsed = schema.safeParse(env);
  if (!parsed.success) {
    throw new Error(`Invalid environment configuration: ${parsed.error.issues.map(i => i.path.join('.') + ' ' + i.message).join('; ')}`);
  }
  if (env.DATABASE_URL && sameDatabasePrincipal(env.DATABASE_URL, parsed.data.RECOVERY_DATABASE_URL)) {
    throw new Error('Invalid environment configuration: RECOVERY_DATABASE_URL must use a separate restricted database role from DATABASE_URL');
  }
  return parsed.data;
}

function sameDatabasePrincipal(legacyUrl, recoveryUrl) {
  if (legacyUrl === recoveryUrl) return true;
  try {
    return new URL(legacyUrl).username === new URL(recoveryUrl).username;
  } catch {
    return false;
  }
}

export const config = parseConfig(process.env);
