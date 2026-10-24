import crypto from 'node:crypto';
import { pool } from './pool.js';
import { config } from '../config.js';

// Shared across API instances. Persist only an HMAC of the IP/key, never the raw address.
export class PostgresRateLimitStore {
  constructor(prefix='api') { this.prefix=prefix; this.windowMs=60_000; }
  init(options) { this.windowMs=options.windowMs; }
  key(key) { return crypto.createHmac('sha256',config.SESSION_PEPPER).update(`${this.prefix}:${key}`).digest('hex'); }
  async increment(key) {
    const result=await pool.query(`INSERT INTO rate_limit_buckets(bucket_key,hits,reset_at)
      VALUES($1,1,now()+($2 * interval '1 millisecond'))
      ON CONFLICT(bucket_key) DO UPDATE SET
        hits=CASE WHEN rate_limit_buckets.reset_at<=now() THEN 1 ELSE rate_limit_buckets.hits+1 END,
        reset_at=CASE WHEN rate_limit_buckets.reset_at<=now() THEN now()+($2 * interval '1 millisecond') ELSE rate_limit_buckets.reset_at END
      RETURNING hits,reset_at`,[this.key(key),this.windowMs]);
    return {totalHits:result.rows[0].hits,resetTime:new Date(result.rows[0].reset_at)};
  }
  async decrement(key) {
    const hashed=this.key(key);
    await pool.query('DELETE FROM rate_limit_buckets WHERE bucket_key=$1 AND hits<=1',[hashed]);
    await pool.query('UPDATE rate_limit_buckets SET hits=hits-1 WHERE bucket_key=$1 AND hits>1',[hashed]);
  }
  async resetKey(key) { await pool.query('DELETE FROM rate_limit_buckets WHERE bucket_key=$1',[this.key(key)]); }
}
