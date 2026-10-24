import fs from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { pool } from './pool.js';
import { config } from '../config.js';

const dir = path.join(path.dirname(fileURLToPath(import.meta.url)), 'migrations');
const MIGRATION_LOCK_KEY = '739184650231';
const client = await pool.connect();
try {
  await client.query('SELECT pg_advisory_lock($1::bigint)', [MIGRATION_LOCK_KEY]);
  const schemaState = await client.query(
    'SELECT current_schema() AS active_schema, EXISTS (SELECT 1 FROM pg_namespace WHERE nspname = $1) AS schema_exists',
    [config.DB_SCHEMA]
  );
  if (!schemaState.rows[0].schema_exists || schemaState.rows[0].active_schema !== config.DB_SCHEMA) {
    throw new Error(`Configured database schema is unavailable or not active: ${config.DB_SCHEMA}`);
  }
  await client.query('CREATE TABLE IF NOT EXISTS schema_migrations (name text PRIMARY KEY, applied_at timestamptz NOT NULL DEFAULT now())');
  const ledger = await client.query(
    `SELECT n.nspname AS schema_name FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace WHERE c.oid = to_regclass('schema_migrations')`
  );
  if (ledger.rows[0]?.schema_name !== config.DB_SCHEMA) {
    throw new Error(`Migration ledger is not in configured schema: ${config.DB_SCHEMA}`);
  }
  const applied = new Set((await client.query('SELECT name FROM schema_migrations')).rows.map(r => r.name));
  for (const name of (await fs.readdir(dir)).filter(n => n.endsWith('.sql')).sort()) {
    if (applied.has(name)) continue;
    const sql = await fs.readFile(path.join(dir, name), 'utf8');
    try { await client.query('BEGIN'); await client.query(sql); await client.query('INSERT INTO schema_migrations(name) VALUES ($1)', [name]); await client.query('COMMIT'); console.log(`Applied migration ${name}`); }
    catch (error) { await client.query('ROLLBACK'); throw error; }
  }
} catch (error) { console.error(`Migration failed: ${error.message}`); process.exitCode = 1; }
finally {
  try { await client.query('SELECT pg_advisory_unlock($1::bigint)', [MIGRATION_LOCK_KEY]); } catch {}
  client.release();
  await pool.end();
}
