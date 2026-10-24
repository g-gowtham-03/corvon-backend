import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';

process.env.NODE_ENV = 'test';
process.env.DATABASE_URL = 'postgres://test:test@localhost/test';
process.env.OTP_PEPPER = 'o'.repeat(40);
process.env.LOOKUP_PEPPER = 'l'.repeat(40);
process.env.RECOVERY_SECRET_PEPPER = 'r'.repeat(40);
process.env.SESSION_PEPPER = 's'.repeat(40);
process.env.CONTACT_DATA_KEY = crypto.randomBytes(32).toString('base64');
process.env.DB_SCHEMA = 'corvon_recovery';

const [{ parseConfig }, { poolOptionsFor }] = await Promise.all([
  import('../src/config.js'),
  import('../src/db/pool.js')
]);

function envWith(overrides = {}) {
  return { ...process.env, ...overrides };
}

test('DB_SCHEMA defaults to the dedicated non-public recovery schema', () => {
  const env = envWith();
  delete env.DB_SCHEMA;
  assert.equal(parseConfig(env).DB_SCHEMA, 'corvon_recovery');
});

test('DB_SCHEMA accepts only safe lowercase PostgreSQL identifiers', () => {
  for (const value of ['corvon_recovery', '_recovery2', 'a']) {
    assert.equal(parseConfig(envWith({ DB_SCHEMA: value })).DB_SCHEMA, value);
  }
  for (const value of ['', 'public', 'Corvon', 'recovery schema', 'recovery;DROP SCHEMA public', 'a.b', '2recovery']) {
    assert.throws(() => parseConfig(envWith({ DB_SCHEMA: value })), /Invalid environment configuration/);
  }
});

test('every pool connection receives a single-schema search_path without public fallback', () => {
  const options = poolOptionsFor({
    DATABASE_URL: 'postgres://test:test@localhost/test',
    DATABASE_SSL: 'false',
    DB_SCHEMA: 'corvon_recovery'
  });
  assert.equal(options.options, '-c search_path=corvon_recovery');
  assert.doesNotMatch(options.options, /public|,/i);
});

test('migration ledger and unqualified application SQL stay within the configured pool schema', () => {
  const runner = fs.readFileSync(new URL('../src/db/migrate.js', import.meta.url), 'utf8');
  const runtimeFiles = [
    '../src/app.js',
    '../src/server.js',
    '../src/db/postgres-rate-limit-store.js',
    '../src/db/migrations/001_initial.sql',
    '../src/db/migrations/002_shared_rate_limits.sql'
  ];
  assert.match(runner, /current_schema\(\).*active_schema/s);
  assert.match(runner, /config\.DB_SCHEMA/);
  assert.match(runner, /CREATE TABLE IF NOT EXISTS schema_migrations/);
  assert.match(runner, /to_regclass\('schema_migrations'\)/);
  for (const file of runtimeFiles) {
    const sql = fs.readFileSync(new URL(file, import.meta.url), 'utf8');
    assert.doesNotMatch(sql, /\bpublic\s*\./i, `${file} must not address public explicitly`);
  }
});
