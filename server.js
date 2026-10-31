const express = require('express');
const cors = require('cors');
const { Pool } = require('pg');
const path = require('node:path');
require('dotenv').config({ path: path.join(__dirname, 'staging-backend', '.env') });
const { createLegacyRouter } = require('./legacy-api.cjs');
const { mountRecoveryApi } = require('./recovery-host.cjs');

const app = express();
app.disable('x-powered-by');

const legacyPool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false },
});

async function initializeLegacyDatabase() {
  await legacyPool.query([
    'CREATE TABLE IF NOT EXISTS devices (',
    '  phone_number TEXT PRIMARY KEY,',
    '  emergency_contact TEXT NOT NULL,',
    '  credential_hash TEXT NOT NULL,',
    "  fcm_token TEXT DEFAULT '',",
    '  registered_at TIMESTAMPTZ DEFAULT NOW(),',
    '  fail_count INTEGER DEFAULT 0,',
    '  locked_until TIMESTAMPTZ NULL',
    ')'
  ].join('\n'));
  await legacyPool.query([
    'CREATE TABLE IF NOT EXISTS location_reports (',
    '  id SERIAL PRIMARY KEY,',
    '  phone_number TEXT NOT NULL,',
    '  latitude DOUBLE PRECISION NOT NULL,',
    '  longitude DOUBLE PRECISION NOT NULL,',
    '  accuracy DOUBLE PRECISION,',
    '  timestamp TEXT,',
    '  received_at TIMESTAMPTZ DEFAULT NOW(),',
    "  source TEXT DEFAULT 'direct'",
    ')'
  ].join('\n'));
  await legacyPool.query([
    'CREATE TABLE IF NOT EXISTS pending_commands (',
    '  phone_number TEXT PRIMARY KEY,',
    '  has_command BOOLEAN DEFAULT FALSE,',
    '  created_at TIMESTAMPTZ DEFAULT NOW()',
    ')'
  ].join('\n'));
  console.log('[legacy] database tables ready');
}

async function start() {
  // The Recovery sub-app owns its parser, CORS policy, authentication, and isolated DB pool.
  // It must be mounted before the legacy JSON parser and is never given DATABASE_URL.
  await mountRecoveryApi(app);

  // Keep legacy middleware and URL contracts available to the existing portal/app.
  app.use(cors());
  app.use(express.json());
  app.use(createLegacyRouter(legacyPool));

  initializeLegacyDatabase().catch(() => {
    console.error('[legacy] database initialization failed');
  });

  const port = process.env.PORT || 3000;
  const server = app.listen(port, '0.0.0.0', () => {
    console.log('CORVON backend listening on configured port');
  });

  let stopping = false;
  async function shutdown() {
    if (stopping) return;
    stopping = true;
    server.close(async () => {
      await legacyPool.end().catch(() => {});
      try {
        const recoveryDb = await import('./staging-backend/src/db/pool.js');
        await recoveryDb.pool.end();
      } catch {
        // Recovery may be disabled or misconfigured; legacy shutdown still completes.
      }
      process.exit(0);
    });
  }
  process.on('SIGINT', shutdown);
  process.on('SIGTERM', shutdown);
}

start().catch(() => {
  // A recovery API configuration problem must not prevent legacy service startup.
  console.error('[server] startup failed');
  process.exitCode = 1;
});

module.exports = { app, legacyPool };
