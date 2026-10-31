const test = require('node:test');
const assert = require('node:assert/strict');
const express = require('express');
const { hasRecoveryConfiguration, mountRecoveryApi } = require('../recovery-host.cjs');

const silentLogger = { warn() {}, error() {} };
const recoverySettings = {
  RECOVERY_DATABASE_URL: 'postgres://recovery-role:placeholder@localhost/recovery',
  OTP_PEPPER: 'o'.repeat(32),
  LOOKUP_PEPPER: 'l'.repeat(32),
  RECOVERY_SECRET_PEPPER: 'r'.repeat(32),
  SESSION_PEPPER: 's'.repeat(32),
  CONTACT_DATA_KEY: 'c'.repeat(44),
};

test('legacy DATABASE_URL alone cannot enable or be used as the Recovery connection', () => {
  assert.equal(hasRecoveryConfiguration({ DATABASE_URL: 'postgres://legacy@localhost/legacy' }), false);
  assert.equal(hasRecoveryConfiguration({ ...recoverySettings, DATABASE_URL: recoverySettings.RECOVERY_DATABASE_URL }), false);
  assert.equal(hasRecoveryConfiguration({ ...recoverySettings, DATABASE_URL: 'postgres://same-role@legacy/db', RECOVERY_DATABASE_URL: 'postgres://same-role@recovery/db' }), false);
});

test('missing Recovery settings keep the host alive and return explicit 503 for /v1', async () => {
  const app = express();
  let imported = false;
  const ready = await mountRecoveryApi(app, {
    env: { DATABASE_URL: 'postgres://legacy@localhost/legacy' },
    importer: async () => { imported = true; throw new Error('must not import'); },
    logger: silentLogger,
  });
  assert.equal(ready, false);
  assert.equal(imported, false);
  const server = app.listen(0, '127.0.0.1');
  await new Promise(resolve => server.once('listening', resolve));
  try {
    const response = await fetch(`http://127.0.0.1:${server.address().port}/v1/sessions`);
    assert.equal(response.status, 503);
    assert.equal((await response.json()).error.code, 'RECOVERY_API_UNAVAILABLE');
  } finally {
    await new Promise(resolve => server.close(resolve));
  }
});

test('complete Recovery configuration mounts the supplied Recovery app', async () => {
  assert.equal(hasRecoveryConfiguration(recoverySettings), true);
  const recoveryApp = express();
  recoveryApp.get('/v1/probe', (_req, res) => res.json({ api: 'recovery' }));
  const app = express();
  const ready = await mountRecoveryApi(app, {
    env: recoverySettings,
    importer: async () => ({ app: recoveryApp }),
    logger: silentLogger,
  });
  assert.equal(ready, true);
  const server = app.listen(0, '127.0.0.1');
  await new Promise(resolve => server.once('listening', resolve));
  try {
    const response = await fetch(`http://127.0.0.1:${server.address().port}/v1/probe`);
    assert.deepEqual(await response.json(), { api: 'recovery' });
  } finally {
    await new Promise(resolve => server.close(resolve));
  }
});

test('invalid Recovery module configuration disables /v1 rather than falling back', async () => {
  const app = express();
  const ready = await mountRecoveryApi(app, {
    env: recoverySettings,
    importer: async () => { throw new Error('config failure'); },
    logger: silentLogger,
  });
  assert.equal(ready, false);
  const server = app.listen(0, '127.0.0.1');
  await new Promise(resolve => server.once('listening', resolve));
  try {
    const response = await fetch(`http://127.0.0.1:${server.address().port}/v1/registrations`);
    assert.equal(response.status, 503);
    assert.equal((await response.json()).error.code, 'RECOVERY_API_UNAVAILABLE');
  } finally {
    await new Promise(resolve => server.close(resolve));
  }
});
