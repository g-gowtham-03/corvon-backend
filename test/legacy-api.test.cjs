const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const express = require('express');
const { createLegacyRouter } = require('../legacy-api.cjs');

const logger = { info() {}, warn() {}, error() {} };

async function withLegacyApi(pool, run) {
  const app = express();
  app.use(express.json());
  app.use(createLegacyRouter(pool, logger));
  const server = app.listen(0, '127.0.0.1');
  await new Promise(resolve => server.once('listening', resolve));
  const address = server.address();
  try {
    await run(`http://127.0.0.1:${address.port}`);
  } finally {
    await new Promise((resolve, reject) => server.close(error => error ? reject(error) : resolve()));
  }
}

function fakePool(handler) {
  const calls = [];
  return {
    calls,
    async query(sql, values = []) {
      calls.push({ sql: sql.replace(/\s+/g, ' ').trim(), values });
      return handler(sql, values, calls.length);
    }
  };
}

test('legacy POST /register preserves request and success response contract', async () => {
  const pool = fakePool(async () => ({ rows: [] }));
  await withLegacyApi(pool, async base => {
    const response = await fetch(`${base}/register`, {
      method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ phoneNumber: '+15551234567', emergencyContact: '+15557654321', credentialHash: 'hash', fcmToken: 'token' })
    });
    assert.equal(response.status, 200);
    assert.deepEqual(await response.json(), { success: true, message: 'Device registered' });
  });
  assert.match(pool.calls[0].sql, /INSERT INTO devices/);
});

test('legacy POST /recover preserves valid recovery response and writes the pending command', async () => {
  const phoneNumber = '+15551234567';
  const credential = 'legacy-secret';
  const credentialHash = crypto.createHash('sha256').update(credential + phoneNumber).digest('hex');
  const pool = fakePool(async sql => {
    if (sql.includes('SELECT * FROM devices')) return { rows: [{ phone_number: phoneNumber, credential_hash: credentialHash, fail_count: 0, locked_until: null }] };
    return { rows: [] };
  });
  await withLegacyApi(pool, async base => {
    const response = await fetch(`${base}/recover`, {
      method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ phoneNumber, credential })
    });
    assert.equal(response.status, 200);
    assert.deepEqual(await response.json(), { success: true, message: 'Recovery command dispatched.' });
  });
  assert.ok(pool.calls.some(call => call.sql.includes('INSERT INTO pending_commands')));
});

test('legacy POST /recover preserves invalid-credential status and response', async () => {
  const pool = fakePool(async sql => sql.includes('SELECT * FROM devices')
    ? { rows: [{ credential_hash: 'not-the-submitted-hash', fail_count: 0, locked_until: null }] }
    : { rows: [] });
  await withLegacyApi(pool, async base => {
    const response = await fetch(`${base}/recover`, {
      method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ phoneNumber: '+15551234567', credential: 'wrong' })
    });
    assert.equal(response.status, 401);
    assert.deepEqual(await response.json(), { error: 'Invalid credential' });
  });
  assert.ok(!pool.calls.some(call => call.sql.includes('INSERT INTO pending_commands')));
});

test('legacy GET /status preserves pending and location response formats', async () => {
  const pool = fakePool(async sql => sql.includes('FROM location_reports')
    ? { rows: [{ latitude: 12.5, longitude: 77.6, accuracy: 9, timestamp: 'captured-time' }] }
    : { rows: [] });
  await withLegacyApi(pool, async base => {
    const response = await fetch(`${base}/status?phoneNumber=%2B15551234567`);
    assert.equal(response.status, 200);
    assert.equal(response.headers.get('access-control-allow-origin'), '*');
    assert.deepEqual(await response.json(), {
      status: 'LOCATION_RECEIVED',
      location: { latitude: 12.5, longitude: 77.6, accuracy: 9, timestamp: 'captured-time' }
    });
  });
  const emptyPool = fakePool(async () => ({ rows: [] }));
  await withLegacyApi(emptyPool, async base => {
    const response = await fetch(`${base}/status?phoneNumber=%2B15551234567`);
    assert.deepEqual(await response.json(), { status: 'PENDING', location: null });
  });
});

test('remaining legacy routes are still registered and preserve representative response contracts', async () => {
  const pool = fakePool(async sql => {
    if (sql.includes('SELECT has_command')) return { rows: [{ has_command: true }] };
    if (sql.includes('SELECT * FROM devices')) return { rows: [{ phone_number: '+15551234567' }] };
    if (sql.includes('SELECT phone_number FROM devices')) return { rows: [{ phone_number: '+15551234567' }] };
    return { rows: [] };
  });
  await withLegacyApi(pool, async base => {
    const command = await fetch(`${base}/checkCommand?phoneNumber=%2B15551234567`);
    assert.deepEqual(await command.json(), { hasCommand: true });
    const report = await fetch(`${base}/locationReport`, {
      method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ phoneNumber: '+15551234567', latitude: 1, longitude: 2, accuracy: 3, timestamp: 't' })
    });
    assert.equal(report.status, 200);
    assert.deepEqual(await report.json(), { success: true });
    const relay = await fetch(`${base}/relayLocation?phone=%2B15551234567&lat=1&lng=2`);
    assert.equal(relay.status, 200);
    assert.match(await relay.text(), /Location shared with owner/);
    const devices = await fetch(`${base}/devices`);
    assert.deepEqual(await devices.json(), { devices: ['+15551234567'] });
  });
});
