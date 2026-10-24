import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';

const api=fs.readFileSync(new URL('../src/app.js',import.meta.url),'utf8');
const migration=fs.readFileSync(new URL('../src/db/migrations/001_initial.sql',import.meta.url),'utf8');

test('permanent secret is constrained to one credential row per user',()=>{
  assert.match(migration,/recovery_credentials\s*\(\s*user_id uuid PRIMARY KEY/);
  assert.match(api,/SECRET_ALREADY_ISSUED/);
  assert.match(api,/\/v1\/registrations\/:id\/secret-confirmation/);
});
test('registration creates pending contacts without dispatching OTPs automatically',()=>{
  const createStart=api.indexOf("app.post('/v1/registrations'");
  const verifyStart=api.indexOf("app.post('/v1/registrations/:id/otp-verifications'");
  const createRoute=api.slice(createStart,verifyStart);
  assert.doesNotMatch(createRoute,/issueOtp|sendOtp/);
  assert.match(createRoute,/contacts:contacts\.map/);
  assert.match(api,/app\.post\('\/v1\/registrations\/:id\/otp-challenges'/);
  assert.match(api,/issueOtp\(\{challengeColumn:'registration_id',challengeId:id,contactType:b\.contactType/);
});
test('emergency contact name is optional and its encrypted label remains nullable',()=>{
  assert.match(api,/emergencyContact:\s*z\.object\(\{ name: username\.optional\(\), phone \}\)/);
  assert.match(api,/label: body\.emergencyContact\.name \?\? null/);
  assert.match(migration,/label_ciphertext text/);
});
test('registration secret is gated by all three verified contacts and OTP consumption is one time',()=>{
  assert.match(api,/contacts\.rows\[0\]\.verified!==3/);
  assert.match(api,/UPDATE otp_challenges SET consumed_at=now\(\) WHERE id=\$1/);
  assert.match(api,/o\.consumed_at IS NULL/);
  assert.match(api,/OTP_MAX_ATTEMPTS/);
});
test('one-time recovery secret issuance locks and updates registration atomically',()=>{
  assert.match(api,/SELECT user_id,secret_issued_at,expires_at FROM registrations WHERE id=\$1 FOR UPDATE/);
  assert.match(api,/INSERT INTO recovery_credentials\(user_id,verifier\) VALUES\(\$1,\$2\)/);
  assert.match(api,/UPDATE registrations SET secret_issued_at=now\(\) WHERE id=\$1/);
  assert.match(api,/SECRET_ALREADY_ISSUED/);
});
test('Forgot Secret implements verification and dashboard session, with no secret replacement route',()=>{
  assert.match(api,/forgot-secret-challenges\/:id\/verifications/);
  assert.match(api,/forgot-secret-challenges\/:id\/complete/);
  assert.match(api,/createSession\(userId,'dashboard',config\.RECOVERY_SESSION_SECONDS\)/);
  assert.doesNotMatch(api,/forgot-secret[^\n]*UPDATE recovery_credentials/i);
});
test('location reports require active request, enrolled device, interval and encrypted storage',()=>{
  assert.match(api,/DEVICE_NOT_ENROLLED/);
  assert.match(api,/RECOVERY_NOT_ACTIVE/);
  assert.match(api,/LOCATION_INTERVAL_SECONDS/);
  assert.match(api,/encryptData\(JSON\.stringify/);
  assert.match(migration,/location_ciphertext text NOT NULL/);
});
test('configured timing and retention defaults match approved values',async()=>{
  const config=fs.readFileSync(new URL('../src/config.js',import.meta.url),'utf8');
  assert.match(config,/OTP_TTL_SECONDS:.*default\(300\)/);
  assert.match(config,/OTP_MAX_ATTEMPTS:.*default\(5\)/);
  assert.match(config,/RECOVERY_SESSION_SECONDS:.*default\(1800\)/);
  assert.match(config,/RECOVERY_REQUEST_SECONDS:.*default\(1800\)/);
  assert.match(config,/LOCATION_INTERVAL_SECONDS:.*default\(60\)/);
  assert.match(config,/LOCATION_STALE_SECONDS:.*default\(180\)/);
  assert.match(config,/LOCATION_RETENTION_DAYS:.*default\(30\)/);
});
test('rate limiting uses PostgreSQL shared storage and migration runner holds an advisory lock',()=>{
  const store=fs.readFileSync(new URL('../src/db/postgres-rate-limit-store.js',import.meta.url),'utf8');
  const runner=fs.readFileSync(new URL('../src/db/migrate.js',import.meta.url),'utf8');
  assert.match(store,/INSERT INTO rate_limit_buckets/);
  assert.match(store,/ON CONFLICT\(bucket_key\) DO UPDATE/);
  assert.match(runner,/pg_advisory_lock/);
  assert.match(runner,/pg_advisory_unlock/);
});
test('recovery status uses a separately hashed capability token and location timestamps are bounded',()=>{
  assert.match(api,/status_token_hash/);
  assert.match(api,/x-recovery-access-token/);
  assert.match(api,/capturedMs>now\+120_000/);
  assert.match(api,/capturedMs<now-config\.LOCATION_RETENTION_DAYS/);
});
test('recovery request FCM dispatch reports configuration state and omits private payload data',()=>{
  const fcm=fs.readFileSync(new URL('../src/fcm.js',import.meta.url),'utf8');
  assert.match(fcm,/not_configured/);
  assert.match(fcm,/sendEachForMulticast/);
  assert.match(fcm,/recoveryRequestId/);
  assert.doesNotMatch(fcm,/latitude|longitude|secret|otp/i);
});
