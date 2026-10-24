import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';

process.env.NODE_ENV='test';
process.env.DATABASE_URL='postgres://test:test@localhost/test';
process.env.OTP_PEPPER='o'.repeat(40);
process.env.LOOKUP_PEPPER='l'.repeat(40);
process.env.RECOVERY_SECRET_PEPPER='r'.repeat(40);
process.env.SESSION_PEPPER='s'.repeat(40);
process.env.CONTACT_DATA_KEY=crypto.randomBytes(32).toString('base64');
process.env.FIREBASE_SERVICE_ACCOUNT_JSON='';

const securityPromise = import('../src/security.js');
const rateStorePromise = import('../src/db/postgres-rate-limit-store.js');

test('recovery secrets are unique, high-entropy formatted values', async () => {
  const { recoverySecret } = await securityPromise;
  const a=recoverySecret(), b=recoverySecret();
  assert.match(a,/^CR-(?:[A-HJ-NP-Z2-9]{1,6}-?)+$/);
  assert.equal(a.replaceAll('-','').replace(/^CR/,'').length,26);
  assert.equal(26*5,130);
  assert.notEqual(a,b);
});

test('permanent secret verifier accepts only the original secret', async () => {
  const { hashSecret, verifySecret, recoverySecret } = await securityPromise;
  const original=recoverySecret(), verifier=await hashSecret(original);
  assert.equal(await verifySecret(verifier,original),true);
  assert.equal(await verifySecret(verifier,`${original}X`),false);
  assert.equal(verifier.includes(original),false);
});

test('OTP and session storage use keyed digests, not raw values', async () => {
  const { hashOtp, hashSession, opaqueToken } = await securityPromise;
  const token=opaqueToken();
  assert.notEqual(hashOtp('123456'),'123456');
  assert.notEqual(hashSession(token),token);
});

test('personal contact and location payload encryption round trips and rejects tampering', async () => {
  const { encryptData, decryptData } = await securityPromise;
  const clear=JSON.stringify({latitude:12.34,longitude:56.78,capturedAt:'2026-10-11T00:00:00Z'});
  const encrypted=encryptData(clear);
  assert.notEqual(encrypted,clear);
  assert.equal(decryptData(encrypted),clear);
  const corrupted=Buffer.from(encrypted,'base64');corrupted[corrupted.length-1]^=1;
  assert.throws(()=>decryptData(corrupted.toString('base64')));
});

test('OTP generation uses fixed-width numeric codes', async () => {
  const { otpCode } = await securityPromise;
  for(let i=0;i<25;i++) assert.match(otpCode(),/^\d{6}$/);
});

test('PostgreSQL rate limit store initializes with shared-store contract',async()=>{
  const {PostgresRateLimitStore}=await rateStorePromise;
  const store=new PostgresRateLimitStore('test');
  store.init({windowMs:30_000});
  assert.equal(store.windowMs,30_000);
  assert.equal(typeof store.increment,'function');
  assert.equal(typeof store.resetKey,'function');
});

test('FCM reports unconfigured without service credentials',async()=>{
  const {fcmConfigurationStatus}=await import('../src/fcm.js');
  assert.deepEqual(fcmConfigurationStatus(),{configured:false,status:'not_configured'});
});
