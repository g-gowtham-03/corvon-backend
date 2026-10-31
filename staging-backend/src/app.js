import express from 'express';
import helmet from 'helmet';
import cors from 'cors';
import { rateLimit } from 'express-rate-limit';
import { z } from 'zod';
import crypto from 'node:crypto';
import { pool } from './db/pool.js';
import { config } from './config.js';
import { decryptData, encryptData, hashOtp, hashSecret, hashSession, lookupHash, opaqueToken, otpCode, recoverySecret, verifySecret } from './security.js';
import { sendOtp } from './delivery.js';
import { sendRecoveryRequest, sendRecoveryRequestStopped } from './fcm.js';
import { PostgresRateLimitStore } from './db/postgres-rate-limit-store.js';

const app = express();
app.disable('x-powered-by');
app.set('trust proxy', config.TRUST_PROXY_HOPS);
app.use(helmet());
app.use(cors({ origin: config.CORS_ORIGINS.split(',').map(x => x.trim()), credentials: true }));
app.use(express.json({ limit: '16kb' }));
app.use((req, res, next) => { req.requestId = cryptoRandomId(); res.setHeader('X-Request-Id', req.requestId); next(); });
app.use('/v1', rateLimit({ windowMs: 60_000, limit: 120, standardHeaders: true, legacyHeaders: false, store: new PostgresRateLimitStore('global') }));
const registrationLimiter=rateLimit({windowMs:60*60_000,limit:10,standardHeaders:true,legacyHeaders:false,store:new PostgresRateLimitStore('registration')});
const loginIpLimiter=rateLimit({windowMs:60*60_000,limit:30,standardHeaders:true,legacyHeaders:false,store:new PostgresRateLimitStore('login-ip')});
const recoverySecretLimiter=rateLimit({windowMs:15*60_000,limit:10,standardHeaders:true,legacyHeaders:false,store:new PostgresRateLimitStore('recovery-secret')});
const forgotLimiter=rateLimit({windowMs:15*60_000,limit:5,standardHeaders:true,legacyHeaders:false,store:new PostgresRateLimitStore('forgot-secret')});

const phone = z.string().trim().regex(/^\+[1-9]\d{7,14}$/);
const email = z.string().trim().email().max(254);
const username = z.string().trim().min(1).max(80);
const secret = z.string().min(10).max(200);
const uuid = z.string().uuid();
const contactsSchema = z.object({
  username,
  phone,
  email,
  emergencyContact: z.object({ name: username.optional(), phone })
});

function cryptoRandomId() { return `req_${crypto.randomUUID()}`; }
function fail(res, status, code, message = 'The request could not be completed.') { return res.status(status).json({ error: { code, message, requestId: res.getHeader('X-Request-Id') } }); }
function parse(schema, input) { const result = schema.safeParse(input); return result.success ? result.data : null; }
function normalizeContacts(body) {
  return [
    { type: 'phone', value: body.phone, label: null },
    { type: 'email', value: body.email.toLowerCase(), label: null },
    { type: 'emergency', value: body.emergencyContact.phone, label: body.emergencyContact.name ?? null }
  ];
}
async function transaction(fn) {
  const client = await pool.connect();
  try { await client.query('BEGIN'); const out = await fn(client); await client.query('COMMIT'); return out; }
  catch (e) { await client.query('ROLLBACK'); throw e; } finally { client.release(); }
}
async function createSession(userId, scope, seconds, deviceId = null, kind = 'access', familyId = crypto.randomUUID()) {
  const token = opaqueToken();
  await pool.query('INSERT INTO sessions(user_id, token_hash, scope, device_id, token_kind, session_family, expires_at) VALUES($1,$2,$3,$4,$5,$6,now()+($7 * interval \'1 second\'))', [userId, hashSession(token), scope, deviceId, kind, familyId, seconds]);
  return { token, expiresAt: new Date(Date.now() + seconds * 1000).toISOString(), scope, familyId };
}
async function auth(req, res, next) {
  const value = req.get('authorization') || '';
  if (!value.startsWith('Bearer ')) return fail(res, 401, 'UNAUTHORIZED');
  const result = await pool.query(`SELECT s.id AS session_id,s.session_family,s.user_id,s.scope,s.device_id FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token_hash=$1 AND s.token_kind='access' AND s.revoked_at IS NULL AND s.expires_at>now() AND u.status='active'`, [hashSession(value.slice(7))]);
  if (!result.rowCount) return fail(res, 401, 'UNAUTHORIZED');
  req.session = result.rows[0]; next();
}
function requireScope(...scopes) { return (req,res,next) => scopes.includes(req.session.scope) ? next() : fail(res,403,'INSUFFICIENT_SESSION_SCOPE'); }
async function issueOtp({ challengeColumn, challengeId, contactType, destination, destinationHash }) {
  const idColumn = challengeColumn === 'registration_id' ? 'registration_id' : 'recovery_challenge_id';
  const code = otpCode();
  const client=await pool.connect();
  try {
    await client.query('BEGIN');
    await client.query('SELECT pg_advisory_xact_lock(hashtext($1)::bigint)',[`${contactType}:${destinationHash}`]);
    const recent = await client.query(`SELECT count(*)::int AS n FROM otp_dispatches WHERE destination_hash=$1 AND contact_type=$2 AND sent_at>now()-interval '15 minutes'`, [destinationHash,contactType]);
    if (recent.rows[0].n >= 3) throw new Error('OTP_RATE_LIMITED');
    // Count attempted delivery before calling the provider, including provider failures.
    await client.query(`INSERT INTO otp_dispatches(${idColumn},contact_type,destination_hash) VALUES($1,$2,$3)`, [challengeId,contactType,destinationHash]);
    await client.query(`UPDATE otp_challenges SET consumed_at=now() WHERE ${idColumn}=$1 AND contact_type=$2 AND consumed_at IS NULL`, [challengeId, contactType]);
    await client.query(`INSERT INTO otp_challenges(${idColumn},contact_type,destination_hash,verifier,expires_at) VALUES($1,$2,$3,$4,now()+($5 * interval '1 second'))`, [challengeId, contactType, destinationHash, hashOtp(code), config.OTP_TTL_SECONDS]);
    await client.query('COMMIT');
  } catch(e) { await client.query('ROLLBACK'); throw e; }
  finally { client.release(); }
  // Deliberately never log destination, OTP, provider response body, or secret.
  await sendOtp({ type: contactType === 'email' ? 'email' : 'sms', destination, code });
}

app.get('/health', async (_req,res) => {
  try { await pool.query('SELECT 1'); return res.json({ status: 'ok' }); }
  catch { return fail(res,503,'DATABASE_UNAVAILABLE'); }
});

app.post('/v1/registrations', registrationLimiter, async (req,res) => {
  const body=parse(contactsSchema,req.body); if(!body) return fail(res,400,'INVALID_REQUEST');
  try {
    const contacts=normalizeContacts(body); const reg=await transaction(async c=>{
      const u=await c.query('INSERT INTO users(username) VALUES($1) RETURNING id',[body.username]); const userId=u.rows[0].id;
      for(const contact of contacts) await c.query('INSERT INTO user_contacts(user_id,contact_type,value_ciphertext,label_ciphertext,lookup_hash) VALUES($1,$2,$3,$4,$5)',[userId,contact.type,encryptData(contact.value),contact.label?encryptData(contact.label):null,lookupHash(contact.value)]);
      const r=await c.query("INSERT INTO registrations(user_id,expires_at) VALUES($1,now()+interval '30 minutes') RETURNING id,expires_at",[userId]); return { userId, id:r.rows[0].id, expiresAt:r.rows[0].expires_at };
    });
    return res.status(201).json({
      registrationId:reg.id,
      status:'pending_verification',
      expiresAt:reg.expiresAt,
      contacts:contacts.map(c=>({contactType:c.type,verified:false}))
    });
  } catch(e) { if(e.code==='23505') return fail(res,409,'CONTACT_ALREADY_REGISTERED'); return fail(res,500,'INTERNAL_ERROR'); }
});

app.post('/v1/registrations/:id/otp-verifications',async(req,res)=>{
  const id=uuid.safeParse(req.params.id).success?req.params.id:null; const b=parse(z.object({contactType:z.enum(['phone','email','emergency']),code:z.string().regex(/^\d{6}$/)}),req.body); if(!id||!b)return fail(res,400,'INVALID_REQUEST');
  try { const result=await transaction(async c=>{
    const q=await c.query('SELECT o.id,o.verifier,o.attempts,o.expires_at FROM otp_challenges o JOIN registrations r ON r.id=o.registration_id WHERE r.id=$1 AND r.expires_at>now() AND o.contact_type=$2 AND o.consumed_at IS NULL ORDER BY o.created_at DESC LIMIT 1 FOR UPDATE OF o',[id,b.contactType]);
    if(!q.rowCount)return {ok:false}; const o=q.rows[0]; if(o.attempts>=config.OTP_MAX_ATTEMPTS||new Date(o.expires_at)<new Date()){await c.query('UPDATE otp_challenges SET consumed_at=now() WHERE id=$1',[o.id]);return {ok:false};}
    if(hashOtp(b.code)!==o.verifier){await c.query('UPDATE otp_challenges SET attempts=attempts+1 WHERE id=$1',[o.id]);return {ok:false};}
    await c.query('UPDATE otp_challenges SET consumed_at=now(),verified_at=now() WHERE id=$1',[o.id]); await c.query('UPDATE user_contacts SET verified_at=now() WHERE user_id=(SELECT user_id FROM registrations WHERE id=$1) AND contact_type=$2',[id,b.contactType]);return {ok:true};
  }); if(!result.ok)return fail(res,400,'OTP_INVALID_OR_EXPIRED');
    const left=await pool.query('SELECT contact_type FROM user_contacts WHERE user_id=(SELECT user_id FROM registrations WHERE id=$1) AND verified_at IS NULL',[id]); return res.json({contactType:b.contactType,verified:true,remainingContacts:left.rows.map(x=>x.contact_type)});
  } catch { return fail(res,500,'INTERNAL_ERROR'); }
});
app.post('/v1/registrations/:id/otp-challenges',async(req,res)=>{
  const id=uuid.safeParse(req.params.id).success?req.params.id:null;const b=parse(z.object({contactType:z.enum(['phone','email','emergency'])}),req.body);if(!id||!b)return fail(res,400,'INVALID_REQUEST');
  try{const q=await pool.query(`SELECT c.value_ciphertext,c.lookup_hash FROM registrations r JOIN users u ON u.id=r.user_id JOIN user_contacts c ON c.user_id=u.id WHERE r.id=$1 AND r.expires_at>now() AND r.secret_issued_at IS NULL AND c.contact_type=$2 AND c.verified_at IS NULL`,[id,b.contactType]);if(!q.rowCount)return fail(res,400,'CHALLENGE_UNAVAILABLE');await issueOtp({challengeColumn:'registration_id',challengeId:id,contactType:b.contactType,destination:decryptData(q.rows[0].value_ciphertext),destinationHash:q.rows[0].lookup_hash});return res.status(202).json({contactType:b.contactType,expiresInSeconds:config.OTP_TTL_SECONDS});}catch(e){if(e.message?.includes('DELIVERY'))return fail(res,503,'OTP_DELIVERY_UNAVAILABLE');if(e.message==='OTP_RATE_LIMITED')return fail(res,429,'OTP_RATE_LIMITED');return fail(res,500,'INTERNAL_ERROR');}
});

app.post('/v1/registrations/:id/secret',async(req,res)=>{
  const id=uuid.safeParse(req.params.id).success?req.params.id:null;if(!id)return fail(res,400,'INVALID_REQUEST');
  try { const result=await transaction(async c=>{
      const registration=await c.query('SELECT user_id,secret_issued_at,expires_at FROM registrations WHERE id=$1 FOR UPDATE',[id]);
      if(!registration.rowCount||new Date(registration.rows[0].expires_at)<new Date())return {error:'REGISTRATION_NOT_READY'};
      if(registration.rows[0].secret_issued_at)return {error:'SECRET_ALREADY_ISSUED'};
      const contacts=await c.query('SELECT count(*)::int AS total,count(*) FILTER (WHERE verified_at IS NOT NULL)::int AS verified FROM user_contacts WHERE user_id=$1',[registration.rows[0].user_id]);
      if(contacts.rows[0].total!==3||contacts.rows[0].verified!==3)return {error:'REGISTRATION_NOT_READY'};
      // The registration row lock serializes issuance. Persist the verifier and
      // issued marker in one transaction so failures cannot strand the account.
      const generated=recoverySecret(),verifier=await hashSecret(generated);
      await c.query('INSERT INTO recovery_credentials(user_id,verifier) VALUES($1,$2)',[registration.rows[0].user_id,verifier]);
      await c.query('UPDATE registrations SET secret_issued_at=now() WHERE id=$1',[id]);
      return {secret:generated};
    });
    if(result.error)return fail(res,409,result.error);
    return res.status(201).json({secret:result.secret,confirmationRequired:true});
  } catch { return fail(res,500,'INTERNAL_ERROR'); }
});

app.post('/v1/registrations/:id/secret-confirmation',async(req,res)=>{
  const id=uuid.safeParse(req.params.id).success?req.params.id:null;const b=parse(z.object({secret}),req.body);if(!id||!b)return fail(res,400,'INVALID_REQUEST');
  try { const q=await pool.query('SELECT r.user_id,c.verifier,c.confirmed_at FROM registrations r JOIN recovery_credentials c ON c.user_id=r.user_id WHERE r.id=$1 AND r.secret_issued_at IS NOT NULL',[id]);if(!q.rowCount)return fail(res,404,'REGISTRATION_NOT_FOUND');if(q.rows[0].confirmed_at)return fail(res,409,'ALREADY_CONFIRMED');
    if(!await verifySecret(q.rows[0].verifier,b.secret))return fail(res,400,'SECRET_CONFIRMATION_FAILED');
    await transaction(async c=>{await c.query('UPDATE recovery_credentials SET confirmed_at=now() WHERE user_id=$1 AND confirmed_at IS NULL',[q.rows[0].user_id]);await c.query("UPDATE users SET status='active',updated_at=now() WHERE id=$1",[q.rows[0].user_id]);await c.query('UPDATE registrations SET secret_confirmed_at=now() WHERE id=$1',[id]);});
    return res.json({status:'registered',userId:q.rows[0].user_id});
  }catch{return fail(res,500,'INTERNAL_ERROR');}
});

app.post('/v1/sessions',loginIpLimiter,async(req,res)=>{
  const b=parse(z.object({phone,secret,installationId:z.string().min(8).max(200).optional()}),req.body);if(!b)return fail(res,400,'INVALID_REQUEST');
  const key=lookupHash(b.phone);
  try { const f=await pool.query('SELECT failures,locked_until FROM login_failures WHERE lookup_hash=$1',[key]);if(f.rowCount&&f.rows[0].locked_until&&new Date(f.rows[0].locked_until)>new Date())return fail(res,429,'LOGIN_TEMPORARILY_DELAYED');
    const u=await pool.query(`SELECT u.id,c.user_id,cr.verifier FROM user_contacts c JOIN users u ON u.id=c.user_id JOIN recovery_credentials cr ON cr.user_id=u.id WHERE c.contact_type='phone' AND c.lookup_hash=$1 AND c.verified_at IS NOT NULL AND u.status='active' AND cr.confirmed_at IS NOT NULL`,[key]);
    if(!u.rowCount||!await verifySecret(u.rows[0].verifier,b.secret)){await pool.query(`INSERT INTO login_failures(lookup_hash,failures,locked_until) VALUES($1,1,NULL) ON CONFLICT(lookup_hash) DO UPDATE SET failures=login_failures.failures+1,locked_until=CASE WHEN login_failures.failures+1 >= $2 THEN now()+($3 * interval '1 second') ELSE NULL END,updated_at=now()`,[key,config.LOGIN_MAX_FAILURES,config.LOGIN_LOCK_SECONDS]);return fail(res,401,'INVALID_CREDENTIALS');}
    await pool.query('DELETE FROM login_failures WHERE lookup_hash=$1',[key]); let deviceId=null;
    if(b.installationId){const d=await pool.query('INSERT INTO devices(user_id,installation_id) VALUES($1,$2) ON CONFLICT(user_id,installation_id) DO UPDATE SET last_seen_at=now() RETURNING id',[u.rows[0].id,b.installationId]);deviceId=d.rows[0].id;}
    const familyId=crypto.randomUUID();const s=await createSession(u.rows[0].id,'full',config.SESSION_TTL_SECONDS,deviceId,'access',familyId);const refresh=await createSession(u.rows[0].id,'full',config.REFRESH_TTL_SECONDS,deviceId,'refresh',familyId);return res.json({accessToken:s.token,accessTokenExpiresAt:s.expiresAt,refreshToken:refresh.token,refreshTokenExpiresAt:refresh.expiresAt,user:{id:u.rows[0].id}});
  }catch{return fail(res,500,'INTERNAL_ERROR');}
});
app.post('/v1/sessions/refresh',async(req,res)=>{
  const b=parse(z.object({refreshToken:z.string().min(32)}),req.body);if(!b)return fail(res,400,'INVALID_REQUEST');
  try{const old=await pool.query("SELECT id,user_id,scope,device_id,session_family FROM sessions WHERE token_hash=$1 AND token_kind='refresh' AND revoked_at IS NULL AND expires_at>now()",[hashSession(b.refreshToken)]);if(!old.rowCount)return fail(res,401,'INVALID_REFRESH_TOKEN');await pool.query('UPDATE sessions SET revoked_at=now() WHERE session_family=$1 AND revoked_at IS NULL',[old.rows[0].session_family]);const access=await createSession(old.rows[0].user_id,old.rows[0].scope,config.SESSION_TTL_SECONDS,old.rows[0].device_id,'access',old.rows[0].session_family);const refresh=await createSession(old.rows[0].user_id,old.rows[0].scope,config.REFRESH_TTL_SECONDS,old.rows[0].device_id,'refresh',old.rows[0].session_family);return res.json({accessToken:access.token,accessTokenExpiresAt:access.expiresAt,refreshToken:refresh.token,refreshTokenExpiresAt:refresh.expiresAt});}catch{return fail(res,500,'INTERNAL_ERROR');}
});

app.post('/v1/forgot-secret-challenges',forgotLimiter,async(req,res)=>{
  const b=parse(z.object({phone}),req.body);if(!b)return fail(res,400,'INVALID_REQUEST');
  const challengeId=crypto.randomUUID();
  try {
    const u=await pool.query("SELECT user_id FROM user_contacts WHERE contact_type='phone' AND lookup_hash=$1 AND verified_at IS NOT NULL",[lookupHash(b.phone)]);
    const userId=u.rows[0]?.user_id??null;
    await pool.query("INSERT INTO recovery_challenges(id,user_id,expires_at) VALUES($1,$2,now()+interval '15 minutes')",[challengeId,userId]);
    if(userId) void dispatchForgotSecretOtps(challengeId,userId);
  } catch { /* Return the same response for unknown accounts and provider/database delivery errors. */ }
  return res.status(202).json({challengeId,status:'verification_pending'});
});

async function dispatchForgotSecretOtps(challengeId,userId) {
  try {
    const contacts=await pool.query('SELECT contact_type,value_ciphertext,lookup_hash FROM user_contacts WHERE user_id=$1 AND verified_at IS NOT NULL',[userId]);
    await Promise.all(contacts.rows.map(c=>issueOtp({challengeColumn:'recovery_challenge_id',challengeId,contactType:c.contact_type,destination:decryptData(c.value_ciphertext),destinationHash:c.lookup_hash}).catch(()=>{})));
  } catch { /* Provider and database failures are intentionally not exposed in logs or responses. */ }
}

app.post('/v1/forgot-secret-challenges/:id/verifications',async(req,res)=>{
  const id=uuid.safeParse(req.params.id).success?req.params.id:null;const b=parse(z.object({contactType:z.enum(['phone','email','emergency']),code:z.string().regex(/^\d{6}$/)}),req.body);if(!id||!b)return fail(res,400,'INVALID_REQUEST');
  try {const result=await transaction(async c=>{const challenge=await c.query('SELECT id FROM recovery_challenges WHERE id=$1 AND expires_at>now() AND completed_at IS NULL FOR UPDATE',[id]);if(!challenge.rowCount)return false;const q=await c.query('SELECT id,verifier,attempts,expires_at FROM otp_challenges WHERE recovery_challenge_id=$1 AND contact_type=$2 AND consumed_at IS NULL ORDER BY created_at DESC LIMIT 1 FOR UPDATE',[id,b.contactType]);if(!q.rowCount)return false;const o=q.rows[0];if(o.attempts>=config.OTP_MAX_ATTEMPTS||new Date(o.expires_at)<new Date()){await c.query('UPDATE otp_challenges SET consumed_at=now() WHERE id=$1',[o.id]);return false;}if(hashOtp(b.code)!==o.verifier){await c.query('UPDATE otp_challenges SET attempts=attempts+1 WHERE id=$1',[o.id]);return false;}await c.query('UPDATE otp_challenges SET consumed_at=now(),verified_at=now() WHERE id=$1',[o.id]);return true;});if(!result)return fail(res,400,'OTP_INVALID_OR_EXPIRED');return res.json({contactType:b.contactType,verified:true});}catch{return fail(res,500,'INTERNAL_ERROR');}
});
app.post('/v1/forgot-secret-challenges/:id/complete',async(req,res)=>{
  const id=uuid.safeParse(req.params.id).success?req.params.id:null;if(!id)return fail(res,400,'INVALID_REQUEST');
  try {const userId=await transaction(async c=>{const q=await c.query('SELECT user_id FROM recovery_challenges WHERE id=$1 AND user_id IS NOT NULL AND expires_at>now() AND completed_at IS NULL FOR UPDATE',[id]);if(!q.rowCount)return null;const v=await c.query("SELECT count(DISTINCT contact_type)::int AS verified FROM otp_challenges WHERE recovery_challenge_id=$1 AND verified_at IS NOT NULL AND contact_type IN ('phone','email','emergency')",[id]);if(v.rows[0].verified!==3)return null;await c.query('UPDATE recovery_challenges SET completed_at=now() WHERE id=$1',[id]);return q.rows[0].user_id;});if(!userId)return fail(res,400,'VERIFICATION_INCOMPLETE');const s=await createSession(userId,'dashboard',config.RECOVERY_SESSION_SECONDS);return res.json({status:'verified',dashboardAccess:{accessToken:s.token,expiresAt:s.expiresAt,scope:'dashboard'}});}catch{return fail(res,500,'INTERNAL_ERROR');}
});

app.get('/v1/me/dashboard',auth,async(req,res)=>{try{const q=await pool.query('SELECT username FROM users WHERE id=$1',[req.session.user_id]);const contacts=await pool.query('SELECT contact_type,value_ciphertext,label_ciphertext,verified_at FROM user_contacts WHERE user_id=$1',[req.session.user_id]);return res.json({user:{id:req.session.user_id,username:q.rows[0].username,contacts:contacts.rows.map(c=>({type:c.contact_type,value:decryptData(c.value_ciphertext),name:c.label_ciphertext?decryptData(c.label_ciphertext):undefined,verified:Boolean(c.verified_at)}))},recoveryInstructions:['Keep your permanent recovery secret stored securely.','Use the recovery website to authorize a recovery request if your phone is lost.','Location reports depend on Android permissions, app availability, and connectivity.']});}catch{return fail(res,500,'INTERNAL_ERROR');}});
app.delete('/v1/sessions/current',auth,async(req,res)=>{await pool.query('UPDATE sessions SET revoked_at=now() WHERE session_family=$1',[req.session.session_family]);return res.status(204).end();});

app.post('/v1/recovery-requests',recoverySecretLimiter,async(req,res)=>{
  const b=parse(z.object({phone,secret}),req.body);if(!b)return fail(res,400,'INVALID_REQUEST');
  try{
    const u=await pool.query(`SELECT u.id,cr.verifier FROM user_contacts c JOIN users u ON u.id=c.user_id JOIN recovery_credentials cr ON cr.user_id=u.id WHERE c.contact_type='phone' AND c.lookup_hash=$1 AND c.verified_at IS NOT NULL AND u.status='active' AND cr.confirmed_at IS NOT NULL`,[lookupHash(b.phone)]);
    if(!u.rowCount||!await verifySecret(u.rows[0].verifier,b.secret))return fail(res,401,'INVALID_CREDENTIALS');
    const statusToken=opaqueToken();
    const r=await pool.query("INSERT INTO recovery_requests(user_id,status,status_token_hash,expires_at) VALUES($1,'active',$2,now()+($3 * interval '1 second')) RETURNING id,expires_at",[u.rows[0].id,hashSession(statusToken),config.RECOVERY_REQUEST_SECONDS]);
    const tokens=await pool.query('SELECT fcm_token_ciphertext FROM devices WHERE user_id=$1 AND revoked_at IS NULL AND fcm_token_ciphertext IS NOT NULL',[u.rows[0].id]);
    const tokenValues=tokens.rows.map(row=>decryptData(row.fcm_token_ciphertext));
    let notification={status:'failed'};
    try{notification=await sendRecoveryRequest(tokenValues,r.rows[0].id,r.rows[0].expires_at);}catch{}
    return res.status(201).json({recoveryRequestId:r.rows[0].id,recoveryAccessToken:statusToken,status:'authorized',expiresAt:r.rows[0].expires_at,locationStatus:'awaiting_device',notificationStatus:notification.status});
  }catch{return fail(res,500,'INTERNAL_ERROR');}
});
app.get('/v1/recovery-requests/:id',async(req,res)=>{const id=uuid.safeParse(req.params.id).success?req.params.id:null;const token=req.get('x-recovery-access-token');if(!id||!token)return fail(res,401,'UNAUTHORIZED');try{const r=await pool.query("SELECT id,CASE WHEN status='active' AND expires_at<=now() THEN 'expired' ELSE status END AS status,expires_at FROM recovery_requests WHERE id=$1 AND status_token_hash=$2",[id,hashSession(token)]);if(!r.rowCount)return fail(res,404,'NOT_FOUND');const l=await pool.query('SELECT location_ciphertext,captured_at,received_at FROM location_reports WHERE request_id=$1 ORDER BY captured_at DESC LIMIT 1',[id]);if(!l.rowCount)return res.json({recoveryRequestId:id,status:r.rows[0].status,expiresAt:r.rows[0].expires_at,locationStatus:r.rows[0].status==='active'?'awaiting_device':r.rows[0].status,latestLocation:null});const loc=JSON.parse(decryptData(l.rows[0].location_ciphertext));const stale=Date.now()-new Date(l.rows[0].captured_at).getTime()>config.LOCATION_STALE_SECONDS*1000;return res.json({recoveryRequestId:id,status:r.rows[0].status,expiresAt:r.rows[0].expires_at,locationStatus:stale?'stale':'current',latestLocation:{...loc,capturedAt:l.rows[0].captured_at,receivedAt:l.rows[0].received_at,stale}});}catch{return fail(res,500,'INTERNAL_ERROR');}});
app.post('/v1/recovery-requests/:id/stop',async(req,res)=>{const id=uuid.safeParse(req.params.id).success?req.params.id:null;const token=req.get('x-recovery-access-token');if(!id||!token)return fail(res,401,'UNAUTHORIZED');try{const changed=await transaction(async c=>{await c.query('SELECT pg_advisory_xact_lock(hashtext($1)::bigint)',[id]);return c.query("UPDATE recovery_requests SET status='stopped',stopped_at=now() WHERE id=$1 AND status_token_hash=$2 AND status='active' AND expires_at>now() RETURNING id,user_id",[id,hashSession(token)]);});if(!changed.rowCount)return fail(res,404,'NOT_FOUND');try{const devices=await pool.query('SELECT fcm_token_ciphertext FROM devices WHERE user_id=$1 AND revoked_at IS NULL AND fcm_token_ciphertext IS NOT NULL',[changed.rows[0].user_id]);await sendRecoveryRequestStopped(devices.rows.map(row=>decryptData(row.fcm_token_ciphertext)),id);}catch{}return res.json({status:'stopped'});}catch{return fail(res,500,'INTERNAL_ERROR');}});
app.post('/v1/recovery-requests/:id/location-reports',auth,requireScope('full'),async(req,res)=>{
  const id=uuid.safeParse(req.params.id).success?req.params.id:null;
  const b=parse(z.object({latitude:z.number().min(-90).max(90),longitude:z.number().min(-180).max(180),accuracyMeters:z.number().nonnegative().max(100000),capturedAt:z.string().datetime(),provider:z.literal('fused')}),req.body);
  if(!id||!b)return fail(res,400,'INVALID_REQUEST');
  const capturedMs=Date.parse(b.capturedAt),now=Date.now();
  if(!Number.isFinite(capturedMs)||capturedMs>now+120_000||capturedMs<now-config.LOCATION_RETENTION_DAYS*86400_000)return fail(res,400,'INVALID_LOCATION_TIMESTAMP');
  if(!req.session.device_id)return fail(res,403,'DEVICE_NOT_ENROLLED');
  try{
    const outcome=await transaction(async c=>{
      await c.query('SELECT pg_advisory_xact_lock(hashtext($1)::bigint)',[id]);
      const active=await c.query("SELECT id FROM recovery_requests WHERE id=$1 AND user_id=$2 AND status='active' AND expires_at>now()",[id,req.session.user_id]);
      if(!active.rowCount)return {error:'RECOVERY_NOT_ACTIVE'};
      const previous=await c.query('SELECT received_at FROM location_reports WHERE request_id=$1 ORDER BY received_at DESC LIMIT 1',[id]);
      if(previous.rowCount&&Date.now()-new Date(previous.rows[0].received_at).getTime()<config.LOCATION_INTERVAL_SECONDS*1000)return {error:'LOCATION_RATE_LIMITED'};
      const inserted=await c.query('INSERT INTO location_reports(request_id,device_id,location_ciphertext,captured_at) VALUES($1,$2,$3,$4) RETURNING id,received_at',[id,req.session.device_id,encryptData(JSON.stringify({latitude:b.latitude,longitude:b.longitude,accuracyMeters:b.accuracyMeters,provider:b.provider})),b.capturedAt]);
      return {report:inserted.rows[0]};
    });
    if(outcome.error)return fail(res,outcome.error==='LOCATION_RATE_LIMITED'?429:403,outcome.error);
    return res.status(201).json({accepted:true,receivedAt:outcome.report.received_at,reportId:outcome.report.id});
  }catch{return fail(res,500,'INTERNAL_ERROR');}
});
app.put('/v1/devices/current/fcm-token',auth,requireScope('full'),async(req,res)=>{const b=parse(z.object({installationId:z.string().min(8).max(200),token:z.string().min(20).max(4096)}),req.body);if(!b)return fail(res,400,'INVALID_REQUEST');try{const r=await pool.query('UPDATE devices SET fcm_token_ciphertext=$1,last_seen_at=now() WHERE user_id=$2 AND installation_id=$3 AND revoked_at IS NULL RETURNING id',[encryptData(b.token),req.session.user_id,b.installationId]);return r.rowCount?res.json({registered:true}):fail(res,404,'DEVICE_NOT_FOUND');}catch{return fail(res,500,'INTERNAL_ERROR');}});

app.use((err,_req,res,_next)=>{ // No request body or provider details are logged.
  return fail(res,500,'INTERNAL_ERROR');
});
export { app };
