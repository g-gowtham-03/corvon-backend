import test, { before, after } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { createServer } from 'node:http';

const testDatabaseUrl=process.env.CORVON_TEST_DATABASE_URL;
if(!testDatabaseUrl){
  test('PostgreSQL API integration suite (set CORVON_TEST_DATABASE_URL to a dedicated migrated test database)',{skip:'PostgreSQL integration tests not run: no test database configured.'},()=>{});
} else {
  process.env.NODE_ENV='test';
  process.env.DATABASE_URL=testDatabaseUrl;
  process.env.OTP_PEPPER='test-otp-pepper-value-32-bytes-minimum';
  process.env.LOOKUP_PEPPER='test-lookup-pepper-value-32-bytes';
  process.env.RECOVERY_SECRET_PEPPER='test-recovery-pepper-32-bytes-minimum';
  process.env.SESSION_PEPPER='test-session-pepper-value-32-bytes';
  process.env.CONTACT_DATA_KEY=crypto.randomBytes(32).toString('base64');
  process.env.TWILIO_ACCOUNT_SID='AC_TEST_ONLY';process.env.TWILIO_AUTH_TOKEN='test-token';process.env.TWILIO_FROM_NUMBER='+15550000000';
  process.env.RESEND_API_KEY='re_test_only';process.env.EMAIL_FROM='test@example.invalid';
  delete process.env.FIREBASE_SERVICE_ACCOUNT_JSON;

  const delivered=new Map(), testPhones=[], testChallengeIds=[];
  let failSms=false,failEmail=false;
  const originalFetch=globalThis.fetch;
  globalThis.fetch=async(url,options={})=>{
    const endpoint=String(url);let destination,body;
    if(baseUrl&&endpoint.startsWith(baseUrl))return originalFetch(url,options);
    if(endpoint.includes('twilio.com')){
      const form=new URLSearchParams(options.body);destination=form.get('To');body=form.get('Body');
      if(failSms)return new Response('{}',{status:503});
    }else{
      const json=JSON.parse(options.body);destination=json.to[0];body=json.text;
      if(failEmail)return new Response('{}',{status:503});
    }
    const code=body.match(/\b(\d{6})\b/)?.[1];if(code)delivered.set(destination,code);
    return new Response('{}',{status:200,headers:{'Content-Type':'application/json'}});
  };

  const [{app},{pool},{lookupHash},{config}]=await Promise.all([
    import('../src/app.js'),import('../src/db/pool.js'),import('../src/security.js'),import('../src/config.js')
  ]);
  const server=createServer(app);let baseUrl;
  const phone=()=>`+1555${String(crypto.randomInt(0,10000000)).padStart(7,'0')}`;
  const email=()=>`corvon-${crypto.randomUUID()}@example.invalid`;
  async function call(path,method='GET',body,headers={}){
    const response=await fetch(`${baseUrl}${path}`,{method,headers:{...(body?{'content-type':'application/json'}:{}),...headers},body:body?JSON.stringify(body):undefined});
    return {response,body:response.status===204?null:await response.json()};
  }
  async function register({includeEmergencyName=true}={}){
    const p=phone(),e=email(),ep=phone();testPhones.push(p,ep);
    for(const target of [p,e,ep])delivered.delete(target);
    const emergencyContact={phone:ep};
    if(includeEmergencyName)emergencyContact.name='Trusted Contact';
    const start=await call('/v1/registrations','POST',{username:'Integration User',phone:p,email:e,emergencyContact});
    assert.equal(start.response.status,201);
    return {registrationId:start.body.registrationId,phone:p,email:e,emergencyPhone:ep,body:start.body};
  }
  async function requestOtp(account,type,{failDelivery=false}={}){
    failSms=failDelivery&&type!=='email';failEmail=failDelivery&&type==='email';
    const result=await call(`/v1/registrations/${account.registrationId}/otp-challenges`,'POST',{contactType:type});
    failSms=false;failEmail=false;
    return result;
  }
  async function finishRegistration(account){
    const current=await pool.query('SELECT contact_type,value_ciphertext,lookup_hash FROM user_contacts WHERE user_id=(SELECT user_id FROM registrations WHERE id=$1)',[account.registrationId]);
    const {decryptData}=await import('../src/security.js');
    const typeToDestination={};
    for(const row of current.rows)typeToDestination[row.contact_type]=decryptData(row.value_ciphertext);
    for(const type of ['phone','email','emergency']){
      const destination=typeToDestination[type];
      let requested=await requestOtp(account,type);
      if(requested.response.status!==202)requested=await requestOtp(account,type);
      assert.equal(requested.response.status,202);
      const verified=await call(`/v1/registrations/${account.registrationId}/otp-verifications`,'POST',{contactType:type,code:delivered.get(destination)});assert.equal(verified.response.status,200);
    }
    const created=await call(`/v1/registrations/${account.registrationId}/secret`,'POST',{});assert.equal(created.response.status,201);
    const secret=created.body.secret;
    const repeated=await call(`/v1/registrations/${account.registrationId}/secret`,'POST',{});assert.equal(repeated.response.status,409);assert.equal('secret' in repeated.body,false);
    const confirmed=await call(`/v1/registrations/${account.registrationId}/secret-confirmation`,'POST',{secret});assert.equal(confirmed.response.status,200);
    account.secret=secret;
    return account;
  }

  before(async()=>{
    const schemaState=await pool.query('SELECT current_schema() AS active_schema, current_schemas(true) AS active_schemas');
    assert.equal(schemaState.rows[0].active_schema,config.DB_SCHEMA);
    assert.ok(schemaState.rows[0].active_schemas.includes(config.DB_SCHEMA));
    assert.ok(!schemaState.rows[0].active_schemas.includes('public'));
    const legacyVisibility=await pool.query(`SELECT c.relname FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
      WHERE n.nspname='public' AND c.relname IN ('devices','location_reports') AND pg_table_is_visible(c.oid)`);
    assert.equal(legacyVisibility.rowCount,0,'legacy public tables must not be visible to unqualified application queries');
    const ledger=await pool.query("SELECT n.nspname AS schema_name FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE c.oid=to_regclass('schema_migrations')");
    assert.equal(ledger.rows[0]?.schema_name,config.DB_SCHEMA);
    await pool.query('SELECT 1 FROM schema_migrations LIMIT 1');
    await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));
    baseUrl=`http://127.0.0.1:${server.address().port}`;
  });
  after(async()=>{
    server.close();globalThis.fetch=originalFetch;
    if(testChallengeIds.length)await pool.query('DELETE FROM recovery_challenges WHERE id=ANY($1::uuid[])',[testChallengeIds]);
    if(testPhones.length){const hashes=testPhones.map(lookupHash);await pool.query('DELETE FROM users WHERE id IN (SELECT user_id FROM user_contacts WHERE lookup_hash=ANY($1::char(64)[]))',[hashes]);}
    await pool.end();
  });

  test('registration sends no OTPs automatically and optional emergency name is stored as null',async()=>{
    const account=await register({includeEmergencyName:false});
    assert.deepEqual(account.body.contacts.map(c=>c.contactType),['phone','email','emergency']);
    assert.equal(account.body.contacts.every(c=>!c.verified),true);
    assert.equal('otpChallenges' in account.body,false);
    assert.equal([account.phone,account.email,account.emergencyPhone].some(target=>delivered.has(target)),false);
    const emergency=await pool.query("SELECT label_ciphertext FROM user_contacts WHERE user_id=(SELECT user_id FROM registrations WHERE id=$1) AND contact_type='emergency'",[account.registrationId]);
    assert.equal(emergency.rows[0].label_ciphertext,null);
  });

  test('each contact requests and verifies its OTP independently',async()=>{
    const account=await register();
    for(const [type,target] of [['phone',account.phone],['email',account.email],['emergency',account.emergencyPhone]]){
      for(const candidate of [account.phone,account.email,account.emergencyPhone])delivered.delete(candidate);
      const requested=await requestOtp(account,type);
      assert.equal(requested.response.status,202);
      assert.equal(requested.body.contactType,type);
      assert.equal('code' in requested.body,false);
      assert.equal('otp' in requested.body,false);
      assert.ok(delivered.has(target));
      const verified=await call(`/v1/registrations/${account.registrationId}/otp-verifications`,'POST',{contactType:type,code:delivered.get(target)});
      assert.equal(verified.response.status,200);
      assert.equal(verified.body.verified,true);
      assert.equal('code' in verified.body,false);
      const replay=await call(`/v1/registrations/${account.registrationId}/otp-verifications`,'POST',{contactType:type,code:delivered.get(target)});
      assert.equal(replay.response.status,400);
      delivered.delete(target);
    }
  });

  test('SMS provider failures preserve registration ID and allow per-contact retry',async()=>{
    const account=await register();
    const failed=await requestOtp(account,'phone',{failDelivery:true});
    assert.equal(failed.response.status,503);
    assert.equal(delivered.has(account.phone),false);
    const resent=await requestOtp(account,'phone');
    assert.equal(resent.response.status,202);
    assert.ok(delivered.has(account.phone));
    await finishRegistration(account);
    assert.ok(account.secret);
  });

  test('email provider failures are surfaced without losing registration and can be retried',async()=>{
    const account=await register();
    const failed=await requestOtp(account,'email',{failDelivery:true});
    assert.equal(failed.response.status,503);
    const resent=await requestOtp(account,'email');
    assert.equal(resent.response.status,202);assert.ok(delivered.has(account.email));
  });

  test('OTP expiry rejects a code after five minutes',async()=>{
    const p=phone(),e=email(),ep=phone();testPhones.push(p,ep);
    const start=await call('/v1/registrations','POST',{username:'Expiry User',phone:p,email:e,emergencyContact:{phone:ep}});
    const account={registrationId:start.body.registrationId,phone:p,email:e,emergencyPhone:ep};
    assert.equal((await requestOtp(account,'phone')).response.status,202);
    const code=delivered.get(p);
    await pool.query("UPDATE otp_challenges SET expires_at=now()-interval '1 second' WHERE registration_id=$1 AND contact_type='phone' AND consumed_at IS NULL",[start.body.registrationId]);
    const result=await call(`/v1/registrations/${start.body.registrationId}/otp-verifications`,'POST',{contactType:'phone',code});
    assert.equal(result.response.status,400);
  });

  test('invalid OTPs are capped at five attempts and a contact OTP is single use',async()=>{
    const account=await register();
    assert.equal((await requestOtp(account,'phone')).response.status,202);
    const correct=delivered.get(account.phone),wrong=correct==='000000'?'000001':'000000';
    for(let attempt=0;attempt<5;attempt++){
      const invalid=await call(`/v1/registrations/${account.registrationId}/otp-verifications`,'POST',{contactType:'phone',code:wrong});
      assert.equal(invalid.response.status,400);
    }
    const blocked=await call(`/v1/registrations/${account.registrationId}/otp-verifications`,'POST',{contactType:'phone',code:correct});
    assert.equal(blocked.response.status,400);
    const saved=await pool.query("SELECT attempts,consumed_at FROM otp_challenges WHERE registration_id=$1 AND contact_type='phone' ORDER BY created_at DESC LIMIT 1",[account.registrationId]);
    assert.equal(saved.rows[0].attempts,5);
    assert.ok(saved.rows[0].consumed_at);
  });

  test('secret generation cannot complete before all three contacts are verified',async()=>{
    const account=await register();
    assert.equal((await requestOtp(account,'phone')).response.status,202);
    const valid=await call(`/v1/registrations/${account.registrationId}/otp-verifications`,'POST',{contactType:'phone',code:delivered.get(account.phone)});
    assert.equal(valid.response.status,200);
    const premature=await call(`/v1/registrations/${account.registrationId}/secret`,'POST',{});
    assert.equal(premature.response.status,409);
    assert.equal('secret' in premature.body,false);
    await finishRegistration(account);
    assert.ok(account.secret);
  });

  test('concurrent secret requests issue exactly one permanent secret',async()=>{
    const account=await register();
    for(const [type,target] of [['phone',account.phone],['email',account.email],['emergency',account.emergencyPhone]]){
      const requested=await requestOtp(account,type);
      assert.equal(requested.response.status,202);
      const verified=await call(`/v1/registrations/${account.registrationId}/otp-verifications`,'POST',{contactType:type,code:delivered.get(target)});
      assert.equal(verified.response.status,200);
    }
    const path=`/v1/registrations/${account.registrationId}/secret`;
    const responses=await Promise.all([call(path,'POST',{}),call(path,'POST',{})]);
    assert.deepEqual(responses.map(x=>x.response.status).sort(),[201,409]);
    const issued=responses.find(x=>x.response.status===201);
    const rejected=responses.find(x=>x.response.status===409);
    assert.ok(issued.body.secret);
    assert.equal(rejected.body.error.code,'SECRET_ALREADY_ISSUED');
    assert.equal('secret' in rejected.body,false);
    const confirmed=await call(`/v1/registrations/${account.registrationId}/secret-confirmation`,'POST',{secret:issued.body.secret});
    assert.equal(confirmed.response.status,200);
  });

  test('duplicate contact registrations are rejected without creating a second account',async()=>{
    const account=await register();
    const duplicate=await call('/v1/registrations','POST',{username:'Duplicate',phone:account.phone,email:email(),emergencyContact:{phone:phone()}});
    assert.equal(duplicate.response.status,409);
    assert.equal(duplicate.body.error.code,'CONTACT_ALREADY_REGISTERED');
  });

  test('Forgot Secret serializes concurrent failures and caps a challenge at five attempts',async()=>{
    const account=await finishRegistration(await register());
    for(const target of [account.phone,account.email,account.emergencyPhone])delivered.delete(target);
    const start=await call('/v1/forgot-secret-challenges','POST',{phone:account.phone});assert.equal(start.response.status,202);testChallengeIds.push(start.body.challengeId);
    for(let i=0;i<100&&![account.phone,account.email,account.emergencyPhone].every(x=>delivered.has(x));i++)await new Promise(r=>setTimeout(r,10));
    assert.ok([account.phone,account.email,account.emergencyPhone].every(x=>delivered.has(x)));
    const wrong=delivered.get(account.phone)==='000000'?'111111':'000000';
    const attempts=await Promise.all(Array.from({length:9},()=>call(`/v1/forgot-secret-challenges/${start.body.challengeId}/verifications`,'POST',{contactType:'phone',code:wrong})));
    assert.ok(attempts.every(x=>x.response.status===400));
    const saved=await pool.query("SELECT attempts FROM otp_challenges WHERE recovery_challenge_id=$1 AND contact_type='phone' ORDER BY created_at DESC LIMIT 1",[start.body.challengeId]);
    assert.equal(saved.rows[0].attempts,5);
    const blocked=await call(`/v1/forgot-secret-challenges/${start.body.challengeId}/verifications`,'POST',{contactType:'phone',code:delivered.get(account.phone)});
    assert.equal(blocked.response.status,400);
  });

  test('Forgot Secret verifies all contacts and grants dashboard access without changing the secret',async()=>{
    const account=await finishRegistration(await register());
    for(const target of [account.phone,account.email,account.emergencyPhone])delivered.delete(target);
    const start=await call('/v1/forgot-secret-challenges','POST',{phone:account.phone});testChallengeIds.push(start.body.challengeId);
    for(let i=0;i<100&&![account.phone,account.email,account.emergencyPhone].every(x=>delivered.has(x));i++)await new Promise(r=>setTimeout(r,10));
    for(const [contactType,target] of [['phone',account.phone],['email',account.email],['emergency',account.emergencyPhone]]){
      const verified=await call(`/v1/forgot-secret-challenges/${start.body.challengeId}/verifications`,'POST',{contactType,code:delivered.get(target)});assert.equal(verified.response.status,200);
    }
    const complete=await call(`/v1/forgot-secret-challenges/${start.body.challengeId}/complete`,'POST',{});assert.equal(complete.response.status,200);assert.equal(complete.body.dashboardAccess.scope,'dashboard');
    const login=await call('/v1/sessions','POST',{phone:account.phone,secret:account.secret});assert.equal(login.response.status,200);
  });

  test('Forgot Secret returns the same shape for a known and unknown phone',async()=>{
    const account=await finishRegistration(await register());
    const known=await call('/v1/forgot-secret-challenges','POST',{phone:account.phone});
    const unknown=await call('/v1/forgot-secret-challenges','POST',{phone:phone()});
    assert.equal(known.response.status,202);assert.equal(unknown.response.status,202);
    assert.deepEqual(Object.keys(known.body).sort(),Object.keys(unknown.body).sort());
    assert.equal(known.body.status,unknown.body.status);
    testChallengeIds.push(known.body.challengeId,unknown.body.challengeId);
  });

  test('PostgreSQL rate limiter shares atomic counters between store instances',async()=>{
    const {PostgresRateLimitStore}=await import('../src/db/postgres-rate-limit-store.js');
    const a=new PostgresRateLimitStore('integration-shared'),b=new PostgresRateLimitStore('integration-shared');a.init({windowMs:60_000});b.init({windowMs:60_000});
    const counts=await Promise.all(Array.from({length:12},(_,i)=>(i%2?a:b).increment('same-test-client')));
    assert.deepEqual(counts.map(x=>x.totalHits).sort((x,y)=>x-y),Array.from({length:12},(_,i)=>i+1));
    await a.resetKey('same-test-client');
  });

  test('recovery login locks after five failures and recovery status is capability-authorized',async()=>{
    const account=await finishRegistration(await register());
    const login=await call('/v1/sessions','POST',{phone:account.phone,secret:account.secret,installationId:`install-${crypto.randomUUID()}`});assert.equal(login.response.status,200);
    const recovery=await call('/v1/recovery-requests','POST',{phone:account.phone,secret:account.secret});assert.equal(recovery.response.status,201);assert.equal(recovery.body.notificationStatus,'not_configured');
    const unauth=await call(`/v1/recovery-requests/${recovery.body.recoveryRequestId}`);assert.equal(unauth.response.status,401);
    const wrong=await call(`/v1/recovery-requests/${recovery.body.recoveryRequestId}`,'GET',undefined,{'x-recovery-access-token':'invalid'});assert.equal(wrong.response.status,404);
    const status=await call(`/v1/recovery-requests/${recovery.body.recoveryRequestId}`,'GET',undefined,{'x-recovery-access-token':recovery.body.recoveryAccessToken});assert.equal(status.response.status,200);
    const stopped=await call(`/v1/recovery-requests/${recovery.body.recoveryRequestId}/stop`,'POST',{}, {'x-recovery-access-token':recovery.body.recoveryAccessToken});assert.equal(stopped.response.status,200);
    const denied=await call(`/v1/recovery-requests/${recovery.body.recoveryRequestId}/stop`,'POST',{}, {'x-recovery-access-token':'wrong'});assert.equal(denied.response.status,404);
    const future=await call(`/v1/recovery-requests/${recovery.body.recoveryRequestId}/location-reports`,'POST',{latitude:1,longitude:2,accuracyMeters:3,capturedAt:new Date(Date.now()+600_000).toISOString(),provider:'fused'},{authorization:`Bearer ${login.body.accessToken}`});assert.equal(future.response.status,400);
    for(let i=0;i<5;i++){const bad=await call('/v1/sessions','POST',{phone:account.phone,secret:`${account.secret}x`});assert.equal(bad.response.status,401);}
    const locked=await call('/v1/sessions','POST',{phone:account.phone,secret:account.secret});assert.equal(locked.response.status,429);
  });
}
