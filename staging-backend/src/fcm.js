import { cert, getApps, initializeApp } from 'firebase-admin/app';
import { getMessaging } from 'firebase-admin/messaging';
import { config } from './config.js';

let app;
let initState='unconfigured';
function getFcmApp() {
  if (app) return app;
  if (initState==='invalid') return null;
  if (!config.FIREBASE_SERVICE_ACCOUNT_JSON) return null;
  try {
    const serviceAccount=JSON.parse(config.FIREBASE_SERVICE_ACCOUNT_JSON);
    if(!serviceAccount.project_id||!serviceAccount.client_email||!serviceAccount.private_key){initState='invalid';return null;}
    app=getApps().find(x=>x.name==='corvon-recovery') ?? initializeApp({credential:cert(serviceAccount),projectId:serviceAccount.project_id},'corvon-recovery');
    initState='configured';
    return app;
  } catch { initState='invalid'; return null; }
}

export function fcmConfigurationStatus() {
  const instance=getFcmApp();
  return {configured:Boolean(instance),status:instance?'configured':initState==='invalid'?'invalid_credentials':'not_configured'};
}

export async function sendRecoveryRequest(tokens,recoveryRequestId) {
  const instance=getFcmApp();
  if(!instance)return {status:initState==='invalid'?'invalid_credentials':'not_configured',accepted:0,failed:0};
  if(!tokens.length)return {status:'no_registered_device',accepted:0,failed:0};
  let accepted=0,failed=0;
  const messaging=getMessaging(instance);
  for(let i=0;i<tokens.length;i+=500){
    const batch=tokens.slice(i,i+500);
    try {
      const result=await messaging.sendEachForMulticast({
        tokens:batch,
        data:{type:'recovery_request',recoveryRequestId},
        android:{priority:'high',ttl:30*60*1000}
      });
      accepted+=result.successCount;failed+=result.failureCount;
    } catch { failed+=batch.length; }
  }
  return {status:accepted?'submitted':failed?'failed':'no_registered_device',accepted,failed};
}
