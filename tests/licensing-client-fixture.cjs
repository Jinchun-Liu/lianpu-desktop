'use strict';
const assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path');
const crypto=require('node:crypto');
const {LicenseClient,LicenseError}=require('../src/licensing/client.cjs');
const {needsLicense}=require('../src/licensing/operations.cjs');
const root=path.resolve(__dirname,'..'),scratch=path.join(root,'work');fs.mkdirSync(scratch,{recursive:true});
// Hypothesis: only cloud-confirmed, device-bound and durably saved licenses enable
// operation, while renewal or transport/storage failure cannot consume an extra
// code or remove current rights. Decision: v1.6 client activation acceptance.
// Stop on the first false activation, changed original expiry, lost request,
// post-expiry operation or discarded valid old entitlement. This fixture uses
// explicitly injected software keys and transport, never claims TPM/cloud proof.
async function fixture(t){
  const protocol=await import('../shared/licensing/protocol.mjs'),directory=fs.mkdtempSync(path.join(scratch,'licensing-client-'));
  t.after(()=>{assert.ok(path.resolve(directory).startsWith(scratch+path.sep));fs.rmSync(directory,{recursive:true,force:true});});
  const pair=crypto.generateKeyPairSync('ec',{namedCurve:'prime256v1'}),spki=pair.publicKey.export({format:'der',type:'spki'}).toString('base64url');
  const device={info:{ok:true,state:'ready',publicKeySpki:spki,deviceId:crypto.createHash('sha256').update(Buffer.from(spki,'base64url')).digest('hex'),storage:{prepared:true},key:{provider:'fixture-only'}},async status(){return this.info;},async prepare(){return this.info;},validate(){return this.info.state==='ready';},signSync(bytes){return crypto.sign('sha256',bytes,{key:pair.privateKey,dsaEncoding:'ieee-p1363'});},verify(bytes,sig){return crypto.verify('sha256',bytes,{key:pair.publicKey,dsaEncoding:'ieee-p1363'},sig);}};
  const signing=await crypto.webcrypto.subtle.generateKey('Ed25519',true,['sign','verify']),pub=Buffer.from(await crypto.webcrypto.subtle.exportKey('spki',signing.publicKey)).toString('base64url');
  const f={protocol,directory,device,signing,now:Date.UTC(2026,8,11,6),mono:0,records:new Map(),requests:[],confirmCalls:0,consumeCount:0,loss:null,quota:false,failWrite:false,events:[]};
  const config={endpoint:'https://isolated.invalid',publicKeys:{fixture:pub}};
  f.transport=async(_endpoint,route,body)=>{
    f.requests.push({route,requestId:body.requestId||body.ticket?.payload.requestId});if(f.quota)throw new LicenseError('SERVICE_QUOTA','免费额度不足，停止兑换。');
    if(route==='/v1/precheck'){
      const payload={v:1,type:'ticket',mode:body.mode,requestId:body.requestId,deviceId:device.info.deviceId,devicePublicKeySpki:spki,codeHash:body.mode==='activate'?await protocol.hashCode(body.code):null,plan:body.mode==='activate'?protocol.planFromCode(body.code):null,issuedAt:f.now,expiresAt:f.now+300000,nonce:crypto.randomBytes(32).toString('base64url')};
      const ticket=await protocol.signEnvelope(payload,'ticket','fixture',signing.privateKey);return {ticket,challenge:{algorithm:'ECDSA-P256-SHA256',bytes:Buffer.from(protocol.ticketProofBytes(ticket)).toString('base64url'),expiresAt:payload.expiresAt},preview:{mode:body.mode,plan:payload.plan}};
    }
    const ticket=await protocol.verifyEnvelope(body.ticket,'ticket',config.publicKeys);await protocol.verifyDeviceProof(body.ticket,body.proof);
    if(route==='/v1/confirm'){
      f.confirmCalls++;if(f.loss==='before'){f.loss=null;throw new LicenseError('LICENSE_NETWORK','fixture request not delivered',true);}
      if(!f.records.has(ticket.requestId)){
        const old=[...f.records.values()].at(-1),days=protocol.PERIOD_DAYS[ticket.plan],payload={v:1,type:'license',licenseId:old?.licenseId||crypto.randomUUID(),deviceId:device.info.deviceId,devicePublicKeySpki:spki,plan:ticket.plan,firstActivatedAt:old?.firstActivatedAt||f.now,issuedAt:f.now,expiresAt:days===null?null:Math.max(f.now,old?.expiresAt||0)+days*86400000,revision:(old?.revision||0)+1,requestId:ticket.requestId};
        f.records.set(ticket.requestId,payload);f.consumeCount++;
      }
      if(f.loss==='after'){f.loss=null;throw new LicenseError('LICENSE_NETWORK','fixture response lost',true);}
    }
    const payload=f.records.get(ticket.requestId);if(!payload)throw new LicenseError('RECOVERY_NOT_FOUND','fixture original request not found');
    const license=await protocol.signEnvelope(payload,'license','fixture',signing.privateKey);
    if(f.tamper)license.payload.expiresAt+=1;
    return {license,recovered:route==='/v1/recover'};
  };
  f.make=()=>{const client=new LicenseClient({protocol,config,device,directory,transport:f.transport,wallClock:()=>f.now,monotonic:()=>f.mono,onChange:status=>f.events.push(status),writeState:value=>{if(f.failWrite&&value.body.license)throw new LicenseError('LICENSE_SAVE_FAILED','fixture local write failure',true);client._writeFile(value);}});return client;};
  f.client=f.make();await f.client.initialize();f.code=(plan='W',suffix='A')=>`LP1-${plan}-${suffix.repeat(40)}`;f.activate=async(plan='W',suffix='A')=>{const pre=await f.client.precheck({code:f.code(plan,suffix)});return f.client.confirm({requestId:pre.requestId});};return f;
}
module.exports={fixture};
