'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs');
const {needsLicense}=require('../src/licensing/operations.cjs');
const {fixture}=require('./licensing-client-fixture.cjs');
test('precheck persists a request without a plaintext code or grant; only saved final proof activates',async t=>{
  const f=await fixture(t),pre=await f.client.precheck({code:f.code()});assert.equal(f.client.status().active,false);assert.equal(f.consumeCount,0);const saved=fs.readFileSync(f.client.file,'utf8');assert.ok(saved.includes(pre.requestId));assert.equal(saved.includes(f.code()),false);
  const result=await f.client.confirm({requestId:pre.requestId});assert.equal(result.status,'activated');assert.equal(result.license.active,true);assert.equal(f.consumeCount,1);assert.equal(f.client.body.pending,null);assert.equal(f.client.payload.expiresAt,f.now+7*86400000);
});
test('all signed durations and renewal accumulation preserve first activation and permanent upgrade',async t=>{
  const f=await fixture(t);for(const [plan,days,suffix]of[['W',7,'A'],['M',30,'B'],['Y',365,'C']]){const previous=f.client.payload?.expiresAt||f.now;await f.activate(plan,suffix);assert.equal(f.client.payload.expiresAt,previous+days*86400000);assert.equal(f.client.payload.firstActivatedAt,f.now);}
  await f.activate('P','D');assert.equal(f.client.payload.expiresAt,null);assert.equal(f.client.status().active,true);
});
test('cloud response loss recovers the original same-device grant after restart without another consumption',async t=>{
  const f=await fixture(t),pre=await f.client.precheck({code:f.code()});f.loss='after';await assert.rejects(f.client.confirm({requestId:pre.requestId}),{code:'LICENSE_NETWORK'});const original=structuredClone(f.records.get(pre.requestId));
  f.client=f.make();await f.client.initialize();const result=await f.client.recover({});assert.equal(result.license.active,true);assert.deepEqual(f.client.payload,original);assert.equal(f.consumeCount,1);
});
test('a confirm that never reached cloud survives a failed recovery and reuses its original request',async t=>{
  const f=await fixture(t),pre=await f.client.precheck({code:f.code()});f.loss='before';await assert.rejects(f.client.confirm({requestId:pre.requestId}),{code:'LICENSE_NETWORK'});
  await assert.rejects(f.client.recover({}),{code:'RECOVERY_NOT_FOUND'});assert.equal(f.client.status().active,false);await assert.rejects(f.client.precheck({code:f.code('M','B')}),{code:'LICENSE_PENDING_RECOVERY'});
  f.client=f.make();await f.client.initialize();const repeated=await f.client.precheck({code:f.code()});assert.equal(repeated.requestId,pre.requestId);await f.client.confirm({requestId:pre.requestId});assert.equal(f.consumeCount,1);
});
test('a cloud-confirmed result with failed local storage remains pending and restores the same entitlement',async t=>{
  const f=await fixture(t),pre=await f.client.precheck({code:f.code()});f.failWrite=true;await assert.rejects(f.client.confirm({requestId:pre.requestId}),{code:'LICENSE_SAVE_FAILED'});assert.equal(f.client.status().active,false);assert.equal(f.consumeCount,1);
  const original=structuredClone(f.records.get(pre.requestId));f.failWrite=false;f.client=f.make();await f.client.initialize();await f.client.recover({});assert.deepEqual(f.client.payload,original);assert.equal(f.consumeCount,1);
});
test('renewal failure and a free-quota rejection preserve an existing unexpired offline license',async t=>{
  const f=await fixture(t);await f.activate();const original=structuredClone(f.client.payload);f.quota=true;await assert.rejects(f.client.precheck({code:f.code('M','B')}),{code:'SERVICE_QUOTA'});assert.equal(f.client.status().active,true);assert.deepEqual(f.client.payload,original);assert.equal(f.client.assertAllowed(),true);assert.equal(f.consumeCount,1);
});
test('modified signatures and a different device cannot create active rights',async t=>{
  const f=await fixture(t),pre=await f.client.precheck({code:f.code()});f.tamper=true;await assert.rejects(f.client.confirm({requestId:pre.requestId}),{code:'INVALID_SIGNATURE'});assert.equal(f.client.status().active,false);f.tamper=false;await f.client.recover({});
  f.device.info.deviceId='0'.repeat(64);const other=f.make();await other.initialize();assert.equal(other.status().active,false);assert.equal(other.status().state,'blocked');
});
test('UTC rollback is detected across process restart and recovery does not restart the license period',async t=>{
  const f=await fixture(t);await f.activate();const expiry=f.client.payload.expiresAt;f.now+=600000;f.mono+=600000;f.client.assertAllowed();f.now-=600000;f.client=f.make();await f.client.initialize();assert.equal(f.client.status().state,'clock_recovery_required');assert.throws(()=>f.client.assertAllowed(),{code:'LICENSE_REQUIRED'});
  f.now+=600000;await f.client.recover({});assert.equal(f.client.status().active,true);assert.equal(f.client.payload.expiresAt,expiry);
});
test('expiry stops new operations while maintenance permissions remain explicit',async t=>{
  const f=await fixture(t);await f.activate();f.now=f.client.payload.expiresAt;f.mono=7*86400000;assert.equal(f.client.status().state,'expired');assert.throws(()=>f.client.assertAllowed(),{code:'LICENSE_REQUIRED'});
  for(const action of ['workspace.snapshot','backup.create','backup.restore','file.export','account.login.clear','hosting.stopAll','update.install'])assert.equal(needsLicense(action),false,action);
  for(const action of ['message.send','delivery.execute','account.sync','media.import','claims.preview','ai.preview','future.unknown'])assert.equal(needsLicense(action),true,action);
  assert.equal(needsLicense('account.hosting.save',{enabled:false}),false);assert.equal(needsLicense('account.hosting.save',{enabled:true}),true);
});
test('state tampering cannot reset the high-water record and device preparation preserves an existing license',async t=>{
  const f=await fixture(t);await f.activate();const prior=structuredClone(f.client.payload);await f.client.prepareDevice();assert.deepEqual(f.client.payload,prior);
  const saved=JSON.parse(fs.readFileSync(f.client.file,'utf8'));saved.body.clock.highWater--;fs.writeFileSync(f.client.file,JSON.stringify(saved));const next=f.make();await next.initialize();assert.equal(next.status().active,false);assert.equal(next.status().state,'blocked');
});
test('missing configuration or unavailable TPM cannot silently fall back to active software licensing',async t=>{
  const f=await fixture(t);f.client.config={endpoint:null,publicKeys:{}};assert.equal(f.client.status().state,'unconfigured');await assert.rejects(f.client.precheck({code:f.code()}),{code:'LICENSE_CONFIG'});
  f.client.config={endpoint:'https://isolated.invalid',publicKeys:{fixture:'invalid'}};f.device.info.state='no_tpm';f.client.ready=false;assert.equal(f.client.status().state,'device_required');await assert.rejects(f.client.precheck({code:f.code()}),{code:'LICENSE_DEVICE_REQUIRED'});
});

