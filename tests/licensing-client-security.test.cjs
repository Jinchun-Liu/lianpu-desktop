'use strict';
// LD01/LD04 are registered in ../evidence-security/license-device-experiments.md.
// Only injected software keys, clocks, local scratch and an in-memory issuer.
const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs');
const {fixture}=require('./licensing-client-fixture.cjs');

test('v1 canonical signatures retain JSON bytes while rejecting non-data and sparse arrays',async()=>{
  const p=await import('../shared/licensing/protocol.mjs');
  assert.equal(p.canonicalJson({z:[1,'二',true,null],a:{x:3}}),'{"a":{"x":3},"z":[1,"二",true,null]}');
  const sparse=new Array(2);sparse.a=1;sparse.b=2;
  let called=false;const accessor={};Object.defineProperty(accessor,'a',{enumerable:true,get(){called=true;return 1;}});
  const hidden={};Object.defineProperty(hidden,'a',{value:1});
  for(const value of [sparse,accessor,hidden,{[Symbol('ignored')]:1}])assert.throws(()=>p.canonicalJson(value),{code:'INVALID_CANONICAL_JSON'});
  assert.equal(called,false);assert.throws(()=>p.validateLicensePayload({v:2}),{code:'INVALID_FORMAT'});
});

test('locally signed malformed state and noncanonical signature cannot reset validated clock state',async t=>{
  const f=await fixture(t);await f.activate();const valid=JSON.parse(fs.readFileSync(f.client.file,'utf8'));
  for(const modify of [x=>{x.signature+='=';},x=>{x.body.clock=null;},x=>{x.body.clock.highWater=-1;},x=>{x.body.pending={requestId:'unexpected'};},x=>{x.extra='ignored';}]){
    const value=structuredClone(valid);modify(value);
    if(value.signature===valid.signature)value.signature=f.device.signSync(f.client._stateBytes(value.body)).toString('base64url');
    fs.writeFileSync(f.client.file,JSON.stringify(value));const candidate=f.make();await candidate.initialize();
    assert.equal(candidate.status().state,'blocked');assert.equal(candidate.status().active,false);assert.equal(candidate.body.pending,null);
  }
});

test('a signed mode substitution is rejected before finalization reaches transport',async t=>{
  const f=await fixture(t),pre=await f.client.precheck({code:f.code()}),pending=f.client.body.pending;
  pending.ticket=await f.protocol.signEnvelope({...pending.ticket.payload,mode:'recover',plan:null,codeHash:null},'ticket','fixture',f.signing.privateKey);
  const requests=f.requests.length;await assert.rejects(f.client.confirm({requestId:pre.requestId}),{code:'LICENSE_TICKET_MISMATCH'});
  assert.equal(f.requests.length,requests);assert.equal(f.consumeCount,0);assert.equal(f.client.status().active,false);
});

test('same-revision changed rights and license identity cannot overwrite the saved grant',async t=>{
  const f=await fixture(t);await f.activate();const original=structuredClone(f.client.payload);
  f.records.set(original.requestId,{...original,expiresAt:original.expiresAt+1000});
  await assert.rejects(f.client.recover({}),{code:'LICENSE_STALE'});assert.deepEqual(f.client.payload,original);assert.equal(f.client.status().active,true);
});

test('expired recovery preserves original expiry and never grants another period',async t=>{
  const f=await fixture(t);await f.activate();const expiry=f.client.payload.expiresAt;
  f.now=expiry+1000;f.mono=7*86400000+1000;await f.client.recover({});
  assert.equal(f.client.payload.expiresAt,expiry);assert.equal(f.client.status().state,'expired');assert.throws(()=>f.client.assertAllowed(),{code:'LICENSE_REQUIRED'});assert.equal(f.consumeCount,1);
});

test('documented residual: complete signed old-state plus old wall clock has no independent rollback anchor',async t=>{
  const f=await fixture(t);await f.activate();const originalTime=f.now,oldState=fs.readFileSync(f.client.file);
  f.now+=600000;f.mono+=600000;f.client.assertAllowed();
  fs.writeFileSync(f.client.file,oldState);f.now=originalTime;f.mono=0;const restored=f.make();await restored.initialize();
  assert.equal(restored.status().active,true,'Known boundary; never describe local signed state as an anti-rollback counter.');
});
