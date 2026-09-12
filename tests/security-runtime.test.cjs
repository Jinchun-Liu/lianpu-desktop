'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const fs=require('node:fs'),path=require('node:path'),{randomBytes}=require('node:crypto');
const {RuntimePolicy,UNSAFE_SWITCHES,isTrustedSender}=require('../src/security/runtime-policy.cjs');
const {Service}=require('../src/core/service.cjs'),{EncryptedStore}=require('../src/core/store.cjs');
const owner={id:'owner',role:'owner',accountIds:[]};
// R1/R2 hypotheses, decision value and stop rules recorded before execution in
// ../experiment-plan.md (delivery root). All connector calls below are synthetic.
test('official launch policy rejects dangerous switches while developer diagnostics remain available',()=>{
  for(const flag of UNSAFE_SWITCHES){assert.throws(()=>new RuntimePolicy({packaged:true,hasSwitch:name=>name===flag}).assertAllowed(),{code:'SECURITY_LAUNCH_POLICY'});assert.equal(new RuntimePolicy({packaged:false,hasSwitch:()=>true}).assertAllowed(),true);}
  assert.equal(new RuntimePolicy({packaged:true,hasSwitch:()=>false}).assertAllowed(),true);
});
test('IPC requires exact main frame, owning window, and local URL; destroyed frames fail closed',()=>{
  const mainFrame={url:'lianpu://app/index.html'},wc={mainFrame},window={webContents:wc,isDestroyed:()=>false};
  const valid={sender:wc,senderFrame:mainFrame};assert.equal(isTrustedSender(valid,window,mainFrame.url),true);
  for(const event of [{...valid,sender:{}},{...valid,senderFrame:{url:mainFrame.url}},null,{sender:wc,get senderFrame(){throw Error('disposed');}}])assert.equal(isTrustedSender(event,window,mainFrame.url),false);
  assert.equal(isTrustedSender(valid,{...window,isDestroyed:()=>true},mainFrame.url),false);
  for(const url of ['https://app/index.html','lianpu://app/index.html?x=1','lianpu://evil/index.html'])assert.equal(isTrustedSender(valid,window,url),false);
});
async function fixture(t,connector={}) {
  const work=path.resolve(__dirname,'../work/security-runtime');fs.mkdirSync(work,{recursive:true});
  const directory=fs.mkdtempSync(path.join(work,'case-')),store=new EncryptedStore(path.join(directory,'synthetic.sqlite'),randomBytes(32));
  t.after(()=>store.close());let restricted=false;
  const policy=new RuntimePolicy({packaged:true,hasSwitch:name=>restricted&&name==='remote-debugging-port'});
  const service=new Service(store,{connector:{testOnly:true,...connector},assertLicense:()=>policy.assertAllowed()});
  await service.run('test.seed',{},owner);store.put('rules',{...store.get('rules','test-rule-1'),enabled:true,assetId:'test-asset-unique'});
  const product=store.get('products','test-product-1');store.put('products',{...product,variants:product.variants.map(variant=>({...variant,assetId:'test-asset-unique'}))});
  return {store,service,restrict:()=>{restricted=true;},allow:()=>{restricted=false;},run:(name,p={})=>service.run(name,p,owner)};
}
test('runtime restriction reaches real core operations while read, backup and unknown inventory survive',async t=>{
  const f=await fixture(t,{sendMessage:async()=>({status:'unknown'})});
  const result=await f.run('delivery.execute',{orderId:'test-order-1'});assert.equal(result.status,'unknown');
  const before=f.store.list('inventory');f.restrict();
  await assert.rejects(f.run('message.send',{conversationId:'test-conversation-1',text:'no send'}),{code:'SECURITY_LAUNCH_POLICY'});
  assert.throws(()=>f.service.authorizeBackground('test-account-1'),{code:'SECURITY_LAUNCH_POLICY'});
  assert.ok(await f.run('workspace.snapshot',{space:'test'}));assert.ok(await f.run('backup.create'));
  assert.deepEqual(f.store.list('inventory'),before);assert.equal(f.store.get('deliveries',result.id).status,'unknown');
});
test('accepted in-flight receipt persists after runtime restriction',async t=>{
  let release;const gate=new Promise(resolve=>release=resolve);
  const f=await fixture(t,{sendMessage:async()=>{await gate;return {status:'sent',receiptId:'synthetic-confirmed-receipt'};}});
  const pending=f.run('delivery.execute',{orderId:'test-order-1'});f.restrict();release();
  const result=await pending;assert.equal(result.status,'sent');assert.equal(f.store.get('deliveries',result.id).receiptId,'synthetic-confirmed-receipt');
  assert.equal(f.store.get('inventory',result.inventoryIds[0]).status,'delivered');
});
test('queued product authorization failure is not submitted and can be retried after recovery',async t=>{
  let release,request,submissions=0;const gate=new Promise(resolve=>release=resolve);
  const f=await fixture(t,{mutateProduct:async input=>{request=input;await gate;input.authorize();submissions++;return {status:'sent',receiptId:'synthetic-retry-receipt'};}});
  const preview=await f.run('batch.preview',{ids:['test-product-1'],changes:{priceCents:2090}});
  const pending=f.run('batch.execute',{previewId:preview.id});assert.equal(typeof request.authorize,'function');f.restrict();release();
  const batch=await pending;assert.equal(batch.results[0].status,'rejected');assert.equal(submissions,0);assert.equal(f.store.get('products','test-product-1').priceCents,1990);
  f.allow();const retried=await f.run('batch.execute',{id:batch.id});assert.equal(retried.results[0].status,'sent');assert.equal(submissions,1);assert.equal(f.store.get('products','test-product-1').priceCents,2090);
});

test('product connection uncertainty remains unknown and cannot be directly retried',async t=>{
  let attempts=0;const f=await fixture(t,{mutateProduct:async input=>{input.authorize();attempts++;throw Error('synthetic connection lost');}});
  const preview=await f.run('batch.preview',{ids:['test-product-1'],changes:{priceCents:2090}});
  const batch=await f.run('batch.execute',{previewId:preview.id});assert.equal(batch.results[0].status,'unknown');
  await f.run('batch.execute',{id:batch.id});assert.equal(attempts,1);assert.equal(f.store.get('products','test-product-1').priceCents,1990);
});
test('synthetic live-mode product success without a receipt stays unknown',async t=>{
  const f=await fixture(t,{mutateProduct:async()=>({status:'sent'})});
  for(const kind of ['accounts','products'])for(const record of f.store.list(kind))f.store.put(kind,{...record,space:'live'});
  const preview=await f.run('batch.preview',{ids:['test-product-1'],changes:{priceCents:2090}});
  const batch=await f.run('batch.execute',{previewId:preview.id});assert.equal(batch.results[0].status,'unknown');assert.equal(f.store.get('products','test-product-1').priceCents,1990);
});
