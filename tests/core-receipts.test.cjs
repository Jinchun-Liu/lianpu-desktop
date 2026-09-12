'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path');
const {randomBytes}=require('node:crypto');
const {EncryptedStore}=require('../src/core/store.cjs'),{Service}=require('../src/core/service.cjs');
const {REVIEW_TEXT}=require('../src/core/receipts.cjs');
const owner={id:'owner',role:'owner',accountIds:[]},accountId='test-account-1',orderId='test-order-1';
const decision=(t,hypothesis,value,stop)=>t.diagnostic(`假设：${hypothesis}；决策价值：${value}；停止条件：${stop}。`);
async function fixture(t,{connector,primary=true}={}){
  const work=path.join(__dirname,'../work');fs.mkdirSync(work,{recursive:true});const dir=fs.mkdtempSync(path.join(work,'receipt-core-')),file=path.join(dir,'encrypted.sqlite'),key=randomBytes(32);
  const f={dir,key,file,connector};f.open=()=>{f.store=new EncryptedStore(file,key);f.service=new Service(f.store,{connector});};f.open();f.run=(action,payload={},actor=owner)=>f.service.run(action,payload,actor);f.reopen=()=>{f.store.close();f.open();};t.after(()=>{f.store.close();fs.rmSync(dir,{recursive:true,force:true});});
  f.store.put('members',{id:owner.id,role:'owner',enabled:true,accountIds:[]});await f.run('test.seed');
  const base={space:'test',accountId};
  await f.run('entity.save',{kind:'assets',record:{...base,id:'gift-fixed',name:'原始赠品',type:'fixed',link:'https://example.com/original-gift',instructions:'原始说明'}});
  await f.run('entity.save',{kind:'rules',record:{...f.store.get('rules','test-rule-1'),enabled:primary,afterReceipt:true,gifts:[{assetId:'gift-fixed',quantity:1},{assetId:'test-asset-unique',quantity:1}],thankYou:'原始致谢文案'}});
  if(primary)await f.run('delivery.execute',{orderId});
  f.job=()=>f.store.list('serviceJobs').find(j=>j.type==='afterReceipt'&&j.orderId===orderId);
  f.receipt=(payload={})=>f.run('order.event.test',{orderId,type:'receipt_confirmed',...payload});
  f.profile=actions=>f.run('entity.save',{kind:'interactionProfiles',record:{id:'profile',space:'test',accountId,name:'明确启用的买家互动',productId:'test-product-1',enabled:true,actions}});
  f.prefs=patch=>f.run('entity.save',{kind:'settings',record:{...f.store.get('settings','test-preferences'),...patch}});
  return f;
}

test('F30 付款主资料与收货后赠品分阶段，完整版本快照与事件去重跨重启保留',async t=>{
  decision(t,'付款只交主资料，收货才发送付款时约定的赠品版本','决定收货服务可否替代旧的整体阻断','一次完整流程、编辑原资料、重复事件及真实数据库重开');
  const f=await fixture(t);const primary=f.store.list('deliveries')[0];assert.ok(!primary.text.includes('原始赠品'));assert.ok(!primary.text.includes('原始致谢'));assert.equal(f.job().status,'waiting_receipt');assert.equal((await f.run('service.preview',{id:f.job().id})).eligible,false);
  await f.run('entity.save',{kind:'assets',record:{...f.store.get('assets','gift-fixed'),link:'https://example.com/changed',instructions:'之后编辑的说明'}});
  await f.run('entity.save',{kind:'products',record:{...f.store.get('products','test-product-1'),title:'之后编辑的商品名称'}});
  await f.run('entity.save',{kind:'rules',record:{...f.store.get('rules','test-rule-1'),thankYou:'之后修改的致谢'}});
  const receipt=await f.receipt();assert.equal(receipt.event.source,'test');assert.equal(receipt.duplicate,false);const preview=await f.run('service.preview',{id:f.job().id});assert.equal(preview.eligible,true);assert.ok(preview.text.includes('https://example.com/original-gift'));assert.ok(preview.text.endsWith('原始致谢文案'));assert.equal(preview.snapshot.product.title,'数字整理入门资料');assert.ok(!preview.text.includes('之后'));
  const sent=await f.run('service.execute',{id:f.job().id});assert.equal(sent.status,'sent');assert.equal(sent.purpose,'after_receipt');assert.equal(sent.items[0].version,1);assert.equal(f.store.get('inventory',sent.inventoryIds[0]).status,'delivered');assert.equal(f.store.get('orders',orderId).costCents,100);
  assert.equal((await f.receipt({eventId:'重复渠道事件'})).duplicate,true);assert.equal(f.store.list('orderEvents').length,1);assert.equal(f.store.list('serviceJobs').length,1);f.reopen();await f.prefs({autoEnabled:true});const count=f.store.list('deliveries').length;await f.run('automation.tick',{space:'test'});assert.equal(f.store.list('deliveries').length,count);assert.equal(f.job().status,'sent');await assert.rejects(f.run('service.execute',{id:f.job().id}),{code:'SERVICE_BLOCKED'});
});

test('F30 并发同一服务只提交一次，未知跨重启保留且核验后重试原快照',async t=>{
  decision(t,'持久outbox在网络等待期间阻挡并发，未知不自动重发','决定服务重试和库存是否可靠','一次并发冲突、unknown重开与有依据的未发送核验重试');
  let calls=0,release;const wait=new Promise(resolve=>release=resolve);let status='unknown';const f=await fixture(t,{connector:{testOnly:true,sendMessage:async request=>{calls++;if(!request.serviceId)return {status:'sent'};await wait;return {status};}}});await f.receipt();const jobId=f.job().id;
  const first=f.run('service.execute',{id:jobId});await assert.rejects(f.run('service.execute',{id:jobId}),{code:'SERVICE_BLOCKED'});release();const unknown=await first;assert.equal(calls,2);assert.equal(unknown.status,'unknown');assert.equal(f.store.get('inventory',unknown.inventoryIds[0]).status,'reserved');
  f.reopen();await f.prefs({autoEnabled:true});await f.run('automation.tick',{space:'test'});assert.equal(calls,2);assert.equal(f.job().status,'unknown');await assert.rejects(f.run('service.retry',{id:jobId,reason:'还未核验'}),{code:'SERVICE_BLOCKED'});
  await f.run('delivery.verify',{deliveryId:unknown.id,outcome:'not_sent',reason:'隔离连接记录确认此次没有发送'});assert.equal(f.job().status,'verified_not_sent');const retryPreview=await f.run('service.preview',{id:jobId,retry:true});assert.equal(retryPreview.eligible,true);assert.equal(retryPreview.canRetry,true);assert.equal(retryPreview.text,unknown.text);status='sent';const sent=await f.run('service.retry',{id:jobId,reason:'核验后手动重试'});assert.equal(sent.status,'sent');assert.equal(sent.text,unknown.text);assert.deepEqual(sent.inventoryIds,unknown.inventoryIds);assert.equal(calls,3);
});

test('F30 唯一赠品最后一份跨订单原子预留，过期快照不能换码重试',async t=>{
  decision(t,'不同订单竞争最后一份只能一个成功且失败重试不换内容','决定唯一赠品是否可以用于收货后服务','两个订单竞争一次，再验证原条目过期停止');
  const f=await fixture(t);for(const entry of f.store.list('inventory').slice(1))await f.run('inventory.adjust',{id:entry.id,status:'disabled',reason:'隔离最后一份验证'});
  f.store.put('orders',{...f.store.get('orders',orderId),id:'second-order',externalId:'00000000000000000000002',buyerId:'second-buyer'});await f.run('delivery.execute',{orderId:'second-order'});await f.receipt();await f.run('order.event.test',{orderId:'second-order'});
  const jobs=f.store.list('serviceJobs');const results=await Promise.allSettled(jobs.map(job=>f.run('service.execute',{id:job.id})));assert.equal(results.filter(r=>r.status==='fulfilled').length,1);assert.equal(f.store.list('inventory').filter(i=>i.status==='delivered').length,1);
  // A separate rejected attempt retains its exact snapshot; an expired original
  // cannot silently be replaced by another available unique entry.
  const g=await fixture(t);await g.run('account.pause',{id:accountId,paused:false});await g.run('entity.save',{kind:'accounts',record:{id:accountId,testOutcome:'rejected'}});await g.receipt();const rejected=await g.run('service.execute',{id:g.job().id});const entry=g.store.get('inventory',rejected.inventoryIds[0]);g.store.put('inventory',{...entry,expiresAt:new Date(Date.now()-1000).toISOString()});await assert.rejects(g.run('service.retry',{id:g.job().id,reason:'测试到期边界'}),{code:'OUT_OF_STOCK'});assert.equal(g.store.list('deliveries').length,2);
});

test('F30/F41 付款退款、接收方、账号、成员与人工接管逐项阻断',async t=>{
  decision(t,'服务每次重新核对业务和成员范围，事件不能通过普通保存伪造','决定是否能对经营成员开放','付款退款、身份范围、暂停、角色、接管各一次');
  const f=await fixture(t);await f.receipt();const jobId=f.job().id,original=f.store.get('orders',orderId);
  for(const patch of [{paymentStatus:'unpaid'},{refundCents:1},{tradeStatus:'refunding'},{buyerId:'wrong-buyer'},{variantId:'wrong-variant'},{amountCents:1}]){f.store.put('orders',{...original,...patch});assert.equal((await f.run('service.preview',{id:jobId})).eligible,false);}f.store.put('orders',original);
  await f.run('account.pause',{id:accountId,paused:true});await assert.rejects(f.run('service.execute',{id:jobId}),{code:'SERVICE_BLOCKED'});await f.run('account.pause',{id:accountId,paused:false});
  await f.run('conversation.takeover',{id:'test-conversation-1',manual:true});assert.equal((await f.run('service.preview',{id:jobId})).eligible,false);await f.run('conversation.takeover',{id:'test-conversation-1',manual:false});
  f.store.put('members',{id:'limited',role:'operator',enabled:true,accountIds:[]});await assert.rejects(f.run('service.preview',{id:jobId},{id:'limited',role:'owner'}),{code:'FORBIDDEN'});f.store.put('members',{id:'limited',role:'viewer',enabled:true,accountIds:[accountId]});const snapshot=await f.run('workspace.snapshot',{space:'test'},{id:'limited',role:'owner'});assert.equal(snapshot.serviceJobs[0].snapshot,undefined);assert.equal(snapshot.deliveries[0].snapshot,undefined);await assert.rejects(f.run('service.execute',{id:jobId},{id:'limited',role:'owner'}),{code:'FORBIDDEN'});
  await assert.rejects(f.run('entity.save',{kind:'orderEvents',record:f.store.list('orderEvents')[0]}),{code:'PROTECTED'});await assert.rejects(f.run('entity.save',{kind:'serviceJobs',record:{...f.job(),status:'sent'}}),{code:'PROTECTED'});
});

test('F41 逐项启用、收货提醒失效、中性评价邀请与全局自动开关实际生效',async t=>{
  decision(t,'只有明确启用且适用的互动会发送，评价不带利益条件','决定互动档案能否开放给商家','提醒/收货切换、单项停用、全局关闭与启用各一次');
  const f=await fixture(t,{primary:false});const pendingBefore=(await f.run('statistics.get',{space:'test'})).pendingCount;await f.profile({thankYou:{enabled:true,text:'谢谢使用'},receiptReminder:{enabled:true,text:'如已收到可按实际情况确认'},reviewRequest:{enabled:true}});
  await f.run('order.event.test',{orderId,type:'delivery_confirmed'});const reminder=f.store.list('serviceJobs')[0];assert.equal((await f.run('service.preview',{id:reminder.id})).eligible,true);await f.receipt();assert.equal((await f.run('service.preview',{id:reminder.id})).eligible,false);
  const profile=f.store.get('interactionProfiles','profile');await f.profile({...profile.actions,thankYou:{enabled:false,text:'谢谢使用'}});await assert.rejects(f.profile({...profile.actions,reviewRequest:{enabled:true,text:'五星好评后赠送资料'}}),{code:'VALIDATION'});
  assert.equal((await f.run('automation.tick',{space:'test'})).services.length,0);await f.prefs({autoEnabled:true,excludedProductIds:['test-product-1']});assert.equal((await f.run('automation.tick',{space:'test'})).services.length,0);const invitation=f.store.list('serviceJobs').find(j=>j.type==='reviewRequest');assert.equal((await f.run('service.preview',{id:invitation.id})).eligible,true);await f.prefs({excludedProductIds:[]});const tick=await f.run('automation.tick',{space:'test'});assert.equal(tick.services.length,1);assert.equal(tick.services[0].text,REVIEW_TEXT);assert.equal(tick.services[0].purpose,'interaction');assert.equal(tick.processed,1);assert.equal((await f.run('automation.tick',{space:'test'})).services.length,0);
  assert.equal((await f.run('statistics.get',{space:'test'})).pendingCount,pendingBefore);const g=await fixture(t,{primary:false});await g.receipt();await g.profile({thankYou:{enabled:true,text:'不应重放历史事件'}});assert.equal((await g.receipt()).duplicate,true);assert.equal(g.store.list('serviceJobs').length,0);
});

test('F30/F41 正式空间缺能力时阻断，连接器合同拒绝错买家与无回执成功',async t=>{
  decision(t,'布尔能力或本地保存不等于正式收货证据，实际适配器仍须独立验收','决定live门禁而非宣称平台已接入','缺证据、错买家、缺单项能力、无回执四种合同分支');
  let input,sendCalls=0;const f=await fixture(t,{primary:false,connector:{orderEvents:async()=>({status:'ok',verified:true,evidenceId:'synthetic-contract-proof',events:[input]}),sendMessage:async()=>{sendCalls++;return {status:'sent'};}}});
  const timestamp=new Date().toISOString();f.store.put('accounts',{id:'live-account',space:'live',accountId:'live-account',name:'隔离合同账号',paused:false,capabilities:{readReceiptEvents:true,sendMessage:true}});f.store.put('products',{id:'live-product',space:'live',accountId:'live-account',title:'合同商品',variants:[]});f.store.put('orders',{id:'live-order',space:'live',accountId:'live-account',externalId:'00000000000000000000001',buyerId:'live-buyer',productId:'live-product',amountCents:100,refundCents:0,paymentStatus:'paid',tradeStatus:'open',source:'platform',verifiedAt:timestamp,paidAt:timestamp,createdAt:timestamp});
  await assert.rejects(f.run('order.event.test',{orderId:'live-order'}),{code:'TEST_ONLY'});assert.equal((await f.run('order.events.sync',{accountId:'live-account'})).status,'blocked');
  await f.run('entity.save',{kind:'interactionProfiles',record:{id:'live-profile',space:'live',accountId:'live-account',name:'合同邀请',enabled:true,actions:{reviewRequest:{enabled:true}}}});
  const proof={available:true,verified:true,evidenceId:'synthetic-contract-only',verifiedAt:new Date().toISOString()};f.store.put('accounts',{...f.store.get('accounts','live-account'),capabilities:{readReceiptEvents:proof,sendMessage:true}});
  input={orderId:'live-order',type:'receipt_confirmed',externalId:'synthetic-event',buyerId:'wrong',productId:'live-product',occurredAt:new Date().toISOString(),permissions:{reviewRequest:true}};assert.equal((await f.run('order.events.sync',{accountId:'live-account'})).errors[0].code,'WRONG_BUYER');assert.equal(f.store.list('orderEvents').length,0);
  input.buyerId='live-buyer';const synced=await f.run('order.events.sync',{accountId:'live-account'});assert.equal(synced.synced,1);const job=synced.results[0].jobs[0];assert.ok(job);assert.equal((await f.run('service.preview',{id:job.id})).eligible,false);assert.equal(sendCalls,0);
  f.store.put('accounts',{...f.store.get('accounts','live-account'),capabilities:{readReceiptEvents:proof,sendMessage:true,sendReviewRequest:proof}});const result=await f.run('service.execute',{id:job.id});assert.equal(result.status,'unknown');assert.equal(sendCalls,1);assert.equal(f.store.get('serviceJobs',job.id).status,'unknown');
});

test('F30 旧备份保留服务事实，新恢复停止历史服务和事件重放',async t=>{
  decision(t,'备份合并不能清除服务发送或将历史收货变成新触发','决定新集合是否可纳入加密备份','旧包恢复和新库恢复各一次');
  const f=await fixture(t);await f.receipt();const backup=await f.run('backup.create');const sent=await f.run('service.execute',{id:f.job().id});const preview=await f.run('backup.preview',{data:backup});await f.run('backup.restore',{data:backup,confirmation:preview.confirmation});assert.equal(f.job().status,'sent');assert.equal(f.store.get('deliveries',sent.id).status,'sent');assert.equal(f.store.get('inventory',sent.inventoryIds[0]).status,'delivered');
  const g=await fixture(t,{primary:false});for(const kind of ['rules','orders','products','assets','inventory','conversations','messages','accounts','settings'])for(const r of g.store.list(kind))g.store.remove(kind,r.id);const ready=await g.run('backup.preview',{data:backup});assert.equal(ready.valid,true);await g.run('backup.restore',{data:backup,confirmation:ready.confirmation});assert.equal(g.job().status,'stopped');assert.equal(g.store.list('orderEvents')[0].source,'restored');assert.equal((await g.run('service.preview',{id:g.job().id})).eligible,false);g.reopen();assert.equal(g.job().status,'stopped');
});

test('F30 在途撤权仍保存结果，accepted保持占用并禁止通过停止抹除',async t=>{
  decision(t,'外部提交后撤权不丢回执，接受提交不等于送达','决定锁定与人工核验是否仍遵循统一outbox','一次在途撤权、accepted核验和重启');
  let release;const waiting=new Promise(resolve=>release=resolve);const f=await fixture(t,{connector:{testOnly:true,sendMessage:async request=>{if(request.serviceId){await waiting;return {status:'accepted',receiptId:'test-accepted'};}return {status:'sent'};}}});await f.receipt();f.store.put('members',{id:'operator',role:'operator',enabled:true,accountIds:[accountId]});const pending=f.run('service.execute',{id:f.job().id},{id:'operator'});f.store.put('members',{id:'operator',role:'operator',enabled:false,accountIds:[accountId]});release();await assert.rejects(pending,{code:'FORBIDDEN'});
  const accepted=f.store.list('deliveries').find(d=>d.serviceId);assert.equal(accepted.status,'accepted');assert.equal(f.job().status,'accepted');assert.equal(f.store.get('inventory',accepted.inventoryIds[0]).status,'reserved');await assert.rejects(f.run('service.stop',{id:f.job().id,reason:'不可用停止代替核验'}),{code:'SERVICE_IN_FLIGHT'});f.reopen();assert.equal(f.job().status,'accepted');await f.run('delivery.verify',{deliveryId:accepted.id,outcome:'sent',reason:'隔离连接回执核验已发送'});assert.equal(f.job().status,'verified_sent');assert.equal(f.store.get('inventory',accepted.inventoryIds[0]).status,'delivered');
});
