'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const {randomBytes}=require('node:crypto');
const {EncryptedStore}=require('../src/core/store.cjs');
const {Service}=require('../src/core/service.cjs');
const {AccountRuntime}=require('../src/core/account-runtime.cjs');
const stamp=()=>new Date().toISOString(),owner={id:'owner',role:'owner',accountIds:[]};
const deferred=()=>{let resolve;const promise=new Promise(r=>resolve=r);return {promise,resolve};};
function decision(t,hypothesis,value,stop){t.diagnostic(`假设：${hypothesis}；决策价值：${value}；停止条件：${stop}；影响：v1.4 本机运行边界，非真实平台验收`);}
function harness(t){
 const store=new EncryptedStore(':memory:',randomBytes(32));store.put('members',{...owner,name:'管理员',enabled:true});const attempts=new Map(),versions=new Map();let n=0;
 const connector={calls:[],paused:[],async startLogin(p){const attemptId=`attempt-${++n}`,r={attemptId,status:'authenticated',identity:{platformUserId:`platform-${n}`,nickname:`昵称${n}`},...p};attempts.set(attemptId,r);return r;},async getLogin({attemptId}){return attempts.get(attemptId);},async cancelLogin({attemptId}){if(attempts.has(attemptId))attempts.get(attemptId).status='cancelled';return {status:'cancelled'};},async bindLogin({attemptId,accountId}){const r=attempts.get(attemptId),sessionGeneration=(versions.get(accountId)||0)+1;versions.set(accountId,sessionGeneration);return {...r,externalId:r.identity.platformUserId,sessionGeneration,evidenceId:'identity-proof',verifiedAt:stamp(),capabilities:{sendMessages:{available:true,evidenceId:'send-proof',verifiedAt:stamp()}}};},pause(id){this.paused.push(id);},resume(){},pauseAll(){},async drain(){},async disconnect(){},async revoke(){return {status:'cleared'};},async sync(account,kind,{authorize}={}){authorize?.();this.calls.push({accountId:account.id,kind});return {status:'ok',records:[]};},async sendMessage(request){request.authorize?.();return {status:'sent',receiptId:'receipt-1'};}};
 const service=new Service(store,{connector}),runtime=new AccountRuntime({store,service,connector});t.after(()=>store.close());
 const run=(action,p={},actor=owner)=>service.run(action,p,actor);
 const bind=async(platform='platform-a',accountId)=>{const attempt=await runtime.startLogin({accountId},owner);attempts.get(attempt.attemptId).identity.platformUserId=platform;return (await runtime.bindLogin({attemptId:attempt.attemptId},owner)).account;};
 return {store,service,runtime,connector,attempts,run,bind};
}
async function fixture(h,account,{suffix='a',historical=false}={}){
 const base={accountId:account.id,space:'live'},save=(kind,record)=>h.run('entity.save',{kind,record});
 const asset=await save('assets',{...base,id:`asset-${suffix}`,name:'资料',type:'unique'});
 await h.run('inventory.import',{assetId:asset.id,entries:[{content:`content-${suffix}`} ]});
 const product=await save('products',{...base,id:`product-${suffix}`,title:'资料商品',priceCents:100,stock:10,variants:[]});
 const rule=await save('rules',{...base,id:`rule-${suffix}`,name:'付款资料',productId:product.id,assetId:asset.id,quantity:1,enabled:true});
 const order={...base,id:`order-${suffix}`,externalId:`external-${suffix}`,buyerId:`buyer-${suffix}`,productId:product.id,amountCents:100,refundCents:0,paymentStatus:'paid',tradeStatus:'paid',source:'platform',verifiedAt:stamp(),paidAt:historical?'2020-01-01T00:00:00Z':stamp(),evidenceId:'order-proof',createdAt:stamp(),updatedAt:stamp()};h.store.put('orders',order);
 const conversation=await save('conversations',{...base,id:`conversation-${suffix}`,buyerId:order.buyerId,productId:product.id,orderId:order.id,manual:false});return {asset,product,rule,order,conversation};
}
test('v1.4 登录归属、取消、错误身份与重复身份保持本地编号',async t=>{
 decision(t,'可信绑定不能跨成员/目标或重复建档','决定账号管理可交付','四个互斥身份边界各一次');const h=harness(t);const a=await h.bind();const f=await fixture(h,a);
 const duplicate=await h.bind();assert.equal(duplicate.id,a.id);assert.equal(h.store.get('orders',f.order.id).accountId,a.id);assert.equal(duplicate.hosting.enabled,false);
 const bad=await h.runtime.startLogin({accountId:a.id},owner);h.attempts.get(bad.attemptId).identity.platformUserId='other';await assert.rejects(h.runtime.bindLogin({attemptId:bad.attemptId},owner),{code:'IDENTITY_MISMATCH'});
 const cancel=await h.runtime.startLogin({},owner);await h.runtime.cancelLogin({attemptId:cancel.attemptId},owner);await assert.rejects(h.runtime.bindLogin({attemptId:cancel.attemptId},owner),{code:'LOGIN_STALE'});
 h.store.put('members',{id:'second',role:'owner',accountIds:[],enabled:true});await assert.rejects(h.runtime.getLogin({attemptId:bad.attemptId},{id:'second'}),{code:'LOGIN_OWNER'});
});
test('v1.4 并发开始/绑定与锁定后的迟到登录不能落库',async t=>{
 decision(t,'登录请求开始前即有代际控制且绑定序列化','决定并发重试不会错绑','两个并发start和两个同身份bind');const h=harness(t),gate=deferred();const original=h.connector.startLogin.bind(h.connector);let first=true;h.connector.startLogin=async p=>{const r=await original(p);if(first){first=false;await gate.promise;}return r;};
 const old=h.runtime.startLogin({},owner);const current=await h.runtime.startLogin({},owner);gate.resolve();assert.equal((await old).status,'cancelled');
 h.attempts.get(current.attemptId).identity.platformUserId='duplicate';const a=await h.runtime.bindLogin({attemptId:current.attemptId},owner);const b=await h.bind('duplicate');assert.equal(a.accountId,b.id);
 const held=deferred();h.connector.startLogin=async p=>{const r=await original(p);await held.promise;return r;};const late=h.runtime.startLogin({},owner);await h.runtime.cancelLogins();held.resolve();assert.equal((await late).status,'cancelled');
});
test('v1.4 五账号范围与受限 owner 后台上下文、单账号撤权',async t=>{
 decision(t,'后台owner只获得单账号与操作列表，不被成员表放大','决定后台持续运行权限模型','5个账号并行一次及局部撤权一次');const h=harness(t),accounts=[];
 for(let i=0;i<6;i++){const account=await h.bind(`platform-${i}`);accounts.push(account);if(i<5)h.runtime.hosting({accountId:account.id,enabled:true,sync:true,replies:false,paidDelivery:false},owner);}
 assert.throws(()=>h.runtime.hosting({accountId:accounts[5].id,enabled:true},owner),{code:'ACCOUNT_LIMIT'});
 const actor=h.service.authorizeBackground(accounts[0].id);assert.equal(h.service._actor(actor).role,'operator');assert.deepEqual(h.service._actor(actor).accountIds,[accounts[0].id]);await assert.rejects(h.service.run('workspace.snapshot',{space:'live'},actor),{code:'BACKGROUND_SCOPE'});
 h.service.invalidate();assert.equal(h.service._fresh(actor,0),actor);await h.runtime.tick();assert.equal(new Set(h.connector.calls.map(c=>c.accountId)).size,5);
 h.runtime.hosting({accountId:accounts[0].id,enabled:false},owner);assert.throws(()=>h.service._actor(actor),{code:'BACKGROUND_REVOKED'});assert.doesNotThrow(()=>h.service.authorizeBackground(accounts[1].id));
});
test('v1.4 accepted 补发拦截、无回执不成功、库存与重复消息保护',async t=>{
 decision(t,'受理结果必须核验，所有交付成功需要回执','决定交付不可重复和库存完整性','accepted和无回执各一条');const h=harness(t);const a=await h.bind();h.runtime.hosting({accountId:a.id,enabled:true},owner);const f=await fixture(h,a);
 h.connector.sendMessage=async r=>{r.authorize();return {status:'accepted'};};const accepted=await h.run('delivery.execute',{orderId:f.order.id});assert.equal(accepted.status,'accepted');await assert.rejects(h.run('delivery.resend',{orderId:f.order.id,reason:'重试'}),{code:'DELIVERY_BLOCKED'});assert.equal(h.store.list('inventory')[0].status,'reserved');
 await h.run('message.send',{conversationId:f.conversation.id,text:'相同消息'});await assert.rejects(h.run('message.send',{conversationId:f.conversation.id,text:'相同消息'}),{code:'RESULT_UNKNOWN'});
 const g=await fixture(h,a,{suffix:'b'});h.connector.sendMessage=async r=>{r.authorize();return {status:'sent'};};assert.equal((await h.run('delivery.execute',{orderId:g.order.id})).status,'unknown');assert.equal(h.store.list('inventory').find(i=>i.assetId===g.asset.id).status,'reserved');
});
test('v1.4 排队发送前暂停/撤权取消，在途明确回执仍持久化',async t=>{
 decision(t,'队列前重查授权，网络在途结果先落账再拒绝返回','决定撤权和停止托管不破坏事实','提交前和提交后各一次');const h=harness(t);const a=await h.bind();h.runtime.hosting({accountId:a.id,enabled:true},owner);const f=await fixture(h,a),queued=deferred();
 h.connector.sendMessage=async r=>{await queued.promise;r.authorize();return {status:'sent',receiptId:'never'};};const send=h.run('delivery.execute',{orderId:f.order.id});h.runtime.hosting({accountId:a.id,enabled:false},owner);queued.resolve();assert.equal((await send).status,'rejected');assert.equal(h.store.list('inventory')[0].status,'available');
 h.runtime.hosting({accountId:a.id,enabled:true},owner);const actor=h.service.authorizeBackground(a.id),network=deferred();h.connector.sendMessage=async r=>{r.authorize();await network.promise;return {status:'sent',receiptId:'committed-in-flight'};};const prepared=h.service.deliver({orderId:f.order.id},actor,h.service.generation,false);h.runtime.hosting({accountId:a.id,enabled:false},owner);network.resolve();await assert.rejects(prepared,{code:'BACKGROUND_REVOKED'});assert.equal(h.store.list('deliveries').at(-1).receiptId,'committed-in-flight');assert.equal(h.store.list('inventory')[0].status,'delivered');
});
test('v1.4 逐订单事实时效、历史订单不回放与可信字段保护',async t=>{
 decision(t,'同步成功不能伪造核验时间，历史成交不能重复交付','决定真实订单自动处理的证据边界','缺失/过时/历史和字段注入各一次');const h=harness(t);const a=await h.bind();h.runtime.hosting({accountId:a.id,enabled:true,sync:false},owner);const f=await fixture(h,a,{historical:true});
 h.connector.sync=async()=>({status:'ok',records:[{...f.order,verifiedAt:undefined,evidenceId:undefined}]});const old=h.store.get('orders',f.order.id).verifiedAt;const result=await h.run('account.sync',{id:a.id,kind:'orders'});assert.equal(result.synced,0);assert.equal(h.store.get('orders',f.order.id).verifiedAt,old);
 await h.runtime.tick();assert.equal(h.store.list('deliveries').length,0);assert.ok(h.store.list('audit').some(a=>a.summary?.includes('历史订单')));
 await h.run('entity.save',{kind:'accounts',record:{...h.store.get('accounts',a.id),platformUserId:'forged',sessionVersion:999,capabilities:{sendMessages:true},hosting:{enabled:true}}});assert.equal(h.store.get('accounts',a.id).platformUserId,a.platformUserId);assert.notEqual(h.store.get('accounts',a.id).sessionVersion,999);
 const backup=await h.run('backup.create');backup.records.accounts[0].platformUserId='forged';const dest=harness(t),preview=await dest.run('backup.preview',{data:backup});await dest.run('backup.restore',{data:backup,confirmation:preview.confirmation});assert.equal(dest.store.get('accounts',a.id).platformUserId,undefined);
});
test('v1.4 清登录失败不可宣称清除，删除有引用账号归档保留关联',async t=>{
 decision(t,'清理结果和归档事实可审计且失败不恢复运营','决定账号退出与历史保留','失败一次再重试归档一次');const h=harness(t);const a=await h.bind();const f=await fixture(h,a);h.connector.revoke=async()=>({status:'failed'});assert.equal((await h.runtime.clearLogin({accountId:a.id},owner)).status,'cleanup_failed');assert.equal(h.store.get('accounts',a.id).paused,true);h.connector.revoke=async()=>({status:'cleared'});const result=await h.runtime.remove({accountId:a.id},owner);assert.equal(result.archived,true);assert.equal(h.store.get('orders',f.order.id).accountId,a.id);assert.equal(h.store.get('accounts',a.id).archived,true);
});
test('v1.4 全停使后台授权失效并排空在途，再恢复需要显式授权',async t=>{
 decision(t,'停止先撤销新任务再等在途，重新打开不自动授权','决定休眠退出更新的停止顺序','一次停止/重建边界');const h=harness(t),a=await h.bind();h.runtime.hosting({accountId:a.id,enabled:true},owner);const actor=h.service.authorizeBackground(a.id);await h.runtime.beginStop();await h.runtime.drain();assert.throws(()=>h.service._actor(actor),{code:'BACKGROUND_REVOKED'});assert.equal(h.store.get('_hosting',a.id).enabled,false);const runtime=new AccountRuntime({store:h.store,service:h.service,connector:h.connector});assert.equal(runtime.status().activeAccounts,0);assert.equal(h.store.get('accounts',a.id).paused,true);
});
test('v1.4 绑定等待期间降级拒绝新账号，operator删除在清会话前拒绝',async t=>{
 decision(t,'登录权限在每次等待后复核，删除先检查完整权限','决定成员管理不会残留授权副作用','一次绑定降级及一次越权删除');const h=harness(t),a=await h.bind();
 h.store.put('members',{id:'operator',role:'operator',accountIds:[a.id],enabled:true});let revokes=0;h.connector.revoke=async()=>{revokes++;return {status:'cleared'};};await assert.rejects(h.runtime.remove({accountId:a.id},{id:'operator'}),{code:'FORBIDDEN'});assert.equal(revokes,0);assert.equal(h.store.get('accounts',a.id).loginStatus,'authenticated');
 const attempt=await h.runtime.startLogin({},owner),wait=deferred(),original=h.connector.bindLogin.bind(h.connector);h.connector.bindLogin=async p=>{const result=await original(p);await wait.promise;return result;};const binding=h.runtime.bindLogin({attemptId:attempt.attemptId},owner);await new Promise(resolve=>setImmediate(resolve));h.store.put('members',{...h.store.get('members',owner.id),role:'operator',accountIds:[a.id]});wait.resolve();await assert.rejects(binding,{code:'LOGIN_PERMISSION_CHANGED'});assert.equal(h.store.list('accounts').length,1);assert.equal(revokes,1);
});
test('v1.4 迟到状态不能重启暂停账号或跨越会话，能力证据过期失效',async t=>{
 decision(t,'状态回写只接受当前代际与新鲜证据','决定真实能力显示不会被旧检查恢复','旧代际、暂停、过期各一次');const h=harness(t),a=await h.bind();h.runtime.hosting({accountId:a.id,enabled:true},owner);
 assert.equal(h.runtime.observeStatus({accountId:a.id,sessionVersion:a.sessionVersion-1,loginStatus:'connected',connectionStatus:'connected'}),false);
 h.runtime.hosting({accountId:a.id,enabled:false},owner);h.runtime.observeStatus({accountId:a.id,sessionVersion:a.sessionVersion,loginStatus:'connected',connectionStatus:'connected',capabilities:{sendMessages:{available:true,sessionVersion:a.sessionVersion,verifiedAt:'2020-01-01T00:00:00Z',evidenceId:'old'}}});const account=h.store.get('accounts',a.id);assert.equal(account.paused,true);assert.equal(account.connectionStatus,'disconnected');assert.equal(account.capabilities.sendMessages.available,false);
});
test('v1.4 排队期间订单变已发货或已完成，最终提交取消且不消耗库存',async t=>{
 decision(t,'预览后平台订单状态变化仍在最终发送前阻断','决定排队不会重复交付平台已处理订单','已发货与已完成各一次且发送调用计数为零');const h=harness(t),a=await h.bind();h.runtime.hosting({accountId:a.id,enabled:true},owner);let submitted=0;
 for(const tradeStatus of ['shipped','completed']){const f=await fixture(h,a,{suffix:tradeStatus}),gate=deferred();h.connector.sendMessage=async request=>{await gate.promise;request.authorize();submitted++;return {status:'sent',receiptId:'should-not-submit'};};const pending=h.run('delivery.execute',{orderId:f.order.id});assert.equal(h.store.list('inventory').find(i=>i.assetId===f.asset.id).status,'reserved');h.store.put('orders',{...h.store.get('orders',f.order.id),tradeStatus,verifiedAt:stamp()});gate.resolve();assert.equal((await pending).status,'rejected');assert.equal(h.store.list('inventory').find(i=>i.assetId===f.asset.id).status,'available');}
 assert.equal(submitted,0);
});
test('v1.4 登录过期撤销单账号授权，排队动作取消且其他账号继续同步',async t=>{
 decision(t,'连接器login_required立即撤销该账号后台并阻止迟到恢复','决定实际过期状态不会无限重试或误继续发送','一个排队过期账号与一个健康账号并行验证');const h=harness(t),a=await h.bind('expired-account'),b=await h.bind('healthy-account');for(const account of [a,b])h.runtime.hosting({accountId:account.id,enabled:true},owner);const f=await fixture(h,a),actor=h.service.authorizeBackground(a.id),gate=deferred();let submitted=0;
 h.connector.sendMessage=async request=>{await gate.promise;request.authorize();submitted++;return {status:'sent',receiptId:'should-not-submit'};};const pending=h.service.deliver({orderId:f.order.id},actor,h.service.generation,false);
 h.runtime.observeStatus({accountId:a.id,sessionVersion:a.sessionVersion,loginStatus:'login_required',connectionStatus:'disconnected',reason:'平台要求重新扫码'});assert.equal(h.store.get('_hosting',a.id).enabled,false);assert.equal(h.store.get('accounts',a.id).paused,true);assert.ok(h.connector.paused.includes(a.id));assert.equal(h.store.get('_hosting',b.id).enabled,true);
 gate.resolve();await assert.rejects(pending,{code:'BACKGROUND_REVOKED'});assert.equal(h.store.list('deliveries').at(-1).status,'rejected');assert.equal(submitted,0);
 h.runtime.observeStatus({accountId:a.id,sessionVersion:a.sessionVersion,loginStatus:'connected',connectionStatus:'connected'});await h.runtime.tick();assert.deepEqual([...new Set(h.connector.calls.map(c=>c.accountId))],[b.id]);assert.equal(h.store.get('accounts',a.id).paused,true);
});
test('restart marks a saved identity unchecked and read-only connection never grants hosting',async t=>{
 decision(t,'重启不能把未核验会话误标为失效，检查连接不能开启托管','决定实号只读检查可以安全单独使用','一次重建及一个受信只读状态事件');
 const h=harness(t),a=await h.bind();const runtime=new AccountRuntime({store:h.store,service:h.service,connector:h.connector});
 const before=h.store.get('accounts',a.id);assert.equal(before.loginStatus,'unverified');assert.equal(before.sessionVersion,a.sessionVersion);assert.equal(before.paused,true);
 runtime.observeStatus({accountId:a.id,sessionVersion:a.sessionVersion,loginStatus:'authenticated',connectionStatus:'connected',readOnlyCheck:true});
 const after=h.store.get('accounts',a.id);assert.equal(after.loginStatus,'authenticated');assert.equal(after.connectionStatus,'connected');assert.equal(after.paused,true);assert.equal(after.hosting.enabled,false);assert.equal(runtime.status().activeAccounts,0);
});
