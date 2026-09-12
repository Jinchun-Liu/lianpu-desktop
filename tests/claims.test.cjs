'use strict';
const test=require('node:test');
const assert=require('node:assert/strict');
const http=require('node:http');
const {randomBytes}=require('node:crypto');
const {EncryptedStore}=require('../src/core/store.cjs');
const {ClaimsEngine,COLLECTIONS,MAX_FILE_BYTES}=require('../src/services/claims.cjs');
const owner={id:'owner',role:'owner',accountIds:[]};
function request(url,{method='GET',headers={}}={}){return new Promise((resolve,reject)=>{const req=http.request(url,{method,headers},res=>{const chunks=[];res.on('data',chunk=>chunks.push(chunk));res.on('end',()=>resolve({status:res.statusCode,headers:res.headers,body:Buffer.concat(chunks)}));});req.on('error',reject);req.end();});}
function fixture(t){
  const store=new EncryptedStore(':memory:',randomBytes(32));const time={value:Date.now()};const engine=new ClaimsEngine(store,{clock:()=>time.value});
  const at=new Date(time.value).toISOString();store.put('members',{id:'owner',role:'owner',enabled:true,accountIds:[]});store.put('members',{id:'operator',role:'operator',enabled:true,accountIds:['account']});store.put('members',{id:'viewer',role:'viewer',enabled:true,accountIds:['account']});
  for(const [id,space]of [['account','test'],['other','test'],['live','live']])store.put('accounts',{id,space,accountId:id,name:id,paused:false});
  for(const [id,accountId,space]of [['order','account','test'],['other-order','other','test'],['live-order','live','live']])store.put('orders',{id,accountId,space,buyerId:`buyer-${id}`,paymentStatus:'paid',tradeStatus:'open',refundCents:0,createdAt:at});
  t.after(async()=>{await engine.stop();store.close();});
  const add=(name='资料示例.txt',bytes=Buffer.from('独立编写的加密领取内容'))=>engine.addFile({name,bytes,space:'test',accountId:'account',rightsConfirmed:true},owner);
  const grant=(fileId,maxClaims=1)=>engine.createGrant({orderId:'order',fileId,maxClaims,expiresAt:new Date(time.value+60000).toISOString()},owner);
  return {store,engine,time,add,grant};
}

test('F20 文件加密、权利确认、权限及仅测试订单边界',async t=>{
  t.diagnostic('假设：文件入库不暴露明文且仅授权成员能生成测试单授权；决策价值：决定可否提供本机领取原型；停止条件：文件、角色、账号和live边界各一次。');
  const f=fixture(t);const bytes=Buffer.from('CLAIM_PRIVATE_BYTES_这是独立内容');const file=f.add('资料.txt',bytes);assert.equal(file.size,bytes.length);assert.equal(file.data,undefined);assert.equal(f.engine.listFiles({space:'test'},owner)[0].data,undefined);
  const ciphertext=f.store.db.prepare('SELECT payload FROM records WHERE kind=? AND id=?').get(COLLECTIONS.files,file.id).payload;assert.equal(Buffer.from(ciphertext).includes(bytes),false);
  assert.throws(()=>f.engine.addFile({name:'missing-rights.txt',bytes,space:'test',accountId:'account'},owner),{code:'FILE_RIGHTS'});
  assert.throws(()=>f.engine.addFile({name:'large.bin',bytes:Buffer.alloc(MAX_FILE_BYTES+1),space:'test',accountId:'account',rightsConfirmed:true},owner),{code:'FILE_SIZE'});
  assert.throws(()=>f.engine.listFiles({space:'test'},{id:'viewer',role:'owner'}),{code:'FORBIDDEN'});
  assert.throws(()=>f.engine.createGrant({orderId:'other-order',fileId:file.id,maxClaims:1,expiresAt:new Date(f.time.value+60000).toISOString()},owner),{code:'CLAIM_FILE_SCOPE'});
  assert.throws(()=>f.engine.createGrant({orderId:'live-order',fileId:file.id,maxClaims:1,expiresAt:new Date(f.time.value+60000).toISOString()},owner),{code:'PUBLIC_HOSTING_UNAVAILABLE'});
  const grant=f.grant(file.id);assert.equal(grant.token.length,43);assert.equal(grant.public,false);assert.equal(f.engine.listGrants({space:'test'},owner)[0].token,undefined);assert.equal(f.engine.listGrants({space:'test'},owner)[0].tokenHash,undefined);assert.equal(JSON.stringify(f.store.list(COLLECTIONS.grants)).includes(grant.token),false);
});

test('F20 页面访问不计领取，并发最后一次仅一个文件响应',async t=>{
  t.diagnostic('假设：SQLite事务可限制并发最后一次且页面只产生page_opened；决策价值：决定次数限制能否开启；停止条件：一次页面访问及两个并发POST最多一成功。');
  const f=fixture(t);const file=f.add('<资料> "你好".txt');const grant=f.grant(file.id);const preview=await f.engine.startLocalPreview({grantId:grant.id,token:grant.token},owner);assert.equal(new URL(preview.url).hostname,'127.0.0.1');assert.equal(f.engine.server.address().address,'127.0.0.1');
  const page=await request(preview.url);assert.equal(page.status,200);assert.ok(page.body.toString().includes('&lt;资料&gt;'));assert.equal(f.store.get(COLLECTIONS.grants,grant.id).claimsStarted,0);assert.equal(f.engine.accessLog({grantId:grant.id},owner)[0].event,'page_opened');
  const options={method:'POST',headers:{Origin:new URL(preview.url).origin,'Content-Length':'0'}};const results=await Promise.all([request(preview.url+'/download',options),request(preview.url+'/download',options)]);assert.deepEqual(results.map(r=>r.status).sort(),[200,409]);assert.equal(f.store.get(COLLECTIONS.grants,grant.id).claimsStarted,1);const success=results.find(r=>r.status===200);assert.equal(success.headers['content-type'],'application/octet-stream');assert.match(success.headers['content-disposition'],/^attachment;/);
  const events=f.engine.accessLog({grantId:grant.id},owner);assert.equal(events.filter(e=>e.event==='access_started').length,1);assert.equal(events.filter(e=>e.event==='response_finished').length,1);assert.equal(events.some(e=>JSON.stringify(e).includes(grant.token)),false);assert.equal(events.some(e=>e.event==='download_complete'),false);assert.equal(f.store.get('orders','order').paymentStatus,'paid');assert.equal(f.store.get('orders','order').deliveryStatus,undefined);
});

test('F20 到期、撤回、退款、权限撤回和锁定停止',async t=>{
  t.diagnostic('假设：每次HTTP访问重新核对到期与业务权限，stop立即关本机监听；决策价值：判断撤回和锁定是否可靠；停止条件：五个不同禁止条件各验证一次。');
  const f=fixture(t);const file=f.add();const grant=f.grant(file.id,3);const preview=await f.engine.startLocalPreview({grantId:grant.id,token:grant.token},{id:'operator',role:'operator'});
  f.time.value+=60001;assert.equal((await request(preview.url)).status,410);f.time.value-=60001;
  f.store.put('orders',{...f.store.get('orders','order'),tradeStatus:'refunding'});assert.equal((await request(preview.url)).status,410);f.store.put('orders',{...f.store.get('orders','order'),tradeStatus:'open'});
  f.store.put('members',{...f.store.get('members','operator'),accountIds:[]});assert.equal((await request(preview.url)).status,403);f.store.put('members',{...f.store.get('members','operator'),accountIds:['account']});
  f.engine.revoke({id:grant.id,reason:'停止本机试运行'},owner);assert.equal((await request(preview.url)).status,410);assert.equal(f.store.get(COLLECTIONS.grants,grant.id).claimsStarted,0);
  await f.engine.stop();assert.equal(f.engine.server,null);await assert.rejects(request(preview.url),error=>['ECONNREFUSED','ECONNRESET'].includes(error.code));
});

test('F20 本机Origin/Host与方法限制不消耗领取次数',async t=>{
  t.diagnostic('假设：外部网页不能通过替换Host或跨源POST消耗本机token；决策价值：确定loopback服务访问边界；停止条件：错误host、跨源/null/缺失origin与GET附件各一次。');
  const f=fixture(t);const grant=f.grant(f.add().id);const preview=await f.engine.startLocalPreview({grantId:grant.id,token:grant.token},owner);
  assert.equal((await request(preview.url,{headers:{Host:'external.example'}})).status,403);
  assert.equal((await request(preview.url+'/download',{method:'POST',headers:{Origin:'https://external.example','Content-Length':'0'}})).status,403);
  assert.equal((await request(preview.url+'/download',{method:'POST',headers:{Origin:'null','Content-Length':'0'}})).status,403);
  assert.equal((await request(preview.url+'/download',{method:'POST',headers:{'Content-Length':'0'}})).status,403);
  assert.equal((await request(preview.url+'/download')).status,405);assert.equal(f.store.get(COLLECTIONS.grants,grant.id).claimsStarted,0);
  assert.equal((await request(preview.url.replace(grant.token,'A'.repeat(43)))).status,404);
});

test('F20/F45 恢复旧备份不返还次数或重启旧令牌',async t=>{
  t.diagnostic('假设：领取次数和响应记录不会被旧包抹去，恢复后令牌一律撤回；决策价值：决定备份迁移是否安全；停止条件：领取后恢复领取前备份一次。');
  const f=fixture(t);const grant=f.grant(f.add().id,2);const older=f.engine.exportBackup(owner);const preview=await f.engine.startLocalPreview({grantId:grant.id,token:grant.token},owner);await request(preview.url+'/download',{method:'POST',headers:{Origin:new URL(preview.url).origin,'Content-Length':'0'}});assert.equal(f.store.get(COLLECTIONS.grants,grant.id).claimsStarted,1);const accessCount=f.store.list(COLLECTIONS.access).length;
  assert.equal(f.engine.validateBackup(older).grantCount,1);const restored=f.engine.restore(older,owner);assert.equal(restored.grantsRevoked,true);assert.equal(f.store.get(COLLECTIONS.grants,grant.id).claimsStarted,1);assert.equal(f.store.list(COLLECTIONS.access).length,accessCount);assert.equal((await request(preview.url)).status,410);
  await assert.rejects(f.engine.startLocalPreview({grantId:grant.id,token:grant.token},owner),{code:'CLAIM_REVOKED'});
});

test('F20 中断文件响应保留已占用次数与不完整证据',async t=>{
  t.diagnostic('假设：客户端收到首块后中断不会返还已开始次数或产生下载完成声明；决策价值：决定网络异常时次数策略是否可靠；停止条件：一次受控中断即可。');
  const f=fixture(t);const file=f.add('large-test.bin',Buffer.alloc(MAX_FILE_BYTES,0x53));const grant=f.grant(file.id,2);const preview=await f.engine.startLocalPreview({grantId:grant.id,token:grant.token},owner);
  await new Promise((resolve,reject)=>{const req=http.request(preview.url+'/download',{method:'POST',headers:{Origin:new URL(preview.url).origin,'Content-Length':'0'}},res=>{res.once('data',()=>{res.destroy();resolve();});res.on('error',()=>{});});req.on('error',reject);req.end();});
  for(let attempt=0;attempt<50&&!f.store.list(COLLECTIONS.access).some(event=>event.event==='response_interrupted');attempt++)await new Promise(resolve=>setTimeout(resolve,5));
  assert.equal(f.store.get(COLLECTIONS.grants,grant.id).claimsStarted,1);const events=f.engine.accessLog({grantId:grant.id},owner);assert.equal(events.filter(event=>event.event==='access_started').length,1);assert.equal(events.filter(event=>event.event==='response_interrupted').length,1);assert.equal(events.some(event=>event.event==='response_finished'),false);
});
