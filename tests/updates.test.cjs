'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path'),http=require('node:http');
const {generateKeyPairSync,createHash,sign,randomBytes}=require('node:crypto');
const {EncryptedStore}=require('../src/core/store.cjs');
const {UpdateManager,canonical,verifyManifest,fetchBytes}=require('../src/services/updates.cjs');
const pair=generateKeyPairSync('ed25519');const keys=[{id:'test-key',publicKey:pair.publicKey.export({format:'pem',type:'spki'}),channel:'development',label:'isolated test key'}];
const data=Buffer.concat([Buffer.from('d0cf11e0a1b11ae1','hex'),Buffer.from('Synthetic signed container only; not installed.')]);
function envelope(fields={}){const manifest={format:'lianpu-update-v1',keyId:'test-key',product:'lianpu-desktop',version:'0.2.0',minVersion:'0.1.0',platform:'win32',arch:'x64',channel:'development',issuedAt:new Date(Date.now()-1000).toISOString(),expiresAt:new Date(Date.now()+86400000).toISOString(),notes:['Isolated update contract'],artifact:{filename:'Lianpu-0.2.0-windows-x64-setup.msi',size:data.length,sha256:createHash('sha256').update(data).digest('hex')},...fields};return {manifest,signature:sign(null,Buffer.from(canonical(manifest)),pair.privateKey).toString('base64')};}
function fixture(t){const dir=path.resolve(__dirname,'../work',`update-test-${Date.now()}-${randomBytes(4).toString('hex')}`);fs.mkdirSync(dir,{recursive:true});const store=new EncryptedStore(':memory:',randomBytes(32));store.put('members',{id:'owner',role:'owner',enabled:true});store.put('members',{id:'viewer',role:'viewer',enabled:true});const manager=new UpdateManager({getStore:()=>store,keys,currentVersion:'0.1.0',downloadRoot:path.join(dir,'prepared')});t.after(()=>store.close());return {dir,store,manager,actor:{id:'owner'}};}
test('F47 signed manifest rejects tampering, unknown roots, wrong architecture and downgrade',()=>{
 const good=envelope();assert.equal(verifyManifest(good,{keys,currentVersion:'0.1.0'}).manifest.version,'0.2.0');
 const edited=structuredClone(good);edited.manifest.notes=['tampered'];assert.throws(()=>verifyManifest(edited,{keys,currentVersion:'0.1.0'}),{code:'UPDATE_SIGNATURE'});
 assert.throws(()=>verifyManifest(good,{keys:[],currentVersion:'0.1.0'}),{code:'UPDATE_UNTRUSTED_KEY'});
 assert.throws(()=>verifyManifest(envelope({arch:'arm64'}),{keys,currentVersion:'0.1.0'}),{code:'UPDATE_TARGET'});
 assert.throws(()=>verifyManifest(good,{keys,currentVersion:'0.2.0'}),{code:'UPDATE_NOT_NEWER'});
 assert.throws(()=>verifyManifest(envelope({expiresAt:new Date(Date.now()-1).toISOString()}),{keys,currentVersion:'0.1.0'}),{code:'UPDATE_EXPIRED'});
});
test('F47 local signed bundle is copied and rechecked before installation',async t=>{
 const f=fixture(t),signed=envelope(),manifestFile=path.join(f.dir,'release.lianpu-update');fs.writeFileSync(manifestFile,JSON.stringify(signed));fs.writeFileSync(path.join(f.dir,signed.manifest.artifact.filename),data);
 assert.throws(()=>f.manager.importManifest(manifestFile,{id:'viewer'}),{code:'FORBIDDEN'});
 const preview=f.manager.importManifest(manifestFile,f.actor);assert.equal(preview.signatureVerified,true);assert.equal(preview.windowsPublisherVerified,false);const ready=await f.manager.prepare({id:preview.id},f.actor);assert.equal(ready.ready,true);
 const prepared=f.manager.previews.get(preview.id).preparedPath;fs.appendFileSync(prepared,'changed');assert.throws(()=>f.manager.takeForInstallation({id:preview.id},f.actor),{code:'UPDATE_HASH'});
 const second=f.manager.importManifest(manifestFile,f.actor);await f.manager.prepare({id:second.id},f.actor);const launch=f.manager.takeForInstallation({id:second.id},f.actor);assert.equal(fs.readFileSync(launch.path).equals(data),true);assert.equal(f.store.list('_updateHistory')[0].status,'launch_requested');assert.throws(()=>f.manager.takeForInstallation({id:second.id},f.actor),{code:'UPDATE_PREVIEW'});
});
test('F47 real loopback feed and artifact fetch enforce redirect and permission boundaries',async t=>{
 const f=fixture(t);let url;const server=http.createServer((req,res)=>{if(req.url==='/redirect'){res.writeHead(302,{Location:'/feed'}).end();return;}if(req.url==='/artifact'){res.end(data);return;}const signed=envelope();signed.manifest.artifact.url=url+'/artifact';signed.signature=sign(null,Buffer.from(canonical(signed.manifest)),pair.privateKey).toString('base64');res.setHeader('Content-Type','application/json');res.end(JSON.stringify(signed));});await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));url=`http://127.0.0.1:${server.address().port}`;t.after(()=>new Promise(resolve=>server.close(resolve)));
 f.manager.settings({feedUrl:url+'/feed'},f.actor);const preview=await f.manager.check(f.actor);assert.equal(preview.local,false);assert.equal((await f.manager.prepare({id:preview.id},f.actor)).ready,true);
 await assert.rejects(fetchBytes(url+'/redirect',{maxBytes:1024}),{code:'UPDATE_HTTP'});
 f.store.put('members',{id:'owner',enabled:false,role:'owner'});assert.throws(()=>f.manager.takeForInstallation({id:preview.id},f.actor),{code:'FORBIDDEN'});
});
test('F47 lock or revocation while awaiting download cancels preparation',async t=>{
 const f=fixture(t),signed=envelope();signed.manifest.artifact.url='http://127.0.0.1/unused';signed.signature=sign(null,Buffer.from(canonical(signed.manifest)),pair.privateKey).toString('base64');
 const preview=f.manager._preview(signed,f.actor);let finish;f.manager.fetcher=()=>new Promise(resolve=>{finish=resolve;});const pending=f.manager.prepare({id:preview.id},f.actor);f.manager.clear();finish(data);await assert.rejects(pending,{code:'UPDATE_CANCELLED'});assert.equal(fs.existsSync(path.join(f.dir,'prepared')),false);
});

test('F47 lock actively aborts a real slow response and stale checks cannot recreate previews',async t=>{
 t.diagnostic('假设：锁定立即中止正在请求的更新，不等到网络超时，迟到响应不能生成新预览；决策价值：决定更新检查是否会拖住安全锁定；停止条件：一次真实慢HTTP断开和一次忽略取消的适配器迟到返回。');
 const f=fixture(t);let received,closed;const requested=new Promise(resolve=>received=resolve),disconnected=new Promise(resolve=>closed=resolve);
 const server=http.createServer((_req,res)=>{res.on('close',closed);res.writeHead(200,{'Content-Type':'application/json'});res.write('{"manifest":');received();});await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));t.after(()=>new Promise(resolve=>{server.close(resolve);server.closeAllConnections();}));
 f.manager.settings({feedUrl:`http://127.0.0.1:${server.address().port}/slow`},f.actor);const pending=f.manager.check(f.actor);await requested;f.manager.clear();await assert.rejects(pending,{code:'UPDATE_CANCELLED'});await disconnected;assert.equal(f.manager.previews.size,0);assert.equal(f.manager.requests.size,0);
 let finish;f.manager.fetcher=()=>new Promise(resolve=>{finish=resolve;});const late=f.manager.check(f.actor);f.manager.clear();finish(Buffer.from(JSON.stringify(envelope())));await assert.rejects(late,{code:'UPDATE_CANCELLED'});assert.equal(f.manager.previews.size,0);
});
