'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path');
const {generateKeyPairSync,sign,createHash,randomBytes}=require('node:crypto');
const {UpdateManager,canonical,readBoundedFile}=require('../src/services/updates.cjs');
const {inspectApplicationInput,inspectStage,inspectHeader}=require('../scripts/package-security.cjs');
const {inspectProtectionProvider}=require('../scripts/protection-provider.cjs');
const {EncryptedStore}=require('../src/core/store.cjs');
const pair=generateKeyPairSync('ed25519'),keys=[{id:'isolated',publicKey:pair.publicKey.export({type:'spki',format:'pem'}),channel:'development'}];
const bytes=Buffer.concat([Buffer.from('d0cf11e0a1b11ae1','hex'),Buffer.from('Synthetic only; never installed.')]);
function signed(version){const manifest={format:'lianpu-update-v1',keyId:'isolated',product:'lianpu-desktop',version,minVersion:'0.1.0',platform:'win32',arch:'x64',channel:'development',issuedAt:new Date(Date.now()-1000).toISOString(),expiresAt:new Date(Date.now()+86400000).toISOString(),notes:[],artifact:{filename:`Lianpu-${version}-windows-x64-setup.msi`,size:bytes.length,sha256:createHash('sha256').update(bytes).digest('hex')}};return {manifest,signature:sign(null,Buffer.from(canonical(manifest)),pair.privateKey).toString('base64')};}
function directory(){return fs.mkdtempSync(path.join(fs.mkdirSync(path.resolve(__dirname,'../work/security-package-unit'),{recursive:true})||path.resolve(__dirname,'../work/security-package-unit'),'case-'));}
function fixture(t){const root=directory(),store=new EncryptedStore(':memory:',randomBytes(32));store.put('members',{id:'owner',role:'owner',enabled:true});t.after(()=>store.close());const make=version=>new UpdateManager({getStore:()=>store,currentVersion:version,keys,downloadRoot:path.join(root,'prepared')});return {root,store,make,owner:{id:'owner'}};}
test('P1 ordinary inputs allowed; private material, source maps, extra resources and unpacked entries rejected',()=>{
 const app=directory();fs.writeFileSync(path.join(app,'main.cjs'),'module.exports=1;');assert.equal(inspectApplicationInput(app).length,1);
 const secret=path.join(app,'secret.txt');fs.writeFileSync(secret,pair.privateKey.export({type:'pkcs8',format:'pem'}));assert.throws(()=>inspectApplicationInput(app),/Private key/);fs.unlinkSync(secret);
 fs.writeFileSync(path.join(app,'main.cjs.map'),'{}');assert.throws(()=>inspectApplicationInput(app),/Non-distributable/);
 assert.throws(()=>inspectHeader({files:{native:{unpacked:true,size:1}}}),/unpacked/);
 const runtime=directory(),stage=directory();fs.writeFileSync(path.join(runtime,'electron.exe'),'runtime');fs.writeFileSync(path.join(runtime,'ffmpeg.dll'),'dll');fs.writeFileSync(path.join(stage,'Lianpu.exe'),'branded');fs.writeFileSync(path.join(stage,'ffmpeg.dll'),'dll');const params={appDir:app,runtime,stage,executable:path.join(stage,'Lianpu.exe')};assert.deepEqual(inspectStage(params),[]);
 fs.appendFileSync(path.join(stage,'ffmpeg.dll'),'replacement');assert.throws(()=>inspectStage(params),/modified Electron resource/);
 fs.writeFileSync(path.join(stage,'ffmpeg.dll'),'dll');fs.mkdirSync(path.join(stage,'resources/app'),{recursive:true});assert.throws(()=>inspectStage(params),/alternative application/);
});
test('P4 default provider is disabled and no vendor or sandbox weakening configuration can execute',()=>{
 assert.equal(inspectProtectionProvider(undefined,{electron:'44.3.0'}).status,'disabled');
 for(const config of [{id:'vmprotect'},{id:'none',disableSandbox:true},{id:'none',command:'anything'}])assert.throws(()=>inspectProtectionProvider(config,{}),{code:'PROTECTION_PROVIDER_UNAVAILABLE'});
});
test('P3 cancelled launch request permits intermediate repair; observed runtime prevents update rollback',async t=>{
 const f=fixture(t),old=f.make('0.1.0');old.reconcile(f.owner);
 const requested=signed('0.4.0');const source=path.join(f.root,requested.manifest.artifact.filename);fs.writeFileSync(source,bytes);const preview=old._preview(requested,f.owner,{localDirectory:f.root});await old.prepare({id:preview.id},f.owner);old.takeForInstallation({id:preview.id},f.owner);
 assert.equal(f.store.get('_updates','observed-floor').version,'0.1.0');assert.equal(old._preview(signed('0.2.0'),f.owner).version,'0.2.0');
 const actual=f.make('0.4.0');actual.reconcile(f.owner);assert.equal(f.store.get('_updates','observed-floor').version,'0.4.0');
 assert.throws(()=>old._preview(signed('0.3.0'),f.owner),{code:'UPDATE_ROLLBACK'});assert.equal(old._preview(signed('0.4.0'),f.owner).version,'0.4.0');
 old.reconcile(f.owner);assert.equal(f.store.get('_updates','observed-floor').version,'0.4.0');
});
test('P3 damaged update-only metadata preserves login reconciliation but blocks new update actions',t=>{
 const f=fixture(t),manager=f.make('0.1.0'),bad={id:'observed-floor',format:'broken',version:'not-a-version'};f.store.put('_updates',bad);
 assert.deepEqual(manager.reconcile(f.owner).code,'UPDATE_STATE');assert.deepEqual(f.store.get('_updates','observed-floor'),bad);assert.equal(manager.owner(f.owner).id,'owner');assert.throws(()=>manager._preview(signed('0.2.0'),f.owner),{code:'UPDATE_STATE'});
});
test('P3 bounded same-handle file read rejects directories, oversize and changed expected size',()=>{
 const dir=directory(),file=path.join(dir,'test.msi');fs.writeFileSync(file,bytes);assert.deepEqual(readBoundedFile(file,{maxBytes:bytes.length,expectedSize:bytes.length}),bytes);
 assert.throws(()=>readBoundedFile(dir,{maxBytes:100}),{code:'UPDATE_FILE_TYPE'});assert.throws(()=>readBoundedFile(file,{maxBytes:8}),{code:'UPDATE_SIZE'});assert.throws(()=>readBoundedFile(file,{maxBytes:1000,expectedSize:8}),{code:'UPDATE_HASH'});
});
