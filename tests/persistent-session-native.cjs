'use strict';
// Hypothesis: real Electron OS protection restores only the latest valid member;
// delayed sign-ins, credential results and shutdown cannot replace that identity.
// Decision: v1.5 persistent-login acceptance. Stop on one bypass or lost boundary;
// existing runtime/claims scripts independently exercise actual submitted sends.
// Debugger fixtures affect only this isolated process; no production test path.
const {_electron}=require('playwright-core');
const fs=require('node:fs'),path=require('node:path'),assert=require('node:assert/strict'),{createHash}=require('node:crypto');
const root=path.resolve(__dirname,'..'),vault=path.join(root,'work',`persistent-native-${Date.now()}`),evidence=path.join(root,'evidence');fs.mkdirSync(vault,{recursive:true});fs.mkdirSync(evidence,{recursive:true});
const password='Native-persistent-initial-2026!',recoveredPassword='Native-persistent-recovered-2026!',viewerPassword='Native-viewer-changed-2026!';
const checks=[],files=['src/main.cjs','src/auth.cjs','src/persistent-session.cjs','src/preload.cjs','src/core/service.cjs','src/core/account-runtime.cjs',path.relative(root,__filename)];
const hashes=()=>Object.fromEntries(files.map(file=>[file,createHash('sha256').update(fs.readFileSync(path.join(root,file))).digest('hex')]));
const sourceHashes=hashes(),report={startedAt:new Date().toISOString(),fixture:vault,sourceHashes,checks,hypothesis:'Windows-protected persistent local identity rejects obsolete credentials and delayed transitions',decisionValue:'v1.5 automatic login and race acceptance',stopCondition:'One case per distinct persistence, identity race or shutdown boundary; any restoration of an obsolete member fails',scope:'Actual Electron and Windows safeStorage in a generated isolated profile. Debugger-only cancellation/drain/save-failure fixtures. No real user credentials, marketplace actions or physical power events.',realPlatformActions:0};
let app,page,owner,viewer;
const call=(action,payload={})=>page.evaluate(({action,payload})=>window.desk.call(action,payload),{action,payload});
const ok=async(action,payload={})=>{const response=await call(action,payload);assert.equal(response.ok,true,`${action}: ${JSON.stringify(response.error)}`);return response.data;};
const pass=name=>{checks.push({name,status:'passed'});console.log('PASS '+name);};
const waitFor=async(fn)=>{for(let i=0;i<120;i++){if(await fn())return;await new Promise(resolve=>setTimeout(resolve,50));}throw new Error('Timed out waiting for isolated boundary');};
async function launch(dir=vault){const env={...process.env,LIANPU_DATA_DIR:dir};delete env.ELECTRON_RUN_AS_NODE;app=await _electron.launch({executablePath:path.join(root,'node_modules/electron/dist/electron.exe'),args:[root],env,timeout:30000});page=await app.firstWindow();await page.waitForFunction(()=>!!window.desk);}
async function close(){if(!app)return;const current=app;await current.close();app=null;page=null;}
async function capture(){
  await app.evaluate(({app})=>{const path=process.getBuiltinModule('node:path'),req=process.getBuiltinModule('node:module').createRequire(path.join(app.getAppPath(),'package.json'));const {AccountRuntime}=req('./src/core/account-runtime.cjs'),details=AccountRuntime.prototype.details;AccountRuntime.prototype.details=function(...args){globalThis.__runtime=this;globalThis.__store=this.store;return details.apply(this,args);};const {VaultIdentity}=req('./src/auth.cjs'),revision=VaultIdentity.prototype.credentialRevision;VaultIdentity.prototype.credentialRevision=function(...args){globalThis.__identity=this;return revision.apply(this,args);};});
  await ok('account.details',{accountId:'persistent-account'});
}
(async()=>{try{
  await launch();const setup=await ok('auth.setup',{name:'Persistent native owner',password});owner=setup.user;assert.equal(setup.rememberedSession.saved,true);assert.equal(setup.rememberedSession.available,true);
  await ok('entity.save',{kind:'accounts',record:{id:'persistent-account',space:'live',name:'Isolated persistent account'}});
  viewer=await ok('auth.member.add',{name:'Persistent native viewer',password,role:'viewer',accountIds:['persistent-account']});await capture();
  await ok('auth.unlock',{id:owner.id,password});
  const protectedBytes=await app.evaluate(({safeStorage,app})=>{const fs=process.getBuiltinModule('node:fs'),path=process.getBuiltinModule('node:path'),identity=globalThis.__identity,bytes=fs.readFileSync(path.join(app.getPath('userData'),'local-session.bin'));const payload=JSON.parse(safeStorage.decryptString(bytes));return {matchesMember:payload.userId===identity.userId,matchesKey:payload.key===identity.key.toString('base64'),plaintextKey:bytes.includes(identity.key)||bytes.includes(Buffer.from(identity.key.toString('base64')))};});
  assert.equal(protectedBytes.matchesMember,true);assert.equal(protectedBytes.matchesKey,true);assert.equal(protectedBytes.plaintextKey,false);assert.equal(fs.readFileSync(path.join(vault,'local-session.bin')).includes(Buffer.from(password)),false);
  assert.equal((await ok('auth.lock')).removed,true);assert.equal((await ok('auth.stopAndLock')).removed,true);assert.equal((await ok('auth.status')).user.id,owner.id);assert.ok((await ok('workspace.snapshot',{space:'live'})).accounts.length);
  pass('actual Windows safeStorage remembers only encrypted capability; removed lock calls remain inert');

  await app.evaluate(()=>{const runtime=globalThis.__runtime,original=runtime.cancelLogins.bind(runtime);let count=0;runtime.cancelLogins=async()=>{const cancelled=original();if(++count===1)await new Promise(resolve=>globalThis.__releaseAuth=resolve);return cancelled;};});
  const oldRecovery=call('auth.recover',{recoveryCode:setup.recoveryCode,newPassword:recoveredPassword});await waitFor(()=>app.evaluate(()=>!!globalThis.__releaseAuth));
  await ok('auth.unlock',{id:viewer.id,password});await app.evaluate(()=>globalThis.__releaseAuth());const staleRecovery=await oldRecovery;
  assert.equal(staleRecovery.ok,false);assert.equal(staleRecovery.error.code,'SESSION_CHANGED');assert.equal(staleRecovery.data,undefined);assert.equal((await ok('auth.status')).user.id,viewer.id);assert.equal(await app.evaluate(()=>globalThis.__identity.userId),viewer.id);
  pass('a delayed recovery response cannot disclose recovery material or roll back a later member login');

  await app.evaluate(()=>{const identity=globalThis.__identity,original=identity.changePassword.bind(identity);identity.changePassword=async payload=>{const result=original(payload);await new Promise(resolve=>globalThis.__releasePassword=resolve);return result;};});
  const oldPassword=call('auth.changePassword',{oldPassword:password,newPassword:viewerPassword});await waitFor(()=>app.evaluate(()=>!!globalThis.__releasePassword));
  await ok('auth.unlock',{id:owner.id,password:recoveredPassword});await app.evaluate(()=>globalThis.__releasePassword());const stalePassword=await oldPassword;
  assert.equal(stalePassword.ok,false);assert.equal(stalePassword.error.code,'SESSION_CHANGED');assert.equal((await ok('auth.status')).user.id,owner.id);
  const savedMember=await app.evaluate(({safeStorage,app})=>{const fs=process.getBuiltinModule('node:fs'),path=process.getBuiltinModule('node:path');return JSON.parse(safeStorage.decryptString(fs.readFileSync(path.join(app.getPath('userData'),'local-session.bin')))).userId;});assert.equal(savedMember,owner.id);
  pass('a password result delayed across member switching cannot overwrite the newer remembered identity');

  const shutdownEvidence=path.join(vault,'shutdown-result.json');
  await app.evaluate(({app},file)=>{const fs=process.getBuiltinModule('node:fs'),identity=globalThis.__identity,store=globalThis.__store,runtime=globalThis.__runtime,drain=runtime.drain.bind(runtime);runtime.drain=async()=>{await new Promise(resolve=>globalThis.__releaseDrain=resolve);return drain();};app.on('before-quit',()=>{if(identity.key===null)fs.writeFileSync(file,JSON.stringify({identityCleared:identity.key===null,userCleared:identity.userId===null,storeKeyZero:store.key.every(byte=>byte===0)}));});app.quit();},shutdownEvidence);
  await waitFor(()=>app.evaluate(()=>!!globalThis.__releaseDrain));const duringClose=await call('auth.unlock',{id:viewer.id,password:viewerPassword});assert.equal(duringClose.ok,false);assert.equal(duringClose.error.code,'APP_CLOSING');assert.equal(await app.evaluate(()=>globalThis.__identity.userId),owner.id);
  await app.evaluate(()=>globalThis.__releaseDrain());await waitFor(()=>fs.existsSync(shutdownEvidence));const closed=JSON.parse(fs.readFileSync(shutdownEvidence,'utf8'));assert.deepEqual(closed,{identityCleared:true,userCleared:true,storeKeyZero:true});try{await app.close();}catch{}app=null;
  await launch();const restored=await ok('auth.status');assert.equal(restored.user.id,owner.id);assert.equal(restored.locked,false);assert.equal(restored.rememberedSession.status,'restored');assert.equal(restored.background.activeAccounts,0);assert.ok((await ok('workspace.snapshot',{space:'live'})).accounts.some(account=>account.id==='persistent-account'));
  pass('shutdown refuses reentrant login, zeros keys after drain, and restart automatically restores viewing without hosting');

  await app.evaluate(({safeStorage})=>{safeStorage.encryptString=()=>{throw new Error('isolated native save failure');};});
  const switched=await ok('auth.unlock',{id:viewer.id,password:viewerPassword});assert.equal(switched.rememberedSession.saved,false);assert.equal(switched.rememberedSession.status,'save_failed');assert.ok(switched.rememberedSession.reason);assert.equal((await ok('auth.status')).user.id,viewer.id);
  await close();await launch();const failedRestore=await ok('auth.status');assert.equal(failedRestore.user,undefined);assert.equal(failedRestore.locked,true);assert.equal(failedRestore.rememberedSession.saved,false);assert.equal(failedRestore.rememberedSession.status,'invalid');
  pass('failed OS save after owner-to-viewer switch is visible and cannot restore the obsolete owner at restart');

  await ok('auth.unlock',{id:viewer.id,password:viewerPassword});await close();
  const missingVault=path.join(vault,'missing-business');fs.mkdirSync(missingVault);for(const file of ['identity.json','local-session.bin'])fs.copyFileSync(path.join(vault,file),path.join(missingVault,file));
  await launch(missingVault);const missing=await ok('auth.status');assert.equal(missing.user,undefined);assert.equal(missing.locked,true);assert.equal(fs.existsSync(path.join(missingVault,'business.sqlite')),false);await close();
  pass('a remembered login with a missing business database requests login without creating an empty replacement');

  await launch();assert.equal((await ok('auth.status')).user.id,viewer.id);await capture();
  await app.evaluate((_electron,memberId)=>{const store=globalThis.__store;store.put('members',{...store.get('members',memberId),enabled:false});},viewer.id);
  // Close before auth.status so startup itself validates the disabled member.
  await close();await launch();const disabled=await ok('auth.status');assert.equal(disabled.user,undefined);assert.equal(disabled.locked,true);assert.equal(disabled.background.keysRetained,false);assert.ok(disabled.users.some(user=>user.id===viewer.id));assert.equal(disabled.rememberedSession.status,'invalid');
  const forbidden=await call('auth.unlock',{id:viewer.id,password:viewerPassword});assert.equal(forbidden.ok,false);assert.equal(forbidden.error.code,'FORBIDDEN');assert.equal((await ok('auth.status')).user,undefined);
  pass('disabled members cannot restore or explicitly reuse remembered credentials; status remains available for another login');
  assert.deepEqual(hashes(),sourceHashes,'Relevant source changed during native verification');report.status='passed';
}catch(error){report.status='failed';report.error={message:error.message,stack:error.stack};console.error(error);process.exitCode=1;}
finally{if(app){try{await app.evaluate(()=>{globalThis.__releaseAuth?.();globalThis.__releasePassword?.();globalThis.__releaseDrain?.();});}catch{}try{await close();}catch(error){report.cleanupError=error.message;process.exitCode=1;report.status='failed';}}report.completedAt=new Date().toISOString();fs.writeFileSync(path.join(evidence,'persistent-session-native.json'),JSON.stringify(report,null,2));}
})();
