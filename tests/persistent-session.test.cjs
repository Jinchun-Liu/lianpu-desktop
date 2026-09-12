'use strict';
const {test}=require('node:test'),assert=require('node:assert/strict');
const fs=require('node:fs'),path=require('node:path'),{randomBytes,createCipheriv,createDecipheriv}=require('node:crypto');
const {VaultIdentity}=require('../src/auth.cjs');
const {PersistentLocalSession}=require('../src/persistent-session.cjs');
const scratch=path.resolve(__dirname,'../work');fs.mkdirSync(scratch,{recursive:true});
const password='Persistent-unit-owner-2026!';
// Hypothesis: the remembered capability is OS-bound and limited to the latest
// legitimate member/credential version. Decision: allow automatic local restore.
// Stop at the first plaintext, wrong-member or obsolete-token restore; one case
// per distinct invalidation boundary, with no real user credential or OS store.
function osProtection(key=randomBytes(32)) {
  return {isEncryptionAvailable:()=>true,
    encryptString(text){const iv=randomBytes(12),cipher=createCipheriv('aes-256-gcm',key,iv);return Buffer.concat([iv,cipher.update(text),cipher.final(),cipher.getAuthTag()]);},
    decryptString(bytes){const cipher=createDecipheriv('aes-256-gcm',key,bytes.subarray(0,12));cipher.setAuthTag(bytes.subarray(-16));return Buffer.concat([cipher.update(bytes.subarray(12,-16)),cipher.final()]).toString('utf8');}};
}
function fixture(t) {
  const dir=fs.mkdtempSync(path.join(scratch,'persistent-unit-'));
  t.after(()=>{const resolved=path.resolve(dir);assert.ok(resolved.startsWith(scratch+path.sep));fs.rmSync(resolved,{recursive:true,force:true});});
  const file=path.join(dir,'identity.json'),token=path.join(dir,'local-session.bin'),safeStorage=osProtection(),identity=new VaultIdentity(file);
  const owner=identity.setup({name:'Local unit owner',password});
  const session=new PersistentLocalSession({file:token,safeStorage,platform:'win32'});
  const remember=()=>{identity.advanceRememberedRevision();return session.save(identity);};
  return {dir,file,token,safeStorage,identity,owner,session,remember};
}
test('a remembered member restores the same key without plaintext password or vault key on disk',t=>{
  const f=fixture(t),key=Buffer.from(f.identity.key);assert.equal(f.remember().saved,true);
  const bytes=fs.readFileSync(f.token);assert.equal(bytes.includes(Buffer.from(password)),false);assert.equal(bytes.includes(key),false);assert.equal(bytes.includes(Buffer.from(key.toString('base64'))),false);
  const oldBuffer=f.identity.key;f.identity.lock();assert.deepEqual(oldBuffer,Buffer.alloc(32));
  const identity=new VaultIdentity(f.file),session=new PersistentLocalSession({file:f.token,safeStorage:f.safeStorage,platform:'win32'});
  const member=session.restore(identity,(id,suppliedKey)=>id===f.owner.id&&suppliedKey.equals(key));
  assert.equal(member.id,f.owner.id);assert.deepEqual(Object.keys(member).sort(),['id','name']);assert.deepEqual(identity.key,key);assert.equal(session.status().status,'restored');identity.lock();key.fill(0);
});
test('switching to a viewer durably invalidates an old owner token even when the new OS save fails',t=>{
  const f=fixture(t);assert.equal(f.remember().saved,true);const oldBlob=fs.readFileSync(f.token);
  f.identity.addMember({id:'viewer',name:'Viewer',password});f.identity.unlock({id:'viewer',password});f.identity.advanceRememberedRevision();
  f.safeStorage.encryptString=()=>{throw new Error('mock OS save failure containing no actual credentials');};
  assert.equal(f.session.save(f.identity).status,'save_failed');assert.deepEqual(fs.readFileSync(f.token),oldBlob);
  const restored=new VaultIdentity(f.file);assert.equal(f.session.restore(restored,()=>true),null);assert.equal(restored.userId,null);assert.equal(restored.key,null);assert.equal(f.session.status().saved,false);
});
test('unavailable OS protection never claims to save and cannot restore a previous member after a switch',t=>{
  const f=fixture(t);f.remember();f.identity.addMember({id:'viewer',name:'Viewer',password});f.identity.unlock({id:'viewer',password});f.identity.advanceRememberedRevision();
  f.safeStorage.isEncryptionAvailable=()=>false;const status=f.session.save(f.identity);assert.equal(status.saved,false);assert.equal(status.status,'unavailable');assert.ok(status.reason);assert.equal(f.session.restore(new VaultIdentity(f.file),()=>true),null);
  f.safeStorage.isEncryptionAvailable=()=>true;assert.equal(f.session.restore(new VaultIdentity(f.file),()=>true),null);
});
test('password rotation and recovery invalidate former remembered capabilities while retaining data',t=>{
  const f=fixture(t),key=Buffer.from(f.identity.key);f.remember();
  f.identity.changePassword({oldPassword:password,newPassword:'Changed-unit-password-2026!'});
  assert.equal(f.session.restore(new VaultIdentity(f.file),()=>true),null);assert.deepEqual(f.identity.key,key);
  f.identity.addMember({id:'viewer',name:'Viewer',password});f.identity.unlock({id:'viewer',password});f.remember();
  f.identity.recover({recoveryCode:f.owner.recoveryCode,newPassword:'Recovered-unit-password-2026!'});
  assert.equal(f.session.restore(new VaultIdentity(f.file),()=>true),null);assert.deepEqual(f.identity.key,key);key.fill(0);
});
test('current member validation is mandatory and rejects a disabled or missing member',t=>{
  const f=fixture(t);f.remember();const blob=fs.readFileSync(f.token);
  for(const validator of [undefined,()=>false,()=>{throw new Error('damaged business store');}]){
    fs.writeFileSync(f.token,blob);const identity=new VaultIdentity(f.file);assert.equal(f.session.restore(identity,validator),null);assert.equal(identity.key,null);assert.equal(f.session.status().status,'invalid');
  }
});
test('another Windows-user protection key and a damaged blob cannot restore a local session',t=>{
  const f=fixture(t);f.remember();
  const wrongUser=new PersistentLocalSession({file:f.token,safeStorage:osProtection(),platform:'win32'});assert.equal(wrongUser.restore(new VaultIdentity(f.file),()=>true),null);
  fs.writeFileSync(f.token,Buffer.from('corrupt ciphertext'));assert.equal(f.session.restore(new VaultIdentity(f.file),()=>true),null);assert.equal(f.session.status().status,'invalid');
});
test('an old installation with no token requests one login and creates no token as a fallback',t=>{
  const f=fixture(t);const identity=new VaultIdentity(f.file);assert.equal(f.session.restore(identity,()=>true),null);assert.equal(f.session.status().status,'not_saved');assert.equal(fs.existsSync(f.token),false);assert.equal(identity.key,null);
  const unsupported=new PersistentLocalSession({file:f.token,safeStorage:f.safeStorage,platform:'linux'});assert.equal(unsupported.save(f.identity).status,'unavailable');assert.equal(fs.existsSync(f.token),false);
});
test('a failed durable member revision update is reported and does not pretend to invalidate old state',t=>{
  const f=fixture(t);f.remember();const before=f.identity.credentialRevision(),originalFile=f.identity.file;
  // Deliberately target a directory in the isolated fixture: rename cannot replace it.
  const blocked=path.join(f.dir,'blocked');fs.mkdirSync(blocked);f.identity.file=blocked;assert.throws(()=>f.identity.advanceRememberedRevision(),{code:'SESSION_SAVE_FAILED'});assert.equal(f.identity.credentialRevision(),before);f.identity.file=originalFile;
  const identity=new VaultIdentity(f.file);assert.equal(f.session.restore(identity,()=>true).id,f.owner.id);identity.lock();
});
