'use strict';
const fs=require('node:fs'),path=require('node:path');
const {randomUUID}=require('node:crypto');

/** Only Electron's Windows-user OS encryption may persist the local vault key. */
class PersistentLocalSession {
  constructor({file,safeStorage,platform=process.platform}) {this.file=file;this.safeStorage=safeStorage;this.platform=platform;this.result={status:'not_saved',saved:false};}
  available() {try{return this.platform==='win32'&&this.safeStorage?.isEncryptionAvailable()===true;}catch{return false;}}
  status() {return {available:this.available(),...this.result};}
  save(identity) {
    if(!identity?.key||!identity.userId)return this.setResult('not_saved','尚未登录本机成员。');
    if(!this.available())return this.setResult('unavailable','Windows 登录保护当前不可用，本次可以继续使用；下次启动需要登录一次。');
    let temporary;
    try{
      const payload={format:'lianpu-local-session',version:1,userId:identity.userId,credentialRevision:identity.credentialRevision(),key:identity.key.toString('base64')};
      const encrypted=this.safeStorage.encryptString(JSON.stringify(payload));
      if(!Buffer.isBuffer(encrypted)||!encrypted.length)throw new Error('OS_ENCRYPTION_FAILED');
      fs.mkdirSync(path.dirname(this.file),{recursive:true,mode:0o700});temporary=this.file+'.'+randomUUID()+'.tmp';
      const fd=fs.openSync(temporary,'wx',0o600);try{fs.writeFileSync(fd,encrypted);fs.fsyncSync(fd);}finally{fs.closeSync(fd);}fs.renameSync(temporary,this.file);
      this.result={status:'saved',saved:true};return this.status();
    }catch{if(temporary)try{fs.unlinkSync(temporary);}catch{}return this.setResult('save_failed','未能保存 Windows 保护的登录。本次可以继续使用，下次启动需要登录一次。');}
  }
  restore(identity,validateMember) {
    if(!fs.existsSync(this.file)){this.setResult('not_saved','首次使用或升级后，请正常登录一次。');return null;}
    if(!this.available()){this.setResult('unavailable','Windows 登录保护当前不可用，请正常登录一次。');return null;}
    let key;
    try{
      if(fs.statSync(this.file).size>65536)throw new Error('SESSION_FORMAT');
      const payload=JSON.parse(this.safeStorage.decryptString(fs.readFileSync(this.file)));
      if(payload?.format!=='lianpu-local-session'||payload.version!==1||typeof payload.key!=='string'||!/^[A-Za-z0-9+/]{43}=$/.test(payload.key))throw new Error('SESSION_FORMAT');
      key=Buffer.from(payload.key,'base64');const user=identity.restoreRemembered({...payload,key},validateMember);
      this.result={status:'restored',saved:true};return user;
    }catch{this.forget('invalid','已保存的登录无法使用，请选择有效成员登录一次。');return null;}
    finally{key?.fill(0);}
  }
  setResult(status,reason) {this.result={status,saved:false,reason};return this.status();}
  forget(status='not_saved',reason='本机登录记录已清除。') {try{fs.unlinkSync(this.file);}catch(error){if(error.code!=='ENOENT')return this.setResult('clear_failed','旧登录记录未能清除，但无效成员或凭据版本仍不能恢复登录。');}return this.setResult(status,reason);}
}
module.exports={PersistentLocalSession};
