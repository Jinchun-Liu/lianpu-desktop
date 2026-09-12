'use strict';
const fs=require('node:fs');const path=require('node:path');const {createHash}=require('node:crypto');
// Sessions are non-persistent Chromium partitions. Only this OS-encrypted cookie
// envelope survives restart. Web storage, cache, IM tokens and pages stay in RAM.
class SessionVault {
 constructor(electron){this.electron=electron;this.generations=new Map();}
 file(id){return path.join(this.electron.app.getPath('userData'),'platform-sessions',createHash('sha256').update(id).digest('hex')+'.bin');}
 async restore(id,session){const generation=this.generations.get(id)||0;const safe=this.electron.safeStorage;if(!safe?.isEncryptionAvailable())return false;const file=this.file(id);if(!fs.existsSync(file))return false;try{const parsed=JSON.parse(safe.decryptString(fs.readFileSync(file)));if(parsed.version!==1||!Array.isArray(parsed.cookies))return false;for(const c of parsed.cookies){if(generation!==(this.generations.get(id)||0))return false;if(!c||typeof c.domain!=='string'||!/(^|\.)(goofish\.com|taobao\.com)$/.test(c.domain.replace(/^\./,'')))continue;if(c.expirationDate&&c.expirationDate<=Date.now()/1000)continue;await session.cookies.set({...c,url:'https://'+c.domain.replace(/^\./,'')+(c.path||'/')});if(generation!==(this.generations.get(id)||0)){await session.clearStorageData();return false;}}return {restored:true,progress:parsed.progress};}catch{return false;}}
 async save(id,session,progress){const generation=this.generations.get(id)||0;const safe=this.electron.safeStorage;if(!safe?.isEncryptionAvailable())return false;const all=await session.cookies.get({});if(generation!==(this.generations.get(id)||0))return false;const cookies=all.filter(c=>/(^|\.)(goofish\.com|taobao\.com)$/.test(c.domain.replace(/^\./,'')));const file=this.file(id);fs.mkdirSync(path.dirname(file),{recursive:true});const pending=file+'.pending';fs.writeFileSync(pending,safe.encryptString(JSON.stringify({version:1,cookies,progress})));fs.renameSync(pending,file);return true;}
 remove(id){this.generations.set(id,(this.generations.get(id)||0)+1);if(!this.electron.app)return;for(const file of [this.file(id),this.file(id)+'.pending'])try{fs.unlinkSync(file);}catch(error){if(error.code!=='ENOENT')throw error;}}
}
module.exports={SessionVault};
