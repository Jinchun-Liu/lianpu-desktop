'use strict';
const fs=require('node:fs'),path=require('node:path'),http=require('node:http'),https=require('node:https');
const {createHash,createPublicKey,verify,randomUUID}=require('node:crypto');
const MAX_MANIFEST=128*1024, MAX_ARTIFACT=512*1024*1024;
class UpdateError extends Error{constructor(code,message){super(message);this.code=code;}}
const fail=(code,message)=>{throw new UpdateError(code,message);};
const digest=bytes=>createHash('sha256').update(bytes).digest('hex');
function canonical(value){if(value===null||typeof value!=='object')return JSON.stringify(value);if(Array.isArray(value))return '['+value.map(canonical).join(',')+']';return '{'+Object.keys(value).sort().map(key=>JSON.stringify(key)+':'+canonical(value[key])).join(',')+'}';}
function version(value){if(typeof value!=='string'||!/^\d{1,3}\.\d{1,3}\.\d{1,5}$/.test(value))fail('UPDATE_FORMAT','更新版本号格式无效。');return value.split('.').map(Number);}
function compare(a,b){const x=version(a),y=version(b);for(let i=0;i<3;i++)if(x[i]!==y[i])return x[i]>y[i]?1:-1;return 0;}
function address(value){let url;try{url=new URL(value);}catch{fail('UPDATE_ADDRESS','请填写完整更新清单地址。');}if(url.protocol!=='https:'&&!(url.protocol==='http:'&&['127.0.0.1','[::1]','localhost'].includes(url.hostname)))fail('UPDATE_ADDRESS','远程更新来源必须使用 HTTPS；HTTP 仅允许本机测试服务。');if(url.username||url.password||url.hash||url.search)fail('UPDATE_ADDRESS','更新地址不能包含登录凭据、查询参数或片段。');return url;}
function keysOnly(object,keys){if(!object||typeof object!=='object'||Array.isArray(object)||Object.keys(object).some(key=>!keys.includes(key)))fail('UPDATE_FORMAT','更新清单包含不支持的字段。');}
function verifyManifest(envelope,{keys,currentVersion,now=Date.now(),arch='x64',platform='win32'}={}){
  keysOnly(envelope,['manifest','signature']);const m=envelope.manifest;keysOnly(m,['format','keyId','product','version','minVersion','platform','arch','channel','issuedAt','expiresAt','notes','artifact']);
  if(m.format!=='lianpu-update-v1'||m.product!=='lianpu-desktop'||m.platform!==platform||m.arch!==arch||!['development','stable'].includes(m.channel))fail('UPDATE_TARGET','更新清单不适用于当前产品、系统或架构。');
  version(m.version);version(m.minVersion);if(compare(m.version,currentVersion)<=0)fail('UPDATE_NOT_NEWER','此版本不高于当前版本，不能通过更新入口降级或重复安装。');if(compare(currentVersion,m.minVersion)<0)fail('UPDATE_BASE_VERSION','当前版本过旧，需要先升级到清单指定的中间版本。');
  if(typeof m.issuedAt!=='string'||typeof m.expiresAt!=='string'||!Number.isFinite(Date.parse(m.issuedAt))||!Number.isFinite(Date.parse(m.expiresAt))||Date.parse(m.issuedAt)>now+300000||Date.parse(m.expiresAt)<=now||Date.parse(m.expiresAt)<=Date.parse(m.issuedAt)||Date.parse(m.expiresAt)-Date.parse(m.issuedAt)>180*86400000)fail('UPDATE_EXPIRED','更新清单尚未生效、已过期或有效期格式不正确。');
  if(!Array.isArray(m.notes)||m.notes.length>20||m.notes.some(note=>typeof note!=='string'||note.length>2000))fail('UPDATE_FORMAT','版本变更说明格式无效。');
  keysOnly(m.artifact,['filename','sha256','size','url']);const a=m.artifact;
  if(typeof a.filename!=='string'||!/^Lianpu-\d{1,3}\.\d{1,3}\.\d{1,5}-windows-x64-setup\.msi$/.test(a.filename)||a.filename!==`Lianpu-${m.version}-windows-x64-setup.msi`||!/^[a-f0-9]{64}$/.test(a.sha256)||!Number.isSafeInteger(a.size)||a.size<8||a.size>MAX_ARTIFACT)fail('UPDATE_FORMAT','安装包名称、大小或摘要无效。');
  if(a.url!==undefined)address(a.url);
  const trusted=keys?.find(key=>key.id===m.keyId&&!key.revoked&&key.channel===m.channel);if(!trusted)fail('UPDATE_UNTRUSTED_KEY','此更新没有使用本版本内置的受信发布密钥。');
  let publicKey;try{publicKey=createPublicKey(trusted.publicKey);}catch{fail('UPDATE_UNTRUSTED_KEY','内置发布公钥无效。');}
  if(publicKey.asymmetricKeyType!=='ed25519')fail('UPDATE_UNTRUSTED_KEY','发布公钥类型不受支持。');
  const signature=typeof envelope.signature==='string'?Buffer.from(envelope.signature,'base64'):Buffer.alloc(0);
  if(signature.length!==64||signature.toString('base64')!==envelope.signature||!verify(null,Buffer.from(canonical(m)),publicKey,signature))fail('UPDATE_SIGNATURE','更新清单签名不正确，内容可能被替换。');
  return {manifest:JSON.parse(JSON.stringify(m)),key:{id:trusted.id,label:trusted.label||trusted.id,fingerprint:digest(publicKey.export({format:'der',type:'spki'})),channel:trusted.channel},windowsPublisherVerified:false};
}
function readEnvelope(bytes){if(!Buffer.isBuffer(bytes))bytes=Buffer.from(bytes);if(bytes.length>MAX_MANIFEST)fail('UPDATE_SIZE','更新清单过大。');try{return JSON.parse(bytes.toString('utf8').replace(/^\uFEFF/,''));}catch{fail('UPDATE_FORMAT','更新清单不是有效 JSON。');}}
function fetchBytes(value,{maxBytes,timeout=20000,onProgress,signal}={}){
  const url=address(value);
  return new Promise((resolve,reject)=>{
    if(signal?.aborted){reject(new UpdateError('UPDATE_CANCELLED','更新请求已取消，尚未执行安装。'));return;}
    let completed=false,timer;
    const abort=()=>{req.destroy();finish(new UpdateError('UPDATE_CANCELLED','更新请求已取消，尚未执行安装。'));};
    const finish=(error,value)=>{if(completed)return;completed=true;clearTimeout(timer);signal?.removeEventListener('abort',abort);error?reject(error):resolve(value);};
    const req=(url.protocol==='https:'?https:http).get(url,{headers:{Accept:'application/octet-stream, application/json'}},res=>{
      if(res.statusCode!==200){req.destroy();finish(new UpdateError('UPDATE_HTTP',res.statusCode>=300&&res.statusCode<400?'更新地址跳转，已停止请求，请核对直接来源地址。':`更新服务未完成请求（HTTP ${res.statusCode}）。`));return;}
      if(res.headers['content-length']&&Number(res.headers['content-length'])>maxBytes){req.destroy();finish(new UpdateError('UPDATE_SIZE','更新内容超过允许大小。'));return;}
      const chunks=[];let length=0;res.on('data',chunk=>{try{length+=chunk.length;if(length>maxBytes)throw new UpdateError('UPDATE_SIZE','更新内容超过允许大小。');onProgress?.(length);chunks.push(chunk);}catch(error){req.destroy();finish(error);}});
      res.on('end',()=>finish(null,Buffer.concat(chunks)));res.on('error',()=>finish(new UpdateError('UPDATE_NETWORK','更新内容传输中断，尚未执行安装。')));
    });
    timer=setTimeout(()=>{req.destroy();finish(new UpdateError('UPDATE_TIMEOUT','更新请求超时，尚未执行安装。'));},timeout);
    signal?.addEventListener('abort',abort,{once:true});
    req.on('error',error=>finish(error instanceof UpdateError?error:new UpdateError('UPDATE_NETWORK','无法连接更新来源，请检查网络和地址。')));
  });
}
class UpdateManager{
  constructor({getStore,keys=[],currentVersion,downloadRoot,fetcher=fetchBytes,clock=()=>Date.now()}={}){this.getStore=getStore;this.keys=keys;this.currentVersion=currentVersion;this.downloadRoot=downloadRoot;this.fetcher=fetcher;this.clock=clock;this.previews=new Map();this.generation=0;this.requests=new Set();}
  owner(actor){const store=this.getStore?.();if(!store)fail('LOCKED','请先登录有效的本机成员。');const current=store.get('members',actor?.id);if(!current||!current.enabled||current.role!=='owner')fail('FORBIDDEN','检查或安装更新需要本机管理员权限。');return current;}
  status(actor){this.owner(actor);const saved=this.getStore().get('_updates','settings');return {currentVersion:this.currentVersion,feedUrl:saved?.feedUrl||'',keys:this.keys.filter(key=>!key.revoked).map(key=>({id:key.id,label:key.label,channel:key.channel,fingerprint:digest(createPublicKey(key.publicKey).export({format:'der',type:'spki'}))})),windowsPublisherVerified:false,history:this.getStore().list('_updateHistory').slice(-20).reverse(),notice:'清单签名用于核对发行密钥及内容；不等于 Windows 发布者代码签名。开发密钥仅支持开发验证版。'};}
  settings({feedUrl},actor){this.owner(actor);if(typeof feedUrl!=='string'||feedUrl.length>2000)fail('UPDATE_ADDRESS','更新地址格式无效。');if(feedUrl)address(feedUrl);this.getStore().put('_updates',{id:'settings',feedUrl,updatedAt:new Date(this.clock()).toISOString()});return this.status(actor);}
  clear(){this.generation++;this.previews.clear();for(const controller of this.requests)controller.abort();this.requests.clear();}
  async _fetch(url,options,actor,guard=()=>{}){
    const generation=this.generation,controller=new AbortController();
    const current=()=>{if(generation!==this.generation)fail('UPDATE_CANCELLED','更新请求已取消，请以当前成员重新检查。');this.owner(actor);guard();};
    current();this.requests.add(controller);
    try{const bytes=await this.fetcher(url,{...options,signal:controller.signal,onProgress:()=>current()});current();return bytes;}
    finally{this.requests.delete(controller);}
  }
  reconcile(actor){this.owner(actor);for(const record of this.getStore().list('_updateHistory'))if(record.status==='launch_requested'&&compare(this.currentVersion,record.version)>=0)this.getStore().put('_updateHistory',{...record,status:'version_observed',observedVersion:this.currentVersion,observedAt:new Date(this.clock()).toISOString(),reason:'已重开目标或更高版本；这不是 Windows 安装器回执。'});}
  _preview(envelope,actor,{localDirectory}={}){this.owner(actor);const checked=verifyManifest(envelope,{keys:this.keys,currentVersion:this.currentVersion,now:this.clock()});const id=randomUUID();this.previews.set(id,{...checked,envelope,actorId:actor.id,localDirectory,createdAt:this.clock()});return this.describe(id);}
  describe(id){const p=this.previews.get(id);return {id,currentVersion:this.currentVersion,...p.manifest,key:p.key,artifact:{...p.manifest.artifact},signatureVerified:true,windowsPublisherVerified:false,local:!!p.localDirectory,ready:!!p.preparedPath,reason:p.manifest.channel==='development'?'已验证本项目开发密钥签名；不是正式 Windows 发行签名。':'已验证内置发布密钥签名；Windows 发布者签名需要另外核对。'};}
  _get(id,actor){this.owner(actor);const p=this.previews.get(id);if(!p||p.actorId!==actor.id||this.clock()-p.createdAt>30*60000)fail('UPDATE_PREVIEW','更新预览已失效，请重新检查。');verifyManifest(p.envelope,{keys:this.keys,currentVersion:this.currentVersion,now:this.clock()});return p;}
  importManifest(file,actor){this.owner(actor);if(fs.statSync(file).size>MAX_MANIFEST)fail('UPDATE_SIZE','更新清单过大。');return this._preview(readEnvelope(fs.readFileSync(file)),actor,{localDirectory:path.dirname(path.resolve(file))});}
  async check(actor){this.owner(actor);const feed=this.getStore().get('_updates','settings')?.feedUrl;if(!feed)fail('UPDATE_SOURCE_REQUIRED','尚未设置更新来源；也可以选择发行方提供的签名清单文件。');const bytes=await this._fetch(feed,{maxBytes:MAX_MANIFEST},actor);return this._preview(readEnvelope(bytes),actor);}
  _checkBytes(bytes,artifact){if(bytes.length!==artifact.size||digest(bytes)!==artifact.sha256)fail('UPDATE_HASH','安装包大小或摘要与签名清单不一致，不能执行安装。');if(!bytes.subarray(0,8).equals(Buffer.from('d0cf11e0a1b11ae1','hex')))fail('UPDATE_FORMAT','文件不是有效的 MSI 容器。');}
  async prepare({id},actor){const p=this._get(id,actor),artifact=p.manifest.artifact;let bytes;
    if(p.localDirectory){const source=path.join(p.localDirectory,artifact.filename);if(!fs.existsSync(source))fail('UPDATE_FILE_REQUIRED','请将签名清单与对应 MSI 安装包放在同一文件夹。');if(fs.statSync(source).size!==artifact.size)fail('UPDATE_HASH','安装包大小与清单不一致。');bytes=fs.readFileSync(source);}
    else {if(!artifact.url)fail('UPDATE_FILE_REQUIRED','此清单未提供下载地址，请选择本地签名清单与安装包。');bytes=await this._fetch(artifact.url,{maxBytes:artifact.size,timeout:120000},actor,()=>this._get(id,actor));}
    this._get(id,actor);this._checkBytes(bytes,artifact);fs.mkdirSync(this.downloadRoot,{recursive:true});const directory=path.join(this.downloadRoot,randomUUID());fs.mkdirSync(directory);const output=path.join(directory,artifact.filename);fs.writeFileSync(output,bytes,{mode:0o600,flag:'wx'});p.preparedPath=output;return this.describe(id);
  }
  takeForInstallation({id},actor){const p=this._get(id,actor);if(!p.preparedPath)fail('UPDATE_NOT_PREPARED','请先下载或检查安装包。');const bytes=fs.readFileSync(p.preparedPath);this._checkBytes(bytes,p.manifest.artifact);const record={id:randomUUID(),version:p.manifest.version,sha256:p.manifest.artifact.sha256,status:'launch_requested',keyId:p.key.id,channel:p.manifest.channel,createdAt:new Date(this.clock()).toISOString()};this.getStore().put('_updateHistory',record);this.previews.delete(id);return {path:p.preparedPath,version:p.manifest.version,sha256:p.manifest.artifact.sha256,size:p.manifest.artifact.size,historyId:record.id};}
}
module.exports={UpdateManager,UpdateError,canonical,compare,address,verifyManifest,readEnvelope,fetchBytes,MAX_MANIFEST,MAX_ARTIFACT};
