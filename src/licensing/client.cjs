'use strict';
const fs=require('node:fs'),path=require('node:path'),{pathToFileURL}=require('node:url');
const {randomUUID}=require('node:crypto');
const {TpmDevice}=require('./device.cjs');
const ROLLBACK_TOLERANCE=300000,CHECKPOINT_INTERVAL=60000;
class LicenseError extends Error {constructor(code,message,retryable=false){super(message);this.code=code;this.retryable=retryable;}}
const fail=(code,message,retryable)=>{throw new LicenseError(code,message,retryable);};
const safeReason=error=>error instanceof LicenseError?error.message:'授权操作未完成，请核对设备或稍后重试。';
const uuid=value=>typeof value==='string'&&/^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(value);
async function cloudPost(endpoint,route,body,fetchImpl=globalThis.fetch){
  let url;try{url=new URL(endpoint);if(url.protocol!=='https:'||url.username||url.password||url.search||url.hash)throw 0;}catch{fail('LICENSE_CONFIG','授权服务尚未配置有效的 HTTPS 地址。');}
  const target=new URL(route,url);let response;
  try{response=await fetchImpl(target.href,{method:'POST',redirect:'error',credentials:'omit',headers:{'content-type':'application/json'},body:JSON.stringify(body),signal:AbortSignal.timeout(20000)});}catch{fail('LICENSE_NETWORK','暂时无法取得云端最终确认；请保留本次请求并稍后恢复。',true);}
  let data;try{if(Number(response.headers.get('content-length'))>262144)throw 0;const reader=response.body.getReader(),chunks=[];let length=0;for(;;){const {done,value}=await reader.read();if(done)break;length+=value.length;if(length>262144){await reader.cancel();throw 0;}chunks.push(Buffer.from(value));}data=JSON.parse(Buffer.concat(chunks).toString('utf8'));}catch{fail('LICENSE_RESPONSE','授权服务返回的内容无效，请稍后恢复原请求。',true);}
  if(!response.ok||data?.ok!==true){const code=typeof data?.error?.code==='string'&&/^[A-Z0-9_]{1,70}$/.test(data.error.code)?data.error.code:'LICENSE_CLOUD';const messages={SERVICE_QUOTA:'免费额度不足，已暂停本次兑换，请稍后手动重试；存储额度不足需发行方处理，不保证次日恢复。',CODE_NOT_FOUND:'兑换码不存在或已不可兑换。',CODE_CONSUMED:'此兑换码已使用，请恢复原兑换请求。',LICENSE_NOT_FOUND:'云端尚未确认这次请求，请核对原兑换码和请求编号。',FREE_BUDGET_EXHAUSTED:'免费服务额度已用尽，暂时停止新兑换。',FREE_PLAN_REQUIRED:'授权服务未满足仅使用免费额度的要求，已停止兑换。'};fail(code,messages[code]||'云端未确认此次授权，请保留请求编号后重试。',data?.error?.retryable===true);}
  return data.data;
}
class LicenseClient {
  constructor({protocol,config,device=new TpmDevice(),directory=path.join(process.env.ProgramData||'C:\\ProgramData','Lianpu','Licensing','v1'),transport=cloudPost,wallClock=()=>Date.now(),monotonic=()=>Number(process.hrtime.bigint()/1000000n),onChange=()=>{},writeState}={}){
    Object.assign(this,{protocol,config:config||{},device,directory,transport,wallClock,monotonic,onChange});this.file=path.join(directory,'license-state.json');this.writer=writeState||((value)=>this._writeFile(value));this.body={v:1,license:null,pending:null,clock:null};this.payload=null;this.generation=0;this.ready=false;this.busy=false;this.lastError=null;this.storageError=null;this.clockRecovery=false;this.lastPublished='';this.anchorMono=monotonic();this.anchorTime=wallClock();this.lastCheckpoint=0;
  }
  configured(){return typeof this.config.endpoint==='string'&&Object.keys(this.config.publicKeys||{}).length>0;}
  _stateBytes(body){return Buffer.from('LIANPU-LICENSING/v1/local-state\0'+this.protocol.canonicalJson(body));}
  _writeFile(value){let temporary;try{if(!fs.existsSync(this.directory))fail('LICENSE_PREPARATION','尚未准备本机授权目录，请完成设备准备。');temporary=path.join(this.directory,randomUUID()+'.tmp');const descriptor=fs.openSync(temporary,'wx',0o600);try{fs.writeFileSync(descriptor,JSON.stringify(value));fs.fsyncSync(descriptor);}finally{fs.closeSync(descriptor);}fs.renameSync(temporary,this.file);}catch(error){if(temporary)try{fs.unlinkSync(temporary);}catch{}if(error instanceof LicenseError)throw error;fail('LICENSE_SAVE_FAILED','本机授权记录尚未保存。云端已确认的授权可用原请求编号恢复。',true);}}
  _save(body){const signature=this.device.signSync(this._stateBytes(body)).toString('base64url');this.writer({v:1,deviceId:this.device.info.deviceId,body,signature});this.body=structuredClone(body);this.storageError=null;}
  async initialize(){
    await this.device.status();this.ready=this.device.validate();if(this.ready&&fs.existsSync(this.file))try{
      if(fs.statSync(this.file).size>262144)fail('LICENSE_STATE_INVALID','本机授权记录无效，请恢复原授权。');const stored=JSON.parse(fs.readFileSync(this.file,'utf8'));
      if(stored.v!==1||stored.deviceId!==this.device.info.deviceId||!stored.body||stored.body.v!==1||typeof stored.signature!=='string'||!this.device.verify(this._stateBytes(stored.body),Buffer.from(stored.signature,'base64url')))fail('LICENSE_STATE_INVALID','本机授权记录无法通过设备核验，请恢复原授权。');
      this.body=stored.body;if(this.body.license)this.payload=await this._validateLicense(this.body.license);
      const clock=this.body.clock;if(clock&&(!Number.isSafeInteger(clock.highWater)||!Number.isSafeInteger(clock.serverAnchor)||clock.highWater<clock.serverAnchor))fail('LICENSE_STATE_INVALID','本机授权时间记录无效，请联网恢复原授权。');
      this.anchorTime=Math.max(this.wallClock(),clock?.highWater||0);this.anchorMono=this.monotonic();this.lastCheckpoint=clock?.highWater||0;
    }catch{this.payload=null;this.storageError='LICENSE_STATE_INVALID';this.lastError='本机授权记录无法恢复，请凭原请求编号向云端找回授权。';}
    return this.status();
  }
  _effectiveTime(){const elapsed=Math.max(0,this.monotonic()-this.anchorMono),expected=this.anchorTime+elapsed,wall=this.wallClock(),high=this.body.clock?.highWater||0;if(this.payload&&(wall+ROLLBACK_TOLERANCE<high||wall+ROLLBACK_TOLERANCE<expected))this.clockRecovery=true;return Math.max(wall,expected,high);}
  _calculate(){
    const info=this.device.info||{},deviceReason=/^DEVICE_(?:PREPARATION_|OPERATION_UNCONFIRMED|SIGN_FAILED|SIGNATURE)/.test(info.code||'')?info.message:({needs_admin:'请准备设备，并在 Windows 提示中由本人确认管理员授权。',not_prepared:'请先准备本机设备保护。',no_tpm:'没有检测到 TPM 2.0，无法启用此设备授权。',tpm_not_2:'当前设备不满足 TPM 2.0 要求。',tpm_not_ready:'设备保护尚未就绪，请检查 Windows 安全设置。',unsupported:'当前平台不支持所需的 Windows TPM 2.0 设备保护。',error:'设备保护组件不可用，请修复完整安装包。'})[info.state],device={state:info.state||'checking',reason:deviceReason,deviceId:info.deviceId,requiresPreparation:['not_prepared','needs_admin'].includes(info.state)||info.storage?.prepared===false,hardwareVerified:this.ready,tpm:info.tpm,diagnostic:{code:info.code||null,operation:info.operation||null,nativeCode:info.nativeCode||null,nativeDeviceCode:info.nativeDeviceCode||null,preparation:info.preparation||null}};
    let state,reason,active=false;const current=this._effectiveTime();
    if(!this.configured()){state='unconfigured';reason='尚未配置发行方授权服务和公钥，经营功能暂不可用。';}
    else if(!this.ready){state=['needs_admin','not_prepared'].includes(info.state)?'preparation_required':'device_required';reason=deviceReason||'本机需要可用的 TPM 2.0 设备保护，不能使用软件密钥替代。';}
    else if(this.storageError){state='blocked';reason=this.lastError||'本机授权记录需要恢复。';}
    else if(this.clockRecovery){state='clock_recovery_required';reason='本机时间明显回拨，请校准时间并联网恢复原授权；授权期限不会重新起算。';}
    else if(this.payload){if(this.payload.expiresAt!==null&&current>=this.payload.expiresAt){state='expired';reason='授权已到期，经营服务已停止；现有资料仍可按成员权限查看和备份。';}else{state='active';active=true;reason='设备授权有效。';}}
    else{state=this.body.pending?'pending':'inactive';reason=this.body.pending?'本次兑换尚未完成最终确认，可继续确认或恢复原请求。':'请先兑换设备授权。';}
    const result={state,active,reason,generation:this.generation,expiresAt:this.payload?.expiresAt===null?null:this.payload?.expiresAt?new Date(this.payload.expiresAt).toISOString():null,plan:this.payload?.plan||null,licenseId:this.payload?.licenseId||null,device,pending:this.body.pending?{requestId:this.body.pending.requestId,state:this.body.pending.phase,mode:this.body.pending.mode,reason:this.lastError||undefined}:null};return result;
  }
  _publish(){const state=this._calculate(),key=JSON.stringify([state.state,state.active,state.reason,state.device.state,state.device.reason,state.device.requiresPreparation,state.licenseId,state.expiresAt,state.pending?.requestId,state.pending?.state,state.pending?.reason]);if(key!==this.lastPublished){this.lastPublished=key;this.generation++;state.generation=this.generation;this.onChange(state);}return state;}
  status(){return this._publish();}
  assertAllowed(){const status=this.status();if(!status.active){const error=new LicenseError('LICENSE_REQUIRED',status.reason);error.licensePreSubmission=true;throw error;}const effective=Math.floor(this._effectiveTime());if(effective-this.lastCheckpoint>=CHECKPOINT_INTERVAL){try{this._save({...this.body,clock:{...this.body.clock,highWater:effective}});this.lastCheckpoint=effective;}catch(error){this.storageError='LICENSE_SAVE_FAILED';this.lastError=safeReason(error);this._publish();const blocked=new LicenseError('LICENSE_REQUIRED',this.lastError);blocked.licensePreSubmission=true;throw blocked;}}return true;}
  checkpoint(){try{if(this.status().active)this.assertAllowed();}catch{}return this.status();}
  async prepareDevice(){if(this.busy)fail('LICENSE_BUSY','正在处理本次授权，请稍候。');this.busy=true;try{await this.device.prepare();this.ready=this.device.validate();if(this.ready&&fs.existsSync(this.file))return await this.initialize();if(this.ready&&!this.body.license&&!this.body.pending){try{this._save(this.body);}catch(error){this.storageError='LICENSE_PREPARATION';this.lastError=safeReason(error);}}return this.status();}finally{this.busy=false;}}
  _requireReady(){if(!this.configured())fail('LICENSE_CONFIG','尚未配置发行方授权服务与公钥。');if(!this.ready)fail('LICENSE_DEVICE_REQUIRED','请先完成真实 TPM 2.0 设备准备。');}
  async _exclusive(fn){if(this.busy)fail('LICENSE_BUSY','正在处理本次授权，请稍候。');this.busy=true;try{return await fn();}catch(error){this.lastError=safeReason(error);this._publish();throw error instanceof LicenseError?error:new LicenseError(error.code||'LICENSE_FAILED',safeReason(error),true);}finally{this.busy=false;}}
  async _ticket(mode,requestId,code){
    const data=await this.transport(this.config.endpoint,'/v1/precheck',{v:1,mode,requestId,devicePublicKeySpki:this.device.info.publicKeySpki,...(mode==='activate'?{code}:{})});
    const payload=await this.protocol.verifyEnvelope(data.ticket,'ticket',this.config.publicKeys);this.protocol.validateTicketPayload(payload);
    if(payload.mode!==mode||payload.requestId!==requestId||payload.deviceId!==this.device.info.deviceId||payload.devicePublicKeySpki!==this.device.info.publicKeySpki||mode==='activate'&&payload.codeHash!==await this.protocol.hashCode(code))fail('LICENSE_TICKET_MISMATCH','云端核对结果不属于本次设备兑换。');
    const bytes=Buffer.from(this.protocol.ticketProofBytes(data.ticket));if(data.challenge?.algorithm!=='ECDSA-P256-SHA256'||data.challenge.bytes!==bytes.toString('base64url')||data.challenge.expiresAt!==payload.expiresAt)fail('LICENSE_CHALLENGE','云端挑战与已签名核对结果不一致。');
    return {ticket:data.ticket,preview:{mode:payload.mode,plan:payload.plan,periodDays:payload.plan?this.protocol.PERIOD_DAYS[payload.plan]:null},payload};
  }
  precheck({code}={}){return this._exclusive(async()=>{
    this._requireReady();code=this.protocol.normalizeCode(code);const codeHash=await this.protocol.hashCode(code),prior=this.body.pending,activation=prior?.mode==='activate'?prior:prior?.activation;
    if(prior&&(prior.phase==='confirming'||prior.mode==='recover')&&activation?.codeHash!==codeHash)fail('LICENSE_PENDING_RECOVERY','上次兑换结果仍待确认，请先恢复原请求；不会用其他兑换码覆盖恢复记录。');
    const requestId=activation?.codeHash===codeHash?activation.requestId:randomUUID();
    this._save({...this.body,pending:{requestId,mode:'activate',codeHash,phase:'checking',ticket:null}});this.lastError=null;this._publish();
    const checked=await this._ticket('activate',requestId,code);this._save({...this.body,pending:{requestId,mode:'activate',codeHash,phase:'prechecked',ticket:checked.ticket}});this._publish();return {requestId,preview:checked.preview,expiresAt:new Date(checked.payload.expiresAt).toISOString(),license:this.status()};
  });}
  async _validateLicense(envelope,requestId){const payload=await this.protocol.verifyEnvelope(envelope,'license',this.config.publicKeys);this.protocol.validateLicensePayload(payload);if(payload.deviceId!==this.device.info.deviceId||payload.devicePublicKeySpki!==this.device.info.publicKeySpki||requestId&&payload.requestId!==requestId)fail('LICENSE_DEVICE_MISMATCH','授权不属于当前设备或本次请求。');return payload;}
  async _finalize(pending,route){
    const ticketPayload=await this.protocol.verifyEnvelope(pending.ticket,'ticket',this.config.publicKeys);this.protocol.validateTicketPayload(ticketPayload);
    if(ticketPayload.requestId!==pending.requestId||ticketPayload.deviceId!==this.device.info.deviceId)fail('LICENSE_TICKET_MISMATCH','原请求与当前设备不一致。');
    this._save({...this.body,pending:{...pending,phase:'confirming'}});this._publish();
    const signature=this.device.signSync(Buffer.from(this.protocol.ticketProofBytes(pending.ticket))).toString('base64url');
    const result=await this.transport(this.config.endpoint,route,{v:1,ticket:pending.ticket,proof:{algorithm:'ECDSA-P256-SHA256',signature}});
    const payload=await this._validateLicense(result.license,pending.requestId);
    if(this.payload&&(payload.revision<this.payload.revision||this.payload.expiresAt===null&&payload.expiresAt!==null||this.payload.expiresAt!==null&&payload.expiresAt!==null&&payload.expiresAt<this.payload.expiresAt))fail('LICENSE_STALE','此授权早于本机已有授权，已保留当前许可。');
    const serverTime=ticketPayload.issuedAt,body={v:1,license:result.license,pending:null,clock:{serverAnchor:serverTime,highWater:serverTime}};
    this._save(body);this.payload=payload;this.anchorTime=serverTime;this.anchorMono=this.monotonic();this.lastCheckpoint=serverTime;this.clockRecovery=false;this.lastError=null;
    return {status:'activated',recovered:result.recovered===true,license:this.status()};
  }
  confirm({requestId}={}){return this._exclusive(async()=>{this._requireReady();const pending=this.body.pending;if(!uuid(requestId)||pending?.requestId!==requestId||!pending.ticket||pending.mode!=='activate')fail('LICENSE_REQUEST_REQUIRED','请先核对本次兑换码，再确认同一请求。');return this._finalize(pending,'/v1/confirm');});}
  recover({requestId}={}){return this._exclusive(async()=>{this._requireReady();const previous=this.body.pending;requestId=requestId||previous?.requestId||this.payload?.requestId;if(!uuid(requestId))fail('LICENSE_REQUEST_REQUIRED','请输入原授权请求编号，找回同一份设备授权。');if(previous&&requestId!==previous.requestId)fail('LICENSE_PENDING_RECOVERY','已有待确认请求，请先恢复原编号，不能覆盖其恢复记录。');const activation=previous?.mode==='activate'?{requestId:previous.requestId,codeHash:previous.codeHash,ticket:previous.ticket}:previous?.activation||null;this._save({...this.body,pending:{requestId,mode:'recover',phase:'checking',ticket:null,activation}});this.lastError=null;this._publish();const checked=await this._ticket('recover',requestId);const pending={requestId,mode:'recover',phase:'prechecked',ticket:checked.ticket,activation};this._save({...this.body,pending});return this._finalize(pending,'/v1/recover');});}
}
async function createLicenseClient(options={}){const protocol=options.protocol||await import(pathToFileURL(path.resolve(__dirname,'../../shared/licensing/protocol.mjs')).href);return new LicenseClient({...options,protocol,config:options.config||require('./config.json')});}
module.exports={LicenseClient,LicenseError,createLicenseClient,cloudPost,ROLLBACK_TOLERANCE,CHECKPOINT_INTERVAL};
