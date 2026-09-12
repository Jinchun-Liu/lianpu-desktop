'use strict';

const { randomUUID, createHash } = require('node:crypto');
const { AccessError } = require('../auth.cjs');
const now = () => new Date().toISOString();
const fingerprint = member => createHash('sha256').update(JSON.stringify({role:member.role,accountIds:member.accountIds||[],enabled:member.enabled!==false})).digest('hex');
const fail = (code,message) => { throw new AccessError(code,message); };
const DEFAULTS = Object.freeze({sync:true,replies:true,paidDelivery:true,services:false,plans:false});
const CAPABILITIES = ['readProducts','readOrders','readMessages','sendMessages','sendMessage','writeProducts','mutateProduct','publishProducts','updateProducts','markShipped','refunds','logistics','promotions','interactions','readOrderEvents','sendThankYou','sendReceiptReminder','sendReviewRequest','sendGifts','orderEvents','afterSales','supplier','downloadPage'];

/** Main-process only. Credentials never pass through this runtime's public results. */
class AccountRuntime {
  constructor({store,service,connector,assertUi = () => {},emit = () => {}}) {
    Object.assign(this,{store,service,connector,assertUi,emit});this.accepting=true;this.attempts=new Map();this.running=new Map();this.connectionTasks=new Set();this.loginStarts=new Map();this.loginEpoch=0;this.bindQueue=Promise.resolve();
    store.transaction(()=>{
      for(const account of store.list('accounts').filter(a=>a.space==='live')) {
        const grant=store.get('_hosting',account.id);
        if(grant?.enabled)store.put('_hosting',{...grant,enabled:false,version:grant.version+1,reason:'启动后需明确开启账号托管。',updatedAt:now()});
        const loginStatus=['cleared','revoked','cleanup_failed','revocation_failed'].includes(account.loginStatus)?account.loginStatus:account.platformUserId||account.externalId?'unverified':'awaiting_scan';
        store.put('accounts',{...account,platformUserId:account.platformUserId||account.externalId,loginStatus,connectionStatus:'disconnected',connectionReason:loginStatus==='unverified'?'已保留本机会话，可检查登录或直接同步；托管保持暂停。':'',capabilities:{},paused:true,hosting:{...DEFAULTS,...account.hosting,enabled:false},authorizationVersion:(account.authorizationVersion||0)+1,updatedAt:now()});
      }
    });
  }
  actor(actor) { this.assertUi(actor);return this.service._actor(actor); }
  account(accountId,actor,operation='operate') { return this.service._record('accounts',accountId,this.actor(actor),operation); }
  audit(actor,action,account,result='ok') { this.service._audit(actor,action,account,result); }
  async startLogin({accountId},actor) {
    this.service.assertLicense();
    actor=this.actor(actor);if(!this.accepting)fail('STOPPING','后台正在保存提交结果，请稍后再开启托管。');
    const target=accountId?this.account(accountId,actor):null;
    if(!target&&actor.role!=='owner')fail('FORBIDDEN','添加新账号需要本机管理员。');
    if(target&&(target.space!=='live'||target.archived))fail('ACCOUNT_INVALID','请选择未归档的真实账号。');
    if(target&&!target.paused)this.hosting({accountId:target.id,enabled:false},actor);
    const slot=`${actor.id}:${accountId||'new'}`,requestEpoch=this.loginEpoch,requestToken=randomUUID();this.loginStarts.set(slot,requestToken);
    for(const attempt of this.attempts.values())if(attempt.memberId===actor.id&&attempt.accountId===accountId&&!attempt.finished)await this.cancelLogin({attemptId:attempt.id},actor);
    const token={memberId:actor.id,memberFingerprint:fingerprint(this.store.get('members',actor.id)),accountId,expectedIdentity:target?.platformUserId||target?.externalId,generation:target?.sessionVersion||0,cancelled:false};
    const result=await this.connector.startLogin(token);
    token.id=result.attemptId||result.id;this.attempts.set(token.id,token);
    if(requestEpoch!==this.loginEpoch||this.loginStarts.get(slot)!==requestToken){token.cancelled=true;token.finished=true;await this.connector.cancelLogin({attemptId:token.id,memberId:actor.id});return {attemptId:token.id,status:'cancelled',reason:'旧登录尝试已被关闭或替换。'};}
    try{this.attempt(token.id,actor);}catch(error){token.cancelled=true;await this.connector.cancelLogin({attemptId:token.id,memberId:actor.id});throw error;}
    return this.publicLogin(result);
  }
  publicLogin(result) {
    if(!result)return null;
    const output={};for(const key of ['attemptId','id','accountId','status','state','reason','code','expiresAt','createdAt','observed','observedStates','nickname','externalId','platformUserId','loginStatus','verificationRequired','windowOpened'])if(result[key]!==undefined)output[key]=structuredClone(result[key]);
    if(result.identity)output.identity={platformUserId:result.identity.platformUserId,nickname:result.identity.nickname};
    output.attemptId ||= result.id;return output;
  }
  attempt(attemptId,actor) {
    actor=this.actor(actor);const attempt=this.attempts.get(attemptId);
    if(!attempt||attempt.memberId!==actor.id)fail('LOGIN_OWNER','此登录尝试不属于当前成员。');
    if(fingerprint(this.store.get('members',actor.id))!==attempt.memberFingerprint||!attempt.accountId&&actor.role!=='owner')fail('LOGIN_PERMISSION_CHANGED','成员授权已变化，请使用当前权限重新开始扫码。');
    if(attempt.accountId)this.account(attempt.accountId,actor);
    return attempt;
  }
  async getLogin({attemptId},actor) {
    const attempt=this.attempt(attemptId,actor);if(attempt.cancelled)return {attemptId,status:'cancelled',reason:'已取消此登录，旧结果不会绑定账号。'};
    const result=await this.connector.getLogin({attemptId,memberId:actor.id});this.attempt(attemptId,actor);return this.publicLogin(result);
  }
  async cancelLogin({attemptId},actor) {
    const attempt=this.attempt(attemptId,actor);attempt.cancelled=true;attempt.finished=true;
    await this.connector.cancelLogin({attemptId,memberId:actor.id});return {attemptId,status:'cancelled'};
  }
  async cancelLogins() {
    this.loginEpoch++;
    await Promise.allSettled([...this.attempts.values()].filter(a=>!a.finished).map(async attempt=>{attempt.cancelled=true;attempt.finished=true;await this.connector.cancelLogin({attemptId:attempt.id,memberId:attempt.memberId});}));
  }
  bindLogin(payload,actor) {const task=this.bindQueue.then(()=>this._bindLogin(payload,actor));this.bindQueue=task.catch(()=>{});return task;}
  async _bindLogin({attemptId,name,note},actor) {
    this.service.assertLicense();
    if(name!==undefined&&(typeof name!=='string'||name.length>100)||note!==undefined&&(typeof note!=='string'||note.length>10000))fail('VALIDATION','账号名称或备注格式无效。');
    const attempt=this.attempt(attemptId,actor);if(attempt.cancelled||attempt.finished)fail('LOGIN_STALE','登录尝试已失效，请重新扫码。');
    const observed=await this.connector.getLogin({attemptId,memberId:actor.id});this.attempt(attemptId,actor);
    const platformUserId=observed?.identity?.platformUserId||observed?.platformUserId||observed?.externalId;
    if(typeof platformUserId!=='string'||!platformUserId)fail('IDENTITY_UNVERIFIED','尚未取得平台确认的账号身份，请完成官方扫码。');
    if(attempt.expectedIdentity&&platformUserId!==attempt.expectedIdentity)fail('IDENTITY_MISMATCH','扫码身份与目标账号不一致，原账号没有被覆盖。');
    const duplicate=this.store.list('accounts').find(a=>a.space==='live'&&(a.platformUserId||a.externalId)===platformUserId);
    if(attempt.accountId&&duplicate&&duplicate.id!==attempt.accountId)fail('IDENTITY_MISMATCH','此平台身份已绑定其他本机账号，不能覆盖目标账号。');
    const accountId=attempt.accountId||duplicate?.id||randomUUID();
    if(duplicate){this.account(duplicate.id,actor);if(!duplicate.paused)this.hosting({accountId:duplicate.id,enabled:false},actor);}
    const trusted=await this.connector.bindLogin({attemptId,memberId:actor.id,accountId,expectedIdentity:attempt.expectedIdentity});
    try{this.attempt(attemptId,actor);if(attempt.cancelled||!this.accepting)fail('LOGIN_STALE','绑定期间登录尝试已失效，请重新扫码。');}catch(error){await this.connector.revoke(accountId);throw error;}
    if((trusted?.identity?.platformUserId||trusted?.externalId)!==platformUserId)fail('IDENTITY_MISMATCH','登录确认中的身份发生变化，未保存绑定。');
    if(typeof trusted.evidenceId!=='string'||!trusted.evidenceId||!Number.isFinite(Date.parse(trusted.verifiedAt)))fail('IDENTITY_UNVERIFIED','平台身份缺少可追溯核验记录。');
    const result=this.store.transaction(()=>{
      this.service.assertLicense();
      const old=this.store.get('accounts',accountId);if(attempt.accountId&&(old?.sessionVersion||0)!==attempt.generation)fail('LOGIN_STALE','账号会话已改变，请重新扫码。');
      const conflict=this.store.list('accounts').find(a=>a.space==='live'&&a.id!==accountId&&(a.platformUserId||a.externalId)===platformUserId);if(conflict)fail('IDENTITY_MISMATCH','此平台身份已绑定其他账号，旧绑定请求已取消。');
      const sessionVersion=trusted.sessionGeneration??trusted.sessionVersion;
      if(!Number.isSafeInteger(sessionVersion)||sessionVersion<1||old?.sessionVersion&&sessionVersion<=old.sessionVersion)fail('SESSION_INVALID','可信会话版本无效或未更新。');
      const candidate={...old,id:accountId,accountId,space:'live',name:typeof name==='string'&&name.trim()?name.trim():old?.name||trusted.identity.nickname||'我的闲鱼账号',note:typeof note==='string'?note:old?.note||'',mode:'live',externalId:platformUserId,platformUserId,nickname:trusted.identity.nickname||'',status:'authenticated',loginStatus:'authenticated',connectionStatus:'disconnected',paused:true,archived:false,archivedAt:undefined,sessionVersion,identityVerifiedAt:trusted.verifiedAt,identityEvidenceId:trusted.evidenceId,capabilities:this.capabilities(trusted.capabilities,sessionVersion),hosting:{...DEFAULTS,...old?.hosting,enabled:false},authorizationVersion:(old?.authorizationVersion||0)+1,createdAt:old?.createdAt||now(),updatedAt:now()};
      const validated=this.service._validate('accounts',candidate,old,true);this.store.put('accounts',validated);const grant=this.store.get('_hosting',accountId);if(grant)this.store.put('_hosting',{...grant,enabled:false,version:grant.version+1,updatedAt:now()});this.audit(actor,'account.login.bind',validated,old?'refreshed':'bound');return validated;
    });
    attempt.finished=true;this.emit('changed');return {account:this.service._public('accounts',result,actor),accountId:result.id,status:'bound',duplicate:!!duplicate};
  }
  capabilities(input,sessionVersion) {
    const result={};for(const key of CAPABILITIES){const fact=input?.[key];if(!fact)continue;const stamp=Date.parse(fact.verifiedAt),verified=typeof fact==='object'&&typeof fact.evidenceId==='string'&&!!fact.evidenceId&&Number.isFinite(stamp)&&stamp<=Date.now()+30000&&Date.now()-stamp<=300000&&(fact.sessionVersion===undefined||fact.sessionVersion===sessionVersion)&&(fact.sessionGeneration===undefined||fact.sessionGeneration===sessionVersion);result[key]={available:verified&&fact.available===true,status:verified&&fact.available===true?'available':['blocked','unavailable','unsupported'].includes(fact.status)?fact.status:'unverified',reason:String(fact.reason||(verified&&fact.available===true?'当前会话已通过此项检查。':'尚未检查此项，请点击检查。')).slice(0,400),...(verified?{evidenceId:fact.evidenceId,verifiedAt:fact.verifiedAt}:{}),...(Number.isFinite(Date.parse(fact.checkedAt))?{checkedAt:fact.checkedAt}:{}),sessionVersion};}return result;
  }
  observeStatus(status) {
    if(!this.accepting||!status||typeof status.accountId!=='string')return false;
    const account=this.store.get('accounts',status.accountId),version=status.sessionVersion??status.sessionGeneration;
    if(!account||account.archived||version!==account.sessionVersion)return false;
    // Paused/revoked accounts cannot be re-enabled by a delayed connector notification.
    let connectionStatus=account.paused&&status.readOnlyCheck!==true?'disconnected':status.connectionStatus||status.connection?.status||status.status||account.connectionStatus;
    const loginStatus=status.loginStatus||status.login?.status||account.loginStatus;
    const halt=['login_required','verification_required','expired','identity_mismatch','failed','revoked','revocation_failed'].includes(loginStatus)||['login_required','verification_required','expired','identity_mismatch'].includes(connectionStatus),grant=this.store.get('_hosting',account.id),mustPause=halt&&grant?.enabled;
    if(halt)connectionStatus='disconnected';
    this.store.transaction(()=>{const next={...account,connectionStatus,loginStatus,connectionReason:String(status.reason||'').slice(0,400),capabilities:halt?{}:status.capabilities?this.capabilities(status.capabilities,version):account.capabilities,...(halt?{paused:true,hosting:{...account.hosting,enabled:false}}:{}),updatedAt:now()};this.store.put('accounts',next);if(mustPause)this.store.put('_hosting',{...grant,enabled:false,version:grant.version+1,reason:'平台需要本人处理，已停止此账号。',updatedAt:now()});this.audit({id:'platform-runtime'},'account.session.status',next,connectionStatus);});
    if(mustPause)this.connector.pause?.(account.id,'平台需要本人处理，请完成官方验证后明确恢复');
    this.emit('platform',{status:{accountId:account.id,loginStatus,connectionStatus}});return true;
  }
  hosting({accountId,enabled,...options},actor) {
    if(enabled)this.service.assertLicense();
    const account=this.account(accountId,actor);actor=this.actor(actor);
    if(account.space!=='live'||account.archived&&enabled)fail('ACCOUNT_INVALID','只能开启未归档真实账号的托管。');
    if(typeof enabled!=='boolean')fail('VALIDATION','请明确开启或停止托管。');
    if(enabled&&!account.platformUserId)fail('IDENTITY_UNVERIFIED','请先完成此账号的官方扫码身份核验。');
    if(enabled&&!this.store.get('_hosting',accountId)?.enabled&&this.store.list('_hosting').filter(g=>g.enabled&&!this.store.get('accounts',g.id)?.paused).length>=5)fail('ACCOUNT_LIMIT','当前最多同时开启 5 个账号的托管。');
    const configuration={...DEFAULTS,...account.hosting,...options,enabled};
    for(const key of Object.keys(options))if(!(key in DEFAULTS)||typeof options[key]!=='boolean')fail('VALIDATION','托管配置只接受已提供的操作开关。');
    const member=this.store.get('members',actor.id);if(!member||!['owner','operator'].includes(member.role))fail('FORBIDDEN','持续经营需要管理员或经营成员授权。');
    const previous=this.store.get('_hosting',accountId),version=(previous?.version||0)+1;
    const grant={id:accountId,actorId:actor.id,accountIds:[accountId],actions:Object.keys(DEFAULTS).filter(k=>configuration[k]),enabled,version,memberFingerprint:fingerprint(member),sessionVersion:account.sessionVersion,enabledAt:enabled?now():previous?.enabledAt,updatedAt:now()};
    const updated={...account,hosting:configuration,paused:!enabled,authorizationVersion:version,updatedAt:now()};
    this.store.transaction(()=>{this.store.put('_hosting',grant);this.store.put('accounts',updated);this.audit(actor,'account.hosting.save',updated,enabled?'enabled':'disabled');});
    if(enabled){const task=Promise.resolve().then(()=>{const current=this.store.get('_hosting',accountId);if(!this.accepting||!current?.enabled||current.version!==version)return;return this.connector.resume?.(updated);}).catch(()=>{if(this.accepting){const current=this.store.get('accounts',accountId);if(current&&this.store.get('_hosting',accountId)?.version===version)this.store.put('accounts',{...current,connectionStatus:'failed',connectionReason:'本机会话恢复失败，请重新扫码或检查官方页面。',updatedAt:now()});}}).finally(()=>this.connectionTasks.delete(task));this.connectionTasks.add(task);}else this.connector.pause?.(accountId,'此账号已停止托管');
    this.emit('changed');return this.service._public('accounts',updated,actor);
  }
  async clearLogin({accountId},actor) {
    const account=this.account(accountId,actor);this.hosting({accountId,enabled:false},actor);
    for(const attempt of this.attempts.values())if(attempt.accountId===accountId){attempt.cancelled=true;attempt.finished=true;}
    // Revoke the epoch before awaiting credential cleanup, so late status cannot restore it.
    const latest=this.store.get('accounts',accountId);this.store.put('accounts',{...latest,sessionVersion:(latest.sessionVersion||0)+1,loginStatus:'cleared',connectionStatus:'disconnected',capabilities:{},updatedAt:now()});
    let cleanup;try{cleanup=await this.connector.revoke(accountId);}catch{cleanup={status:'failed'};}
    if(cleanup?.status==='failed'||cleanup?.status==='cleanup_failed'||cleanup?.loginStatus==='revocation_failed'||cleanup?.ok===false||cleanup?.cleared===false){const current=this.store.get('accounts',accountId);if(current)this.store.put('accounts',{...current,loginStatus:'cleanup_failed',connectionReason:'本机登录资料未能完全清除，请重试清除。',updatedAt:now()});this.audit(actor,'account.login.clear',account,'cleanup_failed');return {accountId,status:'cleanup_failed',reason:'账号已停止处理，但本机登录清理未完成，请重试。'};}
    this.audit(actor,'account.login.clear',account);return {accountId,status:'cleared'};
  }
  async remove({accountId},actor) { this.account(accountId,actor,'owner');const cleared=await this.clearLogin({accountId},actor);if(cleared.status!=='cleared')return {...cleared,removed:false,archived:false};return this.service.remove({kind:'accounts',id:accountId},this.actor(actor)); }
  details({accountId},actor) { const account=this.account(accountId,actor,'read');const snapshot=this.service.snapshot({space:account.space,accountId},this.actor(actor));return {account:this.service._public('accounts',account,actor),...snapshot}; }
  status() {return {accepting:this.accepting,activeAccounts:this.store.list('_hosting').filter(g=>g.enabled&&!this.store.get('accounts',g.id)?.paused).length,runningAccounts:[...this.running.keys()],keysRetained:true};}
  reconcile() {
    for(const grant of this.store.list('_hosting').filter(g=>g.enabled))try{this.service.authorizeBackground(grant.id);}catch{const account=this.store.get('accounts',grant.id);this.store.transaction(()=>{this.store.put('_hosting',{...grant,enabled:false,version:grant.version+1,reason:'成员或账号授权已改变。',updatedAt:now()});if(account)this.store.put('accounts',{...account,paused:true,hosting:{...account.hosting,enabled:false},authorizationVersion:grant.version+1,updatedAt:now()});});this.connector.pause?.(grant.id,'授权已撤销');}
  }
  tick() {
    try{this.service.assertLicense();}catch{return Promise.resolve([]);}
    if(!this.accepting)return Promise.resolve([]);this.reconcile();const tasks=[];
    for(const grant of this.store.list('_hosting').filter(g=>g.enabled)){
      if(this.running.has(grant.id))continue;
      const task=(async()=>{const actor=this.service.authorizeBackground(grant.id);const results=[];
        if(grant.actions.includes('sync'))for(const kind of ['products','orders','messages']){if(!this.accepting)break;results.push(await this.service.run('account.sync',{id:grant.id,kind},actor));}
        if(this.accepting)results.push(await this.service.run('automation.tick',{space:'live',accountId:grant.id},actor));return results;
      })().catch(error=>({status:'needs_attention',code:error.code||'BACKGROUND_ERROR'})).finally(()=>this.running.delete(grant.id));
      this.running.set(grant.id,task);tasks.push(task);
    }
    return Promise.allSettled(tasks);
  }
  beginStop(reason='持续托管已停止') {
    this.accepting=false;this.service.stopBackground();this.service.invalidate();
    this.store.transaction(()=>{for(const grant of this.store.list('_hosting').filter(g=>g.enabled)){this.store.put('_hosting',{...grant,enabled:false,version:grant.version+1,reason,updatedAt:now()});const account=this.store.get('accounts',grant.id);if(account)this.store.put('accounts',{...account,paused:true,hosting:{...account.hosting,enabled:false},authorizationVersion:grant.version+1,updatedAt:now()});}});
    this.connector.pauseAll?.(reason);return this.cancelLogins();
  }
  async drain() { await Promise.allSettled([...this.running.values(),...this.connectionTasks]);await this.connector.drain?.();await this.connector.disconnect?.(); }
}

module.exports={AccountRuntime,DEFAULTS};
