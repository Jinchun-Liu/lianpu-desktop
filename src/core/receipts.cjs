'use strict';

const { createHash, randomUUID } = require('node:crypto');
const now=()=>new Date().toISOString(), clone=value=>structuredClone(value);
const digest=value=>createHash('sha256').update(value).digest('hex');
const stable=(...parts)=>digest(JSON.stringify(parts));
const EVENTS=new Set(['receipt_confirmed','delivery_confirmed']);
const ACTIONS={
  thankYou:{event:'receipt_confirmed',capability:'sendThankYou'},
  receiptReminder:{event:'delivery_confirmed',capability:'sendReceiptReminder'},
  reviewRequest:{event:'receipt_confirmed',capability:'sendReviewRequest'},
};
const REVIEW_TEXT='如果你愿意，可以根据实际使用体验自主评价；无需好评，评价与否不影响已购买的资料或服务。';
const SENT=new Set(['sent','verified_sent']);
const RETRYABLE=new Set(['rejected','rate_limited','blocked','verified_not_sent']);
const error=(code,message)=>{const e=new Error(message);e.code=code;throw e;};
const text=(v,label,required=false,max=10000)=>{if(v==null&&!required)return;if(typeof v!=='string'||v.length>max||(required&&!v.trim()))error('VALIDATION',`${label}须为有效文本。`);};
const validTime=v=>typeof v==='string'&&Number.isFinite(Date.parse(v));

const methods={
  _validateInteractionProfile(record,old) {
    text(record.name,'互动档案名称',true,100);
    if(record.productId)this._relation('products',record.productId,record);
    if(!record.actions||typeof record.actions!=='object'||Array.isArray(record.actions)||Object.keys(record.actions).some(k=>!ACTIONS[k]))error('VALIDATION','互动须逐项配置致谢、收货提醒或中性评价邀请。');
    for(const [type,action]of Object.entries(record.actions)){
      if(!action||typeof action!=='object'||Array.isArray(action)||Object.keys(action).some(k=>!['enabled','text','delaySeconds'].includes(k))||typeof action.enabled!=='boolean')error('VALIDATION','每项互动必须明确是否启用。');
      if(action.delaySeconds!=null&&(!Number.isSafeInteger(action.delaySeconds)||action.delaySeconds<0||action.delaySeconds>2592000))error('VALIDATION','互动延时须为 0 到 2592000 秒的整数。');
      if(type==='reviewRequest'){
        if(action.text!=null&&action.text!==REVIEW_TEXT)error('VALIDATION','评价邀请仅支持固定中性文案，不能代写评价或以赠品换取好评。');
        action.text=REVIEW_TEXT;
      }else text(action.text,'互动文案',action.enabled,10000);
    }
    // Re-enabling is explicit. Historical events are never replayed on profile save.
    record.enabledAt=record.enabled===true?(old?.enabled===true?old.enabledAt:now()):undefined;
    if(record.enabled===true&&this.store.list('interactionProfiles').some(p=>p.id!==record.id&&p.space===record.space&&p.accountId===record.accountId&&p.enabled===true&&(!p.productId||!record.productId||p.productId===record.productId)&&Object.keys(ACTIONS).some(k=>p.actions?.[k]?.enabled===true&&record.actions[k]?.enabled===true)))error('RULE_CONFLICT','同一商品存在重叠启用的互动，请保留唯一生效档案。');
  },
  _verifiedServiceCapability(account,name) {
    if(account.space==='test')return true;
    const capability=account.capabilities?.[name];
    return !!(capability&&typeof capability==='object'&&capability.available===true&&capability.verified===true&&typeof capability.evidenceId==='string'&&capability.evidenceId&&validTime(capability.verifiedAt)&&Date.now()-Date.parse(capability.verifiedAt)<=300000&&Date.parse(capability.verifiedAt)<=Date.now()+30000&&!this.connector?.testOnly);
  },
  _freezeGiftAssets(rule,order) {
    const assets=new Map();
    const visit=(assetId,trail=[])=>{
      if(trail.includes(assetId)||trail.length>8)error('INVALID_BUNDLE','收货后赠品组合循环或层级过深。');
      if(assets.has(assetId))return;
      const asset=this._relation('assets',assetId,order);
      if(asset.images?.length)error('IMAGE_DELIVERY_UNAVAILABLE','赠品含必需图片，当前连接未验证完整图片发送。');
      assets.set(asset.id,clone(asset));
      if(asset.type==='bundle')for(const child of asset.items||[])visit(child.assetId,[...trail,asset.id]);
    };
    for(const gift of rule.gifts||[])visit(gift.assetId);
    return [...assets.values()];
  },
  _recoverServices() {
    // Delivery outbox is authoritative; reconstruct a job only from a confirmed
    // primary snapshot. Never synthesize receipt evidence from a sent message.
    this.store.transaction(()=>{
      for(const delivery of this.store.list('deliveries'))this._afterDeliverySettled(delivery);
    });
  },
  _afterDeliverySettled(delivery) {
    if(delivery.serviceId){
      const job=this.store.get('serviceJobs',delivery.serviceId);
      if(job&&job.status!=='stopped'){const latest=job.deliveryIds?.at(-1);if(latest===delivery.id)this.store.put('serviceJobs',{...job,status:delivery.status,reason:delivery.reason,updatedAt:now()});}
      return;
    }
    const snapshot=delivery.snapshot;
    if(!SENT.has(delivery.status)||!snapshot?.rule?.afterReceipt||(!(snapshot.rule.gifts||[]).length&&!snapshot.rule.thankYou?.trim()))return;
    const jobId=stable('afterReceipt',delivery.space,delivery.accountId,delivery.orderId);
    if(this.store.get('serviceJobs',jobId))return;
    const event=this.store.list('orderEvents').find(e=>e.orderId===delivery.orderId&&e.accountId===delivery.accountId&&e.space===delivery.space&&e.type==='receipt_confirmed');
    this.store.put('serviceJobs',{id:jobId,space:delivery.space,accountId:delivery.accountId,orderId:delivery.orderId,buyerId:delivery.buyerId,productId:snapshot.order.productId,type:'afterReceipt',status:event?'pending':'waiting_receipt',eventId:event?.id,primaryDeliveryId:delivery.id,ruleId:snapshot.rule.id,snapshot:clone(snapshot),deliveryIds:[],createdAt:now(),updatedAt:now()});
  },
  _eventRecord(order,input,source,evidenceId) {
    if(!EVENTS.has(input.type))error('VALIDATION','只支持可信收货或平台交付确认事件。');
    if(input.buyerId!==order.buyerId||input.productId!==order.productId)error('WRONG_BUYER','事件买家或商品与订单不一致。');
    if(input.accountId&&input.accountId!==order.accountId)error('WRONG_ACCOUNT','事件不属于当前账号。');
    if(input.space&&input.space!==order.space)error('WRONG_ACCOUNT','事件空间不一致。');
    if(!validTime(input.occurredAt)||Date.parse(input.occurredAt)>Date.now()+30000||Date.parse(input.occurredAt)<Date.parse(order.paidAt||order.createdAt))error('INVALID_EVENT_TIME','事件时间无效、早于付款或位于未来。');
    text(input.externalId,'事件编号',true,200);text(evidenceId,'可信事件证据编号',true,300);
    const permissions={};for(const name of ['afterReceipt',...Object.keys(ACTIONS)])permissions[name]=input.permissions?.[name]===true;
    return {id:stable('orderEvent',order.space,order.accountId,order.id,input.type),space:order.space,accountId:order.accountId,orderId:order.id,buyerId:order.buyerId,productId:order.productId,type:input.type,externalId:input.externalId,occurredAt:input.occurredAt,source,verifiedAt:now(),evidenceId,permissions,createdAt:now(),updatedAt:now()};
  },
  _acceptOrderEvent(order,input,source,evidenceId,actor) {
    this._check(actor,order,'operate');
    if(order.paymentStatus!=='paid'||order.refundCents>0||['refunding','refunded','closed','cancelled'].includes(order.tradeStatus))error('ORDER_BLOCKED','未付款、退款或关闭订单不能接收执行用事件。');
    const event=this._eventRecord(order,input,source,evidenceId),old=this.store.get('orderEvents',event.id);
    if(old){
      if(old.buyerId!==event.buyerId||old.productId!==event.productId||old.occurredAt!==event.occurredAt)error('EVENT_CONFLICT','同一订单事件事实发生冲突，请核验来源。');
      // A fresh trusted connector may renew verification/permissions, but this
      // never creates jobs or changes a terminal attempt for a duplicate event.
      this.store.put('orderEvents',{...old,source:event.source,verifiedAt:event.verifiedAt,evidenceId:event.evidenceId,permissions:event.permissions,updatedAt:now()});
      return {event:this.store.get('orderEvents',event.id),duplicate:true,jobs:[]};
    }
    this.store.put('orderEvents',event);
    const jobs=[];
    if(event.type==='receipt_confirmed')for(const job of this.store.list('serviceJobs').filter(j=>j.type==='afterReceipt'&&j.orderId===order.id&&j.accountId===order.accountId&&j.space===order.space&&!j.eventId&&j.status==='waiting_receipt')){const next={...job,eventId:event.id,status:'pending',updatedAt:now()};this.store.put('serviceJobs',next);jobs.push(next);}
    for(const profile of this.store.list('interactionProfiles').filter(p=>p.enabled===true&&p.space===order.space&&p.accountId===order.accountId&&(!p.productId||p.productId===order.productId))){
      if(!validTime(profile.enabledAt)||Date.parse(event.occurredAt)<Date.parse(profile.enabledAt))continue;
      for(const [action,config]of Object.entries(profile.actions||{})){
        if(config.enabled!==true||ACTIONS[action]?.event!==event.type)continue;
        const jobId=stable('interaction',order.space,order.accountId,order.id,action);
        if(this.store.get('serviceJobs',jobId))continue;
        const product=this._relation('products',order.productId,order);
        const job={id:jobId,space:order.space,accountId:order.accountId,orderId:order.id,buyerId:order.buyerId,productId:order.productId,type:action,status:'pending',eventId:event.id,profileId:profile.id,snapshot:{order:clone(order),product:clone(product),profile:clone(profile),action:clone(config)},deliveryIds:[],createdAt:now(),updatedAt:now()};
        this.store.put('serviceJobs',job);jobs.push(job);
      }
    }
    this._audit(actor,'order.event',event,'verified');return {event,duplicate:false,jobs};
  },
  testOrderEvent({orderId,type='receipt_confirmed',eventId},actor) {
    const order=this._record('orders',orderId,actor,'operate');
    if(order.space!=='test')error('TEST_ONLY','测试事件只能写入隔离试运行订单，不能制造真实收货事实。');
    const account=this._record('accounts',order.accountId,actor,'operate');if(account.paused)error('PAUSED','账号已暂停。');
    const old=this.store.list('orderEvents').find(e=>e.space===order.space&&e.accountId===order.accountId&&e.orderId===order.id&&e.type===type);
    return this.store.transaction(()=>this._acceptOrderEvent(order,{type,externalId:eventId||`test-event-${order.id}-${type}`,buyerId:order.buyerId,productId:order.productId,occurredAt:old?.occurredAt||now(),permissions:{afterReceipt:true,thankYou:true,receiptReminder:true,reviewRequest:true}},'test',`isolated-test:${eventId||order.id}`,actor));
  },
  async syncOrderEvents({accountId},actor,generation) {
    let account=this._record('accounts',accountId,actor,'operate');
    if(account.space!=='live')return {status:'test_only',synced:0,reason:'试运行请创建明确标记的隔离事件。'};
    if(account.paused||!this._verifiedServiceCapability(account,'readReceiptEvents')||typeof this.connector?.orderEvents!=='function')return {status:'blocked',synced:0,reason:'尚未取得此账号的正式收货事件接口和验证证据；没有推断收货或执行互动。'};
    this._fresh(actor,generation);let response;
    try{response=await this.connector.orderEvents(account);}catch{return {status:'failed',synced:0,reason:'可信事件同步未完成，保留现有事实。'};}
    this._fresh(actor,generation);account=this._record('accounts',accountId,actor,'operate');
    if(account.paused||!this._verifiedServiceCapability(account,'readReceiptEvents'))error('PAUSED','账号已暂停或正式事件能力已失效。');
    if(response?.status!=='ok'||response.verified!==true||typeof response.evidenceId!=='string'||!response.evidenceId||!Array.isArray(response.events))return {status:'blocked',synced:0,reason:'连接器未返回可验证的正式事件证据。'};
    const results=[],errors=[];
    for(const input of response.events.slice(0,1000))try{
      const order=input.orderId?this._record('orders',input.orderId,actor,'operate'):this.store.list('orders').find(o=>o.space==='live'&&o.accountId===account.id&&typeof input.orderExternalId==='string'&&o.externalId===input.orderExternalId);
      if(!order||order.space!=='live'||order.accountId!==account.id)error('WRONG_ACCOUNT','事件未匹配当前账号订单。');
      if(order.source!=='platform'||!validTime(order.verifiedAt)||Date.now()-Date.parse(order.verifiedAt)>300000||Date.parse(order.verifiedAt)>Date.now()+30000)error('UNVERIFIED_ORDER','请先从正式接口核验订单付款和售后状态。');
      results.push(this.store.transaction(()=>this._acceptOrderEvent(order,input,'platform',response.evidenceId,actor)));
    }catch(e){errors.push({code:e.code||'INVALID_EVENT',message:e.message});}
    return {status:errors.length?'partial':'ok',synced:results.length,results,errors};
  },
  _serviceReasons(job,actor) {
    const order=this._record('orders',job.orderId,actor,'operate'),account=this._record('accounts',job.accountId,actor,'operate'),reasons=[];
    if(order.space!==job.space||order.accountId!==job.accountId||order.buyerId!==job.buyerId||order.productId!==job.productId||job.snapshot?.order?.buyerId!==job.buyerId||job.snapshot?.order?.productId!==job.productId||['externalId','variantId','amountCents','quantity'].some(k=>order[k]!==job.snapshot?.order?.[k]))reasons.push('服务快照与当前订单接收方、商品或账号范围不一致。');
    if(account.paused)reasons.push('账号已暂停。');
    if(order.paymentStatus!=='paid'||order.refundCents>0||['refunding','refunded','closed','cancelled'].includes(order.tradeStatus))reasons.push('订单未付款、退款或已关闭，禁止后续服务。');
    const event=this.store.get('orderEvents',job.eventId||'');
    const expectedEvent=job.type==='afterReceipt'?'receipt_confirmed':ACTIONS[job.type]?.event;
    if(!event||event.type!==expectedEvent||event.space!==job.space||event.accountId!==job.accountId||event.orderId!==job.orderId||event.buyerId!==job.buyerId||event.productId!==job.productId||!validTime(event.occurredAt)||Date.parse(event.occurredAt)>Date.now()+30000||Date.parse(event.occurredAt)<Date.parse(order.paidAt||order.createdAt)||!['test','platform'].includes(event.source))reasons.push('缺少身份一致的可信收货或平台交付事件。');
    if(event?.permissions?.[job.type]!==true)reasons.push('事件没有允许此项服务的收件人和平台范围证明。');
    const conversations=this.store.list('conversations').filter(c=>c.space===job.space&&c.accountId===job.accountId&&c.buyerId===job.buyerId);
    const customer=this.store.list('customers').find(c=>c.space===job.space&&c.accountId===job.accountId&&c.buyerId===job.buyerId);
    if(customer?.blocked||conversations.some(c=>c.blocked||c.manual))reasons.push('此买家已屏蔽自动接待或会话转人工，停止后续自动服务。');
    if(job.type==='receiptReminder'&&this.store.list('orderEvents').some(e=>e.space===job.space&&e.accountId===job.accountId&&e.orderId===job.orderId&&e.type==='receipt_confirmed'))reasons.push('订单已有收货事件，不再发送收货提醒。');
    if(job.type==='afterReceipt'){
      const primary=this.store.get('deliveries',job.primaryDeliveryId||''),rule=this.store.get('rules',job.ruleId||'');
      if(!primary||!SENT.has(primary.status)||primary.orderId!==job.orderId||primary.buyerId!==job.buyerId||primary.accountId!==job.accountId||primary.space!==job.space)reasons.push('主资料尚未证实发送，不能开始收货后赠送。');
      if(event&&primary&&Date.parse(event.occurredAt)<Date.parse(primary.submittedAt||primary.createdAt))reasons.push('收货事件早于此份主资料交付，不能证明对应资料已收货。');
      if(rule?.enabled!==true||rule.afterReceipt!==true||rule.space!==job.space||rule.accountId!==job.accountId)reasons.push('原收货后规则已停用或取消。');
    }else{
      const profile=this.store.get('interactionProfiles',job.profileId||'');
      if(!ACTIONS[job.type]||profile?.enabled!==true||profile.actions?.[job.type]?.enabled!==true||profile.space!==job.space||profile.accountId!==job.accountId||(profile.productId&&profile.productId!==job.productId))reasons.push('此项互动未启用或档案范围已改变。');
      if(event&&Date.now()-Date.parse(event.occurredAt)<(job.snapshot?.action?.delaySeconds||0)*1000)reasons.push('尚未达到此项互动的等待时间。');
    }
    if(job.space==='live'){
      if(order.source!=='platform'||!validTime(order.verifiedAt)||Date.now()-Date.parse(order.verifiedAt)>300000||Date.parse(order.verifiedAt)>Date.now()+30000)reasons.push('真实订单付款与售后状态需要重新核验。');
      if(event?.source!=='platform'||!validTime(event?.verifiedAt)||Date.now()-Date.parse(event.verifiedAt)>300000||Date.parse(event.verifiedAt)>Date.now()+30000||!event?.evidenceId)reasons.push('缺少当前有效的正式事件证据。');
      const capability=job.type==='afterReceipt'?'sendPostReceiptService':ACTIONS[job.type]?.capability;
      if(!this._verifiedServiceCapability(account,'readReceiptEvents')||!this._verifiedServiceCapability(account,capability)||!this._capability(account,'sendMessages')||typeof this.connector?.sendMessage!=='function')reasons.push('此账号尚未验证该项正式互动能力，保存设置或普通登录不能执行。');
    }
    return {reasons,order,account,event};
  },
  _serviceContent(job,order) {
    if(job.type!=='afterReceipt')return {text:job.type==='reviewRequest'?REVIEW_TEXT:job.snapshot.action.text,items:[],inventoryIds:[]};
    const result={text:'',items:[],inventoryIds:[]},snapshot=job.snapshot,assets=new Map((snapshot.postReceiptAssets||[]).map(a=>[a.id,a]));
    const lookup=assetId=>{const asset=assets.get(assetId);if(!asset||asset.space!==order.space||asset.accountId!==order.accountId)error('SNAPSHOT_INVALID','赠品版本快照缺失或范围不一致。');return asset;};
    for(const gift of snapshot.rule.gifts||[]){const part=this._assetContent(lookup(gift.assetId),gift.quantity||1,order,new Set(result.inventoryIds),[],lookup);result.text+=(result.text?'\n\n':'')+'赠送资料\n'+part.text;result.items.push(...part.items);result.inventoryIds.push(...part.inventoryIds);}
    if(snapshot.rule.thankYou?.trim())result.text+=(result.text?'\n\n':'')+snapshot.rule.thankYou;
    text(result.text,'收货后服务正文',true,100000);return result;
  },
  _checkServiceInventory(content,job,actor) {
    for(const inventoryId of content.inventoryIds){const entry=this._record('inventory',inventoryId,actor,'operate');if(entry.space!==job.space||entry.accountId!==job.accountId||entry.status!=='available'||(entry.expiresAt&&(!validTime(entry.expiresAt)||Date.parse(entry.expiresAt)<=Date.now())))error('OUT_OF_STOCK','快照中的唯一赠品已占用或过期，不能用其他内容静默替换。');const snap=content.items.flatMap(item=>item.entries||[]).find(i=>i.id===entry.id);if(!snap||snap.content!==entry.content||snap.costCents!==entry.costCents||snap.expiresAt!==entry.expiresAt)error('SNAPSHOT_CHANGED','唯一赠品与待重试的完整快照不一致。');}
  },
  servicePreview({id:jobId,retry=false},actor) {
    const job=this._record('serviceJobs',jobId,actor,'operate'),{reasons,order,event}=this._serviceReasons(job,actor);
    if(job.status==='stopped')reasons.push('此服务已由经营成员停止。');
    const attempts=(job.deliveryIds||[]).map(deliveryId=>this.store.get('deliveries',deliveryId)),last=attempts.at(-1);
    const retryable=!!last&&RETRYABLE.has(last.status)&&!attempts.some(d=>!d||['sending','unknown','accepted','sent','verified_sent'].includes(d.status));
    if(retry&&!retryable)reasons.push('只有已明确未发送的服务才可人工重试；未知或已提交须先核验。');
    if(!retry&&attempts.length)reasons.push('此服务已有发送尝试；未知须先核验，明确未发送须人工选择重试。');
    let content={text:'',items:[],inventoryIds:[]};
    try{content=last?{text:last.text,items:clone(last.items),inventoryIds:clone(last.inventoryIds)}:this._serviceContent(job,order);if(retry)this._checkServiceInventory(content,job,actor);}catch(e){reasons.push(e.message);}
    return {eligible:!reasons.length,canRetry:retryable&&job.status!=='stopped',retry:!!retry,reasons,id:job.id,jobId:job.id,orderId:job.orderId,accountId:job.accountId,space:job.space,buyerId:job.buyerId,type:job.type,status:job.status,event:event?clone(event):null,snapshot:clone(job.snapshot),...content};
  },
  _serviceSendGuard(delivery,actor) {
    const job=this._record('serviceJobs',delivery.serviceId,actor,'operate'),{reasons}=this._serviceReasons(job,actor);
    if(job.status==='stopped'||job.deliveryIds?.at(-1)!==delivery.id)reasons.push('服务已停止或发送记录不再对应。');
    if(reasons.length)error('PAUSED',reasons.join(' '));
  },
  async executeService({id:jobId,reason},actor,generation,retry=false) {
    let delivery;
    this.store.transaction(()=>{
      this._fresh(actor,generation);const job=this._record('serviceJobs',jobId,actor,'operate'),{reasons,order}=this._serviceReasons(job,actor);
      if(job.status==='stopped')reasons.push('此服务已停止，不能再次启动。');
      const previous=(job.deliveryIds||[]).map(deliveryId=>this.store.get('deliveries',deliveryId));
      if(retry){text(reason,'人工重试依据',true,2000);if(!previous.length||!RETRYABLE.has(previous.at(-1)?.status))reasons.push('只有已明确未发送的服务才可人工重试；未知或已提交须先核验。');}
      else if(previous.length)reasons.push('此服务已有持久发送尝试，不能重复执行。');
      if(previous.some(d=>!d||['sending','unknown','accepted','sent','verified_sent'].includes(d.status)))reasons.push('已有发送、送达或未知事实，禁止重复发送。');
      if(reasons.length)error('SERVICE_BLOCKED',reasons.join(' '));
      let content;
      if(retry){const last=previous.at(-1);content={text:last.text,items:clone(last.items),inventoryIds:clone(last.inventoryIds)};}
      else content=this._serviceContent(job,order);
      this._checkServiceInventory(content,job,actor);
      const deliveryId=randomUUID();delivery={id:deliveryId,space:job.space,accountId:job.accountId,orderId:job.orderId,buyerId:job.buyerId,externalId:order.externalId,purpose:job.type==='afterReceipt'?'after_receipt':'interaction',serviceId:job.id,snapshot:clone(job.snapshot),status:'sending',attempt:previous.length+1,...content,reason:retry?reason:undefined,resendOf:retry?previous.at(-1).id:undefined,createdAt:now(),updatedAt:now(),submittedAt:now()};
      for(const inventoryId of content.inventoryIds)this.store.put('inventory',{...this.store.get('inventory',inventoryId),status:'reserved',orderId:order.id,deliveryId,updatedAt:now()});
      this.store.put('deliveries',delivery);this.store.put('serviceJobs',{...job,status:'sending',deliveryIds:[...(job.deliveryIds||[]),deliveryId],updatedAt:now()});this._audit(actor,retry?'service.retry':'service.execute',job,'submitted');
    });
    return this._sendPreparedDelivery(delivery,actor,generation);
  },
  stopService({id:jobId,reason},actor) {
    text(reason,'停止依据',true,2000);const job=this._record('serviceJobs',jobId,actor,'operate');
    if(['sending','unknown','accepted','sent','verified_sent'].includes(job.status))error('SERVICE_IN_FLIGHT','已有发送或待核验事实不能通过停止抹除，请在交付记录核验。');
    const result={...job,status:'stopped',reason,stoppedBy:actor.id,stoppedAt:now(),updatedAt:now()};this.store.put('serviceJobs',result);this._audit(actor,'service.stop',result);return result;
  },
  _validateRestoredServiceRecord(kind,record) {
    const order=this._relation('orders',record.orderId,record);
    if(order.buyerId!==record.buyerId||order.productId!==record.productId)error('VALIDATION','恢复的收货后记录买家或商品不一致。');
    if(kind==='orderEvents'){
      if(!EVENTS.has(record.type)||!validTime(record.occurredAt))error('VALIDATION','恢复的收货事件格式无效。');
      record.source='restored';delete record.verifiedAt;delete record.evidenceId;record.permissions={};
    }else{
      if(!['afterReceipt',...Object.keys(ACTIONS)].includes(record.type)||!record.snapshot||record.snapshot.order?.buyerId!==record.buyerId||record.snapshot.order?.accountId!==record.accountId||record.snapshot.order?.space!==record.space||!Array.isArray(record.deliveryIds))error('VALIDATION','恢复的服务快照格式或范围无效。');
      record.status='stopped';record.reason='恢复的历史服务已停止；不能用备份制造新的收货事件或重放互动。';
    }
    return record;
  },
};

module.exports={methods,REVIEW_TEXT,ACTIONS};
