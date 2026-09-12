'use strict';

const { randomUUID, createHash } = require('node:crypto');
const { parseCsv, exportCsv, unprotect } = require('./csv.cjs');
const { needsLicense } = require('../licensing/operations.cjs');

const KINDS = ['accounts','products','assets','inventory','orders','deliveries','rules','conversations','messages','snippets','replyRules','members','customers','afterSales','plans','batches','notifications','integrations','settings','audit','orderEvents','serviceJobs','interactionProfiles'];
const BASE = ['id','space','accountId','createdAt','updatedAt'];
const FIELDS = {
  accounts: ['name','mode','status','paused','capabilities','note','avatar','externalId','testOutcome','lastSyncedAt','connectionReason','platformUserId','nickname','loginStatus','connectionStatus','sessionVersion','identityVerifiedAt','identityEvidenceId','archived','archivedAt','hosting','authorizationVersion'],
  products: ['title','description','sku','priceCents','stock','status','variants','category','images','sourceProductId','materialRights','platformStatus','platformReceiptId','lastSyncedAt','externalId'],
  assets: ['name','type','link','code','instructions','version','category','threshold','items','images','note'],
  inventory: ['assetId','content','costCents','expiresAt','status','batchId','orderId','deliveryId','fingerprint','adjustments'],
  orders: ['externalId','buyerId','buyerName','productId','productExternalId','variantId','amountCents','refundCents','costCents','paymentStatus','tradeStatus','source','verifiedAt','paidAt','quantity','lastSyncedAt','note','logistics','evidenceId'],
  deliveries: ['orderId','buyerId','status','attempt','text','items','inventoryIds','receiptId','reason','resendOf','verifiedBy','verification','externalId','sentAt','submittedAt','purpose','serviceId','snapshot'],
  rules: ['name','productId','variantId','assetId','quantity','enabled','delaySeconds','priority','gifts','thankYou','afterReceipt'],
  conversations: ['buyerId','buyerName','productId','orderId','manual','unread','pinned','blocked','assigneeId','lastMessage','lastMessageAt','generation','note','externalId'],
  messages: ['conversationId','buyerId','text','direction','status','receiptId','reason','origin','lastSyncedAt','externalId','receivedAt'],
  snippets: ['name','group','text','images'],
  replyRules: ['name','productId','keywords','text','enabled','priority','maxReplies','excludeProductIds','fallback','exact'],
  members: ['name','role','accountIds','enabled'],
  customers: ['buyerId','name','note','pinned','blocked','assigneeId','tags'],
  afterSales: ['orderId','type','status','reason','note','dueAt','requestedCents','platformStatus','receiptId'],
  plans: ['name','productIds','action','scheduledAt','frequencyMinutes','enabled','paused','status','results'],
  batches: ['productIds','changes','status','paused','results','previewId'],
  notifications: ['type','title','body','read','channel','status','eventId'],
  integrations: ['name','type','endpoint','model','enabled','status','capabilities','reason','apiKey','credentialRef','scope','costNotice'],
  settings: ['theme','background','lockMinutes','notificationChannels','aiEnabled','aiEndpoint','aiModel','minPriceCents','maxNegotiations','knowledge','autoEnabled','autoEnabledAt','defaultReply','excludedProductIds','apiKey','updateChannel','announcement','downloadPage','interactions','supplier','logistics','notificationEndpoint'],
  audit: ['actorId','action','targetId','result','code','summary'],
  orderEvents: ['orderId','buyerId','productId','type','externalId','occurredAt','source','verifiedAt','evidenceId','permissions'],
  serviceJobs: ['orderId','buyerId','productId','type','status','eventId','primaryDeliveryId','profileId','ruleId','snapshot','deliveryIds','reason','stoppedBy','stoppedAt'],
  interactionProfiles: ['name','productId','enabled','enabledAt','actions'],
};
const READONLY = new Set(['deliveries','messages','batches','audit','inventory','orderEvents','serviceJobs']);
const SUPPORT_SAVE = new Set(['conversations','customers','afterSales','snippets','notifications']);
const PROTECTED = {
  accounts:['status','capabilities','externalId','lastSyncedAt','connectionReason','platformUserId','nickname','loginStatus','connectionStatus','sessionVersion','identityVerifiedAt','identityEvidenceId','archived','archivedAt','hosting','authorizationVersion'], products:['platformStatus','platformReceiptId','lastSyncedAt'],
  orders:['source','verifiedAt','paidAt','lastSyncedAt','evidenceId','productExternalId'], afterSales:['platformStatus','receiptId'],
  integrations:['status','capabilities','reason','credentialRef'], plans:['status','results'],
};
const now = () => new Date().toISOString();
const id = () => randomUUID();
const hash = value => createHash('sha256').update(typeof value === 'string' ? value : JSON.stringify(value)).digest('hex');
const copy = value => structuredClone(value);
function fail(code, message) { const error = new Error(message); error.code = code; throw error; }
function str(value, name, required = false, limit = 100000) {
  if (value == null && !required) return;
  if (typeof value !== 'string' || value.length > limit || (required && !value.trim())) fail('VALIDATION', `${name}应是${required ? '非空' : ''}文本。`);
}
function int(value, name, min = 0, max = Number.MAX_SAFE_INTEGER) {
  if (value != null && (!Number.isSafeInteger(value) || value < min || value > max)) fail('VALIDATION', `${name}必须是 ${min} 到 ${max} 的整数。`);
}
function date(value, name) { if (value != null && value !== '' && (typeof value !== 'string' || !Number.isFinite(Date.parse(value)))) fail('VALIDATION', `${name}日期无效。`); }
function sanitizeText(value) { return String(value || '').replace(/https?:\/\/\S+/gi, '[链接已隐藏]').replace(/(密码|密钥|提取码|token|cookie|authorization)\s*[:：=]?\s*\S+/gi, '$1 [已隐藏]').slice(0, 300); }

class Service {
  constructor(store, { connector, assertLicense = () => true } = {}) {
    this.store = store;
    this.connector = connector || null;
    this.assertLicense = assertLicense;
    this.generation = 0;
    this.previews = new Map();
    this.backgroundContexts = new WeakMap();
    this.backgroundEpoch = 0;
    // Any call that crossed process exit may have reached the receiver; never infer rejection.
    for (const kind of ['deliveries','messages']) for (const record of store.list(kind)) {
      if (record.status === 'sending') store.put(kind, { ...record, status:'unknown', reason:'上次退出前已提交；请核验是否收到，不能自动重发。', updatedAt:now() });
    }
    for (const batch of store.list('batches')) if (batch.status === 'running') {
      batch.results = (batch.results || []).map(item => item.status === 'sending' ? { ...item,status:'unknown',reason:'程序退出时结果未明确，需人工核验。' } : item);
      store.put('batches',{...batch,status:'paused',paused:true,updatedAt:now()});
    }
    this._recoverServices();
  }
  invalidate() { this.generation++; }
  pause() { this.invalidate(); }
  stopBackground() { this.backgroundEpoch++; }
  authorizeBackground(accountId) {
    this.assertLicense();
    const account=this.store.get('accounts',accountId), grant=this.store.get('_hosting',accountId);
    if(!account||!grant?.enabled||account.paused||account.archived)fail('BACKGROUND_REVOKED','此账号尚未授权持续托管。');
    const actor=Object.freeze({id:grant.actorId,role:'operator',accountIds:Object.freeze([accountId])});
    this.backgroundContexts.set(actor,{accountId,version:grant.version,sessionVersion:account.sessionVersion,epoch:this.backgroundEpoch,memberFingerprint:grant.memberFingerprint});
    this._actor(actor);return actor;
  }
  _background(actor, operation) {
    const context=this.backgroundContexts.get(actor);if(!context)return null;
    this.assertLicense();
    const grant=this.store.get('_hosting',context.accountId),account=this.store.get('accounts',context.accountId),member=this.store.get('members',actor.id);
    const memberFingerprint=member?hash({role:member.role,accountIds:member.accountIds||[],enabled:member.enabled!==false}):null;
    if(context.epoch!==this.backgroundEpoch||!grant?.enabled||grant.version!==context.version||!account||account.paused||account.archived||account.sessionVersion!==context.sessionVersion||!member||member.enabled===false||!['owner','operator'].includes(member.role)||(member.role!=='owner'&&!member.accountIds?.includes(account.id))||memberFingerprint!==context.memberFingerprint)fail('BACKGROUND_REVOKED','成员、账号、会话或托管授权已变更，未提交任务已撤销。');
    if(operation&&!grant.actions?.includes(operation))fail('BACKGROUND_SCOPE','此操作不在该账号的后台授权范围。');
    return context;
  }
  _actor(actor) {
    if (!actor || typeof actor.id !== 'string') fail('UNAUTHENTICATED','请先登录有效的本机成员。');
    if(this._background(actor))return actor;
    const member = this.store.get('members', actor.id);
    if (member) {
      if (member.enabled === false) fail('FORBIDDEN','此成员权限已撤回。');
      return { id:member.id, role:member.role, accountIds:member.accountIds || [] };
    }
    if (actor.role === 'owner' && this.store.list('members').length === 0) return {id:actor.id,role:'owner',accountIds:[]};
    fail('FORBIDDEN','成员不存在或已被移除。');
  }
  _check(actor, record, operation = 'read') {
    actor = this._actor(actor);
    if (actor.role === 'owner') return actor;
    if (!record || !record.accountId || !actor.accountIds.includes(record.accountId)) fail('FORBIDDEN','没有这个账号的数据权限。');
    if (operation !== 'read' && actor.role === 'viewer') fail('FORBIDDEN','只读成员不能执行此操作。');
    if (['sensitive','operate'].includes(operation) && actor.role !== 'operator') fail('FORBIDDEN','此操作需要经营成员或所有者权限。');
    if (operation === 'owner') fail('FORBIDDEN','此操作仅限所有者。');
    return actor;
  }
  _fresh(actor, generation) { this.assertLicense();if (!this.backgroundContexts.has(actor)&&generation !== this.generation) fail('LOCKED','当前成员或托管授权已变更，此次尚未执行的操作已取消。'); return this._actor(actor); }
  _record(kind, recordId, actor, operation = 'read') {
    const record = this.store.get(kind,recordId);
    if (!record) fail('NOT_FOUND','所选记录不存在或已删除。');
    this._check(actor,kind === 'accounts' ? {...record,accountId:record.id} : record,operation);
    return record;
  }
  _audit(actor, action, record, result = 'ok', code) {
    this.store.put('audit',{id:id(),space:record?.space || 'live',accountId:record?.accountId || (action.startsWith('account.') ? record?.id : undefined),actorId:actor.id,action,targetId:record?.id,result,code,createdAt:now(),updatedAt:now()});
  }
  _notice(record,type,title,body) {
    const eventId = `${type}:${record.id}`;
    if (this.store.list('notifications').some(n=>n.eventId===eventId && !n.read)) return;
    this.store.put('notifications',{id:id(),space:record.space,accountId:record.accountId || record.id,type,title,body:sanitizeText(body),read:false,channel:'local',status:'available',eventId,createdAt:now(),updatedAt:now()});
  }
  _explain(actor,action,record,reasons) {
    const summary=reasons.map(sanitizeText).join(' ').slice(0,500);const key=hash(`${action}:${record.id}`);if(this.store.get('_explanations',key)?.summary===summary)return;
    this.store.put('_explanations',{id:key,summary,updatedAt:now()});this.store.put('audit',{id:id(),space:record.space,accountId:record.accountId,actorId:actor.id,action,targetId:record.id,result:'skipped',summary,createdAt:now(),updatedAt:now()});
  }
  _scope(records, actor, space, accountId) {
    if (!['live','test'].includes(space)) fail('VALIDATION','请选择真实经营或试运行空间。');
    if (accountId && actor.role !== 'owner' && !actor.accountIds.includes(accountId)) fail('FORBIDDEN','没有这个账号的数据权限。');
    return records.filter(r => r.space === space && (!accountId || r.accountId === accountId || r.id === accountId) && (actor.role === 'owner' || actor.accountIds.includes(r.accountId || r.id)));
  }
  _public(kind, record, actor) {
    const r = copy(record);
    delete r.apiKey; delete r.credentialRef;
    if (['support','viewer'].includes(actor.role)) {
      for (const key of ['link','code','instructions','items','content','text','knowledge','images','costCents','fingerprint','inventoryIds','apiKey','endpoint','snapshot','actions']) delete r[key];
      if (kind === 'messages' && actor.role === 'support') r.text = r.direction === 'outgoing' && r.origin === 'delivery' ? '[交付资料内容受限]' : record.text;
      if (kind === 'snippets' && actor.role === 'support') r.text = record.text;
      if (kind === 'conversations') delete r.lastMessage;
      if (kind === 'settings') return {id:r.id,space:r.space,accountId:r.accountId};
    }
    return r;
  }
  async run(action, payload = {}, actor) {
    const current = this._actor(actor); const generation = this.generation;
    if(needsLicense(action,payload))this.assertLicense();
    if(this.backgroundContexts.has(current)&&!['automation.tick','account.sync','order.events.sync'].includes(action))fail('BACKGROUND_SCOPE','后台授权不能调用此业务入口。');
    if (!payload || typeof payload !== 'object' || Array.isArray(payload)) fail('VALIDATION','请求内容格式无效。');
    switch (action) {
      case 'workspace.snapshot': return this.snapshot(payload,current);
      case 'entity.save': return this.save(payload,current);
      case 'entity.delete': return this.remove(payload,current);
      case 'test.seed': return this.seed(current);
      case 'delivery.preview': case 'rules.preview': return this.deliveryPreview(payload.orderId,current);
      case 'delivery.execute': return this.deliver(payload,current,generation,false);
      case 'delivery.resend': return this.deliver(payload,current,generation,true);
      case 'delivery.verify': return this.verifyDelivery(payload,current);
      case 'inventory.import': return this.importInventory(payload,current);
      case 'inventory.adjust': return this.adjustInventory(payload,current);
      case 'account.pause': return this.pauseAccount(payload,current);
      case 'account.sync': return this.syncAccount(payload,current,generation);
      case 'order.refresh': return this.refreshOrders(payload,current,generation);
      case 'batch.preview': return this.previewBatch(payload,current);
      case 'batch.execute': return this.executeBatch(payload,current,generation);
      case 'batch.pause': return this.pauseBatch(payload,current);
      case 'message.preview': return this.messagePreview(payload,current);
      case 'message.send': return this.sendMessage(payload,current,generation);
      case 'conversation.takeover': return this.takeover(payload,current);
      case 'reply.preview': return this.replyPreview(payload,current);
      case 'ai.preview': return this.aiPreview(payload,current,generation);
      case 'statistics.get': return this.statistics(payload,current);
      case 'backup.create': return this.createBackup(current);
      case 'backup.preview': return this.previewBackup(payload,current);
      case 'backup.restore': return this.restoreBackup(payload,current);
      case 'data.previewImport': return this.previewImport(payload,current);
      case 'data.import': return this.applyImport(payload,current);
      case 'data.export': return this.exportData(payload,current);
      case 'diagnostics.export': return this.diagnostics(current);
      case 'integration.test': return this.testIntegration(payload,current,generation);
      case 'notification.test': return this.testNotification(payload,current);
      case 'notification.read': return this.markNotification(payload,current);
      case 'plan.run': return this.runPlan(payload,current,generation);
      case 'automation.tick': return this.automationTick(payload,current,generation);
      case 'order.event.test': return this.testOrderEvent(payload,current);
      case 'order.events.sync': return this.syncOrderEvents(payload,current,generation);
      case 'service.preview': case 'interaction.preview': return this.servicePreview(payload,current);
      case 'service.execute': case 'interaction.execute': return this.executeService(payload,current,generation,false);
      case 'service.retry': return this.executeService(payload,current,generation,true);
      case 'service.stop': return this.stopService(payload,current);
      case 'afterSales.execute': case 'logistics.execute': case 'supplier.execute': case 'downloadPage.create': return this.externalExtension(action,payload,current,generation);
      default: fail('UNKNOWN_ACTION','此操作尚未提供。');
    }
  }
  snapshot({space = 'live',accountId},actor) {
    const output = {};
    for (const kind of KINDS) output[kind] = (kind === 'members' ? (actor.role === 'owner' ? this.store.list(kind) : []) : this._scope(this.store.list(kind),actor,space,accountId)).map(r=>this._public(kind,r,actor));
    output.metrics = this.statistics({space,accountId},actor);
    return output;
  }
  _validate(kind, candidate, old, trusted = false) {
    if (!FIELDS[kind]) fail('VALIDATION','不支持的资料类型。');
    if (!candidate || typeof candidate !== 'object' || Array.isArray(candidate)) fail('VALIDATION','记录格式无效。');
    const allowed = new Set([...BASE,...FIELDS[kind]]);
    for (const key of Object.keys(candidate)) if (!allowed.has(key)) fail('VALIDATION',`不允许字段：${key}`);
    const r = { ...(old || {}), ...copy(candidate) };
    if (kind === 'settings') delete r.lockMinutes; // Legacy imports may contain this removed preference.
    r.id ||= id(); str(r.id,'记录编号',true,160);
    r.space ||= 'live'; if (!['test','live'].includes(r.space)) fail('VALIDATION','空间无效。');
    if (old && (r.space !== old.space || r.accountId !== old.accountId)) fail('VALIDATION','记录不能跨账号或跨空间移动。');
    r.createdAt = old?.createdAt || (trusted&&candidate.createdAt?candidate.createdAt:now()); r.updatedAt = now();date(r.createdAt,'创建时间');
    if (kind === 'accounts') {
      r.accountId = r.id; r.mode = r.space === 'test' ? 'test' : 'live'; str(r.name,'账号名称',true,100);
      if (!trusted) { r.status=old?.status || (r.space==='test'?'test_ready':'not_connected'); r.capabilities=old?.capabilities || {}; delete r.externalId; if(old?.externalId)r.externalId=old.externalId; }
      if (r.testOutcome && !['sent','accepted','rejected','unknown','rate_limited','blocked'].includes(r.testOutcome)) fail('VALIDATION','测试结果类型无效。');
    } else if (!['members','settings','integrations'].includes(kind) || r.accountId) {
      str(r.accountId,'所属账号',true,160);
      const account = this.store.get('accounts',r.accountId);
      if (!account || account.space !== r.space) fail('VALIDATION','所属账号不存在或空间不一致。');
    }
    for (const key of Object.keys(r)) {
      if (key.endsWith('Cents')) int(r[key],key);
      if (['quantity','stock','threshold','delaySeconds','priority','maxReplies','frequencyMinutes','lockMinutes','maxNegotiations','unread'].includes(key)) int(r[key],key,0);
      if (['expiresAt','dueAt','scheduledAt'].includes(key)) date(r[key],key);
      if (['enabled','paused','manual','blocked','pinned','read','afterReceipt','fallback','exact','autoEnabled','aiEnabled'].includes(key)&&r[key]!=null&&typeof r[key]!=='boolean') fail('VALIDATION',`${key}必须是开关值。`);
      if (typeof r[key] === 'string' && r[key].length > 200000) fail('VALIDATION','字段内容过长。');
    }
    if (kind === 'assets') {
      str(r.name,'资料名称',true,200); if (!['fixed','unique','bundle'].includes(r.type)) fail('VALIDATION','请选择固定资料、唯一库存或组合资料。');
      if (r.type === 'fixed') { str(r.link,'网盘链接',true); try { const url=new URL(r.link); if(!['https:','http:'].includes(url.protocol))throw 0; } catch {fail('VALIDATION','网盘链接必须是完整的 http 或 https 地址。');} str(r.code,'提取码'); str(r.instructions,'使用说明'); }
      if (r.type === 'bundle') { if (!Array.isArray(r.items) || !r.items.length || r.items.length>50) fail('VALIDATION','组合至少需要一份资料。'); for (const item of r.items) { str(item.assetId,'组合资料编号',true); int(item.quantity,'份数',1,100); this._relation('assets',item.assetId,r); if (item.assetId === r.id) fail('VALIDATION','组合不能包含自己。'); } }
      r.version = old ? (hash({...r,version:0,createdAt:'',updatedAt:''})===hash({...old,version:0,createdAt:'',updatedAt:''}) ? old.version : Number(old.version||1)+1) : (r.version || 1);
    }
    if (kind === 'products') {
      str(r.title,'商品标题',true,300); str(r.description,'商品说明'); str(r.sku,'商家编码'); int(r.priceCents,'售价',0); int(r.stock,'库存',0);
      r.variants ||= []; if (!Array.isArray(r.variants) || r.variants.length > 100) fail('VALIDATION','规格列表无效。');
      const ids=new Set(),names=new Set(); for(const v of r.variants){ if(Object.keys(v).some(k=>!['id','name','priceCents','assetId','quantity'].includes(k)))fail('VALIDATION','规格包含不支持字段。'); str(v.id,'规格编号',true);str(v.name,'规格名称',true);if(ids.has(v.id)||names.has(v.name))fail('VALIDATION','规格编号或名称重复。');ids.add(v.id);names.add(v.name);int(v.priceCents,'规格售价');int(v.quantity,'交付份数',1,100);if(v.assetId)this._relation('assets',v.assetId,r); }
      r.status ||= 'draft';
    }
    if (kind === 'orders') {
      str(r.externalId,'平台订单号',true,200); str(r.buyerId,'买家编号',true,200); str(r.buyerName,'买家称呼');
      if(r.productId)this._relation('products',r.productId,r);
      if(!trusted){ r.source=old?.source || (r.space==='test'?'test':'local');r.verifiedAt=old?.verifiedAt; r.paidAt=old?.paidAt; if(old?.source==='platform'||old?.verifiedAt){ for(const key of ['externalId','buyerId','buyerName','productId','variantId','amountCents','refundCents','paymentStatus','tradeStatus']) if(candidate[key]!==undefined && candidate[key]!==old[key]) fail('PROTECTED','已验证订单事实必须从可信连接器刷新。'); } }
      r.refundCents ??=0; r.costCents ??=0; r.amountCents ??=0; r.paymentStatus||='unpaid';r.tradeStatus||='open';
      if(!['unpaid','paid','refunded','partially_refunded'].includes(r.paymentStatus)||!['open','paid','shipped','completed','refunding','refunded','closed','cancelled'].includes(r.tradeStatus))fail('VALIDATION','付款或交易状态无效。');
      if(r.refundCents>r.amountCents)fail('VALIDATION','退款金额不能超过订单金额。');date(r.verifiedAt,'核验时间');date(r.paidAt,'付款时间');
      if(typeof r.externalId!=='string')fail('VALIDATION','订单编号必须保留为文本，不能使用数值。');
      const dup=this.store.list('orders').find(o=>o.id!==r.id&&o.accountId===r.accountId&&o.space===r.space&&o.externalId===r.externalId); if(dup)fail('DUPLICATE','此账号已有相同平台订单号。');
    }
    if (kind === 'rules') {
      this._relation('products',r.productId,r);this._relation('assets',r.assetId,r);int(r.quantity,'交付份数',1,100);r.quantity??=1;r.priority??=0;r.delaySeconds??=0;
      const product=this.store.get('products',r.productId);if(r.variantId&&!product.variants?.some(v=>v.id===r.variantId))fail('VALIDATION','所选规格不属于此商品。');
      if(r.enabled&&product.variants?.some(v=>!v.assetId)&&!r.variantId)fail('VALIDATION','存在未绑定资料的规格，不能启用通用规则。');
      if(r.gifts!=null){if(!Array.isArray(r.gifts)||r.gifts.length>50)fail('VALIDATION','赠品列表无效。');for(const gift of r.gifts){if(!gift||Object.keys(gift).some(k=>!['assetId','quantity'].includes(k)))fail('VALIDATION','赠品只支持资料和份数，不能绑定评价条件。');this._relation('assets',gift.assetId,r);int(gift.quantity,'赠品份数',1,100);}}
      str(r.thankYou,'致谢文案',false,10000);
    }
    if(kind==='interactionProfiles')this._validateInteractionProfile(r,old);
    if(kind==='members'){str(r.name,'成员名称',true,100);if(!['owner','operator','support','viewer'].includes(r.role))fail('VALIDATION','成员角色无效。');if(!Array.isArray(r.accountIds))r.accountIds=[];for(const accountId of r.accountIds)if(!this.store.get('accounts',accountId))fail('VALIDATION','成员账号范围无效。');r.enabled??=true;}
    if(kind==='conversations'){
      str(r.buyerId,'买家编号',true);if(old&&old.buyerId!==r.buyerId&&this.store.list('messages').some(m=>m.conversationId===r.id))fail('PROTECTED','已有消息的会话不能修改买家身份，请创建独立会话。');
      if(r.orderId){const order=this._relation('orders',r.orderId,r);if(order.buyerId!==r.buyerId)fail('WRONG_BUYER','关联订单不属于当前会话买家。');if(r.productId&&r.productId!==order.productId)fail('WRONG_PRODUCT','会话商品与关联订单不一致。');r.productId ||= order.productId;}
      if(r.productId)this._relation('products',r.productId,r);
      const changed=old&&['buyerId','orderId','productId','manual','blocked','assigneeId'].some(key=>r[key]!==old[key]);r.generation=(old?.generation||0)+(changed?1:0);
      if(!old){const customer=this._customerPolicy(r);if(customer){r.pinned=customer.pinned??r.pinned;r.assigneeId=customer.assigneeId||r.assigneeId;}}
    }
    if(kind==='customers'){
      str(r.buyerId,'买家编号',true,200);if(this.store.list('customers').some(c=>c.id!==r.id&&c.space===r.space&&c.accountId===r.accountId&&c.buyerId===r.buyerId))fail('DUPLICATE','此账号已有相同买家的客户档案，请更新已有记录。');
    }
    if(['conversations','customers'].includes(kind)&&r.assigneeId){const assigned=this.store.get('members',r.assigneeId);if(!assigned||assigned.enabled===false||(assigned.role!=='owner'&&!assigned.accountIds?.includes(r.accountId)))fail('VALIDATION','接待人不存在、已停用或无此账号权限。');}
    if(kind==='afterSales'){this._relation('orders',r.orderId,r);r.status||='open';}
    if(kind==='snippets'){str(r.name,'短语名称',true);str(r.text,'短语内容',true);}
    if(kind==='replyRules'){str(r.name,'规则名称',true);str(r.text,'回复内容',true);if(r.productId)this._relation('products',r.productId,r);if(r.keywords&&!Array.isArray(r.keywords))fail('VALIDATION','关键词须为列表。');r.priority??=0;}
    if(kind==='messages'){const conversation=this._relation('conversations',r.conversationId,r);if(r.buyerId!==conversation.buyerId)fail('VALIDATION','消息买家与会话不一致。');str(r.text,'消息内容',true,10000);date(r.receivedAt,'消息收到时间');if(!['incoming','outgoing'].includes(r.direction))fail('VALIDATION','消息方向无效。');}
    if(kind==='settings'){r.autoEnabledAt=r.autoEnabled===true?(old?.autoEnabled===true?old.autoEnabledAt:now()):undefined;if(r.excludedProductIds&&!Array.isArray(r.excludedProductIds))fail('VALIDATION','排除商品须为商品编号列表。');str(r.defaultReply,'默认回复',false,10000);}
    if(kind==='plans'){str(r.name,'计划名称',true);if(!Array.isArray(r.productIds)||!r.productIds.length)fail('VALIDATION','计划须选择商品。');for(const p of r.productIds)this._relation('products',p,r);if(!['publish','refresh','activate','deactivate'].includes(r.action))fail('VALIDATION','运营动作无效。');}
    if(!trusted)for(const key of PROTECTED[kind]||[]) {if(old?.[key]!==undefined)r[key]=old[key];else delete r[key];}
    if(kind==='accounts'&&!trusted){r.status=old?.status||(r.space==='test'?'test_ready':'not_connected');r.capabilities=old?.capabilities||{};}
    if(kind==='orders'&&!trusted)r.source=old?.source||(r.space==='test'?'test':'local');
    return r;
  }
  _relation(kind, targetId, record) {
    const target=this.store.get(kind,targetId||'');
    if(!target||target.space!==record.space||target.accountId!==record.accountId)fail('VALIDATION','关联资料不属于当前账号与空间。');
    return target;
  }
  save({kind,record},actor) {
    if(kind==='notifications'){
      if(!record||Object.keys(record).some(k=>!['id','space','accountId','read','createdAt','updatedAt'].includes(k)))fail('PROTECTED','通知事实由系统生成，只能修改已查看状态。');
      return this.markNotification({id:record.id,read:record.read},actor);
    }
    if(READONLY.has(kind))fail('PROTECTED','此类记录由对应业务动作生成，不能直接修改。');
    const old=record?.id?this.store.get(kind,record.id):null;
    const r=this._validate(kind,record,old);
    this._check(actor,kind==='accounts'?{...r,accountId:r.id}:r,['members','settings','integrations','accounts'].includes(kind)?'owner':SUPPORT_SAVE.has(kind)?'write':'operate');
    if(kind==='members'&&old?.role==='owner'&&(r.role!=='owner'||r.enabled===false)&&this.store.list('members').filter(m=>m.role==='owner'&&m.enabled!==false).length<=1)fail('LAST_OWNER','必须保留至少一名有效所有者。');
    this.store.transaction(()=>{this.store.put(kind,r);if(kind==='customers')for(const conversation of this.store.list('conversations').filter(c=>c.space===r.space&&c.accountId===r.accountId&&c.buyerId===r.buyerId)){this.store.put('conversations',{...conversation,...(r.pinned!==undefined?{pinned:r.pinned}:{}),...(r.assigneeId!==undefined?{assigneeId:r.assigneeId}:{}),generation:(conversation.generation||0)+1,updatedAt:now()});}this._audit(actor,'entity.save',r);});return this._public(kind,r,actor);
  }
  remove({kind,id:recordId},actor) {
    if(!FIELDS[kind]||READONLY.has(kind)||kind==='orders')fail('PROTECTED','历史事实不能直接删除。');
    const r=this._record(kind,recordId,actor,kind==='members'||kind==='accounts'?'owner':'operate');
    const references={accounts:KINDS.filter(k=>!['accounts','audit','notifications','members'].includes(k)),assets:['rules','inventory','products','assets','serviceJobs'],products:['rules','orders','conversations','plans','serviceJobs','interactionProfiles'],rules:['serviceJobs'],interactionProfiles:['serviceJobs']};
    if(kind==='accounts') {
      const referenced=KINDS.filter(k=>k!=='accounts').some(k=>this.store.list(k).some(v=>v.accountId===r.id||k==='members'&&v.accountIds?.includes(r.id)));
      this.store.transaction(()=>{const grant=this.store.get('_hosting',r.id);if(grant)this.store.put('_hosting',{...grant,enabled:false,version:grant.version+1,updatedAt:now()});if(referenced)this.store.put('accounts',{...r,paused:true,archived:true,archivedAt:now(),loginStatus:'cleared',connectionStatus:'disconnected',capabilities:{},hosting:{...r.hosting,enabled:false},authorizationVersion:(r.authorizationVersion||0)+1,sessionVersion:(r.sessionVersion||0)+1,updatedAt:now()});else this.store.remove('accounts',r.id);this._audit(actor,'account.remove',r,referenced?'archived':'removed');});
      this.connector?.pause?.(r.id,'账号已移除');return {removed:!referenced,archived:referenced,id:r.id};
    }
    if(references[kind]?.some(k=>this.store.list(k).some(v=>v.id!==r.id&&JSON.stringify(v).includes(`"${r.id}"`))))fail('IN_USE','此记录仍有关联业务，请先停用并解除关联。');
    if(kind==='members'&&r.role==='owner'&&this.store.list('members').filter(m=>m.role==='owner'&&m.enabled!==false).length<=1)fail('LAST_OWNER','不能移除最后一名所有者。');
    this.store.remove(kind,r.id);this._audit(actor,'entity.delete',r);return {removed:true,id:r.id};
  }
  _assetContent(asset, quantity, order, used = new Set(), trail = [], lookup) {
    if(trail.includes(asset.id)||trail.length>8)fail('INVALID_BUNDLE','资料组合存在循环或层级过深。');
    int(quantity,'组合交付份数',1,1000);
    if(asset.images?.length)fail('IMAGE_DELIVERY_UNAVAILABLE','该资料含必需图片，当前连接尚未完成图片发送能力验证，请人工处理整份资料。');
    const snapshots=[];const inventoryIds=[];const blocks=[];
    if(asset.type==='bundle'){
      for(const item of asset.items||[]){const child=lookup?lookup(item.assetId):this._relation('assets',item.assetId,order);const part=this._assetContent(child,quantity*(item.quantity||1),order,used,[...trail,asset.id],lookup);snapshots.push(...part.items);inventoryIds.push(...part.inventoryIds);blocks.push(part.text);}
      if(!snapshots.length)fail('INVALID_BUNDLE','组合没有可交付资料。');
    }else if(asset.type==='fixed'){
      if(!asset.link)fail('MISSING_ASSET','资料缺少网盘链接。');
      snapshots.push({...copy(asset),quantity});
      blocks.push(`${asset.name}（版本 ${asset.version || 1}）\n${asset.link}${asset.code?'\n提取码：'+asset.code:''}${asset.instructions?'\n'+asset.instructions:''}${quantity>1?'\n份数：'+quantity:''}`);
    }else{
      const available=this.store.list('inventory').filter(i=>i.assetId===asset.id&&i.space===order.space&&i.accountId===order.accountId&&i.status==='available'&&(!i.expiresAt||Date.parse(i.expiresAt)>Date.now())&&!used.has(i.id)).sort((a,b)=>(a.expiresAt||'9999').localeCompare(b.expiresAt||'9999')||a.createdAt.localeCompare(b.createdAt));
      if(available.length<quantity)fail('OUT_OF_STOCK',`${asset.name} 可用库存 ${available.length} 份，需要 ${quantity} 份。`);
      const chosen=available.slice(0,quantity);chosen.forEach(i=>used.add(i.id));inventoryIds.push(...chosen.map(i=>i.id));
      snapshots.push({...copy(asset),quantity,entries:chosen.map(i=>({id:i.id,content:i.content,costCents:i.costCents,expiresAt:i.expiresAt}))});
      blocks.push(`${asset.name}（版本 ${asset.version||1}）\n${chosen.map(i=>i.content).join('\n\n')}${asset.instructions?'\n'+asset.instructions:''}`);
    }
    return {items:snapshots,inventoryIds,text:blocks.join('\n\n')};
  }
  _capability(account, name) {
    if(account.space==='test')return true;
    if(account.archived||['cleared','cleanup_failed','expired','verification_required','needs_login'].includes(account.loginStatus))return false;
    const aliases={sendMessages:['sendMessage','sendMessages','send_messages','messages.send'],readOrders:['readOrders','read_orders','orders.read'],readProducts:['readProducts','read_products','products.read'],readMessages:['readMessages','read_messages','messages.read'],writeProducts:['mutateProduct','writeProducts','write_products','products.write']};
    return (aliases[name]||[name]).some(key=>{const fact=account.capabilities?.[key];if(account.sessionVersion){if(!fact||typeof fact!=='object'||fact.sessionVersion!==account.sessionVersion||!fact.evidenceId||!Number.isFinite(Date.parse(fact.verifiedAt))||Date.now()-Date.parse(fact.verifiedAt)>300000||Date.parse(fact.verifiedAt)>Date.now()+30000)return false;}return fact===true||fact?.available===true||fact?.status==='available';});
  }
  deliveryPreview(orderId,actor,{resend=false}={}) {
    const order=this._record('orders',orderId,actor,'sensitive');const account=this._record('accounts',order.accountId,actor);const reasons=[];
    if(account.paused)reasons.push('账号已暂停自动处理。');
    if(account.space==='live'&&!this._capability(account,'sendMessages'))reasons.push('尚未获得此账号发送消息的真实平台能力。');
    if(order.paymentStatus!=='paid')reasons.push('订单尚未确认付款。');
    if(['refunding','refunded','closed','cancelled'].includes(order.tradeStatus)||order.refundCents>0)reasons.push('订单处于退款、关闭或已退款状态，不能自动交付。');
    if(order.space==='live'&&['shipped','completed'].includes(order.tradeStatus)&&!resend)reasons.push('平台已发货或已完成订单，请先人工核验历史交付，不能作为新订单自动发送。');
    if(!order.buyerId)reasons.push('买家身份未确认。');
    if(order.space==='live'&&(order.source!=='platform'||!order.verifiedAt))reasons.push('仅本地订单资料不能作为可信付款证据，请从真实平台刷新。');
    if(order.space==='live'&&(!order.verifiedAt||!Number.isFinite(Date.parse(order.verifiedAt))||Date.now()-Date.parse(order.verifiedAt)>300000||Date.parse(order.verifiedAt)>Date.now()+30000))reasons.push('订单核验已超过 5 分钟或时间无效，请先刷新付款与售后状态。');
    const attempts=this.store.list('deliveries').filter(d=>d.orderId===order.id&&!d.serviceId&&(!d.purpose||d.purpose==='primary'));
    if(attempts.some(d=>['sending','unknown','sent','accepted','verified_sent'].includes(d.status))&&!resend)reasons.push('此单已有已提交、送达或待核验记录，禁止自动重复发送。');
    if(resend&&attempts.some(d=>['sending','accepted','unknown'].includes(d.status)))reasons.push('此前发送结果不明或仅受理，请先人工核验，再决定补发。');
    let product;try{product=this._relation('products',order.productId,order);}catch{reasons.push('订单商品不属于当前账号或已缺失。');}
    const variant=product?.variants?.find(v=>v.id===order.variantId);
    if(product?.variants?.length&&!variant)reasons.push('订单规格无效或未确认。');
    const matches=this.store.list('rules').filter(r=>r.enabled&&r.space===order.space&&r.accountId===order.accountId&&r.productId===order.productId&&(!r.variantId||r.variantId===order.variantId)).sort((a,b)=>(b.priority||0)-(a.priority||0)||(!!b.variantId)-(!!a.variantId));
    let rule=matches[0];if(!rule)reasons.push('没有启用且匹配的交付规则。');
    if(matches.length>1&&(matches[0].priority||0)===(matches[1].priority||0)&&!!matches[0].variantId===!!matches[1].variantId)reasons.push('同优先级规则冲突，请明确唯一生效规则。');
    if(rule?.delaySeconds&&Date.now()-Date.parse(order.paidAt||order.createdAt)<rule.delaySeconds*1000)reasons.push('尚未达到规则的交付延时。');
    let content={items:[],inventoryIds:[],text:''};
    let snapshot;
    if(rule)try{
      const asset=this._relation('assets',rule.assetId,order);
      if(variant?.assetId&&rule.assetId!==variant.assetId)fail('VARIANT_MISMATCH','规则资料与商品规格绑定不一致。');
      content=this._assetContent(asset,rule.quantity||1,order);
      if(!rule.afterReceipt){for(const gift of rule.gifts||[]){const giftAsset=this._relation('assets',gift.assetId,order);const extra=this._assetContent(giftAsset,gift.quantity||1,order,new Set(content.inventoryIds));content.items.push(...extra.items);content.inventoryIds.push(...extra.inventoryIds);content.text+='\n\n赠送资料\n'+extra.text;}
      if(typeof rule.thankYou==='string'&&rule.thankYou.trim())content.text+='\n\n'+rule.thankYou;}
      snapshot={order:copy(order),product:copy(product),rule:copy(rule),postReceiptAssets:rule.afterReceipt?this._freezeGiftAssets(rule,order):[]};
    }catch(error){reasons.push(error.message);}
    return {eligible:reasons.length===0,reasons,orderId:order.id,accountId:order.accountId,buyerId:order.buyerId,rule:rule?copy(rule):null,...content,snapshot,afterReceiptDeferred:!!rule?.afterReceipt,afterReceiptNotice:rule?.afterReceipt?(order.space==='test'?'本次只交主资料，赠品和致谢需隔离测试收货事件后另行执行。':'本次只交主资料；后续赠品和致谢必须取得正式收货事件、逐项互动能力和可追溯回执，缺少证据时保持阻断。'):undefined,available:content.inventoryIds.length,space:order.space};
  }
  async _send(account, request) {
    if(account.space==='test'&&!this.connector?.testOnly&&!this.connector?.supportsTest){
      const status=account.testOutcome||'sent';return {status,receiptId:status==='sent'?`test-${request.idempotencyKey}`:undefined,reason:status==='sent'?'隔离测试连接确认；未向真实买家发送。':`隔离测试连接：${status}`};
    }
    if(!this.connector?.sendMessage)return {status:'blocked',reason:'尚无适用于当前账号的真实发送接口。'};
    const authorize=request.authorize;
    return this.connector.sendMessage({...request,account,authorize:()=>{try{return authorize?authorize():this.assertLicense();}catch(error){if(error.licensePreSubmission)return false;throw error;}}});
  }
  async deliver({orderId,reason},actor,generation,resend) {
    if(resend){str(reason,'补发依据',true,1000);this._record('orders',orderId,actor,'operate');}
    let delivery;
    this.store.transaction(()=>{
      this._fresh(actor,generation);
      const preview=this.deliveryPreview(orderId,actor,{resend});
      if(!preview.eligible)fail('DELIVERY_BLOCKED',preview.reasons.join(' '));
      const order=this._record('orders',orderId,actor,'operate');
      const previous=this.store.list('deliveries').filter(d=>d.orderId===order.id&&!d.serviceId&&(!d.purpose||d.purpose==='primary'));
      delivery={id:id(),space:order.space,accountId:order.accountId,orderId:order.id,buyerId:order.buyerId,externalId:order.externalId,status:'sending',purpose:'primary',snapshot:preview.snapshot,attempt:previous.length+1,text:preview.text,items:preview.items,inventoryIds:preview.inventoryIds,reason:resend?reason:undefined,resendOf:resend?previous.at(-1)?.id:undefined,createdAt:now(),updatedAt:now(),submittedAt:now()};
      for(const inventoryId of preview.inventoryIds){const entry=this.store.get('inventory',inventoryId);if(entry.status!=='available')fail('OUT_OF_STOCK','库存刚刚已被另一订单预留。');this.store.put('inventory',{...entry,status:'reserved',orderId,deliveryId:delivery.id,updatedAt:now()});}
      this.store.put('deliveries',delivery);this._audit(actor,resend?'delivery.resend':'delivery.execute',delivery,'submitted');
    });
    return this._sendPreparedDelivery(delivery,actor,generation);
  }
  async _sendPreparedDelivery(delivery,actor,generation) {
    const orderId=delivery.orderId;
    let response;
    try{
      this._fresh(actor,generation);
      const account=this._record('accounts',delivery.accountId,actor,'operate');const order=this._record('orders',orderId,actor,'operate');
      if(account.paused)fail('PAUSED','账号已暂停。');
      if(delivery.serviceId)this._serviceSendGuard(delivery,actor);
      const authorize=()=>{
        this._fresh(actor,generation);const freshAccount=this._record('accounts',delivery.accountId,actor,'operate');
        if(freshAccount.paused||freshAccount.archived||freshAccount.sessionVersion!==account.sessionVersion)fail('PAUSED','账号已暂停或会话已变化。');
        this._background(actor,delivery.serviceId?'services':'paidDelivery');
        if(delivery.serviceId)this._serviceSendGuard(delivery,actor);
        else{
          const freshOrder=this._record('orders',orderId,actor,'operate');
          const deliveryStateChanged=freshOrder.space==='live'&&((['shipped','completed'].includes(freshOrder.tradeStatus)&&!delivery.resendOf)||(this.backgroundContexts.has(actor)&&freshOrder.tradeStatus!=='paid'));
          if(freshOrder.paymentStatus!=='paid'||freshOrder.refundCents>0||deliveryStateChanged||['refunding','refunded','closed','cancelled'].includes(freshOrder.tradeStatus)||(freshOrder.space==='live'&&(!freshOrder.verifiedAt||Date.now()-Date.parse(freshOrder.verifiedAt)>300000)))fail('PAYMENT_CHANGED','付款、退款或待交付状态已变化，停止提交。');
          const rule=this.store.get('rules',delivery.snapshot?.rule?.id);
          if(!rule?.enabled||hash(rule)!==hash(delivery.snapshot.rule))fail('RULE_CHANGED','规则已变更，停止尚未提交的交付。');
        }
        return true;
      };
      authorize();response=await this._send(account,{order,text:delivery.text,idempotencyKey:delivery.id,purpose:delivery.purpose,serviceId:delivery.serviceId,authorize});
      if(account.space==='live'&&response?.status==='sent'&&!(typeof response.receiptId==='string'&&response.receiptId.trim()))response={status:'unknown',reason:'平台没有给出可追溯回执，保留待核验状态。'};
    }catch(error){response={status:error.licensePreSubmission||['LOCKED','FORBIDDEN','PAUSED','BACKGROUND_REVOKED','BACKGROUND_SCOPE','PAYMENT_CHANGED','RULE_CHANGED','CANCELLED','QUEUE_FULL'].includes(error.code)?'rejected':'unknown',reason:'发送未获确认；未提交的动作已取消，已提交结果需要核验。'};}
    const settled = this.store.transaction(()=>{
      const status=['sent','accepted','rejected','unknown','rate_limited','blocked'].includes(response?.status)?response.status:'unknown';
      const persisted=this.store.get('deliveries',delivery.id);
      const result={...persisted,status,receiptId:typeof response?.receiptId==='string'?response.receiptId:undefined,reason:sanitizeText(response?.reason),updatedAt:now(),...(status==='sent'?{sentAt:now()}:{} )};
      this.store.put('deliveries',result);
      for(const inventoryId of result.inventoryIds){const entry=this.store.get('inventory',inventoryId);if(entry.deliveryId!==result.id)fail('INVARIANT','库存预留不一致，已停止处理。');if(status==='sent')this.store.put('inventory',{...entry,status:'delivered',updatedAt:now()});else if(['rejected','rate_limited','blocked'].includes(status)){const {orderId:oldOrder,deliveryId:oldDelivery,...rest}=entry;this.store.put('inventory',{...rest,status:'available',updatedAt:now()});}}
      if(status==='sent'){
        const order=this.store.get('orders',orderId);const cost=result.items.reduce((sum,item)=>sum+(item.entries||[]).reduce((s,e)=>s+(e.costCents||0),0),0);this.store.put('orders',{...order,costCents:(order.costCents||0)+cost,updatedAt:now()});
        const conversation=this.store.list('conversations').find(c=>c.accountId===result.accountId&&c.space===result.space&&c.buyerId===result.buyerId);
        if(conversation)this.store.put('messages',{id:id(),space:result.space,accountId:result.accountId,conversationId:conversation.id,buyerId:result.buyerId,text:result.text,direction:'outgoing',origin:'delivery',status,receiptId:result.receiptId,createdAt:now(),updatedAt:now()});
      }else this._notice(result,'delivery_exception','交付需要处理',status==='unknown'?'发送结果不明，请核验聊天和买家反馈。':result.reason||'发送未完成。');
      this._audit(actor,'delivery.result',result,status);
      this._afterDeliverySettled(result);
      return this.store.get('deliveries',result.id);
    });
    // Facts must commit even when authorization was revoked while the network call was in flight.
    this._check(actor,settled,'sensitive');return this._public('deliveries',settled,this._actor(actor));
  }
  verifyDelivery({deliveryId,outcome,reason},actor) {
    str(reason,'核验依据',true,2000);if(!['sent','not_sent'].includes(outcome))fail('VALIDATION','请选择已送达或确定未发送。');
    return this.store.transaction(()=>{
      const delivery=this._record('deliveries',deliveryId,actor,'operate');if(!['unknown','accepted'].includes(delivery.status))fail('INVALID_STATE','此记录不属于待核验状态。');
      const status=outcome==='sent'?'verified_sent':'verified_not_sent';const result={...delivery,status,verifiedBy:actor.id,verification:{outcome,reason,at:now()},updatedAt:now()};this.store.put('deliveries',result);
      for(const inventoryId of delivery.inventoryIds){const entry=this.store.get('inventory',inventoryId);if(entry.deliveryId!==delivery.id)continue;if(outcome==='sent')this.store.put('inventory',{...entry,status:'delivered',updatedAt:now()});else{const {orderId,deliveryId,...rest}=entry;this.store.put('inventory',{...rest,status:'available',updatedAt:now()});}}
      if(outcome==='sent'){const order=this.store.get('orders',delivery.orderId);const cost=delivery.items.reduce((sum,item)=>sum+(item.entries||[]).reduce((s,e)=>s+(e.costCents||0),0),0);this.store.put('orders',{...order,costCents:(order.costCents||0)+cost,updatedAt:now()});}
      this._afterDeliverySettled(result);
      this._audit(actor,'delivery.verify',result,status);return result;
    });
  }
  importInventory({assetId,entries},actor) {
    const asset=this._record('assets',assetId,actor,'operate');if(asset.type!=='unique')fail('VALIDATION','只有唯一库存资料可逐条入库。');
    if(!Array.isArray(entries)||entries.length>10000)fail('VALIDATION','入库列表须少于 10000 条。');
    const fingerprints=new Set(this.store.list('inventory').filter(i=>i.accountId===asset.accountId&&i.space===asset.space).map(i=>i.fingerprint));
    const valid=[],duplicates=[],errors=[];const batchId=id();
    entries.forEach((entry,index)=>{try{str(entry.content,'库存内容',true,200000);int(entry.costCents,'成本',0);date(entry.expiresAt,'有效期');const fingerprint=hash(entry.content.trim());if(fingerprints.has(fingerprint)){duplicates.push({row:index+1,message:'此账号已导入相同内容。'});return;}fingerprints.add(fingerprint);valid.push({id:id(),space:asset.space,accountId:asset.accountId,assetId,content:entry.content,costCents:entry.costCents||0,expiresAt:entry.expiresAt||undefined,status:entry.expiresAt&&Date.parse(entry.expiresAt)<=Date.now()?'expired':'available',batchId,fingerprint,createdAt:now(),updatedAt:now()});}catch(error){errors.push({row:index+1,message:error.message});}});
    this.store.transaction(()=>{valid.forEach(r=>this.store.put('inventory',r));this._audit(actor,'inventory.import',asset);});return {imported:valid.length,duplicates,errors,batchId};
  }
  adjustInventory({id:inventoryId,status,reason},actor) {
    str(reason,'调整理由',true,1000);if(!['available','expired','disabled'].includes(status))fail('VALIDATION','手动盘点仅可调整可用、失效或停用。');
    const entry=this._record('inventory',inventoryId,actor,'operate');if(['reserved','delivered'].includes(entry.status))fail('IN_USE','已预留或已交付内容不能直接重新入库。');
    if(status==='available'&&entry.expiresAt&&Date.parse(entry.expiresAt)<=Date.now())fail('EXPIRED','过期内容不能重新设为可用。');
    const result={...entry,status,adjustments:[...(entry.adjustments||[]),{from:entry.status,to:status,reason,actorId:actor.id,at:now()}],updatedAt:now()};this.store.put('inventory',result);this._audit(actor,'inventory.adjust',result);return result;
  }
  pauseAccount({id:accountId,accountId:alias,paused},actor) {accountId ||= alias;const account=this._record('accounts',accountId,actor,'operate');if(typeof paused!=='boolean')fail('VALIDATION','暂停状态无效。');if(account.archived&&!paused)fail('ARCHIVED','已归档账号不能恢复托管。');const result={...account,paused,updatedAt:now()};this.store.put('accounts',result);if(paused)this.connector?.pause?.(account.id,'用户暂停此账号');this._audit(actor,'account.pause',result);return result;}
  async syncAccount({id:accountId,kind='orders'},actor,generation) {
    const account=this._record('accounts',accountId,actor,'operate');if(!['orders','products','messages'].includes(kind))fail('VALIDATION','同步类型无效。');
    if(account.space==='test')return {status:'test_only',synced:0,reason:'试运行使用本机隔离数据，没有平台同步。'};
    if(!this.connector?.sync)return {status:'blocked',synced:0,reason:'此普通账号尚无可用的正式同步能力，登录成功不代表取得接口权限。'};
    this._fresh(actor,generation);this._background(actor,'sync');let response;try{response=await this.connector.sync(account,kind,{authorize:()=>{this._fresh(actor,generation);this._background(actor,'sync');const current=this._record('accounts',account.id,actor,'operate');return !current.archived&&current.sessionVersion===account.sessionVersion;}});}catch{return {status:'failed',synced:0,reason:'平台同步失败，已保留上次数据。'};}
    this._fresh(actor,generation);const currentAccount=this._record('accounts',accountId,actor,'operate');if(currentAccount.sessionVersion!==account.sessionVersion||currentAccount.archived||this.backgroundContexts.has(actor)&&currentAccount.paused)fail('STALE_SESSION','同步期间账号或会话已变化，旧结果已丢弃。');
    if(response?.status!=='ok'||!Array.isArray(response.records))return {status:response?.status||'blocked',synced:0,reason:sanitizeText(response?.reason||'平台没有返回可验证数据。')};
    const errors=[];const recordIds=[];let synced=0;
    if(kind==='messages')for(const incoming of response.conversations||[]){try{if(incoming.accountId&&incoming.accountId!==account.id)fail('WRONG_ACCOUNT','会话账号不一致。');const old=this.store.get('conversations',incoming.id);if(old&&old.accountId!==account.id)fail('WRONG_ACCOUNT','会话编号与其他账号冲突。');const record=this._validate('conversations',{...incoming,accountId:account.id,space:'live',manual:old?.manual??false},old,true);this.store.put('conversations',record);}catch(error){errors.push({message:sanitizeText(error.message)});}}
    for(const incoming of response.records){try{
      this.store.transaction(()=>{
        if(incoming.accountId&&incoming.accountId!==account.id)fail('WRONG_ACCOUNT','平台记录账号不一致。');
        const externalId=incoming.externalId;const old=incoming.id?this.store.get(kind,incoming.id):this.store.list(kind).find(r=>r.accountId===account.id&&externalId&&(r.externalId===externalId||kind==='messages'&&r.receiptId===externalId));
        if(old&&(old.accountId!==account.id||old.space!=='live'))fail('WRONG_ACCOUNT','平台记录编号冲突。');
        if(kind==='orders'&&(!incoming.verifiedAt||!Number.isFinite(Date.parse(incoming.verifiedAt))||Date.parse(incoming.verifiedAt)>Date.now()+30000||typeof incoming.evidenceId!=='string'||!incoming.evidenceId))fail('ORDER_EVIDENCE','逐笔订单缺少核验时间或来源证据，保留旧付款事实。');
        const productId=kind==='orders'&&incoming.productExternalId?this.store.list('products').find(p=>p.accountId===account.id&&p.externalId===incoming.productExternalId)?.id:incoming.productId;
        const r=this._validate(kind,{...incoming,id:old?.id||incoming.id||id(),accountId:account.id,space:'live',...(kind==='orders'?{source:'platform',verifiedAt:incoming.verifiedAt,evidenceId:incoming.evidenceId,...(incoming.productExternalId?{productId}: {})}:{}),...(kind==='products'&&old?{variants:old.variants||[]}:{}),...(kind==='messages'&&old?{origin:old.origin}:{}),lastSyncedAt:now()},old,true);
        this.store.put(kind,r);recordIds.push(r.id);synced++;
      });
    }catch(error){errors.push({externalId:typeof incoming.externalId==='string'?incoming.externalId:undefined,message:sanitizeText(error.message)});}}
    this.store.put('accounts',{...currentAccount,lastSyncedAt:now(),updatedAt:now()});this._audit(actor,'account.sync',account,errors.length?'partial':'ok');return {status:errors.length?'partial':'ok',synced,recordIds,errors,lastSyncedAt:now(),hasMore:response.hasMore===true,omitted:response.omitted||0,reason:response.reason||'',scope:response.scope};
  }
  async refreshOrders({ids},actor,generation) {
    if(!Array.isArray(ids)||ids.length>500)fail('VALIDATION','每次最多刷新 500 笔订单。');const orders=ids.map(orderId=>this._record('orders',orderId,actor,'operate'));const results=[];
    for(const accountId of new Set(orders.map(o=>o.accountId))){const result=await this.syncAccount({id:accountId,kind:'orders'},actor,generation);for(const order of orders.filter(o=>o.accountId===accountId)){const refreshed=result.recordIds?.includes(order.id);results.push({id:order.id,...result,...(refreshed?{status:'ok'}:['ok','partial'].includes(result.status)?{status:'unchanged',reason:'此次平台同步没有包含该订单，已保留上次资料，不能视为刷新成功。'}:{})});}}
    return {results,status:results.every(r=>r.status==='ok')?'ok':'partial'};
  }
  _putPreview(type,data,actor) {const preview={id:id(),type,actorId:actor.id,data,createdAt:now(),expiresAt:new Date(Date.now()+1800000).toISOString()};this.store.put('_previews',preview);return preview;}
  _getPreview(previewId,type,actor) {const preview=this.store.get('_previews',previewId||'');if(!preview||preview.type!==type||preview.actorId!==actor.id||Date.parse(preview.expiresAt)<=Date.now())fail('PREVIEW_EXPIRED','预览已过期或不属于当前成员，请重新预览。');return preview;}
  previewBatch({ids,changes},actor) {
    if(!Array.isArray(ids)||!ids.length||ids.length>500||new Set(ids).size!==ids.length)fail('VALIDATION','请选择 1 至 500 件不重复商品。');
    if(!changes||Object.keys(changes).some(k=>!['priceCents','stock','status','action'].includes(k)))fail('VALIDATION','批量维护仅支持价格、库存和上下架。');
    if(changes.action&&!['publish','refresh','activate','deactivate'].includes(changes.action))fail('VALIDATION','批量动作无效。');int(changes.priceCents,'售价');int(changes.stock,'库存');
    const products=ids.map(productId=>this._record('products',productId,actor,'operate'));const space=products[0].space;if(products.some(p=>p.space!==space||p.accountId!==products[0].accountId))fail('VALIDATION','每个批量任务仅限同一账号与空间。');
    const rows=products.map(p=>({id:p.id,accountId:p.accountId,title:p.title,before:{priceCents:p.priceCents,stock:p.stock,status:p.status},after:{priceCents:changes.priceCents??p.priceCents,stock:changes.stock??p.stock,status:changes.status??p.status},fingerprint:hash(p)}));
    const preview=this._putPreview('batch',{space,ids,changes:copy(changes),rows},actor);return {id:preview.id,previewId:preview.id,rows,total:rows.length,scope:'平台操作需要实际能力；本地预览不会修改商品。'};
  }
  async executeBatch({previewId,id:batchId},actor,generation) {
    let batch=batchId?this._record('batches',batchId,actor,'operate'):this.store.list('batches').find(b=>b.previewId===previewId);
    if(batch){this._check(actor,batch,'operate');if(batch.status==='running')fail('IN_PROGRESS','批量任务正在执行。');if(batch.results.every(r=>!['pending','rate_limited','rejected'].includes(r.status)))return batch;if(batch.paused)return batch;}
    else{
      const preview=this._getPreview(previewId,'batch',actor);const {ids,changes,rows,space}=preview.data;
      for(const row of rows){const product=this._record('products',row.id,actor,'operate');if(hash(product)!==row.fingerprint)fail('STALE_PREVIEW','商品在预览后已变化，请重新预览。');}
      batch={id:id(),space,accountId:rows[0].accountId,productIds:ids,changes,status:'running',paused:false,results:rows.map(row=>({id:row.id,accountId:row.accountId,status:'pending'})),previewId,createdAt:now(),updatedAt:now()};
      this.store.put('batches',batch);
    }
    batch={...batch,status:'running',updatedAt:now()};this.store.put('batches',batch);
    for(let index=0;index<batch.results.length;index++){
      batch=this.store.get('batches',batch.id);if(batch.paused)break;
      const item=batch.results[index];if(!['pending','rate_limited','rejected'].includes(item.status))continue;
      let account,product;
      try{this._fresh(actor,generation);product=this._record('products',item.id,actor,'operate');account=this._record('accounts',product.accountId,actor,'operate');if(account.paused)fail('PAUSED','账号已暂停。');}
      catch(error){batch.results[index]={...item,status:'blocked',reason:sanitizeText(error.message)};this.store.put('batches',batch);continue;}
      const attemptId=id();batch.results[index]={...item,status:'sending',attemptId};this.store.put('batches',batch);
      let response;
      try{
        if(account.space==='test'&&!this.connector?.testOnly&&!this.connector?.supportsTest){const status=account.testOutcome||'sent';response={status,receiptId:status==='sent'?`test-${attemptId}`:undefined,reason:'隔离试运行结果，未修改真实商品。'};}
        else if(!this.connector?.mutateProduct)response={status:'blocked',reason:'当前账号未取得商品修改能力。'};
        else response=await this.connector.mutateProduct({account,product,changes:batch.changes,idempotencyKey:attemptId});
      }catch{response={status:'unknown',reason:'连接中断，商品操作结果未知，请先人工核验。'};}
      batch=this.store.get('batches',batch.id);const status=['sent','accepted','rejected','unknown','rate_limited','blocked'].includes(response?.status)?response.status:'unknown';
      batch.results[index]={...item,status,attemptId,reason:sanitizeText(response?.reason),receiptId:response?.receiptId};batch.updatedAt=now();
      this.store.transaction(()=>{
        this.store.put('batches',batch);
        if(status==='sent'){const current=this.store.get('products',product.id);const {action,...changes}=batch.changes;this.store.put('products',{...current,...changes,platformStatus:account.space==='test'?'test_confirmed':'confirmed',platformReceiptId:response.receiptId,updatedAt:now()});}
      });
    }
    batch=this.store.get('batches',batch.id);batch.status=batch.paused?'paused':batch.results.every(r=>r.status==='sent')?'completed':'needs_attention';batch.updatedAt=now();this.store.put('batches',batch);this._audit(actor,'batch.execute',batch,batch.status);this._check(actor,batch,'operate');return batch;
  }
  pauseBatch({id:batchId,paused},actor) {const batch=this._record('batches',batchId,actor,'operate');if(typeof paused!=='boolean')fail('VALIDATION','暂停状态无效。');const result={...batch,paused,status:paused?'paused':batch.status,updatedAt:now()};this.store.put('batches',result);return result;}
  _conversationLinks(conversation) {
    const order=conversation.orderId?this._relation('orders',conversation.orderId,conversation):null;
    const product=conversation.productId?this._relation('products',conversation.productId,conversation):null;
    if(order&&order.buyerId!==conversation.buyerId)fail('WRONG_BUYER','会话买家与关联订单不一致，已阻止读取或发送。');
    if(order&&conversation.productId&&order.productId!==conversation.productId)fail('WRONG_PRODUCT','会话商品与关联订单不一致，已阻止读取或发送。');
    return {order,product};
  }
  messagePreview({conversationId,text},actor) {
    const conversation=this._record('conversations',conversationId,actor,'write');str(text,'消息内容',true,10000);
    const account=this._record('accounts',conversation.accountId,actor);const reasons=[];if(account.paused)reasons.push('账号已暂停。');if(conversation.blocked)reasons.push('此会话已在本机屏蔽。');if(account.space==='live'&&!this._capability(account,'sendMessages'))reasons.push('当前账号尚未取得发送消息的真实平台能力。');
    if(conversation.assigneeId&&conversation.assigneeId!==actor.id&&actor.role!=='owner')reasons.push('此会话正由其他成员接待。');
    const {order,product}=this._conversationLinks(conversation);
    const variables={buyer:conversation.buyerName||conversation.buyerId,product:product?.title,order:order?.externalId};
    const rendered=text.replace(/\{\{\s*(\w+)\s*\}\}/g,(match,key)=>{if(variables[key]==null){reasons.push(`缺少变量 ${key} 的值。`);return match;}return variables[key];});
    return {eligible:!reasons.length,reasons,conversationId,accountId:conversation.accountId,buyerId:conversation.buyerId,buyerName:conversation.buyerName,text:rendered,space:conversation.space};
  }
  async sendMessage(payload,actor,generation) {
    const preview=this.messagePreview(payload,actor);if(!preview.eligible)fail('MESSAGE_BLOCKED',preview.reasons.join(' '));this._fresh(actor,generation);
    const conversation=this._record('conversations',payload.conversationId,actor,'write');const account=this._record('accounts',conversation.accountId,actor);
    const pending=this.store.list('messages').find(m=>m.conversationId===conversation.id&&m.direction==='outgoing'&&m.text===preview.text&&['sending','accepted','unknown'].includes(m.status));if(pending)fail('RESULT_UNKNOWN','相同消息仍在发送、受理或结果未知，请先核验，不能直接重复发送。');
    const message={id:id(),space:conversation.space,accountId:conversation.accountId,conversationId:conversation.id,buyerId:conversation.buyerId,text:preview.text,direction:'outgoing',origin:'manual',status:'sending',createdAt:now(),updatedAt:now()};this.store.put('messages',message);
    let response;try{const authorize=()=>{this._fresh(actor,generation);this._background(actor,'replies');const current=this._record('conversations',conversation.id,actor,'write'),currentAccount=this._record('accounts',account.id,actor);if(currentAccount.paused||currentAccount.archived||currentAccount.sessionVersion!==account.sessionVersion||current.blocked||(current.generation||0)!==(conversation.generation||0)||(this.backgroundContexts.has(actor)&&current.manual))fail('PAUSED','账号、会话或人工接管状态已变化。');return true;};authorize();response=await this._send(account,{conversation,text:preview.text,idempotencyKey:message.id,authorize});if(account.space==='live'&&response?.status==='sent'&&!(typeof response.receiptId==='string'&&response.receiptId.trim()))response={status:'unknown',reason:'发送接口没有可追溯回执，请核验平台聊天。'};}catch(error){response={status:['LOCKED','FORBIDDEN','PAUSED','BACKGROUND_REVOKED','BACKGROUND_SCOPE','CANCELLED','QUEUE_FULL'].includes(error.code)?'rejected':'unknown',reason:'消息未获确认，请查看平台聊天后再处理。'};}
    const status=['sent','accepted','rejected','unknown','rate_limited','blocked'].includes(response?.status)?response.status:'unknown';const result={...message,status,receiptId:response?.receiptId,reason:sanitizeText(response?.reason),updatedAt:now()};this.store.put('messages',result);this._audit(actor,'message.send',result,status);this._check(actor,result,'read');return this._public('messages',result,this._actor(actor));
  }
  takeover({id:conversationId,manual},actor) {const conversation=this._record('conversations',conversationId,actor,'write');if(typeof manual!=='boolean')fail('VALIDATION','接管状态无效。');const result={...conversation,manual,generation:(conversation.generation||0)+1,updatedAt:now()};this.store.put('conversations',result);this._audit(actor,'conversation.takeover',result);return result;}
  _customerPolicy(conversation) {return this.store.list('customers').find(c=>c.space===conversation.space&&c.accountId===conversation.accountId&&c.buyerId===conversation.buyerId)||null;}
  _autoReplyReasons(conversation) {
    const account=this.store.get('accounts',conversation.accountId);const settings=this._settings(conversation);const reasons=[];
    if(conversation.manual)reasons.push('会话已由人工接管。');if(conversation.blocked||this._customerPolicy(conversation)?.blocked)reasons.push('此会话或客户已屏蔽自动接待。');if(account?.paused)reasons.push('账号已暂停。');if((settings.excludedProductIds||[]).includes(conversation.productId))reasons.push('此商品已被排除自动回复，固定规则、AI 和默认答复均不执行。');return reasons;
  }
  replyPreview({conversationId,text,includeDefault=true,onlyDefault=false},actor) {
    const conversation=this._record('conversations',conversationId,actor,'write');str(text,'待测试消息',true,10000);const account=this._record('accounts',conversation.accountId,actor);const reasons=[];
    reasons.push(...this._autoReplyReasons(conversation));if(reasons.length)return {eligible:false,rule:null,text:'',reasons,conversationId,simulated:true};
    const settings=this._settings(conversation);const excluded=(settings.excludedProductIds||[]).includes(conversation.productId);
    const candidates=onlyDefault?[]:this.store.list('replyRules').filter(r=>r.space===conversation.space&&r.accountId===conversation.accountId&&r.enabled&&(!r.productId||r.productId===conversation.productId)&&(!excluded||r.productId===conversation.productId)&&!(r.excludeProductIds||[]).includes(conversation.productId)&&((r.keywords||[]).some(k=>r.exact?text===k:text.includes(k))||r.fallback)).sort((a,b)=>(b.priority||0)-(a.priority||0)||(!!b.productId)-(!!a.productId)||(!!a.fallback)-(!!b.fallback));
    if(includeDefault&&!candidates.length&&!excluded&&typeof settings.defaultReply==='string'&&settings.defaultReply.trim())candidates.push({id:`default:${settings.id}`,space:conversation.space,accountId:conversation.accountId,name:'账号默认回复',text:settings.defaultReply,maxReplies:1,fallback:true,priority:-1});
    const rule=candidates[0];if(!rule)reasons.push('没有匹配的自动回复规则。');if(candidates.length>1&&(candidates[0].priority||0)===(candidates[1].priority||0)&&!!candidates[0].productId===!!candidates[1].productId&&!!candidates[0].fallback===!!candidates[1].fallback)reasons.push('同优先级回复规则冲突。');
    if(rule?.maxReplies&&this.store.list('messages').filter(m=>m.conversationId===conversation.id&&m.origin===`rule:${rule.id}`&&['sent','accepted'].includes(m.status)).length>=rule.maxReplies)reasons.push('此会话已达到规则回复次数上限。');
    let draft='';if(rule){const result=this.messagePreview({conversationId,text:rule.text},actor);draft=result.text;reasons.push(...result.reasons);}
    return {eligible:!reasons.length,rule:rule?this._public('replyRules',rule,actor):null,text:draft,reasons,conversationId,simulated:true};
  }
  _settings(conversation) {return Object.assign({},...this.store.list('settings').filter(s=>s.space===conversation.space&&(!s.accountId||s.accountId===conversation.accountId)).sort((a,b)=>!!a.accountId-!!b.accountId));}
  async aiPreview({conversationId,text},actor,generation) {
    const conversation=this._record('conversations',conversationId,actor,'write');str(text,'待测试问题',true,10000);const settings=this._settings(conversation);const account=this._record('accounts',conversation.accountId,actor);const reasons=[];
    this._conversationLinks(conversation);
    const stopped=this._autoReplyReasons(conversation);if(stopped.length)return {eligible:false,text:'',reasons:stopped,handoff:true};
    const product=conversation.productId?this._relation('products',conversation.productId,conversation):null;
    const publicProduct=product?{id:product.id,title:product.title,description:product.description,priceCents:product.priceCents,variants:product.variants?.map(v=>({id:v.id,name:v.name,priceCents:v.priceCents}))}:null;
    const messages=this.store.list('messages').filter(m=>m.conversationId===conversation.id&&m.accountId===conversation.accountId&&m.space===conversation.space&&m.origin!=='delivery').slice(-20).map(m=>({direction:m.direction,text:m.text}));
    let response;
    if(!this.connector?.aiReply)return {eligible:false,text:'',reasons:['尚未配置并验证模型服务，可继续使用固定回复。'],handoff:true,modelConfigured:false};
    this._fresh(actor,generation);
    try{response=await this.connector.aiReply({account,conversation:{id:conversation.id,buyerId:conversation.buyerId},messages,product:publicProduct,settings:{knowledge:settings.knowledge||'',minPriceCents:settings.minPriceCents,maxNegotiations:settings.maxNegotiations,aiModel:settings.aiModel,aiEndpoint:settings.aiEndpoint},text});}catch{return {eligible:false,text:'',reasons:['模型服务暂不可用，请转人工。'],handoff:true};}
    this._fresh(actor,generation);const current=this._record('conversations',conversation.id,actor,'write');if(this._autoReplyReasons(current).length||(current.generation||0)!==(conversation.generation||0))return {eligible:false,text:'',reasons:['生成期间会话、客户策略或账号状态已变化，答复已取消。'],handoff:true};
    this._conversationLinks(current);
    if(typeof response?.text!=='string'||!response.text.trim())reasons.push('模型没有返回可用文本。');if(response?.handoff)reasons.push('模型建议转人工，未自动发送答复。');
    const output=String(response?.text||'').slice(0,10000);const min=settings.minPriceCents||0;
    if(response?.priceCents!=null&&(!Number.isSafeInteger(response.priceCents)||response.priceCents<min))reasons.push('模型报价低于商家底价或格式无效。');
    const quotedPrices=[...output.matchAll(/(?:¥|￥)\s*(\d+(?:\.\d{1,2})?)|(\d+(?:\.\d{1,2})?)\s*元/g)].map(m=>Math.round(Number(m[1]||m[2])*100));if(quotedPrices.some(price=>price<min))reasons.push('答复中金额低于设定底价。');
    if(/保证.*(库存|退款|降价)|已.*(退款|降价|改价)|免费赠送|无限库存|永久有效/.test(output))reasons.push('答复含未经商家确认的库存、价格或售后承诺。');
    if(response?.action||response?.toolCalls?.length)reasons.push('模型请求执行经营动作，已转人工。');
    const negotiationCount=this.store.list('messages').filter(m=>m.conversationId===conversation.id&&m.origin==='ai:negotiation').length;if(settings.maxNegotiations!=null&&quotedPrices.length&&negotiationCount>=settings.maxNegotiations)reasons.push('已达到商家设置的议价次数。');
    return {eligible:!reasons.length,text:reasons.length?'':output,reasons,references:publicProduct?[publicProduct.id]:[],handoff:!!reasons.length,simulated:true,requiresReview:response?.constrained!==true,constrained:response?.constrained===true,priceCents:response?.priceCents};
  }
  statistics({space='live',accountId,from,to},actor) {
    date(from,'开始');date(to,'结束');if(from&&to&&from>to)fail('VALIDATION','开始日期不能晚于结束日期。');
    const scoped=this._scope(this.store.list('orders'),actor,space,accountId);
    const relevant=scoped.filter(o=>(!from||Date.parse(o.paidAt||o.createdAt)>=Date.parse(from))&&(!to||Date.parse(o.paidAt||o.createdAt)<=Date.parse(to)));
    const orders=relevant.filter(o=>space==='test'?o.source==='test':o.source==='platform'&&!!o.verifiedAt);
    const paid=orders.filter(o=>['paid','refunded','partially_refunded'].includes(o.paymentStatus)||o.refundCents>0);
    const sum=(rows,key)=>{const result=rows.reduce((n,o)=>n+(o[key]||0),0);if(!Number.isSafeInteger(result))fail('AMOUNT_OVERFLOW','金额总和超过安全范围，缩小统计区间后重试。');return result;};
    const grossCents=sum(paid,'amountCents'),refundCents=sum(paid,'refundCents'),costCents=sum(paid,'costCents');
    const inventory=this._scope(this.store.list('inventory'),actor,space,accountId);
    const stock={available:0,reserved:0,delivered:0,expired:0,disabled:0};for(const item of inventory){const status=item.status==='available'&&item.expiresAt&&Date.parse(item.expiresAt)<=Date.now()?'expired':item.status;stock[status]=(stock[status]||0)+1;}
    const trendMap=new Map();for(const order of paid){const day=new Date(order.paidAt||order.createdAt).toISOString().slice(0,10);const t=trendMap.get(day)||{date:day,orders:0,grossCents:0,refundCents:0,costCents:0};t.orders++;t.grossCents+=order.amountCents||0;t.refundCents+=order.refundCents||0;t.costCents+=order.costCents||0;trendMap.set(day,t);}
    const deliveries=this._scope(this.store.list('deliveries'),actor,space,accountId);
    return {space,orderCount:orders.length,paidOrderCount:paid.length,grossCents,revenueCents:grossCents,refundCents,netCents:grossCents-refundCents,costCents,profitCents:grossCents-refundCents-costCents,pendingCount:orders.filter(o=>o.paymentStatus==='paid'&&!deliveries.some(d=>d.orderId===o.id&&!d.serviceId&&(!d.purpose||d.purpose==='primary')&&['sent','accepted','verified_sent'].includes(d.status))).length,unknownDeliveries:deliveries.filter(d=>d.status==='unknown').length,inventory:stock,availableInventory:stock.available,trend:[...trendMap.values()].sort((a,b)=>a.date.localeCompare(b.date)),excludedLocalOrders:relevant.length-orders.length,coverageComplete:false,coverageNote:space==='test'?'试运行统计，与真实营业额隔离。':'仅汇总已同步且经平台验证的订单；当前未取得完整区间覆盖证明。',comparisonPercent:null,lastSyncedAt:this._scope(this.store.list('accounts'),actor,space,accountId).map(a=>a.lastSyncedAt).filter(Boolean).sort().at(-1)||null};
  }
  createBackup(actor) {
    if(actor.role!=='owner')fail('FORBIDDEN','备份业务资料仅限所有者。');
    const records={};for(const kind of KINDS.filter(k=>k!=='members'))records[kind]=this.store.list(kind).map(record=>{const r=copy(record);delete r.apiKey;delete r.credentialRef;return r;});
    return {format:'lianpu-backup',version:1,createdAt:now(),records,containsCredentials:false};
  }
  _backupData(data) {
    if(typeof data==='string'){if(data.length>50*1024*1024)fail('VALIDATION','恢复包过大。');try{data=JSON.parse(data);}catch{fail('VALIDATION','恢复包不是有效 JSON。');}}
    if(!data||data.format!=='lianpu-backup'||data.version!==1||!data.records||typeof data.records!=='object')fail('VALIDATION','恢复包格式或版本不受支持。');
    const errors=[];let total=0;
    for(const [kind,rows]of Object.entries(data.records)){
      if(!KINDS.includes(kind)||kind==='members'||!Array.isArray(rows)){errors.push({kind,message:'恢复包包含不支持的数据类型。'});continue;}
      if(rows.length>100000)fail('VALIDATION','恢复包记录过多。');const seen=new Set();
      rows.forEach((r,index)=>{total++;if(!r||typeof r.id!=='string'||!['live','test'].includes(r.space)||Object.keys(r).some(k=>!BASE.includes(k)&&!FIELDS[kind].includes(k))||seen.has(r.id)){errors.push({kind,row:index+1,message:'记录编号、空间、字段或重复项无效。'});return;}seen.add(r.id);if(r.apiKey||r.credentialRef)errors.push({kind,row:index+1,message:'普通恢复包不得包含凭据。'});if(JSON.stringify(r).length>1000000)errors.push({kind,row:index+1,message:'单条记录过大。'});});
    }
    return {data,errors,total};
  }
  previewBackup({data},actor) {
    if(actor.role!=='owner')fail('FORBIDDEN','恢复资料仅限所有者。');const parsed=this._backupData(data);
    const counts={added:0,existing:0,protected:0};for(const [kind,rows]of Object.entries(parsed.data.records))if(Array.isArray(rows)&&KINDS.includes(kind))for(const record of rows){if(record?.id&&this.store.get(kind,record.id)){counts.existing++;if(['deliveries','messages','inventory','orders','audit','orderEvents','serviceJobs'].includes(kind))counts.protected++;}else counts.added++;}
    const preview=this._putPreview('backup',{hash:hash(parsed.data)},actor);
    return {valid:parsed.errors.length===0,counts,total:parsed.total,errors:parsed.errors,warnings:['恢复采用合并，现有送达、待核验、库存占用与平台订单事实不会被旧包覆盖。','恢复的新真实订单需要重新从平台核验；成员和登录凭据不在普通恢复范围内。'],confirmation:preview.id};
  }
  restoreBackup({data,confirmation},actor) {
    if(actor.role!=='owner')fail('FORBIDDEN','恢复资料仅限所有者。');const parsed=this._backupData(data);if(parsed.errors.length)fail('VALIDATION','恢复包包含无效记录，尚未更改资料。');const preview=this._getPreview(confirmation,'backup',actor);if(hash(parsed.data)!==preview.data.hash)fail('STALE_PREVIEW','恢复内容与预览不一致。');
    let added=0,preserved=0,updated=0;
    this.store.transaction(()=>{
      const restoreKinds=['accounts','assets','products','orders','deliveries','inventory',...KINDS.filter(k=>!['accounts','assets','products','orders','deliveries','inventory','members'].includes(k))];
      const assetRows=[];const pendingAssets=[...(parsed.data.records.assets||[])];
      while(pendingAssets.length){const index=pendingAssets.findIndex(asset=>asset.type!=='bundle'||(asset.items||[]).every(item=>assetRows.some(r=>r.id===item.assetId)||this.store.get('assets',item.assetId)));if(index<0)fail('INVALID_BUNDLE','恢复包组合资料存在循环或缺失依赖。');assetRows.push(pendingAssets.splice(index,1)[0]);}
      for(const kind of restoreKinds)for(const incoming of kind==='assets'?assetRows:(parsed.data.records[kind]||[])){
        const old=this.store.get(kind,incoming.id);if(old&&(old.space!==incoming.space||old.accountId!==incoming.accountId))fail('VALIDATION','恢复记录与现有账号范围冲突。');
        if(old&&['deliveries','messages','inventory','orders','audit','orderEvents','serviceJobs'].includes(kind)){preserved++;continue;}
        let record=copy(incoming);delete record.apiKey;delete record.credentialRef;
        if(kind==='accounts'){for(const key of PROTECTED.accounts){if(old?.[key]!==undefined)record[key]=copy(old[key]);else delete record[key];}record.status=record.space==='test'?'test_ready':'not_connected';record.capabilities={};record.paused=true;record.loginStatus=old?.platformUserId?'needs_login':'awaiting_scan';record.connectionStatus='disconnected';record.hosting={...record.hosting,enabled:false};record.authorizationVersion=(record.authorizationVersion||0)+1;}
        if(kind==='orders'&&!old&&record.space==='live'){record.source='local';delete record.verifiedAt;}
        if(kind==='deliveries'&&!old&&['sending','sent','accepted','verified_sent'].includes(record.status)){record.status='unknown';record.reason='恢复的历史发送记录需要重新核验；禁止自动重发。';}
        if(kind==='messages'&&!old&&record.status==='sending')record.status='unknown';
        if(kind==='messages'&&record.direction==='incoming')this.store.put('_automation',{id:record.id,status:'restored_history',createdAt:now()});
        if(kind==='conversations')record.manual=true;
        if(kind==='inventory'){
          const allocation=this.store.list('deliveries').find(d=>d.inventoryIds?.includes(record.id)&&['sending','unknown','sent','accepted','verified_sent'].includes(d.status));
          if(allocation){record.status=['sent','verified_sent'].includes(allocation.status)?'delivered':'reserved';record.deliveryId=allocation.id;record.orderId=allocation.orderId;}
          else if(['reserved','delivered'].includes(record.status))record.status='disabled';
        }
        if(kind==='interactionProfiles')record.enabled=false;
        if(!READONLY.has(kind)&&!['notifications'].includes(kind))record=this._validate(kind,record,old,false);
        if(kind==='inventory'){
          this._relation('assets',record.assetId,record);str(record.content,'库存内容',true,200000);int(record.costCents,'库存成本');date(record.expiresAt,'库存有效期');record.fingerprint=hash(record.content.trim());
          if(this.store.list('inventory').some(i=>i.id!==record.id&&i.accountId===record.accountId&&i.space===record.space&&i.fingerprint===record.fingerprint))fail('DUPLICATE','恢复包库存内容与现有唯一库存重复。');
          if(!['available','reserved','delivered','expired','disabled'].includes(record.status))fail('VALIDATION','恢复包库存状态无效。');
        }
        if(kind==='deliveries'){const order=this._relation('orders',record.orderId,record);if(order.buyerId!==record.buyerId)fail('VALIDATION','恢复包交付接收方与订单不一致。');str(record.text,'交付快照',true);if(!Array.isArray(record.items)||!Array.isArray(record.inventoryIds)||!['unknown','rejected','rate_limited','blocked','verified_not_sent'].includes(record.status))fail('VALIDATION','恢复包交付事实格式无效。');}
        if(kind==='messages'){const conversation=this._relation('conversations',record.conversationId,record);if(conversation.buyerId!==record.buyerId)fail('VALIDATION','恢复包消息接收方不一致。');str(record.text,'消息内容',true,10000);}
        if(['orderEvents','serviceJobs'].includes(kind))record=this._validateRestoredServiceRecord(kind,record);
        if(incoming.createdAt){date(incoming.createdAt,'恢复记录时间');record.createdAt=old?.createdAt||incoming.createdAt;}
        if(kind==='plans')record.paused=true;
        if(kind==='rules'||kind==='replyRules'||kind==='interactionProfiles')record.enabled=false;
        this.store.put(kind,{...record,updatedAt:now()});old?updated++:added++;
      }
      this.store.remove('_previews',confirmation);this._audit(actor,'backup.restore',{id:id(),space:'live'});
    });
    return {restored:true,added,updated,preserved};
  }
  _prepareInventoryCsv(candidate,actor,duplicates) {
    if(Object.keys(candidate).some(key=>![...BASE,'assetId','content','costCents','expiresAt'].includes(key)))fail('VALIDATION','库存 CSV 包含不支持的可写字段。');
    const asset=this._record('assets',candidate.assetId,actor,'operate');if(asset.type!=='unique')fail('VALIDATION','库存 CSV 只能导入唯一库存资料。');
    if(candidate.space!==asset.space||(candidate.accountId&&candidate.accountId!==asset.accountId))fail('VALIDATION','库存、资料与所选账号空间不一致。');
    str(candidate.content,'库存内容',true,200000);int(candidate.costCents,'库存成本');date(candidate.expiresAt,'库存有效期');
    const fingerprint=hash(candidate.content.trim());const byId=candidate.id?this.store.get('inventory',candidate.id):null;
    const byContent=this.store.list('inventory').find(item=>item.space===asset.space&&item.accountId===asset.accountId&&item.fingerprint===fingerprint);
    if(byId&&(byId.space!==asset.space||byId.accountId!==asset.accountId||byId.assetId!==asset.id))fail('VALIDATION','已有库存不能跨账号、空间或资料移动。');
    if(byId&&byContent&&byId.id!==byContent.id)fail('DUPLICATE','该内容已经属于另一条唯一库存。');
    const duplicate=byId||byContent;
    if(duplicate&&duplicates==='update'&&['reserved','delivered'].includes(duplicate.status))fail('IN_USE','已预留或已交付库存不能通过 CSV 更新或重新入库。');
    if(duplicate&&duplicate.assetId!==asset.id&&duplicates==='update')fail('IN_USE','重复内容已属于另一份资料，不能通过 CSV 移动。');
    const record={...(duplicate||{}),id:duplicate?.id||candidate.id||id(),space:asset.space,accountId:asset.accountId,assetId:asset.id,content:candidate.content,costCents:candidate.costCents??duplicate?.costCents??0,expiresAt:candidate.expiresAt||undefined,fingerprint,status:duplicate?.status||'available',createdAt:duplicate?.createdAt||now(),updatedAt:now()};
    if(record.status==='available'&&record.expiresAt&&Date.parse(record.expiresAt)<=Date.now())record.status='expired';
    return {record,duplicate};
  }
  previewImport({kind,csv,space='live',accountId,assetId,mapping,duplicates='skip'},actor) {
    if(!['assets','products','orders','customers','snippets','inventory'].includes(kind))fail('VALIDATION','此资料类型不支持普通 CSV 导入。');if(!['skip','update'].includes(duplicates))fail('VALIDATION','请选择跳过或更新重复项。');
    const cells=parseCsv(csv);if(!cells.length)fail('VALIDATION','CSV 没有表头。');const header=cells[0];if(new Set(header).size!==header.length)fail('VALIDATION','CSV 表头重复。');
    const rows=[],errors=[],dupes=[];const seen=new Set();
    for(let index=1;index<cells.length;index++){
      const line=cells[index];if(line.every(v=>v===''))continue;
      try{
        if(line.length!==header.length)fail('VALIDATION','本行列数与表头不一致。');const safeFormat=header.indexOf('_format')>=0&&line[header.indexOf('_format')]==='lianpu-csv-v1';const candidate={space,...(accountId?{accountId}:{}),...(kind==='inventory'&&assetId?{assetId}:{} )};
        header.forEach((column,n)=>{const key=mapping?.[column]||column;if(['_format','source','verifiedAt','createdAt','updatedAt','lastSyncedAt','paidAt','platformStatus','platformReceiptId'].includes(key)||(kind==='inventory'&&['status','orderId','deliveryId','batchId','fingerprint','adjustments'].includes(key)))return;const value=unprotect(line[n],safeFormat);if(!value)return;candidate[key]=value;});
        if(candidate.space!==space||(accountId&&candidate.accountId!==accountId)||(kind==='inventory'&&assetId&&candidate.assetId!==assetId))fail('VALIDATION','CSV 行超出本次选择的空间、账号或资料范围。');
        for(const [key,value]of Object.entries(candidate)){
          if(key.endsWith('Cents')||['stock','quantity','threshold','version'].includes(key)){if(!/^\d+$/.test(value))fail('VALIDATION',`${key}应为整数。`);candidate[key]=Number(value);}
          if(['variants','items','images','tags'].includes(key)){try{candidate[key]=JSON.parse(value);}catch{fail('VALIDATION',`${key}应为有效 JSON 列表。`);}}
        }
        let duplicate=candidate.id?this.store.get(kind,candidate.id):kind==='orders'?this.store.list(kind).find(r=>r.accountId===candidate.accountId&&r.externalId===candidate.externalId):null;
        if(duplicate)candidate.id=duplicate.id;
        let record;if(kind==='inventory'){const prepared=this._prepareInventoryCsv(candidate,actor,duplicates);record=prepared.record;duplicate=prepared.duplicate;}else record=this._validate(kind,candidate,duplicate);this._check(actor,record,kind==='customers'||kind==='snippets'?'write':'operate');
        const unique=kind==='inventory'?`${record.space}:${record.accountId}:${record.fingerprint}`:record.id;if(seen.has(unique))fail('DUPLICATE','文件内有重复记录编号或唯一内容。');seen.add(unique);
        rows.push({row:index+1,record,duplicate:!!duplicate,skip:!!duplicate&&duplicates==='skip',fingerprint:duplicate?hash(duplicate):null});if(duplicate)dupes.push({row:index+1,id:duplicate.id,action:duplicates});
      }catch(error){errors.push({row:index+1,message:error.message});}
    }
    const preview=this._putPreview('import',{kind,space,rows,errors,duplicates},actor);
    return {id:preview.id,previewId:preview.id,total:cells.length-1,valid:rows.filter(r=>!r.skip).length,rows:rows.map(r=>({row:r.row,record:this._public(kind,r.record,actor),duplicate:r.duplicate,skip:r.skip})),duplicates:dupes,errors,canImport:errors.length===0};
  }
  applyImport({previewId},actor) {
    const preview=this._getPreview(previewId,'import',actor);const {kind,rows,errors}=preview.data;if(errors.length)fail('IMPORT_ERRORS','预览存在错误行，请修正后重新导入；尚未改动业务数据。');let imported=0,skipped=0;
    this.store.transaction(()=>{for(const item of rows){this._check(actor,item.record,kind==='customers'||kind==='snippets'?'write':'operate');if(item.skip){skipped++;continue;}const current=this.store.get(kind,item.record.id);if(item.fingerprint!== (current?hash(current):null))fail('STALE_PREVIEW','数据在预览后已变化，请重新预览。');let record;if(kind==='inventory'){const candidate=Object.fromEntries([...BASE,'assetId','content','costCents','expiresAt'].filter(key=>item.record[key]!==undefined).map(key=>[key,item.record[key]]));const prepared=this._prepareInventoryCsv(candidate,actor,preview.data.duplicates);if(prepared.record.id!==item.record.id||!!prepared.duplicate!==!!current)fail('STALE_PREVIEW','预览后出现了相同唯一内容，请重新预览。');record={...prepared.record,batchId:current?.batchId||previewId};}else record=this._validate(kind,item.record,current);this.store.put(kind,record);imported++;}this.store.remove('_previews',previewId);this._audit(actor,'data.import',{id:previewId,space:preview.data.space});});return {imported,skipped};
  }
  exportData({kind,space='live',accountId},actor) {
    if(!FIELDS[kind]||kind==='members')fail('VALIDATION','此类型不支持导出。');if(!['owner','operator'].includes(actor.role))fail('FORBIDDEN','导出内容需要经营成员或所有者权限。');
    const rows=this._scope(this.store.list(kind),actor,space,accountId).map(record=>this._public(kind,record,actor));const columns=[...BASE,...FIELDS[kind]].filter(k=>!['apiKey','credentialRef'].includes(k));
    return {filename:`lianpu-${space}-${kind}-${now().slice(0,10)}.csv`,csv:exportCsv(rows,columns),count:rows.length,space,exportedAt:now(),sourceNote:'数据来自本机档案，真实平台来源与同步时间以各记录为准。'};
  }
  diagnostics(actor) {
    if(actor.role!=='owner')fail('FORBIDDEN','诊断导出仅限所有者。');
    return {format:'lianpu-diagnostics',version:1,createdAt:now(),runtime:{node:process.versions.node,platform:process.platform,arch:process.arch},counts:Object.fromEntries(KINDS.map(k=>[k,this.store.list(k).length])),accounts:this.store.list('accounts').map(a=>({id:hash(a.id).slice(0,12),space:a.space,status:a.status,paused:a.paused,capabilities:a.capabilities})),pending:{unknownDeliveries:this.store.list('deliveries').filter(d=>d.status==='unknown').length,unknownMessages:this.store.list('messages').filter(d=>d.status==='unknown').length},audit:this.store.list('audit').slice(-200).map(a=>({at:a.createdAt,action:a.action,result:a.result,code:a.code})),privacy:'已排除凭据、买家身份、资料内容、链接、提取码及消息正文。'};
  }
  async testIntegration({id:integrationId},actor,generation) {
    const integration=this._record('integrations',integrationId,actor,'owner');
    if(!this.connector?.testIntegration)return {status:'blocked',reason:'尚未接入此类外部服务的连接测试能力。'};
    this._fresh(actor,generation);let response;try{response=await this.connector.testIntegration(integration);}catch{response={status:'failed',reason:'外部服务连接失败，请检查地址及授权。'};}
    this._fresh(actor,generation);this._record('integrations',integrationId,actor,'owner');const status=response?.status==='verified'?'verified':'failed';const result={...integration,status,reason:sanitizeText(response?.reason),updatedAt:now()};this.store.put('integrations',result);this._audit(actor,'integration.test',result,status);return {status,reason:result.reason,models:response?.models||[]};
  }
  testNotification({space='live',accountId,channel='local'},actor) {
    if(accountId)this._record('accounts',accountId,actor,'write');else if(actor.role!=='owner')fail('FORBIDDEN','此操作仅限所有者。');
    if(channel!=='local')return {status:'blocked',reason:'该通知渠道尚未完成真实连接验证。',preview:{title:'联铺测试提醒',body:'这是一条由你主动发起的测试提醒。'}};
    const notification={id:id(),space,accountId,type:'test',title:'联铺测试提醒',body:'这是一条由你主动发起的本机测试提醒。',channel:'local',status:'available',read:false,createdAt:now(),updatedAt:now()};this.store.put('notifications',notification);return notification;
  }
  markNotification({id:notificationId,read=true},actor) {if(typeof read!=='boolean')fail('VALIDATION','已查看状态无效。');const record=this._record('notifications',notificationId,actor,'write');const result={...record,read,updatedAt:now()};this.store.put('notifications',result);return result;}
  async runPlan({id:planId},actor,generation) {
    const plan=this._record('plans',planId,actor,'operate');if(!plan.enabled||plan.paused)return {status:'paused',reason:'计划尚未启用或已暂停。'};
    if(plan.scheduledAt&&Date.parse(plan.scheduledAt)>Date.now())return {status:'waiting',reason:'计划尚未到执行时间。'};
    const prior=plan.results?.at(-1);if(prior&&['unknown','running','needs_attention'].includes(prior.status))return {status:'blocked',reason:'此前计划结果需要处理，不能自动重复执行。'};
    if(prior&&(!plan.frequencyMinutes||Date.now()-Date.parse(prior.at)<plan.frequencyMinutes*60000))return {status:'waiting',reason:'计划已执行或尚未到下一次间隔。'};
    const preview=this.previewBatch({ids:plan.productIds,changes:{action:plan.action,...(plan.action==='activate'?{status:'active'}:plan.action==='deactivate'?{status:'inactive'}:{})}},actor);
    const marker={at:now(),status:'running',previewId:preview.id};this.store.put('plans',{...plan,results:[...(plan.results||[]),marker],status:'running',updatedAt:now()});
    const batch=await this.executeBatch({previewId:preview.id},actor,generation);const current=this.store.get('plans',plan.id);current.results[current.results.length-1]={...marker,status:batch.status,batchId:batch.id};current.status=batch.status;current.updatedAt=now();this.store.put('plans',current);return batch;
  }
  async externalExtension(action,payload,actor,generation) {
    let record;
    if(payload.orderId)record=this._record('orders',payload.orderId,actor,'operate');else if(payload.id&&action==='afterSales.execute')record=this._record('afterSales',payload.id,actor,'operate');else if(payload.accountId)record=this._record('accounts',payload.accountId,actor,'operate');else fail('VALIDATION','请选择此扩展所属的账号或订单。');
    const names={'afterSales.execute':'平台退款或售后状态操作','logistics.execute':'真实物流发货','supplier.execute':'外部采购或直充','downloadPage.create':'独立领取页托管','interaction.execute':'平台买家互动'};
    // Presence of a configuration is never accepted as evidence of external execution.
    this._fresh(actor,generation);const result={status:'blocked',action,reason:`${names[action]}尚未完成适用接口、授权和真实回执验证。此操作未执行。`,requirements:action==='downloadPage.create'?['经授权的文件托管与领取服务','可验证的访问记录和限制']:['适用于此账号的正式能力','执行前范围与内容预览','真实接口回执']};this._audit(actor,action,record,'blocked');return result;
  }
  _automationEnabled(record,operation,actor) {
    const account=this.store.get('accounts',record.accountId||record.id);if(!account||account.paused||account.archived)return false;
    if(this.backgroundContexts.has(actor)){this._background(actor);return this.store.get('_hosting',account.id)?.actions?.includes(operation)===true;}
    return record.space==='test'&&this._settings(record).autoEnabled===true;
  }
  async automationTick({space,accountId},actor,generation) {
    if(!['owner','operator'].includes(actor.role))return {status:'blocked',reason:'当前成员没有自动经营权限。'};
    this.tickingAccounts ||= new Set();const tickKey=accountId||'*';if(this.tickingAccounts.has(tickKey))return {status:'running',reason:'上一轮自动处理尚未结束。'};this.tickingAccounts.add(tickKey);
    const report={status:'ok',processed:0,deliveries:[],services:[],replies:[],plans:[],skipped:[]};
    try{
      const allowed=r=>(!space||r.space===space)&&(!accountId||r.accountId===accountId||r.id===accountId)&&(actor.role==='owner'||actor.accountIds.includes(r.accountId||r.id));
      for(const order of this.store.list('orders').filter(allowed)){
        this._fresh(actor,generation);const account=this.store.get('accounts',order.accountId);if(!this._automationEnabled(order,'paidDelivery',actor))continue;
        if(order.space==='live') {const enabledAt=Date.parse(this.store.get('_hosting',account.id)?.enabledAt),paidAt=Date.parse(order.paidAt);if(order.tradeStatus!=='paid'||!Number.isFinite(paidAt)||!Number.isFinite(enabledAt)||paidAt<enabledAt){this._explain(actor,'automation.delivery',order,['历史订单或待交付状态未明确，请人工核验；托管不会自动回放历史成交。']);continue;}}
        const attempt=this.store.list('deliveries').filter(d=>d.orderId===order.id&&!d.serviceId&&(!d.purpose||d.purpose==='primary')).at(-1);if(attempt)continue; // Every retry after an attempt requires an explicit operator decision.
        const preview=this.deliveryPreview(order.id,actor);if(!preview.eligible){report.skipped.push({orderId:order.id,reasons:preview.reasons});this._explain(actor,'automation.delivery',order,preview.reasons);continue;}
        try{report.deliveries.push(await this.deliver({orderId:order.id},actor,generation,false));}catch(error){report.skipped.push({orderId:order.id,reasons:[sanitizeText(error.message)]});}
      }
      for(const job of this.store.list('serviceJobs').filter(allowed)){
        this._fresh(actor,generation);if(!this._automationEnabled(job,'services',actor)||job.status==='stopped'||job.deliveryIds?.length)continue;
        if(this._settings(job).excludedProductIds?.includes(job.productId)){const reasons=['此商品已排除自动回复与后续主动服务，需经营成员明确处理。'];report.skipped.push({serviceId:job.id,reasons});this._explain(actor,'automation.service',job,reasons);continue;}
        const preview=this.servicePreview({id:job.id},actor);if(!preview.eligible){report.skipped.push({serviceId:job.id,reasons:preview.reasons});this._explain(actor,'automation.service',job,preview.reasons);continue;}
        try{report.services.push(await this.executeService({id:job.id},actor,generation,false));}catch(e){report.skipped.push({serviceId:job.id,reasons:[sanitizeText(e.message)]});}
      }
      for(const incoming of this.store.list('messages').filter(m=>allowed(m)&&m.direction==='incoming')){
        this._fresh(actor,generation);if(this.store.get('_automation',incoming.id))continue;
        const conversation=this.store.get('conversations',incoming.conversationId);const account=this.store.get('accounts',incoming.accountId);if(!conversation||conversation.manual||conversation.blocked||account?.paused)continue;
        const settings=this._settings(conversation);if(!this._automationEnabled(conversation,'replies',actor))continue;
        const enabledAt=this.backgroundContexts.has(actor)?this.store.get('_hosting',account.id)?.enabledAt:settings.autoEnabledAt;
        const received=Date.parse(incoming.receivedAt);if(!Number.isFinite(received)||Date.now()-received>300000||received>Date.now()+30000||received<Date.parse(enabledAt||now()))continue;
        const stopReasons=this._autoReplyReasons(conversation);if(stopReasons.length){report.skipped.push({messageId:incoming.id,reasons:stopReasons});this._explain(actor,'automation.reply',incoming,stopReasons);this.store.put('_automation',{id:incoming.id,status:'policy_skipped',createdAt:now()});continue;}
        const reply=this.replyPreview({conversationId:conversation.id,text:incoming.text,includeDefault:false},actor);let draft=reply,origin=reply.rule?`rule:${reply.rule.id}`:'ai';
        if(!reply.eligible&&settings.aiEnabled){draft=await this.aiPreview({conversationId:conversation.id,text:incoming.text},actor,generation);origin=draft.priceCents!=null?'ai:negotiation':'ai';if(!draft.constrained)draft={...draft,eligible:false,reasons:['自由生成答复需要人工审阅，未自动发送。']};}
        if(!draft.eligible&&settings.defaultReply){const fallback=this.replyPreview({conversationId:conversation.id,text:incoming.text,includeDefault:true,onlyDefault:true},actor);if(fallback.eligible&&fallback.rule?.id.startsWith('default:')){draft=fallback;origin=`rule:${fallback.rule.id}`;}}
        if(!draft.eligible){report.skipped.push({messageId:incoming.id,reasons:draft.reasons});this._explain(actor,'automation.reply',incoming,draft.reasons);this.store.put('_automation',{id:incoming.id,status:'needs_attention',createdAt:now()});continue;}
        this._fresh(actor,generation);const current=this._record('conversations',conversation.id,actor,'write');if(this._autoReplyReasons(current).length||(current.generation||0)!==(conversation.generation||0)||!this._automationEnabled(current,'replies',actor))continue;
        this.store.put('_automation',{id:incoming.id,status:'sending',conversationId:conversation.id,createdAt:now()});
        try{const sent=await this.sendMessage({conversationId:conversation.id,text:draft.text},actor,generation);this.store.put('messages',{...this.store.get('messages',sent.id),origin});this.store.put('_automation',{id:incoming.id,status:sent.status,messageId:sent.id,createdAt:now()});report.replies.push(sent);}catch(error){this.store.put('_automation',{id:incoming.id,status:'blocked',reason:sanitizeText(error.message),createdAt:now()});}
      }
      for(const plan of this.store.list('plans').filter(p=>allowed(p)&&p.enabled&&!p.paused&&this._automationEnabled(p,'plans',actor))){this._fresh(actor,generation);try{report.plans.push(await this.runPlan({id:plan.id},actor,generation));}catch(error){report.skipped.push({planId:plan.id,reasons:[sanitizeText(error.message)]});}}
      for(const asset of this.store.list('assets').filter(a=>allowed(a)&&a.type==='unique')){const count=this.store.list('inventory').filter(i=>i.assetId===asset.id&&i.status==='available'&&(!i.expiresAt||Date.parse(i.expiresAt)>Date.now())).length;if(count<=(asset.threshold||0))this._notice(asset,'low_stock','唯一库存不足',`可用库存剩余 ${count} 份，请检查并补充。`);}
      report.processed=report.deliveries.length+report.services.length+report.replies.length+report.plans.filter(p=>p.id).length;return report;
    }finally{this.tickingAccounts.delete(tickKey);}
  }
  seed(actor) {
    if(actor.role!=='owner')fail('FORBIDDEN','建立试运行资料仅限所有者。');
    const accountId='test-account-1';if(this.store.get('accounts',accountId))return {created:false,space:'test',accountId,reason:'试运行资料已存在。'};
    const base={space:'test',accountId,createdAt:now(),updatedAt:now()};
    this.store.transaction(()=>{
      this.store.put('accounts',{...base,id:accountId,name:'我的试运行店铺',mode:'test',status:'test_ready',paused:false,capabilities:{sendMessage:true,readOrders:true,readProducts:true,readMessages:true,mutateProduct:true},testOutcome:'sent',note:'所有试运行数据仅保存在本机；不会发给真实买家。'});
      this.store.put('assets',{...base,id:'test-asset-fixed',name:'数字整理入门包',type:'fixed',link:'https://example.com/demo-materials',code:'DEMO',instructions:'试运行示例资料，不对应真实网盘文件。\n领取后请先阅读使用说明。\n本示例不会访问网盘或联系买家。',version:1,category:'教程',threshold:0});
      this.store.put('assets',{...base,id:'test-asset-unique',name:'练习兑换内容',type:'unique',instructions:'本内容仅用于隔离验证。',version:1,category:'兑换',threshold:2});
      this.store.put('products',{...base,id:'test-product-1',title:'数字整理入门资料',description:'用于学习资料经营流程的本机示例商品。',sku:'DEMO-001',priceCents:1990,stock:50,status:'draft',category:'数字资料',variants:[{id:'standard',name:'标准资料包',priceCents:1990,assetId:'test-asset-fixed',quantity:1}]});
      this.store.put('rules',{...base,id:'test-rule-1',name:'标准资料交付',productId:'test-product-1',variantId:'standard',assetId:'test-asset-fixed',quantity:1,enabled:false,delaySeconds:0,priority:10});
      for(let n=1;n<=3;n++)this.store.put('orders',{...base,id:`test-order-${n}`,externalId:`99000000000000000000000${n}`,buyerId:`test-buyer-${n}`,buyerName:`试运行买家 ${n}`,productId:'test-product-1',variantId:'standard',amountCents:1990,refundCents:n===3?1990:0,costCents:0,paymentStatus:n===2?'unpaid':'paid',tradeStatus:n===3?'refunded':'open',source:'test',verifiedAt:now(),paidAt:now()});
      this.store.put('conversations',{...base,id:'test-conversation-1',buyerId:'test-buyer-1',buyerName:'试运行买家 1',productId:'test-product-1',orderId:'test-order-1',manual:false,unread:1,generation:0,lastMessage:'购买后在哪里领取资料？',lastMessageAt:now()});
      this.store.put('messages',{...base,id:'test-message-1',conversationId:'test-conversation-1',buyerId:'test-buyer-1',text:'购买后在哪里领取资料？',direction:'incoming',status:'received',origin:'test',receivedAt:now()});
      this.store.put('snippets',{...base,id:'test-snippet-1',name:'领取说明',group:'常用',text:'你好 {{buyer}}，{{product}} 的领取信息将在确认付款后发送至当前会话。'});
      this.store.put('replyRules',{...base,id:'test-reply-rule-1',name:'领取方式',productId:'test-product-1',keywords:['领取'],text:'确认付款后会在当前会话发送完整资料与使用说明。如需帮助，请联系人工客服。',enabled:false,priority:10,maxReplies:1});
      for(let n=1;n<=3;n++)this.store.put('inventory',{...base,id:`test-inventory-${n}`,assetId:'test-asset-unique',content:`TEST-ONLY-CODE-00${n}`,costCents:100,status:'available',batchId:'test-initial-batch',fingerprint:hash(`TEST-ONLY-CODE-00${n}`)});
      this.store.put('settings',{id:'test-preferences',space:'test',aiEnabled:false,autoEnabled:false,minPriceCents:1500,maxNegotiations:2,background:true,createdAt:now(),updatedAt:now()});
      this._audit(actor,'test.seed',{id:accountId,...base});
    });
    return {created:true,space:'test',accountId};
  }
}

Object.assign(Service.prototype,require('./receipts.cjs').methods);
module.exports={Service,KINDS,FIELDS};
