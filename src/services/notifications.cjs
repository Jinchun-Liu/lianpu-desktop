'use strict';
const { randomUUID, createHash } = require('node:crypto');
const { AccessError } = require('../auth.cjs');

const EVENTS = Object.freeze([
  { id: 'connection', name: '账号断线或登录失效' },
  { id: 'low_stock', name: '唯一资料库存不足' },
  { id: 'delivery_exception', name: '资料交付异常或待核验' },
  { id: 'after_sales_due', name: '售后处理即将到期或已逾期' }
]);
const TYPES = new Set(EVENTS.map(e => e.id));
const KINDS = Object.freeze({ policies: '_notificationPolicies', events: '_notificationEvents', reads: '_notificationReads', receipts: '_notificationReceipts', attempts: '_notificationAttempts' });
const digest = value => createHash('sha256').update(value).digest('hex');
const key = (...parts) => digest(parts.join('\0'));
function fail(message) { throw new AccessError('INVALID_INPUT', message); }
function integer(value, min, max, name) { if (!Number.isInteger(value) || value < min || value > max) fail(`${name}需要为 ${min} 到 ${max} 的整数。`); }
function spaceCheck(space) { if (!['live', 'test'].includes(space)) fail('请选择真实经营或隔离测试工作区。'); }
function defaults(space) { return { space, enabled: true, eventTypes: [...TYPES], accountMode: 'all', accountIds: [], memberMode: 'all', memberIds: [], afterSalesLeadMinutes: 60, mergeWindowSeconds: 60, channel: 'local' }; }

/** A local fact observer. No platform requests, customer messages or OS notifications. */
class NotificationCenter {
  constructor(store, { clock = () => Date.now() } = {}) { this.store = store; this.clock = clock; }
  now() { return new Date(this.clock()).toISOString(); }
  actor(actor) {
    const member = this.store.get('members', actor?.id);
    if (!member || member.enabled === false || !['owner', 'operator', 'support', 'viewer'].includes(member.role)) throw new AccessError('FORBIDDEN', '本机成员权限已经变更，请选择有效成员登录。');
    return { ...member, accountIds: member.accountIds || [] };
  }
  policy(space) { spaceCheck(space); return { ...defaults(space), ...(this.store.get(KINDS.policies, space)?.settings || {}) }; }
  account(actor, space, accountId) {
    if (!accountId) return;
    const account = this.store.get('accounts', accountId);
    if (!account || account.space !== space || (actor.role !== 'owner' && !actor.accountIds.includes(accountId))) throw new AccessError('FORBIDDEN', '无权查看此账号的经营提醒。');
  }
  getSettings({ space = 'live' } = {}, actor) {
    const member = this.actor(actor), policy = this.policy(space);
    const accounts = this.store.list('accounts').filter(a => a.space === space && (member.role === 'owner' || member.accountIds.includes(a.id))).map(a => ({ id: a.id, name: a.name }));
    const members = this.store.list('members').filter(m => m.enabled !== false && (member.role === 'owner' || m.id === member.id)).map(m => ({ id: m.id, name: m.name, role: m.role }));
    const settings = member.role === 'owner' ? policy : { ...policy, accountIds: policy.accountIds.filter(id => accounts.some(a => a.id === id)), memberIds: policy.memberIds.filter(id => id === member.id) };
    return { settings, events: EVENTS, accounts, members, canEdit: member.role === 'owner', scopeReason: this.scopeReason(policy, member) };
  }
  saveSettings({ space = 'live', settings } = {}, actor) {
    const member = this.actor(actor); spaceCheck(space);
    if (member.role !== 'owner') throw new AccessError('FORBIDDEN', '通知接收规则需要本机管理员设置。');
    if (!settings || typeof settings !== 'object' || Array.isArray(settings)) fail('通知设置格式无效。');
    const allowed = Object.keys(defaults(space));
    if (Object.keys(settings).some(name => !allowed.includes(name))) fail('通知设置含有不支持的字段。');
    const candidate = { ...this.policy(space), ...structuredClone(settings), space };
    if (settings.space !== undefined && settings.space !== space) fail('通知设置不能跨工作区保存。');
    if (typeof candidate.enabled !== 'boolean' || candidate.channel !== 'local') fail('当前仅支持本机通知；外部渠道尚待正式接入。');
    for (const name of ['eventTypes', 'accountIds', 'memberIds']) if (!Array.isArray(candidate[name]) || candidate[name].some(id => typeof id !== 'string') || new Set(candidate[name]).size !== candidate[name].length) fail('通知类型或接收范围格式无效。');
    if (candidate.eventTypes.some(id => !TYPES.has(id))) fail('包含不支持的通知类型。');
    if (!['all', 'selected'].includes(candidate.accountMode) || !['all', 'selected'].includes(candidate.memberMode)) fail('请选择全部或指定范围。');
    for (const id of candidate.accountIds) if (this.store.get('accounts', id)?.space !== space) fail('所选账号不属于当前工作区。');
    for (const id of candidate.memberIds) { const recipient = this.store.get('members', id); if (!recipient || recipient.enabled === false) fail('所选接收成员不存在或已停用。'); }
    integer(candidate.afterSalesLeadMinutes, 0, 10080, '售后提前提醒分钟');
    integer(candidate.mergeWindowSeconds, 30, 600, '提醒合并秒数');
    this.store.put(KINDS.policies, { id: space, settings: candidate, updatedAt: this.now(), updatedBy: member.id });
    return this.getSettings({ space }, member);
  }
  scopeReason(policy, actor) {
    if (!policy.enabled) return '本工作区的经营提醒已暂停。现有业务记录仍保留。';
    if (policy.memberMode === 'selected' && !policy.memberIds.includes(actor.id)) return '当前成员不在本工作区的提醒接收范围内。';
    if (!policy.eventTypes.length) return '尚未选择需要提醒的事件类型。';
    if (policy.accountMode === 'selected' && !policy.accountIds.length) return '尚未选择需要提醒的经营账号。';
    return '';
  }
  visible(event, actor, policy) {
    return event.space === policy.space && !this.scopeReason(policy, actor) && policy.eventTypes.includes(event.type) && (policy.accountMode === 'all' || policy.accountIds.includes(event.accountId)) && (actor.role === 'owner' || actor.accountIds.includes(event.accountId));
  }
  scan() {
    const now = this.clock(), at = new Date(now).toISOString(), conditions = new Map();
    const accounts = this.store.list('accounts').filter(a => ['live', 'test'].includes(a.space));
    const accountMap = new Map(accounts.map(a => [a.id, a]));
    const add = (record, type, title, body, route, detail = {}) => {
      const accountId = record.accountId || record.id, account = accountMap.get(accountId);
      if (!account || account.space !== record.space) return;
      const conditionKey = key(type, record.space, accountId, record.id);
      conditions.set(conditionKey, { conditionKey, space: record.space, accountId, type, title, body, route, sourceId: record.id, ...detail });
    };
    for (const account of accounts) if (!account.paused && ['offline', 'disconnected', 'expired', 'not_connected', 'needs_login', 'login_required', 'auth_expired', 'session_expired', 'error'].includes(account.status)) add(account, 'connection', '账号连接需要检查', '本机记录显示账号未连接或登录已失效。请打开账号页确认状态；未同步期间的数据仍需补核。', 'accounts');
    const inventory = this.store.list('inventory');
    for (const asset of this.store.list('assets')) if (asset.type === 'unique') {
      const count = inventory.filter(i => i.assetId === asset.id && i.accountId === asset.accountId && i.space === asset.space && i.status === 'available' && (!i.expiresAt || Date.parse(i.expiresAt) > now)).length;
      const threshold = Number.isSafeInteger(asset.threshold) && asset.threshold >= 0 ? asset.threshold : 0;
      if (count <= threshold) add(asset, 'low_stock', '唯一资料库存需要补充', `可用 ${count} 份，提醒阈值 ${threshold} 份。已预留、已交付和过期内容不计入可用库存。`, 'inventory', { available: count, threshold });
    }
    for (const delivery of this.store.list('deliveries')) {
      const stalled = delivery.status === 'sending' && Number.isFinite(Date.parse(delivery.submittedAt || delivery.createdAt)) && now - Date.parse(delivery.submittedAt || delivery.createdAt) >= 120000;
      if (stalled || ['unknown', 'accepted', 'failed', 'rejected', 'rate_limited', 'blocked'].includes(delivery.status)) add(delivery, 'delivery_exception', '资料交付需要核对', ['unknown', 'accepted', 'sending'].includes(delivery.status) ? '提交结果尚未明确。先核验接收情况，不能按失败自动重发。' : '本次交付没有取得成功回执。请打开订单检查原因与库存占用，再决定后续处理。', 'orders', { orderId: delivery.orderId, deliveryStatus: delivery.status });
    }
    for (const request of this.store.list('afterSales')) {
      const due = Date.parse(request.dueAt), lead = this.policy(request.space).afterSalesLeadMinutes * 60000;
      if (Number.isFinite(due) && !['closed', 'resolved', 'completed', 'canceled', 'cancelled'].includes(request.status) && due <= now + lead) add(request, 'after_sales_due', due <= now ? '售后处理期限已到' : '售后处理即将到期', '请打开本机售后档案核对处理期限。此提醒不表示平台已受理、退款或结案。', 'afterSales', { orderId: request.orderId, dueAt: new Date(due).toISOString(), overdue: due <= now });
    }
    let created = 0, resolved = 0;
    this.store.transaction(() => {
      const active = new Map(this.store.list(KINDS.events).filter(e => e.status === 'active').map(e => [e.conditionKey, e]));
      for (const [conditionKey, facts] of conditions) {
        const prior = active.get(conditionKey);
        if (!prior) { this.store.put(KINDS.events, { ...facts, id: randomUUID(), status: 'active', createdAt: at, updatedAt: at }); created++; }
        else if (Object.keys(facts).some(k => JSON.stringify(facts[k]) !== JSON.stringify(prior[k]))) this.store.put(KINDS.events, { ...prior, ...facts, updatedAt: at });
      }
      for (const prior of active.values()) if (!conditions.has(prior.conditionKey)) { this.store.put(KINDS.events, { ...prior, status: 'resolved', resolvedAt: at, updatedAt: at }); resolved++; }
    });
    return { created, resolved };
  }
  list({ space = 'live', accountId, includeRead = true } = {}, actor) {
    const member = this.actor(actor), policy = this.policy(space); this.account(member, space, accountId);
    if (typeof includeRead !== 'boolean') fail('已查看筛选格式无效。');
    const all = this.store.list(KINDS.events).filter(e => (!accountId || e.accountId === accountId) && this.visible(e, member, policy)).map(event => {
      const read = this.store.get(KINDS.reads, key(member.id, event.id)), receipt = this.store.get(KINDS.receipts, key(member.id, event.id));
      const { conditionKey, ...summary } = event;
      return { ...summary, read: !!read?.read, readAt: read?.readAt, nativeStatus: receipt?.status || 'not_submitted', nativeAt: receipt?.updatedAt };
    }).sort((a, b) => b.createdAt.localeCompare(a.createdAt));
    return { items: includeRead ? all : all.filter(e => !e.read), unreadCount: all.filter(e => !e.read && e.status === 'active').length, scopeReason: this.scopeReason(policy, member) };
  }
  markRead({ id, read = true } = {}, actor) {
    const member = this.actor(actor), event = this.store.get(KINDS.events, id);
    if (!event || !this.visible(event, member, this.policy(event.space))) throw new AccessError('FORBIDDEN', '此提醒不在当前成员的接收范围内。');
    if (typeof read !== 'boolean') fail('已查看状态无效。');
    this.store.put(KINDS.reads, { id: key(member.id, id), memberId: member.id, eventId: id, read, readAt: this.now() });
    return { id, read };
  }
  preview({ space = 'live', type = 'connection', accountId } = {}, actor) {
    const member = this.actor(actor); spaceCheck(space); this.account(member, space, accountId);
    if (!TYPES.has(type)) fail('请选择支持的提醒类型。');
    return { title: '联铺 · 本机测试通知', body: `【${EVENTS.find(e => e.id === type).name}】这是一条由你发起的测试通知，没有发送给买家。`, channel: 'local', scope: `${space === 'test' ? '隔离测试' : '真实经营'} · 当前 Windows 桌面`, type, space, reason: '测试只验证本机系统提交通道，不产生真实经营事件；系统是否显示受 Windows 通知设置影响。' };
  }
  prepareDigest({ space = 'live' } = {}, actor) {
    const member = this.actor(actor), policy = this.policy(space);
    if (space !== 'live' || this.scopeReason(policy, member)) return null;
    const candidates = this.list({ space, includeRead: false }, member).items.filter(e => e.status === 'active' && !e.restored).filter(e => {
      const receipt = this.store.get(KINDS.receipts, key(member.id, e.id));
      return !receipt || (receipt.status === 'failed' && receipt.attempts < 3 && this.clock() - Date.parse(receipt.updatedAt) >= policy.mergeWindowSeconds * 1000);
    });
    if (!candidates.length) return null;
    const oldest = Math.min(...candidates.map(e => Date.parse(e.createdAt)));
    if (this.clock() - oldest < policy.mergeWindowSeconds * 1000) return null;
    const priorAttempt = this.store.list(KINDS.attempts).filter(a => a.memberId === member.id && a.space === space).at(-1);
    if (priorAttempt && this.clock() - Date.parse(priorAttempt.createdAt) < policy.mergeWindowSeconds * 1000) return null;
    const counts = EVENTS.map(type => ({ ...type, count: candidates.filter(e => e.type === type.id).length })).filter(e => e.count);
    const attempt = { id: randomUUID(), memberId: member.id, space, eventIds: candidates.map(e => e.id), status: 'submitting', count: candidates.length, title: '联铺 · 有经营事项需要处理', body: counts.map(e => `${e.name} ${e.count} 项`).join('；') + '。请打开工作区核对。', createdAt: this.now() };
    // Persist before OS submission. A restart cannot reinterpret an uncertain submit as unsent.
    this.store.transaction(() => {
      this.store.put(KINDS.attempts, attempt);
      for (const event of candidates) { const id = key(member.id, event.id), old = this.store.get(KINDS.receipts, id); this.store.put(KINDS.receipts, { id, memberId: member.id, eventId: event.id, attemptId: attempt.id, status: 'submitting', attempts: (old?.attempts || 0) + 1, updatedAt: this.now() }); }
    });
    return { id: attempt.id, title: attempt.title, body: attempt.body, count: attempt.count };
  }
  finishDigest({ id, status } = {}) {
    if (!['submitted', 'failed', 'unknown'].includes(status)) fail('系统通知提交状态无效。');
    const attempt = this.store.get(KINDS.attempts, id); if (!attempt) throw new AccessError('NOT_FOUND', '本机通知提交记录不存在。');
    this.store.transaction(() => {
      this.store.put(KINDS.attempts, { ...attempt, status, updatedAt: this.now() });
      for (const eventId of attempt.eventIds) { const receiptId = key(attempt.memberId, eventId), old = this.store.get(KINDS.receipts, receiptId); if (old?.attemptId === id) this.store.put(KINDS.receipts, { ...old, status, updatedAt: this.now() }); }
    });
    return { id, status, reason: status === 'submitted' ? '已提交 Windows；未据此宣称通知已经显示。' : status === 'failed' ? 'Windows 通知提交失败，请检查系统通知设置。未记录任何凭据或资料内容。' : '系统提交结果未明确，保留待核验记录，不自动重试。' };
  }
  exportBackup() {
    return { version: 1, ...Object.fromEntries(Object.entries(KINDS).map(([name, kind]) => [name, this.store.list(kind)])) };
  }
  validateBackup(backup) {
    const bad = () => { throw new AccessError('BACKUP_NOTIFICATIONS', '备份中的本机通知记录格式无效。'); };
    if (!backup || backup.version !== 1 || Object.keys(backup).some(k => !['version', ...Object.keys(KINDS)].includes(k))) bad();
    for (const name of Object.keys(KINDS)) {
      const rows = backup[name];
      if (!Array.isArray(rows) || rows.length > 100000 || new Set(rows.map(r => r?.id)).size !== rows.length) bad();
      for (const r of rows) if (!r || typeof r !== 'object' || typeof r.id !== 'string' || !r.id || r.id.length > 200 || JSON.stringify(r).length > 50000) bad();
    }
    for (const p of backup.policies) {
      const s = p.settings;
      if (!['live', 'test'].includes(p.id) || !s || s.space !== p.id || typeof s.enabled !== 'boolean' || s.channel !== 'local' || !Array.isArray(s.eventTypes) || s.eventTypes.some(t => !TYPES.has(t)) || !['all', 'selected'].includes(s.accountMode) || !['all', 'selected'].includes(s.memberMode) || !Array.isArray(s.accountIds) || !Array.isArray(s.memberIds) || [...s.accountIds, ...s.memberIds].some(id => typeof id !== 'string') || !Number.isInteger(s.afterSalesLeadMinutes) || s.afterSalesLeadMinutes < 0 || s.afterSalesLeadMinutes > 10080 || !Number.isInteger(s.mergeWindowSeconds) || s.mergeWindowSeconds < 30 || s.mergeWindowSeconds > 600 || Object.keys(s).some(k => !Object.keys(defaults(p.id)).includes(k))) bad();
    }
    const eventIds = new Set(backup.events.map(e => e.id));
    for (const e of backup.events) if (!['live', 'test'].includes(e.space) || !TYPES.has(e.type) || typeof e.accountId !== 'string' || typeof e.sourceId !== 'string' || e.conditionKey !== key(e.type, e.space, e.accountId, e.sourceId) || !['active', 'resolved'].includes(e.status) || !Number.isFinite(Date.parse(e.createdAt)) || typeof e.title !== 'string' || e.title.length > 100 || typeof e.body !== 'string' || e.body.length > 500 || !['accounts', 'inventory', 'orders', 'afterSales'].includes(e.route)) bad();
    for (const r of backup.reads) if (typeof r.memberId !== 'string' || !eventIds.has(r.eventId) || r.id !== key(r.memberId, r.eventId) || typeof r.read !== 'boolean') bad();
    for (const r of backup.receipts) if (typeof r.memberId !== 'string' || !eventIds.has(r.eventId) || r.id !== key(r.memberId, r.eventId) || !['submitting', 'submitted', 'failed', 'unknown', 'suppressed_restore'].includes(r.status)) bad();
    for (const a of backup.attempts) if (typeof a.memberId !== 'string' || !['live', 'test'].includes(a.space) || !Array.isArray(a.eventIds) || a.eventIds.some(id => !eventIds.has(id)) || !['submitting', 'submitted', 'failed', 'unknown'].includes(a.status)) bad();
    return { valid: true, counts: Object.fromEntries(Object.keys(KINDS).map(name => [name, backup[name].length])), warnings: ['恢复的历史通知不会自动再次提交通知；现有成员已查看记录保留。'] };
  }
  restoreBackup(backup) {
    this.validateBackup(backup);
    let restored = 0, preserved = 0;
    this.store.transaction(() => {
      const members = this.store.list('members').filter(m => m.enabled !== false), accounts = this.store.list('accounts');
      for (const p of backup.policies) if (!this.store.get(KINDS.policies, p.id)) {
        const settings = { ...p.settings, accountIds: p.settings.accountIds.filter(id => accounts.some(a => a.id === id && a.space === p.id)), memberIds: p.settings.memberIds.filter(id => members.some(m => m.id === id)) };
        this.store.put(KINDS.policies, { id: p.id, settings, updatedAt: this.now() });
      }
      const currentEvents = this.store.list(KINDS.events);
      for (const event of backup.events) {
        if (this.store.get(KINDS.events, event.id) || currentEvents.some(e => e.conditionKey === event.conditionKey && e.status === 'active')) { preserved++; continue; }
        if (!accounts.some(a => a.id === event.accountId && a.space === event.space)) continue;
        this.store.put(KINDS.events, { ...event, restored: true }); restored++;
        for (const member of members) this.store.put(KINDS.receipts, { id: key(member.id, event.id), memberId: member.id, eventId: event.id, status: 'suppressed_restore', attempts: 0, updatedAt: this.now() });
      }
      for (const read of backup.reads) if (members.some(m => m.id === read.memberId) && this.store.get(KINDS.events, read.eventId) && !this.store.get(KINDS.reads, read.id)) this.store.put(KINDS.reads, read);
      // Historical OS attempts never return to the retry queue after a restore.
    });
    return { restored, preserved, reason: '已合并本机通知设置和事件；历史通知不自动再次弹出，现有已查看状态保留。' };
  }
}
module.exports = { NotificationCenter, EVENTS, KINDS };
