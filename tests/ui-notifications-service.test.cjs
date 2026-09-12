'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const { randomBytes } = require('node:crypto');
const { EncryptedStore } = require('../src/core/store.cjs');
const { NotificationCenter, KINDS } = require('../src/services/notifications.cjs');

function fixture(t) {
  const store = new EncryptedStore(':memory:', randomBytes(32)); t.after(() => store.close());
  let time = Date.parse('2026-09-11T00:00:00Z'); const clock = () => time;
  for (const [id, role, accountIds] of [['owner', 'owner', []], ['op', 'operator', ['a']], ['viewer', 'viewer', ['b']]]) store.put('members', { id, name: id, role, accountIds, enabled: true });
  for (const [id, space] of [['a', 'live'], ['b', 'live'], ['test-a', 'test']]) store.put('accounts', { id, accountId: id, space, name: id, status: 'online' });
  return { store, clock, center: new NotificationCenter(store, { clock }), owner: { id: 'owner' }, op: { id: 'op' }, viewer: { id: 'viewer' }, advance: ms => { time += ms; } };
}
function facts(h, space = 'live', accountId = 'a') {
  const base = { space, accountId, createdAt: new Date(h.clock()).toISOString() };
  h.store.put('accounts', { ...h.store.get('accounts', accountId), status: 'expired' });
  h.store.put('assets', { id: 'asset', ...base, type: 'unique', threshold: 1, name: '不应进入系统提示的提取码 SECRET' });
  h.store.put('inventory', { id: 'stock', ...base, assetId: 'asset', status: 'available', content: 'SECRET-MATERIAL' });
  h.store.put('deliveries', { id: 'delivery', ...base, status: 'unknown', orderId: 'SECRET-ORDER', reason: '密码 secret / 买家 Alice' });
  h.store.put('afterSales', { id: 'request', ...base, status: 'open', dueAt: new Date(h.clock() + 300000).toISOString(), reason: 'private customer reason' });
}

// Decision: local conditions must produce alerts without enabling buyer automation; stop after four source types and one recurrence.
test('four observed events coalesce throughout one condition and recur only after recovery', t => {
  const h = fixture(t); facts(h); h.store.put('settings', { id: 'disabled', space: 'live', autoEnabled: false });
  assert.deepEqual(h.center.scan(), { created: 4, resolved: 0 });
  let list = h.center.list({ space: 'live' }, h.owner); assert.equal(list.items.length, 4);
  assert.equal(JSON.stringify(list.items.map(e => [e.title, e.body])).includes('SECRET'), false);
  const stock = list.items.find(e => e.type === 'low_stock'); h.center.markRead({ id: stock.id }, h.owner);
  for (let n = 0; n < 3; n++) assert.equal(h.center.scan().created, 0);
  assert.equal(h.center.list({ space: 'live' }, h.owner).items.find(e => e.id === stock.id).read, true);
  assert.equal(h.center.list({ space: 'live' }, h.op).items.find(e => e.id === stock.id).read, false);
  h.store.put('inventory', { id: 'more', accountId: 'a', space: 'live', assetId: 'asset', status: 'available' });
  assert.equal(h.center.scan().resolved, 1);
  h.store.put('inventory', { ...h.store.get('inventory', 'more'), status: 'reserved' }); h.advance(1000);
  assert.equal(h.center.scan().created, 1);
  list = h.center.list({ space: 'live' }, h.owner); assert.equal(list.items.filter(e => e.type === 'low_stock').length, 2);
});

// Decision: event selection and recipient scope cannot expand the member's existing account permissions.
test('accepted primary and post-receipt submissions remain pending verification without being called failures', t => {
  const h = fixture(t);
  for (const id of ['primary', 'after']) h.store.put('deliveries', { id, accountId: 'a', space: 'live', status: 'accepted', ...(id === 'after' ? { serviceId: 'service', purpose: 'after_receipt' } : {}) });
  assert.equal(h.center.scan().created, 2);
  const events = h.center.list({}, h.owner).items; assert.equal(events.length, 2);
  assert.ok(events.every(e => e.type === 'delivery_exception' && e.deliveryStatus === 'accepted' && e.body.startsWith('提交结果尚未明确')));
  h.store.put('deliveries', { ...h.store.get('deliveries', 'after'), status: 'verified_sent' }); assert.equal(h.center.scan().resolved, 1);
});

test('policy scopes recipients, accounts, types and personal read markers', t => {
  const h = fixture(t); facts(h); h.center.scan();
  h.center.saveSettings({ space: 'live', settings: { eventTypes: ['low_stock'], accountMode: 'selected', accountIds: ['a'], memberMode: 'selected', memberIds: ['op'] } }, h.owner);
  assert.equal(h.center.list({ space: 'live' }, h.owner).items.length, 0);
  assert.equal(h.center.list({ space: 'live' }, h.op).items.length, 1);
  assert.equal(h.center.list({ space: 'live' }, h.viewer).items.length, 0);
  assert.throws(() => h.center.list({ space: 'live', accountId: 'b' }, h.op), { code: 'FORBIDDEN' });
  assert.throws(() => h.center.saveSettings({ settings: { enabled: false } }, h.op), { code: 'FORBIDDEN' });
  assert.throws(() => h.center.saveSettings({ space: 'live', settings: { accountIds: ['test-a'] } }, h.owner), { code: 'INVALID_INPUT' });
  const event = h.center.list({ space: 'live' }, h.op).items[0]; h.center.markRead({ id: event.id }, h.op);
  assert.throws(() => h.center.markRead({ id: event.id }, h.viewer), { code: 'FORBIDDEN' });
  h.store.put('members', { ...h.store.get('members', 'op'), accountIds: [] });
  assert.equal(h.center.list({ space: 'live' }, h.op).items.length, 0);
});

// Decision: many simultaneous events cause one generic OS submit, and an interrupted submit must not become an automatic duplicate.
test('native digest is delayed, aggregated, private and restart-safe per member', t => {
  const h = fixture(t); facts(h); h.center.scan(); assert.equal(h.center.prepareDigest({}, h.owner), null);
  h.advance(60000); const first = h.center.prepareDigest({}, h.owner); assert.equal(first.count, 4);
  assert.equal(/SECRET|Alice|password|private/.test(first.title + first.body), false);
  assert.equal(h.center.prepareDigest({}, h.owner), null);
  const restarted = new NotificationCenter(h.store, { clock: h.clock }); assert.equal(restarted.prepareDigest({}, h.owner), null);
  restarted.finishDigest({ id: first.id, status: 'submitted' }); h.advance(60000); assert.equal(restarted.prepareDigest({}, h.owner), null);
  assert.equal(restarted.prepareDigest({}, h.op).count, 4);
  assert.equal(restarted.list({}, h.owner).items[0].nativeStatus, 'submitted');
});

// Decision: a failing Windows channel should stop retrying after a bounded number and keep a truthful failure state.
test('failed submissions retry at the merge interval at most three times', t => {
  const h = fixture(t); facts(h); h.center.scan();
  for (let n = 0; n < 3; n++) { h.advance(60000); const attempt = h.center.prepareDigest({}, h.owner); assert.ok(attempt); h.center.finishDigest({ id: attempt.id, status: 'failed' }); assert.equal(h.center.prepareDigest({}, h.owner), null); }
  h.advance(60000); assert.equal(h.center.prepareDigest({}, h.owner), null);
  assert.equal(h.center.list({}, h.owner).items[0].nativeStatus, 'failed');
});

// Decision: test previews must not fabricate business alerts or send automatic test-space notifications; due reminders honor the selected lead time.
test('test preview has no writes and test events never enter automatic Windows delivery', t => {
  const h = fixture(t); const before = h.store.list(KINDS.events).length;
  const preview = h.center.preview({ space: 'test', type: 'after_sales_due', accountId: 'test-a' }, h.owner);
  assert.equal(preview.title, '联铺 · 本机测试通知'); assert.match(preview.body, /由你发起/); assert.equal(h.store.list(KINDS.events).length, before);
  facts(h, 'test', 'test-a'); h.center.saveSettings({ space: 'test', settings: { afterSalesLeadMinutes: 0 } }, h.owner);
  assert.equal(h.center.scan().created, 3); h.advance(300000); assert.equal(h.center.scan().created, 1);
  h.advance(60000); assert.equal(h.center.prepareDigest({ space: 'test' }, h.owner), null);
  h.store.put('afterSales', { ...h.store.get('afterSales', 'request'), status: 'closed' }); assert.equal(h.center.scan().resolved, 1);
});

// Decision: encrypted backup restore should preserve current acknowledgements and never replay historical system notifications.
test('notification backup validation and merge suppress restored alert replay', t => {
  const h = fixture(t); facts(h); h.center.scan(); const read = h.center.list({}, h.owner).items[0]; h.center.markRead({ id: read.id }, h.owner);
  const backup = h.center.exportBackup(); assert.equal(h.center.validateBackup(backup).valid, true);
  const bad = structuredClone(backup); bad.policies.push({ id: 'live', settings: { ...h.center.policy('live'), channel: 'external' } });
  assert.throws(() => h.center.restoreBackup(bad), { code: 'BACKUP_NOTIFICATIONS' });
  const other = fixture(t); facts(other); const merged = other.center.restoreBackup(backup); assert.equal(merged.restored, 4);
  other.advance(120000); other.center.scan(); assert.equal(other.center.prepareDigest({}, other.owner), null);
  assert.equal(other.center.list({}, other.owner).items.find(e => e.id === read.id).read, true);
  assert.equal(other.center.list({}, other.owner).items[0].nativeStatus, 'suppressed_restore');
  assert.equal(other.center.restoreBackup(backup).preserved, 4);
});
