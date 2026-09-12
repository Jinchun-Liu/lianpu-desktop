'use strict';
// Hypothesis: F44 controls correspond to real scope/consumer fields, and a preview
// cannot create a business event or send a system notification. Decision: accept
// the new notification workflow. Stop at the first mismatch; isolated vault only.
const { _electron } = require('playwright-core');
const fs = require('node:fs'), path = require('node:path'), assert = require('node:assert/strict');
const project = path.resolve(__dirname, '..'), vault = path.join(project, 'work', `ui-notifications-${Date.now()}`);
fs.mkdirSync(vault, { recursive: true });
const env = { ...process.env, LIANPU_DATA_DIR: vault }; delete env.ELECTRON_RUN_AS_NODE;
let app, page; const checks = [], errors = [];
async function call(action, payload = {}) { const r = await page.evaluate(({ action, payload }) => window.desk.call(action, payload), { action, payload }); assert.equal(r.ok, true, JSON.stringify(r.error)); return r.data; }
async function close() { if (await page.locator('#dialog').isVisible()) await page.locator('#dialog [data-action="close-dialog"]').first().click(); }
const pass = name => { checks.push(name); process.stdout.write(`PASS ${name}\n`); };
(async () => { try {
  app = await _electron.launch({ executablePath: path.join(project, 'node_modules', 'electron', 'dist', 'electron.exe'), args: [project], env, timeout: 30000 }); page = await app.firstWindow(); page.on('pageerror', error => errors.push(error.message));
  await page.locator('#auth-form [name="name"]').fill('提醒核验管理员'); await page.locator('#auth-form [name="password"]').fill('Notification-local-passphrase-2026!'); await page.locator('#auth-form [name="confirmation"]').fill('Notification-local-passphrase-2026!'); await page.locator('#auth-form button[type="submit"]').click(); await page.waitForSelector('.shell'); await close();
  const owner = (await call('auth.status')).user;
  await page.locator('#space-select').selectOption('test'); await page.locator('[data-action="seed"]').click(); await page.getByRole('heading', { name: '交付凭条' }).waitFor();
  await page.locator('[data-action="navigate"][data-route="settings"]').click(); await page.locator('[data-action="notification-settings"]').click(); await page.locator('#notification-settings-form').waitFor();
  const form = page.locator('#notification-settings-form');
  for (const checkbox of await form.locator('[name="eventTypes"]').all()) await checkbox.uncheck();
  await form.locator('[name="eventTypes"][value="low_stock"]').check(); await form.locator('[name="eventTypes"][value="after_sales_due"]').check();
  await form.locator('[name="accountMode"]').selectOption('selected'); await form.locator('[name="accountIds"][value="test-account-1"]').check();
  await form.locator('[name="memberMode"]').selectOption('selected'); await form.locator(`[name="memberIds"][value="${owner.id}"]`).check();
  await form.locator('[name="afterSalesLeadMinutes"]').fill('10'); await form.locator('[name="mergeWindowSeconds"]').fill('90');
  assert.equal(await form.locator('[name="afterSalesLeadMinutes"]').inputValue(), '10'); assert.equal(await form.locator('[name="mergeWindowSeconds"]').inputValue(), '90');
  await form.locator('button[type="submit"]').click(); await page.waitForFunction(() => document.querySelector('#toast').textContent === '当前工作区的提醒规则已保存。');
  const policy = (await call('notifications.settings.get', { space: 'test' })).settings;
  assert.deepEqual(policy.eventTypes, ['low_stock', 'after_sales_due']); assert.equal(policy.afterSalesLeadMinutes, 10); assert.equal(policy.mergeWindowSeconds, 90); assert.deepEqual(policy.accountIds, ['test-account-1']); assert.deepEqual(policy.memberIds, [owner.id]);
  assert.equal((await call('notifications.settings.get', { space: 'live' })).settings.accountMode, 'all'); await close(); pass('notification form persists actual event, account, member and timing scope without modifying live settings');

  await page.locator('[data-action="navigate"][data-route="afterSales"]').click(); await page.locator('[data-action="edit"][data-kind="afterSales"]').first().click();
  const future = new Date(Date.now() + 5 * 60000); future.setSeconds(0, 0); const localDue = new Date(future.getTime() - future.getTimezoneOffset() * 60000).toISOString().slice(0, 16);
  await page.locator('#entity-form [name="orderId"]').selectOption('test-order-1'); await page.locator('#entity-form [name="dueAt"]').fill(localDue); await page.locator('#entity-form [name="reason"]').fill('隔离测试售后期限，不执行平台售后'); await page.locator('#entity-form button[type="submit"]').click(); await page.waitForFunction(() => !document.querySelector('#dialog').open);
  const request = (await call('workspace.snapshot', { space: 'test' })).afterSales[0]; assert.equal(request.dueAt, future.toISOString());
  await page.locator(`[data-action="edit"][data-kind="afterSales"][data-id="${request.id}"]`).click(); assert.equal(await page.locator('#entity-form [name="dueAt"]').inputValue(), localDue); await close();
  await call('inventory.adjust', { id: 'test-inventory-1', status: 'disabled', reason: '隔离测试低库存条件' });
  await page.locator('.topbar [data-action="notifications"]').click(); await page.getByRole('heading', { name: '需要留意的经营事项' }).waitFor();
  let notifications = await call('notifications.list', { space: 'test' }); assert.equal(notifications.items.length, 2); assert.ok(notifications.items.some(n => n.type === 'after_sales_due')); assert.ok(notifications.items.some(n => n.type === 'low_stock'));
  await page.screenshot({ path: path.join(__dirname, 'ui-notifications-overview.png'), fullPage: true }); pass('local due time round-trips and real test-space inventory and after-sales facts produce scoped events');

  await page.locator('.notification-row').filter({ has: page.getByRole('heading', { name: '唯一资料库存需要补充' }) }).getByRole('button', { name: '我已查看' }).click();
  notifications = await call('notifications.list', { space: 'test' }); assert.equal(notifications.unreadCount, 1); const count = notifications.items.length;
  await page.locator('#dialog [data-action="notifications"]').click(); assert.equal((await call('notifications.list', { space: 'test' })).items.length, count);
  await page.locator('[data-action="notification-filter"]').click(); assert.equal(await page.locator('.notification-row').count(), 1); pass('personal acknowledgement and unread filter do not recreate an unchanged inventory alert');

  await page.locator('#dialog [data-action="notify-preview"]').click(); await page.locator('#notification-preview-form [name="type"]').selectOption('after_sales_due'); await page.locator('#notification-preview-form button[type="submit"]').click(); await page.getByRole('heading', { name: '核对本机测试通知' }).waitFor();
  const preview = await call('notifications.preview', { space: 'test', type: 'after_sales_due' }); assert.equal((await page.locator('#dialog .content-preview').textContent()).trim(), `${preview.title}\n${preview.body}`);
  assert.equal((await call('notifications.list', { space: 'test' })).items.length, count); assert.equal(await page.locator('#dialog [data-action="notify-send"]').count(), 1);
  await close(); pass('preview matches the main-process content exactly and requires a separate explicit system-test confirmation');
  assert.deepEqual(errors, []); const report = { verifiedAt: new Date().toISOString(), status: 'passed', checks, rendererErrors: errors, vault, screenshots: ['ui-notifications-overview.png'], scope: 'Fresh isolated test vault; no actual Windows toast, buyer message, platform action or external notification was sent' };
  fs.writeFileSync(path.join(__dirname, 'ui-notifications-result.json'), JSON.stringify(report, null, 2)); process.stdout.write(JSON.stringify(report, null, 2) + '\n');
} catch (error) { process.stderr.write(error.stack + '\n'); if(page) { try { process.stderr.write(JSON.stringify({visibleErrors:await page.locator('#page-error,.dialog-error').allTextContents(),rendererErrors:errors})+'\n');await page.screenshot({path:path.join(__dirname,'ui-notifications-failure.png'),mask:[page.locator('input[type="password"]')]}); } catch {} } process.exitCode = 1; } finally { if (app) { try { await app.evaluate(({ app }) => app.quit()); } catch {} try { await app.close(); } catch {} } } })();
