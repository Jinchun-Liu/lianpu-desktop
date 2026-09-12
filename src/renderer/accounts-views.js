/* 联铺 v1.4 account views. Independent business UI using existing local primitives.
 * No IPC, storage, credentials, remote assets or account mutations in this module.
 * Status fields come from the main process; legacy account.status never proves login.
 */
(() => {
  'use strict';
  const loginLabels = Object.freeze({
    awaiting_scan: '等待本人扫码', needs_login: '需要重新登录', checking: '正在核验登录',
    waiting: '等待本人扫码', scanned: '已观察到扫码，等待本人确认',
    scanned_pending_confirmation: '已观察到扫码，等待本人确认', success: '扫码结果已返回，待绑定核验',
    authenticated: '登录已核验', cleared: '本机登录已清除',
    login_required: '需要重新登录', verification_required: '需要本人验证',
    expired: '登录已过期', cancelled: '登录已取消', failed: '登录未完成',
    unverified: '登录状态待核验', identity_mismatch: '扫码身份不匹配',
    revoked: '本机登录已清除', revocation_failed: '本机登录未完整清除',
  });
  const connectionLabels = Object.freeze({
    connected: '消息已连接', disconnected: '消息未连接', connecting: '正在检查连接',
    verification_required: '连接需要本人验证', login_required: '连接需要重新登录',
    unavailable: '消息连接不可用', blocked: '消息连接受阻', timeout: '连接检查超时',
    rate_limited: '连接受平台限流', identity_mismatch: '连接身份不匹配',
    unverified: '消息连接待核验', revoked: '消息连接已撤回', revocation_failed: '连接清除未完成',
  });
  const featureLabels = Object.freeze({
    sync: '同步商品、订单和消息', replies: '按已配置规则自动客服',
    paidDelivery: '向已付款买家交付资料', services: '收货后服务', plans: '商品运营计划',
  });
  const filters = Object.freeze([
    ['all', '全部账号'], ['hosting', '已授权托管'], ['paused', '已暂停'],
    ['login-needed', '登录需处理'], ['archived', '已归档'],
  ]);
  const text = value => typeof value === 'string' ? value : '';
  const archived = account => account?.archived === true;
  const isTest = account => account?.space === 'test' || account?.mode === 'test';
  const platformId = account => text(account?.platformUserId) || text(account?.externalId);
  const hasIdentity = account => !!platformId(account) && !!text(account?.identityEvidenceId) && Number.isFinite(Date.parse(account?.identityVerifiedAt));
  const hostingKey = account => archived(account) ? 'archived' : account?.paused === true ? 'paused' : account?.hosting?.enabled === true ? 'enabled' : account?.hosting?.enabled === false ? 'disabled' : 'unknown';
  const unknown = (value, fallback) => text(value) ? `待核验（${value}）` : fallback;

  function status(account = {}) {
    const login = Object.hasOwn(loginLabels, account.loginStatus) ? loginLabels[account.loginStatus] : unknown(account.loginStatus, '登录状态待核验');
    const connection = Object.hasOwn(connectionLabels, account.connectionStatus) ? connectionLabels[account.connectionStatus] : unknown(account.connectionStatus, '消息连接待核验');
    const hosting = { archived: '已归档，不执行', paused: '已暂停', enabled: '已授权托管', disabled: '未开启托管', unknown: '托管授权待核验' }[hostingKey(account)];
    return { login, connection, hosting };
  }
  function title(account) {
    return hasIdentity(account) && text(account.nickname) ? account.nickname : text(account.name) || (isTest(account) ? '隔离测试账号' : '待核验的闲鱼账号');
  }
  function stateTag(ctx, account, kind) {
    const raw = kind === 'login' ? text(account.loginStatus) : kind === 'connection' ? text(account.connectionStatus) : hostingKey(account);
    const value = status(account)[kind];
    const tone = kind === 'login' && raw === 'authenticated' || kind === 'connection' && raw === 'connected' ? 'success' : kind === 'hosting' && raw === 'enabled' ? 'info' : ['needs_login', 'login_required', 'verification_required', 'expired', 'blocked', 'failed', 'unavailable', 'timeout', 'identity_mismatch'].includes(raw) ? 'warning' : 'neutral';
    return `<span class="badge badge-${tone} account-state" data-account-${kind}="${ctx.e(raw || 'unknown')}">${ctx.e(value)}</span>`;
  }
  function identity(ctx, account, detailed = false) {
    const id = platformId(account), verified = hasIdentity(account);
    return `<div class="account-identity"><strong>${ctx.e(title(account))}</strong>${isTest(account) ? '<span class="badge badge-warning">隔离测试账号</span>' : ''}${archived(account) ? '<span class="badge">已归档</span>' : ''}<small>${id ? `平台标识：<span class="number">${ctx.e(id)}</span>${verified ? '' : ' · 身份依据待核验'}` : '尚未绑定平台身份，等待本人扫码核验'}</small>${verified && text(account.name) && account.name !== account.nickname ? `<small>本机名称：${ctx.e(account.name)}</small>` : ''}${!verified && text(account.nickname) && detailed ? `<small>已有昵称记录：${ctx.e(account.nickname)} · 尚未附带完整身份核验依据</small>` : ''}</div>`;
  }
  function filteredAccounts(ctx) {
    const query = text(ctx.search).trim().toLocaleLowerCase('zh-CN');
    return (Array.isArray(ctx.accounts) ? ctx.accounts : []).filter(account => !ctx.space || account.space === ctx.space).filter(account => {
      if (ctx.filter === 'archived' && !archived(account)) return false;
      if (ctx.filter === 'hosting' && hostingKey(account) !== 'enabled') return false;
      if (ctx.filter === 'paused' && (archived(account) || account.paused !== true)) return false;
      if (ctx.filter === 'login-needed' && (archived(account) || isTest(account) || account.loginStatus === 'authenticated')) return false;
      return !query || [account.name, account.nickname, account.platformUserId, account.externalId, account.note].some(value => text(value).toLocaleLowerCase('zh-CN').includes(query));
    });
  }
  function permissionNotice(ctx) {
    return ctx.canManage ? '' : ctx.notice('当前成员只能查看授权范围内的账号与历史。添加账号、同步、托管、清除登录和移除需要相应管理权限。');
  }
  function backgroundGuide() {
    return '<section class="account-background-guide" aria-label="后台托管说明"><h2>保持登录，按需管理托管</h2><dl><div><dt>持续使用</dt><dd>本机登录会自动保留。闲置、Windows 锁屏或唤醒后继续查看，无需再次输入本机密码。</dd></div><div><dt>停止全部托管</dt><dd>从本机成员菜单或设置中停止后台自动处理；页面和经营资料仍可查看。再次自动处理需明确恢复账号托管。</dd></div></dl><p>最小化、闲置或 Windows 锁屏可继续已授权托管；休眠、完全退出、关机和更新会停止。唤醒或重启后先核对未完成任务，再恢复托管。闲鱼会话失效时，需本人重新扫码。</p></section>';
  }
  function page(ctx) {
    const e = ctx.e, accounts = filteredAccounts(ctx), selected = ctx.selected instanceof Set ? ctx.selected : new Set();
    const selectable = accounts.filter(account => !archived(account) && text(account.id));
    const chosen = selectable.filter(account => selected.has(account.id));
    const scoped = (Array.isArray(ctx.accounts) ? ctx.accounts : []).filter(account => !ctx.space || account.space === ctx.space);
    const chosenAll = selectable.length > 0 && chosen.length === selectable.length;
    const add = ctx.canAdd ? ctx.space === 'test' ? ctx.btn('添加隔离测试账号', 'edit', 'data-kind="accounts"', 'primary') : ctx.btn('添加闲鱼账号', 'account-add', '', 'primary') : '';
    const head = ctx.heading('经营账号', '本人扫码核验身份，再分别检查消息连接与托管授权。', add);
    const filterValue = filters.some(([key]) => key === ctx.filter) ? ctx.filter : 'all';
    const toolbar = `<div class="toolbar account-toolbar"><label class="visually-hidden" for="account-search">搜索昵称、平台标识或备注</label><input id="account-search" type="search" data-account-search value="${e(ctx.search || '')}" placeholder="搜索昵称、平台标识或备注" autocomplete="off"><label class="visually-hidden" for="account-filter">筛选账号状态</label><select id="account-filter" data-account-filter>${filters.map(([key, label]) => `<option value="${key}"${filterValue === key ? ' selected' : ''}>${label}</option>`).join('')}</select><span class="push">显示 ${accounts.length} / ${scoped.length} 个账号</span></div>`;
    const bulkDisabled = !ctx.canManage || !chosen.length;
    const bulkAttrs = bulkDisabled ? 'disabled aria-disabled="true"' : '';
    const bulk = `<div class="account-selection-bar" aria-live="polite"><span data-account-selection-summary>已选择 ${chosen.length} 个账号</span><div class="actions">${ctx.btn('同步所选账号', 'account-bulk-sync', bulkAttrs, 'small')}${ctx.btn('暂停所选托管', 'account-bulk-pause', bulkAttrs, 'small')}${ctx.btn('恢复所选托管', 'account-bulk-resume', bulkAttrs, 'small')}</div><small>${!ctx.canManage ? '当前成员没有账号管理权限。' : !chosen.length ? '先勾选当前列表中的账号；归档账号不可执行。' : '仅处理当前列表内已勾选的账号；执行前再次核对授权，逐项保留结果。'}</small></div>`;
    const checkHeader = `<input type="checkbox" data-account-check-all aria-label="选择当前列表中可操作的账号"${chosenAll ? ' checked' : ''}${!ctx.canManage || !selectable.length ? ' disabled' : ''}>`;
    const body = accounts.map(account => `<tr data-account-id="${e(account.id)}" data-account-archived="${archived(account)}"><td class="account-check-cell"><input type="checkbox" data-account-check="${e(account.id)}" aria-label="选择 ${e(title(account))}"${selected.has(account.id) && !archived(account) ? ' checked' : ''}${!ctx.canManage || archived(account) ? ' disabled' : ''}></td><td class="account-name-cell">${identity(ctx, account)}${account.note ? `<p class="account-note">${e(account.note)}</p>` : ''}</td><td>${stateTag(ctx, account, 'login')}</td><td>${stateTag(ctx, account, 'connection')}${account.connectionReason ? `<small class="account-connection-reason">${e(account.connectionReason)}</small>` : ''}</td><td>${stateTag(ctx, account, 'hosting')}<small>${isTest(account) ? '仅隔离试运行' : '各项能力仍按实际检查结果执行'}</small></td><td class="account-time-cell">${account.lastSyncedAt ? e(ctx.when(account.lastSyncedAt)) : '尚无同步记录'}</td><td>${ctx.btn('查看详情', 'account-detail', `data-id="${e(account.id)}"`, 'small')}</td></tr>`).join('');
    // At the specified 2–5 account scale, keep selection and filtering in the controller.
    // General product pagination must not hide selected account checkboxes.
    const list = accounts.length ? ctx.table([checkHeader, '账号 / 备注', '登录状态', '消息连接', '自动托管', '最近同步', '操作'], body).replace('<table>', '<table class="account-table" data-ux-table="off">') : scoped.length ? ctx.empty('没有符合条件的账号', '调整搜索词或状态筛选，查看其他账号。已归档账号的历史仍可查看。') : ctx.empty(ctx.space === 'test' ? '添加隔离测试账号' : '添加第一个本人闲鱼账号', ctx.space === 'test' ? '创建仅用于隔离试运行的账号，可以配置测试返回结果；不会打开真实扫码页面，也不代表闲鱼登录成功。' : '在隔离的官方页面用闲鱼 APP 扫码确认。核验昵称和平台标识后，整理资料与规则，再明确开启托管。无需填写 Cookie、密钥或平台编号。', add);
    return `<div class="account-page">${head}${permissionNotice(ctx)}${!ctx.canAdd ? '<p class="help account-add-reason">添加新账号需要本机管理员权限。现有账号按当前成员授权范围显示。</p>' : ''}${ctx.space === 'test' ? ctx.notice('当前为隔离测试空间。这里的账号、身份和连接状态不能作为本人闲鱼账号已登录或真实在线的证据。', 'warn') : ''}${scoped.length ? toolbar + bulk : ''}${list}<p class="help account-defaults">默认建议范围：同步商品、订单和消息；按已配置规则自动客服；向已付款买家交付资料。新绑定账号不会自动开始托管，其他操作需要单独启用。</p>${backgroundGuide()}</div>`;
  }
  function details(ctx, account) {
    if (!account) return ctx.empty('账号不可用', '此账号可能已移除，或当前成员不再具有查看权限。请返回账号列表重新核对。');
    const e = ctx.e, attrs = `data-id="${e(account.id)}"`, readonly = archived(account), test = isTest(account);
    const testActions = test ? (ctx.canAdd ? ctx.btn('编辑隔离测试账号', 'edit', `${attrs} data-kind="accounts"`) : '') + (ctx.canManage ? ctx.btn(account.paused ? '恢复隔离处理' : '暂停隔离处理', 'account-pause', attrs) : '') : '';
    const actions = readonly ? '' : `<div class="actions account-detail-actions">${!test && ctx.canManage ? ctx.btn(account.loginStatus === 'authenticated' ? '重新扫码登录' : '本人扫码登录', 'account-login', attrs) : ''}${ctx.btn('检查登录与连接', 'account-status', attrs)}${ctx.canManage ? ctx.btn('同步此账号', 'account-sync-one', attrs) : ''}${ctx.canAdd ? ctx.btn('编辑本机备注', 'account-note', attrs) : ''}${testActions}</div>`;
    const states = `<dl class="account-status-grid"><div><dt>登录状态</dt><dd>${stateTag(ctx, account, 'login')}</dd></div><div><dt>消息连接</dt><dd>${stateTag(ctx, account, 'connection')}</dd></div><div><dt>自动托管</dt><dd>${stateTag(ctx, account, 'hosting')}</dd></div></dl>`;
    const facts = `<dl class="detail-grid account-detail-facts"><dt>本机账号编号</dt><dd class="number">${e(account.id)}</dd><dt>空间</dt><dd>${test ? '隔离测试' : '真实经营'}</dd><dt>身份核验时间</dt><dd>${hasIdentity(account) ? e(ctx.when(account.identityVerifiedAt)) : '尚无完整身份核验依据'}</dd><dt>最近同步</dt><dd>${account.lastSyncedAt ? e(ctx.when(account.lastSyncedAt)) : '尚无同步记录'}</dd><dt>本机备注</dt><dd class="account-detail-note">${e(account.note || '尚无备注')}</dd></dl>`;
    const selectedFeatures = Object.entries(featureLabels).filter(([key]) => account.hosting?.[key] === true).map(([, label]) => label);
    const hostingActions = !readonly && ctx.canManage && !test ? `<div class="actions">${ctx.btn(account.hosting?.enabled === true ? '调整托管范围' : '设置并开启托管', 'account-hosting', attrs, 'primary')}${ctx.btn(account.paused ? '恢复此账号托管' : '暂停此账号托管', 'account-pause', attrs)}</div>` : '';
    const hosting = `<section class="form-section account-hosting-section"><h3>托管范围</h3><p>${selectedFeatures.length ? e(selectedFeatures.join('；')) : '尚未记录明确的托管功能选择。'}</p><p class="help">${account.hosting?.enabled === true ? '以上是已选择的授权范围，不表示每项连接已经验证或任务正在执行。暂停、身份失效、权限或规则变化会阻止相应动作。' : '新绑定或重新登录后需要明确开启。默认建议同步、规则客服和已付款资料交付；保存配置不等于开始运行。'}</p>${test ? '<p class="help">隔离测试账号不参与真实闲鱼持续托管。</p>' : ''}${hostingActions}</section>`;
    const related = `<section class="form-section"><h3>${readonly ? '保留的关联历史' : '此账号的经营资料'}</h3><div class="account-related-links">${[['products', '商品'], ['orders', '订单与交付'], ['messages', '消息与客服'], ['inventory', '唯一库存'], ['rules', '自动处理规则'], ['assets', '资料库']].map(([route, label]) => ctx.btn(label, 'account-related', `${attrs} data-route="${route}"`)).join('')}</div><p class="help">打开后按此账号筛选，继续保留商品、订单、资料和交付记录的关联。</p></section>`;
    const capabilities = typeof ctx.renderCapabilities === 'function' ? `<section class="form-section"><h3>逐项能力与依据</h3>${ctx.renderCapabilities(account)}</section>` : '';
    const remove = !readonly && ((!test && ctx.canManage) || ctx.canAdd) ? `<section class="form-section account-remove-section"><h3>停止使用此账号</h3><p class="help">清除本机登录会停止此账号的托管并使旧会话失效。移除时如有关联业务，将归档账号并保留历史；不删除平台账号。</p><div class="actions">${!test && ctx.canManage ? ctx.btn('清除本机登录', 'account-revoke', attrs) : ''}${ctx.canAdd ? ctx.btn('移除或归档账号', 'account-archive', attrs, 'danger') : ''}</div></section>` : '';
    return `<div class="account-details" data-account-id="${e(account.id)}">${identity(ctx, account, true)}${readonly ? ctx.notice('此账号已归档，只保留本机历史与关联资料。不会重新登录、同步或执行托管。') : permissionNotice(ctx)}${test ? ctx.notice('隔离测试账号，以下身份与连接不代表真实闲鱼登录。', 'warn') : ''}${states}${account.connectionReason ? ctx.notice(e(account.connectionReason), 'warn') : ''}${actions}${facts}${hosting}${related}${capabilities}${remove}${backgroundGuide()}</div>`;
  }
  window.LianpuAccountViews = Object.freeze({ page, details, status });
})();
