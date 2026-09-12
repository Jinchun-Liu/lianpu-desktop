'use strict';
const electron = require('electron');
const { app, BrowserWindow, ipcMain, protocol, net, session, Tray, Menu, nativeImage, powerMonitor, dialog, Notification } = electron;
const fs = require('node:fs'), path = require('node:path');
const { pathToFileURL } = require('node:url');
const { randomUUID, createCipheriv, createDecipheriv, randomBytes, createHash, timingSafeEqual } = require('node:crypto');
const { AsyncLocalStorage } = require('node:async_hooks');
const { VaultIdentity, AccessError, atomicWrite, unwrap } = require('./auth.cjs');
const { EncryptedStore } = require('./core/store.cjs');
const { Service } = require('./core/service.cjs');
const { AccountRuntime } = require('./core/account-runtime.cjs');
const { PersistentLocalSession } = require('./persistent-session.cjs');
const { createLicenseClient, cloudPost } = require('./licensing/client.cjs');
const { TpmDevice } = require('./licensing/device.cjs');
const { needsLicense } = require('./licensing/operations.cjs');
const { RuntimePolicy, isTrustedSender } = require('./security/runtime-policy.cjs');
const runtimePolicy = new RuntimePolicy({packaged:app.isPackaged,hasSwitch:name=>app.commandLine.hasSwitch(name)});
const { createXianyuConnector } = require('./platform/xianyu.cjs');
const { ModelGateway } = require('./services/model.cjs');
const { MediaLibrary } = require('./services/media.cjs');
const { ClaimsEngine, MAX_FILE_BYTES } = require('./services/claims.cjs');
const { NotificationCenter } = require('./services/notifications.cjs');
const { UpdateManager } = require('./services/updates.cjs');
const { inspectMsi } = require('./services/msi-inspect.cjs');
const { Reports } = require('./services/reports.cjs');
const { createReportActions } = require('./services/report-actions.cjs');
let reports, reportAction;
function reportActor(){try{return getActor();}catch{return {id:'guest',role:'guest'};}}
function recordOperation(action,error,result,actor,started,input={}){reports?.capture(action,error,result,actor,{...require('./services/report-context.cjs').reportContext(service,action,input,actor),source:'manual',role:actor.role,durationMs:Date.now()-started});}

app.setName('Lianpu');
app.setAppUserModelId('com.lianpu.desktop');
if (process.env.LIANPU_DATA_DIR && path.isAbsolute(process.env.LIANPU_DATA_DIR)) app.setPath('userData', process.env.LIANPU_DATA_DIR);
protocol.registerSchemesAsPrivileged([{ scheme: 'lianpu', privileges: { standard: true, secure: true, supportFetchAPI: true, corsEnabled: false } }]);
const hasLock = app.requestSingleInstanceLock();
if (!hasLock) { app.quit(); } else { boot().catch(error => {
  reports?.capture('app.startup',error,null,{id:'system',role:'owner'},{source:'system'});reports?.flushLogs();
  // Never include arbitrary exception messages, records, URLs or credentials in startup diagnostics.
  const message = `无法打开本机工作区（${safeCode(error.code)}）。资料不会自动清空。请重新打开，或使用经过验证的备份。`;
  dialog.showErrorBox('联铺启动未完成', message); app.exit(1);
}); }

let win, tray, identity, rememberedSession, licenseClient, store, service, connector, accountRuntime, claims, notificationCenter, updater, updatePending = false, quitting = false, lockTask = null, stopTask = null;
let uiLocked = true, uiGeneration = 0;
const uiRequests = new AsyncLocalStorage();
let editDirty = false, editGeneration = 0, exitTask = null;
const claimWindows = new Set();
const claimDownloads = new Set();
let pending = new Set(), pendingActions = new Map(), lastActivity = Date.now(), restoreCache = null;
const dataRoot = app.getPath('userData');
let preferences = { closeBehavior: 'tray', startAtLogin: false, notifications: true };
function safeCode(value) { return typeof value === 'string' && /^[A-Z0-9_]{1,60}$/.test(value) ? value : 'STARTUP_ERROR'; }
function emit(type, fields = {}) { if (uiLocked && !['access-revoked','workspace-closed','suspended','resumed','member-changed','license-changed'].includes(type)) return; if (win && !win.isDestroyed()) win.webContents.send('desk:event', { type, ...fields }); }
function publicLicense(status=licenseClient.status()){const security=runtimePolicy.status(),active=status.active&&security.allowed;return {...status,active,...(!security.allowed?{state:'security_repair_required',reason:security.reason}:{}),security,accessMode:active?'full':identity?.meta?'readonly':'activation_required'};}
function requireLicense(){runtimePolicy.assertAllowed();return licenseClient.assertAllowed();}
function revokeUiAccess() {
  if(uiLocked)return;uiLocked=true;uiGeneration++;service?.invalidate();rememberedSession?.forget('revoked','此成员已停用，请选择其他有效成员登录。');
  restoreCache=null;updater?.clear();cancelClaimDownloads();for(const preview of claimWindows)if(!preview.isDestroyed())preview.destroy();claimWindows.clear();
  void accountRuntime?.cancelLogins();accountRuntime?.reconcile();emit('access-revoked',{reason:'当前成员已停用，请选择其他有效成员登录。'});rebuildTray();
}
function getActor() {
  if (uiLocked || !identity?.key || lockTask || !store) throw new AccessError('UNAUTHENTICATED', '请先登录有效的本机成员。');
  if(uiRequests.getStore() && uiRequests.getStore().generation!==uiGeneration)throw new AccessError('SESSION_CHANGED','当前成员已变更，旧请求已取消。');
  if(uiRequests.getStore()?.licensed)requireLicense();
  const member = store.get('members', identity.userId);
  if (!member || member.enabled === false) { revokeUiAccess();throw new AccessError('FORBIDDEN', '当前成员已停用，请联系本机管理员。'); }
  return { id: member.id, name: member.name, role: member.role, accountIds: member.accountIds || [] };
}
function requireOwner() { const actor = getActor(); if (actor.role !== 'owner') throw new AccessError('FORBIDDEN', '此操作需要本机管理员权限。'); return actor; }
function cancelClaimDownloads(grantId) {
  for (const download of claimDownloads) if (!grantId || download.grantId === grantId) {
    try { download.item.cancel(); } catch { /* A completed Chromium item may already have been destroyed. */ }
    claimDownloads.delete(download);
  }
}
function activateStore(user, first = false) {
  const retained = !!store;
  try {
  uiLocked = false; uiGeneration++;
  editDirty = false; editGeneration++;
  if (!retained) store = new EncryptedStore(path.join(dataRoot, 'business.sqlite'), Buffer.from(identity.key));
  if (first) store.put('members', { id: user.id, name: user.name, role: 'owner', enabled: true, accountIds: [], space: 'live', createdAt: new Date().toISOString(), updatedAt: new Date().toISOString() });
  const member = store.get('members', user.id);
  if (!member || member.enabled === false) { if(!retained){store.close();store=null;identity.lock();} throw new AccessError('FORBIDDEN', '成员已经停用或授权记录缺失，请联系管理员。'); }
  if (!retained) {
    service = new Service(store, { connector,assertLicense:requireLicense });
    const invokeService=service.run.bind(service);
    service.run=async(action,payload,actor)=>{const background=service.backgroundContexts.has(actor),started=Date.now();try{const result=await invokeService(action,payload,actor);if(background)reports?.capture(action,null,result,actor,{...require('./services/report-context.cjs').reportContext(service,action,payload,actor),source:'background',role:actor.role,durationMs:Date.now()-started});return result;}catch(error){if(background)reports?.capture(action,error,null,actor,{...require('./services/report-context.cjs').reportContext(service,action,payload,actor),source:'background',role:actor.role,durationMs:Date.now()-started});throw error;}};
    accountRuntime = new AccountRuntime({ store, service, connector, assertUi: actor => { const current=getActor(); if(actor.id!==current.id)throw new AccessError('LOCKED','本机成员已切换，此请求已取消。'); }, emit });
    claims = new ClaimsEngine(store);
    notificationCenter = new NotificationCenter(store);
    accountRuntime.accepting=publicLicense().active;
  }
  if (getActor().role === 'owner') updater.reconcile(getActor());
  preferences = { ...preferences, ...(store.get('_desktop', 'preferences')?.value || {}) };
  delete preferences.lockMinutes;
  if (preferences.startAtLogin && app.isPackaged) app.setLoginItemSettings({ name: 'Lianpu', openAtLogin: true, path: process.execPath });
  lastActivity = Date.now(); rebuildTray();
  return { user: getActor(), version: app.getVersion(), preferences, license:publicLicense(),sessionGeneration:uiGeneration, ...(user.recoveryCode ? { recoveryCode: user.recoveryCode } : {}) };
  } catch (error) {
    if(retained){uiLocked=true;uiGeneration++;rebuildTray();throw error;}
    try { store?.close(); } catch {}
    store = null; service = null; accountRuntime = null; claims = null; notificationCenter = null; uiLocked = true; identity.lock(); throw error;
  }
}
function publicBackground() { const status=accountRuntime?.status();return {activeAccounts:status?.activeAccounts||0,accepting:status?.accepting||false,keysRetained:!!identity?.key}; }
async function stopAllHosting(reason = '已停止全部账号托管') {
  if(stopTask)return stopTask;
  if(!accountRuntime)return {status:'stopped',background:publicBackground()};
  const activeRuntime=accountRuntime;
  const stopped=activeRuntime.beginStop(reason);
  const claimsStopped=claims?.stop();cancelClaimDownloads();for(const preview of claimWindows)if(!preview.isDestroyed())preview.destroy();claimWindows.clear();
  const operations=[...pending].filter(operation=>/^(account\.|platform\.|delivery\.|message\.|batch\.|plan\.|service\.|order\.|automation\.|interaction\.|afterSales\.|logistics\.|supplier\.)/.test(pendingActions.get(operation)||''));
  stopTask=(async()=>{await Promise.allSettled([...operations,stopped,claimsStopped]);await activeRuntime.drain();if(accountRuntime===activeRuntime&&!quitting&&!updatePending)activeRuntime.accepting=publicLicense().active;emit('hosting-stopped',{reason,background:publicBackground()});rebuildTray();return {status:'stopped',background:publicBackground()};})();
  try{return await stopTask;}finally{stopTask=null;}
}
async function closeWorkspace(reason = '工作区正在关闭') {
  editDirty = false; editGeneration++;
  if (lockTask) return lockTask;
  if (!identity?.key) return { locked: true };
  uiLocked=true;uiGeneration++;
  const runtimeStopped=stopAllHosting(reason);service?.invalidate?.(); restoreCache = null;
  updater?.clear();
  const claimsStopped = claims?.stop();
  cancelClaimDownloads();
  for (const preview of claimWindows) if (!preview.isDestroyed()) preview.destroy();
  claimWindows.clear();
  emit('workspace-closed', { reason, background:publicBackground() });
  // Existing sends must settle into their durable outbox before the database is closed.
  lockTask = (async () => {
    await Promise.allSettled([...pending, claimsStopped, runtimeStopped]);
    store?.close(); store = null; service = null; accountRuntime = null; claims = null; notificationCenter = null; identity.lock(); rebuildTray();
    return { locked: true };
  })();
  try { return await lockTask; } finally { lockTask = null; }
}
function showWindow() { if (!win || win.isDestroyed()) createWindow(); win.show(); if (win.isMinimized()) win.restore(); win.focus(); }
async function requestQuit() {
  if (exitTask) return exitTask;
  const epoch = editGeneration;
  exitTask = (async () => {
    if (!quitting && editDirty && identity?.key && !lockTask) {
      showWindow();
      const choice = await dialog.showMessageBox(win, {
        type: 'question', title: '退出前保留修改', message: '有尚未保存的修改。',
        detail: '完全退出会放弃本次未保存的表单和回复草稿。已经保存的业务记录会保留。',
        buttons: ['继续编辑', '放弃修改并退出'], defaultId: 0, cancelId: 0, noLink: true
      });
      // Recovery, a new member or update preparation invalidates an older
      // exit decision. Renderer data is never inspected to make this decision.
      if (choice.response !== 1 || epoch !== editGeneration || updatePending) return false;
    }
    quitting = true;
    await closeWorkspace('程序完全退出，停止值守');
    reports?.close();
    tray?.destroy(); app.quit(); return true;
  })();
  try { return await exitTask; }
  catch { quitting = false; dialog.showErrorBox('尚未退出', '未能安全完成退出。已保存的业务记录保留，请重新核对本机工作区。'); return false; }
  finally { exitTask = null; }
}
function trayImage() {
  // Original 16x16 geometric delivery mark, no downloaded icon or font.
  const pixels = Buffer.alloc(16 * 16 * 4);
  for (let y = 0; y < 16; y++) for (let x = 0; x < 16; x++) {
    const i = (y * 16 + x) * 4, mark = (x >= 3 && x <= 12 && (y === 3 || y === 12)) || (y >= 3 && y <= 12 && x === 3) || (x >= 7 && y === 8) || (x === 11 && y >= 6 && y <= 10);
    pixels[i] = mark ? 55 : 0; pixels[i + 1] = mark ? 82 : 0; pixels[i + 2] = mark ? 78 : 0; pixels[i + 3] = mark ? 255 : 0;
  }
  return nativeImage.createFromBitmap(pixels, { width: 16, height: 16 });
}
function rebuildTray() {
  if (!tray) return;
  tray.setToolTip(`联铺 · ${identity?.key && !lockTask && !uiLocked ? publicBackground().activeAccounts ? '账号托管中' : '已登录' : '等待登录'}`);
  tray.setContextMenu(Menu.buildFromTemplate([
    { label: '打开联铺', click: showWindow },
    { label: '停止全部账号托管', enabled: !!identity?.key && !lockTask && !uiLocked && store?.get('members',identity.userId)?.role==='owner', click: () => {try{requireOwner();void stopAllHosting();}catch{}} },
    { type: 'separator' }, { label: '完全退出（停止值守）', click: () => { void requestQuit(); } }
  ]));
}
function createWindow() {
  win = new BrowserWindow({ width: 1440, height: 920, minWidth: 900, minHeight: 620, title: '联铺', autoHideMenuBar: true, show: false,
    backgroundColor: '#ffffff', webPreferences: { preload: path.join(__dirname, 'preload.cjs'), nodeIntegration: false, contextIsolation: true, sandbox: true, webSecurity: true, webviewTag: false, navigateOnDragDrop: false, devTools: !app.isPackaged } });
  win.webContents.setWindowOpenHandler(() => ({ action: 'deny' }));
  win.webContents.on('will-navigate', event => event.preventDefault());
  win.webContents.on('will-attach-webview', event => event.preventDefault());
  win.on('close', event => { if (quitting) return; event.preventDefault(); if (preferences.closeBehavior === 'tray') win.hide(); else void requestQuit(); });
  win.on('query-session-end', event => {
    if(!identity?.key)return;
    event.preventDefault();quitting=true;
    void closeWorkspace('Windows 正在关机或注销，停止托管并保存提交结果').then(()=>app.exit(0)).catch(()=>app.exit(1));
  });
  win.on('session-end', () => { if(identity?.key)void closeWorkspace('Windows 会话已结束，停止托管').catch(()=>{}); });
  win.once('ready-to-show', () => win.show());
  win.loadURL('lianpu://app/index.html');
}
function validSender(event) {
  return isTrustedSender(event,win,'lianpu://app/index.html');
}
async function openClaimWindow(url, grantId) {
  const permitted = new URL(url);
  if (permitted.protocol !== 'http:' || permitted.hostname !== '127.0.0.1' || !/^\/claim\/[A-Za-z0-9_-]{43}$/.test(permitted.pathname)) throw new AccessError('CLAIM_ORIGIN', '本机领取预览地址无效。');
  const preview = new BrowserWindow({ width: 760, height: 650, title: '联铺 · 本机领取试运行', autoHideMenuBar: true, parent: win,
    webPreferences: { partition: `lianpu-claim-${randomUUID()}`, sandbox: true, nodeIntegration: false, contextIsolation: true, webSecurity: true, webviewTag: false, devTools: false, navigateOnDragDrop: false } });
  const allowed = value => value === permitted.href || value === permitted.href + '/download';
  preview.webContents.setWindowOpenHandler(() => ({ action: 'deny' }));
  preview.webContents.on('will-navigate', (event, destination) => { if (!allowed(destination)) event.preventDefault(); });
  preview.webContents.on('will-redirect', event => event.preventDefault());
  preview.webContents.on('will-attach-webview', event => event.preventDefault());
  preview.webContents.session.setPermissionRequestHandler((_wc, _permission, callback) => callback(false));
  preview.webContents.session.setPermissionCheckHandler(() => false);
  preview.webContents.session.webRequest.onBeforeRequest({ urls: ['*://*/*','file://*/*'] }, (details, callback) => callback({ cancel: !allowed(details.url) }));
  preview.webContents.session.on('will-download', (event, item) => {
    try { getActor(); } catch { event.preventDefault(); return; }
    if (item.getURL() !== permitted.href + '/download') { event.preventDefault(); return; }
    const download = { item, grantId }; claimDownloads.add(download);
    item.once('done', () => claimDownloads.delete(download));
    item.on('updated', () => {
      try {
        const current = getActor();
        const grant = claims.listGrants({ space: 'test' }, current).find(grant => grant.id === grantId);
        if (!grant || grant.status !== 'active' || Date.parse(grant.expiresAt) <= Date.now()) item.cancel();
      } catch { item.cancel(); }
    });
    item.setSaveDialogOptions({ title: '保存本机试运行领取文件', properties: ['showOverwriteConfirmation'] });
  });
  claimWindows.add(preview); preview.on('closed', () => claimWindows.delete(preview));
  try { await preview.loadURL(permitted.href); getActor(); }
  catch { if (!preview.isDestroyed()) preview.destroy(); throw new AccessError('CLAIM_PREVIEW', '本机领取页面没有打开，或当前成员已变更。请返回工作区核对。'); }
}
function validatePayload(action, payload) {
  if (typeof action !== 'string' || action.length > 80 || !/^[a-zA-Z][\w.]+$/.test(action)) throw new AccessError('INVALID_ACTION', '操作名称无效。');
  if (!payload || typeof payload !== 'object' || Array.isArray(payload)) throw new AccessError('INVALID_INPUT', '输入格式无效。');
  if (Buffer.byteLength(JSON.stringify(payload)) > 10 * 1024 * 1024) throw new AccessError('TOO_LARGE', '单次数据过大，请拆分后处理。');
}
function encryptBackup(data) {
  const iv = randomBytes(12), cipher = createCipheriv('aes-256-gcm', identity.key, iv);
  cipher.setAAD(Buffer.from('lianpu-backup-v1'));
  const ciphertext = Buffer.concat([cipher.update(JSON.stringify(data), 'utf8'), cipher.final()]);
  const user = identity.meta.users.find(u => u.id === identity.userId);
  return { format: 'lianpu-encrypted-backup', version: 1, createdAt: new Date().toISOString(), userId: user.id, envelope: user.envelope,
    iv: iv.toString('base64'), tag: cipher.getAuthTag().toString('base64'), ciphertext: ciphertext.toString('base64') };
}
function decryptBackup(archive, key) {
  if (archive.format !== 'lianpu-encrypted-backup' || archive.version !== 1) throw new AccessError('BACKUP_FORMAT', '请选择本软件生成的加密备份。');
  const decipher = createDecipheriv('aes-256-gcm', key, Buffer.from(archive.iv, 'base64'));
  decipher.setAAD(Buffer.from('lianpu-backup-v1')); decipher.setAuthTag(Buffer.from(archive.tag, 'base64'));
  return JSON.parse(Buffer.concat([decipher.update(Buffer.from(archive.ciphertext, 'base64')), decipher.final()]).toString('utf8'));
}
async function saveFile(content, defaultPath, filters) {
  const selected = await dialog.showSaveDialog(win, { title: '保存到自己的文件夹', defaultPath, filters });
  getActor();
  if (selected.canceled || !selected.filePath) return { canceled: true };
  const freshContent = typeof content === 'function' ? await content() : content;
  getActor();
  const bytes = typeof freshContent === 'string' ? freshContent : JSON.stringify(freshContent, null, 2);
  fs.writeFileSync(selected.filePath, bytes, { mode: 0o600 });
  return { saved: true, path: selected.filePath, sha256: createHash('sha256').update(bytes).digest('hex') };
}
async function dispatch(action, p) {
  if(action.startsWith('feedback.'))return reportAction(action,p);
  if (updatePending && !['auth.status', 'auth.lock','auth.stopAndLock'].includes(action)) throw new AccessError('UPDATE_PENDING', '正在安全关闭工作区并启动安装，请稍候。');
  if (action === 'auth.status') {
    let user;if(identity.key&&!lockTask&&!uiLocked)try{user=getActor();}catch{}
    return {...identity.status(),locked:!user,interfaceLocked:false,background:publicBackground(),rememberedSession:rememberedSession.status(),license:publicLicense(),version:app.getVersion(),user,sessionGeneration:uiGeneration};
  }
  if(action==='license.status')return publicLicense();
  if(['license.prepareDevice','license.precheck','license.confirm','license.recover'].includes(action)){
    if(quitting||updatePending)throw new AccessError('APP_CLOSING','程序正在保存并退出，请下次启动后继续授权。');
    const result=await licenseClient[action.slice(8)](p);
    return result?.license?{...result,license:publicLicense(result.license)}:publicLicense(result);
  }
  if (action === 'auth.lock' || action === 'auth.stopAndLock') return {status:'removed',removed:true,reason:'本版本已移除锁定功能。停止托管请使用独立托管操作。'};
  if (['auth.setup', 'auth.unlock', 'auth.recover'].includes(action)) {
    if(action==='auth.setup')requireLicense();
    if(quitting||updatePending)throw new AccessError('APP_CLOSING','程序正在保存并退出，请在下次启动后继续。');
    if (lockTask) await lockTask;
    if(quitting||updatePending)throw new AccessError('APP_CLOSING','程序正在保存并退出，请在下次启动后继续。');
    if (store && action==='auth.unlock' && (!store.get('members',p.id)||store.get('members',p.id).enabled===false)) throw new AccessError('FORBIDDEN','此成员已停用或不存在。');
    const previousKey=identity.key?Buffer.from(identity.key):null,previousUser=identity.userId,previousUnavailable=uiLocked;
    let result,cancelled;
    try{
      const user = action === 'auth.setup' ? identity.setup(p) : action === 'auth.recover' ? identity.recover(p) : identity.unlock(p);
      if(store&&!timingSafeEqual(identity.key,store.key))throw new AccessError('SESSION_INVALID','当前身份不属于已打开的资料库。');
      identity.advanceRememberedRevision();
      service?.invalidate();restoreCache=null;updater?.clear();cancelClaimDownloads();for(const preview of claimWindows)if(!preview.isDestroyed())preview.destroy();claimWindows.clear();
      cancelled=accountRuntime?.cancelLogins();
      result=activateStore(user,action==='auth.setup');result.rememberedSession=rememberedSession.save(identity);
    }catch(error){if(previousKey&&store){identity.lock();identity.key=Buffer.from(previousKey);identity.userId=previousUser;uiLocked=previousUnavailable;rebuildTray();}throw error;}
    finally{previousKey?.fill(0);}
    // Only the synchronous activation owns rollback. A newer sign-in may finish
    // while cancellation drains; an older response must never restore its user.
    emit('member-changed',{user:result.user,memberId:result.user.id,generation:result.sessionGeneration,sessionGeneration:result.sessionGeneration});
    await cancelled;
    if(result.sessionGeneration!==uiGeneration||result.user.id!==identity.userId)throw new AccessError('SESSION_CHANGED','当前成员已变更，旧登录结果已取消。');
    return result;
  }
  const actor = getActor();
  if(needsLicense(action,p))requireLicense();
  if(action==='hosting.stopAll'){requireOwner();const result=await stopAllHosting();return {...result,user:getActor()};}
  if(stopTask&&action==='claims.preview')throw new AccessError('BACKGROUND_STOPPING','本机领取服务正在停止，请稍后再打开预览。');
  if(stopTask&&/^(account\.|platform\.|delivery\.|message\.|batch\.|plan\.|service\.|order\.|interaction\.|afterSales\.|logistics\.|supplier\.)/.test(action)&&!['account.details','account.runtime.status','platform.status','account.login.status'].includes(action))throw new AccessError('BACKGROUND_STOPPING','正在保存提交结果并停止托管，请稍后再开始新的账号操作。');
  if (action === 'account.login.start') return accountRuntime.startLogin(p,actor);
  if (action === 'account.login.status') return accountRuntime.getLogin(p,actor);
  if (action === 'account.login.cancel') return accountRuntime.cancelLogin(p,actor);
  if (action === 'account.login.bind') return accountRuntime.bindLogin(p,actor);
  if (action === 'account.hosting.save') return accountRuntime.hosting(p,actor);
  if (action === 'account.login.clear') return accountRuntime.clearLogin(p,actor);
  if (action === 'account.remove') return accountRuntime.remove(p,actor);
  if (action === 'account.details') return accountRuntime.details(p,actor);
  if (action === 'account.runtime.status') return accountRuntime.status();
  if (action === 'entity.delete' && p.kind === 'accounts') return accountRuntime.remove({accountId:p.id},actor);
  if (action === 'account.syncMany') {
    const accountIds=[...new Set(p.accountIds||[])], kinds=p.kinds||['products','orders','messages'];
    if(!accountIds.length||accountIds.length>5||!Array.isArray(kinds)||kinds.some(k=>!['products','orders','messages'].includes(k)))throw new AccessError('VALIDATION','请选择 1–5 个账号及有效同步项目。');
    const results=(await Promise.all(accountIds.map(async accountId=>{const rows=[];for(const kind of kinds){try{getActor();rows.push({accountId,kind,...await service.run('account.sync',{id:accountId,kind},actor)});}catch(error){rows.push({accountId,kind,status:'blocked',reason:error.message});}}return rows;}))).flat();
    return {status:results.every(r=>r.status==='ok')?'ok':'partial',results};
  }
  if (updatePending) throw new AccessError('UPDATE_PENDING', '正在安全关闭工作区并启动安装，请稍候。');
  if (!['workspace.snapshot', 'requirements.status', 'app.preferences.get', 'app.editState', 'platform.status', 'statistics.get'].includes(action)) lastActivity = Date.now();
  if (action === 'app.editState') {
    if (typeof p.dirty !== 'boolean' || Object.keys(p).some(key => key !== 'dirty')) throw new AccessError('INVALID_INPUT', '编辑状态只接受有无未保存修改的布尔值。');
    editDirty = p.dirty; return { dirty: editDirty };
  }
  if (action === 'app.activity') return { active: true };
  if (action === 'auth.changePassword') {const epoch=uiGeneration,result=await identity.changePassword(p);const current=getActor();if(epoch!==uiGeneration||current.id!==actor.id)throw new AccessError('SESSION_CHANGED','当前成员已变更，旧密码修改结果已取消。');return {...result,rememberedSession:rememberedSession.save(identity)};}
  if (action === 'notifications.settings.get') return notificationCenter.getSettings(p, actor);
  if (action === 'notifications.settings.save') return notificationCenter.saveSettings(p, actor);
  if (action === 'notifications.list') { notificationCenter.scan(); return notificationCenter.list(p, actor); }
  if (action === 'notifications.read') return notificationCenter.markRead(p, actor);
  if (action === 'notifications.preview') return notificationCenter.preview(p, actor);
  if (action === 'notifications.test') {
    const preview = notificationCenter.preview(p, actor);
    if (!Notification.isSupported()) return { ...preview, status: 'unavailable', reason: '当前系统不支持桌面通知。' };
    try { new Notification({ title: preview.title, body: preview.body }).show(); return { ...preview, status: 'submitted', reason: '已向 Windows 提交此本机预览，实际显示受系统设置影响。' }; }
    catch { return { ...preview, status: 'failed', reason: 'Windows 通知提交失败，请检查系统设置。' }; }
  }
  if (action === 'update.status') return { ...updater.status(actor), packaged: app.isPackaged };
  if (action === 'update.settings.save') return updater.settings(p, actor);
  if (action === 'update.check') return updater.check(actor);
  if (action === 'update.chooseManifest') {
    requireOwner(); const selected = await dialog.showOpenDialog(win, { title: '选择发行方提供的签名更新清单', properties: ['openFile'], filters: [{ name: '联铺签名更新清单', extensions: ['lianpu-update'] }] });
    const current = requireOwner(); if (selected.canceled || !selected.filePaths.length) return { canceled: true };
    return updater.importManifest(selected.filePaths[0], current);
  }
  if (action === 'update.prepare') {
    await updater.prepare(p, actor);
    const preview = updater._get(p.id, getActor());
    const metadata = await inspectMsi(preview.preparedPath, { expectedVersion: preview.manifest.version });
    updater._get(p.id, getActor());
    return { ...updater.describe(p.id), msiMetadata: metadata };
  }
  if (action === 'update.install') {
    requireOwner();
    if (!app.isPackaged) throw new AccessError('PACKAGED_REQUIRED', '请在已安装的桌面版本中执行更新安装。');
    if (p.confirmation !== '安装并退出') throw new AccessError('UPDATE_CONFIRMATION', '请核对版本和开发签名说明后，点击安装并退出。');
    const preview = updater._get(p.id, actor);
    if (!preview.preparedPath) throw new AccessError('UPDATE_NOT_PREPARED', '请先下载或检查安装包。');
    await inspectMsi(preview.preparedPath, { expectedVersion: preview.manifest.version });
    const installation = updater.takeForInstallation(p, requireOwner()); updatePending = true;
    // Run after this IPC reply settles, so closing never waits for its own request.
    setImmediate(() => void (async () => {
      try {
        requireOwner(); await closeWorkspace('准备更新，工作区资料已保存');
        await inspectMsi(installation.path, { expectedVersion: installation.version });
        const bytes = fs.readFileSync(installation.path);
        updater._checkBytes(bytes, { size: installation.size, sha256: installation.sha256 });
        const { spawn } = require('node:child_process');
        const child = spawn(path.join(process.env.SystemRoot || 'C:\\Windows', 'System32', 'msiexec.exe'), ['/i', installation.path, '/norestart'], { detached: true, stdio: 'ignore' });
        await new Promise((resolve, reject) => { child.once('spawn', resolve); child.once('error', reject); });
        child.unref(); quitting = true; app.quit();
      } catch { updatePending = false; dialog.showErrorBox('更新安装尚未开始', '未能启动经过核验的安装包。工作区资料保留，请重新打开并检查更新；安装请求不代表安装成功。'); }
    })());
    return { status: 'launch_requested', version: installation.version, reason: '正在保存并退出工作区，然后打开 Windows 安装器。请以安装器结果及重开后的版本为准。' };
  }
  if (action === 'claims.files') return claims.listFiles(p, actor);
  if (action === 'claims.grants') return claims.listGrants(p, actor);
  if (action === 'claims.create') return claims.createGrant(p, actor);
  if (action === 'claims.revoke') {
    const result = claims.revoke(p, actor);
    cancelClaimDownloads(p.id);
    return result;
  }
  if (action === 'claims.access') return claims.accessLog(p, actor);
  if (action === 'claims.importFile') {
    if (p.space !== 'test' || !p.accountId) throw new AccessError('PUBLIC_HOSTING_UNAVAILABLE', '请切换到试运行空间并选择测试账号；当前仅提供本机领取试运行。');
    claims.listFiles(p, actor);
    if (p.rightsConfirmed !== true) throw new AccessError('FILE_RIGHTS', '请先确认你有权使用此文件。');
    const selected = await dialog.showOpenDialog(win, { title: '选择有权使用的本机试运行文件（不超过 20 MB）', properties: ['openFile'] });
    const current = getActor(); claims.listFiles(p, current);
    if (selected.canceled || !selected.filePaths.length) return { canceled: true };
    const file = selected.filePaths[0];
    if (fs.statSync(file).size > MAX_FILE_BYTES) throw new AccessError('FILE_SIZE', '每个领取文件不能超过 20 MB。');
    return claims.addFile({ ...p, name: path.basename(file), bytes: fs.readFileSync(file) }, current);
  }
  if (action === 'claims.preview') {
    const result = await claims.startLocalPreview(p, actor); getActor(); await openClaimWindow(result.url, p.grantId); return result;
  }
  if (action === 'media.list') return new MediaLibrary(store).list(p, actor);
  if (action === 'media.remove') return new MediaLibrary(store).remove(p.id, actor);
  if (action === 'media.import') {
    new MediaLibrary(store).authorize(actor, p.space, p.accountId);
    const selected = await dialog.showOpenDialog(win, { title: '选择自己有权使用的图片素材', properties: ['openFile', 'multiSelections'], filters: [{ name: 'PNG / JPEG / WebP 图片', extensions: ['png','jpg','jpeg','webp'] }] });
    if (selected.canceled) return { canceled: true };
    const current = getActor(), library = new MediaLibrary(store); library.authorize(current, p.space, p.accountId);
    if (selected.filePaths.length > 12) throw new AccessError('TOO_MANY_IMAGES', '每次最多导入 12 张图片。');
    const files = selected.filePaths.map(file => { if (fs.statSync(file).size > 5 * 1024 * 1024) throw new AccessError('IMAGE_SIZE', '每张图片需要小于 5 MB。'); return { name: path.basename(file), bytes: fs.readFileSync(file), space: p.space, accountId: p.accountId }; });
    return { items: store.transaction(() => files.map(file => library.add(file, current))), reason: '图片已加密保存在本机素材库，未上传平台。' };
  }
  if (action === 'product.cloneToAccount') {
    const product = store.get('products', p.productId), target = store.get('accounts', p.targetAccountId), library = new MediaLibrary(store);
    if (!product || !target || product.space !== target.space) throw new AccessError('INVALID_INPUT', '请选择同一工作区的来源商品和目标账号。');
    if (p.rightsConfirmed !== true) throw new AccessError('RIGHTS_REQUIRED', '请先确认你有权复用所选文字和图片。');
    library.authorize(actor, product.space, product.accountId); library.authorize(actor, target.space, target.id);
    return store.transaction(() => {
      const clone = { id: randomUUID(), space: target.space, accountId: target.id, title: `${product.title}（副本）`, description: product.description || '', sku: '', priceCents: product.priceCents, stock: product.stock, status: 'draft', category: product.category || '', materialRights: '用户确认有权复用', sourceProductId: product.id,
        variants: (product.variants || []).map(v => ({ ...v, ...(target.id === product.accountId ? {} : { assetId: undefined }) })),
        images: (product.images || []).map(url => target.id === product.accountId ? url : library.copyUrl(url, product.accountId, target.id, actor)) };
      // Core validation is synchronous; its public save enforces the current member again.
      const saved = service.save({ kind: 'products', record: clone }, actor);
      return { product: saved, status: 'local_draft', reason: target.id === product.accountId ? '已建立本机草稿副本，未向平台发布。' : '已复制到目标账号的本机草稿；规格资料绑定已清空，请重新绑定后再启用交付。未执行平台迁移。' };
    });
  }
  if (action === 'auth.member.add') {
    requireOwner();
    if (!['operator', 'support', 'viewer'].includes(p.role)) throw new AccessError('ROLE_INVALID', '请选择经营、客服或只读角色。');
    const accountIds = Array.isArray(p.accountIds) ? [...new Set(p.accountIds)] : [];
    if (accountIds.some(id => !store.get('accounts', id))) throw new AccessError('ACCOUNT_INVALID', '成员账号范围包含不存在的账号。');
    const id = randomUUID(); identity.addMember({ id, name: p.name, password: p.password });
    store.put('members', { id, name: p.name.trim(), role: p.role, accountIds, enabled: true, space: 'live', createdAt: new Date().toISOString(), updatedAt: new Date().toISOString() });
    return { id, name: p.name.trim(), role: p.role, accountIds, enabled: true };
  }
  if (action === 'platform.openLogin' || action === 'platform.revoke') {
    requireOwner(); const account = store.get('accounts', p.accountId);
    if (!account || account.space !== 'live') throw new AccessError('ACCOUNT_INVALID', '请选择真实经营空间中的本人账号。');
    return action === 'platform.openLogin' ? accountRuntime.startLogin({accountId:account.id},actor) : accountRuntime.clearLogin({accountId:account.id},actor);
  }
  if (action === 'platform.status') {
    const account=service._record('accounts',p.accountId,actor,'read');
    if(account.space!=='live'||account.archived||!publicLicense().active)return connector.status(account);
    return connector.inspect(account,{authorize:()=>{requireLicense();const current=service._record('accounts',account.id,getActor(),'read');return !current.archived&&current.sessionVersion===account.sessionVersion;}});
  }
  if (action === 'app.preferences.get') return { ...preferences, version: app.getVersion(), platform: process.platform, arch: process.arch, packaged: app.isPackaged, signed: false };
  if (action === 'app.preferences.save') {
    requireOwner();
    if (p.closeBehavior !== undefined && !['tray', 'quit'].includes(p.closeBehavior)) throw new AccessError('INVALID_INPUT', '关闭窗口行为无效。');
    for (const key of ['startAtLogin', 'notifications']) if (p[key] !== undefined && typeof p[key] !== 'boolean') throw new AccessError('INVALID_INPUT', '偏好开关格式无效。');
    const nextPreferences = { ...preferences };
    for (const key of ['closeBehavior', 'startAtLogin', 'notifications']) if (p[key] !== undefined) nextPreferences[key] = p[key];
    if (p.startAtLogin !== undefined) {
      if (!app.isPackaged && p.startAtLogin) throw new AccessError('PACKAGED_REQUIRED', '请安装桌面版本后启用开机启动。');
      app.setLoginItemSettings({ name: 'Lianpu', openAtLogin: p.startAtLogin, path: process.execPath });
    }
    store.put('_desktop', { id: 'preferences', value: nextPreferences, updatedAt: new Date().toISOString() }); preferences = nextPreferences; return preferences;
  }
  if (action === 'app.notify.test') {
    requireOwner(); if (!Notification.isSupported()) return { status: 'unavailable', reason: '当前系统不支持桌面通知。' };
    new Notification({ title: '联铺 · 本机测试通知', body: '这是一条由你发起的测试通知，没有发送给买家。' }).show(); return { status: 'submitted', reason: '已向 Windows 提交通知；最终显示受系统通知设置影响。' };
  }
  if (action === 'app.quit') { setImmediate(() => { void requestQuit(); }); return { status: 'exit_requested', exiting: false }; }
  if (action === 'requirements.status') {
    const file = path.join(app.getAppPath(), 'docs', 'requirements-status.json');
    return fs.existsSync(file) ? JSON.parse(fs.readFileSync(file, 'utf8')) : { items: [], reason: '逐项验收记录正在建立。' };
  }
  if (action === 'backup.create') {
    requireOwner();
    return saveFile(async () => {
      const data = await service.run('backup.create', {}, requireOwner());
      data.desktopPreferences = { closeBehavior: preferences.closeBehavior, notifications: preferences.notifications };
      data.media = store.list('_media');
      data.claims = claims.exportBackup(requireOwner());
      data.localNotifications = notificationCenter.exportBackup();
      const encrypted = encryptBackup(data);
      if (Buffer.byteLength(JSON.stringify(encrypted, null, 2)) > 100 * 1024 * 1024) throw new AccessError('TOO_LARGE', '当前完整备份超过 100 MB，尚未生成文件。请由维护人员处理大文件备份，不能生成无法由本版本恢复的备份。');
      return encrypted;
    }, `联铺加密备份-${new Date().toISOString().slice(0, 10)}.lianpu`, [{ name: '联铺加密备份', extensions: ['lianpu'] }]);
  }
  if (action === 'backup.chooseRestore') {
    requireOwner(); const selected = await dialog.showOpenDialog(win, { title: '选择联铺加密备份', properties: ['openFile'], filters: [{ name: '联铺加密备份', extensions: ['lianpu'] }] });
    requireOwner(); if (selected.canceled) return { canceled: true };
    if (fs.statSync(selected.filePaths[0]).size > 100 * 1024 * 1024) throw new AccessError('TOO_LARGE', '备份文件超过 100 MB，请先联系维护人员核验。');
    const archive = JSON.parse(fs.readFileSync(selected.filePaths[0], 'utf8')); restoreCache = { archive };
    try { restoreCache.data = decryptBackup(archive, identity.key); } catch { return { requiresPassword: true, reason: '请输入创建此备份时使用的本机管理密码。' }; }
    new MediaLibrary(store).validateBackup(restoreCache.data.media || []);
    if (restoreCache.data.claims) claims.validateBackup(restoreCache.data.claims);
    if (restoreCache.data.localNotifications) notificationCenter.validateBackup(restoreCache.data.localNotifications);
    return service.run('backup.preview', { data: restoreCache.data }, actor);
  }
  if (action === 'backup.unlockRestore') {
    requireOwner(); if (!restoreCache?.archive || typeof p.password !== 'string' || p.password.length > 1024) throw new AccessError('BACKUP_REQUIRED', '请重新选择备份并输入原管理密码。');
    let key;
    try { key = unwrap(restoreCache.archive.envelope, p.password, restoreCache.archive.userId); restoreCache.data = decryptBackup(restoreCache.archive, key); }
    catch { throw new AccessError('BACKUP_PASSWORD', '备份密码不正确或文件已损坏。'); } finally { key?.fill(0); }
    new MediaLibrary(store).validateBackup(restoreCache.data.media || []);
    if (restoreCache.data.claims) claims.validateBackup(restoreCache.data.claims);
    if (restoreCache.data.localNotifications) notificationCenter.validateBackup(restoreCache.data.localNotifications);
    return service.run('backup.preview', { data: restoreCache.data }, actor);
  }
  if (action === 'backup.restore') {
    requireOwner(); if (!restoreCache?.data) throw new AccessError('BACKUP_REQUIRED', '请先选择备份并查看恢复预览。');
    new MediaLibrary(store).validateBackup(restoreCache.data.media || []);
    if (restoreCache.data.claims) claims.validateBackup(restoreCache.data.claims);
    if (restoreCache.data.localNotifications) notificationCenter.validateBackup(restoreCache.data.localNotifications);
    // Core restore is a synchronous transaction; images and core restore must succeed together.
    const result = store.transaction(() => {
      const restored = service.restoreBackup({ data: restoreCache.data, confirmation: p.confirmation }, requireOwner());
      new MediaLibrary(store).restore(restoreCache.data.media || []);
      if (restoreCache.data.claims) restored.claims = claims.restore(restoreCache.data.claims, requireOwner());
      if (restoreCache.data.localNotifications) restored.localNotifications = notificationCenter.restoreBackup(restoreCache.data.localNotifications);
      return restored;
    });
    const restored = restoreCache.data.desktopPreferences;
    if (restored && ['tray', 'quit'].includes(restored.closeBehavior)) {
      preferences = { ...preferences, closeBehavior: restored.closeBehavior, notifications: restored.notifications !== false };
      store.put('_desktop', { id: 'preferences', value: preferences, updatedAt: new Date().toISOString() });
    }
    restoreCache = null; return result;
  }
  if (action === 'file.export') {
    await service.run('data.export', p, actor);
    return saveFile(async () => (await service.run('data.export', p, getActor())).csv, `联铺-${p.kind}-${p.space || 'live'}.csv`, [{ name: 'CSV 表格', extensions: ['csv'] }]);
  }
  if (action === 'file.chooseImport') {
    requireOwner(); const selected = await dialog.showOpenDialog(win, { title: '选择要预览的表格', properties: ['openFile'], filters: [{ name: 'CSV 表格', extensions: ['csv'] }] });
    getActor(); if (selected.canceled) return { canceled: true };
    if (fs.statSync(selected.filePaths[0]).size > 10 * 1024 * 1024) throw new AccessError('TOO_LARGE', '单次导入文件不能超过 10 MB。');
    requireOwner();
    return { csv: fs.readFileSync(selected.filePaths[0], 'utf8'), filename: path.basename(selected.filePaths[0]), kind: p.kind, space: p.space };
  }
  if (action === 'diagnostics.save') { requireOwner(); return saveFile(() => service.run('diagnostics.export', {}, requireOwner()), '联铺诊断报告.json', [{ name: '诊断报告', extensions: ['json'] }]); }
  // Generic maintenance paths do not bypass native file dialogs or owner permission checks.
  if (['backup.preview', 'data.export'].includes(action)) return service.run(action, p, actor);
  return service.run(action, p, actor);
}
async function boot() {
  await app.whenReady();
  reports=new Reports({directory:path.join(dataRoot,'support-v1'),protector:electron.safeStorage,version:app.getVersion(),build:require('../package.json').build||'development',endpoint:require('./licensing/config.json').endpoint,fetchImpl:(url,options)=>net.fetch(url,{...options,credentials:'omit'}),getLicense:async bytes=>{
    const device=licenseClient?.device,license=licenseClient?.body?.license;if(!license||!device?.info?.publicKeySpki)return null;
    const signed=await device.invoke('sign',bytes);const signature=Buffer.from(signed.signature||'','base64url');if(!device.verify(bytes,signature))return null;return {license,publicKey:device.info.publicKeySpki,signature:signature.toString('base64url')};
  }});await reports.init();reportAction=createReportActions({reports,getActor,dialog,nativeImage,getWindow:()=>win});reports.start();
  process.on('uncaughtExceptionMonitor',error=>{reports.capture('app.fatal',error,null,{id:'system',role:'owner'},{source:'system'});reports.flushLogs();if(accountRuntime)accountRuntime.accepting=false;});
  process.on('unhandledRejection',error=>{reports.capture('app.rejection',error instanceof Error?error:new Error('Unhandled rejection'),null,{id:'system',role:'owner'},{source:'system'});void stopAllHosting('程序出现未处理异常，已停止接收新任务').catch(()=>{});});
  app.on('web-contents-created',(_event,contents)=>{contents.on('render-process-gone',(_e,detail)=>reports.capture('renderer.process',null,{status:'failed',code:'RENDER_PROCESS_GONE'},reportActor(),{source:'system',result:detail.reason}));contents.on('unresponsive',()=>reports.capture('renderer.unresponsive',null,{status:'timeout',code:'RENDERER_UNRESPONSIVE'},reportActor(),{source:'system'}));});
  fs.mkdirSync(dataRoot, { recursive: true }); identity = new VaultIdentity(path.join(dataRoot, 'identity.json'));
  rememberedSession=new PersistentLocalSession({file:path.join(dataRoot,'local-session.bin'),safeStorage:electron.safeStorage});
  let licenseWasActive=false;
  licenseClient=await createLicenseClient({transport:(endpoint,route,body)=>cloudPost(endpoint,route,body,(url,options)=>net.fetch(url,options)),device:new TpmDevice({helper:app.isPackaged?path.join(process.resourcesPath,'licensing','Lianpu.Device.exe'):path.join(__dirname,'licensing','native','bin','Lianpu.Device.exe')}),onChange:status=>{
    const expired=licenseWasActive&&!status.active;licenseWasActive=status.active;
    if(accountRuntime&&!stopTask)accountRuntime.accepting=publicLicense(status).active;
    emit('license-changed',{license:publicLicense(status)});
    if(expired&&accountRuntime)void stopAllHosting(status.reason).catch(()=>{});
  }});
  await licenseClient.initialize();
  reports.activate(licenseClient.status().active);
  updater = new UpdateManager({ getStore: () => identity?.key && !lockTask ? store : null, keys: require('./release-trust.json').keys,
    currentVersion: app.getVersion(), downloadRoot: path.join(dataRoot, 'updates') });
  connector = createXianyuConnector({ electron,authorizeTask:()=>{try{return requireLicense();}catch{return false;}}, onStatus: status => { try { accountRuntime?.observeStatus(status); } catch { /* Closed or changed sessions cannot restore account state. */ } } });
  const modelGateway = new ModelGateway({ getStore: () => identity?.key && !lockTask ? store : null });
  connector.aiReply = request => modelGateway.reply(request);
  connector.testIntegration = integration => ['ai', 'model'].includes(integration.type) ? modelGateway.test(integration) : Promise.resolve({ status: 'blocked', reason: '当前连接类型尚未取得正式接口规范与授权，不能只凭保存地址认定接入成功。' });
  const restoredUser=rememberedSession.restore(identity,(userId,key)=>{
    const file=path.join(dataRoot,'business.sqlite');if(!fs.existsSync(file))return false;
    let verification;try{verification=new EncryptedStore(file,key);const member=verification.get('members',userId);return !!member&&member.enabled!==false;}finally{verification?.close();}
  });
  if(restoredUser)try{activateStore(restoredUser);}catch{rememberedSession.forget('invalid','保存的登录无法恢复当前资料库，请正常登录一次。');}
  const rendererRoot = path.join(__dirname, 'renderer');
  // Only clear the UI session's HTTP/code cache, never cookies or storage.
  // Otherwise a newer installed application can reuse old custom-scheme JS.
  await session.defaultSession.clearCache();
  protocol.handle('lianpu', request => {
    const url = new URL(request.url);
    if (url.host !== 'app' || request.method !== 'GET') return new Response('Forbidden', { status: 403 });
    if (url.pathname.startsWith('/media/')) {
      try {
        const asset = new MediaLibrary(store).read(decodeURIComponent(url.pathname.slice('/media/'.length)), getActor());
        return new Response(new Uint8Array(asset.bytes), { headers: { 'Content-Type': asset.mime, 'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff' } });
      } catch { return new Response('Forbidden', { status: 403 }); }
    }
    let target;
    try { target = path.resolve(rendererRoot, `.${decodeURIComponent(url.pathname)}`); } catch { return new Response('Bad request', { status: 400 }); }
    if (!target.startsWith(rendererRoot + path.sep)) return new Response('Forbidden', { status: 403 });
    return net.fetch(pathToFileURL(target).href).then(response=>{
      const headers=new Headers(response.headers);headers.set('Cache-Control','no-store');
      return new Response(response.body,{status:response.status,statusText:response.statusText,headers});
    });
  });
  session.defaultSession.setPermissionRequestHandler((_wc, _permission, cb) => cb(false));
  session.defaultSession.setPermissionCheckHandler(() => false);
  ipcMain.handle('desk:call', async (event, action, payload = {}) => {
    if (!validSender(event)) return { ok: false, error: { code: 'FORBIDDEN', message: '此页面无权访问本机资料。' } };
    const started=Date.now(),reportWho=reportActor();
    try {
      validatePayload(action, payload);
      if(action.startsWith('feedback.'))return {ok:true,data:await dispatch(action,payload)};
      // Authentication/stop calls must never wait for their own pending request.
      if (action.startsWith('auth.') || action.startsWith('license.') || action==='hosting.stopAll') {
        const signsIn=['auth.setup','auth.unlock','auth.recover'].includes(action);
        const epoch=uiGeneration,result=await (signsIn||action.startsWith('license.')||['auth.status','auth.lock','auth.stopAndLock'].includes(action)?dispatch(action,payload):uiRequests.run({generation:epoch},()=>dispatch(action,payload)));
        if((signsIn&&result.sessionGeneration!==uiGeneration)||(!signsIn&&!['auth.status','license.status','auth.lock','auth.stopAndLock'].includes(action)&&epoch!==uiGeneration))throw new AccessError('SESSION_CHANGED','当前成员已变更，旧请求结果已取消。');
        reports.activate(licenseClient.status().active);recordOperation(action,null,result,reportWho,started,payload);return {ok:true,data:result};
      }
      const requestGeneration=uiGeneration;
      const operation = uiRequests.run({generation:requestGeneration,licensed:needsLicense(action,payload)},()=>dispatch(action, payload)); pending.add(operation);pendingActions.set(operation,action);
      let result;
      try { result = await operation; } finally { pending.delete(operation);pendingActions.delete(operation); }
      if (uiLocked || lockTask || !identity.key || requestGeneration!==uiGeneration) throw new AccessError('SESSION_CHANGED', '当前成员已变更，处理结果保留在本机记录中。');
      getActor();
      accountRuntime?.reconcile();
      recordOperation(action,null,result,reportWho,started,payload);return { ok: true, data: result };
    } catch (error) {
      recordOperation(action,error,null,reportWho,started,payload);
      return { ok: false, error: { code: safeCode(error.code), message: error.code && typeof error.message === 'string' ? error.message.slice(0, 500) : '本次操作未完成，请检查输入或打开运行诊断。' } };
    }
  });
  tray = new Tray(trayImage()); tray.on('double-click', showWindow); rebuildTray(); createWindow();
  app.on('second-instance', showWindow);
  app.on('activate', showWindow);
  powerMonitor.on('suspend', () => { emit('suspended',{reason:'电脑休眠，账号托管已停止。唤醒后可直接查看工作区。'});void stopAllHosting('电脑休眠，账号托管已停止').catch(()=>{}); });
  powerMonitor.on('resume', () => { licenseClient.checkpoint();emit('resumed', { reason: '电脑已唤醒，可直接查看工作区。需要继续托管时请明确开启账号。' }); });
  setInterval(()=>licenseClient.checkpoint(),1000).unref();
  setInterval(async () => {
    if (!identity.key || lockTask || stopTask || updatePending || !service || !accountRuntime || !publicLicense().active) return;
    let operation;
    try {
      operation = accountRuntime.tick(); pending.add(operation);pendingActions.set(operation,'automation.tick');
      await operation;emit('changed');
    }
    catch { /* Per-item reasons remain in the audit trail; do not log buyer data. */ }
    finally { if (operation){pending.delete(operation);pendingActions.delete(operation);} }
  }, 15_000).unref();
  // Observation is independent of automation success and never calls a platform endpoint.
  setInterval(() => {
    if (!identity?.key || lockTask || updatePending || !notificationCenter) return;
    const activeCenter = notificationCenter;
    try {
      activeCenter.scan();
      if (!preferences.notifications || !Notification.isSupported()) return;
      const digest = activeCenter.prepareDigest({ space: 'live' }, getActor()); if (!digest) return;
      const notice = new Notification({ title: digest.title, body: digest.body });
      notice.once('failed', () => { try { if (identity?.key && !lockTask && notificationCenter === activeCenter) activeCenter.finishDigest({ id: digest.id, status: 'failed' }); } catch { /* A late OS callback cannot reopen a closed workspace. */ } });
      try { notice.show(); activeCenter.finishDigest({ id: digest.id, status: 'submitted' }); }
      catch { activeCenter.finishDigest({ id: digest.id, status: 'failed' }); }
      emit('notification', { message: '有经营提醒，请打开通知中心核对。' });
    } catch { /* Keep generic OS metadata only; do not expose record text. */ }
  }, 15_000).unref();
  app.on('before-quit', event => {
    if (quitting && !identity?.key) return;
    event.preventDefault(); void requestQuit();
  });
}
