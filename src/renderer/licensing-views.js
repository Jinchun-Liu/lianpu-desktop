/* Original licensing presentation for the existing Lianpu UI system.
 * This module only renders an explicit view model. It never validates licenses,
 * chooses entitlement policy, calls a network endpoint, or stores a sales code. */
(() => {
  'use strict';
  const e = value => window.LianpuUI.escape(value);
  const button = (label, action, { primary = false, disabled = false, attrs = '' } = {}) => `<button type="button" data-action="${e(action)}"${primary ? ' class="primary"' : ''}${disabled ? ' disabled' : ''}${attrs ? ` ${attrs}` : ''}>${e(label)}</button>`;
  const line = (label, value) => value === undefined || value === null || value === '' ? '' : `<div><dt>${e(label)}</dt><dd>${e(value)}</dd></div>`;
  function device(vm) {
    const value = vm.device || {};
    return `<section class="license-device" data-license-device aria-labelledby="license-device-title"><h2 id="license-device-title">此电脑</h2><p class="license-device-state">${e(value.label || '正在读取设备状态')}</p>${value.reason ? `<p class="help">${e(value.reason)}</p>` : ''}<dl class="license-facts">${line('设备识别', value.method)}${line('设备摘要', value.displayId)}${line('本机保护', value.protection)}</dl><p class="help">设备信息由联铺自动检测，无需手动填写机器码。</p></section>`;
  }
  function entitlement(vm) {
    const item = vm.entitlement || {};
    const facts = [line('授权套餐', item.planLabel), line('授权开始', item.startsAt), line('有效期至', item.expiresAt), line('设备名额', item.seats), line('核验时间', item.verifiedAt)].join('');
    return facts ? `<dl class="license-facts license-entitlement">${facts}</dl>` : '';
  }
  function review(vm) {
    const item = vm.precheck;
    if (!item) return '';
    return `<section id="license-precheck-result" class="license-review" aria-labelledby="license-review-title"><h2 id="license-review-title">核对本次激活</h2><p>${e(item.summary || '请核对套餐和此电脑，再确认激活。')}</p><dl class="license-facts">${line('兑换码', item.displayCode)}${line('授权套餐', item.planLabel)}${line('有效期', item.durationLabel)}${line('本次设备', item.deviceLabel)}${line('设备名额', item.quotaLabel)}${line('预核有效期', item.expiresAt)}</dl>${item.consequence ? `<p class="license-confirm-note">${e(item.consequence)}</p>` : ''}<div class="form-end">${button('返回修改', 'license-cancel', { disabled: vm.busy })}${button(vm.busy ? '正在确认…' : '确认激活此电脑', 'license-confirm', { primary: true, disabled: vm.busy || !item.canConfirm })}</div></section>`;
  }
  function redeem(vm) {
    if (!vm.showRedeem) return '';
    return `<form id="license-code-form" class="license-code-form" autocomplete="off"><label for="license-code">销售兑换码<input id="license-code" name="code" type="text" maxlength="80" value="${e(vm.code || '')}" spellcheck="false" autocomplete="off" autocapitalize="characters" placeholder="粘贴销售方提供的 LP1 兑换码" required${vm.busy || !vm.canRedeem ? ' disabled' : ''}></label><p class="help">先核对兑换码与设备，再由你确认激活。</p><div class="form-end"><button type="submit" class="primary"${vm.busy || !vm.canRedeem ? ' disabled' : ''}>${vm.busy ? '正在核对…' : '核对兑换码'}</button></div></form>`;
  }
  function panel(vm) {
    const tone = ['success', 'warning', 'danger', 'info'].includes(vm.tone) ? vm.tone : 'info';
    return `<div class="license-panel" data-license-panel data-license-state="${e(vm.status || 'checking')}" aria-busy="${vm.busy ? 'true' : 'false'}"><div class="license-status license-status-${tone}" role="status"><strong>${e(vm.title || '正在检查软件授权')}</strong><p data-license-reason>${e(vm.reason || '正在读取本机授权与设备状态。')}</p></div>${vm.error ? `<div class="license-error" role="alert">${e(vm.error)}</div>` : ''}${entitlement(vm)}${vm.pending ? `<section class="license-pending"><h2>${vm.active ? '续期结果待确认' : '激活结果待确认'}</h2><p>${e(vm.pendingReason || '尚未取得可用的最终授权。请核验本次结果，不要再次提交新的兑换。')}</p></section>` : ''}${vm.requestId ? `<dl class="license-facts" data-license-request>${line('本次请求',vm.requestId)}</dl>` : ''}${review(vm)}${!vm.precheck ? redeem(vm) : ''}${vm.showRecover && !vm.precheck ? `<details class="license-recovery"><summary>使用原请求编号恢复</summary><label for="license-request-id">原请求编号（可留空）<input id="license-request-id" name="requestId" type="text" value="${e(vm.requestInput || '')}" maxlength="36" autocomplete="off" spellcheck="false" placeholder="留空使用本机保存的原请求"${vm.busy ? ' disabled' : ''}></label></details>` : ''}<div class="license-tools">${vm.showPrepare ? button('准备设备（可能需要 Windows 确认）', 'license-prepare', { primary:true,disabled:vm.busy }) : ''}${button('重新检查', 'license-refresh', { disabled: vm.busy })}${vm.showRecover ? button(vm.busy ? '正在处理…' : '恢复此电脑的授权', 'license-recover', { disabled: vm.busy || !vm.canRecover }) : ''}${vm.showRetryCode ? button('重新核对原兑换码', 'license-retry-code', { disabled:vm.busy }) : ''}</div>${vm.recoveryHint ? `<p class="help">${e(vm.recoveryHint)}</p>` : ''}</div>`;
  }
  function gate(vm) {
    return `<main id="main" class="license-gate-root" tabindex="-1"><section id="license-gate" aria-labelledby="license-gate-title"><header class="license-gate-header"><div class="brand"><span class="brand-symbol" aria-hidden="true">联</span><span class="license-brand-name">联铺</span></div><h1 id="license-gate-title">软件授权</h1><p>为此电脑核验使用授权。经营资料与本机成员保持独立管理。</p></header><div class="license-gate-layout">${device(vm)}${panel(vm)}</div><footer class="license-gate-footer"><span>软件授权不代表闲鱼账号已登录或平台已允许自动处理。</span>${vm.canContinueReadOnly ? button('继续查看已有资料', 'license-continue') : ''}</footer></section></main>`;
  }
  function settings(vm) {
    return `<div class="settings-row" data-license-settings><div><h2>软件授权</h2><p>${e(vm.title || '检查此电脑的软件授权')}</p></div><div class="fields"><p data-license-reason>${e(vm.reason || '打开授权详情，核对套餐、有效期与此电脑的授权状态。')}</p>${entitlement(vm)}${button('查看软件授权', 'license-open')}</div></div>`;
  }
  function banner(vm) {
    if (!vm.banner) return '';
    return `<div class="license-banner" role="status" data-license-readonly="${vm.readOnly ? 'true' : 'false'}"><div><strong>${e(vm.title)}</strong><span>${e(vm.reason)}</span></div>${button(vm.pending ? '核验激活结果' : '查看软件授权', 'license-open')}</div>`;
  }
  const detail = vm => `<div class="license-detail">${device(vm)}${panel(vm)}</div>`;
  window.LianpuLicenseViews = Object.freeze({ gate, panel, settings, banner, detail });
})();
