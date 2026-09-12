/* License presentation follows the main process's persisted, verified status.
 * No sales codes, tickets, keys, or administrator credentials are persisted here. */
(() => {
  'use strict';
  const STATES = new Set(['unconfigured','device_required','preparation_required','inactive','active','expired','clock_recovery_required','pending','blocked']);
  const MODES = new Set(['full','readonly','activation_required']);
  const PLANS = {week:'周授权',month:'月授权',year:'年授权',perpetual:'永久授权'};
  const TITLES = {unconfigured:'授权服务尚未配置',device_required:'此电脑的设备保护尚不可用',preparation_required:'需要准备设备保护',inactive:'此电脑尚未激活',active:'此电脑已激活',expired:'授权已到期 · 只读查看',clock_recovery_required:'需要恢复授权时间',pending:'兑换结果待确认',blocked:'本机授权需要恢复'};
  const MUTATIONS = new Set(('seed related-editor edit media-pick media-import media-remove media-remove-confirm media-use claims-import claims-create claims-preview-once claims-token add-variant add-bundle add-gift remove-row delete-record delete-confirm clone-product clone-account delivery-execute verify resend order-refresh orders-refresh-visible sync inventory-import inventory-confirm inventory-adjust takeover ai-preview use-draft message-send snippets pick-snippet use-snippet batch-edit batch-execute integration-edit member-add notify-preview service-execute service-retry order-event-test order-event-confirm order-events-sync notify-send ai-test choose-import paste-import import-confirm account-add account-login account-login-retry account-hosting account-sync-one account-bulk-sync account-bulk-resume account-note account-archive account-archive-confirm').split(' '));
  const READ_FORMS = new Set(['auth-form','member-switch-form','password-form','recover-form','backup-password-form','service-stop-form','claim-revoke-form','statistics-form','rule-test-form','message-form','update-settings-form']);
  const date = value => {
    const time = typeof value === 'number' ? value : Date.parse(value);
    return Number.isFinite(time) ? new Intl.DateTimeFormat('zh-CN',{year:'numeric',month:'2-digit',day:'2-digit',hour:'2-digit',minute:'2-digit',hour12:false}).format(time) : '尚未确认';
  };
  window.createLianpuLicense = function createLianpuLicense(c) {
    let status = null, preview = null, code = '', requestInput = '', error = '', retryCode = false;
    let generation = 0, busy = false, surface = null;
    const full = () => status?.active === true && status?.accessMode === 'full';
    const requiresActivation = () => status?.accessMode === 'activation_required' || (!c.state.auth?.configured && !full());
    function accept(value) {
      if (!value || !STATES.has(value.state) || typeof value.active !== 'boolean' || !MODES.has(value.accessMode) || typeof value.device?.state !== 'string') {
        throw new Error('本机授权状态尚未取得完整结果，请重新检查。');
      }
      if (status && Number.isSafeInteger(status.generation) && Number.isSafeInteger(value.generation) && value.generation < status.generation) return;
      status = value;
      c.state.license = value;
      if(c.state.auth)c.state.auth.license=value;
    }
    function rememberInputs() {
      const root = surface === 'dialog' ? document.querySelector('#dialog [data-license-panel]') : document.querySelector('#license-gate');
      const input = root?.querySelector('[name="code"]');
      if (input) code = input.value.slice(0,80);
      const request = root?.querySelector('[name="requestId"]');
      if (request) requestInput = request.value.slice(0,36);
    }
    function model() {
      const s = status || {}, device = s.device || {}, pending = !!s.pending, valid = full();
      const ready = device.state === 'ready' && device.hardwareVerified !== false;
      const configured = !!status && s.state !== 'unconfigured';
      const v = {
        status:s.state || 'checking', active:valid, readOnly:s.accessMode === 'readonly',
        title:TITLES[s.state] || '正在检查软件授权', reason:s.reason || '正在读取本机授权与设备状态。',
        tone:valid?'success':['expired','pending','preparation_required','clock_recovery_required'].includes(s.state)?'warning':['blocked','device_required'].includes(s.state)?'danger':'info',
        banner:!!status && (!valid || pending), busy, error, code,
        device:{label:ready?'设备保护已就绪':device.requiresPreparation?'需要 Windows 确认':device.state==='checking'?'正在检测设备':'设备保护尚不可用',method:'自动识别 TPM 2.0',displayId:device.deviceId || '',protection:ready?'设备密钥由 Windows TPM 保护':'以本机检测结果为准'},
        entitlement:s.plan?{planLabel:PLANS[s.plan] || '尚未确认',expiresAt:s.expiresAt === null?'永久有效':date(s.expiresAt)}:null,
        pending:pending && !preview,
        pendingReason:s.pending?.reason || (valid?'续期结果尚待确认。现有授权仍按原期限有效；续期完成不会自动开启托管。':'请保留本次请求编号并恢复结果。尚未确认前，不需要另购兑换码。'),
        requestId:s.pending?.requestId || '',requestInput,
        showRedeem:configured && ready && (!pending || retryCode),canRedeem:configured && ready,
        showPrepare:device.requiresPreparation === true,
        showRecover:configured && ready,canRecover:configured && ready,
        showRetryCode:pending && !preview && !retryCode,
        recoveryHint:pending?'恢复会核验原请求，不会重新起算期限。若云端确认原请求尚未核销，可重新核对原兑换码。':'重装软件后可恢复此设备原有授权；本机记录缺失时，填写原请求编号。',
      };
      if (preview) {
        const p = preview.preview;
        v.precheck = {
          planLabel:PLANS[p.plan],durationLabel:p.plan === 'perpetual'?'永久有效':`${p.periodDays} 天`,
          deviceLabel:device.deviceId || '此电脑',displayCode:code?code.slice(0,5)+'…'+code.slice(-6):'',
          summary:'预核对通过，尚未核销兑换码或启用本次授权。',expiresAt:date(preview.expiresAt),
          consequence:valid?'确认后申请续期；原授权未到期时会在原到期时间上累加。以最终授权为准，托管仍需你手动开启。':'确认后开始兑换。只有取得最终签名授权并成功保存到此电脑，才会开放经营功能。',
          canConfirm:!!preview.requestId && Date.parse(preview.expiresAt) > Date.now(),
        };
      }
      return v;
    }
    function paint() {
      rememberInputs();
      if (surface === 'dialog' && document.querySelector('#dialog')?.open && document.querySelector('#license-dialog-body')) {
        document.querySelector('#license-dialog-body').innerHTML = window.LianpuLicenseViews.detail(model());
      }
      c.changed();
    }
    async function readStatus(token) { const value=await c.call('license.status');if(token===generation)accept(value); }
    async function run(task, {success = false} = {}) {
      if (busy) return;
      rememberInputs();const token = generation;busy = true;error = '';paint();
      try {
        await task(token);
        if (token !== generation) return;
        await readStatus(token);
        if (token !== generation) return;
        if (success && full() && !status.pending) {preview = null;code = '';requestInput = '';retryCode = false;c.toast('本机授权已核验并保存。托管需在经营账号中明确开启。');}
      } catch (err) {
        if (token !== generation || err?.code === 'UI_STALE') return;
        error = err.message || '授权操作未完成，请保留原请求后重试。';
        // This is a local status read, never a cloud retry.
        try { await readStatus(token); } catch (statusError) { if (token === generation) error += ' 本机状态暂未刷新：'+statusError.message; }
      } finally {
        if (token === generation) {busy = false;paint();}
      }
    }
    function reset() {generation++;busy=false;preview=null;code='';requestInput='';error='';retryCode=false;surface=null;}
    function closed() {if(surface === 'dialog')reset();}
    function canAction(name, element) {
      if (full() || name.startsWith('license-')) return true;
      if (name === 'account-pause') {const a=c.getAccount(element?.dataset.id);return !!a && a.paused !== true && (a.space === 'test' || a.hosting?.enabled === true);}
      if (name === 'batch-pause') {const batch=c.getBatch(element?.dataset.id);return batch?.paused !== true;}
      return !MUTATIONS.has(name);
    }
    function canSubmit(form) {const id=form.getAttribute('id')||'';return full() || id==='support-form' || id.startsWith('license-') || READ_FORMS.has(id);}
    function assertAction(name, element) {if(!canAction(name,element))throw new Error('当前软件授权仅允许查看与维护。请先在“软件授权”中激活或续期。');}
    function assertForm(form) {if(!canSubmit(form))throw new Error('当前为只读状态，尚不能保存新的经营变更。已有内容可查看、导出或备份。');}
    function enforce() {
      for (const element of document.querySelectorAll('[data-license-disabled="true"]')) {
        element.disabled=element.dataset.licenseWasDisabled==='true';delete element.dataset.licenseDisabled;delete element.dataset.licenseWasDisabled;
        if(element.dataset.licenseTitle)element.title=element.dataset.licenseTitle;else element.removeAttribute('title');delete element.dataset.licenseTitle;
      }
      if(full())return;
      const disable = element => {if(element.dataset.licenseDisabled==='true')return;element.dataset.licenseWasDisabled=String(!!element.disabled);element.dataset.licenseTitle=element.getAttribute('title')||'';element.disabled=true;element.dataset.licenseDisabled='true';element.title='当前软件授权仅允许查看与维护，请先激活或续期。';};
      for(const element of document.querySelectorAll('button[data-action],input[data-action]'))if(!canAction(element.dataset.action,element))disable(element);
      for(const form of document.querySelectorAll('form'))if(!canSubmit(form))for(const element of form.querySelectorAll('input,select,textarea,button[type="submit"]'))disable(element);
    }
    async function action(name) {
      if(busy && name !== 'license-open')return;
      switch(name) {
        case 'license-open':{
          if(document.querySelector('#dialog')?.open && !(await c.requestClose()))return;
          reset();surface='dialog';c.openDialog('此电脑的软件授权','<div id="license-dialog-body">'+window.LianpuLicenseViews.detail(model())+'</div>',{licenseFlow:true});
          return run(async()=>{});
        }
        case 'license-refresh':return run(async()=>{});
        case 'license-prepare':return run(async()=>{await c.call('license.prepareDevice');});
        case 'license-confirm':{
          if(!preview || !model().precheck.canConfirm) {error='本次核对已过期，请重新核对原兑换码后确认。';paint();return;}
          const requestId=preview.requestId;return run(async()=>{await c.call('license.confirm',{requestId});},{success:true});
        }
        case 'license-recover':{
          rememberInputs();const requestId=requestInput.trim();
          if(requestId&&!/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(requestId)){error='请填写完整的原请求编号，或留空使用本机记录。';paint();return;}
          preview=null;return run(async()=>{await c.call('license.recover',requestId?{requestId}:{});},{success:true});
        }
        case 'license-cancel':case 'license-retry-code':if(busy)return;generation++;preview=null;error='';retryCode=true;paint();return;
        default:throw new Error('未识别的授权操作。');
      }
    }
    async function submit(form) {
      if(form.getAttribute('id')!=='license-code-form')return;
      const entered=String(new FormData(form).get('code')||'').trim().toUpperCase();
      if(!/^LP1-[WMYP]-[A-F0-9]{40}$/.test(entered)){error='请粘贴完整的 LP1 兑换码，并核对是否漏字或多出空格。';paint();return;}
      code=entered;preview=null;
      return run(async token=>{
        const result=await c.call('license.precheck',{code:entered});
        if(token!==generation)return;
        const p=result?.preview,days={week:7,month:30,year:365,perpetual:null};
        if(!result?.requestId || !p || p.mode!=='activate' || !PLANS[p.plan] || p.periodDays!==days[p.plan] || !Number.isFinite(Date.parse(result.expiresAt)))throw new Error('本次核对缺少明确的套餐或期限，请保留原请求并重新检查。');
        preview=result;code=entered;retryCode=false;
      });
    }
    return {
      full,requiresActivation,model,accept,reset,closed,action,submit,enforce,assertAction,assertForm,
      handles:name=>name.startsWith('license-'),isBusy:()=>busy,
      gate:()=>{surface='gate';return window.LianpuLicenseViews.gate(model());},
      settings:()=>window.LianpuLicenseViews.settings(model()),banner:()=>window.LianpuLicenseViews.banner(model()),
      event:value=>{rememberInputs();accept(value);if(!busy)paint();else c.changed();},
      surface:()=>surface,
    };
  };
})();
