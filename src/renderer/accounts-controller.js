/* Account UI only. The trusted main process owns identity, sessions and hosting consent. */
(() => {
  'use strict';
  const LOGIN_STATES = {
    opening:'正在打开官方登录窗口', loading:'正在载入官方登录页', checking:'正在核验登录', page_open:'官方登录页已打开',
    awaiting_scan:'等待扫码', waiting_scan:'等待扫码', waiting_qr:'等待官方二维码', qr_ready:'等待扫码',
    waiting:'等待本人完成官方登录', scanned:'已扫码，等待手机确认', scanned_pending_confirmation:'已扫码，等待手机确认', awaiting_confirmation:'已扫码，等待手机确认',
    authenticated:'已取得登录身份，等待核对绑定', verified:'已取得登录身份，等待核对绑定',
    success:'已取得登录结果，等待核对身份', ready_to_bind:'已取得登录身份，等待核对绑定',
    expired:'本次登录已过期', cancelled:'本次登录已取消', canceled:'本次登录已取消',
    closed:'官方登录窗口已关闭', failed:'本次登录未完成', error:'本次登录未完成',
    blocked:'平台暂不允许继续登录', verification_required:'需要本人在官方页面完成验证',
    manual_verification:'需要本人在官方页面完成验证', needs_verification:'需要本人在官方页面完成验证',
    identity_mismatch:'扫码账号与目标账号不一致', bound:'本次身份已绑定'
  };
  const TERMINAL = new Set(['expired','cancelled','canceled','closed','failed','error','blocked','identity_mismatch','bound']);
  const ACTIONS = new Set(['account-add','account-login','account-login-retry','account-login-check','account-login-cancel','account-detail','account-status','account-hosting','account-pause','account-sync-one','account-bulk-sync','account-bulk-pause','account-bulk-resume','account-note','account-revoke','account-clear-confirm','account-archive','account-archive-confirm','account-related']);
  window.createLianpuAccounts = c => {
    const {state,e,btn,notice,field,check,openDialog,call,rawCall,reload,toast}=c;
    const $ = s => document.querySelector(s);
    let generation=0, attempt=null, timer=null, pollBusy=false, searchTimer=null, bulkGeneration=0;
    let search='',filter='all',selected=new Set(), formAccounts=[];
    const allowed = () => ['owner','operator'].includes(state.auth?.user?.role);
    const archived = a => a.archived===true||a.status==='archived';
    const context = () => ({...c.views(),accounts:c.rows('accounts'),selected,search,filter,canManage:allowed(),canAdd:state.auth?.user?.role==='owner',space:state.space});
    function invalidateAttempt() {
      generation++;clearTimeout(timer);timer=null;pollBusy=false;
      const previous=attempt;attempt=null;
      if(previous?.attemptId)rawCall('account.login.cancel',{attemptId:previous.attemptId}).catch(()=>{});
    }
    function reset() {invalidateAttempt();bulkGeneration++;clearTimeout(searchTimer);search='';filter='all';selected.clear();formAccounts=[];}
    const valid = token => token.generation===generation&&token.epoch===c.epoch()&&!state.auth?.locked&&$('#dialog')?.open&&$('#account-login-state');
    async function dialogRequest(action,payload,token) {
      try {const result=await call(action,payload);if(token!==generation){const error=new Error('旧窗口的操作结果已取消显示。');error.code='UI_STALE';throw error;}return result;}
      catch(error){if(token!==generation){const stale=new Error('旧窗口的操作结果已取消显示。');stale.code='UI_STALE';throw stale;}throw error;}
    }
    function publicIdentity(result) {
      const identity=result?.identity||{};
      return {id:identity.platformUserId||result?.platformUserId||result?.externalId||'',nickname:identity.nickname||result?.nickname||''};
    }
    function paintLogin(result,token) {
      if(!valid(token))return;
      const status=result.status||result.state||'unverified',identity=publicIdentity(result);
      attempt.result=result;
      const stopped=TERMINAL.has(status);
      $('#account-login-state').innerHTML=`<div class="account-login-progress" data-login-status="${e(status)}" role="status" aria-live="polite"><span class="account-login-symbol" aria-hidden="true">${stopped?'!':'↗'}</span><div><h3>${e(LOGIN_STATES[status]||'登录状态待核验')}</h3><p>${e(result.reason||'请在独立的闲鱼官方窗口中完成扫码；此处只显示连接器已观察到的结果。')}</p>${!LOGIN_STATES[status]?`<small>连接器状态：${e(status)}</small>`:''}${result.expiresAt?`<small>连接器报告的有效期：${e(c.when(result.expiresAt))}</small>`:''}</div></div>`;
      const identityArea=$('#account-login-identity');
      const canBind=!!identity.id&&!stopped;
      if(canBind&&identityArea.dataset.identity!==String(identity.id)) {
        identityArea.dataset.identity=String(identity.id);
        const target=c.get('accounts',token.accountId), duplicate=c.rows('accounts').find(a=>(a.platformUserId||a.externalId)===identity.id);
        const mismatch=!!target&&(target.platformUserId||target.externalId)&&String(target.platformUserId||target.externalId)!==String(identity.id);
        identityArea.innerHTML=`<section class="form-section"><h3>核对本次扫码身份</h3><dl class="detail-grid"><dt>平台昵称</dt><dd>${e(identity.nickname||'平台尚未提供昵称')}</dd><dt>平台账号标识</dt><dd class="wrap">${e(identity.id)}</dd>${target?`<dt>目标本机账号</dt><dd>${e(target.name)}</dd>`:''}</dl>${mismatch?notice('扫码身份与原账号不一致。不能覆盖原账号，请取消后重新扫描正确账号。','error'):`${duplicate?notice('该身份已存在。确认后更新原账号会话，保留原有档案和交付历史；需要重新开启托管。'):notice('确认绑定后账号仍保持未托管。配置好资料和规则后，再明确开启自动处理。')}<form id="account-bind-form">${field('name','本机显示名称',target?.name||duplicate?.name||identity.nickname,'text','仅用于在联铺中辨认账号。',true)}${field('note','账号备注',target?.note||duplicate?.note||'','textarea')}<div class="form-end">${btn('取消本次登录','account-login-cancel')}<button type="submit" class="primary">确认绑定此身份</button></div></form>`}</section>`;
        window.LianpuUX.markClean(identityArea);window.LianpuUX.markClean($('#dialog'));
      } else if(!canBind&&identityArea.dataset.identity) {identityArea.innerHTML='';delete identityArea.dataset.identity;window.LianpuUX.markClean($('#dialog'));}
      $('#account-login-tools').innerHTML=`${btn('取消本次登录','account-login-cancel')}${!stopped?btn('检查最新状态','account-login-check'):''}${btn('重新扫码','account-login-retry',`data-id="${e(token.accountId||'')}"`,stopped?'primary':'')}`;
      if(!stopped)timer=setTimeout(()=>poll(token),1500);
    }
    async function poll(token) {
      if(!valid(token)||!attempt?.attemptId||pollBusy)return;
      clearTimeout(timer);pollBusy=true;
      try {const result=await rawCall('account.login.status',{attemptId:attempt.attemptId});if(valid(token))paintLogin(result,token);}
      catch(error){if(valid(token)){$('#account-login-state').innerHTML=notice(`状态读取未完成：${e(error.message)}。可重试检查，或取消后重新扫码。`,'error');}}
      finally{if(token.generation===generation)pollBusy=false;}
    }
    async function start(accountId) {
      if(state.space!=='live')throw new Error('扫码登录仅在真实经营工作区使用。请切换到真实经营；隔离测试不会连接闲鱼。');
      if(!allowed())throw new Error('当前成员没有账号经营权限。');
      if($('#dialog')?.open&&!(await window.LianpuUX.requestClose($('#dialog'))))return;
      invalidateAttempt();const token={generation,epoch:c.epoch(),accountId:accountId||undefined};attempt={...token};
      openDialog(accountId?'重新扫码登录此账号':'添加闲鱼账号',`${notice('请用本人闲鱼 App 扫描独立官方窗口中的二维码，并在手机上核对确认。联铺不会要求你填写闲鱼密码、Cookie 或平台编号。')}<ol class="account-login-steps"><li>官方窗口扫码</li><li>核对身份并绑定</li><li>配置后开启托管</li></ol><section id="account-login-state" aria-busy="true"><p>正在请求打开官方登录窗口…</p></section><div id="account-login-identity"></div><div id="account-login-tools" class="form-end">${btn('取消本次登录','account-login-cancel')}</div>`,{accountFlow:true});
      try {
        const result=await rawCall('account.login.start',accountId?{accountId}:{});
        if(!valid(token)){if(result?.attemptId||result?.id)rawCall('account.login.cancel',{attemptId:result.attemptId||result.id}).catch(()=>{});return;}
        attempt.attemptId=result?.attemptId||result?.id;
        $('#account-login-state').removeAttribute('aria-busy');
        if(!attempt.attemptId)throw new Error('登录服务未返回有效尝试编号，请重试。');
        paintLogin(result,token);
      } catch(error) {if(valid(token)){$('#account-login-state').removeAttribute('aria-busy');$('#account-login-state').innerHTML=notice(e(error.message),'error');$('#account-login-tools').innerHTML=btn('关闭','close-dialog')+btn('重试打开官方窗口','account-login-retry',`data-id="${e(accountId||'')}"`,'primary');}}
    }
    function records(ids) {return ids.map(id=>c.get('accounts',id)).filter(a=>a&&!archived(a));}
    function syncSummary(result,kind) {
      const label={products:'商品',orders:'订单',messages:'消息'}[kind],status={ok:'同步完成',test_only:'仅隔离数据'}[result?.status]||c.t(result?.status||'已返回');
      const count=result?.synced??result?.count,errors=Array.isArray(result?.errors)?result.errors:[];
      const reason=[result?.reason||result?.message,...errors.slice(0,10).map(error=>`${error.externalId?'记录 '+error.externalId+'：':''}${error.message||error.reason||'此条记录未通过检查'}`),errors.length>10?`另有 ${errors.length-10} 条记录未通过检查。`:null].filter(Boolean).join('；');
      return `${label}：${status}${count!==undefined?'（'+count+' 条）':''}${reason?' · '+reason:''}`;
    }
    function selectedAccounts() {const items=records([...selected]);if(!items.length)throw new Error('请先勾选需要处理的账号。');return items;}
    function showHosting(accounts) {
      formAccounts=accounts.map(a=>a.id);const old=accounts.length===1?accounts[0].hosting||{}:{};
      openDialog(accounts.length===1?'设置账号托管':'批量恢复账号托管',`<form id="account-hosting-form"><p>本次账号：<strong>${accounts.map(a=>e(a.name)).join('、')}</strong></p>${notice('开启后，在已配置的资料、规则和本次授权范围内持续处理。最小化、闲置与 Windows 锁屏期间继续；休眠、退出、关机或更新后停止。唤醒或重开仍保持本机登录，核对任务后需明确恢复托管；闲鱼会话失效时需重新扫码。')}<div class="account-hosting-options">${check('sync','同步商品、订单与消息',old.sync!==false)}${check('replies','按已启用规则自动答复买家',old.replies!==false)}${check('paidDelivery','向符合条件的已付款订单自动发送资料',old.paidDelivery!==false)}</div><p class="help">发送仍需当前会话的真实能力、订单事实、资料和规则检查。结果不明的旧尝试会保留并等待核验，不自动重发。商品发布、改价、退款及后续服务不在默认三项授权内。</p><details class="form-section account-hosting-extra"><summary>其他已配置任务（需单独授权）</summary><p class="help">只执行已启用且通过平台能力与业务检查的任务。没有真实能力时会报告受阻，不把保存配置当成可执行。此处不启用退款。</p>${check('services','运行已启用的收货后服务与买家互动规则',false)}${check('plans','运行已启用的商品运营计划（可能修改平台商品）',false)}<p class="help">保存本次选择会替换这五项托管授权。以上扩展任务每次都需另行勾选，未勾选则不继续授权。</p></details><label class="check-label"><input name="consent" type="checkbox" required><span>我确认这些是我有权经营的账号，并允许以上选定的持续自动处理。</span></label><div class="form-end">${btn('取消','close-dialog')}<button type="submit" class="primary">开启所选托管</button></div></form>`);
    }
    async function runBatch(accounts,operation,options={}) {
      const token=++bulkGeneration,epoch=c.epoch();
      openDialog(operation==='sync'?'逐账号同步结果':'逐账号托管设置结果',`${notice('按账号逐项显示实际结果。关闭此窗口将停止提交剩余项目；已经提交的操作仍会保留其结果。')}<div id="account-batch-results" aria-live="polite"></div><p id="account-batch-progress" role="status"></p><div class="form-end">${btn('关闭','close-dialog')}</div>`);
      const items=accounts.map(a=>({id:a.id,name:a.name,status:'等待处理',reason:''}));
      const active=()=>token===bulkGeneration&&epoch===c.epoch()&&!state.auth?.locked&&$('#account-batch-results');
      const paint=()=>{if(!active())return;$('#account-batch-results').innerHTML=c.table(['账号','实际结果','说明'],items.map(item=>`<tr data-account-result="${e(item.id)}"><td>${e(item.name)}</td><td>${e(item.status)}</td><td>${e(item.reason)}</td></tr>`).join(''));};paint();
      for(let i=0;i<items.length;i++) {
        if(!active())break;const item=items[i];item.status='正在处理';paint();
        try {
          if(operation==='sync') {
            const details=[];
            for(const kind of ['products','orders','messages']) {
              if(!active())break;
              try {const result=await call('account.sync',{id:item.id,kind});details.push(syncSummary(result,kind));}
              catch(error){if(error.code==='UI_STALE')throw error;details.push(`${{products:'商品',orders:'订单',messages:'消息'}[kind]}：未完成，${error.message}`);}
            }
            item.status='已取得逐项结果';item.reason=details.join('；');
          } else if(c.get('accounts',item.id)?.space==='test') {await call('account.pause',{id:item.id,paused:operation!=='resume'});item.status=operation==='resume'?'隔离处理已恢复':'隔离处理已暂停';item.reason='仅调整隔离测试账号，不代表真实平台托管。';}
          else {await call('account.hosting.save',{accountId:item.id,enabled:operation==='resume',...options});item.status=operation==='resume'?'托管授权已保存':'托管已暂停';item.reason=operation==='resume'?'实际连接和执行能力请核对账号状态。':'未提交的自动任务停止；已提交结果仍保留。';}
        } catch(error){if(error.code==='UI_STALE')return;item.status='未完成';item.reason=error.message;}
        paint();if(active())$('#account-batch-progress').textContent=`已检查 ${i+1} / ${items.length} 个账号，请逐项核对结果。`;
      }
      if(epoch===c.epoch()&&!state.auth?.locked){selected.clear();await reload();}
    }
    function detail(id,observation) {const a=c.get('accounts',id);if(!a)throw new Error('账号已不在当前范围，请刷新列表。');const checked=observation?`<section class="form-section"><h3>本次连接检查</h3>${notice(e(observation.reason||'连接器已返回当前检查结果。'))}<p>登录：${e(window.LianpuAccountViews.status(observation).login)} · 消息：${e(window.LianpuAccountViews.status(observation).connection)}</p>${c.views().renderCapabilities({capabilities:observation.capabilities})}</section>`:'';openDialog(a.name||'账号详情',checked+window.LianpuAccountViews.details(context(),a),{sheet:true});}
    async function action(name,element) {
      const id=element?.dataset.id;
      if(['account-note','account-archive','account-archive-confirm'].includes(name)&&state.auth?.user?.role!=='owner')throw new Error('编辑账号档案或移除账号需要本机管理员权限。');
      switch(name) {
        case 'account-add':case 'account-login':case 'account-login-retry':return start(id);
        case 'account-login-check':return attempt&&poll({...attempt});
        case 'account-login-cancel':if(await window.LianpuUX.requestClose($('#dialog')))invalidateAttempt();return;
        case 'account-detail':return detail(id);
        case 'account-status':{const token=generation,observation=await dialogRequest('platform.status',{accountId:id},token);await reload();if(token===generation)return detail(id,observation);return;}
        case 'account-hosting':return showHosting(records([id]));
        case 'account-pause':{const a=c.get('accounts',id);if(a?.space==='test')return runBatch(records([id]),a.paused?'resume':'pause');return a?.paused||!a?.hosting?.enabled?showHosting(records([id])):runBatch(records([id]),'pause');}
        case 'account-sync-one':return runBatch(records([id]),'sync');
        case 'account-bulk-sync':return runBatch(selectedAccounts(),'sync');
        case 'account-bulk-pause':return runBatch(selectedAccounts(),'pause');
        case 'account-bulk-resume':return state.space==='test'?runBatch(selectedAccounts(),'resume'):showHosting(selectedAccounts());
        case 'account-note':{const a=c.get('accounts',id);openDialog('编辑本机名称与备注',`<form id="account-note-form" data-id="${e(id)}">${field('name','本机显示名称',a?.name,'text','修改本机名称不会改变平台身份。',true)}${field('note','账号备注',a?.note,'textarea')}<div class="form-end">${btn('取消','close-dialog')}<button type="submit" class="primary">保存名称与备注</button></div></form>`);return;}
        case 'account-revoke':openDialog('清除此账号的本机登录',`${notice('将停止此账号托管并清除联铺保存的本机会话。业务档案和交付历史保留，其他设备的登录不受影响。','warn')}<p>${e(c.get('accounts',id)?.name)}</p><div class="form-end">${btn('取消','close-dialog')}${btn('确认清除本机登录','account-clear-confirm',`data-id="${e(id)}"`,'danger')}</div>`);return;
        case 'account-clear-confirm':{const token=generation;await dialogRequest('account.login.clear',{accountId:id},token);await reload();if(token===generation)return detail(id);return;}
        case 'account-archive':openDialog('移除账号并保留已引用历史',`${notice('将停止此账号托管并清除本机登录。已有商品、订单、库存、规则或交付引用时，只归档账号并保留关联历史；没有引用的账号可从本机删除。','warn')}<p>${e(c.get('accounts',id)?.name)}</p><div class="form-end">${btn('取消','close-dialog')}${btn('确认移除账号','account-archive-confirm',`data-id="${e(id)}"`,'danger')}</div>`);return;
        case 'account-archive-confirm':{const token=generation,result=await dialogRequest('account.remove',{accountId:id},token);if(state.accountId===id){await c.changeScope(state.space,'');if(state.auth?.locked)return;}else {await reload();if(token!==generation)return;}c.resultDialog('账号移除结果',result,notice('请以本次实际返回的归档或删除状态为准。'));return;}
        case 'account-related':if(await window.LianpuUX.requestClose($('#dialog'))){if(await c.changeScope(state.space,id))await c.navigate(element.dataset.route);}return;
      }
    }
    async function submit(form) {
      const fd=new FormData(form);
      if(form.id==='account-bind-form') {
        if(!attempt?.attemptId)throw new Error('登录尝试已失效，请重新扫码。');
        const token={...attempt};clearTimeout(timer);
        let result;
        try{result=await rawCall('account.login.bind',{attemptId:token.attemptId,name:String(fd.get('name')||''),note:String(fd.get('note')||'')});}
        catch(error){if(!valid(token))return;throw error;}
        if(!valid(token))return;
        attempt=null;generation++;window.LianpuUX.closeDialog($('#dialog'),{force:true});
        const accountId=result.accountId||result.account?.id;
        if(accountId)await c.changeScope('live',accountId);else await reload();
        toast(result.duplicate?'已更新原账号会话，历史保留。请重新核对并开启托管。':'账号身份已绑定，尚未开启自动托管。');
        if(accountId)detail(accountId);return;
      }
      if(form.id==='account-hosting-form') {if(fd.get('consent')!=='on')throw new Error('请先确认本次持续托管授权。');return runBatch(records(formAccounts),'resume',{sync:fd.get('sync')==='on',replies:fd.get('replies')==='on',paidDelivery:fd.get('paidDelivery')==='on',services:fd.get('services')==='on',plans:fd.get('plans')==='on'});}
      if(form.id==='account-note-form') {const token=generation;await dialogRequest('entity.save',{kind:'accounts',record:{id:form.dataset.id,name:String(fd.get('name')||''),note:String(fd.get('note')||'')}},token);await reload();if(token===generation)return detail(form.dataset.id);return;}
    }
    function change(target) {
      if(target.hasAttribute('data-account-filter')){filter=target.value;selected.clear();c.render();return true;}
      if(target.hasAttribute('data-account-check')){target.checked?selected.add(target.dataset.accountCheck):selected.delete(target.dataset.accountCheck);updateSelection();return true;}
      if(target.hasAttribute('data-account-check-all')){document.querySelectorAll('[data-account-check]:not(:disabled)').forEach(box=>{box.checked=target.checked;target.checked?selected.add(box.dataset.accountCheck):selected.delete(box.dataset.accountCheck);});updateSelection();return true;}
      return false;
    }
    function updateSelection() {
      const target=$('[data-account-selection-summary]');if(target)target.textContent=`已选择 ${selected.size} 个账号`;
      document.querySelectorAll('[data-action^="account-bulk-"]').forEach(button=>{button.disabled=!allowed()||!selected.size;button.setAttribute('aria-disabled',String(button.disabled));});
      const boxes=Array.from(document.querySelectorAll('[data-account-check]:not(:disabled)')),all=$('[data-account-check-all]');
      if(all){const count=boxes.filter(box=>box.checked).length;all.checked=!!boxes.length&&count===boxes.length;all.indeterminate=count>0&&count<boxes.length;}
    }
    function input(target) {if(!target.hasAttribute('data-account-search'))return false;search=target.value;selected.clear();clearTimeout(searchTimer);const epoch=c.epoch(),position=target.selectionStart;searchTimer=setTimeout(()=>{if(epoch!==c.epoch()||state.auth?.locked)return;c.render();const input=$('[data-account-search]');input?.focus();input?.setSelectionRange(position,position);},160);return true;}
    return {page:()=>window.LianpuAccountViews.page(context()),handles:name=>ACTIONS.has(name),action,submit,handlesForm:form=>['account-bind-form','account-hosting-form','account-note-form'].includes(form.id),change,input,reset,invalidateAttempt,dialogClosed:()=>{invalidateAttempt();bulkGeneration++;},clearSelection:()=>{selected.clear();updateSelection();}};
  };
})();
