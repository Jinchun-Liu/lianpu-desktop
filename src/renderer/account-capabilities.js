/* Original account readiness presentation. No requests or credential access. */
(() => {
  'use strict';
  const reads=[['readProducts','商品同步','products'],['readMessages','消息同步','messages'],['readOrders','订单核验','orders']];
  const pendingFeatures=[
    ['发布与修改商品','当前版本未接入平台发布、改价与上下架，请在闲鱼 App 中操作。'],
    ['平台标记发货','资料发送与平台发货状态是两件事；本版本尚未接入平台标记发货。'],
    ['退款与实物物流','当前版本未接入，请在闲鱼 App 中办理退款、填写或查询实物物流。'],
    ['商品运营与买家互动','本机可整理计划；平台运营与互动执行入口尚未接入。'],
    ['收货后服务','收货事件尚未接入，赠品、致谢、收货提醒与评价邀请不会自动执行。'],
  ];
  function render(ctx,account){
    const {e,btn,badge}=ctx,caps=account.capabilities||{};
    const table=(headers,body)=>ctx.table(headers,body).replace('<table>','<table data-ux-table="off">');
    const loginNeeded=!account.platformUserId||['needs_login','login_required','expired','cleared','revoked','cleanup_failed','revocation_failed','identity_mismatch'].includes(account.loginStatus);
    const rows=reads.map(([key,label,kind])=>{
      const fact=caps[key],verified=fact?.available===true;
      const attempted=!!fact?.checkedAt||['unavailable','blocked'].includes(fact?.status);
      let status=verified?'已读取验证':loginNeeded?'需要登录':attempted?'本次未读到':'尚未检查';
      let reason=verified?fact.reason||'已从当前账号取得有效响应；可继续增量同步。':loginNeeded?'先完成本人扫码，再检查此项。':attempted&&fact?.reason||'点击检查即可读取，不需要开启自动托管。';
      if(verified&&/跳过/.test(fact.reason||''))status='已读取部分内容';
      if(!verified&&attempted&&fact?.reason&&/当前会话未提供|订单.*尚未核验|订单.*未能核验/.test(fact.reason))status='暂不可核验';
      const action=account.archived?'账号已归档':!ctx.canSync?'请联系管理员检查':loginNeeded?btn('扫码登录','account-login',`data-id="${e(account.id)}"`,'small'):btn(verified?'再次同步':'检查此项','account-read-one',`data-id="${e(account.id)}" data-kind="${kind}"`,'small');
      return `<tr><td>${label}</td><td>${badge(status)}</td><td>${e(reason)}${verified&&fact.verifiedAt?`<small>最近检查 ${e(ctx.when(fact.verifiedAt))}</small>`:''}</td><td>${action}</td></tr>`;
    });
    const send=caps.sendMessages||caps.sendMessage,connected=send?.available===true||account.connectionStatus==='connected';
    rows.push(`<tr><td>回复与资料发送</td><td>${badge(connected?'连接已就绪':'尚未就绪')}</td><td>${connected?'消息连接已认证；本次只读检查没有发送任何内容，也不代表送达验证通过。':'先检查消息连接。连接完成后，人工回复和资料交付仍会逐次检查接收方、规则与回执。'}</td><td>${btn('查看会话','account-related',`data-id="${e(account.id)}" data-route="messages"`,'small')}</td></tr>`);
    return `<p class="help">先检查商品、消息和订单，再配置资料与规则。检查与同步不会发送消息、发货、改价或退款；托管开关保持原样。</p>${table(['功能','当前状态','说明','下一步'],rows.join(''))}<details class="form-section"><summary>当前版本尚未接入的功能（${pendingFeatures.length} 类）</summary><p class="help">以下属于软件尚未完成的接入，不是你的账号设置问题，重复扫码不会让它们变为可用。</p>${table(['功能','使用安排'],pendingFeatures.map(([name,reason])=>`<tr><td>${name}</td><td>${reason}</td></tr>`).join(''))}</details>`;
  }
  window.LianpuAccountCapabilities=Object.freeze({render});
})();
