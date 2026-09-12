'use strict';
// Defense in depth for the official build. This is not an attestation of a
// process controlled by an administrator, and ignored environment values are
// deliberately not treated as proof of tampering.
const UNSAFE_SWITCHES = Object.freeze([
  'no-sandbox', 'disable-sandbox', 'disable-web-security',
  'remote-debugging-port', 'remote-debugging-pipe',
  'inspect', 'inspect-brk', 'inspect-port', 'js-flags'
]);
class RuntimePolicy {
  constructor({packaged,hasSwitch=()=>false}={}) { this.packaged=packaged===true;this.hasSwitch=hasSwitch; }
  status() {
    const blocked=this.packaged&&UNSAFE_SWITCHES.some(name=>this.hasSwitch(name));
    return {allowed:!blocked,code:blocked?'SECURITY_LAUNCH_POLICY':null,
      reason:blocked?'检测到调试或关闭安全隔离的启动参数，已停止新的经营动作。诊断编号 SECURITY_LAUNCH_POLICY；请退出后从原安装快捷方式重新打开，仍异常时用经核验的安装包修复。现有资料可查看、导出和备份。':null};
  }
  assertAllowed() {
    const status=this.status();
    if(!status.allowed)throw Object.assign(new Error(status.reason),{code:status.code,licensePreSubmission:true});
    return true;
  }
}
function isTrustedSender(event,window,expectedUrl) {
  try { return !!window&&!window.isDestroyed()&&event.sender===window.webContents&&event.senderFrame===window.webContents.mainFrame&&event.senderFrame.url===expectedUrl; }
  catch { return false; }
}
module.exports={RuntimePolicy,UNSAFE_SWITCHES,isTrustedSender};
