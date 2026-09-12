'use strict';
// Explicit exceptions remain subject to the existing member/account permissions.
const MAINTENANCE=new Set([
  'auth.status','auth.setup','auth.unlock','auth.recover','auth.changePassword','auth.lock','auth.stopAndLock',
  'license.status','license.prepareDevice','license.precheck','license.confirm','license.recover',
  'hosting.stopAll','workspace.snapshot','account.details','account.runtime.status','account.login.status','account.login.cancel','account.login.clear','platform.revoke','platform.status',
  'app.preferences.get','app.preferences.save','app.editState','app.activity','app.quit','requirements.status',
  'statistics.get','backup.create','backup.chooseRestore','backup.unlockRestore','backup.preview','backup.restore','data.export','file.export','diagnostics.export','diagnostics.save',
  'update.status','update.settings.save','update.check','update.chooseManifest','update.prepare','update.install',
  'media.list','claims.files','claims.grants','claims.access','claims.revoke','notifications.settings.get','notifications.list','notifications.read','notification.read',
  'delivery.preview','rules.preview','message.preview','reply.preview','batch.preview','service.preview','interaction.preview','service.stop'
]);
function needsLicense(action,payload={}){
  if(MAINTENANCE.has(action))return false;
  if(action==='account.hosting.save'&&payload.enabled===false)return false;
  if(action==='account.pause'&&payload.paused===true)return false;
  if(action==='batch.pause'&&payload.paused!==false)return false;
  return true;
}
module.exports={needsLicense,MAINTENANCE};
