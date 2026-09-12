'use strict';
// Deliberately no environment-variable loader, shell command, download or vendor invocation.
// A future reviewed adapter belongs before ASAR creation, and must return a report in
// this shape. Acceptance of an adapter requires exact-runtime and business-operation
// evidence; a vendor declaration alone never changes effectiveness to verified.
function inspectProtectionProvider(request={id:'none'},runtime){
  if(!request||request.id!=='none'||Object.keys(request).some(key=>key!=='id')){
    const error=new Error('No commercial protection adapter is authorized and validated in this build. Review exact runtime, license, core coverage, sandbox, performance and recovery evidence before integrating one.');
    error.code='PROTECTION_PROVIDER_UNAVAILABLE';throw error;
  }
  return {format:'lianpu-protection-provider-v1',id:'none',status:'disabled',runtime,commercialProtectionVerified:false,
    integrationStage:'before ASAR; native signing and pinned digest refresh precede archive creation',
    requiredEvaluation:['exact Electron/Node/V8 ABI and Windows x64','vendor license and unattended CI rights','real protected core operation coverage','sandbox and security software unchanged','startup and long-running performance','offline/license-expiry/read-only/export/backup/upgrade recovery'],
    boundary:'This is a replaceable build seam, not installed vendor protection.'};
}
module.exports={inspectProtectionProvider};
