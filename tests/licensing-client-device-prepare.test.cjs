'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path'),vm=require('node:vm'),crypto=require('node:crypto');
const {createRequire}=require('node:module');
const {LicenseClient}=require('../src/licensing/client.cjs');
// Hypothesis: interrupted elevation and failed child processes cannot become ready,
// and the original caller must prove signing before every successful preparation.
// Decision: preserve accurate failure/retry semantics without another UAC or key write.
// Stop after distinct interruption, cancellation, process, permission and proof paths.
// All child processes below are test-local substitutes; no native helper is executed.
const filename=path.resolve(__dirname,'../src/licensing/device.cjs'),source=fs.readFileSync(filename,'utf8'),nativeRequire=createRequire(filename);
function fixture({elevationError=null,signFailure=false,diagnostic={kind:'completed',exitCode:0}}={}){
  const pair=crypto.generateKeyPairSync('ec',{namedCurve:'prime256v1'}),spki=pair.publicKey.export({type:'spki',format:'der'});
  const ready={version:1,ok:true,state:'ready',testMode:false,tpm:{present:true,version:'2.0'},storage:{prepared:true},publicKeySpki:spki.toString('base64url'),deviceId:crypto.createHash('sha256').update(spki).digest('hex'),key:{prepared:true,provider:'Microsoft Platform Crypto Provider',machineKey:true,hardwareBacked:true,exportable:false,algorithm:'ECDSA_P256',implementationFlags:1}};
  const calls={elevations:0,signs:0,status:0,prepare:0};
  const substitutes={execFile(file,args,options,callback){assert.match(file,/powershell\.exe$/i);assert.equal(options.timeout,120000);calls.elevations++;queueMicrotask(()=>callback(elevationError,''));return {stdin:{end(){}}};},spawnSync(_file,args,options){assert.deepEqual(Array.from(args),['sign']);calls.signs++;const challenge=Buffer.from(options.input,'base64url'),signature=crypto.sign('sha256',challenge,{key:pair.privateKey,dsaEncoding:'ieee-p1363'}).toString('base64url');return {status:signFailure?null:0,signal:signFailure?'SIGTERM':null,error:signFailure?Object.assign(new Error('test interrupted'),{killed:true}):undefined,stdout:JSON.stringify({...ready,signature,signatureFormat:'ieee-p1363',hashAlgorithm:'SHA-256'})};}};
  const module={exports:{}};vm.runInNewContext(source,{module,exports:module.exports,require:name=>name==='node:child_process'?substitutes:nativeRequire(name),__dirname:path.dirname(filename),Buffer,process},{filename});
  const device=new module.exports.TpmDevice();device._available=()=>{};
  device._elevate=async()=>{calls.elevations++;return module.exports.elevationOutcome(elevationError,diagnostic);};
  const denied={version:1,ok:false,state:'needs_admin',testMode:false,tpm:{present:true,version:'2.0'},storage:{prepared:true},code:'ACCESS_DENIED',operation:'key.open',nativeCode:'0x80090010'};
  device.status=async()=>{calls.status++;return device.info=structuredClone(denied);};
  device.invoke=async command=>{assert.equal(command,'prepare');calls.prepare++;return structuredClone(denied);};
  return {device,calls,ready,denied,exports:module.exports};
}
test('timed-out elevation with null exit code remains unconfirmed and never rechecks/signs/re-prompts',async()=>{
  const f=fixture({elevationError:{code:null,killed:true,signal:'SIGTERM'}}),result=await f.device.prepare();
  assert.equal(result.ok,false);assert.equal(result.code,'DEVICE_PREPARATION_UNCONFIRMED');assert.equal(result.preparation.kind,'unconfirmed');assert.equal(f.device.validate(),false);
  assert.deepEqual(f.calls,{elevations:1,signs:0,status:1,prepare:1});assert.doesNotMatch(result.message,/已报告取消/);
});
test('only explicit Windows 1223 is cancellation; exit failure and launch failure remain distinct',async()=>{
  for(const [error,code] of [[{code:1223},'DEVICE_PREPARATION_CANCELLED'],[{code:20},'DEVICE_PREPARATION_WRAPPER_FAILED'],[{code:'ENOENT'},'DEVICE_PREPARATION_LAUNCH_FAILED']]){
    const f=fixture({elevationError:error}),result=await f.device.prepare();assert.equal(result.code,code);assert.equal(result.ok,false);assert.equal(f.calls.elevations,1);assert.equal(f.calls.signs,0);
  }
  const {preparationScript,elevatedPreparationScript}=fixture().exports,helper="C:\\Program Files\\Lianpu's\\Lianpu.Device.exe",hash='a'.repeat(64),pipe='Lianpu.Device.Preparation.'+'b'.repeat(48),script=preparationScript(helper,hash,pipe);
  assert.match(script,/NativeErrorCode -eq 1223/);assert.match(script,/exit 1223\}; exit 1/);assert.match(script,/-EncodedCommand /);assert.match(elevatedPreparationScript(helper,hash,pipe),/Lianpu''s/);
});
test('elevated process completion does not hide the original user key access failure',async()=>{
  const f=fixture(),result=await f.device.prepare();assert.equal(result.code,'DEVICE_PREPARATION_ACCESS_UNCONFIRMED');assert.equal(result.nativeDeviceCode,'ACCESS_DENIED');assert.equal(result.operation,'key.open');assert.equal(result.nativeCode,'0x80090010');assert.equal(result.preparation.exitCode,0);assert.equal(f.calls.status,2);assert.equal(f.calls.signs,0);
});
test('non-elevated successful native preparation still requires a fresh verified signature',async()=>{
  const f=fixture();f.device.status=async()=>{f.calls.status++;return f.device.info={...f.denied,state:'not_prepared'};};f.device.invoke=async()=>{f.calls.prepare++;return structuredClone(f.ready);};
  const result=await f.device.prepare();assert.equal(result.ok,true);assert.equal(f.device.validate(),true);assert.equal(f.calls.elevations,0);assert.equal(f.calls.signs,1);
});
test('valid-looking signed JSON from a failed process cannot mark preparation ready',async()=>{
  const f=fixture({signFailure:true});f.device.status=async()=>{f.calls.status++;return f.device.info=structuredClone(f.ready);};
  const result=await f.device.prepare();assert.equal(result.ok,false);assert.equal(result.code,'DEVICE_SIGN_FAILED');assert.equal(f.device.validate(),false);assert.equal(f.calls.elevations,0);assert.equal(f.calls.signs,1);
});
test('native ready with incomplete storage is rejected before any signing',async()=>{
  const f=fixture();f.device.status=async()=>{f.calls.status++;return f.device.info={...f.denied,state:'not_prepared'};};f.device.invoke=async()=>{f.calls.prepare++;return {...structuredClone(f.ready),storage:{prepared:false}};};
  const result=await f.device.prepare();assert.equal(result.ok,false);assert.equal(result.code,'DEVICE_PREPARATION_INCOMPLETE');assert.equal(f.device.validate(),false);assert.equal(f.calls.signs,0);assert.equal(f.calls.elevations,0);
});
test('public status preserves unconfirmed preparation reason and safe native diagnostics while cloud stays unconfigured',async()=>{
  const f=fixture({elevationError:{code:null,killed:true,signal:'SIGTERM'}});await f.device.prepare();
  const client=new LicenseClient({device:f.device,config:{endpoint:null,publicKeys:{}},directory:path.join(__dirname,'work','unused-device-prepare-state')});
  const status=client.status();assert.equal(status.active,false);assert.equal(status.state,'unconfigured');assert.equal(status.device.hardwareVerified,false);assert.equal(status.device.reason,f.device.info.message);assert.equal(status.device.diagnostic.code,'DEVICE_PREPARATION_UNCONFIRMED');assert.equal(status.device.diagnostic.preparation.kind,'unconfirmed');
});
test('current elevated ACL conflict replaces stale ACCESS_DENIED without copying arbitrary diagnostic fields',async()=>{
  const f=fixture(),{parsePreparationDiagnostic}=f.exports;
  const diagnostic=parsePreparationDiagnostic(JSON.stringify({version:1,kind:'native-failure',exitCode:1,nativeFailure:{state:'error',code:'KEY_ACL_POLICY_CONFLICT',operation:'key.acl',nativeCode:'0x80090010',message:'arbitrary content',privateKey:'must-not-propagate'},publicKeySpki:'untrusted',ok:true}));
  f.device._elevate=async()=>{f.calls.elevations++;return diagnostic;};
  const result=await f.device.prepare();assert.equal(result.code,'KEY_ACL_POLICY_CONFLICT');assert.equal(result.nativeDeviceCode,'KEY_ACL_POLICY_CONFLICT');assert.equal(result.operation,'key.acl');assert.match(result.message,/KEY_ACL_POLICY_CONFLICT/);assert.equal(JSON.stringify(result).includes('must-not-propagate'),false);assert.equal(JSON.stringify(result).includes('ACCESS_DENIED'),false);assert.equal(f.calls.signs,0);assert.equal(f.calls.status,1);
});
test('wrapper timeout, missing diagnostic and wrapper failure remain distinct and clear the previous native operation',async()=>{
  for(const [diagnostic,code] of [[{kind:'timeout',exitCode:null},'DEVICE_PREPARATION_TIMEOUT'],[null,'DEVICE_PREPARATION_UNCONFIRMED'],[{kind:'wrapper-failure',exitCode:null,wrapperCode:'HELPER_HASH_MISMATCH'},'DEVICE_PREPARATION_WRAPPER_FAILED']]){
    const f=fixture({diagnostic}),result=await f.device.prepare();assert.equal(result.code,code);assert.equal(result.operation,undefined);assert.equal(result.nativeCode,undefined);assert.equal(result.nativeDeviceCode,undefined);assert.equal(f.calls.signs,0);assert.equal(f.calls.status,1);
  }
});
test('a completed diagnostic never grants readiness without fresh ordinary-user status and signature',async()=>{
  const f=fixture();f.device.status=async()=>{f.calls.status++;return f.device.info=structuredClone(f.calls.status===1?f.denied:f.ready);};
  const result=await f.device.prepare();assert.equal(result.ok,true);assert.equal(f.calls.status,2);assert.equal(f.calls.signs,1);assert.equal(f.calls.elevations,1);
  const changed=fixture();changed.device.status=async()=>{changed.calls.status++;return changed.device.info=structuredClone(changed.calls.status===1?{...changed.denied,deviceId:'0'.repeat(64)}:changed.ready);};
  assert.equal((await changed.device.prepare()).code,'DEVICE_PREPARATION_IDENTITY_CHANGED');assert.equal(changed.calls.signs,0);
});
