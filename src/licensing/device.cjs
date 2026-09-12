'use strict';
const path=require('node:path'),fs=require('node:fs'),net=require('node:net');
const {execFile,spawnSync}=require('node:child_process');
const {createPublicKey,createHash,verify,randomBytes}=require('node:crypto');
class DeviceError extends Error {constructor(code,message,state='blocked'){super(message);this.code=code;this.state=state;}}
const SIGNING_DOMAINS=Object.freeze({preparation:'LIANPU-LICENSING/v1/preparation\0',state:'LIANPU-LICENSING/v1/local-state\0',ticket:'LIANPU-LICENSING/v1/device-proof\0',reportSession:'LIANPU-REPORT/v1/session\0'});
function safeHelperEnvironment(environment=process.env){return Object.fromEntries(Object.entries(environment).filter(([key])=>!/^(?:NODE_|ELECTRON_|DOTNET_|COMPLUS_|COR_|CORECLR_)/i.test(key)));}
function validateSigningInput(bytes){
  const reject=()=>{throw new DeviceError('DEVICE_SIGNING_PURPOSE','设备签名用途或参数无效，请更新或修复完整安装包。');};
  if(!(Buffer.isBuffer(bytes)||ArrayBuffer.isView(bytes)&&bytes.BYTES_PER_ELEMENT===1)||bytes.length===0||bytes.length>16384)reject();
  const data=Buffer.from(bytes);let purpose,prefix;
  for(const [name,domain]of Object.entries(SIGNING_DOMAINS)){const candidate=Buffer.from(domain);if(data.subarray(0,candidate.length).equals(candidate)){purpose=name;prefix=candidate;break;}}
  if(!purpose)reject();const suffix=data.subarray(prefix.length);
  if(purpose==='preparation'){if(suffix.length!==32)reject();return purpose;}
  let text,value;try{text=new TextDecoder('utf-8',{fatal:true}).decode(suffix);value=JSON.parse(text);}catch{reject();}
  const exact=(object,keys)=>object&&Object.getPrototypeOf(object)===Object.prototype&&Object.keys(object).sort().join('|')===[...keys].sort().join('|');
  const canonical=(item,depth=0)=>{if(depth>20)reject();if(item===null||typeof item==='string'||typeof item==='boolean')return JSON.stringify(item);if(typeof item==='number'){if(!Number.isSafeInteger(item))reject();return JSON.stringify(item);}if(Array.isArray(item))return '['+item.map(entry=>canonical(entry,depth+1)).join(',')+']';if(!item||typeof item!=='object')reject();return '{'+Object.keys(item).sort().map(key=>JSON.stringify(key)+':'+canonical(item[key],depth+1)).join(',')+'}';};
  const validKey=spki=>{try{if(typeof spki!=='string')return false;const raw=Buffer.from(spki,'base64url'),key=createPublicKey({key:raw,format:'der',type:'spki'});return raw.length===91&&raw.toString('base64url')===spki&&key.asymmetricKeyType==='ec'&&key.asymmetricKeyDetails?.namedCurve==='prime256v1'&&key.export({type:'spki',format:'der'}).equals(raw);}catch{return false;}};
  if(purpose==='reportSession'){
    const challenged=value&&Object.hasOwn(value,'challenge');
    if(!exact(value,challenged?['publicKey','nonce','challenge']:['publicKey','nonce'])||!validKey(value.publicKey)||typeof value.nonce!=='string'||!/^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/i.test(value.nonce)||challenged&&(typeof value.challenge!=='string'||value.challenge.length>=4096||!/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]{43}$/.test(value.challenge))||text!==JSON.stringify({publicKey:value.publicKey,nonce:value.nonce,...(challenged?{challenge:value.challenge}:{})}))reject();
  }else{
    if(text!==canonical(value))reject();
    if(purpose==='state'&&(!exact(value,['v','license','pending','clock'])||value.v!==1))reject();
    if(purpose==='ticket'&&(!exact(value,['keyId','payload','signature'])||typeof value.keyId!=='string'||!/^[A-Za-z0-9_-]{1,64}$/.test(value.keyId)||typeof value.signature!=='string'||!/^[A-Za-z0-9_-]{86}$/.test(value.signature)||!exact(value.payload,['v','type','mode','requestId','deviceId','devicePublicKeySpki','codeHash','plan','issuedAt','expiresAt','nonce'])||value.payload.v!==1||value.payload.type!=='ticket'||!['activate','recover'].includes(value.payload.mode)||!validKey(value.payload.devicePublicKeySpki)))reject();
  }
  return purpose;
}
function parsePreparationDiagnostic(bytes){
  if(Buffer.byteLength(String(bytes))>8192)return null;
  let value;try{value=JSON.parse(String(bytes).trim());}catch{return null;}
  if(value?.version!==1||!['completed','native-failure','timeout','wrapper-failure'].includes(value.kind))return null;
  const result={kind:value.kind,exitCode:Number.isInteger(value.exitCode)?value.exitCode:null};
  if(value.kind==='completed')return value.exitCode===0?result:null;
  if(value.kind==='native-failure'){
    const native=value.nativeFailure;
    if(!native||!['needs_admin','error','unsupported','no_tpm','tpm_not_2','tpm_not_ready','not_prepared'].includes(native.state)||!/^[A-Z][A-Z0-9_]{1,79}$/.test(native.code||'')||!Number.isInteger(value.exitCode)||value.exitCode===0)return null;
    result.nativeFailure={state:native.state,code:native.code};
    if(typeof native.operation==='string'&&/^[A-Za-z0-9_.:-]{1,80}$/.test(native.operation))result.nativeFailure.operation=native.operation;
    if(typeof native.nativeCode==='string'&&/^0x[0-9A-Fa-f]{8}$/.test(native.nativeCode))result.nativeFailure.nativeCode=native.nativeCode;
  }
  if(['HELPER_PATH_UNSAFE','HELPER_HASH_MISMATCH','HELPER_START_FAILED','HELPER_RESPONSE_INVALID','OUTPUT_LIMIT','WRAPPER_FAILED','PIPE_UNAVAILABLE'].includes(value.wrapperCode))result.wrapperCode=value.wrapperCode;
  return result;
}
function elevationOutcome(error,diagnostic=null){
  if(!error)return diagnostic||{kind:'unconfirmed',exitCode:0,reason:'diagnostic-missing'};
  const exitCode=Number.isInteger(error.code)?error.code:null;
  if(error.killed||error.signal||error.code==='ETIMEDOUT')return {kind:'unconfirmed',exitCode,signal:error.signal||null,killed:error.killed===true};
  if(exitCode===1223)return {kind:'cancelled',exitCode};
  if(typeof error.code==='string')return {kind:'launch-failed',exitCode:null,code:error.code};
  return {kind:'wrapper-failure',exitCode};
}
function elevatedPreparationScript(helper,expectedSha256,pipeName){
  if(!/^[A-Za-z]:\\/.test(helper)||helper.slice(2).includes(':')||helper.includes('\0')||!/^Lianpu\.Device\.Preparation\.[a-f0-9]{48}$/.test(pipeName)||!/^[a-f0-9]{64}$/.test(expectedSha256||''))throw new DeviceError('DEVICE_PREPARATION_PATH','设备准备路径或校验标识不合法。');
  const literal="'"+helper.replace(/'/g,"''")+"'";
  return String.raw`$ErrorActionPreference='Stop'
$helper=${literal};$expected='${expectedSha256}';$pipeName='${pipeName}'
$result=@{version=1;kind='wrapper-failure';exitCode=$null;wrapperCode='WRAPPER_FAILED'};$lock=$null;$child=$null
try {
 $result.wrapperCode='HELPER_PATH_UNSAFE'
 if([IO.Path]::GetFullPath($helper) -cne $helper){throw 'path'}
 $cursor=$helper
 while($cursor){if(([IO.File]::GetAttributes($cursor) -band [IO.FileAttributes]::ReparsePoint) -ne 0){throw 'link'};$parent=[IO.Directory]::GetParent($cursor);if($null -eq $parent){break};$cursor=$parent.FullName}
 $lock=[IO.File]::Open($helper,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
 $result.wrapperCode='HELPER_HASH_MISMATCH';$algorithm=[Security.Cryptography.SHA256]::Create()
 try{$actual=[BitConverter]::ToString($algorithm.ComputeHash($lock)).Replace('-','').ToLowerInvariant()}finally{$algorithm.Dispose()}
 if($actual -cne $expected){throw 'hash'}
 $result.wrapperCode='HELPER_START_FAILED'
 $start=New-Object Diagnostics.ProcessStartInfo;$start.FileName=$helper;$start.Arguments='prepare';$start.WorkingDirectory=[IO.Path]::GetDirectoryName($helper)
 $start.UseShellExecute=$false;$start.CreateNoWindow=$true;$start.RedirectStandardInput=$true;$start.RedirectStandardOutput=$true;$start.RedirectStandardError=$true
 $child=New-Object Diagnostics.Process;$child.StartInfo=$start;if(-not $child.Start()){throw 'start'};$child.StandardInput.Close()
 $out=New-Object Text.StringBuilder;$err=New-Object Text.StringBuilder;$outBuffer=New-Object char[] 4096;$errBuffer=New-Object char[] 4096
 $outDone=$false;$errDone=$false;$outTask=$child.StandardOutput.ReadAsync($outBuffer,0,4096);$errTask=$child.StandardError.ReadAsync($errBuffer,0,4096)
 $watch=[Diagnostics.Stopwatch]::StartNew()
 while(-not ($child.HasExited -and $outDone -and $errDone)){
  if($watch.ElapsedMilliseconds -ge 20000){$result=@{version=1;kind='timeout';exitCode=$null};try{$child.Kill()}catch{};throw 'timeout'}
  if(-not $outDone -and $outTask.IsCompleted){$n=$outTask.GetAwaiter().GetResult();if($n -eq 0){$outDone=$true}else{if($out.Length+$n -gt 65536){$result.wrapperCode='OUTPUT_LIMIT';try{$child.Kill()}catch{};throw 'limit'};[void]$out.Append($outBuffer,0,$n);$outTask=$child.StandardOutput.ReadAsync($outBuffer,0,4096)}}
  if(-not $errDone -and $errTask.IsCompleted){$n=$errTask.GetAwaiter().GetResult();if($n -eq 0){$errDone=$true}else{if($err.Length+$n -gt 65536){$result.wrapperCode='OUTPUT_LIMIT';try{$child.Kill()}catch{};throw 'limit'};[void]$err.Append($errBuffer,0,$n);$errTask=$child.StandardError.ReadAsync($errBuffer,0,4096)}}
  [Threading.Thread]::Sleep(10)
 }
 $result.wrapperCode='HELPER_RESPONSE_INVALID';$native=ConvertFrom-Json -InputObject $out.ToString()
 if($native.version -ne 1 -or $native.testMode -ne $false -or $err.Length -ne 0){throw 'response'}
 if($child.ExitCode -eq 0 -and $native.ok -eq $true -and $native.state -eq 'ready'){$result=@{version=1;kind='completed';exitCode=0}}
 elseif($child.ExitCode -ne 0 -and $native.ok -eq $false -and $native.code -cmatch '^[A-Z][A-Z0-9_]{1,79}$'){
  $failure=@{state=$native.state;code=$native.code}
  if($native.operation -cmatch '^[A-Za-z0-9_.:-]{1,80}$'){$failure.operation=$native.operation}
  if($native.nativeCode -cmatch '^0x[0-9A-Fa-f]{8}$'){$failure.nativeCode=$native.nativeCode}
  $result=@{version=1;kind='native-failure';exitCode=$child.ExitCode;nativeFailure=$failure}
 }else{throw 'response'}
}catch{}finally{if($null -ne $child){$child.Dispose()};if($null -ne $lock){$lock.Dispose()}}
try {
 $pipe=New-Object IO.Pipes.NamedPipeClientStream('.', $pipeName, [IO.Pipes.PipeDirection]::Out, [IO.Pipes.PipeOptions]::Asynchronous, [Security.Principal.TokenImpersonationLevel]::Anonymous)
 try{$pipe.Connect(3000);$bytes=[Text.Encoding]::UTF8.GetBytes(($result|ConvertTo-Json -Compress -Depth 4));$write=$pipe.WriteAsync($bytes,0,$bytes.Length);if(-not $write.Wait(3000)){exit 1};$pipe.Flush()}finally{$pipe.Dispose()}
 exit 0
}catch{exit 1}`;
}
function preparationScript(helper,expectedSha256,pipeName){
  const encoded=Buffer.from(elevatedPreparationScript(helper,expectedSha256,pipeName),'utf16le').toString('base64');
  return "$ErrorActionPreference='Stop'; try { $powershell=[IO.Path]::Combine([Environment]::GetFolderPath('System'),'WindowsPowerShell','v1.0','powershell.exe'); $devicePreparation = Start-Process -FilePath $powershell -ArgumentList '-NoProfile -NonInteractive -EncodedCommand "+encoded+"' -Verb RunAs -WindowStyle Hidden -Wait -PassThru; if($null -eq $devicePreparation -or $null -eq $devicePreparation.ExitCode){exit 1}; exit $devicePreparation.ExitCode } catch { $deviceFailure=$_.Exception.GetBaseException(); if($deviceFailure -is [ComponentModel.Win32Exception] -and $deviceFailure.NativeErrorCode -eq 1223){exit 1223}; exit 1 }";
}
async function preparationChannel(){
  const name='Lianpu.Device.Preparation.'+randomBytes(24).toString('hex'),sockets=new Set();let finish;
  const result=new Promise(resolve=>{finish=resolve;});
  const server=net.createServer(socket=>{
    sockets.add(socket);let bytes=0,chunks=[];socket.setTimeout(5000,()=>socket.destroy());
    socket.on('data',chunk=>{bytes+=chunk.length;if(bytes>8192){chunks=[];socket.destroy();return;}chunks.push(chunk);});
    socket.on('end',()=>{if(bytes<=8192){const diagnostic=parsePreparationDiagnostic(Buffer.concat(chunks).toString('utf8'));if(diagnostic)finish(diagnostic);}});
    socket.on('error',()=>{});socket.on('close',()=>sockets.delete(socket));
  });
  server.maxConnections=2;
  await new Promise((resolve,reject)=>{server.once('error',reject);server.listen('\\\\.\\pipe\\'+name,resolve);});
  server.on('error',()=>finish(null));
  return {name,result,close(){for(const socket of sockets)socket.destroy();server.close();finish(null);}};
}
class TpmDevice {
  constructor({helper=path.join(__dirname,'native','bin','Lianpu.Device.exe'),expectedSha256=require('./native-integrity.json').sha256}={}){this.helper=helper;this.expectedSha256=expectedSha256;this.info=null;}
  _parse(stdout){let result;try{result=JSON.parse(String(stdout).trim());}catch{throw new DeviceError('DEVICE_RESPONSE','本机设备保护未返回有效结果。');}if(!result||result.version!==1||result.testMode!==false||typeof result.ok!=='boolean'||typeof result.state!=='string')throw new DeviceError('DEVICE_RESPONSE','本机设备保护结果无效。');return result;}
  _available(){if(process.platform!=='win32')throw new DeviceError('DEVICE_PLATFORM','当前授权需要 Windows TPM 2.0。','unsupported');if(!fs.existsSync(this.helper))throw new DeviceError('DEVICE_HELPER_MISSING','本机设备保护组件缺失，请使用完整安装包。');if(!/^[a-f0-9]{64}$/.test(this.expectedSha256||'')||createHash('sha256').update(fs.readFileSync(this.helper)).digest('hex')!==this.expectedSha256)throw new DeviceError('DEVICE_HELPER_INTEGRITY','设备保护组件与发行版本不符，请修复安装；现有资料会保留。');}
  async invoke(command,bytes){if(!['status','prepare','sign'].includes(command)||command!=='sign'&&bytes!==undefined)throw new DeviceError('DEVICE_COMMAND','设备操作参数无效。');if(command==='sign')validateSigningInput(bytes);this._available();return new Promise((resolve,reject)=>{const child=execFile(this.helper,[command],{windowsHide:true,timeout:20000,maxBuffer:65536,env:safeHelperEnvironment()},(error,stdout)=>{try{if(error&&(error.killed||error.signal))throw new DeviceError('DEVICE_OPERATION_UNCONFIRMED','本机设备操作未返回确认结果。请保留诊断，勿重复准备。','error');const result=this._parse(stdout);if(error&&(result.ok||!result.code))throw new DeviceError('DEVICE_FAILED','本机设备保护操作未完成。');if(command==='sign')this._validatedSignature(result,bytes);resolve(result);}catch(e){reject(e);}});child.stdin?.end(bytes?Buffer.from(bytes).toString('base64url'):'');});}
  async status(){try{this.info=await this.invoke('status');return this.info;}catch(error){return this.info={ok:false,state:error.state||'error',code:error.code||'DEVICE_FAILED',message:error.message};}}
  async _elevate(){
    let channel;try{
      channel=await preparationChannel();
      const system=process.env.SystemRoot||'C:\\Windows';
      const error=await new Promise(resolve=>{const child=execFile(path.join(system,'System32','WindowsPowerShell','v1.0','powershell.exe'),['-NoProfile','-NonInteractive','-Command',preparationScript(this.helper,this.expectedSha256,channel.name)],{windowsHide:true,timeout:120000,maxBuffer:65536,env:safeHelperEnvironment()},error=>resolve(error));child.stdin?.end();});
      if(error)return elevationOutcome(error);
      let timer;const diagnostic=await Promise.race([channel.result,new Promise(resolve=>{timer=setTimeout(()=>resolve(null),500);})]);clearTimeout(timer);
      return elevationOutcome(null,diagnostic);
    }catch{return {kind:'wrapper-failure',exitCode:null,wrapperCode:'WRAPPER_FAILED'};}
    finally{channel?.close();}
  }
  async prepare(){
    await this.status();const priorId=this.info?.deviceId;
    if(this.validate())return this._finishPreparation(priorId);
    this.info=await this.invoke('prepare');
    if(this.info.state==='needs_admin'){
      this._available();
      const outcome=await this._elevate();
      if(outcome.kind!=='completed'){
        const failures={unconfirmed:['DEVICE_PREPARATION_UNCONFIRMED','Windows 设备准备没有返回完整确认，可能仍在进行。请先检查系统提示，勿重复准备。'],timeout:['DEVICE_PREPARATION_TIMEOUT','设备准备执行超过 20 秒，已停止等待，不能确认操作完整完成。请保留诊断，勿重复准备。'],cancelled:['DEVICE_PREPARATION_CANCELLED','Windows 已报告取消本次设备准备。未确认本机设备就绪。'],'native-failure':['DEVICE_PREPARATION_NATIVE_FAILED','设备保护组件返回失败，请按本次原生诊断处理。未确认本机设备就绪。'],'wrapper-failure':['DEVICE_PREPARATION_WRAPPER_FAILED','Windows 设备准备的诊断程序未能完整执行。未确认本机设备就绪。'],'launch-failed':['DEVICE_PREPARATION_LAUNCH_FAILED','Windows 设备准备程序未能正常启动。请保留诊断信息。']};
        const [code,message]=failures[outcome.kind]||failures.unconfirmed,native=outcome.nativeFailure;
        // Never carry the earlier unelevated ACCESS_DENIED into a different error.
        this.info={...this.info,ok:false,state:native?.state||'needs_admin',code: native?.code||code,message,preparation:outcome};
        delete this.info.operation;delete this.info.nativeCode;delete this.info.nativeDeviceCode;
        if(native){this.info.message='设备保护组件返回 '+native.code+'，未确认本机设备就绪。请保留本次诊断。';this.info.nativeDeviceCode=native.code;if(native.operation)this.info.operation=native.operation;if(native.nativeCode)this.info.nativeCode=native.nativeCode;}
        return this.info;
      }
      await this.status();this.info.preparation=outcome;
      if(!this.validate()){
        const originalCode=this.info.code;this.info={...this.info,ok:false,code:'DEVICE_PREPARATION_ACCESS_UNCONFIRMED',nativeDeviceCode:originalCode,message:'Windows 准备程序已结束，但当前用户仍不能确认设备密钥和存储权限。请保留诊断，勿反复确认。'};return this.info;
      }
    }
    return this._finishPreparation(priorId);
  }
  _finishPreparation(priorId){
    if(!this.validate()){if(this.info?.ok&&this.info.state==='ready')this.info={...this.info,ok:false,state:'error',code:'DEVICE_PREPARATION_INCOMPLETE',message:'设备组件返回的密钥或存储条件不完整，未确认本机设备就绪。'};return this.info;}
    try{if(priorId&&priorId!==this.info.deviceId)throw new DeviceError('DEVICE_PREPARATION_IDENTITY_CHANGED','准备前后的设备身份不一致。已停止使用该结果。','error');this.signSync(Buffer.concat([Buffer.from('LIANPU-LICENSING/v1/preparation\0'),randomBytes(32)]));return this.info;}
    catch(error){this.info={...this.info,ok:false,state:'error',code:error.code||'DEVICE_PREPARATION_FAILED',message:error.message};return this.info;}
  }
  signSync(bytes){validateSigningInput(bytes);this._available();const response=spawnSync(this.helper,['sign'],{windowsHide:true,timeout:20000,maxBuffer:65536,encoding:'utf8',env:safeHelperEnvironment(),input:Buffer.from(bytes).toString('base64url')});if(response.error||response.signal||response.status!==0)throw new DeviceError('DEVICE_SIGN_FAILED','设备签名进程未确认成功，请保留诊断信息。','error');return this._validatedSignature(this._parse(response.stdout),bytes);}
  _validatedSignature(result,bytes){if(!this.validate(result)||result.deviceId!==this.info?.deviceId||result.publicKeySpki!==this.info?.publicKeySpki||result.signatureFormat!=='ieee-p1363'||result.hashAlgorithm!=='SHA-256')throw new DeviceError('DEVICE_SIGN_FAILED','设备签名返回的身份或保护条件不一致，请保留诊断信息。','error');const signature=Buffer.from(result.signature||'','base64url');if(signature.length!==64||signature.toString('base64url')!==result.signature||!this.verify(bytes,signature))throw new DeviceError('DEVICE_SIGNATURE','设备签名不能通过本机核验。');return signature;}
  verify(bytes,signature){try{const key=createPublicKey({key:Buffer.from(this.info.publicKeySpki,'base64url'),format:'der',type:'spki'});return key.asymmetricKeyType==='ec'&&key.asymmetricKeyDetails?.namedCurve==='prime256v1'&&verify('sha256',Buffer.from(bytes),{key,dsaEncoding:'ieee-p1363'},Buffer.from(signature));}catch{return false;}}
  validate(info=this.info){if(info?.version!==1||!info.ok||info.state!=='ready'||info.testMode!==false||info.tpm?.version!=='2.0'||info.tpm?.present!==true||info.storage?.prepared!==true)return false;try{const raw=Buffer.from(info.publicKeySpki,'base64url'),key=createPublicKey({key:raw,format:'der',type:'spki'});return raw.length===91&&raw.toString('base64url')===info.publicKeySpki&&key.asymmetricKeyType==='ec'&&key.asymmetricKeyDetails?.namedCurve==='prime256v1'&&key.export({type:'spki',format:'der'}).equals(raw)&&createHash('sha256').update(raw).digest('hex')===info.deviceId&&info.key?.provider==='Microsoft Platform Crypto Provider'&&info.key.prepared===true&&info.key.algorithm==='ECDSA_P256'&&Number.isInteger(info.key.implementationFlags)&&(info.key.implementationFlags&1)===1&&(info.key.implementationFlags&2)===0&&info.key.machineKey===true&&info.key.hardwareBacked===true&&info.key.exportable===false;}catch{return false;}}
}
module.exports={TpmDevice,DeviceError,elevationOutcome,preparationScript,elevatedPreparationScript,parsePreparationDiagnostic,preparationChannel,validateSigningInput,SIGNING_DOMAINS,safeHelperEnvironment};
