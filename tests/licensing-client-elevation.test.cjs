'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),path=require('node:path'),crypto=require('node:crypto');
const {spawnSync,execFile}=require('node:child_process');
const {elevatedPreparationScript,preparationScript,parsePreparationDiagnostic,preparationChannel,elevationOutcome}=require('../src/licensing/device.cjs');
const helper="C:\\Program Files\\Lianpu's\\Lianpu.Device.exe",hash='a'.repeat(64),pipe='Lianpu.Device.Preparation.'+'b'.repeat(48);
// Hypothesis: fixed EncodedCommand has valid PowerShell syntax and contains only
// fixed prepare/hash validation, bounded output, and one anonymous named-pipe send.
// Decision: qualify diagnostics without UAC, native device execution or key writes.
// Stop after AST/argument guards and one normal-user synthetic pipe roundtrip.
test('encoded wrapper is fixed to prepare, pins helper hash, rejects path substitution and has no diagnostic-file write',()=>{
 const script=elevatedPreparationScript(helper,hash,pipe),launcher=preparationScript(helper,hash,pipe);
 const encoded=launcher.match(/-EncodedCommand ([A-Za-z0-9+/=]+)/)[1];assert.equal(Buffer.from(encoded,'base64').toString('utf16le'),script);
 assert.ok(Buffer.byteLength(launcher,'utf16le')<60000,'Windows command line stays below 32767 UTF-16 characters');
 for(const fragment of ["$start.Arguments='prepare'",'$start.UseShellExecute=$false','$child.StandardInput.Close()','$expected=',"'"+hash+"'",'ReparsePoint','FileShare]::Read','-ge 20000','-gt 65536','TokenImpersonationLevel]::Anonymous'])assert.ok(script.includes(fragment),fragment);
 assert.doesNotMatch(script,/WriteAllText|WriteAllBytes|Out-File|Set-Content|CreateNew|Export-Clixml/);
 for(const input of ['relative.exe','\\\\server\\share\\helper.exe','C:\\helper.exe:payload'])assert.throws(()=>elevatedPreparationScript(input,hash,pipe));
 assert.throws(()=>elevatedPreparationScript(helper,'not-a-sha',pipe));assert.throws(()=>elevatedPreparationScript(helper,hash,'arbitrary\\path'));
});
test('diagnostic parser accepts only small typed whitelist and process interruption overrides success claims',()=>{
 assert.equal(parsePreparationDiagnostic('x'.repeat(8193)),null);assert.equal(parsePreparationDiagnostic('{}'),null);
 assert.equal(parsePreparationDiagnostic(JSON.stringify({version:1,kind:'completed',exitCode:1})),null);
 assert.equal(parsePreparationDiagnostic(JSON.stringify({version:1,kind:'native-failure',exitCode:1,nativeFailure:{state:'ready',code:'FALSE_SUCCESS'}})),null);
 assert.deepEqual(elevationOutcome(null),{kind:'unconfirmed',exitCode:0,reason:'diagnostic-missing'});
 assert.equal(elevationOutcome({code:1223},{kind:'completed',exitCode:0}).kind,'cancelled');
 assert.equal(elevationOutcome({killed:true,signal:'SIGTERM'},{kind:'completed',exitCode:0}).kind,'unconfirmed');
});
test('PowerShell parses both wrapper layers without executing either', {skip:process.platform!=='win32'},()=>{
 const powershell=path.join(process.env.SystemRoot||'C:\\Windows','System32','WindowsPowerShell','v1.0','powershell.exe');
 const parser="$ErrorActionPreference='Stop';$tokens=$null;$errors=$null;[void][Management.Automation.Language.Parser]::ParseInput([Console]::In.ReadToEnd(),[ref]$tokens,[ref]$errors);if($errors.Count){[Console]::Out.Write(($errors|ForEach-Object {$_.ErrorId}) -join ',');exit 1};[Console]::Out.Write('parsed')";
 for(const source of [elevatedPreparationScript(helper,hash,pipe),preparationScript(helper,hash,pipe)]){
  const result=spawnSync(powershell,['-NoProfile','-NonInteractive','-Command',parser],{input:source,encoding:'utf8',windowsHide:true,timeout:10000});assert.equal(result.status,0,result.stdout);assert.equal(result.stdout,'parsed');
 }
});
test('real normal-user PowerShell can return a synthetic failure through the anonymous named-pipe channel', {skip:process.platform!=='win32'},async()=>{
 const channel=await preparationChannel(),system=process.env.SystemRoot||'C:\\Windows';
 const payload=JSON.stringify({version:1,kind:'native-failure',exitCode:1,nativeFailure:{state:'error',code:'KEY_ACL_POLICY_CONFLICT',operation:'key.acl',nativeCode:'0x80090010',message:'not forwarded'}});
 const script=`$ErrorActionPreference='Stop';$pipe=New-Object IO.Pipes.NamedPipeClientStream('.', '${channel.name}', [IO.Pipes.PipeDirection]::Out, [IO.Pipes.PipeOptions]::Asynchronous, [Security.Principal.TokenImpersonationLevel]::Anonymous);try{$pipe.Connect(3000);$bytes=[Text.Encoding]::UTF8.GetBytes('${payload}');$task=$pipe.WriteAsync($bytes,0,$bytes.Length);if(-not $task.Wait(3000)){exit 1};$pipe.Flush()}finally{$pipe.Dispose()}`;
 let timer;
 try{
  const completed=new Promise((resolve,reject)=>{const child=execFile(path.join(system,'System32','WindowsPowerShell','v1.0','powershell.exe'),['-NoProfile','-NonInteractive','-EncodedCommand',Buffer.from(script,'utf16le').toString('base64')],{windowsHide:true,timeout:10000,maxBuffer:4096},error=>error?reject(error):resolve());child.stdin?.end();});
  const result=await Promise.race([Promise.all([channel.result,completed]).then(values=>values[0]),new Promise((_,reject)=>{timer=setTimeout(()=>reject(Error('pipe timeout')),12000);})]);
  assert.equal(result.kind,'native-failure');assert.equal(result.nativeFailure.code,'KEY_ACL_POLICY_CONFLICT');assert.equal(result.nativeFailure.message,undefined);
 }finally{clearTimeout(timer);channel.close();}
});
