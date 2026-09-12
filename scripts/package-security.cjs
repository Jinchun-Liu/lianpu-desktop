'use strict';
// Packaging-only integration with Electron's documented Windows ASAR integrity resource.
const fs = require('node:fs'), path = require('node:path');
const { createHash } = require('node:crypto'), { spawnSync } = require('node:child_process');
const {pathToFileURL}=require('node:url');
const hash = bytes => createHash('sha256').update(bytes).digest('hex');
function packageError(message){throw new Error('PACKAGE_SECURITY: '+message);}
function plainFiles(root){
  const files=[];
  function visit(directory){for(const entry of fs.readdirSync(directory,{withFileTypes:true})){const file=path.join(directory,entry.name),stat=fs.lstatSync(file);if(stat.isSymbolicLink()||(!stat.isDirectory()&&!stat.isFile()))packageError('Links and special files are not allowed: '+path.relative(root,file));if(stat.isDirectory())visit(file);else files.push(file);}}
  if(fs.lstatSync(root).isSymbolicLink()||!fs.statSync(root).isDirectory())packageError('Build input must be a regular directory');visit(root);return files.sort();
}
function inspectApplicationInput(appDir){
  const files=plainFiles(appDir);
  for(const file of files){const name=path.relative(appDir,file).replaceAll('\\','/');
    if(/(?:^|\/)(?:\.git|\.env(?:\.[^/]*)?|node_modules|work|evidence|tests)(?:\/|$)/i.test(name)||/\.(?:pfx|p12|dpapi|key|map)$/i.test(name))packageError('Non-distributable input: '+name);
    if(/-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY-----/.test(fs.readFileSync(file,'utf8')))packageError('Private key material is not distributable: '+name);
  }
  return files.map(file=>({path:path.relative(appDir,file).replaceAll('\\','/'),sha256:hash(fs.readFileSync(file))}));
}
function inspectStage({appDir,stage,executable,runtime}){
  const relative=path.relative(stage,executable);if(!relative||relative.startsWith('..')||path.isAbsolute(relative)||relative.includes(path.sep))packageError('Executable must be directly inside stage');
  for(const name of ['app','default_app.asar','app.asar.unpacked'])if(fs.existsSync(path.join(stage,'resources',name)))packageError('Unexpected alternative application resource: '+name);
  const expected=new Map(plainFiles(runtime).filter(file=>!file.endsWith('default_app.asar')&&!/\.log$/i.test(file)).map(file=>[path.relative(runtime,file).replaceAll('\\','/'),file]));
  expected.delete('electron.exe');
  const actual=plainFiles(stage),external=[];
  for(const file of actual){const name=path.relative(stage,file).replaceAll('\\','/');if(file===executable)continue;
    if(name==='resources/licensing/Lianpu.Device.exe'){
      const manifest=path.join(appDir,'src','licensing','native-integrity.json');if(!fs.existsSync(manifest))packageError('External device component has no integrity manifest');
      const sha256=hash(fs.readFileSync(file));if(JSON.parse(fs.readFileSync(manifest,'utf8')).sha256!==sha256)packageError('External device component digest mismatch');external.push({path:name,sha256,verification:'Pinned in ASAR; device provider rechecks before invocation'});continue;
    }
    const reference=expected.get(name);if(!reference||hash(fs.readFileSync(file))!==hash(fs.readFileSync(reference)))packageError('Unexpected or modified Electron resource: '+name);expected.delete(name);
  }
  if(expected.size)packageError('Missing Electron resources: '+[...expected.keys()].join(', '));return external;
}
function inspectHeader(node){for(const child of Object.values(node.files||{})){if(child.link||child.unpacked)packageError('ASAR links and unpacked files are not permitted');if(child.files)inspectHeader(child);else if(child.integrity?.algorithm!=='SHA256'||!/^[a-f0-9]{64}$/.test(child.integrity?.hash||''))packageError('ASAR file is missing SHA-256 integrity');}}
const RESOURCE_SCRIPT = String.raw`param([string]$Configuration)
$ErrorActionPreference='Stop'
Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public static class AsarResource {
 [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern IntPtr BeginUpdateResourceW(string file,bool deleteAll);
 [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern bool UpdateResourceW(IntPtr update,string type,string name,ushort language,byte[] data,uint size);
 [DllImport("kernel32.dll",SetLastError=true)] static extern bool EndUpdateResourceW(IntPtr update,bool discard);
 [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern IntPtr LoadLibraryExW(string file,IntPtr handle,uint flags);
 [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern IntPtr FindResourceW(IntPtr module,string name,string type);
 [DllImport("kernel32.dll",SetLastError=true)] static extern IntPtr LoadResource(IntPtr module,IntPtr resource);
 [DllImport("kernel32.dll")] static extern IntPtr LockResource(IntPtr resource);
 [DllImport("kernel32.dll")] static extern uint SizeofResource(IntPtr module,IntPtr resource);
 [DllImport("kernel32.dll")] static extern bool FreeLibrary(IntPtr module);
 static void Check(bool value){if(!value)throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());}
 public static void Write(string file,byte[] data){
  IntPtr handle=BeginUpdateResourceW(file,false);Check(handle!=IntPtr.Zero);bool done=false;
  try {Check(UpdateResourceW(handle,"Integrity","ElectronAsar",0,data,(uint)data.Length));Check(EndUpdateResourceW(handle,false));done=true;}
  finally {if(!done)EndUpdateResourceW(handle,true);}
 }
 public static byte[] Read(string file){
  IntPtr module=LoadLibraryExW(file,IntPtr.Zero,2|32);Check(module!=IntPtr.Zero);
  try {IntPtr resource=FindResourceW(module,"ElectronAsar","Integrity");Check(resource!=IntPtr.Zero);
   uint length=SizeofResource(module,resource);Check(length>0);IntPtr loaded=LoadResource(module,resource);Check(loaded!=IntPtr.Zero);
   IntPtr data=LockResource(loaded);Check(data!=IntPtr.Zero);byte[] result=new byte[length];Marshal.Copy(data,result,0,(int)length);return result;
  } finally {FreeLibrary(module);}
 }
}
'@
$cfg=Get-Content -LiteralPath $Configuration -Raw -Encoding UTF8 | ConvertFrom-Json
$bytes=[Text.Encoding]::UTF8.GetBytes([string]$cfg.resource)
[AsarResource]::Write($cfg.executable,$bytes)
$actual=[AsarResource]::Read($cfg.executable)
if([Convert]::ToBase64String($actual) -cne [Convert]::ToBase64String($bytes)){throw 'ASAR resource readback mismatch'}
Write-Output 'ASAR integrity resource verified'
`;
async function securePackage({appDir,stage,executable,work,protectionProvider}={}) {
  if(process.platform!=='win32')throw new Error('Windows packaging host required');
  for(const value of [appDir,stage,executable,work])if(typeof value!=='string'||!path.isAbsolute(value))packageError('Absolute build paths required');
  const referenceRoot=path.dirname(require.resolve('electron/package.json'));
  const actualVersions={electron:require(path.join(referenceRoot,'package.json')).version,asar:require(path.join(path.dirname(require.resolve('@electron/asar')),'..','package.json')).version,fuses:require(path.join(path.dirname(require.resolve('@electron/fuses')),'..','package.json')).version};
  const locked=require('../package.json').devDependencies;
  for(const [name,version] of Object.entries(actualVersions))if(locked[name==='electron'?name:'@electron/'+name]!==version)packageError('Installed build dependency does not match pinned version: '+name);
  const provider=require('./protection-provider.cjs').inspectProtectionProvider(protectionProvider,{electron:actualVersions.electron,platform:'win32',arch:'x64'});
  const inputFiles=inspectApplicationInput(appDir);
  const externalComponents=inspectStage({appDir,stage,executable,runtime:path.join(referenceRoot,'dist')});
  fs.mkdirSync(work,{recursive:true});
  const asar = await import(pathToFileURL(require.resolve('@electron/asar')).href);
  const fuses = await import(pathToFileURL(require.resolve('@electron/fuses')).href);
  const archive=path.join(stage,'resources','app.asar');
  if(fs.existsSync(archive))throw new Error('Refusing to overwrite existing ASAR');
  await asar.createPackageWithOptions(appDir,archive,{dot:true});
  const header=asar.getRawHeader(archive);
  inspectHeader(header.header);
  const headerSha256=hash(header.headerString);
  const resource=JSON.stringify([{file:'resources\\app.asar',alg:'sha256',value:headerSha256}]);
  const configuration=path.join(work,'integrity-resource.json'), script=path.join(work,'integrity-resource.ps1');
  fs.writeFileSync(configuration,JSON.stringify({executable,resource}));
  fs.writeFileSync(script,'\uFEFF'+RESOURCE_SCRIPT);
  const windows=process.env.SystemRoot;if(!windows||!path.isAbsolute(windows))packageError('Cannot locate Windows resource tooling');
  const run=spawnSync(path.join(windows,'System32','WindowsPowerShell','v1.0','powershell.exe'),['-NoProfile','-NonInteractive','-File',script,'-Configuration',configuration],{encoding:'utf8',timeout:90000,windowsHide:true});
  if(run.status!==0)throw new Error('Integrity resource failed: '+(run.stderr||run.stdout||run.error?.message));
  const {FuseV1Options:O,FuseVersion:V,FuseState:S}=fuses;
  const prior=await fuses.getCurrentFuseWire(executable);
  // Cookie encryption is a one-way storage migration; preserve its current state.
  for(const key of [O.EnableCookieEncryption,O.WasmTrapHandlers])if(![S.ENABLE,S.DISABLE].includes(prior[key]))packageError('Unsupported preserved fuse state: '+key);
  const required={version:V.V1,strictlyRequireAllFuses:true,[O.RunAsNode]:false,[O.EnableCookieEncryption]:prior[O.EnableCookieEncryption]===S.ENABLE,[O.EnableNodeOptionsEnvironmentVariable]:false,[O.EnableNodeCliInspectArguments]:false,[O.EnableEmbeddedAsarIntegrityValidation]:true,[O.OnlyLoadAppFromAsar]:true,[O.LoadBrowserProcessSpecificV8Snapshot]:false,[O.GrantFileProtocolExtraPrivileges]:false,[O.WasmTrapHandlers]:prior[O.WasmTrapHandlers]===S.ENABLE};
  await fuses.flipFuses(executable,required);
  const actual=await fuses.getCurrentFuseWire(executable);
  for(const [name,value] of Object.entries(required))if(/^\d+$/.test(name)&&actual[name] !== (value?S.ENABLE:S.DISABLE))throw new Error('Fuse verification failed: '+name);
  const loose=path.join(stage,'resources','app');
  if(fs.existsSync(loose))throw new Error('Loose app directory must remain outside the distribution');
  return {asarSha256:hash(fs.readFileSync(archive)),headerSha256,executableSha256:hash(fs.readFileSync(executable)),resourceReadbackVerified:true,fuses:actual,
    archiveFiles:asar.listPackage(archive),libraries:actualVersions,inputFiles,externalComponents,protectionProvider:provider,
    signingOrder:['Review/protect application inputs and native components','Sign native components, then refresh their pinned digest','Create ASAR','Apply branding, ASAR resource and Fuses','Authenticode-sign executable','Build and Authenticode-sign installer','Hash final installer and sign update manifest'],
    repair:'重新运行经核验的安装包修复程序文件；保留授权与业务资料。',
    boundary:'防止受支持入口加载被改写的应用归档；不是不可破解保证。Windows 发布者签名仍未提供。'};
}
module.exports={securePackage,inspectApplicationInput,inspectStage,inspectHeader};
