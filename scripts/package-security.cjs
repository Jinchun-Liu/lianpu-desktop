'use strict';
// Packaging-only integration with Electron's documented Windows ASAR integrity resource.
const fs = require('node:fs'), path = require('node:path');
const { createHash } = require('node:crypto'), { spawnSync } = require('node:child_process');
const hash = bytes => createHash('sha256').update(bytes).digest('hex');
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
async function securePackage({appDir,stage,executable,work}) {
  if(process.platform!=='win32')throw new Error('Windows packaging host required');
  fs.mkdirSync(work,{recursive:true});
  const asar = await import('@electron/asar');
  const fuses = await import('@electron/fuses');
  const archive=path.join(stage,'resources','app.asar');
  if(fs.existsSync(archive))throw new Error('Refusing to overwrite existing ASAR');
  await asar.createPackageWithOptions(appDir,archive,{dot:true});
  const header=asar.getRawHeader(archive);
  const headerSha256=hash(header.headerString);
  const resource=JSON.stringify([{file:'resources\\app.asar',alg:'sha256',value:headerSha256}]);
  const configuration=path.join(work,'integrity-resource.json'), script=path.join(work,'integrity-resource.ps1');
  fs.writeFileSync(configuration,JSON.stringify({executable,resource}));
  fs.writeFileSync(script,'\uFEFF'+RESOURCE_SCRIPT);
  const run=spawnSync('powershell.exe',['-NoProfile','-NonInteractive','-File',script,'-Configuration',configuration],{encoding:'utf8',timeout:90000,windowsHide:true});
  if(run.status!==0)throw new Error('Integrity resource failed: '+(run.stderr||run.stdout||run.error?.message));
  const {FuseV1Options:O,FuseVersion:V,FuseState:S}=fuses;
  const required={version:V.V1,[O.RunAsNode]:false,[O.EnableNodeOptionsEnvironmentVariable]:false,[O.EnableNodeCliInspectArguments]:false,[O.EnableEmbeddedAsarIntegrityValidation]:true,[O.OnlyLoadAppFromAsar]:true};
  await fuses.flipFuses(executable,required);
  const actual=await fuses.getCurrentFuseWire(executable);
  for(const [name,value] of Object.entries(required))if(name!=='version'&&actual[name] !== (value?S.ENABLE:S.DISABLE))throw new Error('Fuse verification failed: '+name);
  const loose=path.join(stage,'resources','app');
  if(fs.existsSync(loose))throw new Error('Loose app directory must remain outside the distribution');
  return {asarSha256:hash(fs.readFileSync(archive)),headerSha256,executableSha256:hash(fs.readFileSync(executable)),resourceReadbackVerified:true,fuses:actual,
    archiveFiles:asar.listPackage(archive),libraries:{asar:'4.3.0',fuses:'2.1.3'},
    repair:'重新运行经核验的安装包修复程序文件；保留授权与业务资料。',
    boundary:'防止受支持入口加载被改写的应用归档；不是不可破解保证。Windows 发布者签名仍未提供。'};
}
module.exports={securePackage};
