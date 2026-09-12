'use strict';
// Original geometric application mark and Windows resources. No downloaded art or resource editor.
const fs = require('node:fs'), path = require('node:path'), zlib = require('node:zlib');
const { createHash } = require('node:crypto'), { spawnSync } = require('node:child_process');
const hash = bytes => createHash('sha256').update(bytes).digest('hex');
function crc32(bytes) { let crc = 0xffffffff; for (const byte of bytes) { crc ^= byte; for (let n=0;n<8;n++) crc = (crc >>> 1) ^ ((crc & 1) ? 0xedb88320 : 0); } return (crc ^ 0xffffffff) >>> 0; }
function chunk(type, data) { const name=Buffer.from(type), size=Buffer.alloc(4), check=Buffer.alloc(4);size.writeUInt32BE(data.length);check.writeUInt32BE(crc32(Buffer.concat([name,data])));return Buffer.concat([size,name,data,check]); }
function iconPNG(size) {
  const stride=size*4+1, raster=Buffer.alloc(size*stride), c=[88,97,43];
  for(let y=0;y<size;y++)for(let x=0;x<size;x++) {
    let coverage=0;
    for(let sy=0;sy<4;sy++)for(let sx=0;sx<4;sx++) {
      const u=(x+(sx+.5)/4)/size*16, v=(y+(sy+.5)/4)/size*16;
      const box=(u>=3&&u<=11.6&&v>=3&&v<=4.3)||(u>=3&&u<=4.3&&v>=3&&v<=13)||(u>=3&&u<=11.6&&v>=11.7&&v<=13);
      const arrow=(u>=7&&u<=13.2&&v>=7.35&&v<=8.65)||((u>=10&&u<=13.4)&&Math.abs(Math.abs(v-8)-(13-u))<.87);
      if(box||arrow)coverage++;
    }
    const i=y*stride+1+x*4; raster[i]=c[0];raster[i+1]=c[1];raster[i+2]=c[2];raster[i+3]=Math.round(coverage/16*255);
  }
  const ihdr=Buffer.alloc(13);ihdr.writeUInt32BE(size,0);ihdr.writeUInt32BE(size,4);ihdr[8]=8;ihdr[9]=6;
  return Buffer.concat([Buffer.from([137,80,78,71,13,10,26,10]),chunk('IHDR',ihdr),chunk('IDAT',zlib.deflateSync(raster)),chunk('IEND',Buffer.alloc(0))]);
}
function icons() {
  const images=[32,48,256].map(size=>({size,bytes:iconPNG(size)})); const header=Buffer.alloc(6);header.writeUInt16LE(1,2);header.writeUInt16LE(images.length,4);
  let offset=6+16*images.length;
  const entries=images.map(({size,bytes})=>{const item=Buffer.alloc(16);item[0]=item[1]=size===256?0:size;item.writeUInt16LE(1,4);item.writeUInt16LE(32,6);item.writeUInt32LE(bytes.length,8);item.writeUInt32LE(offset,12);offset+=bytes.length;return item;});
  const groupEntries=images.map(({size,bytes},i)=>{const item=Buffer.alloc(14);item[0]=item[1]=size===256?0:size;item.writeUInt16LE(1,4);item.writeUInt16LE(32,6);item.writeUInt32LE(bytes.length,8);item.writeUInt16LE(i+1,12);return item;});
  return {images,ico:Buffer.concat([header,...entries,...images.map(x=>x.bytes)]),group:Buffer.concat([header,...groupEntries])};
}
const pad = bytes => Buffer.concat([bytes,Buffer.alloc((4-bytes.length%4)%4)]);
const wide = text => Buffer.from(text+'\0','utf16le');
function block(key,type,value=Buffer.alloc(0),children=[],valueLength=value.length) {
  const header=Buffer.alloc(6);header.writeUInt16LE(valueLength,2);header.writeUInt16LE(type,4);
  const body=Buffer.concat([pad(Buffer.concat([header,wide(key)])),...(value.length?[pad(value)]:[]),...children.map(pad)]);body.writeUInt16LE(body.length,0);return body;
}
function versionResource(version,{productName='联铺',executableName='Lianpu.exe',description='联铺 · 数字资料经营工作区'}={}) {
  const [major,minor,patch]=version.split('.').map(Number);if(![major,minor,patch].every(n=>Number.isInteger(n)&&n>=0&&n<=65535))throw new Error('Invalid resource version');
  const fixed=Buffer.alloc(52);[0xfeef04bd,0x10000,(major<<16|minor)>>>0,(patch<<16)>>>0,(major<<16|minor)>>>0,(patch<<16)>>>0,0x3f,0,0x40004,1,0,0,0].forEach((n,i)=>fixed.writeUInt32LE(n,i*4));
  const strings={CompanyName:'Independent commissioned development',FileDescription:description,FileVersion:version,InternalName:path.basename(executableName,'.exe'),LegalCopyright:'Original application rights reserved; third-party notices included',OriginalFilename:executableName,ProductName:productName,ProductVersion:version};
  const table=block('080404B0',1,Buffer.alloc(0),Object.entries(strings).map(([key,value])=>block(key,1,wide(value),[],value.length+1)),0);
  const translation=Buffer.alloc(4);translation.writeUInt16LE(2052);translation.writeUInt16LE(1200,2);
  return block('VS_VERSION_INFO',0,fixed,[block('StringFileInfo',1,Buffer.alloc(0),[table],0),block('VarFileInfo',1,Buffer.alloc(0),[block('Translation',0,translation)],0)]);
}
const updater = String.raw`param([string]$PayloadPath)
$ErrorActionPreference = 'Stop'
Add-Type -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
public class LianpuResources {
  private delegate bool Names(IntPtr module, IntPtr type, IntPtr name, IntPtr param);
  private delegate bool Langs(IntPtr module, IntPtr type, IntPtr name, ushort language, IntPtr param);
  [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)] private static extern IntPtr LoadLibraryExW(string path,IntPtr file,uint flags);
  [DllImport("kernel32.dll")] private static extern bool FreeLibrary(IntPtr module);
  [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)] private static extern bool EnumResourceNamesW(IntPtr module,IntPtr type,Names callback,IntPtr param);
  [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)] private static extern bool EnumResourceLanguagesW(IntPtr module,IntPtr type,IntPtr name,Langs callback,IntPtr param);
  [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)] private static extern IntPtr BeginUpdateResourceW(string path,bool deleteAll);
  [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)] private static extern bool UpdateResourceW(IntPtr update,IntPtr type,IntPtr name,ushort language,byte[] bytes,uint size);
  [DllImport("kernel32.dll", SetLastError=true)] private static extern bool EndUpdateResourceW(IntPtr update,bool discard);
  private class Resource { public int Type; public IntPtr Name; public ushort Language; public bool Allocated; }
  private static void Check(bool success) { if(!success) throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error()); }
  public static void Apply(string path,byte[][] images,byte[] group,byte[] version) {
    var resources=new List<Resource>();
    IntPtr module=LoadLibraryExW(path,IntPtr.Zero,2|32); if(module==IntPtr.Zero) throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());
    try {
      foreach(int resourceType in new int[]{3,14,16}) {
        Names names=(m,t,n,p)=>{ Langs languages=(lm,lt,ln,lang,lp)=>{ bool allocated=((long)ln>>16)!=0; resources.Add(new Resource{Type=resourceType,Name=allocated?Marshal.StringToHGlobalUni(Marshal.PtrToStringUni(ln)):ln,Language=lang,Allocated=allocated});return true;}; EnumResourceLanguagesW(m,t,n,languages,IntPtr.Zero);GC.KeepAlive(languages);return true;};
        EnumResourceNamesW(module,(IntPtr)resourceType,names,IntPtr.Zero);GC.KeepAlive(names);
      }
    } finally { FreeLibrary(module); }
    IntPtr update=BeginUpdateResourceW(path,false);if(update==IntPtr.Zero)throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error()); bool committed=false;
    try {
      foreach(var resource in resources)Check(UpdateResourceW(update,(IntPtr)resource.Type,resource.Name,resource.Language,null,0));
      for(int i=0;i<images.Length;i++)Check(UpdateResourceW(update,(IntPtr)3,(IntPtr)(i+1),2052,images[i],(uint)images[i].Length));
      Check(UpdateResourceW(update,(IntPtr)14,(IntPtr)1,2052,group,(uint)group.Length));
      Check(UpdateResourceW(update,(IntPtr)16,(IntPtr)1,2052,version,(uint)version.Length));
      Check(EndUpdateResourceW(update,false));committed=true;
    } finally { if(!committed)EndUpdateResourceW(update,true);foreach(var resource in resources)if(resource.Allocated)Marshal.FreeHGlobal(resource.Name); }
  }
}
'@
$spec = Get-Content -LiteralPath $PayloadPath -Raw -Encoding UTF8 | ConvertFrom-Json
$pictures = [System.Collections.Generic.List[byte[]]]::new()
foreach($picture in $spec.images) { $pictures.Add([Convert]::FromBase64String($picture)) }
[LianpuResources]::Apply($spec.executable,$pictures.ToArray(),[Convert]::FromBase64String($spec.group),[Convert]::FromBase64String($spec.version))
$resourceInfo = [Diagnostics.FileVersionInfo]::GetVersionInfo($spec.executable)
if($resourceInfo.ProductName -ne $spec.productName -or $resourceInfo.OriginalFilename -ne $spec.executableName) { throw 'Updated product resource did not verify' }
Write-Output 'Original application icon and product resources verified.'
`;
function applyBranding(executable,{version,workDir,productName='联铺',executableName='Lianpu.exe',description='联铺 · 数字资料经营工作区'}={}) {
  if(process.platform!=='win32')throw new Error('Branding requires the Windows build host');
  const work=workDir||path.resolve(__dirname,'../work/branding');fs.mkdirSync(work,{recursive:true});
  const icon=icons(), originalSha256=hash(fs.readFileSync(executable));fs.writeFileSync(path.join(work,'Lianpu.ico'),icon.ico);
  const script=path.join(work,'update-resources.ps1'), payload=path.join(work,'resources.json');fs.writeFileSync(script,'\ufeff'+updater);
  fs.writeFileSync(payload,JSON.stringify({executable:path.resolve(executable),productName,executableName,images:icon.images.map(i=>i.bytes.toString('base64')),group:icon.group.toString('base64'),version:versionResource(version,{productName,executableName,description}).toString('base64')}));
  const run=spawnSync('powershell.exe',['-NoProfile','-NonInteractive','-File',script,'-PayloadPath',payload],{encoding:'utf8',timeout:90000,windowsHide:true});
  if(run.status!==0)throw new Error(`Application resource update failed: ${run.stderr||run.error?.message||run.stdout}`);
  const result={originalSha256,brandedSha256:hash(fs.readFileSync(executable)),iconSha256:hash(icon.ico),modifications:'Only Win32 icon and product version resources; runtime code unchanged',status:'resource metadata verified',at:new Date().toISOString()};
  fs.writeFileSync(path.join(work,'branding.json'),JSON.stringify(result,null,2));return result;
}
module.exports={applyBranding,icons,versionResource};
if(require.main===module){const root=path.resolve(__dirname,'..'), version=require(path.join(root,'package.json')).version;console.log(JSON.stringify(applyBranding(process.argv[2],{version}),null,2));}
