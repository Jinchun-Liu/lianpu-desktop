'use strict';
const fs=require('node:fs'),path=require('node:path');
const {generateKeyPairSync,createPrivateKey,createPublicKey,createHash,sign}=require('node:crypto');
const {spawnSync}=require('node:child_process');
const {canonical}=require('../src/services/updates.cjs');
const ROOT=path.resolve(__dirname,'..'),WORK=path.join(ROOT,'work','release-signing'),TRUST=path.join(ROOT,'src','release-trust.json');
function protect(bytes,operation){
  if(process.platform!=='win32')throw new Error('Development release signing key is protected by the Windows build account.');
  fs.mkdirSync(WORK,{recursive:true});const script=path.join(WORK,'key-protection.ps1');
  fs.writeFileSync(script,`param([ValidateSet('protect','unprotect')][string]$Operation)\n$ErrorActionPreference='Stop'\nAdd-Type -AssemblyName System.Security\n$inputBytes=[Convert]::FromBase64String([Console]::In.ReadToEnd())\nif($Operation -eq 'protect'){$result=[Security.Cryptography.ProtectedData]::Protect($inputBytes,$null,[Security.Cryptography.DataProtectionScope]::CurrentUser)}else{$result=[Security.Cryptography.ProtectedData]::Unprotect($inputBytes,$null,[Security.Cryptography.DataProtectionScope]::CurrentUser)}\n[Console]::Out.Write([Convert]::ToBase64String($result))\n[Array]::Clear($inputBytes,0,$inputBytes.Length)\n[Array]::Clear($result,0,$result.Length)\n`);
  // Private material is transmitted only through child stdin/stdout pipes, never CLI arguments or logs.
  const windows=process.env.SystemRoot;if(!windows||!path.isAbsolute(windows))throw new Error('Cannot locate Windows key protection component.');
  const executable=path.join(windows,'System32','WindowsPowerShell','v1.0','powershell.exe');
  const result=spawnSync(executable,['-NoProfile','-NonInteractive','-File',script,'-Operation',operation],{input:bytes.toString('base64'),encoding:'utf8',windowsHide:true,timeout:20000});
  if(result.status!==0)throw new Error('Windows key protection failed; private material was not printed.');
  return Buffer.from(result.stdout.trim(),'base64');
}
function signingKey({create=false}={}){
  const privatePath=path.join(WORK,'development-key.dpapi');let privateKey;
  if(!fs.existsSync(privatePath)){
    if(!create)throw new Error('No protected development release signing key; initialize it explicitly on the build host.');
    if(fs.existsSync(TRUST))throw new Error('Existing trust anchors found; refusing to replace them with a new key.');
    const pair=generateKeyPairSync('ed25519');const bytes=pair.privateKey.export({format:'der',type:'pkcs8'});
    try{fs.mkdirSync(WORK,{recursive:true});fs.writeFileSync(privatePath,protect(bytes,'protect'),{mode:0o600,flag:'wx'});}finally{bytes.fill(0);}
    privateKey=pair.privateKey;const der=pair.publicKey.export({format:'der',type:'spki'}),fingerprint=createHash('sha256').update(der).digest('hex');
    fs.writeFileSync(TRUST,JSON.stringify({format:'lianpu-release-trust-v1',keys:[{id:'dev-'+fingerprint.slice(0,24),publicKey:pair.publicKey.export({format:'pem',type:'spki'}),label:'本项目本机开发发布密钥',channel:'development',fingerprint,createdAt:new Date().toISOString(),commercialPublisherVerified:false}]},null,2)+'\n');
  }else{const bytes=protect(fs.readFileSync(privatePath),'unprotect');try{privateKey=createPrivateKey({key:bytes,format:'der',type:'pkcs8'});}finally{bytes.fill(0);}}
  const publicKey=createPublicKey(privateKey).export({format:'pem',type:'spki'});const trust=JSON.parse(fs.readFileSync(TRUST,'utf8'));const key=trust.keys.find(key=>key.publicKey===publicKey&&!key.revoked&&key.channel==='development');if(!key)throw new Error('Protected signing key does not match the public trust anchor.');return {privateKey,key};
}
function signRelease({artifactUrl}={}){
  const {privateKey,key}=signingKey();const build=JSON.parse(fs.readFileSync(path.join(ROOT,'release/build-manifest.json'),'utf8'));
  const filename=path.basename(build.installer),file=path.join(ROOT,'release',filename),bytes=fs.readFileSync(file),sha256=createHash('sha256').update(bytes).digest('hex');
  if(sha256!==build.installerSha256)throw new Error('MSI hash differs from build manifest; will not sign.');
  const now=Date.now();const manifest={format:'lianpu-update-v1',keyId:key.id,product:'lianpu-desktop',version:build.version,minVersion:'0.1.0',platform:'win32',arch:'x64',channel:'development',issuedAt:new Date(now).toISOString(),expiresAt:new Date(now+90*86400000).toISOString(),notes:['独立 Windows 开发验证版；具体功能和安装证据见随包验收记录。','更新清单已由本项目开发密钥签名；Windows 发布者代码签名仍需单独核验。'],artifact:{filename,sha256,size:bytes.length,...(artifactUrl?{url:artifactUrl}:{})}};
  const envelope={manifest,signature:sign(null,Buffer.from(canonical(manifest)),privateKey).toString('base64')};const output=path.join(ROOT,'release',`Lianpu-${build.version}-windows-x64.lianpu-update`);fs.writeFileSync(output,JSON.stringify(envelope,null,2)+'\n');return {path:output,keyId:key.id,fingerprint:key.fingerprint,version:build.version,channel:'development',windowsCodeSigned:false};
}
if(require.main===module){try{if(process.argv.includes('--initialize')){const {key}=signingKey({create:true});console.log(JSON.stringify({keyId:key.id,fingerprint:key.fingerprint,storage:'Windows DPAPI CurrentUser, work/release-signing, excluded from source archives',commercialPublisherVerified:false}));}else console.log(JSON.stringify(signRelease()));}catch(error){console.error(error.message);process.exitCode=1;}}
module.exports={signingKey,signRelease};
