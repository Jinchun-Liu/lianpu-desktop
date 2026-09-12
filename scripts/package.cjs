'use strict';
const fs = require('node:fs');
const path = require('node:path');
const { spawnSync } = require('node:child_process');
const { generate, walk, sha } = require('./licenses.cjs');
const ROOT = path.resolve(__dirname, '..');
const WORK = path.join(ROOT, 'work');
const RELEASE = path.join(ROOT, 'release');
const NSIS_VERSION = '3.12';
const NSIS_ZIP_SHA256 = '56581f90db321581c5381193d796fffcf2d24b2f8fed2160a6c6a3baa67f2c4f';
function inside(parent, target) {
  const resolved = path.resolve(target); const rel = path.relative(path.resolve(parent), resolved);
  if (!rel || rel.startsWith('..') || path.isAbsolute(rel)) throw new Error('拒绝对工作范围外路径执行文件操作');
  return resolved;
}
function nsi(value) { return String(value).replaceAll('$', '$$').replaceAll('"', '$\\"'); }
function installerScript({ stage, outfile, version, build }) {
  return `Unicode true
RequestExecutionLevel user
ManifestDPIAware true
Name "联铺"
OutFile "${nsi(outfile)}"
InstallDir "$LOCALAPPDATA\\Programs\\Lianpu"
SetCompressor /SOLID zlib
ShowInstDetails show
ShowUninstDetails show
VIProductVersion "${version}.0"
VIAddVersionKey /LANG=2052 "ProductName" "联铺"
VIAddVersionKey /LANG=2052 "FileDescription" "联铺 Windows x64 开发验证安装程序"
VIAddVersionKey /LANG=2052 "FileVersion" "${version}"
VIAddVersionKey /LANG=2052 "LegalCopyright" "Original application rights reserved by owner; third-party notices included"
!include "MUI2.nsh"
!include "FileFunc.nsh"
!include "LogicLib.nsh"
!include "x64.nsh"
Var Validation
Var PriorBuild
!define MUI_ABORTWARNING
!define MUI_WELCOMEPAGE_TITLE "安装联铺"
!define MUI_WELCOMEPAGE_TEXT "管理你的资料、订单与交付记录。所需运行组件已包含在安装程序内。$\\r$\\n$\\r$\\n此版本用于开发验证，真实闲鱼自动接入仍待完成，安装程序尚未代码签名。$\\r$\\n$\\r$\\n仅为当前用户安装；升级和卸载都保留本机业务资料。升级前请先退出联铺。"
!insertmacro MUI_PAGE_WELCOME
!insertmacro MUI_PAGE_DIRECTORY
!insertmacro MUI_PAGE_INSTFILES
!define MUI_FINISHPAGE_RUN "$INSTDIR\\versions\\${build}\\Lianpu.exe"
!define MUI_FINISHPAGE_RUN_NOTCHECKED
!insertmacro MUI_PAGE_FINISH
!define MUI_UNCONFIRMPAGE_TEXT_TOP "卸载联铺程序。你的本机业务资料和账号会话将保留在个人资料目录，卸载后不会自动处理订单。重新安装后可继续使用。"
!insertmacro MUI_UNPAGE_CONFIRM
!insertmacro MUI_UNPAGE_INSTFILES
!insertmacro MUI_LANGUAGE "SimpChinese"

Function .onInit
  SetShellVarContext current
  SetRegView 64
  StrCpy $Validation "0"
  \${GetParameters} $0
  ClearErrors
  \${GetOptions} $0 "/VALIDATION" $1
  IfErrors +2 0
  StrCpy $Validation "1"
  \${IfNot} \${RunningX64}
    MessageBox MB_ICONSTOP "此安装程序适用于 Windows x64。"
    Abort
  \${EndIf}
FunctionEnd

Function .onVerifyInstDir
  \${GetFileName} "$INSTDIR" $0
  \${If} $0 != "Lianpu"
    Abort
  \${EndIf}
FunctionEnd

Section "联铺" Main
  Call .onVerifyInstDir
  ReadINIStr $PriorBuild "$INSTDIR\\install.ini" "Install" "Build"
  StrCmp $PriorBuild "" ReadyToInstall
  \${GetFileName} "$PriorBuild" $1
  StrCmp $1 $PriorBuild 0 BadPreviousInstall
  IfFileExists "$INSTDIR\\versions\\$PriorBuild\\Lianpu.exe" 0 ReadyToInstall
  ClearErrors
  FileOpen $0 "$INSTDIR\\versions\\$PriorBuild\\Lianpu.exe" a
  IfErrors RunningApp 0
  FileClose $0
  Goto ReadyToInstall
RunningApp:
  MessageBox MB_ICONSTOP "请先完全退出联铺，再继续安装。你的业务资料不会被删除。"
  Abort
BadPreviousInstall:
  MessageBox MB_ICONSTOP "已有安装记录不符合预期，已停止安装并保留文件。"
  Abort
ReadyToInstall:
  SetOutPath "$INSTDIR\\versions\\${build}"
  ClearErrors
  File /r "${nsi(stage)}\\*"
  IfErrors InstallFailed 0
  WriteINIStr "$INSTDIR\\install.ini" "Install" "Marker" "lianpu-owned-install-v1"
  WriteINIStr "$INSTDIR\\install.ini" "Install" "Build" "${build}"
  WriteINIStr "$INSTDIR\\install.ini" "Install" "Validation" "$Validation"
  WriteUninstaller "$INSTDIR\\Uninstall.exe"
  StrCmp $Validation "1" InstallComplete
  CreateDirectory "$SMPROGRAMS\\联铺"
  CreateShortcut "$SMPROGRAMS\\联铺\\联铺.lnk" "$INSTDIR\\versions\\${build}\\Lianpu.exe"
  CreateShortcut "$SMPROGRAMS\\联铺\\卸载联铺.lnk" "$INSTDIR\\Uninstall.exe"
  WriteRegStr HKCU "Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\Lianpu" "DisplayName" "联铺"
  WriteRegStr HKCU "Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\Lianpu" "DisplayVersion" "${version}"
  WriteRegStr HKCU "Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\Lianpu" "InstallLocation" "$INSTDIR"
  WriteRegStr HKCU "Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\Lianpu" "DisplayIcon" "$INSTDIR\\versions\\${build}\\Lianpu.exe"
  WriteRegStr HKCU "Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\Lianpu" "UninstallString" '$\\"$INSTDIR\\Uninstall.exe$\\"'
  WriteRegDWORD HKCU "Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\Lianpu" "NoModify" 1
  WriteRegDWORD HKCU "Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\Lianpu" "NoRepair" 1
  Goto InstallComplete
InstallFailed:
  MessageBox MB_ICONSTOP "安装文件未能完整写入，已保留原有业务资料。请检查磁盘空间，并退出正在运行的联铺后重试。"
  Abort
InstallComplete:
SectionEnd

Section "Uninstall"
  SetShellVarContext current
  SetRegView 64
  \${GetFileName} "$INSTDIR" $0
  StrCmp $0 "Lianpu" 0 UnsafeUninstall
  ReadINIStr $0 "$INSTDIR\\install.ini" "Install" "Marker"
  StrCmp $0 "lianpu-owned-install-v1" 0 UnsafeUninstall
  ReadINIStr $Validation "$INSTDIR\\install.ini" "Install" "Validation"
  ClearErrors
  RMDir /r "$INSTDIR\\versions"
  IfErrors UninstallFailed 0
  Delete "$INSTDIR\\install.ini"
  Delete "$INSTDIR\\Uninstall.exe"
  RMDir "$INSTDIR"
  StrCmp $Validation "1" UninstallComplete
  Delete "$SMPROGRAMS\\联铺\\联铺.lnk"
  Delete "$SMPROGRAMS\\联铺\\卸载联铺.lnk"
  RMDir "$SMPROGRAMS\\联铺"
  DeleteRegKey HKCU "Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\Lianpu"
  Goto UninstallComplete
UnsafeUninstall:
  MessageBox MB_ICONSTOP "无法确认本目录属于联铺安装，已停止卸载并保留全部文件。"
  Abort
UninstallFailed:
  MessageBox MB_ICONSTOP "部分程序文件仍在使用中，请完全退出联铺后重试卸载。业务资料已保留。"
  Abort
UninstallComplete:
SectionEnd
`;
}
async function packageApp({ format = 'msi', signUpdate = false } = {}) {
  if (process.platform !== 'win32' || process.arch !== 'x64') throw new Error('本阶段打包仅支持开发方 Windows x64；不构建 Mac 包');
  const manifest = JSON.parse(fs.readFileSync(path.join(ROOT, 'package.json')));
  const electronPkg = JSON.parse(fs.readFileSync(path.join(ROOT, 'node_modules/electron/package.json')));
  if (manifest.devDependencies.electron !== electronPkg.version) throw new Error('Electron 版本与锁定版本不一致');
  const runtime = path.join(ROOT, 'node_modules', 'electron', 'dist');
  for (const file of ['electron.exe', 'LICENSE', 'LICENSES.chromium.html']) if (!fs.existsSync(path.join(runtime, file))) throw new Error('开发方 Electron 运行时尚未完整下载：' + file);
  for (const file of ['src/main.cjs', 'src/preload.cjs', 'src/renderer/index.html', 'src/renderer/app.js']) if (!fs.existsSync(path.join(ROOT, file))) throw new Error('应用文件尚未完成：' + file);
  if (!['msi','nsis'].includes(format)) throw new Error('未知安装器格式');
  const inventory = generate({ installerFormat: format });
  if (inventory.runtime.files.some(f => f.architecture && f.architecture !== 'x64')) throw new Error('运行时包含非 x64 原生组件');
  const appFiles = walk(path.join(ROOT, 'src')).filter(f => !f.endsWith('.test.cjs') && !path.relative(ROOT,f).replaceAll('\\','/').startsWith('src/licensing/native/'));
  const sharedFiles = walk(path.join(ROOT,'shared')).filter(f => f.endsWith('.mjs'));
  const nativeHelper = path.join(ROOT,'src','licensing','native','bin','Lianpu.Device.exe');
  const nativeIntegrity = path.join(ROOT,'src','licensing','native-integrity.json');
  if(!fs.existsSync(nativeHelper)||!fs.existsSync(nativeIntegrity)||JSON.parse(fs.readFileSync(nativeIntegrity,'utf8')).sha256!==sha(fs.readFileSync(nativeHelper)))throw new Error('设备保护组件缺失或摘要不符，请先构建并记录');
  const licenseConfig=JSON.parse(fs.readFileSync(path.join(ROOT,'src','licensing','config.json'),'utf8'));
  if(Object.keys(licenseConfig).some(key=>!['endpoint','publicKeys'].includes(key)))throw new Error('客户授权配置只能包含公开地址和公钥');
  if(licenseConfig.endpoint){const address=new URL(licenseConfig.endpoint);if(address.protocol!=='https:'||address.username||address.password||address.search||address.hash)throw new Error('发行包授权地址必须为无凭据的 HTTPS 地址');}
  for(const key of Object.values(licenseConfig.publicKeys||{})){if(typeof key!=='string'||!/^[A-Za-z0-9_-]+$/.test(key))throw new Error('客户公钥必须为 SPKI base64url');const bytes=Buffer.from(key,'base64url');if(bytes.toString('base64url')!==key||require('node:crypto').createPublicKey({key:bytes,type:'spki',format:'der'}).asymmetricKeyType!=='ed25519')throw new Error('客户包只允许 Ed25519 公钥，禁止签发私钥');}
  const docsFiles = fs.existsSync(path.join(ROOT,'docs')) ? walk(path.join(ROOT,'docs')) : [];
  const extraFiles = ['README.md', 'LICENSE'].map(name => path.join(ROOT,name)).filter(file => fs.existsSync(file));
  const uiReuseRoot = path.join(ROOT,'compliance','ui-reuse');
  const uiReuseInputs = fs.existsSync(uiReuseRoot) ? [path.join(uiReuseRoot,'origin.json'),path.join(uiReuseRoot,'manifest.json'),...walk(path.join(uiReuseRoot,'licenses'))] : [];
  const buildInputs = [...appFiles,...sharedFiles,nativeHelper,...docsFiles,...extraFiles,...uiReuseInputs,path.join(ROOT, 'package.json'), path.join(ROOT, 'package-lock.json'), __filename, path.join(__dirname, 'licenses.cjs'), path.join(__dirname,'release-msi.cjs'), path.join(__dirname,'release-signing.cjs'), path.join(__dirname,'branding.cjs'),path.join(__dirname,'package-security.cjs'),path.join(__dirname,'protection-provider.cjs')].sort();
  const sourceSha = sha(Buffer.concat(buildInputs.map(file => Buffer.concat([Buffer.from(relativeSource(file) + '\0'), fs.readFileSync(file)]))));
  const build = `${manifest.version}-${sourceSha.slice(0, 12)}`;
  const stage = inside(WORK, path.join(WORK, 'package', 'windows-x64', `${build}-${Date.now()}`));
  fs.mkdirSync(stage, { recursive: true }); fs.mkdirSync(RELEASE, { recursive: true });
  fs.cpSync(runtime, stage, { recursive: true, filter: p => !p.endsWith('default_app.asar') && !/\.log$/i.test(p) });
  fs.renameSync(path.join(stage, 'electron.exe'), path.join(stage, 'Lianpu.exe'));
  const branding = require('./branding.cjs').applyBranding(path.join(stage,'Lianpu.exe'),{version:manifest.version,workDir:path.join(WORK,'package',`branding-${build}-${Date.now()}`)});
  fs.mkdirSync(path.join(ROOT,'evidence'),{recursive:true});
  fs.writeFileSync(path.join(ROOT,'evidence',`branding-${build}.json`),JSON.stringify(branding,null,2));
  const appDir = inside(WORK,path.join(WORK,'package',`asar-input-${build}-${Date.now()}`)); fs.mkdirSync(appDir, { recursive: true });
  for (const file of [...appFiles,...sharedFiles,...docsFiles,...extraFiles]) { const dest = path.join(appDir, relativeSource(file)); fs.mkdirSync(path.dirname(dest), { recursive: true }); fs.copyFileSync(file, dest); }
  fs.mkdirSync(path.join(stage,'resources','licensing'),{recursive:true});
  fs.copyFileSync(nativeHelper,path.join(stage,'resources','licensing','Lianpu.Device.exe'));
  const { devDependencies, scripts, ...runtimeManifest } = manifest;
  fs.writeFileSync(path.join(appDir, 'package.json'), JSON.stringify({...runtimeManifest,build}, null, 2));
  const protection = await require('./package-security.cjs').securePackage({appDir,stage,executable:path.join(stage,'Lianpu.exe'),work:path.join(WORK,'package',`protection-${build}-${Date.now()}`)});
  fs.writeFileSync(path.join(ROOT,'evidence',`protection-${build}.json`),JSON.stringify(protection,null,2));
  const distributionProvenance = {build,branding,protection,runtimeFiles:inventory.runtime.files.filter(f=>f.bundled).map(file=>{
    const destination=file.path==='electron.exe'?'Lianpu.exe':file.path;
    return {upstreamPath:file.path,distributionPath:destination,upstreamSha256:file.sha256,distributionSha256:sha(fs.readFileSync(path.join(stage,destination))),modified:file.path==='electron.exe',modification:file.path==='electron.exe'?'Win32 品牌资源、ASAR 完整性资源及 Electron 官方运行开关；详见 branding/protection 记录。':'未修改',licenseReviewStatus:file.licenseReviewStatus||'aggregate-and-individual-notice-review-incomplete'};
  })};
  fs.writeFileSync(path.join(ROOT,'compliance','distribution-provenance.json'),JSON.stringify(distributionProvenance,null,2));
  inventory.distributionProvenance='compliance/distribution-provenance.json';
  fs.writeFileSync(path.join(ROOT,'compliance','inventory.json'),JSON.stringify(inventory,null,2));
  const bom=JSON.parse(fs.readFileSync(path.join(ROOT,'SBOM.cdx.json'),'utf8'));
  bom.components.push({type:'application',name:'Lianpu.exe (Electron runtime with product resources and fuses)',version:electronPkg.version,scope:'required',hashes:[{alg:'SHA-256',content:protection.executableSha256}],properties:[{name:'lianpu:upstream-sha256',value:branding.originalSha256},{name:'lianpu:modification',value:'Win32 product resources, ASAR integrity resource and documented Electron fuses'},{name:'lianpu:license-review',value:'incomplete-exact-binary-license-mapping'}]});
  fs.writeFileSync(path.join(ROOT,'SBOM.cdx.json'),JSON.stringify(bom,null,2));
  fs.appendFileSync(path.join(ROOT,'THIRD_PARTY_NOTICES.md'),'\n本产品将 Electron 主程序命名为 Lianpu.exe，修改 Win32 品牌资源、加入 ASAR 完整性资源，并设置官方 Electron 运行开关。上游与发行摘要及修改说明见 compliance/distribution-provenance.json。@electron/asar 与 @electron/fuses 仅用于构建，MIT 许可原文随附。\n');
  for (const name of ['THIRD_PARTY_NOTICES.md', 'SBOM.cdx.json']) fs.copyFileSync(path.join(ROOT, name), path.join(stage, name));
  fs.cpSync(path.join(ROOT, 'compliance'), path.join(stage, 'compliance'), { recursive: true });
  const outfile = path.join(RELEASE, `Lianpu-${manifest.version}-windows-x64-setup.${format === 'msi' ? 'msi' : 'exe'}`);
  const compileWork = inside(WORK,path.join(WORK,'package',`installer-${build}-${Date.now()}`)); fs.mkdirSync(compileWork,{recursive:true});
  let installerDetails;
  if (format === 'msi') {
    const interim = path.join(compileWork,path.basename(outfile));
    installerDetails = require('./release-msi.cjs').buildMsi({stage,outfile:interim,version:manifest.version,build,work:compileWork});
    fs.copyFileSync(interim,outfile);
  } else {
    const nsisZip = path.join(WORK,'tools','nsis-curl.zip');
    if (!fs.existsSync(nsisZip) || sha(fs.readFileSync(nsisZip)) !== NSIS_ZIP_SHA256) throw new Error('NSIS 官方工具缺失或哈希不符');
    const compiler = path.join(WORK,'tools',`nsis-${NSIS_VERSION}`,'makensis.exe');
    const check = spawnSync(compiler,['/VERSION'],{encoding:'utf8',windowsHide:true});
    if (check.status !== 0 || check.stdout.trim() !== 'v3.12') throw new Error('NSIS 版本不符');
    const script = path.join(compileWork,'installer.nsi'); fs.writeFileSync(script,'\uFEFF'+installerScript({stage,outfile,version:manifest.version,build}));
    const compiled = spawnSync(compiler,['/V3','/INPUTCHARSET','UTF8',script],{encoding:'utf8',windowsHide:true,maxBuffer:8*1024*1024});
    fs.writeFileSync(path.join(compileWork,'build.log'),`${compiled.stdout}\n${compiled.stderr}`);
    if (compiled.status !== 0) throw new Error('NSIS 构建失败，见 '+compileWork);
    installerDetails = {format:'nsis',nsisVersion:NSIS_VERSION,nsisZipSha256:NSIS_ZIP_SHA256};
  }
  fs.mkdirSync(path.join(ROOT, 'evidence'), { recursive: true });
  const result = { builtAt: new Date().toISOString(), platform: 'win32', architecture: 'x64', version: manifest.version, build, sourceSha256: sourceSha, installer: path.relative(ROOT, outfile), installerSha256: sha(fs.readFileSync(outfile)), installerBytes: fs.statSync(outfile).size,
    runtimeVersions: inventory.runtime.version, branding, protection, nativeHelperSha256:sha(fs.readFileSync(nativeHelper)), ...installerDetails, payloadDirectory:path.relative(ROOT,stage), compilationDirectory:path.relative(ROOT,compileWork),
    packageLockSha256: inventory.packageLockSha256, licensingServiceConfigured:!!licenseConfig.endpoint&&Object.keys(licenseConfig.publicKeys||{}).length>0, signed: false, signatureStatus: 'not-signed', commercialRelease: false,
    remaining: ['真实闲鱼业务链路尚未验收', '许可逐组件审查尚未全部完成', '本构建的实际安装、升级、卸载结果须对照独立验证记录，构建完成不等于验收通过', '干净标准用户机器、最低目标系统与 Windows 发布者代码签名尚待验收'],
    payloadFiles: walk(stage).map(file => ({ path: path.relative(stage, file).replaceAll('\\', '/'), sha256: sha(fs.readFileSync(file)), size: fs.statSync(file).size })) };
  fs.writeFileSync(path.join(RELEASE, 'build-manifest.json'), JSON.stringify(result, null, 2));
  const sums = [`${result.installerSha256}  ${path.basename(outfile)}`];
  if (format === 'msi' && signUpdate) {
    const signedUpdate = require('./release-signing.cjs').signRelease();
    result.updateManifest = {file:path.relative(ROOT,signedUpdate.path),sha256:sha(fs.readFileSync(signedUpdate.path)),bytes:fs.statSync(signedUpdate.path).size,keyId:signedUpdate.keyId,fingerprint:signedUpdate.fingerprint,channel:'development',signatureAlgorithm:'Ed25519',commercialPublisherVerified:false,windowsCodeSigned:false,artifactUrl:null};
    fs.writeFileSync(path.join(RELEASE, 'build-manifest.json'), JSON.stringify(result, null, 2));
    sums.push(`${result.updateManifest.sha256}  ${path.basename(signedUpdate.path)}`);
  }
  sums.push(`${sha(fs.readFileSync(path.join(RELEASE, 'build-manifest.json')))}  build-manifest.json`);
  fs.writeFileSync(path.join(RELEASE, 'SHA256SUMS.txt'), sums.join('\n') + '\n');
  process.stdout.write(JSON.stringify({ installer: outfile, bytes: result.installerBytes, sha256: result.installerSha256, signed: false, build }) + '\n');
  return result;
}
function relativeSource(file) { return path.relative(ROOT, file); }
if (require.main === module) { packageApp({format:process.argv.includes('--legacy-nsis')?'nsis':'msi',signUpdate:process.argv.includes('--sign-update')}).catch(error=>{console.error(error.message);process.exitCode=1;}); }
module.exports = { packageApp, installerScript, inside, NSIS_ZIP_SHA256 };
