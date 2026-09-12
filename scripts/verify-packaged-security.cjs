'use strict';
// P2: synthetic app only. Never loads the product entry point, accounts or TPM.
const fs=require('node:fs'),path=require('node:path'),assert=require('node:assert/strict');
const {spawnSync}=require('node:child_process');
const {securePackage}=require('./package-security.cjs');
const root=path.resolve(__dirname,'..'),base=path.join(root,'work','security-packaged');
const main=String.raw`
'use strict';
const {app,BrowserWindow,protocol,net,ipcMain}=require('electron'),fs=require('node:fs'),path=require('node:path');
const {pathToFileURL}=require('node:url');
const {RuntimePolicy,isTrustedSender}=require('./runtime-policy.cjs');
const folder=process.env.LIANPU_SYNTHETIC_PROFILE;
app.setPath('userData',path.join(folder,'userData'));app.setPath('logs',path.join(folder,'logs'));app.setPath('crashDumps',path.join(folder,'crashes'));
app.disableHardwareAcceleration();
protocol.registerSchemesAsPrivileged([{scheme:'lianpu',privileges:{standard:true,secure:true,supportFetchAPI:true}}]);
let primary;const url='lianpu://app/index.html';
setTimeout(()=>app.exit(4),12000).unref();
app.whenReady().then(async()=>{
 protocol.handle('lianpu',()=>net.fetch(pathToFileURL(path.join(__dirname,'index.html')).href));
 ipcMain.handle('synthetic:probe',event=>isTrustedSender(event,primary,url)?'accepted':'rejected');
 const options={show:false,webPreferences:{preload:path.join(__dirname,'preload.cjs'),sandbox:true,contextIsolation:true,nodeIntegration:false,devTools:false}};
 primary=new BrowserWindow(options);await primary.loadURL(url);const first=await primary.webContents.executeJavaScript('window.probe.check()');
 const other=new BrowserWindow(options);await other.loadURL(url);const second=await other.webContents.executeJavaScript('window.probe.check()');
 const result={versions:process.versions,packaged:app.isPackaged,customProtocolNetFetch:true,primary:first,sameUrlSecondWindow:second,sandbox:primary.webContents.getLastWebPreferences().sandbox,nodeIntegration:primary.webContents.getLastWebPreferences().nodeIntegration,inspectorUrl:require('node:inspector').url()||null,runtimePolicy:new RuntimePolicy({packaged:app.isPackaged,hasSwitch:name=>app.commandLine.hasSwitch(name)}).status()};
 fs.writeFileSync(process.env.LIANPU_SYNTHETIC_RESULT,JSON.stringify(result));other.destroy();primary.destroy();app.exit(0);
}).catch(error=>{fs.writeFileSync(process.env.LIANPU_SYNTHETIC_RESULT,JSON.stringify({error:error.message}));app.exit(3);});
`;
async function verify(){
 fs.mkdirSync(base,{recursive:true});const work=fs.mkdtempSync(path.join(base,'run-')),appDir=path.join(work,'input'),stage=path.join(work,'payload');fs.mkdirSync(appDir);
 const runtime=path.join(path.dirname(require.resolve('electron/package.json')),'dist');
 fs.cpSync(runtime,stage,{recursive:true,filter:file=>!file.endsWith('default_app.asar')&&!/\.log$/i.test(file)});
 const executable=path.join(stage,'SecuritySynthetic.exe');fs.renameSync(path.join(stage,'electron.exe'),executable);
 fs.writeFileSync(path.join(appDir,'package.json'),JSON.stringify({name:'lianpu-security-synthetic',version:'1.0.0',main:'main.cjs'}));
 fs.writeFileSync(path.join(appDir,'main.cjs'),main);
 fs.writeFileSync(path.join(appDir,'preload.cjs'),"const {contextBridge,ipcRenderer}=require('electron');contextBridge.exposeInMainWorld('probe',{check:()=>ipcRenderer.invoke('synthetic:probe')});");
 fs.writeFileSync(path.join(appDir,'index.html'),'<meta http-equiv="Content-Security-Policy" content="default-src \'self\'; script-src \'self\'"><title>Synthetic security validation</title><p>Isolated test only</p>');
 fs.copyFileSync(path.join(root,'src/security/runtime-policy.cjs'),path.join(appDir,'runtime-policy.cjs'));
 const started=Date.now(),protection=await securePackage({appDir,stage,executable,work:path.join(work,'build')});
 const profile=path.join(work,'profile');for(const part of ['','roaming','local','temp','userData','logs','crashes'])fs.mkdirSync(path.join(profile,part),{recursive:true});
 const marker=path.join(work,'injected.txt'),inject=path.join(work,'inject.cjs');fs.writeFileSync(inject,"require('node:fs').writeFileSync(process.env.LIANPU_INJECTION_MARKER,'unexpected injection');");
 const cases=[];
 function run(name,args=[],overrides={},expectedPolicy=true){
  const resultFile=path.join(work,name+'.json');const env={...process.env,APPDATA:path.join(profile,'roaming'),LOCALAPPDATA:path.join(profile,'local'),TEMP:path.join(profile,'temp'),TMP:path.join(profile,'temp'),LIANPU_SYNTHETIC_PROFILE:profile,LIANPU_SYNTHETIC_RESULT:resultFile,LIANPU_INJECTION_MARKER:marker,...overrides};
  delete env.NODE_PATH;if(!('ELECTRON_RUN_AS_NODE' in overrides))delete env.ELECTRON_RUN_AS_NODE;if(!('NODE_OPTIONS' in overrides))delete env.NODE_OPTIONS;
  const at=Date.now(),child=spawnSync(executable,['--noerrdialogs',...args],{env,encoding:'utf8',windowsHide:true,timeout:18000,maxBuffer:1024*1024});
  const result=fs.existsSync(resultFile)?JSON.parse(fs.readFileSync(resultFile,'utf8')):null;
  const record={name,elapsedMs:Date.now()-at,status:child.status,signal:child.signal,error:child.error?.message,result,stdout:child.stdout,stderr:child.stderr,injectionMarker:fs.existsSync(marker)};cases.push(record);
  if(name==='tampered-asar'){assert.notEqual(child.status,0);assert.equal(result,null);assert.equal(!!child.error,false);}
  else{assert.equal(child.status,0,JSON.stringify(record));assert.equal(result.primary,'accepted');assert.equal(result.sameUrlSecondWindow,'rejected');assert.equal(result.sandbox,true);assert.equal(result.nodeIntegration,false);assert.equal(result.customProtocolNetFetch,true);assert.equal(result.inspectorUrl,null);assert.equal(record.injectionMarker,false);assert.equal(result.runtimePolicy.allowed,expectedPolicy);}
 }
 let failure;
 try{
  run('baseline');run('node-options',[],{NODE_OPTIONS:'--require "'+inject+'"'});run('run-as-node',['-e',"require('node:fs').writeFileSync(process.env.LIANPU_INJECTION_MARKER,'unexpected node')"],{ELECTRON_RUN_AS_NODE:'1'});
  run('inspect',['--inspect=127.0.0.1:0'],{},false);run('remote-debugging-policy',['--remote-debugging-port=0'],{},false);
  const archive=path.join(stage,'resources','app.asar'),bytes=fs.readFileSync(archive),at=bytes.indexOf(Buffer.from('Synthetic security validation'));assert.ok(at>0);bytes[at]=bytes[at]===83?84:83;fs.writeFileSync(archive,bytes);run('tampered-asar');
 }catch(error){failure=error;}
 const report={at:new Date().toISOString(),scope:'Local synthetic Electron package, not product installer/cloud/account/TPM acceptance',work,elapsedMs:Date.now()-started,protection,cases,pass:!failure,failure:failure?.message,residual:'EXE/DLL replacement, administrator-controlled OS, MSI final-open race and restored old state remain outside this local runtime test.'};
 const output=path.resolve(root,'../evidence-security/package-runtime.json');fs.writeFileSync(output,JSON.stringify(report,null,2));console.log(JSON.stringify({output,pass:report.pass,cases:cases.map(({name,status,result})=>({name,status,runtime:result?.versions?.electron,policy:result?.runtimePolicy?.allowed})),failure:failure?.message}));if(failure)throw failure;
}
if(require.main===module)verify().catch(error=>{console.error(error.message);process.exitCode=1;});
module.exports={verify};
