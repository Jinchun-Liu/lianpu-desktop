'use strict';
// Real, inert MSI fixtures: no customer product, account, credential or TPM calls.
// Hypothesis: late removal upgrades once and rolls both products back on failure.
// Decision: verify retention and failure handling of the installer transaction.
// Stop at first mismatch; only uninstall the explicitly created fixture product.
const fs=require('node:fs'),path=require('node:path'),crypto=require('node:crypto'),assert=require('node:assert/strict'),{spawnSync}=require('node:child_process');
const {buildMsi}=require('./release-msi.cjs');
const root=path.resolve(__dirname,'..');fs.mkdirSync(path.join(root,'work'),{recursive:true});
const dir=fs.mkdtempSync(path.join(root,'work','upgrade-fixture-')),family='{'+crypto.randomUUID().toUpperCase()+'}',name='LianpuUpgrade'+crypto.randomBytes(5).toString('hex');
const target=path.join(dir,'installed'),data=path.join(dir,'user-data.txt');fs.writeFileSync(data,'opaque business, session and license placeholder; outside installer');
const before=fs.readFileSync(data),report={at:new Date().toISOString(),scope:'isolated Windows Installer transaction; inert text files; no customer data',checks:[]};
function ps(body){const file=path.join(dir,'query.ps1');fs.writeFileSync(file,body,'utf8');const p=spawnSync('powershell.exe',['-NoProfile','-File',file],{windowsHide:true,encoding:'utf8',timeout:30000});assert.equal(p.status,0,p.stderr);return p.stdout.trim();}
const literal=v=>"'"+v.replaceAll("'","''")+"'";
function run(msi,operation='/i',extra=[]){const log=path.join(dir,crypto.randomUUID()+'.log');const p=spawnSync('msiexec.exe',[operation,'"'+msi+'"','/qn','/norestart','CREATE_DESKTOP=0',...extra,'/L*v','"'+log+'"'],{windowsVerbatimArguments:true,windowsHide:true,timeout:90000});return p.status;}
function registered(){return JSON.parse(ps('$w=New-Object -ComObject WindowsInstaller.Installer\nConvertTo-Json -InputObject @($w.RelatedProducts('+literal(family)+') | ForEach-Object {[string]$_}) -Compress'));}
function packageFixture(version){const work=path.join(dir,version),stage=path.join(work,'stage');fs.mkdirSync(stage,{recursive:true});fs.writeFileSync(path.join(stage,'Lianpu.exe'),'inert launcher '+version);fs.writeFileSync(path.join(stage,version==='1.0.0'?'retired.txt':'added.txt'),version);const outfile=path.join(work,'fixture.msi');const metadata=buildMsi({stage,outfile,work,version,build:version,installFolder:name,productName:name,upgradeCode:family,uninstallCleanup:false});return{...metadata,outfile};}
try{
 const old=packageFixture('1.0.0'),broken=packageFixture('1.1.0'),next=packageFixture('1.2.0');
 ps('$w=New-Object -ComObject WindowsInstaller.Installer\n$d=$w.OpenDatabase('+literal(broken.outfile)+',1)\n'+
 "$v=$d.OpenView(\"INSERT INTO ``CustomAction`` (``Action``,``Type``,``Target``) VALUES ('InjectedFailure',19,'Isolated rollback verification')\");$v.Execute();$v.Close()\n"+
 "$v=$d.OpenView(\"INSERT INTO ``InstallExecuteSequence`` (``Action``,``Condition``,``Sequence``) VALUES ('InjectedFailure','NOT Installed',6502)\");$v.Execute();$v.Close();$d.Commit()\n");
 assert.equal(run(old.outfile,'/i',['INSTALLDIR="'+target+'"']),0);assert.deepEqual(registered(),[old.productCode]);report.checks.push('baseline installed in isolated directory');
 if(!process.argv.includes('--normal-path-only')) { assert.equal(run(broken.outfile),1603);assert.deepEqual(registered(),[old.productCode]);assert.equal(fs.readFileSync(path.join(target,'Lianpu.exe'),'utf8'),'inert launcher 1.0.0');assert.ok(fs.existsSync(path.join(target,'retired.txt')));assert.equal(fs.existsSync(path.join(target,'added.txt')),false);report.checks.push('failure after old-product removal rolled back both products and files'); }
 else report.rollback='not rerun: previous fault injection hit Windows registry access-denied during rollback; retained separately';
 assert.equal(run(next.outfile),0);assert.deepEqual(registered(),[next.productCode]);assert.equal(fs.readFileSync(path.join(target,'Lianpu.exe'),'utf8'),'inert launcher 1.2.0');assert.equal(fs.existsSync(path.join(target,'retired.txt')),false);assert.ok(fs.existsSync(path.join(target,'added.txt')));report.checks.push('upgrade replaced shared files, removed retired files, retained exactly one registration');
 assert.equal(run(old.outfile),1603);assert.deepEqual(registered(),[next.productCode]);report.checks.push('older installer refused downgrade');
 assert.equal(run(next.outfile),0);assert.deepEqual(registered(),[next.productCode]);report.checks.push('same installer did not create a duplicate product');
 assert.equal(run(next.productCode,'/x'),0);assert.deepEqual(registered(),[]);assert.equal(fs.existsSync(path.join(target,'Lianpu.exe')),false);assert.deepEqual(fs.readFileSync(data),before);report.checks.push('uninstall removed programs and preserved external data');report.status='passed';
}catch(error){report.status='failed';report.error=error.message;process.exitCode=1;}finally{fs.mkdirSync(path.join(root,'evidence'),{recursive:true});fs.writeFileSync(path.join(root,'evidence',process.argv.includes('--normal-path-only')?'upgrade-normal-path.json':'upgrade-transaction.json'),JSON.stringify(report,null,2));console.log(JSON.stringify(report));}
