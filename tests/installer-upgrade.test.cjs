'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),os=require('node:os'),path=require('node:path');
const {database,UPGRADE_CODE}=require('../scripts/release-msi.cjs');
test('major upgrades keep the old product until new installation executes and preserve component identities',t=>{
 t.diagnostic('Hypothesis: a failed new payload cannot begin removing the prior product. Decision: enforce transactional upgrade placement and stable resource identities. Stop on any ordering or identity mismatch.');
 const dir=fs.mkdtempSync(path.join(os.tmpdir(),'lianpu-msi-contract-'));t.after(()=>fs.rmSync(dir,{recursive:true,force:true}));
 fs.writeFileSync(path.join(dir,'Lianpu.exe'),'isolated inert fixture');fs.writeFileSync(path.join(dir,'resources.dat'),'old');
 const old=database({stage:dir,version:'0.5.1',build:'old',outfile:'old.msi'});fs.writeFileSync(path.join(dir,'added.txt'),'new file shifts table indices');
 const next=database({stage:dir,version:'0.5.2',build:'new',outfile:'new.msi'});const table=(c,n)=>c.definitions.find(x=>x[0]===n)[3];
 const seq=Object.fromEntries(table(next,'InstallExecuteSequence').map(x=>[x[0],x[2]]));
 assert.ok(seq.InstallFiles<seq.InstallExecute);assert.ok(seq.InstallExecute<seq.RemoveExistingProducts);assert.ok(seq.RemoveExistingProducts<seq.InstallFinalize);
 for(const file of old.payload){const current=next.payload.find(x=>x.rel===file.rel);assert.equal(table(old,'Component').find(x=>x[0]===file.component)[1],table(next,'Component').find(x=>x[0]===current.component)[1]);}
 assert.equal(next.upgradeCode,UPGRADE_CODE);assert.notEqual(next.productCode,old.productCode);
 const upgrades=table(next,'Upgrade');assert.equal(upgrades[0][5],null);assert.equal(upgrades[0][4]&512,512);assert.equal(upgrades[1][4]&2,2);
 assert.ok(table(next,'LaunchCondition').some(x=>x[0]==='NOT NEWERPRODUCTS'));
 assert.ok(table(next,'File').every(x=>(x[6]&512)!==0),'required payload cannot be ignored');
 assert.equal(Object.fromEntries(table(next,'Property')).REINSTALLMODE,'amus','same-version replacement must not mix executable and ASAR');
 assert.deepEqual(table(next,'RemoveFile').map(x=>[x[2],x[3]]),[[null,'AppMenu']]);
 assert.ok(!JSON.stringify(next.definitions).includes('Licensing\\\\v1'));
 assert.ok(!table(next,'Directory').some(x=>/Partitions|TPM|ProgramData/.test(x.join(' '))));
});
