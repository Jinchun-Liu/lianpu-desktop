'use strict';
const test=require('node:test');
const assert=require('node:assert/strict');
const {randomBytes}=require('node:crypto');
const {EncryptedStore}=require('../src/core/store.cjs');
const {Service}=require('../src/core/service.cjs');
const owner={id:'owner',role:'owner',accountIds:[]};
async function setup(t){const store=new EncryptedStore(':memory:',randomBytes(32));const service=new Service(store);t.after(()=>store.close());const run=(action,payload,actor=owner)=>service.run(action,payload,actor);await run('entity.save',{kind:'accounts',record:{id:'account',space:'test',name:'试运行账号'}});await run('entity.save',{kind:'assets',record:{id:'unique',space:'test',accountId:'account',name:'唯一资料',type:'unique'}});return {store,service,run};}
test('F16/F43 库存CSV保持整条多行内容、预览不写、正常导出回读',async t=>{
  t.diagnostic('假设：CSV引号内换行属于同一库存；决策价值：允许多行兑换内容入库；停止条件：一次导入导出往返且条目数量准确。');
  const h=await setup(t);const csv='assetId,content,costCents,expiresAt,space,accountId\r\nunique,"第一行\n第二行,""引号""",125,,test,account\r\nunique,000123,50,,test,account';const preview=await h.run('data.previewImport',{kind:'inventory',space:'test',csv,duplicates:'skip'});assert.equal(preview.canImport,true);assert.equal(preview.valid,2);assert.equal(h.store.list('inventory').length,0);assert.equal(preview.rows[0].record.content,'第一行\n第二行,"引号"');const result=await h.run('data.import',{previewId:preview.id});assert.equal(result.imported,2);assert.equal(h.store.list('inventory')[1].content,'000123');
  const exported=await h.run('data.export',{kind:'inventory',space:'test'});const again=await h.run('data.previewImport',{kind:'inventory',space:'test',csv:exported.csv,duplicates:'skip'});assert.equal(again.canImport,true);assert.equal(again.duplicates.length,2);assert.equal((await h.run('data.import',{previewId:again.id})).skipped,2);assert.equal(h.store.list('inventory').length,2);
});
test('F16/F43 重复策略、无效行与占用状态不能绕过',async t=>{
  t.diagnostic('假设：重复与错误均先显示，已占用内容不能更新；决策价值：防止CSV重新出售已分配内容；停止条件：重复更新、占用拒绝、错误整批回滚各一次。');
  const h=await setup(t);await h.run('inventory.import',{assetId:'unique',entries:[{content:'code-a',costCents:20}]});const entry=h.store.list('inventory')[0];let preview=await h.run('data.previewImport',{kind:'inventory',space:'test',assetId:'unique',csv:'content,costCents\ncode-a,30',duplicates:'update'});assert.equal(preview.duplicates.length,1);await h.run('data.import',{previewId:preview.id});assert.equal(h.store.get('inventory',entry.id).costCents,30);
  h.store.put('inventory',{...h.store.get('inventory',entry.id),status:'reserved',orderId:'pending-order',deliveryId:'pending-delivery'});preview=await h.run('data.previewImport',{kind:'inventory',space:'test',assetId:'unique',csv:'content,costCents\ncode-b,50\ncode-a,40',duplicates:'update'});assert.equal(preview.canImport,false);assert.match(preview.errors[0].message,/已预留/);await assert.rejects(h.run('data.import',{previewId:preview.id}),{code:'IMPORT_ERRORS'});assert.equal(h.store.list('inventory').length,1);assert.equal(h.store.get('inventory',entry.id).status,'reserved');
  preview=await h.run('data.previewImport',{kind:'inventory',space:'test',assetId:'unique',csv:'content,costCents\ncode-c,1.50\ncode-d,90',duplicates:'skip'});assert.equal(preview.errors.length,1);assert.equal(h.store.list('inventory').length,1);
});
test('F43/F56 CSV预览后库存竞争及跨空间/权限被阻断',async t=>{
  t.diagnostic('假设：预览后的新增重复和撤权不能在应用时绕过；决策价值：决定事务导入与协作可用；停止条件：竞争/跨空间/权限各验证一次。');
  const h=await setup(t);const preview=await h.run('data.previewImport',{kind:'inventory',space:'test',assetId:'unique',csv:'content,costCents\nnew-first,10\nracing,10',duplicates:'skip'});await h.run('inventory.import',{assetId:'unique',entries:[{content:'racing'}]});await assert.rejects(h.run('data.import',{previewId:preview.id}),{code:'STALE_PREVIEW'});assert.equal(h.store.list('inventory').length,1);assert.equal(h.store.list('inventory')[0].content,'racing');
  const wrong=await h.run('data.previewImport',{kind:'inventory',space:'test',assetId:'unique',csv:'content,space\ncross-space,live'});assert.equal(wrong.canImport,false);
  h.store.put('members',{id:'owner',role:'owner',enabled:true,accountIds:[]});h.store.put('members',{id:'operator',role:'operator',enabled:true,accountIds:['account']});const actor={id:'operator',role:'operator',accountIds:['account']};const scoped=await h.run('data.previewImport',{kind:'inventory',space:'test',assetId:'unique',csv:'content\nnot-after-revoke'},actor);h.store.put('members',{...h.store.get('members','operator'),accountIds:[]});await assert.rejects(h.run('data.import',{previewId:scoped.id},actor),{code:'FORBIDDEN'});assert.equal(h.store.list('inventory').length,1);
});
