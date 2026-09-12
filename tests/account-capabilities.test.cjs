'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path'),vm=require('node:vm');
const context={window:{}};vm.runInNewContext(fs.readFileSync(path.join(__dirname,'../src/renderer/account-capabilities.js'),'utf8'),context);
const ctx={e:v=>String(v).replaceAll('&','&amp;').replaceAll('<','&lt;').replaceAll('"','&quot;'),btn:(label,action,attrs)=>`<button data-action="${action}" ${attrs}>${label}</button>`,badge:s=>`<b>${s}</b>`,table:(_h,rows)=>`<table>${rows}</table>`,when:s=>s,canSync:true};
// Hypothesis: users can distinguish an unchecked read from unavailable product
// features. Decision: ship actionable status UI; stop if a read implies sending.
test('unverified session has actionable reads, one send row and explicit implementation gaps',()=>{
 const html=context.window.LianpuAccountCapabilities.render(ctx,{id:'a',platformUserId:'p',loginStatus:'unverified',capabilities:{sendMessages:{},sendMessage:{}}});
 assert.equal((html.match(/data-action="account-read-one"/g)||[]).length,3);assert.equal((html.match(/回复与资料发送/g)||[]).length,1);assert.match(html,/当前版本未接入/);assert.match(html,/重复扫码不会/);assert.doesNotMatch(html,/尚未获得已验证权限/);
});
test('connection readiness never claims a real message was sent and platform reasons are escaped',()=>{
 const html=context.window.LianpuAccountCapabilities.render(ctx,{id:'a',platformUserId:'p',loginStatus:'authenticated',connectionStatus:'connected',capabilities:{readOrders:{status:'unavailable',reason:'<script>bad</script>'}}});
 assert.match(html,/不代表送达验证通过/);assert.match(html,/&lt;script>/);assert.doesNotMatch(html,/<script>/);
 const viewer=context.window.LianpuAccountCapabilities.render({...ctx,canSync:false},{id:'a',platformUserId:'p',loginStatus:'unverified'});assert.doesNotMatch(viewer,/account-read-one/);
});
