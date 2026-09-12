'use strict';
const {test}=require('node:test'),assert=require('node:assert/strict');
const {cloudPost}=require('../src/licensing/client.cjs');
// Decision: the desktop may use Chromium's system-aware transport without
// losing redirect, credential, response-size or one-attempt quota protections.
// Synthetic transport contract only; real client reachability is separate.
test('supplied desktop transport preserves POST boundaries and returns only confirmed data',async()=>{
 let calls=0;
 const result=await cloudPost('https://license.example','/v1/precheck',{v:1},async(url,options)=>{
  calls++;assert.equal(url,'https://license.example/v1/precheck');assert.equal(options.method,'POST');assert.equal(options.redirect,'error');assert.equal(options.credentials,'omit');assert.equal(options.body,'{"v":1}');assert.ok(options.signal instanceof AbortSignal);
  return Response.json({ok:true,data:{ticket:'synthetic'}});
 });assert.equal(calls,1);assert.deepEqual(result,{ticket:'synthetic'});
});
test('quota, transport loss and oversized responses stop without a second transport attempt',async()=>{
 for(const kind of ['quota','network','size']){
  let calls=0;const request=async()=>{calls++;if(kind==='network')throw Error('synthetic reset');if(kind==='size')return new Response('x'.repeat(262145));return Response.json({ok:false,error:{code:'SERVICE_QUOTA',retryable:false}},{status:503});};
  await assert.rejects(cloudPost('https://license.example','/v1/confirm',{v:1},request),{code:kind==='quota'?'SERVICE_QUOTA':kind==='network'?'LICENSE_NETWORK':'LICENSE_RESPONSE'});assert.equal(calls,1);
 }
});
