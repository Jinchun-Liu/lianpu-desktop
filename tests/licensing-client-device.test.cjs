'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),crypto=require('node:crypto'),fs=require('node:fs'),path=require('node:path');
const {TpmDevice}=require('../src/licensing/device.cjs');
// Hypothesis: the JS/native contract accepts the helper's exact TPM 2.0 shape
// and rejects software, test or altered helper output. Decision: prevent a
// permanent false hardware block or software fallback. Stop after each distinct
// type/policy/integrity boundary; this is structural validation, not TPM signing.
test('device validation accepts the native version string and rejects mismatched hardware policies',()=>{
  const pair=crypto.generateKeyPairSync('ec',{namedCurve:'prime256v1'}),der=pair.publicKey.export({format:'der',type:'spki'}),device=new TpmDevice();
  // Exact type observed in the compiled native helper and its source contract.
  const actual={tpm:{present:true,version:'2.0'}};
  const info={version:1,ok:true,state:'ready',testMode:false,tpm:actual.tpm,storage:{prepared:true},publicKeySpki:der.toString('base64url'),deviceId:crypto.createHash('sha256').update(der).digest('hex'),key:{provider:'Microsoft Platform Crypto Provider',machineKey:true,hardwareBacked:true,exportable:false,prepared:true,algorithm:'ECDSA_P256',implementationFlags:1}};
  device.info=structuredClone(info);assert.equal(device.validate(),true);
  for(const version of [2,'2','1.2','unknown',null]){device.info={...info,tpm:{present:true,version}};assert.equal(device.validate(),false,String(version));}
  for(const patch of [{version:undefined},{testMode:undefined},{testMode:true},{storage:{prepared:false}},{tpm:{present:false,version:'2.0'}},{key:{...info.key,prepared:false}},{key:{...info.key,implementationFlags:3}},{key:{...info.key,exportable:true}},{key:{...info.key,hardwareBacked:false}},{key:{...info.key,provider:'Microsoft Software Key Storage Provider'}},{deviceId:'0'.repeat(64)}]){device.info={...info,...patch};assert.equal(device.validate(),false);}
});
test('a helper hash mismatch is blocked before spawning any native command',()=>{
  const device=new TpmDevice({expectedSha256:'0'.repeat(64)});assert.throws(()=>device._available(),{code:'DEVICE_HELPER_INTEGRITY'});
});
