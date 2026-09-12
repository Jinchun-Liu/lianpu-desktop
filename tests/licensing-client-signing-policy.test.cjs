'use strict';
// LD02/LD03 are registered before this run; software fixtures and pure C# entry only.
const test=require('node:test'),assert=require('node:assert/strict'),crypto=require('node:crypto'),fs=require('node:fs'),path=require('node:path'),{spawnSync}=require('node:child_process');
const {TpmDevice,validateSigningInput,SIGNING_DOMAINS,safeHelperEnvironment}=require('../src/licensing/device.cjs');
const root=path.resolve(__dirname,'..'),directory=path.join(root,'work/security-signing-policy'),evidenceDirectory=path.resolve(root,'../evidence-security');
const sha=file=>crypto.createHash('sha256').update(fs.readFileSync(file)).digest('hex');

test('JS and pure native policy agree on documented signature purposes and reject unrelated inputs',async()=>{
  const p=await import('../shared/licensing/protocol.mjs'),reports=await import('../shared/reports/protocol.mjs');
  const pair=crypto.generateKeyPairSync('ec',{namedCurve:'prime256v1'}),publicKey=pair.publicKey.export({format:'der',type:'spki'}).toString('base64url'),nonce=crypto.randomUUID();
  const issuer=await crypto.webcrypto.subtle.generateKey('Ed25519',true,['sign','verify']);
  const ticket=await p.signEnvelope({v:1,type:'ticket',mode:'activate',requestId:crypto.randomUUID(),deviceId:await p.deviceIdFromSpki(publicKey),devicePublicKeySpki:publicKey,codeHash:'a'.repeat(64),plan:'week',issuedAt:1789185600000,expiresAt:1789185900000,nonce:crypto.randomBytes(32).toString('base64url')},'ticket','fixture',issuer.privateKey);
  const state={v:1,license:null,pending:null,clock:null},challenge=Buffer.from(JSON.stringify({purpose:'device-challenge',publicKey,nonce,exp:1789185900000})).toString('base64url')+'.'+crypto.randomBytes(32).toString('base64url');
  const framed=(purpose,value)=>Buffer.from(SIGNING_DOMAINS[purpose]+p.canonicalJson(value));
  const vectors=[];const add=(name,bytes,expected)=>vectors.push({name,base64:Buffer.from(bytes).toString('base64'),expected,nativeExpected:expected||'SIGNING_PURPOSE_INVALID'});
  add('preparation existing 32-byte nonce',Buffer.concat([Buffer.from(SIGNING_DOMAINS.preparation),crypto.randomBytes(32)]),'preparation');
  add('canonical local state',framed('state',state),'state');add('signed licensing ticket',p.ticketProofBytes(ticket),'ticket');
  add('legacy feedback session',reports.proofBytes('session',{publicKey,nonce}),'reportSession');
  add('fresh challenge feedback session',reports.proofBytes('session',{publicKey,nonce,challenge}),'reportSession');
  add('arbitrary signing input',Buffer.from('arbitrary challenge'),null);add('empty input',Buffer.alloc(0),null);add('oversize input',Buffer.alloc(16385),null);
  add('license issuer domain',Buffer.from('LIANPU-LICENSING/v1/license\0{}'),null);add('report submit domain',reports.proofBytes('submit',{}),null);
  add('short preparation',Buffer.from(SIGNING_DOMAINS.preparation+'short'),null);
  add('unknown local-state member',framed('state',{...state,reset:true}),null);
  add('local-state duplicate v',Buffer.from(SIGNING_DOMAINS.state+'{"clock":null,"license":null,"pending":null,"v":2,"v":1}'),null);
  add('deeply nested state',Buffer.from(SIGNING_DOMAINS.state+'{"clock":null,"license":null,"pending":'+'['.repeat(21)+'null'+']'.repeat(21)+',"v":1}'),null);
  add('noncanonical local state',Buffer.from(SIGNING_DOMAINS.state+JSON.stringify(state)),null);
  add('report unknown field',reports.proofBytes('session',{publicKey,nonce,extra:true}),null);
  add('report invalid challenge',reports.proofBytes('session',{publicKey,nonce,challenge:'unframed'}),null);
  add('report too long challenge',reports.proofBytes('session',{publicKey,nonce,challenge:'a'.repeat(4052)+'.'+'a'.repeat(43)}),null);
  add('report invalid key',reports.proofBytes('session',{publicKey:'wrong',nonce}),null);
  add('ticket invalid shape',framed('ticket',{...ticket,payload:{...ticket.payload,extra:true}}),null);
  for(const vector of vectors){const bytes=Buffer.from(vector.base64,'base64');if(vector.expected)assert.equal(validateSigningInput(bytes),vector.expected,vector.name);else assert.throws(()=>validateSigningInput(bytes),{code:'DEVICE_SIGNING_PURPOSE'},vector.name);}
  fs.mkdirSync(directory,{recursive:true});fs.mkdirSync(evidenceDirectory,{recursive:true});const vectorFile=path.join(directory,'vectors.json');fs.writeFileSync(vectorFile,JSON.stringify(vectors));
  const source=path.join(root,'src/licensing/native/LianpuTpm.cs'),harness=path.join(__dirname,'licensing-client-signing-policy.cs'),compiler=path.join(process.env.WINDIR||'C:\\Windows','Microsoft.NET/Framework64/v4.0.30319/csc.exe'),executable=path.join(directory,'SigningPolicyTests.exe');
  assert.equal(process.platform,'win32');assert.equal(fs.existsSync(compiler),true);
  const compile=spawnSync(compiler,['/nologo','/target:exe','/platform:x64','/optimize+','/warnaserror+','/utf8output','/reference:System.Web.Extensions.dll','/main:SigningPolicyTests','/out:'+executable,source,harness],{windowsHide:true,encoding:'utf8',timeout:30000});
  assert.ifError(compile.error);assert.equal(compile.status,0,compile.stdout+compile.stderr);
  const run=spawnSync(executable,[vectorFile],{windowsHide:true,encoding:'utf8',timeout:10000});assert.ifError(run.error);
  const result=JSON.parse(run.stdout.trim());fs.writeFileSync(path.join(evidenceDirectory,'license-device-signing-policy.json'),JSON.stringify({recordedAt:new Date().toISOString(),runtime:process.versions,hardwareInvoked:false,sourceSha256:sha(source),jsSha256:sha(path.join(root,'src/licensing/device.cjs')),harnessSha256:sha(harness),testSha256:sha(__filename),vectorSha256:sha(vectorFile),testExecutableSha256:sha(executable),result},null,2)+'\n');
  assert.equal(run.status,0,JSON.stringify(result));assert.equal(result.pureSigningPolicyOnly,true);assert.equal(result.hardwareInvoked,false);assert.equal(result.tests,vectors.length);
});

test('invalid commands fail before helper availability and native child environment drops code injection settings',async()=>{
  const device=new TpmDevice();device._available=()=>assert.fail('native process must not be reached');
  await assert.rejects(device.invoke('export-private'),{code:'DEVICE_COMMAND'});await assert.rejects(device.invoke('status',Buffer.from('unexpected')),{code:'DEVICE_COMMAND'});await assert.rejects(device.invoke('sign',Buffer.from('arbitrary')),{code:'DEVICE_SIGNING_PURPOSE'});
  assert.throws(()=>device.signSync(Buffer.from('arbitrary')),{code:'DEVICE_SIGNING_PURPOSE'});
  assert.deepEqual(safeHelperEnvironment({SystemRoot:'C:\\Windows',ProgramData:'C:\\ProgramData',PATH:'system',NODE_OPTIONS:'inject',ELECTRON_RUN_AS_NODE:'1',COR_ENABLE_PROFILING:'1',CORECLR_PROFILER:'x',DOTNET_STARTUP_HOOKS:'x',COMPLUS_Version:'v2'}),{SystemRoot:'C:\\Windows',ProgramData:'C:\\ProgramData',PATH:'system'});
});

test('async and sync signature results share strict device identity and signature validation',()=>{
  const pair=crypto.generateKeyPairSync('ec',{namedCurve:'prime256v1'}),raw=pair.publicKey.export({format:'der',type:'spki'}),bytes=Buffer.concat([Buffer.from(SIGNING_DOMAINS.preparation),crypto.randomBytes(32)]),device=new TpmDevice();
  const info={version:1,ok:true,state:'ready',testMode:false,tpm:{present:true,version:'2.0'},storage:{prepared:true},publicKeySpki:raw.toString('base64url'),deviceId:crypto.createHash('sha256').update(raw).digest('hex'),key:{provider:'Microsoft Platform Crypto Provider',machineKey:true,hardwareBacked:true,exportable:false,prepared:true,algorithm:'ECDSA_P256',implementationFlags:1}};device.info=info;
  const signed={...info,signatureFormat:'ieee-p1363',hashAlgorithm:'SHA-256',signature:crypto.sign('sha256',bytes,{key:pair.privateKey,dsaEncoding:'ieee-p1363'}).toString('base64url')};
  assert.equal(device._validatedSignature(signed,bytes).length,64);
  for(const patch of [{testMode:true},{deviceId:'a'.repeat(64)},{key:{...info.key,exportable:true}},{hashAlgorithm:'SHA-1'}])assert.throws(()=>device._validatedSignature({...signed,...patch},bytes),{code:'DEVICE_SIGN_FAILED'});
  assert.throws(()=>device._validatedSignature({...signed,signature:signed.signature+'='},bytes),{code:'DEVICE_SIGNATURE'});
});
