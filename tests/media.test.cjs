'use strict';
const { test } = require('node:test'), assert = require('node:assert/strict');
const { randomBytes } = require('node:crypto');
const { EncryptedStore } = require('../src/core/store.cjs');
const { MediaLibrary, detectImage } = require('../src/services/media.cjs');
const png = Buffer.from('iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMCAO+Xx6QAAAAASUVORK5CYII=', 'base64');
function setup(t) {
  const store = new EncryptedStore(':memory:', randomBytes(32)); t.after(() => store.close());
  store.put('members', { id:'owner',role:'owner',enabled:true });
  for(const id of ['a','b'])store.put('accounts',{id,accountId:id,space:'test'});
  return {store, media:new MediaLibrary(store), owner:{id:'owner'}};
}
// Hypothesis: materials are account scoped and dependent delivery images cannot disappear; this determines whether local reusable assets may be exposed.
test('media import deduplicates in one account, isolates accounts, protects referenced content', t => {
  const {store,media,owner}=setup(t);
  const first=media.add({name:'自己 图片.png',bytes:png,space:'test',accountId:'a'},owner);
  assert.equal(first.data, undefined); assert.equal(media.add({name:'重复.png',bytes:png,space:'test',accountId:'a'},owner).duplicate,true);
  const secondUrl=media.copyUrl(first.url,'a','b',owner); assert.notEqual(secondUrl,first.url);
  store.put('members',{id:'restricted',role:'operator',accountIds:['b'],enabled:true});
  assert.throws(()=>media.read(first.id,{id:'restricted'}),{code:'FORBIDDEN'});
  store.put('products',{id:'p',space:'test',accountId:'a',images:[first.url]}); assert.throws(()=>media.remove(first.id,owner),{code:'IN_USE'});
  assert.deepEqual(media.read(first.id,owner).bytes,png);
});
// Hypothesis: script formats and tampered archived images are refused before mutation; stop after one format and one integrity boundary.
test('media rejects executable formats and tampered backups', t => {
  const {store,media,owner}=setup(t); assert.throws(()=>detectImage(Buffer.from('<svg onload="alert(1)"></svg>')),{code:'IMAGE_FORMAT'});
  media.add({name:'a.png',bytes:png,space:'test',accountId:'a'},owner);
  const rows=store.list('_media'); rows[0].sha256='wrong'; assert.throws(()=>media.validateBackup(rows),{code:'BACKUP_MEDIA'});
});
