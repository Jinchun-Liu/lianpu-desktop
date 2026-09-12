'use strict';
const fs=require('node:fs'),path=require('node:path'),crypto=require('node:crypto'),root=path.resolve(__dirname,'..');
const expected=JSON.parse(fs.readFileSync(path.join(root,'shared/licensing/version.json')));
const actual=crypto.createHash('sha256').update(fs.readFileSync(path.join(root,'shared/licensing/protocol.mjs'))).digest('hex');
if(expected.version!==1||actual!==expected.sha256)throw new Error('授权协议副本已变化，请同步两个仓库后更新版本记录。');
console.log('授权协议 v1 摘要一致。');

const support=JSON.parse(fs.readFileSync(path.join(root,'shared/reports/version.json')));if(support.version!==1||crypto.createHash('sha256').update(fs.readFileSync(path.join(root,'shared/reports/protocol.mjs'))).digest('hex')!==support.sha256)throw Error('反馈协议摘要不一致。');
