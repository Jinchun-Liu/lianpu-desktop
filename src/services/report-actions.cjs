'use strict';
const fs=require('node:fs'),path=require('node:path');
function createReportActions({reports,getActor,dialog,nativeImage,getWindow}){
 const actor=()=>{try{return getActor();}catch{return {id:'guest',role:'guest'};}};
 function check(previous){const current=actor();if(current.id!==previous.id)throw Object.assign(new Error('当前成员已改变，请重新打开反馈。'),{code:'SESSION_CHANGED'});return current;}
 return async function action(name,p={}){const who=actor();
  if(name==='feedback.status')return reports.status(who);
  if(name==='feedback.settings')return reports.configure(p,who);
  if(name==='feedback.list')return reports.list(who);
  if(name==='feedback.detail')return reports.get(p.id,who).report;
  if(name==='feedback.image.read'){const r=reports.get(p.id,who),meta=r.report.attachments.find(a=>a.id===p.attachmentId);if(!meta)throw Error('REPORT_NOT_FOUND');const image=reports.read(path.join(reports.directory,meta.id+'.image'));if(image.reportId!==r.report.id||image.owner!==r.owner)throw Error('REPORT_IMAGE_OWNER');reports.attachments.set(meta.id,{owner:who.id,meta,bytes:Buffer.from(image.data,'base64')});return {dataUrl:'data:'+meta.mime+';base64,'+image.data};}
  if(name==='feedback.preview')return reports.preview(p,who);
  if(name==='feedback.draft')return reports.draft(p,who);
  if(name==='feedback.submit'){const out=await reports.submit(p,who);check(who);return out;}
  if(name==='feedback.refresh'){const out=await reports.refresh(p.id,who);check(who);return out;}
  if(name==='feedback.clientError'){reports.capture('renderer.'+reports.p.tag(p.feature,'event'),{code:reports.p.tag(p.code,'RENDERER_ERROR'),stack:typeof p.stack==='string'?p.stack.slice(0,4000):''},null,who,{source:'manual'});return {recorded:true};}
  if(name==='feedback.export'){const data=p.id?reports.get(p.id,who).report:{format:'lianpu-support',version:1,records:reports.list(who),steps:reports.logs.filter(x=>who.role==='owner'||x.owner===who.id).map(({owner,...r})=>r)};const choice=await dialog.showSaveDialog(getWindow(),{title:'导出脱敏反馈',defaultPath:'联铺反馈.json',filters:[{name:'诊断 JSON',extensions:['json']}]});check(who);if(choice.canceled)return {canceled:true};const full=path.resolve(choice.filePath),own=path.resolve(reports.directory);if(full===own||full.startsWith(own+path.sep)||path.extname(full).toLowerCase()!=='.json')throw Error('INVALID_DESTINATION');fs.writeFileSync(full,JSON.stringify(data,null,2));return {saved:true};}
  if(name==='feedback.clear'){for(const r of [...reports.records.values()])if(reports.allowed(r,who)&&r.state==='received'&&r.uploaded.length===r.report.attachments.length){for(const file of [r.report.id+'.report',...r.report.attachments.map(a=>a.id+'.image')])fs.rmSync(path.join(reports.directory,file),{force:true});reports.records.delete(r.report.id);}return reports.list(who);}
  if(name==='feedback.image.choose'){const choice=await dialog.showOpenDialog(getWindow(),{title:'选择截图（请先隐藏敏感内容）',properties:['openFile'],filters:[{name:'静态图片',extensions:['png','jpg','jpeg']}]});check(who);if(choice.canceled)return {canceled:true};if(fs.statSync(choice.filePaths[0]).size>5*1024*1024)throw Object.assign(new Error('所选图片超过 5 MiB，请先缩小。'),{code:'REPORT_IMAGE_LARGE'});let image=nativeImage.createFromBuffer(fs.readFileSync(choice.filePaths[0]));const size=image.getSize();if(image.isEmpty()||size.width*size.height>16000000)throw Error('REPORT_IMAGE_INVALID');if(Math.max(size.width,size.height)>1600)image=image.resize(size.width>=size.height?{width:1600}:{height:1600});return {dataUrl:'data:image/jpeg;base64,'+image.toJPEG(85).toString('base64')};}
  if(name==='feedback.image.store'){if(typeof p.dataUrl!=='string'||p.dataUrl.length>800000||!/^data:image\/(png|jpeg);base64,[A-Za-z0-9+/=]+$/.test(p.dataUrl))throw Error('REPORT_IMAGE_INVALID');const image=nativeImage.createFromDataURL(p.dataUrl),size=image.getSize();if(image.isEmpty()||size.width>1600||size.height>1600)throw Error('REPORT_IMAGE_INVALID');const bytes=image.toJPEG(80);return reports.addImage(bytes,'image/jpeg',who);}
  throw Object.assign(new Error('没有此反馈操作。'),{code:'INVALID_ACTION'});
 };
}
module.exports={createReportActions};
