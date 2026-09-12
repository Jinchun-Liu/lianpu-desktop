'use strict';
const n=require('./normalize.cjs');const {randomUUID}=require('node:crypto');
const stop=()=>({status:'blocked',reason:'账号状态已改变，游标没有前进'});
function hasNext(value){if(value===true||value==='true')return true;if(value===false||value==='false'||value==null)return false;throw new Error('平台分页结束标记格式变化，未推进游标');}
function cursor(data,previous){if(!data?.hasMore)return null;const next=data.nextCursor;if(!['string','number'].includes(typeof next)||String(next)===String(previous)||String(next).trim()==='')throw new Error('平台分页游标未提供或没有前进');return next;}
class ReadCursorSync {
 constructor(){this.progress=new Map();}
 export(id){return structuredClone(this.progress.get(id)||{});}
 restore(id,value){if(value&&typeof value==='object')this.progress.set(id,structuredClone(value));}
 clear(id){this.progress.delete(id);}
 async run({id,identity,adapter,kind,valid}){
  const p=this.export(id);p.messages||={};p.conversations||={};const records=[],conversations=[];let omitted=0,boundary='';
  const ingestProducts=r=>{if(!Array.isArray(r.data?.cardList))throw new Error('官方商品列表结构变化');for(const card of r.data.cardList)try{records.push(n.product(card));}catch{omitted++;}};
  const ingestSessions=r=>{if(!Array.isArray(r.data?.sessions))throw new Error('官方会话结构变化');for(const raw of r.data.sessions)try{const c=n.conversation(raw,id,identity);p.conversations[c.externalId]=c;conversations.push(c);}catch{omitted++;}};
  const ingestMessages=(r,c)=>{if(!Array.isArray(r.data?.messages))throw new Error('官方消息结构变化');for(const raw of r.data.messages)try{records.push(n.message(raw,c,identity));}catch{omitted++;}};
  try{
   if(kind==='products'){
    const first=await adapter.request('products',{userId:identity,pageNumber:1,pageSize:20,needGroupInfo:true});if(first.status!=='ok')return first;ingestProducts(first);if(!valid())return stop();
    if(p.products){const current=p.products;const next=await adapter.request('products',{userId:identity,pageSize:20,needGroupInfo:false,...current});if(next.status!=='ok')return next;ingestProducts(next);if(hasNext(next.data.nextPage)){if(next.data.nextPageModel==null&&next.data.nextPageNum==null)return {status:'unavailable',reason:'商品分页缺少官网返回的续页信息，未推进游标'};p.products={pageNumber:(current.pageNumber||1)+1,nextPageModel:next.data.nextPageModel,nextPageNum:next.data.nextPageNum};}else p.products=null;
    }else if(hasNext(first.data.nextPage)){if(first.data.nextPageModel==null&&first.data.nextPageNum==null)return {status:'unavailable',reason:'商品分页缺少官网返回的续页信息，未推进游标'};p.products={pageNumber:2,nextPageModel:first.data.nextPageModel,nextPageNum:first.data.nextPageNum};}
   }else{
    const latest=await adapter.sessions(identity);if(latest.status!=='ok')return latest;ingestSessions(latest);if(!valid())return stop();
    if(p.sessions){const next=await adapter.sessions(identity,p.sessions);if(next.status!=='ok')return next;ingestSessions(next);p.sessions=cursor(next.data,p.sessions);}else p.sessions=cursor(latest.data);
    // Newest conversations have a reserved share of each run; a round-robin
    // history share prevents old pages being starved by a busy inbox.
    const all=Object.values(p.conversations),latestIds=new Set(conversations.slice(0,4).map(c=>c.externalId));const selected=conversations.slice(0,4);const offset=p.offset||0;for(let i=0;i<Math.min(4,all.length);i++){const c=all[(offset+i)%all.length];if(!latestIds.has(c.externalId))selected.push(c);}p.offset=all.length?(offset+4)%all.length:0;
    for(const conv of selected){if(!valid())return stop();if(kind==='messages'){
      const first=await adapter.messages(identity,conv.externalId);if(first.status!=='ok')return first;ingestMessages(first,conv);if(!valid())return stop();const saved=p.messages[conv.externalId];if(saved){const next=await adapter.messages(identity,conv.externalId,saved);if(next.status!=='ok')return next;ingestMessages(next,conv);p.messages[conv.externalId]=cursor(next.data,saved);}else p.messages[conv.externalId]=cursor(first.data);
    }else{
      const r=await adapter.request('trade',{sessionId:conv.externalId,sessionType:1,peerUserId:conv.buyerId});if(r.status!=='ok')return r;for(const externalId of n.orderIds(r.data)){if(!valid())return stop();const detail=await adapter.request('order',{tid:externalId});if(detail.status!=='ok')return detail;try{records.push(n.order(detail.data,externalId,identity,new Date().toISOString(),'xy-order-'+randomUUID()));}catch{omitted++;boundary='本人订单详情的卖家/买家身份、付款和退款状态、精确金额字段尚未核验';}}}
    }
    if(kind==='orders'&&!records.length)return {status:'unavailable',reason:boundary||'当前会话未提供可逐笔核验的订单；官网卖出订单入口当前要求在闲鱼 APP 查看'};
   }
  }catch(error){return {status:'unavailable',reason:error.message};}
  if(!valid())return stop();if(omitted&&!records.length&&kind==='products')return {status:'unavailable',reason:'商品字段未能核验，未推进游标'};
  this.progress.set(id,p);const hasMore=!!(p.products||p.sessions||Object.values(p.messages).some(Boolean));return {status:'ok',records:[...new Map(records.map(r=>[r.externalId,r])).values()],conversations:kind==='messages'?Object.values(p.conversations):undefined,hasMore,omitted,scope:'每轮优先读取最新页，并从加密保存的游标继续历史分页',reason:hasMore?'本轮读取完成，后续同步从已保存游标继续':omitted?'部分非文本或尚不能核验的记录已跳过':''};
 }
}
module.exports={ReadCursorSync,cursor};
