'use strict';
const VERSION='0.0.175';
const APIS=Object.freeze({identity:'mtop.taobao.idlemessage.pc.loginuser.get',profile:'mtop.idle.web.user.page.nav',products:'mtop.idle.web.xyh.item.list',sessions:'mtop.taobao.idlemessage.pc.session.sync',messages:'mtop.taobao.idlemessage.pc.message.sync',trade:'mtop.idle.trade.message.chat.tradeinfo',order:'mtop.idle.web.trade.order.detail'});
function cleanFailure(ret){const code=String(Array.isArray(ret)?ret[0]||'':ret||'').split('::')[0];if(/SESSION|TOKEN_EXOIRED|TOKEN_EXPIRED|LOGIN/.test(code))return {status:'login_required',reason:'平台登录已过期，请由本人重新扫码'};if(/RGV|VALIDATE|USER_VALIDATE|CAPTCHA|RISK/.test(code))return {status:'verification_required',reason:'平台要求人工验证，请在官方页面完成后重试'};if(/LIMIT|FREQUENT/.test(code))return {status:'rate_limited',reason:'平台限制请求频率，已停止本轮操作'};return {status:'unavailable',reason:'平台拒绝请求或网页接口不兼容，请查看官方页面'};}
// This function runs only inside the official HTTPS page. It uses that page's
// already-loaded first-party request/IM modules; no cookie or token leaves it.
async function officialPageOperation(input){
 if(location.origin!=='https://www.goofish.com')return {status:'unavailable',reason:'official_origin_required'};
 const scripts=[...document.scripts].map(s=>s.src);if(!scripts.some(s=>s.includes('/idle-pc/xy-site/'+input.version+'/')))return {status:'unavailable',reason:'official_page_version_changed'};
 let req;const chunks=window.webpackChunk_ice_lite_scaffold;if(!Array.isArray(chunks))return {status:'unavailable',reason:'official_runtime_missing'};
 chunks.push([['lianpu-observe-'+Date.now()+'-'+Math.random()],{},r=>{req=r;}]);
 if(!req)return {status:'unavailable',reason:'official_runtime_missing'};
 const bounded=(p,ms=15000)=>Promise.race([p,new Promise(resolve=>setTimeout(()=>resolve({status:'timeout'}),ms))]);
 if(input.operation==='request'){
  try {const api=req(84229)?.G;if(typeof api!=='function')return {status:'unavailable'};const response=await bounded(api({api:input.api,v:input.v||'1.0',data:input.data||{},valueType:'string',needLoginPC:false}));if(response?.status==='timeout')return response;return {ret:response?.ret,data:response?.data};}catch(e){return {ret:Array.isArray(e?.ret)?e.ret:['REQUEST_FAILED']};}
 }
 const manager=req(7844)?.h?.getInstance?.();if(!manager||typeof manager.getConnectionStatus!=='function')return {status:'unavailable'};
 const connected=manager.getConnectionStatus()===4;const userId=String(manager.getUserId?.()||'');
 if(!connected||userId!==input.identity)return {status:connected?'identity_mismatch':'disconnected'};
 if(input.operation==='connection')return {status:'connected',identity:userId,sendSupported:typeof req(20376)?.y2?.getMsgService?.()?.sendMessage==='function'};
 if(input.operation==='sessions'){
  try{const sdk=req(20376)?.y2?.getConvService?.();if(typeof sdk?.listConversationsPagination!=='function')return {status:'unavailable'};const result=await bounded(sdk.listConversationsPagination(input.cursor??Number.MAX_SAFE_INTEGER,30));if(!Array.isArray(result?.userConvs))return {status:'unavailable'};const sessions=result.userConvs.flatMap(v=>{const raw=v.singleChatUserConversation,chat=raw?.singleChatConversation;if(!chat?.cid||!chat.pairFirst||!chat.pairSecond)return [];const strip=value=>String(value).split('@')[0];return [{sessionId:req(33891).d.convertIdToUI(String(chat.cid)),ownerInfo:{userId:strip(chat.pairFirst)},userInfo:{userId:strip(chat.pairSecond)},unread:raw.redPoint||0}];});return {status:'ok',data:{sessions,nextCursor:result.nextCursor,hasMore:result.hasMore===true||result.hasMore==='true'}};}catch{return {status:'unavailable'};}
 }
 if(input.operation==='messages'){
  try{const sdk=req(20376)?.y2?.getMsgService?.();if(typeof sdk?.listPrevMsgs!=='function')return {status:'unavailable'};const result=await bounded(sdk.listPrevMsgs(req(33891).d.convertIdToPaas(input.sessionId),input.cursor??Number.MAX_SAFE_INTEGER,30));if(!Array.isArray(result?.userMessageModels))return {status:'unavailable'};const messages=result.userMessageModels.map(m=>req(5738).vk.imUserMessageModelToUI(m)).map(m=>({messageId:m.messageId,senderInfo:{userId:m.senderInfo?.userId},content:{text:{text:m.content?.text?.text}},timeStamp:m.timeStamp}));return {status:'ok',data:{messages,nextCursor:result.nextCursor,hasMore:result.hasMore===true||result.hasMore==='true'}};}catch{return {status:'unavailable'};}
 }
 if(input.operation==='recipient'){
  let found;try{found=await bounded(req(20376).y2.getConvService().getConversation(req(33891).d.convertIdToPaas(input.sessionId)));}catch{return {status:'blocked',reason:'recipient_not_verified'};}const chat=found?.singleChatUserConversation?.singleChatConversation;const people=[chat?.pairFirst,chat?.pairSecond].map(v=>String(v||'').split('@')[0]);if(!chat||!people.includes(input.buyerId)||!people.includes(input.identity)||req(33891).d.convertIdToUI(String(chat.cid))!==input.sessionId)return {status:'blocked',reason:'recipient_not_verified'};
  return {status:'ok',identity:input.identity,buyerId:input.buyerId,sessionId:input.sessionId,verifiedAt:Date.now()};
 }
 if(input.operation==='send'){
  const proof=input.recipient;if(proof?.status!=='ok'||proof.identity!==input.identity||proof.buyerId!==input.buyerId||proof.sessionId!==input.sessionId||Date.now()-proof.verifiedAt>30000)return {status:'blocked',reason:'recipient_proof_expired'};
  const sdk=req(20376)?.y2?.getMsgService?.(),convert=req(5738)?.vk,contentType=req(33554)?.Nr;
  if(!sdk||typeof sdk.sendMessage!=='function'||typeof convert?.uiConvertToIMPaasSendMessageModel!=='function'||contentType==null)return {status:'blocked',reason:'sender_incompatible'};
  const message=convert.uiConvertToIMPaasSendMessageModel({uuid:input.key,sessionId:input.sessionId,content:{contentType,text:{text:input.text}},redPointPolicy:1,extJson:'{}'});
  try{const reply=await bounded(sdk.sendMessage(message),20000);const m=reply?.message||reply?.data?.message;if(m?.messageId&&String(m.uuid)===input.key&&String(m.cid)===String(message.cid))return {status:'accepted',receiptId:String(m.messageId),uuid:String(m.uuid),cid:String(m.cid),createdAt:m.createAt};return {status:'unknown'};}catch{return {status:'unknown'};}
 }
 return {status:'unavailable'};
}
class OfficialPageAdapter {
 constructor(window){this.window=window;}
 async run(operation,args={}){const web=this.window?.webContents;if(!web?.executeJavaScript||this.window.isDestroyed())return {status:'unavailable',reason:'官方页面连接已关闭'};try{return await web.executeJavaScript('('+officialPageOperation.toString()+')('+JSON.stringify({version:VERSION,operation,...args})+')',false);}catch{return {status:operation==='send'?'unknown':'unavailable',reason:'官方页面连接中断'};}}
 async request(kind,data={},v){const response=await this.run('request',{api:APIS[kind],data,v});if(Array.isArray(response?.ret)&&response.ret.some(s=>String(s).startsWith('SUCCESS::')))return {status:'ok',data:response.data};if(response?.status==='unavailable'){const reasons={official_page_version_changed:'闲鱼网页已更新，当前联铺版本暂不兼容，请检查软件更新；重复扫码无法解决。',official_runtime_missing:'闲鱼页面仍在准备，稍后点击检查重试。',official_origin_required:'请在闲鱼官方窗口完成本人登录后重试。'};return {status:'unavailable',reason:reasons[response.reason]||'闲鱼页面连接暂不可用，请检查网络后重试。'};}return response?.status==='timeout'?{status:'timeout',reason:'官方页面请求超时，请稍后重试。'}:cleanFailure(response?.ret);}
 connection(identity){return this.run('connection',{identity});}
 sessions(identity,cursor){return this.run('sessions',{identity,cursor});}
 messages(identity,sessionId,cursor){return this.run('messages',{identity,sessionId,cursor});}
 prepareRecipient(args){return this.run('recipient',args);}
 send(args){return this.run('send',args);}
}
module.exports={OfficialPageAdapter,APIS,VERSION,cleanFailure,officialPageOperation};
