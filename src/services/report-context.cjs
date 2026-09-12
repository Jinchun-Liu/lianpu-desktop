'use strict';
// Resolve only existing, member-authorized records. Return state, never content/IDs.
function reportContext(service,action,input,actor){
 const out={};if(!service||!input||typeof input!=='object')return out;
 try{
  let record,order,accountId=input.accountId;
  const prefix=action.split('.')[0],kinds={account:'accounts',order:'orders',delivery:'deliveries',conversation:'conversations',product:'products'};
  const kind=kinds[prefix],id=input.orderId||input.id;
  if(input.orderId){order=service._record('orders',input.orderId,actor);record=order;}
  else if(kind&&typeof id==='string'){record=service._record(kind,id,actor);if(kind==='orders')order=record;}
  if(record){accountId=record.accountId||(kind==='accounts'?record.id:accountId);out.space=record.space;}
  if(accountId){const a=service._record('accounts',accountId,actor);out.login=a.loginStatus;out.connection=a.connectionStatus;out.hosting=a.hosting?.enabled===true;out.space=a.space;}
  if(order){const rule=service.store.list('rules').find(r=>r.accountId===order.accountId&&r.productId===order.productId&&(r.variantId||'')===(order.variantId||'')&&r.enabled);out.bound=!!rule?.assetId;if(rule?.assetId){const asset=service._record('assets',rule.assetId,actor);if(asset.type==='unique'){const available=service.store.list('inventory').filter(i=>i.accountId===order.accountId&&i.assetId===asset.id&&i.status==='available'&&(!i.expiresAt||Date.parse(i.expiresAt)>Date.now())).length;out.stockAvailable=available>=(order.quantity||1)*(rule.quantity||1);}else if(asset.type==='fixed')out.stockAvailable=true;}}
 }catch{/* Stale permission, missing records or a closed store add no context. */}
 return out;
}
module.exports={reportContext};
