'use strict';
class AccountQueue {
  constructor({capacity=40}={}) { this.capacity=capacity;this.items=[];this.active=null;this.generation=0;this.closed=false;this.waiters=[]; }
  run(fn,{authorize=()=>true,submitted=false}={}) {
    if(this.closed)return Promise.resolve({status:'blocked',reason:'账号任务已暂停',receiptId:null});
    if(this.items.length+(this.active?1:0)>=this.capacity)return Promise.resolve({status:'rate_limited',reason:'此账号任务队列已满，请稍后重试',receiptId:null});
    return new Promise(resolve=>{this.items.push({fn,authorize,resolve,generation:this.generation,submitted});void this._next();});
  }
  async _next(){if(this.active)return;const item=this.items.shift();if(!item){for(const done of this.waiters.splice(0))done();return;}this.active=item;let result;
    try{if(this.closed||item.generation!==this.generation||!(await item.authorize()))result={status:'blocked',reason:'任务执行前授权或账号状态已改变',receiptId:null};else if(this.closed||item.generation!==this.generation)result={status:'blocked',reason:'授权等待期间账号已暂停',receiptId:null};else result=await item.fn({valid:()=>!this.closed&&item.generation===this.generation,authorize:item.authorize,markSubmitted:()=>{item.submitted=true;}});}catch{result={status:item.submitted?'unknown':'failed',reason:item.submitted?'提交后未能取得确定回执，请核验后再发送':'任务未完成，请检查账号连接',receiptId:null};}
    item.resolve(result);this.active=null;void this._next();
  }
  pause(){this.closed=true;this.generation++;for(const item of this.items.splice(0))item.resolve({status:'blocked',reason:'任务已取消，未提交到平台',receiptId:null});if(!this.active)for(const done of this.waiters.splice(0))done();}
  resume(){this.closed=false;}
  drain(){return this.active||this.items.length?new Promise(resolve=>this.waiters.push(resolve)):Promise.resolve();}
  status(){return {pending:this.items.length,inFlight:this.active?1:0,capacity:this.capacity,paused:this.closed};}
}
module.exports={AccountQueue};
