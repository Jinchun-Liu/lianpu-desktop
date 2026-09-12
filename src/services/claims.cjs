'use strict';

const http = require('node:http');
const path = require('node:path');
const { randomBytes, randomUUID, createHash, timingSafeEqual } = require('node:crypto');

const MAX_FILE_BYTES = 20 * 1024 * 1024;
const COLLECTIONS = Object.freeze({ files: '_claimFiles', grants: '_claimGrants', access: '_claimAccess' });
const TOKEN_PATTERN = /^[A-Za-z0-9_-]{43}$/;
const ACCESS_EVENTS = new Set(['page_opened', 'access_started', 'response_finished', 'response_interrupted']);
const FILE_FIELDS = new Set(['id','space','accountId','name','size','sha256','mime','data','rights','createdAt']);
const GRANT_FIELDS = new Set(['id','space','accountId','orderId','buyerId','fileId','tokenHash','maxClaims','claimsStarted','expiresAt','status','createdBy','createdAt','updatedAt','revokedBy','revokeReason','revokedAt']);
const EVENT_FIELDS = new Set(['id','grantId','orderId','space','accountId','event','at','declaredBytes','fileSha256','attemptId','evidence']);
const SHA = bytes => createHash('sha256').update(bytes).digest('hex');
const escapeHtml = value => String(value).replace(/[&<>"']/g, c => ({ '&':'&amp;', '<':'&lt;', '>':'&gt;', '"':'&quot;', "'":'&#39;' })[c]);

class ClaimError extends Error {
  constructor(code, message) { super(message); this.code = code; }
}
function reject(code, message) { throw new ClaimError(code, message); }
function requireDate(value, name) {
  if (typeof value !== 'string' || !Number.isFinite(Date.parse(value))) reject('CLAIM_INPUT', `${name}需要有效日期。`);
}
function publicFile(file) { const { data, rights, ...summary } = file; return { ...summary, rightsConfirmed: !!rights }; }
function publicGrant(grant) { const { tokenHash, ...summary } = grant; return { ...summary, remainingClaims: Math.max(0, grant.maxClaims - grant.claimsStarted), public: false, scope: 'loopback' }; }

/** A loopback-only verification engine. It does not create a public hosting service. */
class ClaimsEngine {
  constructor(store, { clock = () => Date.now() } = {}) {
    this.store = store;
    this.clock = clock;
    this.server = null;
    this.origin = null;
    this.generation = 0;
    this.starting = null;
    this.stopping = null;
    this.sessions = new Map();
  }
  _now() { return new Date(this.clock()).toISOString(); }
  _member(actor) {
    const member = this.store.get('members', actor?.id || '');
    if (!member || member.enabled === false || !['owner','operator'].includes(member.role)) reject('FORBIDDEN', '领取文件需要管理员或经营成员权限。');
    return member;
  }
  _authorize(actor, space, accountId) {
    const member = this._member(actor);
    if (!['live','test'].includes(space)) reject('CLAIM_INPUT', '请选择文件所属工作区。');
    const account = this.store.get('accounts', accountId || '');
    if (!account || account.space !== space || (member.role !== 'owner' && !member.accountIds?.includes(accountId))) reject('FORBIDDEN', '没有此账号的领取文件权限。');
    return member;
  }
  _getGrant(grantId, actor) {
    const grant = this.store.get(COLLECTIONS.grants, grantId || '');
    if (!grant) reject('CLAIM_NOT_FOUND', '领取授权不存在。');
    this._authorize(actor, grant.space, grant.accountId);
    return grant;
  }
  listFiles({ space, accountId } = {}, actor) {
    const member = this._member(actor);
    if (!['live','test'].includes(space)) reject('CLAIM_INPUT', '请选择文件所属工作区。');
    if (accountId) this._authorize(actor, space, accountId);
    return this.store.list(COLLECTIONS.files).filter(file => file.space === space && (!accountId || file.accountId === accountId) && (member.role === 'owner' || member.accountIds?.includes(file.accountId))).map(publicFile);
  }
  addFile({ bytes, name, space, accountId, rightsConfirmed } = {}, actor) {
    const member = this._authorize(actor, space, accountId);
    if (rightsConfirmed !== true) reject('FILE_RIGHTS', '请确认你有权托管和交付此文件。');
    if (!Buffer.isBuffer(bytes) || bytes.length === 0 || bytes.length > MAX_FILE_BYTES) reject('FILE_SIZE', '每个领取文件须为非空文件，且不超过 20 MB。');
    if (typeof name !== 'string' || !name.trim() || name.length > 300 || /[\x00-\x1f\x7f]/.test(name)) reject('FILE_NAME', '文件名称无效。');
    const safeName = path.win32.basename(name.replaceAll('/', '\\')).slice(0, 180);
    if (!safeName || safeName === '.' || safeName === '..') reject('FILE_NAME', '请提供具体文件名称。');
    const sha256 = SHA(bytes);
    const duplicate = this.store.list(COLLECTIONS.files).find(file => file.space === space && file.accountId === accountId && file.sha256 === sha256);
    if (duplicate) return { ...publicFile(duplicate), duplicate: true };
    const file = { id: randomUUID(), space, accountId, name: safeName, size: bytes.length, sha256, mime: 'application/octet-stream', data: bytes.toString('base64'), rights: { actorId: member.id, confirmedAt: this._now() }, createdAt: this._now() };
    this.store.put(COLLECTIONS.files, file);
    return publicFile(file);
  }
  createGrant({ orderId, fileId, maxClaims = 1, expiresAt } = {}, actor) {
    const order = this.store.get('orders', orderId || '');
    if (!order) reject('CLAIM_ORDER', '请选择已有订单。');
    const member = this._authorize(actor, order.space, order.accountId);
    if (order.space !== 'test') reject('PUBLIC_HOSTING_UNAVAILABLE', '当前引擎仅提供试运行订单的本机领取预览；公网托管、TLS 和域名尚未完成，不能交给真实买家。');
    const file = this.store.get(COLLECTIONS.files, fileId || '');
    if (!file || file.space !== order.space || file.accountId !== order.accountId) reject('CLAIM_FILE_SCOPE', '文件和订单必须属于同一账号及工作区。');
    this._checkOrder(order);
    if (!Number.isSafeInteger(maxClaims) || maxClaims < 1 || maxClaims > 1000) reject('CLAIM_INPUT', '领取次数须为 1 至 1000 的整数。');
    requireDate(expiresAt, '领取截止时间');
    if (Date.parse(expiresAt) <= this.clock()) reject('CLAIM_EXPIRED', '领取截止时间须晚于当前时间。');
    const token = randomBytes(32).toString('base64url');
    const grant = { id: randomUUID(), space: 'test', accountId: order.accountId, orderId: order.id, buyerId: order.buyerId, fileId: file.id, tokenHash: SHA(token), maxClaims, claimsStarted: 0, expiresAt, status: 'active', createdBy: member.id, createdAt: this._now(), updatedAt: this._now() };
    this.store.put(COLLECTIONS.grants, grant);
    return { ...publicGrant(grant), token, tokenShownOnce: true, notice: '此令牌只在本次创建时提供。仅可打开本机试运行页面，不是公网领取链接。' };
  }
  listGrants({ space, accountId } = {}, actor) {
    const member = this._member(actor);
    if (!['live','test'].includes(space)) reject('CLAIM_INPUT', '请选择领取授权所属工作区。');
    if (accountId) this._authorize(actor, space, accountId);
    return this.store.list(COLLECTIONS.grants).filter(grant => grant.space === space && (!accountId || grant.accountId === accountId) && (member.role === 'owner' || member.accountIds?.includes(grant.accountId))).map(publicGrant);
  }
  revoke({ id, reason } = {}, actor) {
    const grant = this._getGrant(id, actor);
    if (typeof reason !== 'string' || !reason.trim() || reason.length > 1000) reject('CLAIM_INPUT', '请填写撤回理由。');
    const result = { ...grant, status:'revoked', revokedBy:actor.id, revokeReason:reason, revokedAt:this._now(), updatedAt:this._now() };
    this.store.put(COLLECTIONS.grants, result);this.sessions.delete(grant.id);
    return publicGrant(result);
  }
  accessLog({ grantId } = {}, actor) {
    this._getGrant(grantId, actor);
    return this.store.list(COLLECTIONS.access).filter(event => event.grantId === grantId);
  }
  _checkOrder(order) {
    if (!order.buyerId || order.paymentStatus !== 'paid' || ['refunding','refunded','closed','cancelled'].includes(order.tradeStatus) || order.refundCents > 0) reject('CLAIM_ORDER', '订单未付款、退款中或已关闭，领取已停止。');
  }
  _active(grant, actorId) {
    if (grant.space !== 'test') reject('PUBLIC_HOSTING_UNAVAILABLE', '真实订单不能使用本机试运行领取服务。');
    this._authorize({id:actorId}, grant.space, grant.accountId);
    this._authorize({id:grant.createdBy}, grant.space, grant.accountId);
    if (grant.status !== 'active') reject('CLAIM_REVOKED', '此领取授权已撤回。');
    if (!Number.isFinite(Date.parse(grant.expiresAt)) || Date.parse(grant.expiresAt) <= this.clock()) reject('CLAIM_EXPIRED', '此领取授权已到期或时间无效。');
    const order = this.store.get('orders', grant.orderId);
    if (!order || order.space !== grant.space || order.accountId !== grant.accountId || order.buyerId !== grant.buyerId) reject('CLAIM_ORDER', '订单身份发生变化，领取已停止。');
    this._checkOrder(order);
    const account = this.store.get('accounts', grant.accountId);
    if (account.paused) reject('CLAIM_PAUSED', '所属账号已暂停，领取已停止。');
  }
  _matchToken(token) {
    if (typeof token !== 'string' || !TOKEN_PATTERN.test(token)) reject('CLAIM_NOT_FOUND', '领取入口不存在。');
    const digest = Buffer.from(SHA(token), 'hex');
    const grant = this.store.list(COLLECTIONS.grants).find(record => typeof record.tokenHash === 'string' && /^[a-f0-9]{64}$/.test(record.tokenHash) && timingSafeEqual(Buffer.from(record.tokenHash, 'hex'), digest));
    if (!grant) reject('CLAIM_NOT_FOUND', '领取入口不存在。');
    return grant;
  }
  _event(grant, event, fields = {}) {
    const record = { id:randomUUID(), grantId:grant.id, orderId:grant.orderId, space:grant.space, accountId:grant.accountId, event, at:this._now(), ...fields };
    this.store.put(COLLECTIONS.access, record);return record;
  }
  async startLocalPreview({ grantId, token } = {}, actor) {
    const grant = this._getGrant(grantId, actor);
    if (this._matchToken(token).id !== grant.id) reject('CLAIM_NOT_FOUND', '令牌不属于此领取授权。');
    this._active(grant, actor.id);
    if (this.stopping) await this.stopping;
    const generation = this.generation;
    if (!this.server && !this.starting) {
      this.starting = new Promise((resolve, rejectStart) => {
        const server = http.createServer((req,res) => this._handle(req,res));
        server.requestTimeout = 5000;server.headersTimeout = 5000;server.keepAliveTimeout = 1000;server.maxConnections = 20;
        server.on('clientError', (_error, socket) => socket.end('HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n'));
        server.once('error', rejectStart);
        server.listen(0, '127.0.0.1', () => { this.server=server;this.origin=`http://127.0.0.1:${server.address().port}`;resolve(); });
      }).finally(() => { this.starting=null; });
    }
    if (this.starting) await this.starting;
    if (generation !== this.generation || !this.server) reject('LOCKED', '本机领取预览已停止。');
    this._active(this._getGrant(grantId,actor), actor.id);
    this.sessions.set(grantId, { actorId:actor.id, generation });
    return { url:`${this.origin}/claim/${token}`, public:false, scope:'loopback', address:'127.0.0.1', port:this.server.address().port, grant:publicGrant(grant), notice:'仅当前电脑可访问；页面打开或响应结束不代表买家完成下载。' };
  }
  _headers(res) {
    // Chromium sends Origin:null for form POST under no-referrer. Preserve the
    // origin needed by the strict POST guard, without disclosing the token path.
    res.setHeader('Cache-Control','no-store');res.setHeader('Referrer-Policy','strict-origin');res.setHeader('X-Content-Type-Options','nosniff');res.setHeader('X-Frame-Options','DENY');res.setHeader('Connection','close');
    res.setHeader('Content-Security-Policy',"default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'");
  }
  _handle(req,res) {
    this._headers(res);
    try {
      if (!this.server || !this.origin || req.headers.host !== this.origin.slice('http://'.length) || !['127.0.0.1','::ffff:127.0.0.1'].includes(req.socket.remoteAddress)) reject('CLAIM_ORIGIN','此服务仅允许当前电脑的本机预览。');
      const url = new URL(req.url,this.origin);
      if (url.origin !== this.origin || url.search) reject('CLAIM_NOT_FOUND','领取入口不存在。');
      const match = /^\/claim\/([A-Za-z0-9_-]{43})(\/download)?$/.exec(url.pathname);
      if (!match) reject('CLAIM_NOT_FOUND','领取入口不存在。');
      const grant = this._matchToken(match[1]);const session=this.sessions.get(grant.id);
      if (!session || session.generation !== this.generation) reject('CLAIM_REVOKED','此本机预览已停止，请在软件中重新打开。');
      this._active(grant,session.actorId);
      if (!match[2] && req.method === 'GET') {
        const file = this.store.get(COLLECTIONS.files, grant.fileId);
        if (!file || file.accountId !== grant.accountId || file.space !== grant.space) reject('CLAIM_FILE_SCOPE','领取文件不存在或范围不匹配。');
        this._event(grant,'page_opened');res.statusCode=200;res.setHeader('Content-Type','text/html; charset=utf-8');
        res.end(`<!doctype html><html lang="zh-CN"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>联铺 · 本机领取试运行</title><style>body{max-width:620px;margin:10vh auto;padding:24px;font:16px/1.8 system-ui;color:#233a35;background:#f5f7f4}main{background:white;border:1px solid #ccd9d3;padding:28px;border-radius:12px}h1{font-size:25px}button{font:inherit;padding:10px 20px;background:#315b4f;color:white;border:0;border-radius:6px}small{color:#5b6b65}</style><main><small>仅当前电脑 · 隔离试运行</small><h1>${escapeHtml(file.name)}</h1><p>文件大小：${file.size} 字节<br>剩余发起领取次数：${Math.max(0,grant.maxClaims-grant.claimsStarted)}<br>截止时间：${escapeHtml(grant.expiresAt)}</p><form method="post" action="${url.pathname}/download"><button type="submit">发起本机文件领取</button></form><p><small>每次发起文件响应占用一次领取次数，即使连接中断也不自动返还。页面打开不计作领取；响应结束只表示服务器写出响应，不证明文件已完整下载。此页面不能作为真实买家的公网领取入口。</small></p></main></html>`);
        return;
      }
      if (match[2] && req.method === 'POST') {
        if (req.headers.origin !== this.origin || (req.headers['content-length'] && req.headers['content-length'] !== '0') || req.headers['transfer-encoding']) reject('CLAIM_ORIGIN','请从本机领取预览页发起空内容领取请求。');
        let payload,started,allocated;
        this.store.transaction(() => {
          allocated=this.store.get(COLLECTIONS.grants,grant.id);this._active(allocated,session.actorId);
          if (allocated.claimsStarted >= allocated.maxClaims) reject('CLAIM_LIMIT','领取次数已用完。');
          const file=this.store.get(COLLECTIONS.files,allocated.fileId);
          if (!file || file.space !== allocated.space || file.accountId !== allocated.accountId) reject('CLAIM_FILE_SCOPE','领取文件范围不匹配。');
          payload=Buffer.from(file.data,'base64');
          if (payload.length !== file.size || payload.length > MAX_FILE_BYTES || SHA(payload) !== file.sha256) reject('CLAIM_FILE_CORRUPT','领取文件校验失败，尚未开始文件响应。');
          this.store.put(COLLECTIONS.grants,{...allocated,claimsStarted:allocated.claimsStarted+1,updatedAt:this._now()});
          started=this._event(allocated,'access_started',{declaredBytes:file.size,fileSha256:file.sha256});
          allocated={...allocated,fileName:file.name};
        });
        let finished=false;
        res.once('finish',()=>{finished=true;this._event(allocated,'response_finished',{attemptId:started.id,declaredBytes:payload.length,evidence:'server_response_written_not_download_proof'});});
        res.once('close',()=>{if(!finished)this._event(allocated,'response_interrupted',{attemptId:started.id,evidence:'response_incomplete_or_unknown'});});
        res.statusCode=200;res.setHeader('Content-Type','application/octet-stream');res.setHeader('Content-Length',payload.length);res.setHeader('Content-Disposition',`attachment; filename="lianpu-file.bin"; filename*=UTF-8''${encodeURIComponent(allocated.fileName).replaceAll("'",'%27')}`);
        // Yield between bounded chunks so locking, revocation and socket closure can interrupt a large response.
        let offset=0;
        const writeNext=()=>{if(res.destroyed)return;try{this._active(this.store.get(COLLECTIONS.grants,grant.id),session.actorId);}catch{res.destroy();return;}const end=Math.min(offset+64*1024,payload.length);const ready=res.write(payload.subarray(offset,end));offset=end;if(offset===payload.length){res.end();return;}if(ready)setImmediate(writeNext);else res.once('drain',()=>setImmediate(writeNext));};
        writeNext();return;
      }
      res.statusCode=405;res.setHeader('Allow',match[2]?'POST':'GET');res.end('此入口不支持该请求方式。');
    } catch(error) {
      if(res.headersSent){res.destroy();return;}
      res.statusCode=error.code==='CLAIM_NOT_FOUND'?404:error.code==='CLAIM_ORIGIN'||error.code==='FORBIDDEN'?403:error.code==='CLAIM_LIMIT'?409:error instanceof ClaimError?410:500;
      res.setHeader('Content-Type','text/plain; charset=utf-8');res.end(error instanceof ClaimError?error.message:'本机领取暂未完成，请返回软件查看状态。');
    }
  }
  async stop() {
    if(this.stopping)return this.stopping;
    this.generation++;this.sessions.clear();
    this.stopping=(async()=>{
      if(this.starting)await this.starting.catch(()=>{});
      const server=this.server;this.server=null;this.origin=null;
      if(server)await new Promise(resolve=>{server.close(()=>resolve());server.closeAllConnections();});
      return {stopped:true};
    })();
    try{return await this.stopping;}finally{this.stopping=null;}
  }
  exportBackup(actor) {
    if(this._member(actor).role!=='owner')reject('FORBIDDEN','领取文件备份仅限管理员。');
    return {version:1,files:this.store.list(COLLECTIONS.files),grants:this.store.list(COLLECTIONS.grants),access:this.store.list(COLLECTIONS.access)};
  }
  validateBackup(data) {
    if(!data||data.version!==1||!Array.isArray(data.files)||!Array.isArray(data.grants)||!Array.isArray(data.access)||data.files.length>10000||data.grants.length>100000||data.access.length>500000)reject('CLAIM_BACKUP','领取资料备份格式无效。');
    const ids=new Set();
    for(const file of data.files){
      if(!file||Object.keys(file).some(key=>!FILE_FIELDS.has(key))||typeof file.id!=='string'||!['test','live'].includes(file.space)||typeof file.accountId!=='string'||typeof file.data!=='string'||typeof file.name!=='string'||file.name.length>180||/[\x00-\x1f\x7f]/.test(file.name)||typeof file.rights?.actorId!=='string'||Object.keys(file.rights).some(key=>!['actorId','confirmedAt'].includes(key)))reject('CLAIM_BACKUP','领取文件记录无效。');
      const bytes=Buffer.from(file.data,'base64');if(!bytes.length||bytes.length>MAX_FILE_BYTES||file.size!==bytes.length||SHA(bytes)!==file.sha256||ids.has(file.id))reject('CLAIM_BACKUP','领取文件重复或内容校验不一致。');ids.add(file.id);
      const old=this.store.get(COLLECTIONS.files,file.id);if(old&&(old.sha256!==file.sha256||old.space!==file.space||old.accountId!==file.accountId))reject('CLAIM_BACKUP','领取文件编号与本机内容冲突。');
    }
    ids.clear();
    for(const grant of data.grants){
      if(!grant||Object.keys(grant).some(key=>!GRANT_FIELDS.has(key))||typeof grant.id!=='string'||grant.space!=='test'||!['active','revoked'].includes(grant.status)||!Number.isSafeInteger(grant.maxClaims)||grant.maxClaims<1||grant.maxClaims>1000||!Number.isSafeInteger(grant.claimsStarted)||grant.claimsStarted<0||grant.claimsStarted>grant.maxClaims||!/^[a-f0-9]{64}$/.test(grant.tokenHash||'')||ids.has(grant.id))reject('CLAIM_BACKUP','领取授权记录无效。');
      requireDate(grant.expiresAt,'领取授权到期时间');ids.add(grant.id);
      const old=this.store.get(COLLECTIONS.grants,grant.id);if(old&&['orderId','buyerId','accountId','space','fileId','tokenHash','maxClaims'].some(key=>old[key]!==grant[key]))reject('CLAIM_BACKUP','领取授权与本机身份或次数范围冲突。');
    }
    ids.clear();
    for(const event of data.access){if(!event||Object.keys(event).some(key=>!EVENT_FIELDS.has(key))||typeof event.id!=='string'||!ACCESS_EVENTS.has(event.event)||event.space!=='test'||ids.has(event.id))reject('CLAIM_BACKUP','领取访问记录无效。');requireDate(event.at,'领取访问时间');ids.add(event.id);const old=this.store.get(COLLECTIONS.access,event.id);if(old&&JSON.stringify(old)!==JSON.stringify(event))reject('CLAIM_BACKUP','领取访问事实与本机记录冲突。');}
    for(const grant of data.grants)if(data.access.filter(event=>event.grantId===grant.id&&event.event==='access_started').length>grant.claimsStarted)reject('CLAIM_BACKUP','领取访问事实多于授权次数记录，已停止恢复。');
    return {fileCount:data.files.length,grantCount:data.grants.length,accessCount:data.access.length,warning:'恢复的领取授权全部撤回，不恢复旧令牌的访问能力。'};
  }
  restore(data,actor) {
    if(this._member(actor).role!=='owner')reject('FORBIDDEN','领取文件恢复仅限管理员。');
    this.validateBackup(data);
    let added=0,preserved=0;
    this.store.transaction(()=>{
      for(const file of data.files){const account=this.store.get('accounts',file.accountId);if(!account||account.space!==file.space)reject('CLAIM_BACKUP','领取文件缺少所属账号。');if(!this.store.get(COLLECTIONS.files,file.id)){this.store.put(COLLECTIONS.files,file);added++;}else preserved++;}
      for(const grant of data.grants){const order=this.store.get('orders',grant.orderId),file=this.store.get(COLLECTIONS.files,grant.fileId);if(!order||!file||order.space!=='test'||order.accountId!==grant.accountId||order.buyerId!==grant.buyerId||file.accountId!==grant.accountId||file.space!==grant.space)reject('CLAIM_BACKUP','恢复的领取授权不属于对应订单或文件。');const old=this.store.get(COLLECTIONS.grants,grant.id);this.store.put(COLLECTIONS.grants,{...(old||grant),claimsStarted:Math.max(old?.claimsStarted||0,grant.claimsStarted),status:'revoked',revokeReason:'从备份恢复后须重新创建授权；旧令牌不能继续使用。',revokedAt:this._now(),updatedAt:this._now()});this.sessions.delete(grant.id);old?preserved++:added++;}
      for(const event of data.access){const grant=this.store.get(COLLECTIONS.grants,event.grantId);if(!grant||event.space!==grant.space||event.accountId!==grant.accountId||event.orderId!==grant.orderId)reject('CLAIM_BACKUP','恢复的领取访问记录身份不一致。');if(!this.store.get(COLLECTIONS.access,event.id)){this.store.put(COLLECTIONS.access,event);added++;}else preserved++;}
      for(const original of data.grants){const grant=this.store.get(COLLECTIONS.grants,original.id);const started=this.store.list(COLLECTIONS.access).filter(event=>event.grantId===grant.id&&event.event==='access_started').length;if(started>grant.maxClaims)reject('CLAIM_BACKUP','合并后的领取事实超过授权次数，请核验备份来源。');if(started>grant.claimsStarted)this.store.put(COLLECTIONS.grants,{...grant,claimsStarted:started});}
    });
    return {restored:true,added,preserved,grantsRevoked:true};
  }
}

module.exports={ClaimsEngine,ClaimError,COLLECTIONS,MAX_FILE_BYTES};
