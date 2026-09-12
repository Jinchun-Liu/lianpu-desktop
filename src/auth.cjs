'use strict';
const fs = require('node:fs');
const path = require('node:path');
const { randomBytes, randomUUID, scryptSync, createCipheriv, createDecipheriv, createHash } = require('node:crypto');

class AccessError extends Error {
  constructor(code, message) { super(message); this.code = code; }
}
function atomicWrite(file, value) {
  fs.mkdirSync(path.dirname(file), { recursive: true, mode: 0o700 });
  const tmp = `${file}.${randomUUID()}.tmp`;
  const fd = fs.openSync(tmp, 'wx', 0o600);
  try { fs.writeFileSync(fd, JSON.stringify(value)); fs.fsyncSync(fd); } finally { fs.closeSync(fd); }
  fs.renameSync(tmp, file);
}
function passwordCheck(password) {
  if (typeof password !== 'string' || password.length < 12 || password.length > 1024)
    throw new AccessError('PASSWORD_LENGTH', '管理密码需要 12–1024 个字符；可以使用容易记住的长句。');
}
function keyFrom(password, salt) {
  return scryptSync(password, Buffer.from(salt, 'base64'), 32, { N: 32768, r: 8, p: 1, maxmem: 64 * 1024 * 1024 });
}
function wrap(key, password, id) {
  const salt = randomBytes(16).toString('base64');
  const derived = keyFrom(password, salt), iv = randomBytes(12);
  try {
    const cipher = createCipheriv('aes-256-gcm', derived, iv);
    cipher.setAAD(Buffer.from(`lianpu-vault-v1:${id}`));
    const ciphertext = Buffer.concat([cipher.update(key), cipher.final()]);
    return { salt, iv: iv.toString('base64'), tag: cipher.getAuthTag().toString('base64'), ciphertext: ciphertext.toString('base64') };
  } finally { derived.fill(0); }
}
function unwrap(envelope, password, id) {
  const derived = keyFrom(password, envelope.salt);
  try {
    const decipher = createDecipheriv('aes-256-gcm', derived, Buffer.from(envelope.iv, 'base64'));
    decipher.setAAD(Buffer.from(`lianpu-vault-v1:${id}`));
    decipher.setAuthTag(Buffer.from(envelope.tag, 'base64'));
    return Buffer.concat([decipher.update(Buffer.from(envelope.ciphertext, 'base64')), decipher.final()]);
  } finally { derived.fill(0); }
}
class VaultIdentity {
  constructor(file, clock = () => Date.now()) { this.file = file; this.clock = clock; this.key = null; this.userId = null; this.load(); }
  load() {
    this.meta = fs.existsSync(this.file) ? JSON.parse(fs.readFileSync(this.file, 'utf8')) : null;
    if (this.meta && (this.meta.version !== 1 || !Array.isArray(this.meta.users))) throw new AccessError('VAULT_FORMAT', '访问保护文件版本无法识别，请使用兼容版本或已验证备份。');
  }
  status() { return { configured: !!this.meta, locked: !this.key, users: this.meta?.users.map(({ id, name }) => ({ id, name })) || [] }; }
  credentialRevision(id = this.userId) {
    const user=this.meta?.users.find(u=>u.id===id);if(!user)throw new AccessError('SESSION_INVALID','保存的成员身份已失效。');
    return createHash('sha256').update(JSON.stringify({id,ownerId:this.meta.ownerId,envelope:user.envelope,revision:this.meta.rememberedRevision||0})).digest('hex');
  }
  advanceRememberedRevision() {
    const previous=this.meta.rememberedRevision||0;this.meta.rememberedRevision=previous+1;
    try{atomicWrite(this.file,this.meta);}catch(error){this.meta.rememberedRevision=previous;throw new AccessError('SESSION_SAVE_FAILED','无法更新当前成员的持久登录版本，本次身份切换未完成。');}
    return this.credentialRevision();
  }
  restoreRemembered({userId,key,credentialRevision},validateMember) {
    const user=this.meta?.users.find(u=>u.id===userId);
    if(!user||credentialRevision!==this.credentialRevision(userId)||!Buffer.isBuffer(key)||key.length!==32)throw new AccessError('SESSION_INVALID','保存的登录已失效，请登录一次。');
    if(typeof validateMember!=='function'||validateMember(userId,key)!==true)throw new AccessError('FORBIDDEN','保存的成员已停用或无权访问工作区。');
    const restored=Buffer.from(key);this.lock();this.key=restored;this.userId=userId;return {id:user.id,name:user.name};
  }
  setup({ name, password }) {
    if (this.meta) throw new AccessError('ALREADY_CONFIGURED', '本机已经设置访问保护，请登录。');
    passwordCheck(password);
    if (typeof name !== 'string' || !name.trim() || name.length > 80) throw new AccessError('NAME_REQUIRED', '请填写不超过 80 字的管理名称。');
    const id = randomUUID(), key = randomBytes(32), recoveryCode = randomBytes(32).toString('base64url');
    const now = new Date(this.clock()).toISOString();
    this.meta = { version: 1, ownerId: id, createdAt: now, users: [{ id, name: name.trim(), envelope: wrap(key, password, id), failures: 0, blockedUntil: 0 }], recovery: wrap(key, recoveryCode, 'recovery') };
    atomicWrite(this.file, this.meta); this.key = key; this.userId = id;
    return { id, name: name.trim(), recoveryCode };
  }
  unlock({ id, password }) {
    if (typeof password !== 'string' || password.length > 1024) throw new AccessError('LOGIN_FAILED', '名称或密码不正确。');
    const user = this.meta?.users.find(u => u.id === id);
    if (!user) throw new AccessError('LOGIN_FAILED', '名称或密码不正确。');
    if (user.blockedUntil > this.clock()) throw new AccessError('TRY_LATER', '连续登录失败，请稍后再试。');
    let key;
    try { key = unwrap(user.envelope, password, id); }
    catch {
      user.failures = (user.failures || 0) + 1;
      user.blockedUntil = user.failures >= 5 ? this.clock() + Math.min(15 * 60_000, 30_000 * 2 ** Math.min(user.failures - 5, 5)) : 0;
      atomicWrite(this.file, this.meta);
      throw new AccessError('LOGIN_FAILED', '名称或密码不正确。');
    }
    user.failures = 0; user.blockedUntil = 0; atomicWrite(this.file, this.meta);
    this.lock(); this.key = key; this.userId = id; return { id, name: user.name };
  }
  changePassword({ oldPassword, newPassword }) {
    if (!this.key) throw new AccessError('LOCKED', '请先登录有效的本机成员。');
    passwordCheck(newPassword);
    const user = this.meta.users.find(u => u.id === this.userId);
    let check;
    try { check = unwrap(user.envelope, oldPassword, user.id); }
    catch { throw new AccessError('LOGIN_FAILED', '原密码不正确。'); }
    finally { check?.fill(0); }
    user.envelope = wrap(this.key, newPassword, user.id); atomicWrite(this.file, this.meta);
    return { changed: true };
  }
  addMember({ id, name, password }) {
    if (!this.key || this.userId !== this.meta.ownerId) throw new AccessError('FORBIDDEN', '只有本机管理员可以创建成员。');
    passwordCheck(password);
    if (!name || typeof name !== 'string' || name.length > 80) throw new AccessError('NAME_REQUIRED', '请输入成员名称。');
    if (this.meta.users.some(u => u.id === id)) throw new AccessError('DUPLICATE', '成员已存在。');
    this.meta.users.push({ id, name: name.trim(), envelope: wrap(this.key, password, id), failures: 0, blockedUntil: 0 });
    atomicWrite(this.file, this.meta); return { id, name: name.trim() };
  }
  recover({ recoveryCode, newPassword }) {
    passwordCheck(newPassword);
    if (!this.meta || typeof recoveryCode !== 'string' || recoveryCode.length > 1024) throw new AccessError('RECOVERY_FAILED', '恢复材料不正确。');
    if ((this.meta.recoveryBlockedUntil || 0) > this.clock()) throw new AccessError('TRY_LATER', '连续恢复失败，请稍后再试。');
    let key;
    try { key = unwrap(this.meta.recovery, recoveryCode.trim(), 'recovery'); }
    catch {
      this.meta.recoveryFailures = (this.meta.recoveryFailures || 0) + 1;
      if (this.meta.recoveryFailures >= 5) this.meta.recoveryBlockedUntil = this.clock() + 60_000;
      atomicWrite(this.file, this.meta); throw new AccessError('RECOVERY_FAILED', '恢复材料不正确。');
    }
    const owner = this.meta.users.find(u => u.id === this.meta.ownerId), nextRecoveryCode = randomBytes(32).toString('base64url');
    owner.envelope = wrap(key, newPassword, owner.id); owner.failures = 0; owner.blockedUntil = 0;
    this.meta.recovery = wrap(key, nextRecoveryCode, 'recovery'); this.meta.recoveryFailures = 0; this.meta.recoveryBlockedUntil = 0;
    this.meta.rememberedRevision=(this.meta.rememberedRevision||0)+1;
    atomicWrite(this.file, this.meta); this.lock(); this.key = key; this.userId = owner.id;
    return { id: owner.id, name: owner.name, recoveryCode: nextRecoveryCode };
  }
  lock() { this.key?.fill(0); this.key = null; this.userId = null; }
}
module.exports = { VaultIdentity, AccessError, atomicWrite, wrap, unwrap };
