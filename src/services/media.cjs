'use strict';
const path = require('node:path');
const { randomUUID, createHash } = require('node:crypto');
const { AccessError } = require('../auth.cjs');
const PREFIX = 'lianpu://app/media/';
function detectImage(bytes) {
  if (!Buffer.isBuffer(bytes) || bytes.length < 12 || bytes.length > 5 * 1024 * 1024) throw new AccessError('IMAGE_SIZE', '每张图片需要小于 5 MB，且是有效的 PNG、JPEG 或 WebP 图片。');
  if (bytes.subarray(0, 8).equals(Buffer.from([137,80,78,71,13,10,26,10]))) return 'image/png';
  if (bytes[0] === 255 && bytes[1] === 216 && bytes[2] === 255) return 'image/jpeg';
  if (bytes.toString('ascii', 0, 4) === 'RIFF' && bytes.toString('ascii', 8, 12) === 'WEBP') return 'image/webp';
  throw new AccessError('IMAGE_FORMAT', '仅支持 PNG、JPEG 和 WebP 图片，不接受脚本、网页或 SVG 文件。');
}
class MediaLibrary {
  constructor(store) { this.store = store; }
  authorize(actor, space, accountId) {
    const member = this.store.get('members', actor?.id);
    if (!member || member.enabled === false || !['owner', 'operator'].includes(member.role)) throw new AccessError('FORBIDDEN', '素材内容需要管理员或经营人员权限。');
    if (!['live', 'test'].includes(space)) throw new AccessError('INVALID_INPUT', '请选择素材所属工作区。');
    const account = this.store.get('accounts', accountId);
    if (!account || account.space !== space || (member.role !== 'owner' && !member.accountIds?.includes(accountId))) throw new AccessError('FORBIDDEN', '没有此账号的素材管理权限。');
    return member;
  }
  public(record) { const { data, ...summary } = record; return { ...summary, url: PREFIX + record.id }; }
  list({ space, accountId }, actor) {
    const member = this.store.get('members', actor?.id);
    if (!member || member.enabled === false || !['owner', 'operator'].includes(member.role)) throw new AccessError('FORBIDDEN', '素材内容需要管理员或经营人员权限。');
    if (!['live', 'test'].includes(space)) throw new AccessError('INVALID_INPUT', '请选择素材所属工作区。');
    if (accountId) this.authorize(actor, space, accountId);
    return this.store.list('_media').filter(r => r.space === space && (!accountId || r.accountId === accountId) && (member.role === 'owner' || member.accountIds.includes(r.accountId))).map(r => this.public(r));
  }
  add({ name, bytes, space, accountId }, actor) {
    this.authorize(actor, space, accountId); const mime = detectImage(bytes), sha256 = createHash('sha256').update(bytes).digest('hex');
    const duplicate = this.store.list('_media').find(r => r.accountId === accountId && r.space === space && r.sha256 === sha256);
    if (duplicate) return { ...this.public(duplicate), duplicate: true };
    const record = { id: randomUUID(), space, accountId, name: path.basename(name).slice(0, 200), mime, bytes: bytes.length, sha256, data: bytes.toString('base64'), createdAt: new Date().toISOString() };
    this.store.put('_media', record); return this.public(record);
  }
  read(id, actor) {
    const record = this.store.get('_media', id);
    if (!record) throw new AccessError('NOT_FOUND', '素材不存在。');
    this.authorize(actor, record.space, record.accountId); return { bytes: Buffer.from(record.data, 'base64'), mime: record.mime };
  }
  remove(id, actor) {
    const record = this.store.get('_media', id); if (!record) throw new AccessError('NOT_FOUND', '素材不存在。');
    this.authorize(actor, record.space, record.accountId);
    for (const kind of ['products', 'assets', 'deliveries', 'snippets']) if (this.store.list(kind).some(r => JSON.stringify(r).includes(PREFIX + id))) throw new AccessError('IN_USE', '素材仍被商品、资料或历史交付使用，请保留对应内容。');
    this.store.remove('_media', id); return { removed: true };
  }
  copyUrl(url, sourceAccountId, targetAccountId, actor) {
    if (typeof url !== 'string' || !url.startsWith(PREFIX)) return url;
    const media = this.store.get('_media', url.slice(PREFIX.length));
    if (!media || media.accountId !== sourceAccountId) throw new AccessError('MEDIA_REFERENCE', '商品素材不属于源账号。');
    const copied = this.add({ name: media.name, bytes: Buffer.from(media.data, 'base64'), space: media.space, accountId: targetAccountId }, actor);
    return copied.url;
  }
  validateBackup(records) {
    if (!Array.isArray(records) || records.length > 10000) throw new AccessError('BACKUP_MEDIA', '备份素材列表无效。');
    for (const r of records) {
      if (!r || typeof r.id !== 'string' || !/^[\w-]{1,80}$/.test(r.id) || !['live','test'].includes(r.space) || typeof r.accountId !== 'string' || typeof r.data !== 'string') throw new AccessError('BACKUP_MEDIA', '备份包含无效素材记录。');
      const bytes = Buffer.from(r.data, 'base64');
      if (detectImage(bytes) !== r.mime || createHash('sha256').update(bytes).digest('hex') !== r.sha256) throw new AccessError('BACKUP_MEDIA', '备份素材校验不一致。');
      const existing = this.store.get('_media', r.id);
      if (existing && (existing.sha256 !== r.sha256 || existing.accountId !== r.accountId || existing.space !== r.space)) throw new AccessError('BACKUP_MEDIA', '备份素材编号与本机内容冲突，已停止恢复。');
    }
    return { materialCount: records.length };
  }
  restore(records) {
    this.validateBackup(records);
    for (const r of records) if (!this.store.get('_media', r.id)) {
      const account = this.store.get('accounts', r.accountId);
      if (!account || account.space !== r.space) throw new AccessError('BACKUP_MEDIA', '备份素材缺少所属账号。');
      this.store.put('_media', { id:r.id,space:r.space,accountId:r.accountId,name:r.name,mime:r.mime,bytes:Buffer.from(r.data,'base64').length,sha256:r.sha256,data:r.data,createdAt:r.createdAt });
    }
  }
}
module.exports = { MediaLibrary, detectImage, PREFIX };
