'use strict';

const { DatabaseSync } = require('node:sqlite');
const { randomBytes, createCipheriv, createDecipheriv } = require('node:crypto');
const { mkdirSync } = require('node:fs');
const { dirname } = require('node:path');

/** Each business payload is authenticated independently; metadata contains opaque ids only. */
class EncryptedStore {
  constructor(file, key) {
    if (!Buffer.isBuffer(key) || key.length !== 32) throw new Error('资料密钥必须是 32 字节。');
    if (file !== ':memory:') mkdirSync(dirname(file), { recursive: true });
    this.key = Buffer.from(key);
    this.db = new DatabaseSync(file);
    this.db.exec('PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; PRAGMA foreign_keys=ON; PRAGMA busy_timeout=5000; CREATE TABLE IF NOT EXISTS records (kind TEXT NOT NULL, id TEXT NOT NULL, payload BLOB NOT NULL, PRIMARY KEY(kind,id));');
    this.depth = 0;
    // Authenticate before any migration or writes so a wrong key never appears as an empty vault.
    try {
      const marker = this.get('_meta', 'key-check');
      if (!marker) this.put('_meta', { id: 'key-check', schema: 1 });
    } catch (error) { this.db.close(); this.key.fill(0); throw error; }
  }
  _encode(kind, record) {
    const nonce = randomBytes(12);
    const cipher = createCipheriv('aes-256-gcm', this.key, nonce);
    cipher.setAAD(Buffer.from(`${kind}\0${record.id}`));
    const data = Buffer.concat([cipher.update(JSON.stringify(record), 'utf8'), cipher.final()]);
    return Buffer.concat([Buffer.from([1]), nonce, cipher.getAuthTag(), data]);
  }
  _decode(kind, id, bytes) {
    const raw = Buffer.from(bytes);
    if (raw.length < 30 || raw[0] !== 1) throw new Error('资料格式不受支持。');
    const cipher = createDecipheriv('aes-256-gcm', this.key, raw.subarray(1, 13));
    cipher.setAAD(Buffer.from(`${kind}\0${id}`));
    cipher.setAuthTag(raw.subarray(13, 29));
    try { return JSON.parse(Buffer.concat([cipher.update(raw.subarray(29)), cipher.final()]).toString('utf8')); }
    catch { throw new Error('无法打开资料，密钥不匹配或资料已损坏。'); }
  }
  get(kind, id) {
    const row = this.db.prepare('SELECT payload FROM records WHERE kind=? AND id=?').get(kind, id);
    return row ? this._decode(kind, id, row.payload) : null;
  }
  list(kind) {
    return this.db.prepare('SELECT id,payload FROM records WHERE kind=? ORDER BY rowid').all(kind).map(row => this._decode(kind, row.id, row.payload));
  }
  put(kind, record) {
    if (typeof kind !== 'string' || !kind || !record || typeof record.id !== 'string' || !record.id) throw new Error('记录类型和编号不能为空。');
    this.db.prepare('INSERT INTO records(kind,id,payload) VALUES(?,?,?) ON CONFLICT(kind,id) DO UPDATE SET payload=excluded.payload').run(kind, record.id, this._encode(kind, record));
    return structuredClone(record);
  }
  remove(kind, id) { return this.db.prepare('DELETE FROM records WHERE kind=? AND id=?').run(kind, id).changes > 0; }
  transaction(fn) {
    const nested = this.depth > 0;
    const point = `t${this.depth}`;
    this.db.exec(nested ? `SAVEPOINT ${point}` : 'BEGIN IMMEDIATE');
    this.depth++;
    try {
      const value = fn();
      if (value && typeof value.then === 'function') throw new Error('资料事务内禁止等待网络。');
      this.db.exec(nested ? `RELEASE ${point}` : 'COMMIT');
      return value;
    } catch (error) {
      this.db.exec(nested ? `ROLLBACK TO ${point}; RELEASE ${point}` : 'ROLLBACK');
      throw error;
    } finally { this.depth--; }
  }
  close() { this.db.close(); this.key.fill(0); }
}

module.exports = { EncryptedStore };
