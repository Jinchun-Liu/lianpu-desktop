// Shared wire format. No Node, Electron, platform storage, or network dependencies.
export const PROTOCOL_VERSION = 1;
export const PERIOD_DAYS = Object.freeze({ week: 7, month: 30, year: 365, perpetual: null });
export const DOMAINS = Object.freeze({
  ticket: 'LIANPU-LICENSING/v1/ticket\0',
  license: 'LIANPU-LICENSING/v1/license\0',
  deviceProof: 'LIANPU-LICENSING/v1/device-proof\0',
});
export const TICKET_TTL_MS = 300000;
export const DEVICE_PROOF_ALGORITHM = 'ECDSA-P256-SHA256';
const encoder = new TextEncoder();
const HEX = /^[a-f0-9]{64}$/;
const UUID = /^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/;
const PLAN_LETTERS = { W: 'week', M: 'month', Y: 'year', P: 'perpetual' };

export class ProtocolError extends Error {
  constructor(code, message = code) { super(message); this.name = 'ProtocolError'; this.code = code; }
}
function ensure(value, code = 'INVALID_FORMAT') { if (!value) throw new ProtocolError(code); }
function object(value) {
  ensure(value && typeof value === 'object' && !Array.isArray(value));
  ensure(Object.getPrototypeOf(value) === Object.prototype || Object.getPrototypeOf(value) === null);
  dataKeys(value);
}
// Only JSON data participates in signatures. Do not invoke accessors or silently
// ignore symbols/non-enumerable members supplied by an in-process caller.
function dataKeys(value, array = false) {
  const keys = Reflect.ownKeys(value);
  for (const key of keys) {
    if (array && key === 'length') continue;
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    ensure(typeof key === 'string' && descriptor.enumerable && Object.hasOwn(descriptor, 'value'), 'INVALID_CANONICAL_JSON');
  }
  return Object.keys(value);
}
export function exactKeys(value, keys) {
  object(value);
  ensure(Object.keys(value).sort().join('|') === [...keys].sort().join('|'));
  return value;
}
export function canonicalJson(value) {
  const seen = new Set();
  function visit(item, depth) {
    ensure(depth <= 20, 'INVALID_CANONICAL_JSON');
    if (item === null || typeof item === 'string' || typeof item === 'boolean') return JSON.stringify(item);
    if (typeof item === 'number') { ensure(Number.isSafeInteger(item), 'INVALID_CANONICAL_JSON'); return JSON.stringify(item); }
    ensure(item && typeof item === 'object' && !seen.has(item), 'INVALID_CANONICAL_JSON');
    seen.add(item);
    let text;
    if (Array.isArray(item)) {
      const keys = dataKeys(item, true);
      ensure(keys.length === item.length && keys.every((key, index) => key === String(index)), 'INVALID_CANONICAL_JSON');
      text = '[' + item.map(entry => visit(entry, depth + 1)).join(',') + ']';
    } else {
      object(item);
      text = '{' + Object.keys(item).sort().map(key => JSON.stringify(key) + ':' + visit(item[key], depth + 1)).join(',') + '}';
    }
    seen.delete(item);
    return text;
  }
  return visit(value, 0);
}
export function toBase64Url(value) {
  const bytes = value instanceof Uint8Array ? value : new Uint8Array(value);
  let binary = '';
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
}
export function fromBase64Url(value, expectedLength) {
  ensure(typeof value === 'string' && value.length > 0 && value.length <= 16384 && /^[A-Za-z0-9_-]+$/.test(value), 'INVALID_BASE64URL');
  let bytes;
  try { bytes = Uint8Array.from(atob(value.replace(/-/g, '+').replace(/_/g, '/') + '='.repeat((4 - value.length % 4) % 4)), c => c.charCodeAt(0)); }
  catch { throw new ProtocolError('INVALID_BASE64URL'); }
  ensure(toBase64Url(bytes) === value && (expectedLength === undefined || bytes.length === expectedLength), 'INVALID_BASE64URL');
  return bytes;
}
export async function sha256Hex(value) {
  const bytes = typeof value === 'string' ? encoder.encode(value) : value;
  return [...new Uint8Array(await crypto.subtle.digest('SHA-256', bytes))].map(byte => byte.toString(16).padStart(2, '0')).join('');
}
export function normalizeCode(value) {
  ensure(typeof value === 'string' && value.length <= 80, 'INVALID_CODE');
  const code = value.trim().toUpperCase();
  ensure(/^LP1-[WMYP]-[A-F0-9]{40}$/.test(code), 'INVALID_CODE');
  return code;
}
export async function hashCode(value) { return sha256Hex(normalizeCode(value)); }
export function planFromCode(value) { return PLAN_LETTERS[normalizeCode(value)[4]]; }
export function validateRequestId(value) { ensure(typeof value === 'string' && UUID.test(value), 'INVALID_REQUEST_ID'); return value; }
export function validateDigest(value) { ensure(typeof value === 'string' && HEX.test(value), 'INVALID_DIGEST'); return value; }
export function validatePlan(value) { ensure(Object.hasOwn(PERIOD_DAYS, value), 'INVALID_PLAN'); return value; }
function timestamp(value) { ensure(Number.isSafeInteger(value) && value > 0, 'INVALID_TIMESTAMP'); }
export async function importDevicePublicKey(spki) {
  const bytes = fromBase64Url(spki, 91);
  let key;
  try { key = await crypto.subtle.importKey('spki', bytes, { name: 'ECDSA', namedCurve: 'P-256' }, true, ['verify']); }
  catch { throw new ProtocolError('INVALID_DEVICE_KEY'); }
  ensure(toBase64Url(await crypto.subtle.exportKey('spki', key)) === spki, 'INVALID_DEVICE_KEY');
  return key;
}
export async function deviceIdFromSpki(spki) {
  await importDevicePublicKey(spki);
  return sha256Hex(fromBase64Url(spki));
}
export function validateTicketPayload(payload) {
  exactKeys(payload, ['v', 'type', 'mode', 'requestId', 'deviceId', 'devicePublicKeySpki', 'codeHash', 'plan', 'issuedAt', 'expiresAt', 'nonce']);
  ensure(payload.v === 1 && payload.type === 'ticket' && ['activate', 'recover'].includes(payload.mode), 'INVALID_TICKET');
  validateRequestId(payload.requestId); validateDigest(payload.deviceId); fromBase64Url(payload.devicePublicKeySpki, 91);
  fromBase64Url(payload.nonce, 32); timestamp(payload.issuedAt); timestamp(payload.expiresAt);
  ensure(payload.expiresAt - payload.issuedAt === TICKET_TTL_MS, 'INVALID_TICKET');
  if (payload.mode === 'activate') { validateDigest(payload.codeHash); validatePlan(payload.plan); }
  else ensure(payload.codeHash === null && payload.plan === null, 'INVALID_TICKET');
  return payload;
}
export function validateLicensePayload(payload) {
  exactKeys(payload, ['v', 'type', 'licenseId', 'deviceId', 'devicePublicKeySpki', 'plan', 'firstActivatedAt', 'issuedAt', 'expiresAt', 'revision', 'requestId']);
  ensure(payload.v === 1 && payload.type === 'license', 'INVALID_LICENSE');
  validateRequestId(payload.licenseId); validateRequestId(payload.requestId); validateDigest(payload.deviceId);
  fromBase64Url(payload.devicePublicKeySpki, 91); validatePlan(payload.plan); timestamp(payload.issuedAt); timestamp(payload.firstActivatedAt);
  ensure(payload.firstActivatedAt <= payload.issuedAt, 'INVALID_LICENSE');
  ensure(Number.isSafeInteger(payload.revision) && payload.revision > 0, 'INVALID_LICENSE');
  if (payload.plan === 'perpetual') ensure(payload.expiresAt === null, 'INVALID_LICENSE');
  else { timestamp(payload.expiresAt); ensure(payload.expiresAt > payload.issuedAt, 'INVALID_LICENSE'); }
  return payload;
}
function envelopeBytes(envelope, domain) {
  ensure(domain === 'ticket' || domain === 'license', 'INVALID_DOMAIN');
  return encoder.encode(DOMAINS[domain] + canonicalJson({ keyId: envelope.keyId, payload: envelope.payload }));
}
function validateEnvelope(envelope, domain) {
  exactKeys(envelope, ['keyId', 'payload', 'signature']);
  ensure(typeof envelope.keyId === 'string' && /^[A-Za-z0-9_-]{1,64}$/.test(envelope.keyId), 'INVALID_KEY_ID');
  fromBase64Url(envelope.signature, 64);
  if (domain === 'ticket') validateTicketPayload(envelope.payload);
  else if (domain === 'license') validateLicensePayload(envelope.payload);
  else throw new ProtocolError('INVALID_DOMAIN');
}
export async function signEnvelope(payload, domain, keyId, privateKey) {
  const envelope = { keyId, payload, signature: toBase64Url(new Uint8Array(64)) };
  validateEnvelope(envelope, domain);
  envelope.signature = toBase64Url(await crypto.subtle.sign('Ed25519', privateKey, envelopeBytes(envelope, domain)));
  return envelope;
}
export async function verifyEnvelope(envelope, domain, publicKeys) {
  validateEnvelope(envelope, domain);
  const material = publicKeys instanceof Map ? publicKeys.get(envelope.keyId) : Object.hasOwn(publicKeys || {}, envelope.keyId) ? publicKeys[envelope.keyId] : null;
  ensure(material, 'UNTRUSTED_SIGNING_KEY');
  let key;
  try { key = typeof material === 'string' ? await crypto.subtle.importKey('spki', fromBase64Url(material, 44), 'Ed25519', false, ['verify']) : material; }
  catch { throw new ProtocolError('INVALID_SIGNING_KEY'); }
  ensure(await crypto.subtle.verify('Ed25519', key, fromBase64Url(envelope.signature, 64), envelopeBytes(envelope, domain)), 'INVALID_SIGNATURE');
  ensure(await deviceIdFromSpki(envelope.payload.devicePublicKeySpki) === envelope.payload.deviceId, 'DEVICE_MISMATCH');
  return envelope.payload;
}
export function ticketProofBytes(ticket) {
  validateEnvelope(ticket, 'ticket');
  return encoder.encode(DOMAINS.deviceProof + canonicalJson(ticket));
}
export async function verifyDeviceProof(ticket, proof) {
  exactKeys(proof, ['algorithm', 'signature']);
  ensure(proof.algorithm === DEVICE_PROOF_ALGORITHM, 'INVALID_PROOF');
  const key = await importDevicePublicKey(ticket.payload.devicePublicKeySpki);
  ensure(await crypto.subtle.verify({ name: 'ECDSA', hash: 'SHA-256' }, key, fromBase64Url(proof.signature, 64), ticketProofBytes(ticket)), 'INVALID_PROOF');
}
