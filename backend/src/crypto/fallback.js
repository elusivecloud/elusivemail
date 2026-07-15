const crypto = require('crypto');

let KEY = null;

const B32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

function init(keyHex) {
  KEY = Buffer.from(String(keyHex).trim(), 'hex');
}

function seal(buf) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', KEY, iv);
  const enc = Buffer.concat([cipher.update(buf), cipher.final()]);
  return Buffer.concat([iv, cipher.getAuthTag(), enc]);
}

function open(raw) {
  const iv = raw.subarray(0, 12);
  const tag = raw.subarray(12, 28);
  const enc = raw.subarray(28);
  const decipher = crypto.createDecipheriv('aes-256-gcm', KEY, iv);
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(enc), decipher.final()]);
}

function encrypt(plaintext) {
  return seal(Buffer.from(String(plaintext ?? ''), 'utf8')).toString('base64');
}
function decrypt(payload) {
  if (!payload) return '';
  return open(Buffer.from(payload, 'base64')).toString('utf8');
}
function encryptBytes(buf) {
  return seal(Buffer.isBuffer(buf) ? buf : Buffer.from(buf));
}
function decryptBytes(payload) {
  return open(Buffer.isBuffer(payload) ? payload : Buffer.from(payload));
}

function sha256Hex(input) {
  return crypto.createHash('sha256').update(String(input)).digest('hex');
}

function base32Decode(s) {
  let bits = '';
  for (const c of s.replace(/=+$/, '').toUpperCase()) {
    const v = B32.indexOf(c);
    if (v >= 0) bits += v.toString(2).padStart(5, '0');
  }
  const bytes = [];
  for (let i = 0; i + 8 <= bits.length; i += 8) bytes.push(parseInt(bits.slice(i, i + 8), 2));
  return Buffer.from(bytes);
}
function hotp(secret, counter) {
  const buf = Buffer.alloc(8);
  buf.writeBigUInt64BE(BigInt(counter));
  const hmac = crypto.createHmac('sha1', base32Decode(secret)).update(buf).digest();
  const offset = hmac[hmac.length - 1] & 0x0f;
  const bin = ((hmac[offset] & 0x7f) << 24) | (hmac[offset + 1] << 16) | (hmac[offset + 2] << 8) | hmac[offset + 3];
  return (bin % 1e6).toString().padStart(6, '0');
}
function totpRandomSecret() {
  const buf = crypto.randomBytes(20);
  let bits = '', out = '';
  for (const b of buf) bits += b.toString(2).padStart(8, '0');
  for (let i = 0; i + 5 <= bits.length; i += 5) out += B32[parseInt(bits.slice(i, i + 5), 2)];
  return out;
}
function totpVerify(secret, code, nowMs) {
  if (!/^\d{6}$/.test(String(code || ''))) return false;
  const s = Math.floor(nowMs / 1000 / 30);
  for (let w = -1; w <= 1; w++) {
    const expected = hotp(secret, s + w);
    if (crypto.timingSafeEqual(Buffer.from(expected), Buffer.from(String(code)))) return true;
  }
  return false;
}
function totpGenerate(secret, nowMs) {
  return hotp(secret, Math.floor(nowMs / 1000 / 30));
}

module.exports = {
  init, encrypt, decrypt, encryptBytes, decryptBytes, sha256Hex,
  totpRandomSecret, totpVerify, totpGenerate,
};
