const nodeCrypto = require('crypto');
const native = require('./native');
const fallback = require('./fallback');
const pgp = require('./pgp');
const prekeys = require('./prekeys');

const primitives = native || fallback;
if (process.env.NODE_ENV === 'production' && !native) {
  console.warn('[crypto] native crypto-core not built; using the JS fallback. Run `npm run build`.');
}

if (!process.env.MASTER_KEY) {
  throw new Error('MASTER_KEY must be set. Generate one with: openssl rand -hex 32');
}
const KEY_HEX = process.env.MASTER_KEY;
if (Buffer.from(KEY_HEX, 'hex').length !== 32) {
  throw new Error('MASTER_KEY must be 64 hex characters (32 bytes). Generate one with: openssl rand -hex 32');
}
primitives.init(KEY_HEX);
const KEY_BUF = Buffer.from(KEY_HEX, 'hex');

const { encrypt, decrypt, encryptBytes, decryptBytes, sha256Hex } = primitives;

function hmacHex(value) {
  return nodeCrypto.createHmac('sha256', KEY_BUF).update(String(value ?? '').toLowerCase()).digest('hex');
}

function encryptJSON(obj) {
  return encrypt(JSON.stringify(obj == null ? {} : obj));
}
function decryptJSON(payload) {
  if (!payload) return {};
  try { return JSON.parse(decrypt(payload)); } catch { return {}; }
}
function encryptInt(n) {
  return encrypt(String(Number(n) || 0));
}
function decryptInt(payload) {
  if (!payload) return 0;
  const s = decrypt(payload);
  const n = Number(s);
  return Number.isFinite(n) ? n : 0;
}

const isE2E = (user) => user && user.enc_mode !== 'auto' && user.public_key;

async function encryptMessage(user, subject, body, from = '', to = '') {
  if (isE2E(user)) {
    const claimed = user.id ? prekeys.claim(user.id) : null;
    const pk = claimed ? claimed.publicKey : user.public_key;
    const encKey = claimed ? `prekey:${claimed.kind}:${claimed.id}` : 'pgp';
    return {
      subject: await pgp.encryptText(pk, subject),
      body: await pgp.encryptText(pk, body),
      from_addr: await pgp.encryptText(pk, from),
      to_addr: await pgp.encryptText(pk, to),
      enc_key: encKey,
    };
  }
  return { subject: encrypt(subject), body: encrypt(body), from_addr: encrypt(from), to_addr: encrypt(to), enc_key: null };
}

async function encryptAttachment(owner, buf) {
  if (isE2E(owner)) {
    const claimed = owner.id ? prekeys.claimSigned(owner.id) : null;
    const pk = claimed ? claimed.publicKey : owner.public_key;
    const encKey = claimed ? `prekey:${claimed.kind}:${claimed.id}` : 'pgp';
    return { data: await pgp.encryptBytes(pk, buf), enc_key: encKey };
  }
  return { data: encryptBytes(buf), enc_key: null };
}

const totp = {
  randomSecret: () => primitives.totpRandomSecret(),
  verify: (secret, code, now = Date.now()) => primitives.totpVerify(secret, String(code || ''), now),
  generate: (secret, now = Date.now()) => primitives.totpGenerate(secret, now),
  otpauthURL: (secret, label, issuer = 'Elusive') =>
    `otpauth://totp/${encodeURIComponent(issuer)}:${encodeURIComponent(label)}?secret=${secret}&issuer=${encodeURIComponent(issuer)}`,
};

module.exports = {
  encrypt, decrypt, encryptBytes, decryptBytes, sha256Hex,
  hmacHex, encryptJSON, decryptJSON, encryptInt, decryptInt,
  encryptMessage, encryptAttachment, totp,
  usingNative: !!native,
};
