const assert = require('assert');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const Database = require('better-sqlite3');

process.env.ELUSIVE_DB = path.join(__dirname, 'test-upgrade.db');
for (const f of [process.env.ELUSIVE_DB, `${process.env.ELUSIVE_DB}-wal`, `${process.env.ELUSIVE_DB}-shm`]) {
  fs.rmSync(f, { force: true });
}

process.env.MASTER_KEY = process.env.MASTER_KEY || crypto.randomBytes(32).toString('hex');
process.env.SESSION_SECRET = process.env.SESSION_SECRET || crypto.randomBytes(32).toString('hex');

const B32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
function randomBase32Secret() {
  const buf = crypto.randomBytes(20);
  let bits = '', out = '';
  for (const b of buf) bits += b.toString(2).padStart(8, '0');
  for (let i = 0; i + 5 <= bits.length; i += 5) out += B32[parseInt(bits.slice(i, i + 5), 2)];
  return out;
}

const USERNAME = 'upgradetest';
const EMAIL = 'upgradetest@elusive.local';
const RAW_PASSWORD = 'hunter2hunter2';
const RECOVERY_CODE = 'upgrade-recovery';
const PROOF = crypto.createHash('sha256').update(RECOVERY_CODE).digest('hex'); // client-sent value
const TOTP_SECRET = randomBase32Secret();
const SEEDED_RECEIVED_AT = Date.now();
const SEEDED_CREATED_AT = Date.now();

const openpgp = require('openpgp');
const bcrypt = require('bcrypt');
// safe to require early, src/crypto doesn't pull in src/db, so this can't trigger the v4 migration early
const { encrypt, sha256Hex, hmacHex } = require('../src/crypto');

async function setup() {
  const keypair = await openpgp.generateKey({
    type: 'ecc', curve: 'curve25519', userIDs: [{ name: 'upgrade' }], format: 'armored',
  });
  const seed = Database(process.env.ELUSIVE_DB);
  seed.pragma('journal_mode = WAL');

  seed.exec(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE NOT NULL,
      email TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      nickname TEXT NOT NULL DEFAULT '',
      created_at INTEGER NOT NULL,
      enc_mode TEXT NOT NULL DEFAULT 'auto',
      public_key TEXT,
      enc_private_key TEXT,
      enc_private_key_recovery TEXT,
      recovery_hash TEXT,
      totp_secret TEXT,
      totp_enabled INTEGER NOT NULL DEFAULT 0,
      totp_backup TEXT,
      session_epoch INTEGER NOT NULL DEFAULT 0,
      onboarded INTEGER NOT NULL DEFAULT 1,
      is_admin INTEGER NOT NULL DEFAULT 0,
      suspended INTEGER NOT NULL DEFAULT 0
    );
    CREATE TABLE IF NOT EXISTS invite_codes (code TEXT PRIMARY KEY, used_by INTEGER REFERENCES users(id));
    CREATE TABLE IF NOT EXISTS addresses (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL REFERENCES users(id),
      local_part TEXT UNIQUE NOT NULL,
      is_temp INTEGER NOT NULL DEFAULT 0,
      expires_at INTEGER,
      created_at INTEGER NOT NULL,
      burn_on_read INTEGER NOT NULL DEFAULT 0,
      group_id INTEGER
    );
    CREATE TABLE IF NOT EXISTS groups (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL REFERENCES users(id), name TEXT NOT NULL, created_at INTEGER NOT NULL, color TEXT);
    CREATE TABLE IF NOT EXISTS messages (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      address_id INTEGER NOT NULL REFERENCES addresses(id),
      direction TEXT NOT NULL CHECK (direction IN ('in', 'out')),
      from_addr TEXT NOT NULL,
      to_addr TEXT NOT NULL,
      subject TEXT NOT NULL DEFAULT '',
      body TEXT NOT NULL DEFAULT '',
      is_read INTEGER NOT NULL DEFAULT 0,
      received_at INTEGER NOT NULL,
      enc_key TEXT,
      folder_id INTEGER,
      is_junk INTEGER NOT NULL DEFAULT 0,
      auth_fail INTEGER NOT NULL DEFAULT 0
    );
    CREATE INDEX IF NOT EXISTS idx_messages_address ON messages(address_id);
    CREATE TABLE IF NOT EXISTS attachments (id INTEGER PRIMARY KEY AUTOINCREMENT, message_id INTEGER NOT NULL REFERENCES messages(id), filename TEXT NOT NULL, mime TEXT NOT NULL DEFAULT 'application/octet-stream', size INTEGER NOT NULL, enc_key TEXT, data BLOB NOT NULL);
    CREATE INDEX IF NOT EXISTS idx_attachments_message ON attachments(message_id);
    CREATE TABLE IF NOT EXISTS folders (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL REFERENCES users(id), name TEXT NOT NULL, created_at INTEGER NOT NULL);
    CREATE TABLE IF NOT EXISTS prekeys (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL REFERENCES users(id), kind TEXT NOT NULL CHECK (kind IN ('onetime', 'signed')), public_key TEXT NOT NULL, enc_private_key TEXT NOT NULL, used INTEGER NOT NULL DEFAULT 0, created_at INTEGER NOT NULL);
    CREATE INDEX IF NOT EXISTS idx_prekeys_claim ON prekeys(user_id, kind, used);
    CREATE TABLE IF NOT EXISTS reserved_names (name TEXT PRIMARY KEY);
  `);

  const passwordHash = bcrypt.hashSync(RAW_PASSWORD, 12);
  const { lastInsertRowid: userId } = seed.prepare(
    `INSERT INTO users (username, email, password_hash, created_at, totp_secret, totp_enabled, enc_mode, public_key, enc_private_key, enc_private_key_recovery, recovery_hash)
     VALUES (?, ?, ?, ?, ?, 1, 'private', ?, ?, ?, ?)`
  ).run(USERNAME, EMAIL, passwordHash, SEEDED_CREATED_AT, encrypt(TOTP_SECRET), keypair.publicKey, keypair.privateKey, keypair.privateKey, sha256Hex(PROOF));

  const { lastInsertRowid: addressId } = seed.prepare(
    `INSERT INTO addresses (user_id, local_part, is_temp, created_at) VALUES (?, ?, 0, ?)`
  ).run(userId, USERNAME, SEEDED_CREATED_AT);

  seed.prepare(
    `INSERT INTO messages (address_id, direction, from_addr, to_addr, subject, body, is_read, is_junk, folder_id, auth_fail, received_at)
     VALUES (?, 'in', ?, ?, ?, ?, 0, 0, NULL, 0, ?)`
  ).run(addressId, encrypt('sender@example.com'), encrypt(`${USERNAME}@elusive.local`), encrypt('hello subject'), encrypt('hello body'), SEEDED_RECEIVED_AT);

  seed.pragma('user_version = 3');
  seed.close();
  return keypair;
}

const jar = {};
async function api(base, method, urlPath, body, csrf) {
  const res = await fetch(base + urlPath, {
    method,
    headers: {
      'content-type': 'application/json',
      cookie: Object.entries(jar).map(([k, v]) => `${k}=${v}`).join('; '),
      ...(csrf ? { 'x-csrf-token': csrf } : {}),
    },
    body: body ? JSON.stringify(body) : undefined,
  });
  for (const sc of res.headers.getSetCookie()) {
    const [pair] = sc.split(';');
    const i = pair.indexOf('=');
    jar[pair.slice(0, i)] = pair.slice(i + 1);
  }
  return { status: res.status, data: await res.json().catch(() => ({})) };
}

function assertSelectThrows(label, sql) {
  let threw = false;
  try { db.prepare(sql).get(); } catch (e) { threw = true; }
  assert.ok(threw, `${label}: referencing a dropped column must throw: ${sql}`);
}

let db;
async function main() {
  const keypair = await setup();

  db = require('../src/db'); // this require is the actual migration run, v1-v3 skip since we're already at 3
  const { totp, decrypt, decryptJSON, decryptInt } = require('../src/crypto');
  const { createApp } = require('../src/app');

  const server = createApp().listen(0);
  const base = `http://127.0.0.1:${server.address().port}`;

  assert.strictEqual(db.pragma('user_version', { simple: true }), 4, 'user_version must be 4 after upgrade');

  const user = db.prepare('SELECT username, email, username_hmac, email_hmac, created_at_enc FROM users WHERE id = 1').get();
  const addr = db.prepare('SELECT id, local_part, local_part_hmac, created_at_enc FROM addresses WHERE user_id = 1').get();
  const msg = db.prepare('SELECT meta_enc, received_at_enc FROM messages WHERE address_id = ?').get(addr.id);

  assert.notStrictEqual(user.username, USERNAME, 'username column must be ciphertext post-migration');
  assert.strictEqual(decrypt(user.username), USERNAME, 'decrypted username must round-trip');
  assert.strictEqual(user.username_hmac, hmacHex(USERNAME), 'username_hmac must be the keyed HMAC of the username');
  assert.notStrictEqual(user.email, EMAIL, 'email column must be ciphertext post-migration');
  assert.strictEqual(decrypt(user.email), EMAIL, 'decrypted email must round-trip');
  assert.strictEqual(user.email_hmac, hmacHex(EMAIL), 'email_hmac must be the keyed HMAC of the email');
  assert.notStrictEqual(addr.local_part, USERNAME, 'local_part column must be ciphertext post-migration');
  assert.strictEqual(decrypt(addr.local_part), USERNAME, 'decrypted local_part must round-trip');
  assert.strictEqual(addr.local_part_hmac, hmacHex(USERNAME), 'local_part_hmac must be the keyed HMAC of the local_part');

  assertSelectThrows('users.created_at', 'SELECT created_at FROM users LIMIT 1');
  assertSelectThrows('addresses.created_at', 'SELECT created_at FROM addresses LIMIT 1');
  assertSelectThrows('messages.is_read', 'SELECT is_read FROM messages LIMIT 1');
  assertSelectThrows('messages.is_junk', 'SELECT is_junk FROM messages LIMIT 1');
  assertSelectThrows('messages.folder_id', 'SELECT folder_id FROM messages LIMIT 1');
  assertSelectThrows('messages.auth_fail', 'SELECT auth_fail FROM messages LIMIT 1');
  assertSelectThrows('messages.received_at', 'SELECT received_at FROM messages LIMIT 1');

  assert.deepStrictEqual(decryptJSON(msg.meta_enc), { is_read: 0, is_junk: 0, folder_id: null, auth_fail: 0 },
    'meta_enc must decrypt to the folded read/junk/folder/auth_fail state');
  assert.strictEqual(decryptInt(msg.received_at_enc), SEEDED_RECEIVED_AT, 'received_at_enc must round-trip the seeded timestamp');
  assert.strictEqual(decryptInt(user.created_at_enc), SEEDED_CREATED_AT, 'user created_at_enc must round-trip');
  assert.strictEqual(decryptInt(addr.created_at_enc), SEEDED_CREATED_AT, 'address created_at_enc must round-trip');

  let r = await api(base, 'POST', '/api/login', { username: USERNAME, password: RAW_PASSWORD });
  assert.strictEqual(r.status, 401, 'login without totp code must be rejected');
  assert.strictEqual(r.data.totpRequired, true, 'login without totp must flag totpRequired');

  const code = totp.generate(TOTP_SECRET);
  r = await api(base, 'POST', '/api/login', { username: USERNAME, password: RAW_PASSWORD, totpCode: code });
  assert.strictEqual(r.status, 200, `login with totp failed: ${JSON.stringify(r.data)}`);

  const inbox = await api(base, 'GET', `/api/mail/inbox/${addr.id}`);
  assert.strictEqual(inbox.status, 200, `inbox fetch failed: ${JSON.stringify(inbox.data)}`);
  const m = inbox.data.messages[0];
  assert.ok(m, 'seeded message must appear in the inbox');
  assert.strictEqual(m.from_addr, 'sender@example.com', 'from_addr must round-trip after v4');
  assert.strictEqual(m.subject, 'hello subject', 'subject must round-trip');
  assert.strictEqual(m.body, 'hello body', 'body must round-trip');
  assert.strictEqual(m.is_read, 0, 'is_read must survive the v4 fold');
  assert.strictEqual(m.received_at, SEEDED_RECEIVED_AT, 'received_at must survive the v4 fold');

  // exercises verifyRecovery's legacy (non-bcrypt) branch specifically
  r = await api(base, 'POST', '/api/recover', {
    username: USERNAME, recoveryProof: PROOF,
    newPassword: 'newpassword123', newEncPrivateKey: keypair.privateKey,
  });
  assert.strictEqual(r.status, 200, `recover failed: ${JSON.stringify(r.data)}`);

  const after = db.prepare('SELECT recovery_hash, totp_enabled, totp_secret FROM users WHERE id = 1').get();
  assert.ok(String(after.recovery_hash).startsWith('$2'), 'recovery_hash must be upgraded to bcrypt ($2...) on legacy match');

  assert.strictEqual(after.totp_enabled, 0, 'recovery must disable 2FA');
  assert.strictEqual(after.totp_secret, null, 'recovery must clear totp_secret');

  r = await api(base, 'POST', '/api/login', { username: USERNAME, password: 'newpassword123' });
  assert.strictEqual(r.status, 200, `post-recovery login (no totp) failed: ${JSON.stringify(r.data)}`);

  server.close();
  console.log('upgrade-check: all assertions passed');
  process.exit(0);
}

main().catch((e) => { console.error(e); process.exit(1); });
