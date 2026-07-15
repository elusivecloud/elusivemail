const assert = require('assert');
const fs = require('fs');
const path = require('path');

process.env.ELUSIVE_DB = path.join(__dirname, 'test-account.db');
for (const f of [process.env.ELUSIVE_DB, `${process.env.ELUSIVE_DB}-wal`, `${process.env.ELUSIVE_DB}-shm`]) {
  fs.rmSync(f, { force: true });
}

process.env.MASTER_KEY = process.env.MASTER_KEY || require('crypto').randomBytes(32).toString('hex');
process.env.SESSION_SECRET = process.env.SESSION_SECRET || require('crypto').randomBytes(32).toString('hex');

const openpgp = require('openpgp');
const { createApp } = require('../src/app');
const db = require('../src/db');
const { sha256Hex, encrypt, encryptBytes, hmacHex, encryptJSON, encryptInt } = require('../src/crypto');

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

const deriveAuth = (username, password) => sha256Hex(`${username.toLowerCase()}:${password}`); // must match the frontend's derivation exactly, or this test lies

async function main() {
  const server = createApp().listen(0);
  const base = `http://127.0.0.1:${server.address().port}`;

  const { publicKey, privateKey } = await openpgp.generateKey({
    type: 'ecc', curve: 'curve25519', userIDs: [{ name: 'test' }], format: 'armored',
  });

  const rawPassword = 'hunter2hunter2';
  const joinBody = {
    username: 'accttest', password: deriveAuth('accttest', rawPassword), tos: true,
    publicKey, encPrivateKey: privateKey, encPrivateKeyRecovery: privateKey, recoveryHash: sha256Hex('recovery-code'),
  };
  let r = await api(base, 'POST', '/api/join', joinBody);
  assert.strictEqual(r.status, 200, `join failed: ${JSON.stringify(r.data)}`);

  const csrf = (await api(base, 'GET', '/api/me')).data.csrf;

  const addrId = db.prepare(`SELECT id FROM addresses WHERE local_part_hmac = ?`).get(hmacHex('accttest')).id;
  const userId = db.prepare(`SELECT id FROM users WHERE username_hmac = ?`).get(hmacHex('accttest')).id;
  const msgId = db.prepare(
    `INSERT INTO messages (address_id, direction, from_addr, to_addr, subject, body, enc_key, meta_enc, received_at_enc)
     VALUES (?, 'in', ?, ?, ?, ?, NULL, ?, ?)`
  ).run(addrId, encrypt('sender@example.com'), encrypt('accttest@elusive.local'), encrypt('hello subject'), encrypt('hello body'), encryptJSON({ is_read: 0, is_junk: 0, folder_id: null, auth_fail: 0 }), encryptInt(Date.now())).lastInsertRowid;
  const attPlain = Buffer.from('exportable attachment bytes');
  const attId = db.prepare(
    `INSERT INTO attachments (message_id, filename, mime, size, enc_key, data) VALUES (?, ?, ?, ?, NULL, ?)`
  ).run(msgId, encrypt('f.txt'), encrypt('text/plain'), attPlain.length, encryptBytes(attPlain)).lastInsertRowid;

  r = await api(base, 'GET', '/api/account/export');
  assert.strictEqual(r.status, 200, `export failed: ${JSON.stringify(r.data)}`);
  const exp = r.data;

  assert.strictEqual(exp.user.username, 'accttest');
  assert.strictEqual(exp.user.password_hash, undefined, 'export must never include password_hash');
  assert.strictEqual(exp.user.recovery_hash, undefined, 'export must never include recovery_hash');
  assert.strictEqual(exp.user.totp_secret, undefined, 'export must never include totp_secret');
  assert.strictEqual(exp.user.totp_backup, undefined, 'export must never include totp_backup');
  assert.strictEqual(exp.user.public_key, publicKey, 'export should include the public key');
  assert.strictEqual(exp.user.enc_private_key, privateKey, 'export should include the locked private key blob');

  const expMsg = exp.messages.find((m) => m.id === msgId);
  assert.ok(expMsg, 'exported message must round-trip');
  assert.strictEqual(expMsg.subject, 'hello subject');
  assert.strictEqual(expMsg.body, 'hello body');
  assert.strictEqual(expMsg.from_addr, 'sender@example.com');

  const expAtt = exp.attachments.find((a) => a.id === attId);
  assert.ok(expAtt, 'exported attachment must round-trip');
  assert.strictEqual(expAtt.filename, 'f.txt');
  assert.strictEqual(Buffer.from(expAtt.data, 'base64').toString(), 'exportable attachment bytes', 'attachment bytes round-trip through export');

  r = await api(base, 'POST', '/api/account/delete', { password: deriveAuth('accttest', 'wrong-password') }, csrf);
  assert.ok(r.status === 401 || r.status === 400, `wrong password should be rejected, got ${r.status}`);

  r = await api(base, 'POST', '/api/account/delete', { password: deriveAuth('accttest', rawPassword) }, csrf);
  assert.strictEqual(r.status, 200, `delete failed: ${JSON.stringify(r.data)}`);
  assert.strictEqual(r.data.ok, true);

  assert.strictEqual(db.prepare('SELECT COUNT(*) n FROM users WHERE id = ?').get(userId).n, 0, 'user row must be gone');
  assert.strictEqual(db.prepare('SELECT COUNT(*) n FROM addresses WHERE user_id = ?').get(userId).n, 0, 'addresses must be gone');
  assert.strictEqual(db.prepare('SELECT COUNT(*) n FROM messages WHERE id = ?').get(msgId).n, 0, 'messages must be gone');
  assert.strictEqual(db.prepare('SELECT COUNT(*) n FROM attachments WHERE id = ?').get(attId).n, 0, 'attachments must be gone');
  assert.strictEqual(db.prepare('SELECT COUNT(*) n FROM prekeys WHERE user_id = ?').get(userId).n, 0, 'prekeys must be gone');
  assert.strictEqual(db.prepare('SELECT COUNT(*) n FROM groups WHERE user_id = ?').get(userId).n, 0, 'groups must be gone');
  assert.strictEqual(db.prepare('SELECT COUNT(*) n FROM folders WHERE user_id = ?').get(userId).n, 0, 'folders must be gone');

  r = await api(base, 'GET', '/api/me');
  assert.strictEqual(r.status, 401, 'session must be dead after account deletion');

  server.close();
  console.log('account-check: all assertions passed');
  process.exit(0);
}

main().catch((e) => { console.error(e); process.exit(1); });
