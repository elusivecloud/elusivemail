const assert = require('assert');
const fs = require('fs');
const path = require('path');

process.env.ELUSIVE_DB = path.join(__dirname, 'test-security.db');
for (const f of [process.env.ELUSIVE_DB, `${process.env.ELUSIVE_DB}-wal`, `${process.env.ELUSIVE_DB}-shm`]) {
  fs.rmSync(f, { force: true });
}

process.env.MASTER_KEY = process.env.MASTER_KEY || require('crypto').randomBytes(32).toString('hex');
process.env.SESSION_SECRET = process.env.SESSION_SECRET || require('crypto').randomBytes(32).toString('hex');

const openpgp = require('openpgp');
const { createApp } = require('../src/app');
const db = require('../src/db');
const { sha256Hex, totp, encrypt, encryptBytes, decryptBytes, hmacHex, encryptJSON, encryptInt, decryptInt } = require('../src/crypto');
const { wkdHash } = require('../src/wkd');
const bcrypt = require('bcrypt');

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

async function main() {
  const server = createApp().listen(0);
  const base = `http://127.0.0.1:${server.address().port}`;

  const { publicKey, privateKey } = await openpgp.generateKey({
    type: 'ecc', curve: 'curve25519', userIDs: [{ name: 'test' }], format: 'armored',
  });

  const recoveryCode = 'test-recovery-code';
  const proof = sha256Hex(recoveryCode);
  const joinBody = {
    username: 'sectest', password: 'hunter2hunter2', tos: true,
    publicKey, encPrivateKey: privateKey, encPrivateKeyRecovery: privateKey, recoveryHash: proof,
  };

  let r = await api(base, 'POST', '/api/join', { ...joinBody, username: 'sectest2', publicKey: 'not a key' });
  assert.strictEqual(r.status, 400, 'garbage publicKey should be rejected');

  r = await api(base, 'POST', '/api/join', joinBody);
  assert.strictEqual(r.status, 200, `join failed: ${JSON.stringify(r.data)}`);

  const stored = db.prepare(`SELECT recovery_hash FROM users WHERE username_hmac = ?`).get(hmacHex('sectest')).recovery_hash;
  assert.notStrictEqual(stored, proof, 'DB must not store the recovery proof');
  assert.ok(stored.startsWith('$2'), 'DB must store a bcrypt hash, not the raw sha256 proof');
  assert.ok(bcrypt.compareSync(sha256Hex(proof), stored), 'bcrypt(sha256(proof)) verifies the proof');

  let csrf = (await api(base, 'GET', '/api/me')).data.csrf;
  r = await api(base, 'POST', '/api/2fa/setup', {}, csrf);
  assert.strictEqual(r.status, 200);
  const secret = r.data.secret;
  r = await api(base, 'POST', '/api/2fa/enable', { code: totp.generate(secret) }, csrf);
  assert.strictEqual(r.status, 200, `2fa enable failed: ${JSON.stringify(r.data)}`);
  assert.ok(r.data.backupCodes.every((c) => c.length === 20), 'backup codes are 10 bytes (20 hex chars)');
  const backup = r.data.backupCodes[0];
  r = await api(base, 'POST', '/api/2fa/setup', {}, csrf);
  assert.strictEqual(r.status, 400, '2fa setup while enabled must require a code');
  r = await api(base, 'POST', '/api/2fa/setup', { code: backup }, csrf);
  assert.strictEqual(r.status, 200, 'backup code should authorize re-setup');

  r = await api(base, 'POST', '/api/recover', {
    username: 'sectest', recoveryProof: proof, newPassword: 'newpassword123', newEncPrivateKey: privateKey,
  });
  assert.strictEqual(r.status, 200, `recover failed: ${JSON.stringify(r.data)}`);
  r = await api(base, 'GET', '/api/me');
  assert.strictEqual(r.status, 401, 'recover must invalidate existing sessions');
  r = await api(base, 'POST', '/api/recover', {
    username: 'sectest', recoveryProof: 'wrong', newPassword: 'newpassword123', newEncPrivateKey: privateKey,
  });
  assert.strictEqual(r.status, 401, 'wrong proof must fail');

  // simulates what v3 does to a legacy row, don't skip this, it's the only
  // thing that catches a broken migration before it hits real accounts
  db.prepare(`UPDATE users SET recovery_hash = ? WHERE username_hmac = ?`).run(proof, hmacHex('sectest')); // legacy format
  db.prepare(`UPDATE users SET recovery_hash = ? WHERE username_hmac = ?`).run(sha256Hex(proof), hmacHex('sectest')); // what v3 does
  r = await api(base, 'POST', '/api/recover', {
    username: 'sectest', recoveryProof: proof, newPassword: 'newpassword123', newEncPrivateKey: privateKey,
  });
  assert.strictEqual(r.status, 200, 'migrated legacy recovery code must still work');

  r = await api(base, 'POST', '/api/login', { username: 'sectest', password: 'newpassword123' });
  assert.strictEqual(r.status, 200, `re-login failed: ${JSON.stringify(r.data)}`);
  csrf = (await api(base, 'GET', '/api/me')).data.csrf;

  const addrId = db.prepare(`SELECT id FROM addresses WHERE local_part_hmac = ?`).get(hmacHex('sectest')).id;
  const msgId = db.prepare(
    `INSERT INTO messages (address_id, direction, from_addr, to_addr, subject, body, enc_key, meta_enc, received_at_enc)
     VALUES (?, 'in', ?, ?, ?, ?, NULL, ?, ?)`
  ).run(addrId, encrypt('a@b'), encrypt('sectest@elusive.local'), encrypt('subj'), encrypt('body'), encryptJSON({ is_read: 0, is_junk: 0, folder_id: null, auth_fail: 0 }), encryptInt(Date.now())).lastInsertRowid;
  const attPlain = Buffer.from('hello attachment');
  const attId = db.prepare(
    `INSERT INTO attachments (message_id, filename, mime, size, enc_key, data) VALUES (?, ?, ?, ?, NULL, ?)`
  ).run(msgId, encrypt('f.txt'), encrypt('text/plain'), attPlain.length, encryptBytes(attPlain)).lastInsertRowid;
  r = await api(base, 'POST', '/api/enc/disable-e2e', { messages: [], attachments: [] }, csrf);
  assert.strictEqual(r.status, 200, `disable-e2e (empty) failed: ${JSON.stringify(r.data)}`);

  const kp = await openpgp.generateKey({ type: 'ecc', curve: 'curve25519', userIDs: [{ name: 'e2e' }], format: 'armored' });
  r = await api(base, 'POST', '/api/enc/enable-e2e', { custody: 'keyfile', publicKey: kp.publicKey }, csrf);
  assert.strictEqual(r.status, 200, `enable-e2e failed: ${JSON.stringify(r.data)}`);
  let att = db.prepare('SELECT enc_key, data FROM attachments WHERE id = ?').get(attId);
  assert.strictEqual(att.enc_key, 'pgp', 'attachment must be re-encrypted to PGP on enable');
  const priv = await openpgp.readPrivateKey({ armoredKey: kp.privateKey });
  const dec = await openpgp.decrypt({
    message: await openpgp.readMessage({ binaryMessage: new Uint8Array(att.data) }),
    decryptionKeys: priv, format: 'binary',
  });
  assert.strictEqual(Buffer.from(dec.data).toString(), 'hello attachment', 'attachment survives enable-e2e');

  r = await api(base, 'POST', '/api/enc/disable-e2e', { messages: [{ id: msgId, subject: 's', body: 'b', from: 'a@b', to: 'c@d' }] }, csrf);
  assert.strictEqual(r.status, 400, 'disable-e2e must refuse when attachment plaintext is missing');
  r = await api(base, 'POST', '/api/enc/disable-e2e', {
    messages: [{ id: msgId, subject: 's', body: 'b', from: 'a@b', to: 'c@d' }],
    attachments: [{ id: attId, data: attPlain.toString('base64') }],
  }, csrf);
  assert.strictEqual(r.status, 200, `disable-e2e failed: ${JSON.stringify(r.data)}`);
  att = db.prepare('SELECT enc_key, data FROM attachments WHERE id = ?').get(attId);
  assert.strictEqual(att.enc_key, null);
  assert.strictEqual(decryptBytes(att.data).toString(), 'hello attachment', 'attachment survives disable-e2e');

  r = await api(base, 'POST', '/api/enc/enable-e2e', { custody: 'keyfile', publicKey: kp.publicKey }, csrf);
  assert.strictEqual(r.status, 200);
  r = await api(base, 'POST', '/api/mail/addresses', { localPart: 'burner123', isTemp: true }, csrf);
  assert.strictEqual(r.status, 200, `temp address failed: ${JSON.stringify(r.data)}`);
  let wk = await fetch(`${base}/.well-known/openpgpkey/hu/${wkdHash('sectest')}`);
  assert.strictEqual(wk.status, 200, 'WKD must serve the master address key');
  wk = await fetch(`${base}/.well-known/openpgpkey/hu/${wkdHash('burner123')}`);
  assert.strictEqual(wk.status, 404, 'WKD must never serve temp alias keys');

  r = await api(base, 'DELETE', `/api/mail/message/${msgId}`, null, csrf);
  assert.strictEqual(r.status, 200);
  assert.strictEqual(db.prepare('SELECT COUNT(*) n FROM attachments WHERE message_id = ?').get(msgId).n, 0,
    'attachments must be deleted with their message');
  assert.strictEqual(db.pragma('secure_delete', { simple: true }), 1, 'secure_delete must be on');

  server.close();
  console.log('security-check: all assertions passed');
  process.exit(0);
}

main().catch((e) => { console.error(e); process.exit(1); });
