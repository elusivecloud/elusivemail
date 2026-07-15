const crypto = require('crypto');
const express = require('express');
const bcrypt = require('bcrypt');
const rateLimit = require('express-rate-limit');
const openpgp = require('openpgp');
const db = require('../db');
const { DOMAIN, MASTER_LIMIT, isReserved } = require('../config');
const { encrypt, decrypt, encryptBytes, decryptBytes, sha256Hex, totp, encryptMessage, hmacHex, decryptInt, encryptInt } = require('../crypto');
const pgp = require('../crypto/pgp');
const prekeys = require('../crypto/prekeys');
const { publicUser, requireAuth } = require('./middleware');
const { asyncHandler } = require('../async');

const router = express.Router();

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 10,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'too many attempts, try again later' },
});

const loginKey = (raw) => {
  const s = String(raw || '').trim().toLowerCase();
  const at = s.lastIndexOf('@');
  return at > 0 ? s.slice(0, at) : s;
};

const DUMMY_HASH = bcrypt.hashSync('unused-enumeration-guard', 12);

const recoveryLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 5,
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) => `${req.body?.username || ''}|${req.ip}`,
  message: { error: 'too many recovery attempts, try again later' },
});

const isArmored = (v) => typeof v === 'string' && v.startsWith('-----BEGIN PGP');

const hashProof = (proof) => bcrypt.hashSync(sha256Hex(String(proof)), 12);

function verifyRecovery(proof, stored) {
  if (!stored) return { match: false, upgrade: false };
  if (stored.startsWith('$2')) {
    return { match: bcrypt.compareSync(sha256Hex(String(proof)), stored), upgrade: false };
  }
  const a = Buffer.from(sha256Hex(String(proof)));
  const b = Buffer.from(String(stored));
  const match = a.length === b.length && crypto.timingSafeEqual(a, b);
  return { match, upgrade: match };
}

async function validPublicKey(armored) {
  try {
    await openpgp.readKey({ armoredKey: String(armored) });
    return true;
  } catch {
    return false;
  }
}

function allMessagesOf(userId) {
  return db.prepare(
    `SELECT id, subject, body, from_addr, to_addr, enc_key FROM messages
      WHERE address_id IN (SELECT id FROM addresses WHERE user_id = ?)`
  ).all(userId);
}

const ATTS_OF = `at.message_id IN (SELECT id FROM messages WHERE address_id IN (SELECT id FROM addresses WHERE user_id = ?))`;

function genBackupCodes() {
  return Array.from({ length: 8 }, () => crypto.randomBytes(10).toString('hex'));
}
function hashBackup(code) {
  return sha256Hex(String(code).replace(/[\s-]/g, '').toLowerCase());
}
function consumeBackupCode(userId, code) {
  return db.transaction(() => {
    const row = db.prepare('SELECT totp_backup FROM users WHERE id = ?').get(userId);
    let hashes;
    try { hashes = JSON.parse(row.totp_backup || '[]'); } catch { return false; }
    const i = hashes.indexOf(hashBackup(code));
    if (i === -1) return false;
    hashes.splice(i, 1);
    db.prepare('UPDATE users SET totp_backup = ? WHERE id = ?').run(JSON.stringify(hashes), userId);
    return true;
  })();
}

router.post('/api/join', authLimiter, asyncHandler(async (req, res) => {
  const { username, password, tos, publicKey, encPrivateKey, encPrivateKeyRecovery, recoveryHash } = req.body || {};

  if (!username || !password || !tos) return res.status(400).json({ error: 'all fields are required' });
  if (String(password).length < 10) return res.status(400).json({ error: 'password must be at least 10 characters' });
  if (!/^[a-z0-9_.-]{3,20}$/i.test(username)) {
    return res.status(400).json({ error: 'username must be 3-20 chars: letters, numbers, . _ -' });
  }
  if (isReserved(username)) return res.status(400).json({ error: 'that username is reserved' });
  if (!publicKey || !encPrivateKey || !encPrivateKeyRecovery || !recoveryHash) {
    return res.status(400).json({ error: 'end-to-end key material is required' });
  }
  if (!(await validPublicKey(publicKey))) return res.status(400).json({ error: 'unreadable public key' });

  const email = `${username.toLowerCase()}@${DOMAIN}`;
  const uHmac = hmacHex(username);
  const eHmac = hmacHex(email);
  if (db.prepare('SELECT id FROM users WHERE username_hmac = ? OR email_hmac = ?').get(uHmac, eHmac)) {
    return res.status(409).json({ error: 'username or email already taken' });
  }

  const passwordHash = bcrypt.hashSync(password, 12);
  const insertUser = db.prepare(
    `INSERT INTO users (username, email, username_hmac, email_hmac, password_hash, created_at_enc, onboarded, enc_mode, public_key, enc_private_key, enc_private_key_recovery, recovery_hash)
     VALUES (?, ?, ?, ?, ?, ?, 0, 'private', ?, ?, ?, ?)`
  );
  const userId = db.transaction(() => {
    const info = insertUser.run(encrypt(username), encrypt(email), uHmac, eHmac, passwordHash, encryptInt(Date.now()), publicKey, encPrivateKey, encPrivateKeyRecovery, hashProof(recoveryHash));
    const lp = username.toLowerCase();
    db.prepare('INSERT INTO addresses (user_id, local_part, local_part_hmac, is_temp, created_at_enc) VALUES (?, ?, ?, 0, ?)')
      .run(info.lastInsertRowid, encrypt(lp), hmacHex(lp), encryptInt(Date.now()));
    return info.lastInsertRowid;
  })();

  const user = db.prepare('SELECT id, username, email FROM users WHERE id = ?').get(userId);
  req.session.userId = user.id;
  req.session.epoch = 0;
  req.session.lastSeen = Date.now();
  res.json({ ok: true, user: publicUser(user) });
}));

router.post('/api/login', authLimiter, (req, res) => {
  const { username, password } = req.body || {};
  if (!username || !password) return res.status(400).json({ error: 'username/email and password are required' });

  const user = db.prepare('SELECT * FROM users WHERE username_hmac = ?').get(hmacHex(loginKey(username)));
  const hash = user ? user.password_hash : DUMMY_HASH;
  const valid = bcrypt.compareSync(password, hash) && !!user;
  if (!valid) return res.status(401).json({ error: 'invalid credentials' });
  if (user.suspended) return res.status(403).json({ error: 'this account has been suspended' });

  if (user.totp_enabled) {
    const code = req.body?.totpCode;
    if (!code) return res.status(401).json({ error: '2fa required', totpRequired: true });
    const ok2fa = totp.verify(decrypt(user.totp_secret), code) || consumeBackupCode(user.id, code);
    if (!ok2fa) return res.status(401).json({ error: 'invalid 2fa code', totpRequired: true });
  }

  req.session.userId = user.id;
  req.session.epoch = user.session_epoch;
  req.session.lastSeen = Date.now();
  res.json({ ok: true, user: publicUser(user), encMode: user.enc_mode, encPrivateKey: user.enc_private_key });
});

router.post('/api/recover/challenge', recoveryLimiter, (req, res) => {
  const username = String(req.body?.username ?? '');
  const user = db.prepare('SELECT enc_mode, enc_private_key_recovery FROM users WHERE username_hmac = ?').get(hmacHex(loginKey(username)));
  if (!user || user.enc_mode !== 'private' || !user.enc_private_key_recovery) {
    return res.status(404).json({ error: 'no recovery available for this account' });
  }
  res.json({ encPrivateKeyRecovery: user.enc_private_key_recovery });
});

router.post('/api/recover', recoveryLimiter, (req, res) => {
  const { username, recoveryProof, newPassword, newEncPrivateKey } = req.body || {};
  if (!username || !recoveryProof || !newPassword || !newEncPrivateKey) {
    return res.status(400).json({ error: 'all fields are required' });
  }
  if (String(newPassword).length < 10) return res.status(400).json({ error: 'password must be at least 10 characters' });

  const user = db.prepare('SELECT id, recovery_hash FROM users WHERE username_hmac = ?').get(hmacHex(loginKey(username)));
  const stored = user?.recovery_hash || '';
  const { match, upgrade } = verifyRecovery(recoveryProof, stored);
  if (!user || !stored || !match) return res.status(401).json({ error: 'invalid recovery code' });

  const passwordHash = bcrypt.hashSync(String(newPassword), 12);
  const recoveryHash = upgrade ? hashProof(recoveryProof) : null;
  db.prepare(
    `UPDATE users SET password_hash = ?, enc_private_key = ?, session_epoch = session_epoch + 1,
      totp_secret = NULL, totp_enabled = 0, totp_backup = NULL${recoveryHash ? ', recovery_hash = ?' : ''} WHERE id = ?`
  ).run(
    ...(recoveryHash ? [passwordHash, String(newEncPrivateKey), recoveryHash, user.id]
      : [passwordHash, String(newEncPrivateKey), user.id])
  );
  res.json({ ok: true });
});

router.post('/api/recovery/regenerate', requireAuth, (req, res) => {
  const user = db.prepare('SELECT enc_mode FROM users WHERE id = ?').get(req.session.userId);
  if (user.enc_mode !== 'private') return res.status(400).json({ error: 'recovery codes apply to accounts with the key stored here' });
  const { encPrivateKeyRecovery, recoveryHash } = req.body || {};
  if (!encPrivateKeyRecovery || !recoveryHash) return res.status(400).json({ error: 'missing recovery material' });
  db.prepare('UPDATE users SET enc_private_key_recovery = ?, recovery_hash = ? WHERE id = ?')
    .run(String(encPrivateKeyRecovery), hashProof(recoveryHash), req.session.userId);
  res.json({ ok: true });
});

router.post('/api/logout', (req, res) => {
  req.session = null;
  res.json({ ok: true });
});

router.post('/api/logout-all', requireAuth, (req, res) => {
  db.prepare('UPDATE users SET session_epoch = session_epoch + 1 WHERE id = ?').run(req.session.userId);
  req.session.epoch = db.prepare('SELECT session_epoch FROM users WHERE id = ?').get(req.session.userId).session_epoch;
  res.json({ ok: true });
});

router.get('/api/me', requireAuth, (req, res) => {
  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(req.session.userId);
  if (!user) return res.status(401).json({ error: 'not logged in' });
  if (!req.session.csrf) req.session.csrf = crypto.randomBytes(24).toString('base64url');
  res.json({
    user: publicUser(user),
    domain: DOMAIN,
    masterLimit: MASTER_LIMIT,
    csrf: req.session.csrf,
    encMode: user.enc_mode,
    encPrivateKey: user.enc_private_key,
    publicKey: user.public_key,
    totpEnabled: !!user.totp_enabled,
    onboarded: !!user.onboarded,
    isAdmin: !!user.is_admin,
  });
});

router.post('/api/onboarded', requireAuth, (req, res) => {
  db.prepare('UPDATE users SET onboarded = 1 WHERE id = ?').run(req.session.userId);
  res.json({ ok: true });
});

router.post('/api/2fa/setup', requireAuth, (req, res) => {
  const cur = db.prepare('SELECT totp_secret, totp_enabled FROM users WHERE id = ?').get(req.session.userId);
  if (cur.totp_enabled) {
    const code = req.body?.code;
    if (!totp.verify(decrypt(cur.totp_secret), code) && !consumeBackupCode(req.session.userId, code)) {
      return res.status(400).json({ error: 'current 2fa code required to re-run setup' });
    }
  }
  const secret = totp.randomSecret();
  db.prepare('UPDATE users SET totp_secret = ?, totp_enabled = 0 WHERE id = ?').run(encrypt(secret), req.session.userId);
  const user = db.prepare('SELECT username FROM users WHERE id = ?').get(req.session.userId);
  res.json({ secret, otpauth: totp.otpauthURL(secret, `${decrypt(user.username)}@${DOMAIN}`) });
});

router.post('/api/2fa/enable', requireAuth, (req, res) => {
  const user = db.prepare('SELECT totp_secret FROM users WHERE id = ?').get(req.session.userId);
  if (!user.totp_secret) return res.status(400).json({ error: 'run setup first' });
  if (!totp.verify(decrypt(user.totp_secret), req.body?.code)) return res.status(400).json({ error: 'code did not match' });
  const codes = genBackupCodes();
  db.prepare('UPDATE users SET totp_enabled = 1, totp_backup = ? WHERE id = ?')
    .run(JSON.stringify(codes.map(hashBackup)), req.session.userId);
  res.json({ ok: true, backupCodes: codes });
});

router.post('/api/2fa/disable', requireAuth, (req, res) => {
  const user = db.prepare('SELECT totp_secret, totp_enabled FROM users WHERE id = ?').get(req.session.userId);
  if (user.totp_enabled && !totp.verify(decrypt(user.totp_secret), req.body?.code)
      && !consumeBackupCode(req.session.userId, req.body?.code)) {
    return res.status(400).json({ error: 'code did not match' });
  }
  db.prepare('UPDATE users SET totp_secret = NULL, totp_enabled = 0, totp_backup = NULL WHERE id = ?').run(req.session.userId);
  res.json({ ok: true });
});

router.post('/api/profile', requireAuth, (req, res) => {
  const nickname = String(req.body?.nickname ?? '').trim().slice(0, 40);
  db.prepare('UPDATE users SET nickname = ? WHERE id = ?').run(nickname ? encrypt(nickname) : '', req.session.userId);
  res.json({ ok: true, nickname });
});

router.get('/api/account/export', requireAuth, (req, res) => {
  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(req.session.userId);

  const messages = allMessagesOf(req.session.userId).map((m) => (
    m.enc_key
      ? { id: m.id, subject: m.subject, body: m.body, from_addr: m.from_addr, to_addr: m.to_addr, enc_key: m.enc_key }
      : {
          id: m.id,
          subject: decrypt(m.subject),
          body: decrypt(m.body),
          from_addr: isArmored(m.from_addr) ? m.from_addr : decrypt(m.from_addr),
          to_addr: isArmored(m.to_addr) ? m.to_addr : decrypt(m.to_addr),
          enc_key: null,
        }
  ));

  const attachments = db.prepare(
    `SELECT at.id, at.message_id, at.filename, at.mime, at.size, at.enc_key, at.data FROM attachments at WHERE ${ATTS_OF}`
  ).all(req.session.userId).map((a) => ({
    id: a.id,
    message_id: a.message_id,
    filename: decrypt(a.filename),
    mime: decrypt(a.mime),
    size: a.size,
    enc_key: a.enc_key,
    data: (a.enc_key ? a.data : decryptBytes(a.data)).toString('base64'),
  }));

  const addresses = db.prepare(
    'SELECT local_part, is_temp, expires_at, burn_on_read, created_at_enc FROM addresses WHERE user_id = ?'
  ).all(req.session.userId).map((a) => ({ ...a, local_part: decrypt(a.local_part), created_at: decryptInt(a.created_at_enc) }));

  res.json({
    exportedAt: Date.now(),
    user: {
      username: decrypt(user.username),
      email: decrypt(user.email),
      nickname: user.nickname ? decrypt(user.nickname) : '',
      created_at: decryptInt(user.created_at_enc),
      enc_mode: user.enc_mode,
      public_key: user.public_key,
      enc_private_key: user.enc_private_key,
    },
    addresses,
    messages,
    attachments,
  });
});

router.post('/api/account/delete', requireAuth, (req, res) => {
  const user = db.prepare('SELECT password_hash FROM users WHERE id = ?').get(req.session.userId);
  if (!bcrypt.compareSync(String(req.body?.password || ''), user.password_hash)) {
    return res.status(401).json({ error: 'incorrect password' });
  }

  const userId = req.session.userId;
  db.transaction(() => {
    const addrIds = db.prepare('SELECT id FROM addresses WHERE user_id = ?').all(userId).map((r) => r.id);
    const delAtt = db.prepare('DELETE FROM attachments WHERE message_id IN (SELECT id FROM messages WHERE address_id = ?)');
    const delMsg = db.prepare('DELETE FROM messages WHERE address_id = ?');
    for (const aid of addrIds) { delAtt.run(aid); delMsg.run(aid); }
    db.prepare('DELETE FROM addresses WHERE user_id = ?').run(userId);
    db.prepare('DELETE FROM groups WHERE user_id = ?').run(userId);
    db.prepare('DELETE FROM folders WHERE user_id = ?').run(userId);
    db.prepare('DELETE FROM prekeys WHERE user_id = ?').run(userId);
    db.prepare('DELETE FROM users WHERE id = ?').run(userId);
  })();
  req.session = null;
  res.json({ ok: true });
});

router.post('/api/enc/enable-e2e', requireAuth, asyncHandler(async (req, res) => {
  const user = db.prepare('SELECT enc_mode FROM users WHERE id = ?').get(req.session.userId);
  if (user.enc_mode !== 'auto') return res.status(400).json({ error: 'already end-to-end' });

  const { custody, publicKey, encPrivateKey, encPrivateKeyRecovery, recoveryHash } = req.body || {};
  if (!publicKey || (custody !== 'private' && custody !== 'keyfile')) {
    return res.status(400).json({ error: 'publicKey and custody required' });
  }
  if (custody === 'private' && (!encPrivateKey || !encPrivateKeyRecovery || !recoveryHash)) {
    return res.status(400).json({ error: 'private custody needs the locked key + recovery' });
  }
  if (!(await validPublicKey(publicKey))) return res.status(400).json({ error: 'unreadable public key' });

  const owner = { enc_mode: 'private', public_key: publicKey };
  const updates = [];
  for (const m of allMessagesOf(req.session.userId)) {
    if (m.enc_key) continue;
    const e = await encryptMessage(owner, decrypt(m.subject), decrypt(m.body), decrypt(m.from_addr), decrypt(m.to_addr));
    updates.push({ id: m.id, ...e });
  }
  const attUpdates = [];
  for (const at of db.prepare(`SELECT at.id, at.data FROM attachments at WHERE at.enc_key IS NULL AND ${ATTS_OF}`).all(req.session.userId)) {
    attUpdates.push({ id: at.id, data: await pgp.encryptBytes(publicKey, decryptBytes(at.data)) });
  }

  db.transaction(() => {
    const up = db.prepare(`UPDATE messages SET subject = ?, body = ?, from_addr = ?, to_addr = ?, enc_key = 'pgp' WHERE id = ?`);
    for (const u of updates) up.run(u.subject, u.body, u.from_addr, u.to_addr, u.id);
    const upAtt = db.prepare(`UPDATE attachments SET data = ?, enc_key = 'pgp' WHERE id = ?`);
    for (const u of attUpdates) upAtt.run(u.data, u.id);
    db.prepare(
      `UPDATE users SET enc_mode = ?, public_key = ?, enc_private_key = ?, enc_private_key_recovery = ?, recovery_hash = ? WHERE id = ?`
    ).run(custody, publicKey, encPrivateKey || null, encPrivateKeyRecovery || null, recoveryHash ? hashProof(recoveryHash) : null, req.session.userId);
  })();

  res.json({ ok: true });
}));

// client sends back plaintext for everything before we strip keys. skip that
// check and a bad request bricks mail nobody can ever decrypt again.
router.post('/api/enc/disable-e2e', requireAuth, (req, res) => {
  const user = db.prepare('SELECT enc_mode FROM users WHERE id = ?').get(req.session.userId);
  if (user.enc_mode === 'auto') return res.status(400).json({ error: 'not end-to-end' });

  const provided = new Map((req.body?.messages || []).map((m) => [Number(m.id), m]));
  const pgpRows = allMessagesOf(req.session.userId).filter((m) => m.enc_key);
  if (pgpRows.some((m) => !provided.has(m.id))) {
    return res.status(400).json({ error: 'plaintext missing for some messages, refusing to strip keys' });
  }

  const providedAtts = new Map((req.body?.attachments || []).map((a) => [Number(a.id), a]));
  const pgpAtts = db.prepare(`SELECT at.id FROM attachments at WHERE at.enc_key IS NOT NULL AND ${ATTS_OF}`).all(req.session.userId);
  if (pgpAtts.some((a) => !providedAtts.has(a.id))) {
    return res.status(400).json({ error: 'plaintext missing for some attachments, refusing to strip keys' });
  }

  db.transaction(() => {
    const up = db.prepare(`UPDATE messages SET subject = ?, body = ?, from_addr = ?, to_addr = ?, enc_key = NULL WHERE id = ?`);
    for (const m of pgpRows) {
      const p = provided.get(m.id);
      up.run(
        encrypt(String(p.subject ?? '')), encrypt(String(p.body ?? '')),
        isArmored(m.from_addr) ? encrypt(String(p.from ?? '')) : m.from_addr,
        isArmored(m.to_addr) ? encrypt(String(p.to ?? '')) : m.to_addr,
        m.id
      );
    }
    const upAtt = db.prepare(`UPDATE attachments SET data = ?, enc_key = NULL WHERE id = ?`);
    for (const a of pgpAtts) {
      upAtt.run(encryptBytes(Buffer.from(String(providedAtts.get(a.id).data || ''), 'base64')), a.id);
    }
    db.prepare(
      `UPDATE users SET enc_mode = 'auto', public_key = NULL, enc_private_key = NULL, enc_private_key_recovery = NULL, recovery_hash = NULL WHERE id = ?`
    ).run(req.session.userId);
    prekeys.deleteAll(req.session.userId);
  })();

  res.json({ ok: true });
});

router.post('/api/enc/to-keyfile', requireAuth, (req, res) => {
  const user = db.prepare('SELECT enc_mode FROM users WHERE id = ?').get(req.session.userId);
  if (user.enc_mode !== 'private') return res.status(400).json({ error: 'not server-stored e2e' });
  db.prepare(
    `UPDATE users SET enc_mode = 'keyfile', enc_private_key = NULL, enc_private_key_recovery = NULL, recovery_hash = NULL WHERE id = ?`
  ).run(req.session.userId);
  res.json({ ok: true });
});

router.post('/api/enc/to-server', requireAuth, asyncHandler(async (req, res) => {
  const user = db.prepare('SELECT enc_mode, public_key FROM users WHERE id = ?').get(req.session.userId);
  if (user.enc_mode !== 'keyfile') return res.status(400).json({ error: 'not keyfile custody' });
  const { encPrivateKey, encPrivateKeyRecovery, recoveryHash } = req.body || {};
  if (!encPrivateKey || !encPrivateKeyRecovery || !recoveryHash) {
    return res.status(400).json({ error: 'locked key + recovery required' });
  }
  try {
    const priv = await openpgp.readPrivateKey({ armoredKey: encPrivateKey });
    const pub = await openpgp.readKey({ armoredKey: user.public_key });
    if (priv.getFingerprint() !== pub.getFingerprint()) {
      return res.status(400).json({ error: 'this key does not match your account' });
    }
  } catch {
    return res.status(400).json({ error: 'unreadable key' });
  }
  db.prepare(
    `UPDATE users SET enc_mode = 'private', enc_private_key = ?, enc_private_key_recovery = ?, recovery_hash = ? WHERE id = ?`
  ).run(encPrivateKey, encPrivateKeyRecovery, hashProof(recoveryHash), req.session.userId);
  res.json({ ok: true });
}));

router.get('/api/enc/prekeys/status', requireAuth, (req, res) => {
  res.json(prekeys.status(req.session.userId));
});

router.post('/api/enc/prekeys', requireAuth, asyncHandler(async (req, res) => {
  const { signed, onetime } = req.body || {};
  if (signed && (!signed.publicKey || !signed.encPrivateKey || !(await validPublicKey(signed.publicKey)))) {
    return res.status(400).json({ error: 'bad signed prekey' });
  }
  if (onetime !== undefined) {
    if (!Array.isArray(onetime) || onetime.length > 200 || onetime.some((k) => !k.publicKey || !k.encPrivateKey)) {
      return res.status(400).json({ error: 'bad one-time prekeys' });
    }
    for (const k of onetime) {
      if (!(await validPublicKey(k.publicKey))) return res.status(400).json({ error: 'bad one-time prekeys' });
    }
  }
  prekeys.publish(req.session.userId, { signed, onetime });
  res.json({ ok: true });
}));

router.get('/api/enc/prekeys/:id', requireAuth, (req, res) => {
  const row = prekeys.getPrivate(req.session.userId, req.params.id);
  if (!row) return res.status(404).json({ error: 'not found' });
  res.json({ kind: row.kind, encPrivateKey: row.enc_private_key });
});

router.delete('/api/enc/prekeys/:id', requireAuth, (req, res) => {
  prekeys.consume(req.session.userId, req.params.id);
  res.json({ ok: true });
});

module.exports = { router };
