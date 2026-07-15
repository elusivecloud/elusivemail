const express = require('express');
const rateLimit = require('express-rate-limit');
const db = require('../db');
const { DOMAIN, MASTER_LIMIT, isReserved } = require('../config');
const { encrypt, decrypt, decryptBytes, hmacHex, encryptJSON, decryptJSON, encryptInt, decryptInt } = require('../crypto');
const { requireAuth, ownsAddress } = require('../auth/middleware');
const { sendMail } = require('./transport');
const { asyncHandler } = require('../async');

const router = express.Router();

const namesOut = (rows) => rows.map((r) => ({ ...r, name: decrypt(r.name), color: r.color == null ? null : decrypt(r.color) }));
const isArmored = (v) => typeof v === 'string' && v.startsWith('-----BEGIN PGP');
const envelope = (v) => (isArmored(v) ? v : decrypt(v));

const HEX_COLOR_RE = /^#[0-9a-f]{6}$/i;

const delAttsForAddress = db.prepare(
  'DELETE FROM attachments WHERE message_id IN (SELECT id FROM messages WHERE address_id = ?)'
);

const sendLimiter = rateLimit({
  windowMs: 60 * 60 * 1000,
  limit: 30,
  keyGenerator: (req) => String(req.session.userId),
  standardHeaders: true,
  legacyHeaders: false,
  validate: false,
  message: { error: 'sending too fast, please slow down and try again shortly' },
});

router.get('/api/groups', requireAuth, (req, res) => {
  const groups = db.prepare('SELECT id, name, color, created_at FROM groups WHERE user_id = ? ORDER BY created_at').all(req.session.userId);
  res.json({ groups: namesOut(groups) });
});

router.post('/api/groups', requireAuth, (req, res) => {
  const name = String(req.body?.name ?? '').trim().slice(0, 40);
  if (!name) return res.status(400).json({ error: 'group name is required' });
  const info = db.prepare('INSERT INTO groups (user_id, name, created_at) VALUES (?, ?, ?)').run(req.session.userId, encrypt(name), Date.now());
  res.json({ ok: true, group: { id: info.lastInsertRowid, name } });
});

router.patch('/api/groups/:id', requireAuth, (req, res) => {
  if (!db.prepare('SELECT id FROM groups WHERE id = ? AND user_id = ?').get(req.params.id, req.session.userId)) {
    return res.status(404).json({ error: 'not found' });
  }
  if (req.body?.name !== undefined) {
    const name = String(req.body.name).trim().slice(0, 40);
    if (!name) return res.status(400).json({ error: 'group name is required' });
    db.prepare('UPDATE groups SET name = ? WHERE id = ?').run(encrypt(name), req.params.id);
  }
  if (req.body?.color !== undefined) {
    const color = req.body.color === null ? null : String(req.body.color);
    if (color !== null && !HEX_COLOR_RE.test(color)) return res.status(400).json({ error: 'color must be a hex value like #7c5cff' });
    db.prepare('UPDATE groups SET color = ? WHERE id = ?').run(color == null ? null : encrypt(color), req.params.id);
  }
  res.json({ ok: true });
});

router.delete('/api/groups/:id', requireAuth, (req, res) => {
  if (!db.prepare('SELECT id FROM groups WHERE id = ? AND user_id = ?').get(req.params.id, req.session.userId)) {
    return res.status(404).json({ error: 'not found' });
  }
  db.prepare('UPDATE addresses SET group_id = NULL WHERE group_id = ?').run(req.params.id);
  db.prepare('DELETE FROM groups WHERE id = ?').run(req.params.id);
  res.json({ ok: true });
});

router.get('/api/mail/addresses', requireAuth, (req, res) => {
  const now = Date.now();
  db.prepare('DELETE FROM attachments WHERE message_id IN (SELECT id FROM messages WHERE address_id IN (SELECT id FROM addresses WHERE is_temp = 1 AND expires_at IS NOT NULL AND expires_at < ?))').run(now);
  db.prepare('DELETE FROM messages WHERE address_id IN (SELECT id FROM addresses WHERE is_temp = 1 AND expires_at IS NOT NULL AND expires_at < ?)').run(now);
  db.prepare('DELETE FROM addresses WHERE is_temp = 1 AND expires_at IS NOT NULL AND expires_at < ?').run(now);
  const addresses = db.prepare(
    'SELECT id, local_part, is_temp, expires_at, burn_on_read, group_id FROM addresses WHERE user_id = ? ORDER BY id'
  ).all(req.session.userId).map((a) => ({ ...a, local_part: decrypt(a.local_part) }));
  const groups = db.prepare('SELECT id, name, color, created_at FROM groups WHERE user_id = ? ORDER BY created_at').all(req.session.userId);
  res.json({ addresses, groups: namesOut(groups), domain: DOMAIN });
});

router.post('/api/mail/addresses', requireAuth, (req, res) => {
  const localPart = String(req.body?.localPart ?? '').trim().toLowerCase();
  const isTemp = !!req.body?.isTemp;
  const burnOnRead = isTemp && !!req.body?.burnOnRead;
  const ttlMinutes = Math.min(Math.max(Number(req.body?.ttlMinutes || 60), 1), 1440);
  const groupId = req.body?.groupId ? Number(req.body.groupId) : null;

  if (!/^[a-z0-9._-]{2,30}$/.test(localPart)) {
    return res.status(400).json({ error: 'address must be 2-30 chars: letters, numbers, . _ -' });
  }
  if (isReserved(localPart)) return res.status(400).json({ error: 'that address is reserved' });
  if (groupId && !db.prepare('SELECT id FROM groups WHERE id = ? AND user_id = ?').get(groupId, req.session.userId)) {
    return res.status(400).json({ error: 'unknown group' });
  }
  if (!isTemp) {
    const masterCount = db.prepare('SELECT COUNT(*) AS n FROM addresses WHERE user_id = ? AND is_temp = 0').get(req.session.userId).n;
    if (masterCount >= MASTER_LIMIT) return res.status(400).json({ error: `master mailboxes are capped at ${MASTER_LIMIT}` });
  }
  if (db.prepare('SELECT id FROM addresses WHERE local_part_hmac = ?').get(hmacHex(localPart))) {
    return res.status(409).json({ error: 'address already taken' });
  }

  const expiresAt = isTemp ? Date.now() + (burnOnRead ? 1440 : ttlMinutes) * 60 * 1000 : null;
  const info = db.prepare(
    'INSERT INTO addresses (user_id, local_part, local_part_hmac, is_temp, expires_at, burn_on_read, group_id, created_at_enc) VALUES (?, ?, ?, ?, ?, ?, ?, ?)'
  ).run(req.session.userId, encrypt(localPart), hmacHex(localPart), isTemp ? 1 : 0, expiresAt, burnOnRead ? 1 : 0, groupId, String(Date.now()));

  res.json({ ok: true, address: { id: info.lastInsertRowid, local_part: localPart, is_temp: isTemp ? 1 : 0, expires_at: expiresAt, burn_on_read: burnOnRead ? 1 : 0, group_id: groupId } });
});

router.patch('/api/mail/addresses/:id', requireAuth, (req, res) => {
  if (!ownsAddress(req.session.userId, req.params.id)) return res.status(404).json({ error: 'not found' });
  let groupId = req.body?.groupId;
  groupId = (groupId === null || groupId === undefined || groupId === '') ? null : Number(groupId);
  if (groupId && !db.prepare('SELECT id FROM groups WHERE id = ? AND user_id = ?').get(groupId, req.session.userId)) {
    return res.status(400).json({ error: 'unknown group' });
  }
  db.prepare('UPDATE addresses SET group_id = ? WHERE id = ?').run(groupId, req.params.id);
  res.json({ ok: true });
});

router.delete('/api/mail/addresses/:id', requireAuth, (req, res) => {
  if (!ownsAddress(req.session.userId, req.params.id)) return res.status(404).json({ error: 'not found' });
  delAttsForAddress.run(req.params.id);
  db.prepare('DELETE FROM messages WHERE address_id = ?').run(req.params.id);
  db.prepare('DELETE FROM addresses WHERE id = ?').run(req.params.id);
  res.json({ ok: true });
});

router.get('/api/mail/inbox/:addressId', requireAuth, (req, res) => {
  if (!ownsAddress(req.session.userId, req.params.addressId)) return res.status(404).json({ error: 'not found' });
  const rows = db.prepare(
    'SELECT id, direction, from_addr, to_addr, subject, body, enc_key, meta_enc, received_at_enc FROM messages WHERE address_id = ? ORDER BY id DESC'
  ).all(req.params.addressId);
  const attsByMsg = {};
  for (const a of db.prepare(
    'SELECT id, message_id, filename, mime, size, enc_key FROM attachments WHERE message_id IN (SELECT id FROM messages WHERE address_id = ?)'
  ).all(req.params.addressId)) {
    (attsByMsg[a.message_id] ||= []).push({ id: a.id, filename: decrypt(a.filename), mime: decrypt(a.mime), size: a.size, enc_key: a.enc_key });
  }
  const messages = rows.map((m) => {
    const meta = decryptJSON(m.meta_enc);
    const out = {
      id: m.id, direction: m.direction, enc_key: m.enc_key,
      from_addr: envelope(m.from_addr), to_addr: envelope(m.to_addr),
      is_read: meta.is_read || 0, received_at: decryptInt(m.received_at_enc),
      folder_id: meta.folder_id ?? null, is_junk: meta.is_junk || 0,
      attachments: attsByMsg[m.id] || [],
    };
    // e2e messages stay ciphertext here, the browser decrypts with the prekey/PGP key named in enc_key
    return m.enc_key ? { ...out, subject: m.subject, body: m.body } : { ...out, subject: decrypt(m.subject), body: decrypt(m.body) };
  });
  res.json({ messages });
});

router.post('/api/mail/read/:messageId', requireAuth, (req, res) => {
  const msg = db.prepare(
    `SELECT m.id, m.address_id, m.meta_enc FROM messages m JOIN addresses a ON a.id = m.address_id WHERE m.id = ? AND a.user_id = ?`
  ).get(req.params.messageId, req.session.userId);
  if (!msg) return res.json({ ok: true });
  const meta = decryptJSON(msg.meta_enc);
  meta.is_read = 1;
  db.prepare('UPDATE messages SET meta_enc = ? WHERE id = ?').run(encryptJSON(meta), msg.id);

  const addr = db.prepare('SELECT burn_on_read FROM addresses WHERE id = ?').get(msg.address_id);
  if (addr && addr.burn_on_read) {
    delAttsForAddress.run(msg.address_id);
    db.prepare('DELETE FROM messages WHERE address_id = ?').run(msg.address_id);
    db.prepare('DELETE FROM addresses WHERE id = ?').run(msg.address_id);
    return res.json({ ok: true, burned: msg.address_id });
  }
  res.json({ ok: true });
});

router.delete('/api/mail/message/:messageId', requireAuth, (req, res) => {
  db.prepare(
    `DELETE FROM attachments WHERE message_id IN (SELECT id FROM messages WHERE id = ? AND address_id IN (SELECT id FROM addresses WHERE user_id = ?))`
  ).run(req.params.messageId, req.session.userId);
  db.prepare(
    `DELETE FROM messages WHERE id = ? AND address_id IN (SELECT id FROM addresses WHERE user_id = ?)`
  ).run(req.params.messageId, req.session.userId);
  res.json({ ok: true });
});

router.patch('/api/mail/message/:messageId', requireAuth, (req, res) => {
  const owned = db.prepare(
    `SELECT m.id, m.meta_enc FROM messages m JOIN addresses a ON a.id = m.address_id WHERE m.id = ? AND a.user_id = ?`
  ).get(req.params.messageId, req.session.userId);
  if (!owned) return res.status(404).json({ error: 'not found' });

  const meta = decryptJSON(owned.meta_enc);
  let changed = false;
  if (req.body?.folderId !== undefined) {
    let folderId = req.body.folderId;
    folderId = (folderId === null || folderId === '') ? null : Number(folderId);
    if (folderId && !db.prepare('SELECT id FROM folders WHERE id = ? AND user_id = ?').get(folderId, req.session.userId)) {
      return res.status(400).json({ error: 'unknown folder' });
    }
    meta.folder_id = folderId;
    changed = true;
  }
  if (req.body?.isJunk !== undefined) {
    meta.is_junk = req.body.isJunk ? 1 : 0;
    changed = true;
  }
  if (req.body?.isRead !== undefined) {
    meta.is_read = req.body.isRead ? 1 : 0;
    changed = true;
  }
  if (changed) db.prepare('UPDATE messages SET meta_enc = ? WHERE id = ?').run(encryptJSON(meta), req.params.messageId);
  res.json({ ok: true });
});

router.get('/api/folders', requireAuth, (req, res) => {
  const folders = db.prepare('SELECT id, name, created_at FROM folders WHERE user_id = ? ORDER BY created_at').all(req.session.userId);
  res.json({ folders: namesOut(folders) });
});

router.post('/api/folders', requireAuth, (req, res) => {
  const name = String(req.body?.name ?? '').trim().slice(0, 40);
  if (!name) return res.status(400).json({ error: 'folder name is required' });
  const info = db.prepare('INSERT INTO folders (user_id, name, created_at) VALUES (?, ?, ?)').run(req.session.userId, encrypt(name), Date.now());
  res.json({ ok: true, folder: { id: info.lastInsertRowid, name } });
});

router.patch('/api/folders/:id', requireAuth, (req, res) => {
  const name = String(req.body?.name ?? '').trim().slice(0, 40);
  if (!name) return res.status(400).json({ error: 'folder name is required' });
  if (!db.prepare('SELECT id FROM folders WHERE id = ? AND user_id = ?').get(req.params.id, req.session.userId)) {
    return res.status(404).json({ error: 'not found' });
  }
  db.prepare('UPDATE folders SET name = ? WHERE id = ?').run(encrypt(name), req.params.id);
  res.json({ ok: true });
});

router.delete('/api/folders/:id', requireAuth, (req, res) => {
  if (!db.prepare('SELECT id FROM folders WHERE id = ? AND user_id = ?').get(req.params.id, req.session.userId)) {
    return res.status(404).json({ error: 'not found' });
  }
  for (const m of db.prepare('SELECT id, meta_enc FROM messages WHERE meta_enc IS NOT NULL').all()) {
    const meta = decryptJSON(m.meta_enc);
    if (meta.folder_id === Number(req.params.id)) {
      meta.folder_id = null;
      db.prepare('UPDATE messages SET meta_enc = ? WHERE id = ?').run(encryptJSON(meta), m.id);
    }
  }
  db.prepare('DELETE FROM folders WHERE id = ?').run(req.params.id);
  res.json({ ok: true });
});

router.get('/api/mail/attachment/:id', requireAuth, (req, res) => {
  const att = db.prepare(
    `SELECT at.filename, at.mime, at.enc_key, at.data
       FROM attachments at JOIN messages m ON m.id = at.message_id JOIN addresses a ON a.id = m.address_id
      WHERE at.id = ? AND a.user_id = ?`
  ).get(req.params.id, req.session.userId);
  if (!att) return res.status(404).json({ error: 'not found' });
  if (att.enc_key) {
    res.setHeader('Content-Type', 'application/json');
    return res.json({ encKey: att.enc_key, data: att.data.toString('base64') });
  }
  const safeName = String(decrypt(att.filename)).replace(/[^\w.\- ]/g, '_');
  res.setHeader('Content-Type', decrypt(att.mime) || 'application/octet-stream');
  res.setHeader('Content-Disposition', `attachment; filename="${safeName}"`);
  res.send(decryptBytes(att.data));
});

router.post('/api/mail/send', requireAuth, sendLimiter, asyncHandler(async (req, res) => {
  const { addressId, to, subject, body, attachments } = req.body || {};
  if (!ownsAddress(req.session.userId, addressId)) return res.status(404).json({ error: 'not found' });
  if (!to || !subject) return res.status(400).json({ error: 'to and subject are required' });

  const row = db.prepare('SELECT local_part FROM addresses WHERE id = ?').get(addressId);
  try {
    await sendMail({ fromAddress: decrypt(row.local_part), to, subject, body: body || '', attachments: Array.isArray(attachments) ? attachments : [] });
    res.json({ ok: true });
  } catch {
    res.status(502).json({ error: 'send failed' });
  }
}));

module.exports = { router };
