const fs = require('fs');
const express = require('express');
const bcrypt = require('bcrypt');
const db = require('../db');
const { DOMAIN, PRODUCTION, RESERVED } = require('../config');
const { totp, decrypt, decryptInt } = require('../crypto');
const { requireAdmin } = require('../auth/middleware');

function requireStepUp(req, res) {
  const user = db.prepare('SELECT password_hash, totp_secret, totp_enabled FROM users WHERE id = ?').get(req.session.userId);
  if (!user) { res.status(401).json({ error: 'step-up authentication required' }); return false; }
  const code = req.body?.totpCode;
  const pw = String(req.body?.password || '');
  if (user.totp_enabled) {
    if (code && totp.verify(decrypt(user.totp_secret), code)) return true;
  } else {
    if (pw && bcrypt.compareSync(pw, user.password_hash)) return true;
  }
  res.status(401).json({ error: 'step-up authentication required' });
  return false;
}

const router = express.Router();

router.get('/api/admin/stats', requireAdmin, (req, res) => {
  const g = (sql, ...p) => db.prepare(sql).get(...p);
  const now = Date.now();

  const users = g(`SELECT COUNT(*) total,
      COALESCE(SUM(enc_mode='auto'),0) auto,
      COALESCE(SUM(enc_mode='private'),0) private,
      COALESCE(SUM(enc_mode='keyfile'),0) keyfile,
      COALESCE(SUM(totp_enabled),0) totp,
      COALESCE(SUM(is_admin),0) admins,
      COALESCE(SUM(suspended),0) suspended
    FROM users`);
  const messages = g(`SELECT COUNT(*) total,
      COALESCE(SUM(direction='in'),0) inbound,
      COALESCE(SUM(direction='out'),0) outbound,
      COALESCE(SUM(enc_key IS NOT NULL),0) e2e
    FROM messages`);
  const addresses = g(`SELECT COUNT(*) total, COALESCE(SUM(is_temp),0) temp FROM addresses`);
  const attachments = g(`SELECT COUNT(*) total, COALESCE(SUM(size),0) bytes FROM attachments`);
  const groups = g(`SELECT COUNT(*) total FROM groups`).total;

  let dbBytes = 0, disk = null;
  try { dbBytes = fs.statSync(db.name).size; } catch {}
  try { const s = fs.statfsSync(db.name); disk = { free: s.bsize * s.bfree, total: s.bsize * s.blocks }; } catch {}

  res.json({
    users, messages, addresses, attachments, groups,
    storage: { dbBytes, disk, attachmentBytes: attachments.bytes },
    process: { uptimeSec: Math.floor(process.uptime()), rss: process.memoryUsage().rss, node: process.version },
    transport: {
      domain: DOMAIN,
      production: PRODUCTION,
      dkim: !!process.env.DKIM_PRIVATE_KEY,
      tls: !!(process.env.MAIL_TLS_KEY && process.env.MAIL_TLS_CERT),
      relay: process.env.SMTP_HOST || null,
    },
    now,
  });
});

router.get('/api/admin/users', requireAdmin, (req, res) => {
  const users = db.prepare(`
    SELECT u.id, u.username, u.email, u.created_at_enc, u.enc_mode, u.totp_enabled, u.is_admin, u.suspended, u.onboarded,
      (SELECT COUNT(*) FROM addresses a WHERE a.user_id = u.id) addresses,
      (SELECT COALESCE(SUM(LENGTH(m.subject) + LENGTH(m.body)), 0)
         FROM messages m WHERE m.address_id IN (SELECT id FROM addresses WHERE user_id = u.id)) body_bytes
    FROM users u ORDER BY u.id DESC`).all().map((u) => ({ ...u, username: decrypt(u.username), email: decrypt(u.email), created_at: decryptInt(u.created_at_enc) }));
  res.json({ users });
});

router.post('/api/admin/users/:id/suspend', requireAdmin, (req, res) => {
  const id = Number(req.params.id);
  if (id === req.session.userId) return res.status(400).json({ error: 'you cannot suspend your own account' });
  if (!db.prepare('SELECT id FROM users WHERE id = ?').get(id)) return res.status(404).json({ error: 'not found' });
  if (!requireStepUp(req, res)) return;
  const suspended = req.body?.suspended ? 1 : 0;
  db.prepare('UPDATE users SET suspended = ?, session_epoch = session_epoch + 1 WHERE id = ?').run(suspended, id);
  res.json({ ok: true, suspended });
});

router.delete('/api/admin/users/:id', requireAdmin, (req, res) => {
  const id = Number(req.params.id);
  if (id === req.session.userId) return res.status(400).json({ error: 'you cannot delete your own account here' });
  const target = db.prepare('SELECT id, is_admin FROM users WHERE id = ?').get(id);
  if (!target) return res.status(404).json({ error: 'not found' });
  if (!requireStepUp(req, res)) return;
  if (target.is_admin && db.prepare('SELECT COUNT(*) n FROM users WHERE is_admin = 1').get().n <= 1) {
    return res.status(400).json({ error: 'cannot delete the last admin' });
  }
  db.transaction(() => {
    const addrIds = db.prepare('SELECT id FROM addresses WHERE user_id = ?').all(id).map((r) => r.id);
    const delAtt = db.prepare('DELETE FROM attachments WHERE message_id IN (SELECT id FROM messages WHERE address_id = ?)');
    const delMsg = db.prepare('DELETE FROM messages WHERE address_id = ?');
    for (const aid of addrIds) { delAtt.run(aid); delMsg.run(aid); }
    db.prepare('DELETE FROM addresses WHERE user_id = ?').run(id);
    db.prepare('DELETE FROM groups WHERE user_id = ?').run(id);
    db.prepare('DELETE FROM prekeys WHERE user_id = ?').run(id);
    db.prepare('DELETE FROM users WHERE id = ?').run(id);
  })();
  res.json({ ok: true });
});

router.get('/api/admin/reserved', requireAdmin, (req, res) => {
  const custom = db.prepare('SELECT name FROM reserved_names ORDER BY name').all().map((r) => r.name);
  res.json({ builtin: [...RESERVED].sort(), custom });
});
router.post('/api/admin/reserved', requireAdmin, (req, res) => {
  const name = String(req.body?.name ?? '').trim().toLowerCase();
  if (!/^[a-z0-9._-]{1,30}$/.test(name)) return res.status(400).json({ error: 'invalid name' });
  db.prepare('INSERT OR IGNORE INTO reserved_names (name) VALUES (?)').run(name);
  res.json({ ok: true });
});
router.delete('/api/admin/reserved/:name', requireAdmin, (req, res) => {
  db.prepare('DELETE FROM reserved_names WHERE name = ?').run(String(req.params.name).toLowerCase());
  res.json({ ok: true });
});

module.exports = { router };
