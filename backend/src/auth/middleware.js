const db = require('../db');
const { decrypt } = require('../crypto');
const { IDLE_MS } = require('../config');

function publicUser(row) {
  return { id: row.id, username: decrypt(row.username), email: decrypt(row.email), nickname: row.nickname ? decrypt(row.nickname) : '' };
}

function requireAuth(req, res, next) {
  if (!req.session.userId) return res.status(401).json({ error: 'not logged in' });
  const now = Date.now();
  if (req.session.lastSeen && now - req.session.lastSeen > IDLE_MS) {
    req.session = null;
    return res.status(401).json({ error: 'session expired, please log in again' });
  }
  const user = db.prepare('SELECT session_epoch, suspended FROM users WHERE id = ?').get(req.session.userId);
  if (!user || (req.session.epoch || 0) !== user.session_epoch) {
    req.session = null;
    return res.status(401).json({ error: 'session was signed out elsewhere' });
  }
  if (user.suspended) {
    req.session = null;
    return res.status(403).json({ error: 'this account has been suspended' });
  }
  req.session.lastSeen = now;
  next();
}

function requireAdmin(req, res, next) {
  requireAuth(req, res, () => {
    const u = db.prepare('SELECT is_admin FROM users WHERE id = ?').get(req.session.userId);
    if (!u || !u.is_admin) return res.status(403).json({ error: 'admin only' });
    next();
  });
}

function ownsAddress(userId, addressId) {
  return db.prepare('SELECT id FROM addresses WHERE id = ? AND user_id = ?').get(addressId, userId);
}

module.exports = { publicUser, requireAuth, requireAdmin, ownsAddress };
