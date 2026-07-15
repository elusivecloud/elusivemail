const db = () => require('../db'); // lazy on purpose. hoist it and this file breaks the require cycle.
const SIGNED_MAX_AGE_MS = 7 * 24 * 60 * 60 * 1000;
const LOW_WATERMARK = 10;
const TOP_UP = 30;

function claim(userId) {
  const one = db().prepare(
    `SELECT id, public_key FROM prekeys WHERE user_id = ? AND kind = 'onetime' AND used = 0 ORDER BY id LIMIT 1`
  ).get(userId);
  if (one) {
    db().prepare('UPDATE prekeys SET used = 1 WHERE id = ?').run(one.id);
    return { id: one.id, kind: 'onetime', publicKey: one.public_key };
  }
  return claimSigned(userId);
}

function claimSigned(userId) {
  const signed = db().prepare(
    `SELECT id, public_key FROM prekeys WHERE user_id = ? AND kind = 'signed' ORDER BY id DESC LIMIT 1`
  ).get(userId);
  return signed ? { id: signed.id, kind: 'signed', publicKey: signed.public_key } : null;
}

function status(userId) {
  const onetimeCount = db().prepare(
    `SELECT COUNT(*) n FROM prekeys WHERE user_id = ? AND kind = 'onetime' AND used = 0`
  ).get(userId).n;
  const signed = db().prepare(
    `SELECT created_at FROM prekeys WHERE user_id = ? AND kind = 'signed' ORDER BY id DESC LIMIT 1`
  ).get(userId);
  return {
    onetimeCount,
    needsSigned: !signed || Date.now() - signed.created_at > SIGNED_MAX_AGE_MS,
    lowWatermark: LOW_WATERMARK,
    topUp: TOP_UP,
  };
}

function publish(userId, { signed, onetime } = {}) {
  db().transaction(() => {
    if (signed) {
      db().prepare(`DELETE FROM prekeys WHERE user_id = ? AND kind = 'signed'`).run(userId);
      db().prepare(
        `INSERT INTO prekeys (user_id, kind, public_key, enc_private_key, used, created_at) VALUES (?, 'signed', ?, ?, 0, ?)`
      ).run(userId, signed.publicKey, signed.encPrivateKey, Date.now());
    }
    if (Array.isArray(onetime)) {
      const ins = db().prepare(
        `INSERT INTO prekeys (user_id, kind, public_key, enc_private_key, used, created_at) VALUES (?, 'onetime', ?, ?, 0, ?)`
      );
      for (const k of onetime) ins.run(userId, k.publicKey, k.encPrivateKey, Date.now());
    }
  })();
}

function getPrivate(userId, id) {
  return db().prepare(`SELECT kind, enc_private_key FROM prekeys WHERE id = ? AND user_id = ?`).get(id, userId);
}

function consume(userId, id) {
  db().prepare(`DELETE FROM prekeys WHERE id = ? AND user_id = ? AND kind = 'onetime'`).run(id, userId);
}

function deleteAll(userId) {
  db().prepare('DELETE FROM prekeys WHERE user_id = ?').run(userId);
}

module.exports = { claim, claimSigned, status, publish, getPrivate, consume, deleteAll };
