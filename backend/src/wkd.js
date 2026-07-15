const express = require('express');
const crypto = require('crypto');
const openpgp = require('openpgp');
const db = require('./db');
const { decrypt } = require('./crypto');

const ZB32 = 'ybndrfg8ejkmcpqxot1uwisza345h769';

function zbase32(buf) {
  let bits = 0, value = 0, out = '';
  for (const b of buf) {
    value = (value << 8) | b;
    bits += 8;
    while (bits >= 5) {
      out += ZB32[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
    value &= (1 << bits) - 1;
  }
  if (bits > 0) out += ZB32[(value << (5 - bits)) & 31];
  return out;
}

function wkdHash(localPart) {
  return zbase32(crypto.createHash('sha1').update(String(localPart).toLowerCase()).digest());
}

async function serveKey(hash, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  // a.is_temp = 0 stays. burners share the owner's key; serve it here and you've
  // just handed out a way to link a burner to the real account.
  const rows = db.prepare(
    'SELECT a.local_part, u.public_key FROM addresses a JOIN users u ON u.id = a.user_id WHERE u.public_key IS NOT NULL AND a.is_temp = 0'
  ).all();
  const match = rows.find((r) => wkdHash(decrypt(r.local_part)) === hash);
  if (!match) return res.status(404).type('text/plain').send('');
  try {
    const key = await openpgp.readKey({ armoredKey: match.public_key });
    res.setHeader('Content-Type', 'application/octet-stream');
    res.send(Buffer.from(key.write()));
  } catch {
    res.status(404).type('text/plain').send('');
  }
}

const router = express.Router();

router.get('/.well-known/openpgpkey/policy', (req, res) => res.type('text/plain').send(''));
router.get('/.well-known/openpgpkey/:domain/policy', (req, res) => res.type('text/plain').send(''));
router.get('/.well-known/openpgpkey/hu/:hash', (req, res) => serveKey(req.params.hash, res));
router.get('/.well-known/openpgpkey/:domain/hu/:hash', (req, res) => serveKey(req.params.hash, res));

module.exports = { router, wkdHash };
