const assert = require('assert');
const fs = require('fs');
const path = require('path');

process.env.ELUSIVE_DB = path.join(__dirname, 'test-smtp.db');
for (const f of [process.env.ELUSIVE_DB, `${process.env.ELUSIVE_DB}-wal`, `${process.env.ELUSIVE_DB}-shm`]) {
  fs.rmSync(f, { force: true });
}
process.env.MAIL_PORT = '0';

process.env.MASTER_KEY = process.env.MASTER_KEY || require('crypto').randomBytes(32).toString('hex');
process.env.SESSION_SECRET = process.env.SESSION_SECRET || require('crypto').randomBytes(32).toString('hex');

const nodemailer = require('nodemailer');
const db = require('../src/db');
const { DOMAIN } = require('../src/config');
const { startInboundServer } = require('../src/mail/transport');
const { encrypt, hmacHex, encryptJSON, encryptInt, decryptJSON } = require('../src/crypto');

async function main() {
  const now = Date.now();
  const userId = db.prepare(
    `INSERT INTO users (username, email, username_hmac, email_hmac, password_hash, created_at_enc) VALUES (?, ?, ?, ?, ?, ?)`
  ).run(encrypt('smtptest'), encrypt('smtptest@example.com'), hmacHex('smtptest'), hmacHex('smtptest@example.com'), 'x', encryptInt(now)).lastInsertRowid;
  db.prepare(`INSERT INTO addresses (user_id, local_part, local_part_hmac, is_temp, created_at_enc) VALUES (?, ?, ?, 0, ?)`)
    .run(userId, encrypt('smtptest'), hmacHex('smtptest'), encryptInt(now));
  const addressId = db.prepare(`SELECT id FROM addresses WHERE local_part_hmac = ?`).get(hmacHex('smtptest')).id;

  const server = startInboundServer();
  // smtp-server never re-emits 'listening' on itself, wait on server.server or this hangs forever
  await new Promise((resolve) => server.server.once('listening', resolve));
  const port = server.server.address().port;

  const client = nodemailer.createTransport({ host: '127.0.0.1', port, secure: false, ignoreTLS: true });

  await client.sendMail({
    from: 'sender@example.com',
    to: `smtptest@${DOMAIN}`,
    subject: 'hello',
    text: 'just a small test message',
  });

  await new Promise((resolve) => setTimeout(resolve, 300));
  const rows = db.prepare('SELECT meta_enc FROM messages WHERE address_id = ?').all(addressId).map((r) => decryptJSON(r.meta_enc));
  assert.strictEqual(rows.length, 1, 'message should have been delivered');
  assert.strictEqual(rows[0].auth_fail, 1, 'auth_fail should be 1 when SPF/DKIM cannot be verified (no DNS in sandbox)');

  const big = 'a'.repeat(26 * 1024 * 1024);
  let rejected = false;
  try {
    await client.sendMail({
      from: 'sender@example.com',
      to: `smtptest@${DOMAIN}`,
      subject: 'too big',
      text: big,
    });
  } catch (e) {
    rejected = true;
    assert.ok(/552|size/i.test(e.message), `rejection should mention size: ${e.message}`);
  }
  assert.ok(rejected, 'oversized message must be rejected');

  const countAfter = db.prepare('SELECT COUNT(*) AS n FROM messages WHERE address_id = ?').get(addressId).n;
  assert.strictEqual(countAfter, 1, 'oversized message must not be stored');

  server.close();
  console.log('smtp-check: all assertions passed');
  process.exit(0);
}

main().catch((e) => { console.error(e); process.exit(1); });
