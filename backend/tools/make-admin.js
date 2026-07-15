const crypto = require('crypto');
const bcrypt = require('bcrypt');
const db = require('../src/db');
const { encrypt, hmacHex } = require('../src/crypto');

const [, , usernameArg] = process.argv;
const password = process.env.ELUSIVE_ADMIN_PASSWORD;
if (!usernameArg || !password) {
  console.error('usage: ELUSIVE_ADMIN_PASSWORD=... node backend/tools/make-admin.js <username>');
  process.exit(1);
}
const username = usernameArg.toLowerCase();
const DOMAIN = process.env.MAIL_DOMAIN || 'elusive.local';
const SYSTEM = ['support', 'abuse', 'postmaster', 'security', 'hostmaster', 'webmaster', 'help', 'info'];

function confirm(prompt) {
  return new Promise((resolve) => {
    const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
    rl.question(prompt, (answer) => { rl.close(); resolve(answer.trim()); });
  });
}

(async () => {
  const typed = await confirm(`Are you sure you want to make ${username} an admin? Type the username to confirm: `);
  if (typed !== username) {
    console.log('confirmation did not match; aborting');
    process.exit(0);
  }

  const authProof = crypto.createHash('sha256').update(username + ':' + password, 'utf8').digest('hex');
  const passwordHash = bcrypt.hashSync(authProof, 12);

  let user = db.prepare('SELECT * FROM users WHERE username_hmac = ?').get(hmacHex(username));
  if (!user) {
    const email = `${username}@${DOMAIN}`;
    if (db.prepare('SELECT id FROM users WHERE email_hmac = ?').get(hmacHex(email))) {
      console.error(`email ${email} already exists under a different username`);
      process.exit(1);
    }
    const info = db.prepare(
      `INSERT INTO users (username, email, username_hmac, email_hmac, password_hash, created_at_enc, onboarded, enc_mode, is_admin)
       VALUES (?, ?, ?, ?, ?, ?, 1, 'auto', 1)`
    ).run(encrypt(username), encrypt(email), hmacHex(username), hmacHex(email), passwordHash, String(Date.now()));
    db.prepare('INSERT INTO addresses (user_id, local_part, local_part_hmac, is_temp, created_at_enc) VALUES (?, ?, ?, 0, ?)')
      .run(info.lastInsertRowid, encrypt(username), hmacHex(username), String(Date.now()));
    user = db.prepare('SELECT * FROM users WHERE id = ?').get(info.lastInsertRowid);
    console.log(`created ops account ${username}@${DOMAIN} (auto mode, admin)`);
  } else {
    db.prepare('UPDATE users SET is_admin = 1, suspended = 0 WHERE id = ?').run(user.id);
    if (user.enc_mode !== 'auto') {
      console.log(`note: ${username} is in ${user.enc_mode} mode; system mailboxes will be`);
      console.log('end-to-end to this account and not renderable in the panel. Use a');
      console.log('dedicated auto-mode account for the in-panel support view.');
    }
    console.log(`promoted ${username} to admin`);
  }

  const findAddr = db.prepare('SELECT user_id FROM addresses WHERE local_part_hmac = ?');
  const insAddr = db.prepare('INSERT INTO addresses (user_id, local_part, local_part_hmac, is_temp, created_at_enc) VALUES (?, ?, ?, 0, ?)');
  for (const box of SYSTEM) {
    const cur = findAddr.get(hmacHex(box));
    if (!cur) { insAddr.run(user.id, encrypt(box), hmacHex(box), String(Date.now())); console.log(`  + ${box}@${DOMAIN}`); }
    else if (cur.user_id !== user.id) console.log(`  ! ${box}@ owned by another account, left alone`);
  }

  console.log('\ndone. log in at /login, then open /admin');
  process.exit(0);
})();
