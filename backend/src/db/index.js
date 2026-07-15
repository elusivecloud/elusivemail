const path = require('path');
const Database = require('better-sqlite3');

const DB_PATH = process.env.ELUSIVE_DB || path.join(__dirname, '../../elusive.db');
const db = new Database(DB_PATH);

db.pragma('journal_mode = WAL');
db.pragma('secure_delete = ON'); // "delete" doesn't mean deleted without this

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    nickname TEXT NOT NULL DEFAULT '',
    created_at INTEGER NOT NULL
  );

  CREATE TABLE IF NOT EXISTS invite_codes (
    code TEXT PRIMARY KEY,
    used_by INTEGER REFERENCES users(id)
  );

  CREATE TABLE IF NOT EXISTS addresses (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL REFERENCES users(id),
    local_part TEXT UNIQUE NOT NULL,
    is_temp INTEGER NOT NULL DEFAULT 0,
    expires_at INTEGER,
    created_at INTEGER NOT NULL
  );

  CREATE TABLE IF NOT EXISTS groups (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL REFERENCES users(id),
    name TEXT NOT NULL,
    created_at INTEGER NOT NULL
  );

  CREATE TABLE IF NOT EXISTS messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    address_id INTEGER NOT NULL REFERENCES addresses(id),
    direction TEXT NOT NULL CHECK (direction IN ('in', 'out')),
    from_addr TEXT NOT NULL,
    to_addr TEXT NOT NULL,
    subject TEXT NOT NULL DEFAULT '',
    body TEXT NOT NULL DEFAULT '',
    is_read INTEGER NOT NULL DEFAULT 0,
    received_at INTEGER NOT NULL
  );

  CREATE INDEX IF NOT EXISTS idx_messages_address ON messages(address_id);

  CREATE TABLE IF NOT EXISTS attachments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    message_id INTEGER NOT NULL REFERENCES messages(id),
    filename TEXT NOT NULL,
    mime TEXT NOT NULL DEFAULT 'application/octet-stream',
    size INTEGER NOT NULL,
    enc_key TEXT,
    data BLOB NOT NULL
  );
  CREATE INDEX IF NOT EXISTS idx_attachments_message ON attachments(message_id);
`);

const addColumn = (sql) => { try { db.exec(sql); } catch (e) { if (!/duplicate column/.test(e.message)) throw e; } };
addColumn(`ALTER TABLE users ADD COLUMN enc_mode TEXT NOT NULL DEFAULT 'auto'`);
addColumn(`ALTER TABLE users ADD COLUMN public_key TEXT`);
addColumn(`ALTER TABLE users ADD COLUMN enc_private_key TEXT`);
addColumn(`ALTER TABLE users ADD COLUMN enc_private_key_recovery TEXT`);
addColumn(`ALTER TABLE users ADD COLUMN recovery_hash TEXT`);
addColumn(`ALTER TABLE messages ADD COLUMN enc_key TEXT`);
addColumn(`ALTER TABLE users ADD COLUMN totp_secret TEXT`);
addColumn(`ALTER TABLE users ADD COLUMN totp_enabled INTEGER NOT NULL DEFAULT 0`);
addColumn(`ALTER TABLE users ADD COLUMN totp_backup TEXT`);
addColumn(`ALTER TABLE users ADD COLUMN session_epoch INTEGER NOT NULL DEFAULT 0`);
addColumn(`ALTER TABLE users ADD COLUMN onboarded INTEGER NOT NULL DEFAULT 1`);
addColumn(`ALTER TABLE addresses ADD COLUMN burn_on_read INTEGER NOT NULL DEFAULT 0`);
addColumn(`ALTER TABLE addresses ADD COLUMN group_id INTEGER REFERENCES groups(id)`);
addColumn(`ALTER TABLE users ADD COLUMN is_admin INTEGER NOT NULL DEFAULT 0`);
addColumn(`ALTER TABLE users ADD COLUMN suspended INTEGER NOT NULL DEFAULT 0`);
addColumn(`ALTER TABLE groups ADD COLUMN color TEXT`);
db.exec(`CREATE TABLE IF NOT EXISTS reserved_names (name TEXT PRIMARY KEY)`);

db.exec(`
  CREATE TABLE IF NOT EXISTS folders (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL REFERENCES users(id),
    name TEXT NOT NULL,
    created_at INTEGER NOT NULL
  );
`);
addColumn(`ALTER TABLE messages ADD COLUMN folder_id INTEGER REFERENCES folders(id)`);
addColumn(`ALTER TABLE messages ADD COLUMN is_junk INTEGER NOT NULL DEFAULT 0`);
addColumn(`ALTER TABLE messages ADD COLUMN auth_fail INTEGER NOT NULL DEFAULT 0`);

db.exec(`
  CREATE TABLE IF NOT EXISTS prekeys (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL REFERENCES users(id),
    kind TEXT NOT NULL CHECK (kind IN ('onetime', 'signed')),
    public_key TEXT NOT NULL,
    enc_private_key TEXT NOT NULL,
    used INTEGER NOT NULL DEFAULT 0,
    created_at INTEGER NOT NULL
  );
  CREATE INDEX IF NOT EXISTS idx_prekeys_claim ON prekeys(user_id, kind, used);
`);

const { encrypt, sha256Hex, hmacHex, encryptJSON, encryptInt } = require('../crypto');
if (db.pragma('user_version', { simple: true }) < 1) {
  db.transaction(() => {
    const upMsg = db.prepare('UPDATE messages SET from_addr = ?, to_addr = ? WHERE id = ?');
    for (const m of db.prepare('SELECT id, from_addr, to_addr FROM messages').all()) {
      upMsg.run(encrypt(m.from_addr), encrypt(m.to_addr), m.id);
    }
    const upTotp = db.prepare('UPDATE users SET totp_secret = ? WHERE id = ?');
    for (const u of db.prepare('SELECT id, totp_secret FROM users WHERE totp_secret IS NOT NULL').all()) {
      upTotp.run(encrypt(u.totp_secret), u.id);
    }
    db.pragma('user_version = 1');
  })();
}

if (db.pragma('user_version', { simple: true }) < 2) {
  db.transaction(() => {
    const upGroup = db.prepare('UPDATE groups SET name = ? WHERE id = ?');
    for (const g of db.prepare('SELECT id, name FROM groups').all()) upGroup.run(encrypt(g.name), g.id);
    const upFolder = db.prepare('UPDATE folders SET name = ? WHERE id = ?');
    for (const f of db.prepare('SELECT id, name FROM folders').all()) upFolder.run(encrypt(f.name), f.id);
    const upNick = db.prepare('UPDATE users SET nickname = ? WHERE id = ?');
    for (const u of db.prepare(`SELECT id, nickname FROM users WHERE nickname != ''`).all()) upNick.run(encrypt(u.nickname), u.id);
    const upAtt = db.prepare('UPDATE attachments SET filename = ?, mime = ? WHERE id = ?');
    for (const a of db.prepare('SELECT id, filename, mime FROM attachments').all()) upAtt.run(encrypt(a.filename), encrypt(a.mime), a.id);
    db.pragma('user_version = 2');
  })();
}

if (db.pragma('user_version', { simple: true }) < 3) {
  db.transaction(() => {
    const up = db.prepare('UPDATE users SET recovery_hash = ? WHERE id = ?');
    for (const u of db.prepare('SELECT id, recovery_hash FROM users WHERE recovery_hash IS NOT NULL').all()) {
      up.run(sha256Hex(u.recovery_hash), u.id);
    }
    db.pragma('user_version = 3');
  })();
}

const addCol = (sql) => { try { db.exec(sql); } catch (e) { if (!/duplicate column/i.test(e.message)) throw e; } };
const dropCol = (table, col) => { try { db.exec(`ALTER TABLE ${table} DROP COLUMN ${col}`); } catch (e) { if (!/no such column/i.test(e.message)) throw e; } };
if (db.pragma('user_version', { simple: true }) < 4) {
  db.transaction(() => {
    addCol('ALTER TABLE users ADD COLUMN username_hmac TEXT');
    addCol('ALTER TABLE users ADD COLUMN email_hmac TEXT');
    addCol('ALTER TABLE users ADD COLUMN created_at_enc TEXT');
    addCol('ALTER TABLE addresses ADD COLUMN local_part_hmac TEXT');
    addCol('ALTER TABLE addresses ADD COLUMN created_at_enc TEXT');
    addCol('ALTER TABLE messages ADD COLUMN meta_enc TEXT');
    addCol('ALTER TABLE messages ADD COLUMN received_at_enc TEXT');

    const upUser = db.prepare('UPDATE users SET username = ?, email = ?, username_hmac = ?, email_hmac = ?, created_at_enc = ? WHERE id = ?');
    for (const u of db.prepare('SELECT id, username, email, created_at FROM users').all()) {
      const email = u.email || `${u.username.toLowerCase()}@${process.env.MAIL_DOMAIN || 'elusive.local'}`;
      upUser.run(encrypt(u.username), encrypt(email), hmacHex(u.username), hmacHex(email), encryptInt(u.created_at), u.id);
    }
    const upAddr = db.prepare('UPDATE addresses SET local_part = ?, local_part_hmac = ?, created_at_enc = ? WHERE id = ?');
    for (const a of db.prepare('SELECT id, local_part, created_at FROM addresses').all()) {
      upAddr.run(encrypt(a.local_part), hmacHex(a.local_part), encryptInt(a.created_at), a.id);
    }
    const upMsg = db.prepare('UPDATE messages SET meta_enc = ?, received_at_enc = ? WHERE id = ?');
    for (const m of db.prepare('SELECT id, is_read, is_junk, folder_id, auth_fail, received_at FROM messages').all()) {
      upMsg.run(encryptJSON({ is_read: m.is_read, is_junk: m.is_junk, folder_id: m.folder_id, auth_fail: m.auth_fail }), encryptInt(m.received_at), m.id);
    }

    db.exec('CREATE UNIQUE INDEX IF NOT EXISTS idx_users_username_hmac ON users(username_hmac)');
    db.exec('CREATE UNIQUE INDEX IF NOT EXISTS idx_users_email_hmac ON users(email_hmac)');
    db.exec('CREATE UNIQUE INDEX IF NOT EXISTS idx_addresses_local_part_hmac ON addresses(local_part_hmac)');

    dropCol('users', 'created_at');
    dropCol('addresses', 'created_at');
    dropCol('messages', 'is_read');
    dropCol('messages', 'is_junk');
    dropCol('messages', 'folder_id');
    dropCol('messages', 'auth_fail');
    dropCol('messages', 'received_at');

    db.pragma('user_version = 4');
  })();
}

db.prepare('DELETE FROM attachments WHERE message_id NOT IN (SELECT id FROM messages)').run();
db.pragma('wal_checkpoint(TRUNCATE)');

module.exports = db;
