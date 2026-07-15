const path = require('path');
const db = require('./db');

const PRODUCTION = process.env.NODE_ENV === 'production';
const DOMAIN = process.env.MAIL_DOMAIN || 'elusive.local';
const PORT = Number(process.env.PORT || 3000);

const STATIC_DIR = path.join(__dirname, '../../frontend');

const REPO_URL = 'https://github.com/elusivecloud/elusivemail';
function resolveGitSha() {
  if (process.env.GIT_SHA) return process.env.GIT_SHA;
  try {
    return require('child_process')
      .execFileSync('git', ['rev-parse', 'HEAD'], { cwd: __dirname, stdio: ['ignore', 'pipe', 'ignore'] })
      .toString()
      .trim();
  } catch {
    return null;
  }
}
const GIT_SHA = resolveGitSha();
const IMAGE_DIGEST = process.env.IMAGE_DIGEST || null;

const MASTER_LIMIT = 5;
const IDLE_MS = 2 * 60 * 60 * 1000;

const BIG_JSON_PATHS = new Set(['/api/mail/send', '/api/enc/disable-e2e']);
const CSRF_EXEMPT = new Set(['/api/login', '/api/join', '/api/recover', '/api/recover/challenge']);

const RESERVED = new Set(['postmaster', 'abuse', 'admin', 'administrator', 'root', 'hostmaster', 'webmaster', 'security', 'noreply', 'no-reply', 'mailer-daemon', 'daemon', 'support', 'help', 'info', 'billing', 'elusive']);

const reservedStmt = db.prepare('SELECT 1 FROM reserved_names WHERE name = ?');
function isReserved(name) {
  const n = String(name).toLowerCase();
  return RESERVED.has(n) || !!reservedStmt.get(n);
}

module.exports = {
  PRODUCTION, DOMAIN, PORT, STATIC_DIR, REPO_URL, GIT_SHA, IMAGE_DIGEST,
  MASTER_LIMIT, IDLE_MS, BIG_JSON_PATHS, CSRF_EXEMPT, RESERVED, isReserved,
};
