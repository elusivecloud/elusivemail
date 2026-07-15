const fs = require('fs');
const net = require('net');
const dns = require('dns');
const nodemailer = require('nodemailer');
const { SMTPServer } = require('smtp-server');
const { simpleParser } = require('mailparser');
const { authenticate } = require('mailauth');
const openpgp = require('openpgp');
const db = require('../db');
const { DOMAIN } = require('../config');
const { encrypt, encryptMessage, encryptAttachment, hmacHex, encryptJSON, encryptInt } = require('../crypto');
const { wkdHash } = require('../wkd');

function htmlToText(html) {
  return String(html || '')
    .replace(/<(script|style)[^>]*>[\s\S]*?<\/\1>/gi, ' ')
    .replace(/<br\s*\/?>/gi, '\n')
    .replace(/<\/(p|div|tr|li|h[1-6])>/gi, '\n')
    .replace(/<[^>]+>/g, ' ')
    .replace(/&nbsp;/gi, ' ').replace(/&amp;/gi, '&').replace(/&lt;/gi, '<').replace(/&gt;/gi, '>').replace(/&#0?39;|&apos;/gi, "'").replace(/&quot;/gi, '"')
    .replace(/[ \t]+/g, ' ').replace(/ *\n */g, '\n').replace(/\n{3,}/g, '\n\n').trim();
}

function ownerOf(localPart) {
  return db.prepare(
    `SELECT a.id AS address_id, u.id AS id, u.enc_mode, u.public_key
       FROM addresses a JOIN users u ON u.id = a.user_id
      WHERE a.local_part_hmac = ? AND (a.expires_at IS NULL OR a.expires_at > ?)`
  ).get(hmacHex(localPart), Date.now());
}

const MAX_STORED_BYTES = 500 * 1024 * 1024;
function overQuota(userId) {
  const inAddrs = `SELECT id FROM addresses WHERE user_id = ?`;
  const body = db.prepare(
    `SELECT COALESCE(SUM(LENGTH(subject) + LENGTH(body)), 0) AS n FROM messages WHERE address_id IN (${inAddrs})`
  ).get(userId).n;
  const att = db.prepare(
    `SELECT COALESCE(SUM(size), 0) AS n FROM attachments WHERE message_id IN (SELECT id FROM messages WHERE address_id IN (${inAddrs}))`
  ).get(userId).n;
  return body + att >= MAX_STORED_BYTES;
}

const insertMessage = db.prepare(
  `INSERT INTO messages (address_id, direction, from_addr, to_addr, subject, body, enc_key, meta_enc, received_at_enc)
   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`
);

const MAX_ATTACH_BYTES = 10 * 1024 * 1024;
const insertAttachment = db.prepare(
  `INSERT INTO attachments (message_id, filename, mime, size, enc_key, data) VALUES (?, ?, ?, ?, ?, ?)`
);
async function storeAttachments(owner, msgId, atts) {
  for (const a of atts || []) {
    const buf = a.content;
    if (!Buffer.isBuffer(buf) || !buf.length || buf.length > MAX_ATTACH_BYTES) continue;
    const e = await encryptAttachment(owner, buf);
    insertAttachment.run(msgId, encrypt(a.filename || 'attachment'), encrypt(a.contentType || 'application/octet-stream'), buf.length, e.enc_key, e.data);
  }
}

const dkim = process.env.DKIM_PRIVATE_KEY
  ? (() => {
      const keyPath = process.env.DKIM_PRIVATE_KEY;
      const privateKey = fs.readFileSync(keyPath, 'utf8');
      try {
        const st = fs.statSync(keyPath);
        if (st.mode & 0o077) console.warn('[security] DKIM private key is group/world readable; chmod 0600');
      } catch {}
      return { domainName: DOMAIN, keySelector: process.env.DKIM_SELECTOR || 'elusive', privateKey };
    })()
  : undefined;

const transport = nodemailer.createTransport({
  ...(process.env.SMTP_HOST
    ? {
        host: process.env.SMTP_HOST,
        port: Number(process.env.SMTP_PORT || 587),
        auth: process.env.SMTP_USER ? { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS } : undefined,
        // relay sidecar is on the private network and self-signs its cert, CA validation
        // has nothing to check against here; the real outbound hop is postfix -> the world
        tls: { rejectUnauthorized: false },
      }
    : { direct: true, name: DOMAIN }),
  dkim,
});

const WKD_CACHE_TTL_MS = 60 * 60 * 1000;
const wkdCache = new Map();
const WKD_CACHE_MAX = 2000;
function wkdCacheSet(address, entry) {
  if (wkdCache.size >= WKD_CACHE_MAX) {
    const oldest = wkdCache.keys().next().value;
    wkdCache.delete(oldest);
  }
  wkdCache.set(address, entry);
}

function isPrivateIPv4(ip) {
  const parts = ip.split('.').map(Number);
  if (parts.length !== 4 || parts.some((n) => Number.isNaN(n) || n < 0 || n > 255)) return false;
  const [a, b] = parts;
  if (a === 0) return true;
  if (a === 10) return true;
  if (a === 127) return true;
  if (a === 169 && b === 254) return true;
  if (a === 172 && b >= 16 && b <= 31) return true;
  if (a === 192 && b === 168) return true;
  if (a >= 224) return true;
  return false;
}

function isPrivateIPv6(ip) {
  const lc = ip.toLowerCase();
  if (lc === '::1' || lc === '::') return true;
  if (lc.startsWith('fc') || lc.startsWith('fd')) return true;
  if (lc.startsWith('fe80')) return true;
  if (lc.startsWith('::ffff:')) return isPrivateIPv4(lc.slice('::ffff:'.length));
  return false;
}

function isPrivateIP(ip) {
  const v = net.isIP(ip);
  if (v === 4) return isPrivateIPv4(ip);
  if (v === 6) return isPrivateIPv6(ip);
  return false;
}

async function isAllowedHost(domain) {
  const d = String(domain || '').toLowerCase().trim();
  if (!d || d === 'localhost') return false;
  if (d.endsWith('.local') || d.endsWith('.internal')) return false;
  if (net.isIP(d)) return !isPrivateIP(d);
  try {
    const addrs = await new Promise((resolve, reject) => {
      const to = setTimeout(() => reject(new Error('dns timeout')), 2000);
      dns.lookup(d, { all: true }, (err, res) => { clearTimeout(to); if (err) reject(err); else resolve(res); });
    });
    return addrs.length > 0 && addrs.every((a) => !isPrivateIP(a.address));
  } catch {
    return false;
  }
}

async function fetchKey(url) {
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), 3000);
  try {
    const res = await fetch(url, { signal: ctrl.signal });
    if (!res.ok) return null;
    const binaryKey = new Uint8Array(await res.arrayBuffer());
    if (!binaryKey.length) return null;
    return await openpgp.readKey({ binaryKey });
  } catch {
    return null;
  } finally {
    clearTimeout(t);
  }
}

async function wkdLookup(address) {
  const cached = wkdCache.get(address);
  if (cached && cached.expires > Date.now()) return cached.key;

  const [localPart, domain] = String(address).split('@');
  if (localPart && domain) {
    if (!(await isAllowedHost(domain))) {
      wkdCacheSet(address, { key: null, expires: Date.now() + WKD_CACHE_TTL_MS });
      return null;
    }
    const hash = wkdHash(localPart);
    const l = encodeURIComponent(localPart);
    const advanced = `https://openpgpkey.${domain}/.well-known/openpgpkey/${domain}/hu/${hash}?l=${l}`;
    const direct = `https://${domain}/.well-known/openpgpkey/hu/${hash}?l=${l}`;
    const key = (await fetchKey(advanced)) || (await fetchKey(direct));
    wkdCacheSet(address, { key, expires: Date.now() + WKD_CACHE_TTL_MS });
    return key;
  }
  wkdCacheSet(address, { key: null, expires: Date.now() + WKD_CACHE_TTL_MS });
  return null;
}

async function sendMail({ fromAddress, to, subject, body, attachments = [] }) {
  const from = `${fromAddress}@${DOMAIN}`;
  const atts = (attachments || []).map((a) => ({
    filename: a.filename || 'attachment',
    contentType: a.mime || 'application/octet-stream',
    content: Buffer.from(String(a.content || ''), 'base64'),
  }));

  const recipients = String(to).split(',').map((r) => r.trim()).filter(Boolean);
  let text = body;
  if (!atts.length && recipients.length) {
    const keys = await Promise.all(recipients.map(wkdLookup));
    if (keys.every(Boolean)) {
      try {
        const armored = await openpgp.encrypt({
          message: await openpgp.createMessage({ text: body }),
          encryptionKeys: keys,
          config: { aeadProtect: false },
        });
        text = armored;
      } catch {
        text = body;
      }
    }
  }
  await transport.sendMail({ from, to, subject, text, attachments: atts });
  const owner = ownerOf(fromAddress);
  if (!owner) return;
  if (overQuota(owner.id)) return;
  const enc = await encryptMessage(owner, subject, body, from, to);
  const info = insertMessage.run(owner.address_id, 'out', enc.from_addr, enc.to_addr, enc.subject, enc.body, enc.enc_key, encryptJSON({ is_read: 1, is_junk: 0, folder_id: null, auth_fail: 0 }), encryptInt(Date.now()));
  await storeAttachments(owner, info.lastInsertRowid, atts);
}

// ECDHE only. do not add a plain RSA suite back in, that's how you lose forward secrecy.
const PFS_CIPHERS = [
  'ECDHE-ECDSA-AES128-GCM-SHA256', 'ECDHE-RSA-AES128-GCM-SHA256',
  'ECDHE-ECDSA-AES256-GCM-SHA384', 'ECDHE-RSA-AES256-GCM-SHA384',
  'ECDHE-ECDSA-CHACHA20-POLY1305', 'ECDHE-RSA-CHACHA20-POLY1305',
].join(':');

function tlsOptions() {
  const keyPath = process.env.MAIL_TLS_KEY, certPath = process.env.MAIL_TLS_CERT;
  if (!keyPath || !certPath) return { disabledCommands: ['STARTTLS'] };
  try {
    return {
      key: fs.readFileSync(keyPath), cert: fs.readFileSync(certPath),
      minVersion: 'TLSv1.2', ciphers: PFS_CIPHERS, honorCipherOrder: true,
    };
  } catch (e) {
    console.warn(`STARTTLS off: TLS cert not readable yet (${e.code}); mail still accepted`);
    return { disabledCommands: ['STARTTLS'] };
  }
}

const MAX_INBOUND_BYTES = 25 * 1024 * 1024;

function authFailed(authResult) {
  const dmarcResult = authResult?.dmarc && authResult.dmarc.status?.result;
  if (dmarcResult === 'fail') return true;
  const spfPass = authResult?.spf?.status?.result === 'pass';
  const dkimPass = (authResult?.dkim?.results || []).some((r) => r.status?.result === 'pass');
  return !spfPass && !dkimPass;
}

function startInboundServer() {
  const rcptByIp = new Map();
  setInterval(() => {
    const now = Date.now();
    const win = 60000;
    for (const [ip, arr] of rcptByIp) {
      const live = arr.filter((t) => now - t < win);
      if (live.length) rcptByIp.set(ip, live);
      else rcptByIp.delete(ip);
    }
  }, 5 * 60 * 1000).unref();

  const server = new SMTPServer({
    authOptional: true,
    size: MAX_INBOUND_BYTES,
    ...tlsOptions(),
    onRcptTo(address, session, cb) {
      const ip = session.remoteAddress;
      const now = Date.now();
      const win = 60000;
      const arr = (rcptByIp.get(ip) || []).filter((t) => now - t < win);
      arr.push(now);
      rcptByIp.set(ip, arr);
      if (arr.length > 100) return cb(new Error('421 too many recipients from this host, slow down'));
      if (session.envelope.rcptTo.length >= 50) return cb(new Error('450 too many recipients'));
      const localPart = address.address.split('@')[0].toLowerCase();
      const owner = ownerOf(localPart);
      if (!owner) return cb(new Error('550 no such mailbox'));
      if (overQuota(owner.id)) return cb(new Error('552 mailbox is full'));
      cb();
    },
    onData(stream, session, cb) {
      const chunks = [];
      stream.on('data', (c) => chunks.push(c));
      stream.on('error', (e) => cb(e));
      stream.on('end', async () => {
        if (stream.sizeExceeded) {
          const err = new Error('message exceeds fixed maximum message size');
          err.responseCode = 552;
          return cb(err);
        }
        const raw = Buffer.concat(chunks);

        let authFail = 0;
        try {
          const authResult = await authenticate(raw, {
            ip: session.remoteAddress,
            helo: session.hostNameAppearsAs,
            sender: session.envelope.mailFrom && session.envelope.mailFrom.address,
          });
          authFail = authFailed(authResult) ? 1 : 0;
        } catch {
          authFail = 2;
        }

        simpleParser(raw, {}, async (err, parsed) => {
          if (err) return cb(err);
          try {
            const to = session.envelope.rcptTo.map((r) => r.address.toLowerCase());
            for (const addr of to) {
              const owner = ownerOf(addr.split('@')[0]);
              if (!owner) continue;
              const enc = await encryptMessage(owner, parsed.subject || '', parsed.text || htmlToText(parsed.html), parsed.from?.text || '', addr);
              const info = insertMessage.run(owner.address_id, 'in', enc.from_addr, enc.to_addr, enc.subject, enc.body, enc.enc_key, encryptJSON({ is_read: 0, is_junk: 0, folder_id: null, auth_fail: authFail }), encryptInt(Date.now()));
              await storeAttachments(owner, info.lastInsertRowid, parsed.attachments);
            }
            cb();
          } catch (e) {
            cb(e);
          }
        });
      });
    },
  });

  const port = Number(process.env.MAIL_PORT || 2525);
  server.listen(port, () => console.log(`inbound SMTP listening on port ${port} for @${DOMAIN}`));
  server.on('error', (err) => console.error('SMTP server error:', err.message));
  return server;
}

module.exports = { sendMail, startInboundServer };
