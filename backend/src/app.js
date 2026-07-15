const path = require('path');
const crypto = require('crypto');
const express = require('express');
const cookieSession = require('cookie-session');
const helmet = require('helmet');
const db = require('./db');
const { PRODUCTION, DOMAIN, STATIC_DIR, BIG_JSON_PATHS, CSRF_EXEMPT, REPO_URL, GIT_SHA, IMAGE_DIGEST } = require('./config');

const authRoutes = require('./auth/routes');
const mailRoutes = require('./mail/routes');
const adminRoutes = require('./admin/routes');
const wkd = require('./wkd');
const { wkdHash } = wkd;

const SECURITY_TXT_EXPIRES = new Date(Date.now() + 365 * 24 * 60 * 60 * 1000).toISOString();

function createApp() {
  const app = express();
  app.set('trust proxy', Number(process.env.TRUST_PROXY || 0));
  app.disable('x-powered-by');

  app.use(helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        scriptSrc: ["'self'", "'wasm-unsafe-eval'"],
        styleSrc: ["'self'", "'unsafe-inline'"],
        imgSrc: ["'self'", 'data:'],
        connectSrc: ["'self'"],
        fontSrc: ["'self'"],
        objectSrc: ["'none'"],
        baseUri: ["'none'"],
        frameAncestors: ["'none'"],
        formAction: ["'self'"],
      },
    },
    hsts: { maxAge: 63072000, includeSubDomains: true, preload: true },
    referrerPolicy: { policy: 'no-referrer' },
  }));

  app.use((req, res, next) => {
    res.setHeader(
      'Permissions-Policy',
      'camera=(), microphone=(), geolocation=(), payment=(), usb=(), accelerometer=(), gyroscope=(), magnetometer=(), interest-cohort=(), browsing-topics=()'
    );
    res.setHeader('X-Frame-Options', 'DENY');
    next();
  });

  const smallJson = express.json({ limit: '256kb' });
  app.use((req, res, next) => (BIG_JSON_PATHS.has(req.path) ? next() : smallJson(req, res, next)));
  app.use('/api/enc/disable-e2e', express.json({ limit: '25mb' }));
  app.use('/api/mail/send', express.json({ limit: '25mb' }));

  app.use(cookieSession({
    name: 'session',
    keys: [process.env.SESSION_SECRET, process.env.SESSION_SECRET_PREVIOUS].filter(Boolean),
    maxAge: 12 * 60 * 60 * 1000,
    httpOnly: true,
    secure: PRODUCTION,
    sameSite: 'strict',
  }));

  app.use('/api', (req, res, next) => {
    res.setHeader('Cache-Control', 'no-store');
    next();
  });

  app.get(['/admin', '/admin.html'], (req, res) => {
    const uid = req.session && req.session.userId;
    if (uid) {
      const u = db.prepare('SELECT is_admin, suspended, session_epoch FROM users WHERE id = ?').get(uid);
      if (u && u.is_admin && !u.suspended && (req.session.epoch || 0) === u.session_epoch) {
        return res.sendFile(path.join(STATIC_DIR, 'admin.html'));
      }
    }
    res.status(404).type('html').send('<!doctype html><meta charset="utf-8"><title>404</title>Not found');
  });

  app.use((req, res, next) => {
    if (req.method !== 'GET' && req.method !== 'HEAD') return next();
    const qs = req.url.slice(req.path.length);
    if (req.path === '/index.html' || req.path === '/index') return res.redirect(301, '/' + qs);
    const m = req.path.match(/^(\/[a-z0-9/_-]*)\.html$/i);
    if (m) return res.redirect(301, m[1] + qs);
    next();
  });
  app.use(express.static(STATIC_DIR, { extensions: ['html'], index: 'index.html' }));

  app.use((req, res, next) => {
    if (!/^(POST|PUT|PATCH|DELETE)$/.test(req.method)) return next();
    if (!req.path.startsWith('/api/') || CSRF_EXEMPT.has(req.path)) return next();
    if (!req.session.userId) return next();
    if (req.get('x-csrf-token') && req.session.csrf && req.get('x-csrf-token') === req.session.csrf) return next();
    return res.status(403).json({ error: 'bad or missing CSRF token' });
  });

  app.get('/.well-known/security.txt', (req, res) => {
    res.type('text/plain').send(
      `Contact: mailto:security@${DOMAIN}\n` +
      `Expires: ${SECURITY_TXT_EXPIRES}\n` +
      `Preferred-Languages: en\n` +
      `Canonical: https://${DOMAIN}/.well-known/security.txt\n` +
      `Policy: https://${DOMAIN}/security.html\n` +
      `Encryption: https://${DOMAIN}/.well-known/openpgpkey/hu/${wkdHash('security')}\n`
    );
  });
  app.get('/.well-known/build-info', (req, res) => {
    res.json({
      repo: REPO_URL,
      commit: GIT_SHA,
      commitUrl: GIT_SHA ? `${REPO_URL}/commit/${GIT_SHA}` : null,
      imageDigest: IMAGE_DIGEST,
      verify: IMAGE_DIGEST
        ? `cosign verify --certificate-identity-regexp 'https://github.com/elusivecloud/elusivemail/.github/workflows/release.yml@.*' --certificate-oidc-issuer https://token.actions.githubusercontent.com ${IMAGE_DIGEST}`
        : null,
    });
  });
  app.get('/.well-known/mta-sts.txt', (req, res) => {
    res.type('text/plain').send(`version: STSv1\nmode: ${process.env.MTA_STS_MODE || 'enforce'}\nmx: ${DOMAIN}\nmax_age: 604800\n`);
  });
  app.use(wkd.router);
  app.get('/api/stats', (req, res) => {
    res.json({ users: db.prepare(`SELECT COUNT(*) c FROM users WHERE is_admin = 0`).get().c });
  });
  app.get('/api/session', (req, res) => {
    res.json({ loggedIn: !!(req.session && req.session.userId) });
  });

  app.use(authRoutes.router);
  app.use(mailRoutes.router);
  app.use(adminRoutes.router);

  app.use((err, req, res, next) => {
    if (res.headersSent) return next(err);
    res.status(500).json({ error: 'server error' });
  });

  return app;
}

module.exports = { createApp };
