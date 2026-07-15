# Security Policy

## Reporting a vulnerability

If you believe you've found a security vulnerability in Elusive, report it
responsibly and privately. Do not open a public GitHub issue.

Email security@elusivemail.xyz. PGP is preferred: fetch our public key from
the WKD endpoint or from `/.well-known/security.txt` on the production
deployment, encrypt your report, and include a way for us to reply securely.

Please include a clear description, reproducible steps, affected versions,
and an impact assessment. A proof of concept is appreciated but not required.

## Scope

In scope: the source code maintained in this repository, running with the
configuration documented in `.env.example`. This covers the Node backend,
the Rust `crypto-core` napi crate, and the frontend assets.

Out of scope: vulnerabilities in third-party dependencies (report those to
their respective maintainers, and via `npm audit` / `cargo audit` if
applicable), and issues that require controlling legitimate secrets already
in your possession.

## What to expect

We aim to acknowledge receipt within 48 hours, and to provide a substantive
update at least every 7 days until the issue is resolved or closed. For
high-impact issues we coordinate disclosure timing and publish a CVE when a
fix ships.

## Safe harbor

We support good-faith security research and will not pursue legal action
against researchers who respect user privacy (no accessing or modifying
data belonging to others), avoid degrading service availability (no DoS,
spam, or mass automated exploitation), and report promptly without
disclosing publicly before a fix is released or an agreed embargo has
passed. In return, give us reasonable time to remediate before any public
disclosure.

## References

- Security contact and PGP key: `https://elusivemail.xyz/.well-known/security.txt`
- Automated advisories run as `npm audit` / `cargo audit` CI jobs; see
  `.github/workflows/ci.yml`.
