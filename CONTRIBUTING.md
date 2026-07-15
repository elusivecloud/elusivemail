# Contributing to Elusive

Thanks for your interest in improving Elusive. This document is short on
purpose.

## Sign-off

Every commit needs a `Signed-off-by: Your Name <you@example.com>` line (use
`git commit -s`). This certifies the Developer Certificate of Origin: that
you wrote the contribution and have the right to submit it under the
project's license.

## License

This project is inbound = outbound: contributions are accepted under the
same terms as the project, the [GNU AGPL-3.0-or-later](LICENSE). There's no
CLA to sign. By submitting a contribution, you agree it will be licensed
under AGPL-3.0-or-later.

## Coding style

Match the style of the files you're editing. The codebase is plain
JavaScript (CommonJS, no TypeScript) and idiomatic Rust for the napi crate.
Don't add comments unless they're essential for safety (for example, a
security-critical invariant) or match existing patterns; self-documenting
code is preferred. Don't add new dependencies without review; open an issue
first describing the need and the proposed package. Security-sensitive
additions (crypto, parsing, auth) get extra scrutiny.

## Before opening a pull request

Run `npm test` in `backend/`; this executes the security self-check
(`test/security-check.js`). If your change touches
`backend/crates/crypto-core`, also run
`cargo test --manifest-path backend/crates/crypto-core/Cargo.toml`. Check
that `npm audit --omit=dev --audit-level=high` reports no new high-severity
issues introduced by your change. Don't commit secrets, `.env` files,
database files (`*.db`, `*.db-wal`, `*.db-shm`), backups, or local-only
artifacts. `.gitignore` already excludes these; verify with `git status`
before pushing.

## Security

Security fixes are welcome but must follow the disclosure policy in
[SECURITY.md](SECURITY.md). Report vulnerabilities privately to
security@elusivemail.xyz rather than as a public issue.

## Contact

Open a GitHub issue for bugs and feature discussion. For security reports,
use the private channel in SECURITY.md.
