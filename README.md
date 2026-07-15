<p align="center">
  <img src="marketing/assets/x-header.png" alt="Elusive: keep your inbox to yourself" width="100%">
</p>

# Elusive

Encrypted email that shows you the exact line between what's sealed to your
key and what the server can see, instead of just claiming it can't read your
mail.

**[elusivemail.xyz](https://elusivemail.xyz)**. Free, no ads, no invite code,
no waitlist.

## What it is

Your key is generated in your browser and never leaves it, so your mail stays
with you. Alongside your main address you can make disposable aliases that
vanish on a timer or the moment they're opened, and group any of them under a
persona.

## What's sealed to your key, and what we see

**Sealed to your key.** We hold nothing to hand over.
- Message bodies, subject lines, and attachments
- Who a stored message is from and to
- Your username, aliases, and whether you've read a message
- In keyfile mode, the key itself

**Visible to the server**, only because delivery needs it, never logged.
- Who a message is from and to at the moment it passes through
- When mail arrives, and to which of your aliases
- Incoming mail the instant it arrives, before it's sealed to your key,
  except mail a sender's own app already encrypted to you with PGP; that
  reaches us sealed and we never see the plaintext

Read the full model at [elusivemail.xyz/security](https://elusivemail.xyz/security).

## Proof points

- Keys generated in the browser: OpenPGP.js, curve25519, Argon2id.
- Every message gets forward secrecy from a one-time prekey, deleted the
  moment it's decrypted.
- Your password never leaves your device. The server stores only a hash, so
  it can't derive your key.
- End to end by default, plus a keyfile mode where nothing stored can decrypt
  your mail.
- Deleting mail overwrites the freed space, so it can't be recovered from the
  raw database file.
- No request or IP logging. Every API response is marked no-store.
- Free, no ads, no trackers, makes no money.
- The source is public, so none of this is a claim you have to take on
  faith. See below.

## The honest limits

We say these first, before anyone asks.
- Incoming external mail arrives in plaintext and is sealed to your key at
  receipt, unless the sender's own app already encrypted it via PGP. True of
  every provider that isn't PGP-to-PGP. We just say it.
- Metadata (sender, recipient, timing) is visible to the server to route
  mail.

## Roadmap

A trust ladder people can push. As more people join, we commit to shipping
these, in order. The live count and current milestone are on the
[homepage roadmap](https://elusivemail.xyz/#roadmap).

| Users   | Milestone                                              |
|---------|----------------------------------------------------------|
| 300     | A documented public API with tokens you control.         |
| 800     | Native mobile and desktop apps; donations open.           |
| 1,500   | Our own servers, standalone hardware in Switzerland.      |
| 2,500   | Multi-server structure: mail, keys, and web app split.    |
| 4,000   | An independent security audit, published in full.         |
| 6,000   | An encrypted communicator, built on the same keys.        |
| 10,000  | Full infrastructure: encrypted file sharing and drive.    |

Elusive is step one of a full open source privacy architecture: encrypted
email now, an encrypted communicator and private file sharing next, all on
the same keys.

## Security

Found a vulnerability? Report it privately, see [SECURITY.md](SECURITY.md).
Do not open a public issue for security reports.

## License

Copyright (C) Elusive contributors. Licensed under the
[GNU Affero General Public License v3.0 or later](LICENSE) (AGPL-3.0-or-later).
Network use of this software triggers AGPL source-disclosure obligations; see
the `LICENSE` file for terms.

## Running your own instance

The hosted service at elusivemail.xyz is the easiest way to use Elusive, but
nothing here is gated behind it. If you'd rather run your own instance (your
own mail domain, your own data), the whole stack is in this repo.

1. Copy `cp .env.example .env` and fill in the required secrets:
   ```bash
   openssl rand -hex 32   # SESSION_SECRET
   openssl rand -hex 32   # MASTER_KEY  (32-byte AES-256 key, 64 hex chars)
   ```
   See `.env.example` for the full list. The server refuses to start without
   `SESSION_SECRET` and `MASTER_KEY`.
2. Install dependencies and build the native crypto crate:
   ```bash
   cd backend
   npm install
   npm run build        # builds the Rust napi crate via @napi-rs/cli
   ```
   Building the native crate requires a Rust toolchain (`cargo`) and a C
   compiler. The server falls back to a JS crypto implementation if the
   native module is absent, so `npm run build` is optional but recommended
   for production throughput.
3. Run:
   ```bash
   npm start            # starts the HTTP API on PORT (default 3000)
   ```
4. Run the security self-check and Rust tests:
   ```bash
   npm test
   npm run test:core    # cargo test on crypto-core
   ```

A multi-stage `Dockerfile` and `docker-compose.yml` are also provided. The
image runs as a non-root user, exposes ports 3000 (HTTP) and 2525 (SMTP), and
requires `SESSION_SECRET`, `MASTER_KEY`, and `MAIL_DOMAIN` at runtime, no
secrets are baked into the image. See `docker-compose.yml`.

A single Node.js process (`backend/src/server.js`) serves the static
frontend, exposes the REST API, and accepts inbound SMTP. State is kept in a
local SQLite database via `better-sqlite3`. Messages and secrets are
encrypted at rest with AES-256-GCM; user key material is wrapped with
OpenPGP.js so decryption happens client-side. A small Rust crate,
`crypto-core`, exposes a native accelerator for symmetric crypto and TOTP
through napi-rs; it's optional, the JS fallback remains the security
boundary. DKIM signing, MTA-STS enforcement, and STARTTLS on inbound mail are
first-class.

## Links

- [Create an inbox](https://elusivemail.xyz/join)
- [Security model](https://elusivemail.xyz/security)
- [Help](https://elusivemail.xyz/help)
- [@elusivemail on X](https://x.com/elusivemail)
