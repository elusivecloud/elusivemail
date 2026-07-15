# syntax=docker/dockerfile:1.7

FROM node:20-bookworm AS build

ENV CI=1
WORKDIR /app

RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      ca-certificates curl build-essential pkg-config \
      libssl-dev \
 && rm -rf /var/lib/apt/lists/*

ENV RUSTUP_HOME=/usr/local/rustup \
    CARGO_HOME=/usr/local/cargo \
    PATH=/usr/local/cargo/bin:$PATH
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y \
      --default-toolchain stable --profile minimal \
 && chmod -R a+rx /usr/local/rustup /usr/local/cargo

COPY backend/package.json backend/package-lock.json* ./backend/
RUN cd backend && npm ci

COPY backend ./backend
RUN cd backend && npm run build

RUN cd backend && npm prune --omit=dev

FROM node:20-bookworm-slim AS runtime

ARG GIT_SHA=
ENV NODE_ENV=production \
    PORT=3000 \
    MAIL_PORT=2525 \
    ELUSIVE_DB=/app/backend/data/elusive.db \
    GIT_SHA=${GIT_SHA}

RUN groupadd --system --gid 1001 elusive \
 && useradd  --system --uid 1001 --gid elusive --home-dir /app --shell /usr/sbin/nologin elusive \
 && mkdir -p /app/backend/data \
 && chown -R elusive:elusive /app

WORKDIR /app

RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates tini \
 && rm -rf /var/lib/apt/lists/*

COPY --from=build --chown=elusive:elusive /app/backend/node_modules        ./backend/node_modules
COPY --from=build --chown=elusive:elusive /app/backend/native             ./backend/native
COPY --from=build --chown=elusive:elusive /app/backend/package.json       ./backend/package.json
COPY --from=build --chown=elusive:elusive /app/backend/package-lock.json*  ./backend/package-lock.json
COPY --chown=elusive:elusive backend/src                                  ./backend/src
COPY --chown=elusive:elusive backend/crates                               ./backend/crates

COPY --chown=elusive:elusive frontend                                     ./frontend

USER elusive
EXPOSE 3000 2525

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD node -e "fetch('http://127.0.0.1:'+(process.env.PORT||3000)+'/.well-known/security.txt').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"

ENTRYPOINT ["/usr/bin/tini", "--"]
CMD ["node", "backend/src/server.js"]