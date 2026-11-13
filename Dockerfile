# syntax=docker/dockerfile:1
#
# Multi-stage build on Docker Hardened Images (pulling from dhi.io needs `docker login dhi.io`
# with a Docker Hub account):
#   build      dev image (npm, root): installs all dependencies and builds the UI
#   prod-deps  dev image: production dependencies only
#   runtime    hardened image (non-root uid 1000, no shell, no package manager)
#
# Both build stages run on the builder's native platform (--platform=$BUILDPLATFORM): their
# output is architecture independent (built assets, pure-JS dependencies), so the arm64 and
# amd64 images are produced without emulation. Typecheck, lint and tests run in CI, not here.
#
#   docker build -t mailwatch .        (or: npm run docker:build)
#
# Images are pinned by digest (multi-arch index); Dependabot keeps them up to date.

FROM --platform=$BUILDPLATFORM dhi.io/node:26-alpine-dev@sha256:16375cc385b69dbd63d19603d5ba671493294b4cd4d0e3d8132abb0562e29db5 AS build
WORKDIR /src
COPY package.json package-lock.json ./
RUN --mount=type=cache,target=/root/.npm npm ci --no-audit --no-fund
COPY tsconfig.json tsconfig.server.json tsconfig.web.json vite.config.ts ./
COPY src ./src
RUN npm run build

FROM --platform=$BUILDPLATFORM dhi.io/node:26-alpine-dev@sha256:16375cc385b69dbd63d19603d5ba671493294b4cd4d0e3d8132abb0562e29db5 AS prod-deps
WORKDIR /src
COPY package.json package-lock.json ./
RUN --mount=type=cache,target=/root/.npm npm ci --omit=dev --ignore-scripts --no-audit --no-fund

FROM dhi.io/node:26-alpine@sha256:f7b40a7a5e3b75dafd68687f9f5cd4989a2ca02a5004e03147596e7bf8653acc AS runtime
ARG REVISION=unknown
LABEL org.opencontainers.image.title="mailwatch" \
      org.opencontainers.image.description="Monitoring dashboard for e-mail DNS and server setup, DMARC and TLS reports, and delivery tests" \
      org.opencontainers.image.source="https://github.com/sebastka/mailwatch" \
      org.opencontainers.image.revision="${REVISION}"

ENV NODE_ENV=production \
    LISTEN_HOST=0.0.0.0 \
    PORT=3000

# Same /app layout as the release archive (scripts/bundle.sh). Everything is owned by root
# and world-readable, so the app user (1000) cannot modify it: a read-only root filesystem works.
WORKDIR /app
COPY package.json ./
COPY --from=prod-deps /src/node_modules ./node_modules
COPY --from=build /src/dist ./dist
COPY src/server ./src/server
COPY src/shared ./src/shared

EXPOSE 3000

# No shell or curl in the image, so the probe is written in Node.
HEALTHCHECK --interval=30s --timeout=5s --start-period=30s --retries=3 \
  CMD ["node", "-e", "fetch(`http://127.0.0.1:${process.env.PORT}/api/health`).then((r) => process.exit(r.ok ? 0 : 1), () => process.exit(1))"]

CMD ["node", "/app/src/server/index.ts"]
