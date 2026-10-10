# syntax=docker/dockerfile:1

# ---- Build: compile the web app and the server ----
FROM node:22-bookworm-slim AS build
# Toolchain for native modules (argon2, better-sqlite3) when no prebuilt binary matches.
RUN apt-get update && apt-get install -y --no-install-recommends python3 make g++ && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY server/package.json server/package-lock.json server/
COPY web/package.json web/package-lock.json web/
RUN npm --prefix server ci && npm --prefix web ci
COPY server server
COPY web web
RUN npm --prefix web run build \
 && npm --prefix server run build \
 && npm --prefix server prune --omit=dev

# ---- Runtime: only compiled output and production dependencies ----
FROM node:22-bookworm-slim
ENV NODE_ENV=production \
    ANYSSH_HOST=0.0.0.0 \
    ANYSSH_PORT=8080 \
    ANYSSH_DATA_DIR=/data \
    ANYSSH_WEB_ROOT=/app/web/dist \
    ANYSSH_COOKIE_SECURE=true \
    ANYSSH_TRUST_PROXY=true
WORKDIR /app/server
COPY --from=build --chown=root:root /src/server/package.json ./
COPY --from=build --chown=root:root /src/server/node_modules ./node_modules
COPY --from=build --chown=root:root /src/server/dist ./dist
COPY --from=build --chown=root:root /src/web/dist /app/web/dist
# The app runs unprivileged and can write only to /data.
RUN mkdir -p /data && chown node:node /data && chmod 700 /data
USER node
VOLUME ["/data"]
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD ["node", "-e", "fetch('http://127.0.0.1:8080/api/health').then(r=>process.exit(r.ok?0:1),()=>process.exit(1))"]
CMD ["node", "dist/index.js"]
