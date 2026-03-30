# ─── Builder ──────────────────────────────────────────────────────────────────
FROM oven/bun:1-alpine AS builder

WORKDIR /app

# Install dependencies first — cached layer unless lock file changes
COPY package.json bun.lock ./
RUN bun install --frozen-lockfile

# Compile TypeScript
COPY tsconfig.json ./
COPY src/ ./src/
RUN bun run build

# ─── Runner ───────────────────────────────────────────────────────────────────
FROM oven/bun:1-alpine AS runner

WORKDIR /app

ENV NODE_ENV=production
ENV PORT=8000
# SQLite cache — override at runtime with -e DB_PATH=/your/path
ENV DB_PATH=/data/dependency-guard.db

# Persist SQLite cache across container restarts
VOLUME ["/data"]

COPY --from=builder /app/dist ./dist
COPY --from=builder /app/node_modules ./node_modules
COPY package.json ./

EXPOSE 8000

# bun:sqlite is a Bun built-in — must run with Bun, not Node
CMD ["bun", "dist/index.js"]
