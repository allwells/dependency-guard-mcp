FROM node:20-alpine AS builder

WORKDIR /app

COPY package.json bun.lock ./

RUN npm install -g bun && bun install --frozen-lockfile

COPY tsconfig.json ./
COPY src/ ./src/

RUN bun run build


FROM oven/bun:alpine AS runner

WORKDIR /app

ENV NODE_ENV=production
ENV PORT=8000
ENV DB_PATH=/data/dependency-guard.db

COPY package.json ./
COPY --from=builder /app/dist ./dist
COPY --from=builder /app/node_modules ./node_modules

VOLUME ["/data"]

EXPOSE 8000

CMD ["bun", "dist/index.js"]
