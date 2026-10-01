# syntax=docker/dockerfile:1.7
# Provenza web UI (Next.js). The API is reached on the same origin under
# /api/v1 through the reverse proxy, so one image works for any domain.
# Build context: repository root (see deploy/docker-compose.yml).

ARG NODE_VERSION=20

FROM node:${NODE_VERSION}-slim AS build
WORKDIR /app
ENV NEXT_TELEMETRY_DISABLED=1
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY frontend/ ./
RUN rm -f apply_*.py theme_block.css
ARG NEXT_PUBLIC_API_URL=/api/v1
ENV NEXT_PUBLIC_API_URL=${NEXT_PUBLIC_API_URL}
RUN npm run build && npm prune --omit=dev --no-audit --no-fund

FROM node:${NODE_VERSION}-slim AS runtime
LABEL org.opencontainers.image.title="Provenza web" \
      org.opencontainers.image.source="https://github.com/kironovlaziz-del/provenza" \
      org.opencontainers.image.licenses="Apache-2.0"
RUN apt-get update && apt-get install -y --no-install-recommends tini && rm -rf /var/lib/apt/lists/*
WORKDIR /app
ENV NODE_ENV=production NEXT_TELEMETRY_DISABLED=1 PORT=3000 HOSTNAME=0.0.0.0
COPY --from=build --chown=node:node /app/package.json ./package.json
COPY --from=build --chown=node:node /app/node_modules ./node_modules
COPY --from=build --chown=node:node /app/.next ./.next
COPY --from=build --chown=node:node /app/public ./public
USER node
EXPOSE 3000
ENTRYPOINT ["tini", "--"]
CMD ["node", "node_modules/next/dist/bin/next", "start", "-p", "3000", "-H", "0.0.0.0"]
