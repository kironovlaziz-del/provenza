# ---- Provenza — frontend (Next.js 16) ----
# Multi-stage: install+build, then a lean runtime image.

FROM node:20-slim AS builder
WORKDIR /app

# NEXT_PUBLIC_* vars are inlined at build time, so pass the API URL as a build arg
ARG NEXT_PUBLIC_API_URL=http://localhost:8000/api/v1
ENV NEXT_PUBLIC_API_URL=$NEXT_PUBLIC_API_URL

COPY package.json package-lock.json ./
RUN npm ci

COPY . .
RUN npm run build

# ---- runtime ----
FROM node:20-slim AS runner
WORKDIR /app
ENV NODE_ENV=production

# copy only what's needed to run `next start`
COPY --from=builder /app/package.json /app/package-lock.json ./
COPY --from=builder /app/node_modules ./node_modules
COPY --from=builder /app/.next ./.next
COPY --from=builder /app/public ./public
COPY --from=builder /app/next.config.* ./

EXPOSE 3000
CMD ["npm", "start"]
