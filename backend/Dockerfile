# Pinned to a Node.js LTS line (24, supported until 2028-04-30) on a supported
# Alpine release (3.24, supported until 2028-06-01). Do not use floating tags
# like "node:alpine".
#
# For fully reproducible builds, also pin the digest:
#   docker buildx imagetools inspect node:24-alpine3.24   # copy the "Digest:" line
#   FROM node:24-alpine3.24@sha256:<digest>
# and let Renovate/Dependabot bump it, otherwise it never receives updates.
FROM node:24-alpine3.24

ENV NODE_ENV=production

WORKDIR /app

# Apply Alpine security updates without leaving a package cache behind.
RUN apk upgrade --no-cache

# Production dependencies only (devDependencies are not installed).
COPY package*.json ./
RUN npm ci --omit=dev && npm cache clean --force

COPY --chown=node:node src ./src

# Drop root: the "node" user (uid 1000) ships with the official image.
USER node

# No --watch in production. Restarts are handled by Docker's restart policy,
# and `docker compose watch` (sync+restart) covers local development.
CMD ["node", "src/server.js"]