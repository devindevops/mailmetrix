# Unprivileged Nginx build: runs entirely as uid 101 ("nginx") and listens on
# 8080, so no root process and no privileged-port binding are needed.
# 1.30 is the current stable nginx line. Do not use the floating "nginx:alpine".
#
# For fully reproducible builds, also pin the digest:
#   docker buildx imagetools inspect nginxinc/nginx-unprivileged:1.30-alpine
#   FROM nginxinc/nginx-unprivileged:1.30-alpine@sha256:<digest>
# and let Renovate/Dependabot bump it, otherwise it never receives updates.
FROM nginxinc/nginx-unprivileged:1.30-alpine

# Apply Alpine security updates (needs root).
USER root
RUN apk upgrade --no-cache

# Copy assets and configuration with root ownership so the unprivileged nginx worker
# can read them but cannot modify or tamper with them at runtime.
COPY src /usr/share/nginx/html
COPY nginx.conf /etc/nginx/conf.d/default.conf

# Drop privileges to the unprivileged "nginx" user (uid 101).
USER nginx

EXPOSE 8080

CMD ["nginx", "-g", "daemon off;"]