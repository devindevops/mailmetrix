# MailMetrix

**Self-hosted email infrastructure diagnostics.**

MailMetrix is an email diagnostics toolkit for developers, system administrators, and DevOps engineers. It brings SMTP testing, DNS email authentication checks, email header analysis, and DKIM/DMARC generation together in one web application.

Run MailMetrix in your own environment and maintain control over how you deploy and access your email diagnostic tools.

> **Project status:** Under active development. Review the current implementation and the [Security and Privacy](#security-and-privacy) section before using MailMetrix with sensitive credentials or exposing it to a network.

> **Important:** MailMetrix has **no built-in user authentication**. Do not expose it to the public internet without placing authentication in front of it. See [Protect access to your deployment](#protect-access-to-your-deployment).

## Why MailMetrix?

Troubleshooting email infrastructure can require SMTP credentials, DNS configuration details, and potentially sensitive email headers.

MailMetrix provides a self-hosted alternative to relying entirely on hosted email diagnostic tools. You can run the application using Docker Compose and access its web interface from your own environment.

Self-hosting helps reduce dependence on third-party diagnostic services, but it does not automatically guarantee security. The security of a deployment also depends on application behavior, network configuration, access controls, and how credentials are handled.

### Key principles

- **Self-hosted:** Run the application in infrastructure you control.
- **Containerized:** Deploy the frontend and backend using Docker Compose.
- **Modular:** Keep backend routes, services, and frontend feature logic separated.
- **Practical:** Bring commonly used email diagnostics into one interface.
- **Hardened by default:** Outbound-connection guardrails, rate limiting, security headers, and non-root containers are built in.
- **Transparent:** Inspect the source code, report issues, and contribute improvements.

## Features

### 1. SMTP Tester

Test SMTP connectivity and authentication against a specified mail server.

Use it to investigate connection problems and troubleshoot SMTP configuration.

Because this tool makes outbound connections and can send a real email, it is guarded by several restrictions (see [Built-in protections](#built-in-protections)):

- Only standard mail ports are allowed by default (`25`, `465`, `587`, `2525`).
- Servers that resolve to loopback, private, link-local, or cloud-metadata addresses are rejected. To test a trusted internal relay, add its hostname to `SMTP_ALLOWED_HOSTS`.
- The From and Recipient fields must each be a single plain email address.
- Network-level failures return a generic message; SMTP protocol errors (for example, rejected credentials) are still shown.

### 2. DNS Email Checker

Inspect DNS records associated with email infrastructure.

Supported checks include:

- MX records
- SPF records
- DMARC records
- DKIM records using a specified selector

Example API requests:

```http
GET /api/dns/check?domain=example.com
GET /api/dns/dkim?domain=example.com&selector=google
```

The results depend on the domain's published DNS records and the implementation of the relevant checks.

### 3. Email Header Analyzer

Submit email headers for analysis to help investigate message routing and email authentication information.

```http
POST /api/headers/analyze
```

Review sensitive information before submitting headers, especially when they originate from real users or production email systems.

### 4. DKIM & DMARC Generator

Generate DKIM and DMARC configuration material to assist with email authentication setup.

Review generated records and key material before deploying them to production DNS.

RSA key generation is CPU-intensive, so it runs off the main thread with a concurrency limit. If the server is busy, the API returns `503` with a `Retry-After` header; retry shortly.

**Note:** A generated record is not proof that your email authentication configuration is correct. Validate the published configuration after deployment.

## Architecture

MailMetrix separates the backend API from the frontend application.

- **Frontend:** an unprivileged Nginx container that serves the web interface and proxies `/api/` to the backend. It listens on port `8080` inside the container, published on host port `50000`.
- **Backend:** a Node.js API that is **not published to the host**; it is reachable only through the frontend proxy or from other containers on the Compose network.

### Backend

```text
backend/
├── Dockerfile
├── package.json
├── package-lock.json
└── src
    ├── routes
    │   ├── dns.js
    │   ├── generator.js
    │   ├── headers.js
    │   └── smtp.js
    ├── server.js
    └── services
        ├── dns.js
        ├── generator.js
        ├── headers.js
        └── smtp.js
```

### Frontend

```text
frontend/
├── Dockerfile
├── nginx.conf
└── src
    ├── app.js
    ├── features
    │   ├── dns.js
    │   ├── flow.js
    │   ├── generator.js
    │   ├── headers.js
    │   ├── smtp.js
    │   ├── tabs.js
    │   └── utils.js
    ├── icons
    │   ├── android-chrome-192x192.png
    │   ├── android-chrome-512x512.png
    │   ├── apple-touch-icon.png
    │   ├── favicon-16x16.png
    │   ├── favicon-32x32.png
    │   └── favicon.ico
    ├── index.html
    ├── sitemap.xml
    ├── site.webmanifest
    ├── style.css
    └── version.json
```

`server.js` and `app.js` serve as the backend and frontend bootstrap/orchestration files.

Backend routes and services separate API handling from feature logic. Frontend feature modules organize the corresponding user-interface behavior.

The frontend intentionally uses a single-page HTML shell, avoiding unnecessary template and loading complexity.

## Version Management

MailMetrix includes a version synchronization script at `scripts/sync-version.js` to keep version information consistent across the project.

The root `package.json` is the single source of truth for the application version.

### What the script updates

When executed through npm's `version` lifecycle hook, the script synchronizes the version across the following files:

| File | Purpose |
|---|---|
| `package.json` | Defines the source version |
| `frontend/src/version.json` | Provides version information to the frontend footer |
| `backend/package.json` | Keeps the backend package version synchronized |
| `backend/package-lock.json` | Updates the backend lockfile version metadata |

The script also attempts to stage the modified files using `git add`, allowing them to be included in the version commit created by npm.

### Bumping the version

From the project root, run one of the following commands:

```bash
npm version patch
```

For a minor release:

```bash
npm version minor
```

For a major release:

```bash
npm version major
```

These commands follow semantic versioning conventions:

- **Patch:** Bug fixes and backward-compatible corrections, such as `1.0.0` → `1.0.1`.
- **Minor:** Backward-compatible feature additions, such as `1.0.0` → `1.1.0`.
- **Major:** Changes that introduce breaking behavior, such as `1.0.0` → `2.0.0`.

Use the version increment that reflects the actual changes in the release.

### How synchronization works

When npm invokes the `version` lifecycle hook, the script:

1. Reads the updated version from the root `package.json`.
2. Updates `frontend/src/version.json`, including its build timestamp.
3. Synchronizes the version in the backend `package.json`, if present.
4. Updates the corresponding version metadata in the backend `package-lock.json`, if present.
5. Attempts to stage the modified files for the version commit.

The script is designed to run automatically when the root package's npm version lifecycle is configured to invoke it.

**Important:** Verify that the root `package.json` contains the appropriate `version` lifecycle configuration, such as:

```json
{
  "scripts": {
    "version": "node scripts/sync-version.js"
  }
}
```

If the `version` script already exists, integrate the command into the existing configuration rather than replacing it.

### Release considerations

- Run version commands from the repository root.
- Ensure the working tree is in an appropriate state before creating a release.
- Review the generated changes before publishing.
- Confirm that the frontend footer displays the updated version.
- Ensure the backend package and lockfile remain synchronized.

The script updates local project files; it does not publish Docker images, create a GitHub Release, or deploy the application by itself.


## Requirements

Before starting MailMetrix, ensure you have:

- Docker Engine installed and running.
- Docker Compose v2 available through the `docker compose` command.
- A terminal with access to the project directory.

The initial deployment builds the application from source.

## Quick Start

### 1. Clone the repository

```bash
git clone https://github.com/devindevops/mailmetrix.git
cd mailmetrix
```

### 2. Configure the environment

Review `.env.example` and the Docker Compose configuration.

Create a local `.env` file only if your deployment requires the variables defined by the project:

```bash
cp .env.example .env
```

Do not add real SMTP credentials, passwords, API keys, or other secrets to the repository.

All optional settings, including security options, are listed in [Configuration](#configuration).

### 3. Build the containers

```bash
docker compose build
```

For a clean rebuild without using cached build layers:

```bash
docker compose build --no-cache
```

### 4. Start MailMetrix

```bash
docker compose up -d
```

### 5. Open the application

```bash
http://localhost:50000
```

### 6. Inspect container status

```bash
docker compose ps
```

View service logs:

```bash
docker compose logs --tail=100
```

Follow logs in real time:

```bash
docker compose logs -f
```

Stop the application:

```bash
docker compose down
```

### Development with Docker Compose Watch

If your Docker Compose configuration defines file-watch actions, you can use:

```bash
docker compose watch
```

Watch behavior depends on the configured services and synchronization or rebuild rules. If watching is not configured, use the regular build-and-run workflow.

The production image does not use `node --watch`; automatic restarts during development are handled by Compose Watch (`sync+restart`), and restarts after a crash are handled by Docker's restart policy.

## API Reference

The following endpoints are currently documented by the project.

| Method | Endpoint | Purpose |
|---|---|---|
| `GET` | `/api/health` | Minimal liveness probe (returns only a status) |
| `POST` | `/api/smtp/test` | Run an SMTP test |
| `GET` | `/api/dns/check?domain=example.com` | Check email-related DNS records |
| `GET` | `/api/dns/dkim?domain=example.com&selector=google` | Check a DKIM selector |
| `POST` | `/api/headers/analyze` | Analyze submitted email headers |
| `POST` | `/api/generator` | Generate SPF, DKIM, and DMARC records |

Request bodies, response schemas, and error formats depend on the current API implementation.

Refer to the backend route and service modules for implementation details.

### Rate limiting and busy responses

API endpoints are rate limited per client IP address. Clients receive:

- `429 Too Many Requests` when a limit is exceeded. The `Retry-After` and `RateLimit-*` headers indicate when to retry.
- `503 Service Unavailable` from `/api/generator` when too many key generations are already in progress.

Default limits and how to change them are in [Configuration](#configuration).

### Health endpoints

`/api/health` is intentionally minimal and safe to expose to monitoring systems. It does not report memory or CPU usage.

Detailed process telemetry is available from the backend at `/internal/health`, which only answers requests that come directly from inside the Docker network and are not proxied. It is blocked at the Nginx layer (`/api/internal/`). To read it from the host:

```bash
docker compose exec backend node -e "fetch('http://127.0.0.1:4000/internal/health').then(r=>r.json()).then(console.log)"
```

## Security and Privacy

MailMetrix is designed to support self-hosted email diagnostics. Deploy it with appropriate security controls.

### Built-in protections

| Area | Protection |
|---|---|
| **Outbound connection abuse (SSRF)** | The SMTP test resolves the target host once, validates every returned address, and connects only to the validated IP, which mitigates DNS-rebinding. Loopback, private (RFC 1918), CGNAT, link-local (including the `169.254.169.254` cloud metadata address), multicast, and reserved ranges are blocked, including IPv6 and IPv4-mapped forms. Ports are limited to `25`, `465`, `587`, and `2525` by default. |
| **Port-scanning oracle** | Network-level SMTP failures (refused, timeout, reset) return one generic message, so responses cannot be used to map internal hosts. Genuine SMTP protocol errors, such as rejected credentials, are still reported. |
| **Email abuse** | From and Recipient must each be a single valid address; address lists, `Name <addr>` forms, and header-injection attempts are rejected. Display names cannot add recipients. Subject is limited to 200 characters and message to 5,000. Optional recipient-domain restrictions are available. |
| **Rate limiting** | Per-IP limits on every API route, with stricter limits for the SMTP, generator, and DNS endpoints. |
| **Resource exhaustion** | DKIM key generation runs off the main thread with a concurrency cap and a bounded queue; excess requests receive `503` instead of stalling the server. |
| **HTTP hardening** | Nginx sends `Content-Security-Policy`, `X-Frame-Options`, `X-Content-Type-Options`, `Referrer-Policy`, and `Permissions-Policy` headers, hides its version, and strips the backend's `X-Powered-By` header. |
| **Information exposure** | The public health probe returns no process internals. Detailed telemetry is limited to the internal network. |
| **Container privileges** | Both containers run as non-root users (`node` for the backend, uid `101` for Nginx). All Linux capabilities are dropped and `no-new-privileges` is set. Base images are pinned to supported versions rather than floating tags. |

These controls reduce risk but do **not** replace authentication. Please read the limitations below.

### Protect access to your deployment

MailMetrix can open outbound connections, send test emails, and query DNS on behalf of whoever can reach it, and it has **no built-in login**. If it is reachable from the public internet without authentication, others can use your server to attempt credential stuffing against third-party SMTP servers, send unwanted email, and hide the origin of abusive traffic.

Put MailMetrix behind one of:

- Reverse-proxy authentication (for example, Nginx or Caddy HTTP Basic Auth)
- An identity-aware gateway such as Cloudflare Access or Authelia
- A private network such as Tailscale or WireGuard

Because Nginx is the only published service, protecting the whole site also protects the API.

Example of HTTP Basic Auth in `frontend/nginx.conf`. Add the `auth_basic` lines inside the `server` block:

```nginx
server {
    listen 8080;

    auth_basic           "MailMetrix";
    auth_basic_user_file /etc/nginx/.htpasswd;

    # Keep the container healthcheck working without credentials.
    location = /nginx-health {
        auth_basic off;
        access_log off;
        return 200 "ok\n";
    }

    # ... existing locations ...
}
```

Then:

1. Create the password file: `htpasswd -c frontend/.htpasswd youruser`
2. Mount it read-only into the frontend service in `docker-compose.yml`:
   ```yaml
   volumes:
     - ./frontend/.htpasswd:/etc/nginx/.htpasswd:ro
   ```
3. Change the frontend healthcheck to `wget -q --spider http://127.0.0.1:8080/nginx-health || exit 1`. Without this, the healthcheck receives `401` and the container reports unhealthy.
4. Do not commit `.htpasswd` to Git.

### Protect SMTP credentials

- Use credentials intended for testing whenever possible.
- Do not submit production credentials unless the deployment and its security controls have been reviewed.
- Do not commit credentials to Git.
- Avoid placing secrets in URLs, shell history, logs, or screenshots.
- Rotate credentials if they may have been exposed.

### Protect the application

- Put authentication in front of the application (see above) before exposing it to any untrusted network.
- Use HTTPS when accessing the application remotely. If TLS terminates in front of the Nginx container, enable `Strict-Transport-Security` there.
- Set `TRUST_PROXY` correctly so rate limiting identifies real client addresses (see [Configuration](#configuration)).
- Keep Docker, the host operating system, base images, and application dependencies updated. Pinned image tags do not update themselves; consider Renovate or Dependabot to propose bumps.
- Do not publish the backend port. The default Compose file uses `expose`, not `ports`, for the backend; keep it that way, because `TRUST_PROXY` and the internal-only health endpoint assume that Nginx is the only way in.
- If other services share the Compose network, consider placing them on a separate network so a compromised or misconfigured container cannot reach MailMetrix's backend directly.
- Review the application's logging and error-handling behavior before processing sensitive information.

### Understand the limits of the built-in controls

- Rate limits are stored in memory, per process. They reset when the backend restarts and are not shared across replicas. Use a shared store such as Redis if you run multiple backend instances.
- Per-IP limits slow down credential guessing but cannot stop a distributed attacker.
- `ENFORCE_TEST_RECIPIENT` compares the recipient with the user-supplied From address, so it limits each request to one mailbox rather than preventing abuse. `ALLOWED_RECIPIENT_DOMAINS` is the strong control because only the operator sets it.
- The Content Security Policy is strict (`script-src 'self'`). If you add inline scripts, third-party scripts, or web fonts to the frontend, update the policy in `frontend/nginx.conf`.
- Internationalized (non-ASCII) email domains must be supplied in punycode form.
- Network-level controls still matter. If you run on a cloud host, also block container access to the metadata address (`169.254.169.254`) or require IMDSv2 with a hop limit of 1.

### Understand external connections

Self-hosting does not mean that every diagnostic operation is entirely local.

For example:

- SMTP tests connect to the mail server being tested.
- DNS checks query DNS infrastructure.
- Header analysis processes the supplied header data.
- DKIM/DMARC generation operates according to the implementation of the generator.

Review the source code to understand which services receive requests or data during each operation.

### Report security vulnerabilities

Please do not publish exploitable security vulnerabilities or exposed credentials in public issues.

See [SECURITY.md](SECURITY.md) for reporting guidance.

## Configuration

The example environment file currently documents the backend port:

```dotenv
PORT=4000
```

Review the Docker Compose file and backend startup configuration to understand how this variable is used and how service ports are mapped.

Do not assume that every environment variable supported by a dependency is supported by MailMetrix.

### Optional settings

All of the following are optional. Add them to `.env` (or the backend `environment` block in `docker-compose.yml`) to override the defaults. Values set in the `environment` block take precedence over `.env`.

| Variable | Default | Purpose |
|---|---|---|
| `PORT` | `4000` | Backend listening port. |
| `TRUST_PROXY` | `1` in `docker-compose.yml` | Number of reverse proxies in front of the backend (or a subnet list such as `loopback, 172.16.0.0/12`). Must match your real setup: too low and every user shares one rate-limit bucket; too high lets clients spoof their IP. Never use `true`. If something sits in front of the Nginx container (a load balancer or CDN), increase it accordingly. |
| `RATE_LIMIT_WINDOW_MS` | `900000` | Rate-limit window in milliseconds (15 minutes). |
| `RATE_LIMIT_SMTP` | `20` | Max SMTP test requests per client per window. |
| `RATE_LIMIT_GENERATOR` | `30` | Max generator requests per client per window. |
| `RATE_LIMIT_DNS` | `60` | Max DNS requests per client per window. |
| `RATE_LIMIT_HEADERS` | `100` | Max header-analysis requests per client per window. |
| `SMTP_ALLOWED_PORTS` | `25,465,587,2525` | SMTP ports the tester may connect to. |
| `SMTP_ALLOWED_HOSTS` | *(empty)* | Comma-separated hostnames of trusted internal relays that bypass the private-address block. Only list names you control. |
| `ALLOWED_RECIPIENT_DOMAINS` | *(empty)* | Restrict test-email recipients to these domains, for example `example.com,*.corp.example.com`. `*.` matches subdomains. Empty means no domain restriction. |
| `ENFORCE_TEST_RECIPIENT` | `false` | When `true`, the test email may only be sent to the From address. |
| `DKIM_MAX_CONCURRENT` | `2` | Maximum simultaneous DKIM key generations. |
| `DKIM_MAX_QUEUE` | `10` | Maximum queued key generations before returning `503`. |

Example for a shared or internet-adjacent deployment:

```dotenv
PORT=4000
ALLOWED_RECIPIENT_DOMAINS=example.com
ENFORCE_TEST_RECIPIENT=true
RATE_LIMIT_SMTP=10
```

Keep `.env.example` in sync with this list when you add or change settings.

## Contributing

Contributions, bug reports, documentation improvements, and feature suggestions are welcome.

Before submitting a pull request:

1. Review the existing code structure.
2. Keep changes focused on the relevant feature.
3. Test the affected functionality.
4. Avoid committing secrets, credentials, or private email data.
5. Describe the changes and any testing performed.

For security-sensitive findings, follow the instructions in [SECURITY.md](SECURITY.md) instead of opening a public issue.

## License

MailMetrix is distributed under the license provided in the repository's `LICENSE` file.

Review that file before redistributing or incorporating MailMetrix into another project.

## Project Links

- **Source code:** https://github.com/devindevops/mailmetrix
- **Issues:** https://github.com/devindevops/mailmetrix/issues
- **Security policy:** [SECURITY.md](SECURITY.md)

---

**MailMetrix — Email diagnostics, self-hosted and under your control.**