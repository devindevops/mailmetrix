# MailMetrix

**Self-hosted email infrastructure diagnostics.**

MailMetrix is an email diagnostics toolkit for developers, system administrators, and DevOps engineers. It brings SMTP testing, DNS email authentication checks, email header analysis, and DKIM/DMARC generation together in one web application. It also includes blacklist checking, a domain deliverability score, a TLS certificate inspector, and shareable, exportable results.

Run MailMetrix in your own environment and maintain control over how you deploy and access your email diagnostic tools.

> **Project status:** Under active development. Review the current implementation and the [Security and Privacy](#security-and-privacy) section before using MailMetrix with sensitive credentials or exposing it to a network.

> **Important:** MailMetrix has **no built-in user authentication**. Do not expose it to the public internet without placing authentication in front of it. See [Protect access to your deployment](#protect-access-to-your-deployment).

> **Authorized use only:** Use MailMetrix only against systems, domains, and mail servers you own or are explicitly authorized to test.

> **Checked before release:** Changes are validated with CodeQL code scanning, CI code and dependency validation, Docker validation, and a SonarCloud quality gate. See [Quality and Security Checks](#quality-and-security-checks).

> **Privacy:** MailMetrix is self-hosted. The maintainers do not receive your data. See the [Privacy Policy](#privacy-policy).

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

### 5. Blacklist Checker

Check whether a sending IP address or domain is listed on common DNS blacklists (DNSBLs).

- **IPv4 addresses** are checked against 9 lists: Spamhaus ZEN, Barracuda, SpamCop, Passive Spam Block List, UCEPROTECT Level 1, DroneBL, Mailspike, Manitu (NiX Spam), and s5h.net.
- **Domains** are checked against 3 domain lists (Spamhaus DBL, SURBL, URIBL). The domain's first three A-record IPs are also checked against the IP lists.
- Each list reports `listed`, `clean`, or `unknown`, with the return code and the list's reason text where available.
- IPv6 addresses are not supported for IP blacklists.

```http
POST /api/blacklist
Content-Type: application/json

{ "target": "203.0.113.10" }
```

**Note:** Several blacklists (Spamhaus in particular) refuse queries that arrive through large public resolvers such as `8.8.8.8` or `1.1.1.1`. These answers are shown as `unknown`, not `clean`. If you see many `unknown` results, point the backend container at your host's or provider's resolver using the commented `dns:` option in `docker-compose.yml`.

### 6. Deliverability Score

Grade a domain's overall email health from **A to F** (0-100) by combining several checks into one report, with fixes ordered by impact.

| Check | Weight | What is evaluated |
|---|---|---|
| MX records | 10 | Presence and redundancy of MX records |
| SPF | 20 | Single record, enforcement mechanism (`-all`, `~all`, `+all`), and the 10 DNS-lookup limit |
| DKIM | 15 | Public key found on a supplied selector or on common selectors |
| DMARC | 20 | Policy strength (`none`, `quarantine`, `reject`) and reporting address |
| Reverse DNS (FCrDNS) | 10 | Forward-confirmed PTR records for the MX IP addresses |
| Blacklists | 10 | MX IP addresses on the IP blacklists listed above |
| MTA-STS | 5 | Presence of the `_mta-sts` TXT record |
| Mail server TLS | 10 | Certificate and protocol of the primary MX on port 25 |

Checks that cannot be evaluated (for example, the TLS check when outbound port 25 is blocked, or blacklist servers refusing the resolver) are skipped and excluded from the total rather than counted as failures.

```http
POST /api/score
Content-Type: application/json

{ "domain": "example.com", "selector": "default" }
```

`selector` is optional. When omitted, a list of common DKIM selectors is probed; a domain using a custom selector may therefore show a partial DKIM result until its selector is supplied.

**Note:** A score is a diagnostic aid, not a guarantee of inbox placement. Receiving providers apply their own reputation and content rules.

### 7. TLS Certificate Inspector

Negotiate TLS with a mail (or other TLS) server and review its certificate and connection details.

- Supported ports: `25`, `587`, `2525` (SMTP with STARTTLS), and `465`, `993`, `995`, `443` (implicit TLS).
- Reports the negotiated protocol and cipher, whether the certificate chain is trusted, the certificate subject, issuer, validity dates, days remaining, key type and size, subject alternative names, SHA-256 fingerprint, and the certificate chain.
- Produces severity-rated findings for expired or soon-to-expire certificates, hostname mismatch, untrusted or self-signed certificates, deprecated TLS versions, weak ciphers, and weak RSA keys.
- Optionally probes which TLS versions (1.0-1.3) the server accepts. This opens several extra connections and is slower.
- Untrusted certificates on port 25 are reported as warnings rather than failures, because opportunistic TLS between mail servers commonly tolerates them. Strict senders and MTA-STS do not.

```http
POST /api/tls
Content-Type: application/json

{ "host": "mail.example.com", "port": 25, "versions": false }
```

Because this tool makes outbound connections to a host you specify, it is guarded by the same address restrictions as the SMTP tester (see [Built-in protections](#built-in-protections)).

### 8. Shareable Links & Export

The results of every tool (SMTP Tester, DNS Email Checker, Email Header Analyzer, DKIM & DMARC Generator, Blacklist Checker, Deliverability Score, and TLS Inspector) include a bar with:

- **Share link:** stores the result on the server and returns a link of the form `/?share=<id>`. Links expire automatically (7 days by default; see `SHARE_TTL_DAYS`).
- **JSON** and **CSV:** download the result from the browser. CSV values are protected against spreadsheet formula injection.
- **PDF:** prints only the result using the browser's print dialog, where you can choose "Save as PDF".

```http
POST /api/share
GET  /api/share/<id>
GET  /api/share/<id>/export?format=json|csv|html
```

Notes:

- SMTP Tester, DNS Checker, Header Analyzer, DKIM & DMARC Generator, Blacklist, Deliverability Score, and TLS results can be shared.
- A Header Analyzer share contains only the parsed analysis (sender and return-path addresses, message ID, authentication results, delivery path, and findings). The raw header text you pasted is never sent to the share endpoint. Header analyses can still contain third-party email addresses and mail server IP addresses, so by default the subject, display names, and the username part of every email address are hidden in shared and exported results. You can turn this off with the checkbox shown under the result. The PDF option prints the result exactly as displayed on screen.
- An SMTP share contains only the diagnostic output: status, message ID, accepted and rejected recipients, error stage and code, plus the SMTP host, port, and security mode. It never contains the username, password, From address, or message body.
- A DNS share contains the MX, SPF, and DMARC results, plus the DKIM result if a selector was checked.
- DKIM private keys are never included in shared results, JSON/CSV downloads, or printed output, even though the generator displays them on screen. The server also removes private-key blocks and any field named like a password, secret, token, or private key before anything is stored.
- Anyone who has a share link can view the result until it expires. Link IDs are random and unguessable, but links are not otherwise authenticated.
- If you protect your deployment with authentication, people opening a share link need access to the deployment too.
- Shared results are written to the `mailmetrix-data` Docker volume so they survive container restarts and rebuilds. Each result is limited to 256 KB, and storage is capped at 5,000 results.

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
    │   ├── _util.js
    │   ├── blacklist.js
    │   ├── dns.js
    │   ├── generator.js
    │   ├── headers.js
    │   ├── score.js
    │   ├── share.js
    │   ├── smtp.js
    │   └── tls.js
    ├── server.js
    └── services
        ├── blacklist.js
        ├── dns.js
        ├── generator.js
        ├── headers.js
        ├── netguard.js
        ├── score.js
        ├── share.js
        ├── smtp.js
        └── tls.js
```

### Frontend

```text
frontend/
├── Dockerfile
├── nginx.conf
└── src
    ├── app.js
    ├── features
    │   ├── blacklist.js
    │   ├── dns.js
    │   ├── flow.js
    │   ├── generator.js
    │   ├── headers.js
    │   ├── renderers.js
    │   ├── score.js
    │   ├── share.js
    │   ├── smtp.js
    │   ├── tabs.js
    │   ├── tls.js
    │   ├── ui.js
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

Shared building blocks:

- `backend/src/services/netguard.js` is the common outbound-connection guard (public-address validation and hostname checks) used by the blacklist, score, and TLS services.
- `frontend/src/features/flow.js` drives the Workflow card for every tool, and `frontend/src/features/share.js` wires the Blacklist, Score, and TLS tools (request, rendering, and the share/export bar) and provides the same share/export bar to the SMTP, DNS, and Generator tabs. `renderers.js` renders shared SMTP, DNS, and Generator results when a share link is opened. `ui.js` provides DOM helpers that build results with text nodes rather than `innerHTML`.

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

Shared results are kept in the `mailmetrix-data` volume. `docker compose down` keeps the volume; `docker compose down -v` deletes it, along with all stored share links.

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
| `POST` | `/api/blacklist` | Check an IPv4 address or domain against DNS blacklists |
| `POST` | `/api/score` | Calculate a domain's deliverability score |
| `POST` | `/api/tls` | Inspect a server's TLS certificate and connection |
| `POST` | `/api/share` | Store a shareable result (SMTP, DNS, Header, Generator, Blacklist, Score, or TLS) and return a share ID |
| `GET` | `/api/share/<id>` | Retrieve a shared result |
| `GET` | `/api/share/<id>/export?format=json\|csv\|html` | Download a shared result |

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
| **TLS inspector and score connections** | The TLS inspector (and the TLS check inside the deliverability score) validates the hostname, resolves it once, rejects loopback, private, link-local, and reserved addresses, and connects only to the validated IP. Ports are limited to a fixed allow-list (`25`, `465`, `587`, `2525`, `443`, `993`, `995`). |
| **Shared results** | Only SMTP, DNS, Header, Generator, Blacklist, Score, and TLS results can be stored, and header shares never include the raw header text. Private keys and secret-named fields are removed before storage. Share IDs are random, entries expire automatically, payload size and total count are capped, shared output is rendered with escaped text, and the HTML export is served with a restrictive Content-Security-Policy. |

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
- Shared result links are protected only by an unguessable ID. Anyone with a link can view the result until it expires, and anyone who can reach the deployment can create links. Share results only if their contents (hostnames, IP addresses, certificate details, and domain configuration) are fine to disclose to the recipients. For SMTP results this includes the SMTP host and the accepted and rejected recipient addresses; for header analyses it includes mail server hostnames and IP addresses from the delivery path.
- Shared results are stored as files in the `mailmetrix-data` volume and are removed after `SHARE_TTL_DAYS`. Back up or delete that volume according to your own retention needs.

### Understand external connections

Self-hosting does not mean that every diagnostic operation is entirely local.

For example:

- SMTP tests connect to the mail server being tested.
- DNS checks query DNS infrastructure.
- Header analysis processes the supplied header data.
- DKIM/DMARC generation operates according to the implementation of the generator.
- Blacklist checks send DNS queries containing the IP address or domain being checked to the operators of the blacklists, through the resolver available to the backend container.
- The TLS inspector connects to the host and port you specify, and the deliverability score connects to the domain's primary MX on port 25 and queries DNS for its records and blacklists.

Review the source code to understand which services receive requests or data during each operation.

### Use it only on systems you are authorized to test

MailMetrix can connect to mail servers, query DNS, and send test emails. Use it only against infrastructure you own or have explicit permission to test, and only send test emails to recipients who expect them. Using it to probe, harass, or send unsolicited email through systems you do not control may violate the law or the terms of those services. You are responsible for how you use it.

For what data an instance handles and where it goes, see the [Privacy Policy](#privacy-policy).

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
| `RATE_LIMIT_BLACKLIST` | `30` | Max blacklist-check requests per client per window. |
| `RATE_LIMIT_SCORE` | `15` | Max deliverability-score requests per client per window. |
| `RATE_LIMIT_TLS` | `20` | Max TLS-inspection requests per client per window. |
| `RATE_LIMIT_SHARE` | `60` | Max share and share-export requests per client per window. |
| `SHARE_DIR` | `/app/data/shares` in `docker-compose.yml` | Directory where shared results are stored. Keep it on the `mailmetrix-data` volume so links survive restarts. |
| `SHARE_TTL_DAYS` | `7` | Days before a shared result link expires and is deleted. |
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

## Quality and Security Checks

The following automated checks are run on changes before a release:

| Check | What it covers |
|---|---|
| **CodeQL** (GitHub code scanning) | Static analysis of the source code for security vulnerabilities and coding errors. |
| **MailMetrix CI: Code and dependency validation** | Validates the application code and its dependencies. |
| **MailMetrix CI: Docker validation** | Validates the Docker build configuration. |
| **SonarCloud Code Analysis** | Static analysis for code quality and security issues; the Quality Gate must pass. |

These checks reduce risk but do not guarantee that the software is free of vulnerabilities or defects. They complement, and do not replace, code review, testing, and the deployment guidance in [Security and Privacy](#security-and-privacy).

## Privacy Policy

*Last updated: 11 November 2026*

### In short

- MailMetrix is **self-hosted software**. The maintainers do not operate a hosted service and **do not receive any data** from your instance.
- MailMetrix has **no analytics, advertising, tracking, or telemetry**, and does not send data to the maintainers.
- The backend does not store SMTP credentials, email headers, or generated keys. They are processed for the request and discarded.
- The only results the backend stores are SMTP, DNS, Header Analysis, Generator, Blacklist, Deliverability Score, and TLS results that a user explicitly chooses to share. Passwords, DKIM private keys, and raw header text are never stored. Header analyses hide the subject, display names, and email usernames by default. Shared results are kept on your instance's disk until they expire.
- Data leaves your instance only to destinations **you** specify, such as the SMTP server you test and DNS resolvers.

### Scope and responsibility

This policy applies to the MailMetrix software and to the project's GitHub Pages website. Because you run MailMetrix yourself, **you (or your organization) are the operator of your instance** and are responsible for the data it processes, for protecting access to it, and for informing and obtaining any permissions needed from anyone else who uses it. If you run MailMetrix for other people, you may need your own privacy notice describing how your deployment handles their data.

### What an instance processes

| Data | Purpose | Retention |
|---|---|---|
| SMTP host, port, username, password, sender, recipient, subject, and message | To authenticate to and send a test email through the SMTP server you specify. | Used in memory for the request and not stored by MailMetrix. The password is not included in API responses. The data is sent to the SMTP server you specify, which handles it under its own policies. |
| Domain names and DKIM selectors | To perform DNS lookups. | Not stored. They appear in request logs because they are part of the request URL. |
| Email headers | To analyze message routing and authentication results. | Processed in memory and not stored. Only the parsed analysis (never the raw header text) is stored, and only if the user selects "Share link". |
| Generated DKIM private keys | To give you key material to publish and keep. | Not stored on the server. The key is delivered to your browser, so protect it and transmit it only over HTTPS. |
| IP addresses, domains, hostnames, and ports submitted to the Blacklist, Score, and TLS tools | To perform blacklist lookups, score checks, and TLS handshakes. | Sent in the request body and processed in memory; not stored unless the user shares the result. The queried IP or domain is sent to blacklist operators via DNS, and the TLS and score tools connect to the host specified. |
| Shared results (SMTP, DNS, Header Analysis, Generator, Blacklist, Score, and TLS results) | To let a user send a result to someone else through a link. Shared SMTP results contain diagnostic output and the SMTP host and port, not credentials or message content; shared generator results exclude private keys; shared header analyses exclude the raw headers and, by default, hide the subject, display names, and email usernames. | Stored as a file on the instance's `mailmetrix-data` volume only when the user selects "Share link", and deleted automatically after `SHARE_TTL_DAYS` (7 days by default). Anyone with the link can view it until then. |
| Client IP addresses | To apply rate limits. | Held temporarily in memory as counters, which expire after the rate-limit window and reset on restart. They also appear in Nginx access logs. |
| Logs | To operate and troubleshoot the instance. | See below. |

### Logs

- **Backend:** logs a timestamp, request method, URL (including the query string), status code, and duration. It does not intentionally log request bodies, so SMTP credentials sent in a request body are not written to these logs. Error messages may also be logged.
- **Nginx:** logs client IP addresses, request lines, status codes, and user agents in its standard access-log format. Opening a share link (`/?share=<id>`) records the share ID in these logs.
- **Retention:** Docker keeps container logs on the host. The default Compose file rotates them (10 MB per file, up to 3 files per service). Removing the containers, for example with `docker compose down`, deletes their logs. Adjust log settings if you need shorter retention.

### Third parties and external connections

- MailMetrix does not include third-party analytics, advertising, or tracking services.
- SMTP tests connect to the mail server you specify, and DNS checks query DNS resolvers available to your environment. Those services receive the data needed for the lookup or message and handle it under their own policies.
- Blacklist checks and the blacklist portion of the deliverability score send DNS queries containing the IP address or domain being checked to the blacklist operators (for example Spamhaus, Barracuda, or SpamCop) through your resolver. Those operators handle query data under their own policies.
- Your hosting provider, network, or reverse proxy can observe traffic to your instance. Use HTTPS for remote access.

### Cookies and browser storage

The MailMetrix web interface is designed not to use tracking cookies or third-party scripts. If you add authentication or other components in front of it, those may set their own cookies, which are your responsibility.

### The project website

The MailMetrix GitHub Pages site is a static page. It does not use analytics, cookies, or forms, and does not load third-party fonts or scripts. The site is hosted by GitHub, which may process visitor information such as IP addresses under [GitHub's privacy statement](https://docs.github.com/en/site-policy/privacy-policies/github-general-privacy-statement).

### Your choices

- Use test credentials rather than production credentials wherever possible.
- Protect your instance with authentication and HTTPS.
- Be careful before pasting real email headers, which can contain addresses, IP addresses, and message identifiers of third parties.
- Configure log retention to suit your needs.
- Share results only when their contents are fine for the recipients to see, and lower `SHARE_TTL_DAYS` if you want links to expire sooner.
- Do not post credentials, private keys, or personal data in public issues.

### Changes to this policy

Changes are made through the repository, and the history is visible in Git. The date above shows when this policy was last updated.

### Questions

For privacy questions, open an issue without including personal data. For security vulnerabilities, follow [SECURITY.md](SECURITY.md) instead of opening a public issue.

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

MailMetrix is distributed under the license provided in the repository's [LICENSE](LICENSE) file.

Review that file before redistributing or incorporating MailMetrix into another project. It sets out the exact terms of use, including any warranty and liability disclaimers. MailMetrix is provided to you to run on your own systems, and you are responsible for how you deploy and use it.

## Project Links

- **Source code:** https://github.com/devindevops/mailmetrix
- **Issues:** https://github.com/devindevops/mailmetrix/issues
- **Security policy:** [SECURITY.md](SECURITY.md)
- **Privacy policy:** [Privacy Policy](#privacy-policy)
- **License:** [LICENSE](LICENSE)

---

**MailMetrix — Email diagnostics, self-hosted and under your control.**