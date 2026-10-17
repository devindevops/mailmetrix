# MailMetrix

**Self-hosted email infrastructure diagnostics.**

MailMetrix is an email diagnostics toolkit for developers, system administrators, and DevOps engineers. It brings SMTP testing, DNS email authentication checks, email header analysis, and DKIM/DMARC generation together in one web application.

Run MailMetrix in your own environment and maintain control over how you deploy and access your email diagnostic tools.

> **Project status:** Under active development. Review the current implementation and security considerations before using MailMetrix with sensitive credentials or exposing it to a network.

## Why MailMetrix?

Troubleshooting email infrastructure can require SMTP credentials, DNS configuration details, and potentially sensitive email headers.

MailMetrix provides a self-hosted alternative to relying entirely on hosted email diagnostic tools. You can run the application using Docker Compose and access its web interface from your own environment.

Self-hosting helps reduce dependence on third-party diagnostic services, but it does not automatically guarantee security. The security of a deployment also depends on application behavior, network configuration, access controls, and how credentials are handled.

### Key principles

- **Self-hosted:** Run the application in infrastructure you control.
- **Containerized:** Deploy the frontend and backend using Docker Compose.
- **Modular:** Keep backend routes, services, and frontend feature logic separated.
- **Practical:** Bring commonly used email diagnostics into one interface.
- **Transparent:** Inspect the source code, report issues, and contribute improvements.

## Features

### 1. SMTP Tester

Test SMTP connectivity and authentication against a specified mail server.

Use it to investigate connection problems and troubleshoot SMTP configuration.

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

**Note:** A generated record is not proof that your email authentication configuration is correct. Validate the published configuration after deployment.

## Architecture

MailMetrix separates the backend API from the frontend application.

### Backend

```text
backend/
└── src/
    ├── Dockerfile
    ├── package.json
    ├── package-lock.json
    └── src/
        ├── routes/
        │   ├── dns.js
        │   ├── generator.js
        │   ├── headers.js
        │   └── smtp.js
        ├── services/
        │   ├── dns.js
        │   ├── generator.js
        │   ├── headers.js
        │   └── smtp.js
        └── server.js
```

### Frontend

```text
frontend/
├── Dockerfile
├── nginx.conf
└── src/
    ├── app.js
    ├── features/
    │   ├── dns.js
    │   ├── flow.js
    │   ├── generator.js
    │   ├── headers.js
    │   ├── smtp.js
    │   ├── tabs.js
    │   └── utils.js
    ├── icons/
    ├── index.html
    ├── sitemap.xml
    ├── site.webmanifest
    └── style.css
```

`server.js` and `app.js` serve as the backend and frontend bootstrap/orchestration files.

Backend routes and services separate API handling from feature logic. Frontend feature modules organize the corresponding user-interface behavior.

The frontend intentionally uses a single-page HTML shell, avoiding unnecessary template and loading complexity.

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

## API Reference

The following endpoints are currently documented by the project.

| Method | Endpoint | Purpose |
|---|---|---|
| `GET` | `/api/health` | Check backend health |
| `POST` | `/api/smtp/test` | Run an SMTP test |
| `GET` | `/api/dns/check?domain=example.com` | Check email-related DNS records |
| `GET` | `/api/dns/dkim?domain=example.com&selector=google` | Check a DKIM selector |
| `POST` | `/api/headers/analyze` | Analyze submitted email headers |

Request bodies, response schemas, and error formats depend on the current API implementation.

Refer to the backend route and service modules for implementation details.

## Security and Privacy

MailMetrix is designed to support self-hosted email diagnostics. Deploy it with appropriate security controls.

### Protect SMTP credentials

- Use credentials intended for testing whenever possible.
- Do not submit production credentials unless the deployment and its security controls have been reviewed.
- Do not commit credentials to Git.
- Avoid placing secrets in URLs, shell history, logs, or screenshots.
- Rotate credentials if they may have been exposed.

### Protect the application

- Do not expose an unauthenticated diagnostic interface to untrusted networks.
- Restrict access through appropriate network controls and authentication.
- Use HTTPS when accessing the application remotely.
- Keep Docker, the host operating system, and application dependencies updated.
- Review the application's logging and error-handling behavior before processing sensitive information.

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