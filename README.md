# MailMetrix

SMTP & Email Infrastructure Diagnostics.

## Tools
- SMTP Tester
- DNS Email Checker (MX, SPF, DMARC, DKIM selector)
- Email Header Analyzer
- DKIM & DMARC Generator

## Architecture
```text
backend/src/
├── Dockerfile
├── package.json
├── package-lock.json
└── src
    ├── routes
    │   ├── dns.js
    │   ├── generator.js
    │   ├── headers.js
    │   └── smtp.js
    ├── server.js
    └── services
        ├── dns.js
        ├── generator.js
        ├── headers.js
        └── smtp.js
```

```text
frontend/
├── Dockerfile
├── nginx.conf
└── src
    ├── app.js
    ├── features
    │   ├── dns.js
    │   ├── flow.js
    │   ├── generator.js
    │   ├── headers.js
    │   ├── smtp.js
    │   ├── tabs.js
    │   └── utils.js
    ├── icons
    │   ├── android-chrome-192x192.png
    │   ├── android-chrome-512x512.png
    │   ├── apple-touch-icon.png
    │   ├── favicon-16x16.png
    │   ├── favicon-32x32.png
    │   └── favicon.ico
    ├── index.html
    ├── sitemap.xml
    ├── site.webmanifest
    └── style.css
```

`server.js` and `app.js` are bootstrap/orchestration files. Feature logic is separated into route/service modules on the backend and feature modules on the frontend.

The HTML intentionally remains a single page shell to avoid unnecessary template/loading complexity.

## Run
```bash
docker compose build --no-cache
docker compose up -d
docker compose watch ## To Run Docker Watching Mode
```

Open `http://localhost:50000`.

## API
```text
GET  /api/health
POST /api/smtp/test
GET  /api/dns/check?domain=example.com
GET  /api/dns/dkim?domain=example.com&selector=google
POST /api/headers/analyze
```
