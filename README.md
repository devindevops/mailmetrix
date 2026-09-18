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
├── server.js
├── routes/
│   ├── smtp.js
│   ├── dns.js
│   ├── generator.js
│   └── headers.js
└── services/
    ├── smtp.js
    ├── dns.js
    ├── generator.js
    └── headers.js

frontend/src/
├── app.js
├── index.html
├── style.css
├── site.webmanifest
├── sitemap.xml
└── features/
    ├── utils.js
    ├── tabs.js
    ├── smtp.js
    ├── dns.js
    ├── flow.js
    ├── generator.js
    └── headers.js
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
