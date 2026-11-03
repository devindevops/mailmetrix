require("dotenv").config();

const net = require("node:net");
const express = require("express");
const rateLimit = require("express-rate-limit");

const smtpRoutes = require("./routes/smtp");
const dnsRoutes = require("./routes/dns");
const headerRoutes = require("./routes/headers");
const generatorRoutes = require("./routes/generator");

const app = express();
const PORT = Number(process.env.PORT || 4000);

/* ------------------------------------------------------------------ */
/* Reverse proxy / client IP (required for correct rate limiting)      */
/*                                                                     */
/* Behind nginx or another proxy, req.ip is the proxy's address unless */
/* Express is told how many hops to trust. Without this, every client  */
/* shares ONE rate-limit bucket. Set TRUST_PROXY to the number of      */
/* proxies in front of this app (e.g. 1 for a single nginx container), */
/* or to a subnet list such as "loopback, 172.16.0.0/12".              */
/* Do NOT use "true": it lets clients spoof X-Forwarded-For and dodge  */
/* the limiter. Leave unset if the app is exposed directly.            */
/* ------------------------------------------------------------------ */

const TRUST_PROXY = (process.env.TRUST_PROXY || "").trim();
if (TRUST_PROXY) {
  app.set(
    "trust proxy",
    /^\d+$/.test(TRUST_PROXY) ? Number(TRUST_PROXY) : TRUST_PROXY
  );
}

/* ------------------------------------------------------------------ */
/* Rate limiting (SEC-03 / CWE-770)                                    */
/* ------------------------------------------------------------------ */

const positiveInt = (value, fallback) => {
  const n = Number(value);
  return Number.isInteger(n) && n > 0 ? n : fallback;
};

const WINDOW_MS = positiveInt(process.env.RATE_LIMIT_WINDOW_MS, 15 * 60 * 1000);

function createLimiter(limit, message) {
  return rateLimit({
    windowMs: WINDOW_MS,
    limit,
    standardHeaders: true, // RateLimit-* headers + Retry-After on 429
    legacyHeaders: false,
    message: { success: false, error: message }
  });
}

// Outbound SMTP: credential brute-forcing, SSRF probing, real email sent.
const smtpLimiter = createLimiter(
  positiveInt(process.env.RATE_LIMIT_SMTP, 20),
  "SMTP test limit reached. Please try again later."
);

// DKIM keygen is CPU-heavy (see SEC-02), so it gets a tighter cap.
const generatorLimiter = createLimiter(
  positiveInt(process.env.RATE_LIMIT_GENERATOR, 30),
  "Record generation limit reached. Please try again later."
);

// DNS checks fan out to upstream resolvers.
const dnsLimiter = createLimiter(
  positiveInt(process.env.RATE_LIMIT_DNS, 60),
  "DNS check limit reached. Please try again later."
);

const headersLimiter = createLimiter(
  positiveInt(process.env.RATE_LIMIT_HEADERS, 100),
  "Too many requests, please try again later."
);

// HTTP request logging (registered first so 429 responses are logged too).
app.use((req, res, next) => {
  const startTime = Date.now();

  res.on("finish", () => {
    const duration = Date.now() - startTime;

    console.log(
      `${new Date().toISOString()} ${req.method} ${req.originalUrl} ${res.statusCode} ${duration}ms`
    );
  });

  next();
});

// Limiters run BEFORE body parsing so rejected requests cost almost nothing.
// /health, /api/health and / are intentionally NOT limited (Docker healthchecks).
app.use("/smtp", smtpLimiter);
app.use("/generator", generatorLimiter);
app.use("/dns", dnsLimiter);
app.use("/headers", headersLimiter);

// Parse JSON request bodies with a size limit.
app.use(express.json({ limit: "100kb" }));

// Root endpoint.
app.get("/", (_req, res) => {
  res.json({
    service: "Mail Metrix Backend",
    status: "running",
  });
});

/* ------------------------------------------------------------------ */
/* Health probes (SEC-06 / CWE-200)                                    */
/* ------------------------------------------------------------------ */

// PUBLIC liveness probe: deliberately minimal. No process internals.
// ("backend" is kept only so a UI that checks it for a status badge keeps
// working; it carries no sensitive information.)
function healthHandler(_req, res) {
  res.status(200).json({
    status: "healthy",
    backend: "connected"
  });
}

app.get("/health", healthHandler);
// Also map /api/health to the same handler if your frontend polls /api/health
app.get("/api/health", healthHandler);

// INTERNAL telemetry: for monitoring from inside the Docker network only.
//
// A request counts as internal when it (a) did NOT come through the reverse
// proxy (nginx always adds forwarding headers) and (b) its TCP peer is a
// loopback/private address. Nginx also blocks /api/internal/ outright, so this
// is defense in depth. Anything else falls through to the normal 404.
const internalNets = new net.BlockList();
internalNets.addSubnet("127.0.0.0", 8, "ipv4");
internalNets.addSubnet("10.0.0.0", 8, "ipv4");
internalNets.addSubnet("172.16.0.0", 12, "ipv4");
internalNets.addSubnet("192.168.0.0", 16, "ipv4");
internalNets.addAddress("::1", "ipv6");
internalNets.addSubnet("fc00::", 7, "ipv6");

function isInternalAddress(addr) {
  if (!addr) return false;
  const mapped = addr.match(/^::ffff:(\d{1,3}(?:\.\d{1,3}){3})$/i);
  const ip = mapped ? mapped[1] : addr;
  const family = net.isIP(ip);
  if (!family) return false;
  return internalNets.check(ip, family === 4 ? "ipv4" : "ipv6");
}

function isInternalRequest(req) {
  const h = req.headers;
  if (h["x-forwarded-for"] || h["x-real-ip"] || h["forwarded"]) {
    return false; // arrived via a reverse proxy => possibly public
  }
  return isInternalAddress(req.socket.remoteAddress);
}

// Real CPU utilisation since the previous sample (100 = one full core).
let lastCpu = process.cpuUsage();
let lastCpuTime = process.hrtime.bigint();

function sampleCpuPercent() {
  const now = process.hrtime.bigint();
  const usage = process.cpuUsage();

  const elapsedMicros = Number(now - lastCpuTime) / 1000;
  const usedMicros =
    usage.user - lastCpu.user + (usage.system - lastCpu.system);

  lastCpu = usage;
  lastCpuTime = now;

  if (elapsedMicros <= 0) return 0;
  return Math.round((usedMicros / elapsedMicros) * 1000) / 10;
}

const toMb = (bytes) => Math.round((bytes / 1024 / 1024) * 10) / 10;

app.get("/internal/health", (req, res, next) => {
  if (!isInternalRequest(req)) return next(); // -> standard 404

  const mem = process.memoryUsage();

  res.set("Cache-Control", "no-store");
  res.status(200).json({
    status: "healthy",
    uptimeSeconds: Math.round(process.uptime()),
    cpuPercent: sampleCpuPercent(),
    memory: {
      rssMb: toMb(mem.rss),
      heapUsedMb: toMb(mem.heapUsed),
      heapTotalMb: toMb(mem.heapTotal)
    }
  });
});

// Application routes.
app.use("/smtp", smtpRoutes);
app.use("/dns", dnsRoutes);
app.use("/headers", headerRoutes);
app.use("/generator", generatorRoutes);

// Handle unmatched routes.
app.use((req, res) => {
  res.status(404).json({
    error: "Route not found",
    path: req.originalUrl,
  });
});

// Handle unexpected application errors.
app.use((err, _req, res, _next) => {
  console.error("Request error:", err.message);

  if (res.headersSent) {
    return res.end();
  }

  res.status(err.status || 500).json({
    error: err.status && err.status < 500
      ? err.message
      : "Internal server error",
  });
});

// Start the server.
app.listen(PORT, "0.0.0.0", () => {
  console.log(`MailMetrix backend running on port ${PORT}`);
});