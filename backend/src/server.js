require("dotenv").config();

const express = require("express");

const smtpRoutes = require("./routes/smtp");
const dnsRoutes = require("./routes/dns");
const headerRoutes = require("./routes/headers");
const generatorRoutes = require("./routes/generator");

const app = express();
const PORT = Number(process.env.PORT || 4000);

// Parse JSON request bodies with a size limit.
app.use(express.json({ limit: "100kb" }));

// HTTP request logging.
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

// Root endpoint.
app.get("/", (_req, res) => {
  res.json({
    service: "MailProbe Backend",
    status: "running",
  });
});

// Health-check endpoint.
app.get("/health", (_req, res) => {
  res.status(200).json({
    status: "healthy",
    backend: "connected",
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
