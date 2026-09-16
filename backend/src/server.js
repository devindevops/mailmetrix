require("dotenv").config();

const express = require("express");

const smtpRoutes = require("./routes/smtp");
const dnsRoutes = require("./routes/dns");
const headerRoutes = require("./routes/headers");

const app = express();
const PORT = Number(process.env.PORT || 4000);

app.use(express.json({ limit: "100kb" }));

app.get("/", (req, res) => {
  res.json({ service: "MailProbe Backend", status: "running" });
});

app.get("/health", (req, res) => {
  res.json({ status: "healthy", backend: "connected" });
});

app.use("/smtp", smtpRoutes);
app.use("/dns", dnsRoutes);
app.use("/headers", headerRoutes);

app.listen(PORT, "0.0.0.0", () => {
  console.log(`MailProbe backend running on port ${PORT}`);
});
