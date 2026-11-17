"use strict";

const express = require("express");
const { getLatestRelease } = require("../services/version");

const router = express.Router();

// GET /version/check (also reachable as /api/version/check, see server.js)
router.get("/check", async (_req, res, next) => {
  try {
    res.set("Cache-Control", "no-store");
    res.json(await getLatestRelease());
  } catch (err) {
    next(err);
  }
});

module.exports = router;