const express = require("express");
const { generateRecords } = require("../services/generator");

const router = express.Router();

router.post("/", async (req, res) => {
  try {
    const result = await generateRecords(req.body || {});

    // Key generation queue full: tell clients when to retry.
    if (result.httpStatus === 503) {
      res.set("Retry-After", "5");
    }

    return res.status(result.httpStatus).json(result.body);
  } catch (error) {
    console.error("Generator error:", error);
    return res.status(500).json({
      success: false,
      error: "Unable to generate SPF, DKIM and DMARC records."
    });
  }
});

module.exports = router;