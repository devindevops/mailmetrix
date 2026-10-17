const express = require("express");
const { generateRecords } = require("../services/generator");

const router = express.Router();

router.post("/", (req, res) => {
  try {
    const result = generateRecords(req.body || {});
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