const express = require("express");
const { testSMTP } = require("../services/smtp");

const router = express.Router();

router.post("/test", async (req, res) => {
  try {
    const result = await testSMTP(req.body);
    return res.status(result.httpStatus).json(result.body);
  } catch (error) {
    console.error("SMTP route error:", error.message);
    return res.status(500).json({
      success: false,
      stage: "server",
      error: "An unexpected SMTP error occurred."
    });
  }
});

module.exports = router;
