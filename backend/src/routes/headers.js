const express = require("express");
const { analyzeHeaders } = require("../services/headers");

const router = express.Router();

router.post("/analyze", (req, res) => {
  const result = analyzeHeaders(req.body?.headers);
  return res.status(result.httpStatus).json(result.body);
});

module.exports = router;
