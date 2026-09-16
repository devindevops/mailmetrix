const express = require("express");
const { checkEmailDNS, checkDKIM } = require("../services/dns");

const router = express.Router();

router.get("/check", async (req, res) => {
  const result = await checkEmailDNS(req.query.domain);
  return res.status(result.httpStatus).json(result.body);
});

router.get("/dkim", async (req, res) => {
  const result = await checkDKIM(req.query.domain, req.query.selector);
  return res.status(result.httpStatus).json(result.body);
});

module.exports = router;
