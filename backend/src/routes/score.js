'use strict';
const express = require('express');
const service = require('../services/score');
const sendError = require('./_util');

const router = express.Router();
router.use(express.json({ limit: '10kb' }));

router.post('/', async (req, res) => {
  try {
    res.json(await service.score(req.body?.domain, { selector: req.body?.selector }));
  } catch (e) { sendError(res, e); }
});

module.exports = router;
