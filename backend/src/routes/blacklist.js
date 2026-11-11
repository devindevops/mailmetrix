'use strict';
const express = require('express');
const service = require('../services/blacklist');
const sendError = require('./_util');

const router = express.Router();
router.use(express.json({ limit: '10kb' }));

router.post('/', async (req, res) => {
  try {
    res.json(await service.check(req.body?.target));
  } catch (e) { sendError(res, e); }
});

module.exports = router;
