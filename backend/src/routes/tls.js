'use strict';
const express = require('express');
const service = require('../services/tls');
const sendError = require('./_util');

const router = express.Router();
router.use(express.json({ limit: '10kb' }));

router.post('/', async (req, res) => {
  try {
    const { host, port, mode, versions } = req.body || {};
    res.json(await service.inspect({ host, port: port ?? 25, mode, versions: versions === true }));
  } catch (e) { sendError(res, e); }
});

module.exports = router;
