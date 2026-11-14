'use strict';

const express = require('express');

const service = require('../services/tls');
const sendError = require('./_util');

const router = express.Router();

router.use(express.json({
  limit: '10kb',
}));

router.post('/', async (req, res) => {
  try {
    const {
      host,
      port = 25,
      mode,
      versions,
    } = req.body || {};

    // ----------------------------------------------
    // Validate hostname
    // ----------------------------------------------

    if (
      typeof host !== 'string' ||
      !host.trim() ||
      host.length > 253
    ) {
      return res.status(400).json({
        error: 'A valid hostname or IP address is required',
      });
    }

    // ----------------------------------------------
    // Validate mode
    // ----------------------------------------------

    if (
      mode !== undefined &&
      !['implicit', 'starttls'].includes(mode)
    ) {
      return res.status(400).json({
        error: 'mode must be implicit or starttls',
      });
    }

    // ----------------------------------------------
    // Validate versions
    // ----------------------------------------------

    if (
      versions !== undefined &&
      typeof versions !== 'boolean'
    ) {
      return res.status(400).json({
        error: 'versions must be a boolean',
      });
    }

    // ----------------------------------------------
    // TLS inspection
    // ----------------------------------------------

    const result = await service.inspect({
      host: host.trim(),
      port: port ?? 25,
      mode,
      versions: versions === true,
    });

    return res.json(result);
  } catch (error) {
    return sendError(res, error);
  }
});

module.exports = router;