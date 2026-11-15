'use strict';

const express = require('express');
const net = require('net');

const service = require('../services/tls');
const { isValidHostname, isPrivateIp } = require('../services/netguard');
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
    // Validate & sanitize hostname / IP address
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

    const sanitizedHost = host.trim().toLowerCase();

    const isIp = net.isIP(sanitizedHost);

    // Host must be either a valid public hostname or a valid IP literal
    if (!isIp && !isValidHostname(sanitizedHost)) {
      return res.status(400).json({
        error: 'A valid public hostname or IP address is required',
      });
    }

    // Direct check: reject private, loopback, or reserved IP addresses immediately
    if (isIp && isPrivateIp(sanitizedHost)) {
      return res.status(400).json({
        error: 'Private or reserved IP addresses are not permitted',
      });
    }

    // ----------------------------------------------
    // Validate port
    // ----------------------------------------------

    const parsedPort = Number(port ?? 25);
    if (!Number.isInteger(parsedPort) || !service.ALLOWED_PORTS.has(parsedPort)) {
      return res.status(400).json({
        error: `Port must be one of: ${[...service.ALLOWED_PORTS].join(', ')}`,
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
      host: sanitizedHost,
      port: parsedPort,
      mode,
      versions: versions === true,
    });

    return res.json(result);
  } catch (error) {
    return sendError(res, error);
  }
});

module.exports = router;