'use strict';
const express = require('express');
const service = require('../services/share');
const sendError = require('./_util');

const router = express.Router();
router.use(express.json({ limit: '300kb' }));

router.post('/', async (req, res) => {
  try {
    res.status(201).json(await service.create(req.body?.type, req.body?.data, req.ip));
  } catch (e) { sendError(res, e); }
});

router.get('/:id', async (req, res) => {
  try {
    const rec = await service.get(req.params.id);
    if (!rec) return res.status(404).json({ error: 'Share not found or expired' });
    res.json({ type: rec.type, data: rec.data, createdAt: rec.createdAt, expiresAt: rec.expiresAt });
  } catch (e) { sendError(res, e); }
});

router.get('/:id/export', async (req, res) => {
  try {
    const rec = await service.get(req.params.id);
    if (!rec) return res.status(404).json({ error: 'Share not found or expired' });
    const fmt = String(req.query.format || 'json');
    const name = `mailprobe-${rec.type}-${req.params.id}`;
    if (fmt === 'csv') {
      res.type('text/csv').set('Content-Disposition', `attachment; filename="${name}.csv"`);
      return res.send(service.toCsv(rec.data));
    }
    if (fmt === 'html') {
      res.set('Content-Security-Policy', "default-src 'none'; style-src 'unsafe-inline'");
      return res.type('html').send(service.toHtml(rec, req.params.id));
    }
    res.type('application/json').set('Content-Disposition', `attachment; filename="${name}.json"`);
    return res.send(JSON.stringify(rec.data, null, 2));
  } catch (e) { sendError(res, e); }
});

module.exports = router;
