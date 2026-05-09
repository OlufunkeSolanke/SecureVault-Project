const express = require('express');
const { v4: uuidv4 } = require('uuid');
const { db } = require('../utils/db');
const { auditLog } = require('../utils/logger');
const { authenticate } = require('../middleware/auth');
const { noteValidation, handleValidation } = require('../middleware/validator');
const { apiLimiter } = require('../middleware/rateLimiter');

const router = express.Router();

// All notes routes require authentication
router.use(authenticate);
router.use(apiLimiter);

// GET /api/notes — get only the authenticated user's notes
router.get('/', (req, res) => {
  const notes = db.get('notes')
    .filter({ userId: req.user.id })
    .orderBy('createdAt', 'desc')
    .value();
  res.json({ notes });
});

// POST /api/notes — create a new note
router.post('/', noteValidation, handleValidation, (req, res) => {
  const { title, content } = req.body;
  const note = {
    id: uuidv4(),
    userId: req.user.id, // Ownership bound at creation — cannot be changed
    title,
    content,
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString(),
  };
  db.get('notes').push(note).write();
  auditLog({ userId: req.user.id, action: 'NOTE_CREATE', resource: `/notes/${note.id}`, ip: req.ip, status: 'success' });
  res.status(201).json({ message: 'Note created', note });
});

// PUT /api/notes/:id — update own note only
router.put('/:id', noteValidation, handleValidation, (req, res) => {
  const note = db.get('notes').find({ id: req.params.id }).value();

  if (!note) return res.status(404).json({ error: 'Note not found' });

  // IDOR protection: enforce ownership — users cannot edit each other's notes
  if (note.userId !== req.user.id) {
    auditLog({ userId: req.user.id, action: 'UNAUTHORIZED_NOTE_EDIT', resource: `/notes/${req.params.id}`, ip: req.ip, status: 'blocked' });
    return res.status(403).json({ error: 'Access denied' });
  }

  const { title, content } = req.body;
  db.get('notes').find({ id: req.params.id }).assign({ title, content, updatedAt: new Date().toISOString() }).write();
  auditLog({ userId: req.user.id, action: 'NOTE_UPDATE', resource: `/notes/${req.params.id}`, ip: req.ip, status: 'success' });
  res.json({ message: 'Note updated' });
});

// DELETE /api/notes/:id
router.delete('/:id', (req, res) => {
  const note = db.get('notes').find({ id: req.params.id }).value();
  if (!note) return res.status(404).json({ error: 'Note not found' });

  if (note.userId !== req.user.id) {
    auditLog({ userId: req.user.id, action: 'UNAUTHORIZED_NOTE_DELETE', resource: `/notes/${req.params.id}`, ip: req.ip, status: 'blocked' });
    return res.status(403).json({ error: 'Access denied' });
  }

  db.get('notes').remove({ id: req.params.id }).write();
  auditLog({ userId: req.user.id, action: 'NOTE_DELETE', resource: `/notes/${req.params.id}`, ip: req.ip, status: 'success' });
  res.json({ message: 'Note deleted' });
});

module.exports = router;
