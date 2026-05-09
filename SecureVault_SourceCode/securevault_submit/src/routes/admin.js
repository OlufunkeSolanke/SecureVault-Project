const express = require('express');
const { db } = require('../utils/db');
const { authenticate, authorize } = require('../middleware/auth');
const { auditLog } = require('../utils/logger');

const router = express.Router();

// All admin routes: must be authenticated AND have 'admin' role
router.use(authenticate);
router.use(authorize('admin'));

// GET /api/admin/users — list all users (admin only)
router.get('/users', (req, res) => {
  const users = db.get('users')
    .map(u => ({ id: u.id, name: u.name, email: u.email, role: u.role, isActive: u.isActive, createdAt: u.createdAt, lastLogin: u.lastLogin }))
    .value();
  auditLog({ userId: req.user.id, action: 'ADMIN_LIST_USERS', resource: '/admin/users', ip: req.ip, status: 'success' });
  res.json({ users });
});

// GET /api/admin/audit-logs — view full audit trail
router.get('/audit-logs', (req, res) => {
  const logs = db.get('audit_logs').orderBy('timestamp', 'desc').take(200).value();
  res.json({ logs });
});

// PUT /api/admin/users/:id/deactivate — deactivate a user account
router.put('/users/:id/deactivate', (req, res) => {
  const user = db.get('users').find({ id: req.params.id }).value();
  if (!user) return res.status(404).json({ error: 'User not found' });

  db.get('users').find({ id: req.params.id }).assign({ isActive: false }).write();
  auditLog({ userId: req.user.id, action: 'ADMIN_DEACTIVATE_USER', resource: `/admin/users/${req.params.id}`, ip: req.ip, status: 'success', details: `Deactivated user: ${user.email}` });
  res.json({ message: 'User deactivated' });
});

module.exports = router;
