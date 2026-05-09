const jwt = require('jsonwebtoken');
const { db } = require('../utils/db');
const { auditLog } = require('../utils/logger');

const JWT_SECRET = process.env.JWT_SECRET || 'CHANGE_THIS_IN_PRODUCTION_USE_ENV';

// Verify JWT token on protected routes
function authenticate(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'No token provided' });
  }

  const token = authHeader.split(' ')[1];
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    // Confirm user still exists in DB (handles revoked sessions)
    const user = db.get('users').find({ id: decoded.id, isActive: true }).value();
    if (!user) {
      return res.status(401).json({ error: 'User account not found or deactivated' });
    }
    req.user = { id: user.id, email: user.email, role: user.role };
    next();
  } catch (err) {
    auditLog({ action: 'TOKEN_VERIFY_FAIL', resource: req.path, ip: req.ip, status: 'failure', details: err.message });
    return res.status(401).json({ error: 'Invalid or expired token' });
  }
}

// Role-based access control — only allow specified roles
function authorize(...roles) {
  return (req, res, next) => {
    if (!roles.includes(req.user.role)) {
      auditLog({ userId: req.user.id, action: 'UNAUTHORIZED_ACCESS', resource: req.path, ip: req.ip, status: 'blocked' });
      return res.status(403).json({ error: 'Access denied: insufficient permissions' });
    }
    next();
  };
}

module.exports = { authenticate, authorize, JWT_SECRET };
