const { db } = require('./db');
const { v4: uuidv4 } = require('uuid');

// Simple console logger
const logger = {
  info: (msg) => console.log(`[INFO] ${new Date().toISOString()} - ${msg}`),
  warn: (msg) => console.warn(`[WARN] ${new Date().toISOString()} - ${msg}`),
  error: (msg) => console.error(`[ERROR] ${new Date().toISOString()} - ${msg}`),
};

// Audit trail - records every security-relevant event to DB
function auditLog({ userId, action, resource, ip, status, details = '' }) {
  const entry = {
    id: uuidv4(),
    timestamp: new Date().toISOString(),
    userId: userId || 'anonymous',
    action,
    resource,
    ip,
    status, // 'success' | 'failure' | 'blocked'
    details,
  };
  try {
    db.get('audit_logs').push(entry).write();
  } catch (err) {
    logger.error(`Audit log write failed: ${err.message}`);
  }
  logger.info(`AUDIT | ${action} | user:${entry.userId} | status:${status} | ip:${ip}`);
}

module.exports = { logger, auditLog };
