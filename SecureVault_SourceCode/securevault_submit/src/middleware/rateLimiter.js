const rateLimit = require('express-rate-limit');
const { auditLog } = require('../utils/logger');

// Strict rate limit for login/register - prevents brute force attacks
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15-minute window
  max: 10,                   // Maximum 10 attempts per window per IP
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many attempts. Please try again in 15 minutes.' },
  handler: (req, res, next, options) => {
    auditLog({
      action: 'RATE_LIMIT_HIT',
      resource: req.path,
      ip: req.ip,
      status: 'blocked',
      details: `Login rate limit exceeded from ${req.ip}`
    });
    res.status(options.statusCode).json(options.message);
  }
});

// General API rate limit - prevents API abuse
const apiLimiter = rateLimit({
  windowMs: 60 * 1000, // 1 minute
  max: 100,
  message: { error: 'Too many requests. Slow down.' }
});

module.exports = { loginLimiter, apiLimiter };
