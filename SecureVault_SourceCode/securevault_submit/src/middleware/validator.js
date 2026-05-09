const { body, validationResult } = require('express-validator');

// Reusable validation chain for registration
const registerValidation = [
  body('email')
    .isEmail().withMessage('Valid email required')
    .normalizeEmail()
    .isLength({ max: 100 }).withMessage('Email too long'),
  body('password')
    .isLength({ min: 8 }).withMessage('Password must be at least 8 characters')
    .matches(/[A-Z]/).withMessage('Password must contain an uppercase letter')
    .matches(/[0-9]/).withMessage('Password must contain a number')
    .matches(/[!@#$%^&*]/).withMessage('Password must contain a special character (!@#$%^&*)')
    .isLength({ max: 72 }).withMessage('Password too long'),
  body('name')
    .trim()
    .isLength({ min: 2, max: 50 }).withMessage('Name must be 2-50 characters')
    .matches(/^[a-zA-Z\s'-]+$/).withMessage('Name contains invalid characters'),
];

// Validation for notes
const noteValidation = [
  body('title')
    .trim()
    .isLength({ min: 1, max: 100 }).withMessage('Title must be 1-100 characters')
    .escape(), // Sanitize against XSS
  body('content')
    .trim()
    .isLength({ min: 1, max: 5000 }).withMessage('Content must be 1-5000 characters')
    .escape(),
];

// Middleware to return validation errors
function handleValidation(req, res, next) {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(422).json({
      error: 'Validation failed',
      details: errors.array().map(e => ({ field: e.path, message: e.msg }))
    });
  }
  next();
}

module.exports = { registerValidation, noteValidation, handleValidation };
