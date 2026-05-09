const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { v4: uuidv4 } = require('uuid');
const { db } = require('../utils/db');
const { auditLog, logger } = require('../utils/logger');
const { loginLimiter } = require('../middleware/rateLimiter');
const { registerValidation, handleValidation } = require('../middleware/validator');
const { JWT_SECRET } = require('../middleware/auth');

const router = express.Router();
const SALT_ROUNDS = 12; // bcrypt cost factor — higher = slower brute force

// POST /api/auth/register
router.post('/register', registerValidation, handleValidation, async (req, res) => {
  try {
    const { email, password, name } = req.body;

    // Check if email already exists
    const existing = db.get('users').find({ email }).value();
    if (existing) {
      // Don't reveal whether the email exists (prevents user enumeration)
      return res.status(409).json({ error: 'Registration failed. Please try a different email.' });
    }

    // Hash password with bcrypt (never store plaintext)
    const hashedPassword = await bcrypt.hash(password, SALT_ROUNDS);

    const newUser = {
      id: uuidv4(),
      name,
      email,
      password: hashedPassword,
      role: 'user',           // Default role — admin must be set manually
      isActive: true,
      createdAt: new Date().toISOString(),
      lastLogin: null,
    };

    db.get('users').push(newUser).write();

    auditLog({ userId: newUser.id, action: 'USER_REGISTER', resource: '/auth/register', ip: req.ip, status: 'success' });

    res.status(201).json({ message: 'Account created successfully. Please log in.' });
  } catch (err) {
    logger.error(`Register error: ${err.message}`);
    res.status(500).json({ error: 'Registration failed. Please try again.' });
  }
});

// POST /api/auth/login
router.post('/login', loginLimiter, async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password are required' });
    }

    const user = db.get('users').find({ email: email.toLowerCase().trim() }).value();

    // Use constant-time comparison to prevent timing attacks
    // Always run bcrypt even if user not found (prevents user enumeration via timing)
    const dummyHash = '$2a$12$dummyhashfortimingequalityxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx';
    const passwordMatch = await bcrypt.compare(password, user ? user.password : dummyHash);

    if (!user || !passwordMatch || !user.isActive) {
      auditLog({ userId: user?.id, action: 'LOGIN_FAIL', resource: '/auth/login', ip: req.ip, status: 'failure' });
      return res.status(401).json({ error: 'Invalid email or password' });
    }

    // Update last login timestamp
    db.get('users').find({ id: user.id }).assign({ lastLogin: new Date().toISOString() }).write();

    // Sign JWT — expires in 2 hours
    const token = jwt.sign(
      { id: user.id, email: user.email, role: user.role },
      JWT_SECRET,
      { expiresIn: '2h', algorithm: 'HS256' }
    );

    auditLog({ userId: user.id, action: 'LOGIN_SUCCESS', resource: '/auth/login', ip: req.ip, status: 'success' });

    res.json({
      message: 'Login successful',
      token,
      user: { id: user.id, name: user.name, email: user.email, role: user.role }
    });
  } catch (err) {
    logger.error(`Login error: ${err.message}`);
    res.status(500).json({ error: 'Login failed. Please try again.' });
  }
});

module.exports = router;
