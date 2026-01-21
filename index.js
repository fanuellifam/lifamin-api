/**
 * ======================================================
 * Environment & Core Imports
 * ======================================================
 */
require('dotenv').config();

const express = require('express');
const mysql = require('mysql2/promise');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const cors = require('cors');
const morgan = require('morgan');

/**
 * ======================================================
 * Environment Validation
 * ======================================================
 */
const requiredEnv = [
  'JWT_SECRET',
  'REFRESH_TOKEN_SECRET',
  'ACCESS_TOKEN_EXPIRES',
  'REFRESH_TOKEN_EXPIRES_DAYS'
];

for (const key of requiredEnv) {
  if (!process.env[key]) {
    console.error(`❌ Missing environment variable: ${key}`);
    process.exit(1);
  }
}

/**
 * ======================================================
 * App Initialization
 * ======================================================
 */
const app = express();

/**
 * ======================================================
 * Global Middleware
 * ======================================================
 */
app.use(express.json());
app.use(cors());

/**
 * HTTP Access Logs
 */
app.use(
  morgan(':method :url :status :res[content-length] - :response-time ms')
);

/**
 * ======================================================
 * Database Connection Pool
 * ======================================================
 */
const pool = mysql.createPool({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASS,
  database: process.env.DB_NAME,
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0,
  connectTimeout: 5000
});

/**
 * ======================================================
 * JWT Helper Functions
 * ======================================================
 */
function generateAccessToken(user) {
  return jwt.sign(
    { id: user.id, role: user.role },
    process.env.JWT_SECRET,
    { expiresIn: process.env.ACCESS_TOKEN_EXPIRES }
  );
}

function generateRefreshToken(user) {
  return jwt.sign(
    { id: user.id },
    process.env.REFRESH_TOKEN_SECRET,
    { expiresIn: `${process.env.REFRESH_TOKEN_EXPIRES_DAYS}d` }
  );
}

/**
 * ======================================================
 * LOGIN (MYSQL + ACCESS + REFRESH TOKEN)
 * ======================================================
 */
app.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ message: 'Email and password required' });
    }

    const [rows] = await pool.execute(
      'SELECT id, email, password_hash, role FROM users WHERE email = ? LIMIT 1',
      [email]
    );

    if (rows.length === 0) {
      console.warn(`❌ Login failed (no user): ${email}`);
      return res.status(401).json({ message: 'Invalid credentials' });
    }

    const user = rows[0];

    const valid = await bcrypt.compare(password, user.password_hash);
    if (!valid) {
      console.warn(`❌ Login failed (bad password): ${email}`);
      return res.status(401).json({ message: 'Invalid credentials' });
    }

    const accessToken = generateAccessToken(user);
    const refreshToken = generateRefreshToken(user);

    const expiresAt = new Date();
    expiresAt.setDate(
      expiresAt.getDate() + Number(process.env.REFRESH_TOKEN_EXPIRES_DAYS)
    );

    await pool.execute(
      `INSERT INTO refresh_tokens (user_id, token, expires_at)
       VALUES (?, ?, ?)`,
      [user.id, refreshToken, expiresAt]
    );

    console.log(`✅ Successful login: ${email} (${user.role})`);

    res.json({ accessToken, refreshToken });

  } catch (err) {
    console.error('🔥 Login error:', err);
    res.status(500).json({ message: 'Internal Server Error' });
  }
});

/**
 * ======================================================
 * REFRESH TOKEN ROTATION
 * ======================================================
 */
app.post('/refresh', async (req, res) => {
  const { refreshToken } = req.body;

  if (!refreshToken) {
    return res.status(400).json({ message: 'Refresh token required' });
  }

  try {
    jwt.verify(refreshToken, process.env.REFRESH_TOKEN_SECRET);

    const [rows] = await pool.execute(
      `SELECT id, user_id, revoked, expires_at
       FROM refresh_tokens
       WHERE token = ? LIMIT 1`,
      [refreshToken]
    );

    if (rows.length === 0 || rows[0].revoked) {
      return res.status(403).json({ message: 'Invalid refresh token' });
    }

    if (new Date(rows[0].expires_at) < new Date()) {
      return res.status(403).json({ message: 'Refresh token expired' });
    }

    const [users] = await pool.execute(
      'SELECT id, role FROM users WHERE id = ? LIMIT 1',
      [rows[0].user_id]
    );

    if (users.length === 0) {
      return res.status(403).json({ message: 'User not found' });
    }

    const user = users[0];

    await pool.execute(
      'UPDATE refresh_tokens SET revoked = TRUE WHERE id = ?',
      [rows[0].id]
    );

    const newAccessToken = generateAccessToken(user);
    const newRefreshToken = generateRefreshToken(user);

    const expiresAt = new Date();
    expiresAt.setDate(
      expiresAt.getDate() + Number(process.env.REFRESH_TOKEN_EXPIRES_DAYS)
    );

    await pool.execute(
      `INSERT INTO refresh_tokens (user_id, token, expires_at)
       VALUES (?, ?, ?)`,
      [user.id, newRefreshToken, expiresAt]
    );

    console.log(`🔄 Token rotated for user ${user.id}`);

    res.json({
      accessToken: newAccessToken,
      refreshToken: newRefreshToken
    });

  } catch (err) {
    console.error('🔥 Refresh error:', err);
    res.status(403).json({ message: 'Invalid refresh token' });
  }
});

/**
 * ======================================================
 * AUTHORIZATION MIDDLEWARE
 * ======================================================
 */
function authMiddleware(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.sendStatus(401);
  }

  try {
    req.user = jwt.verify(
      authHeader.split(' ')[1],
      process.env.JWT_SECRET
    );
    next();
  } catch {
    return res.sendStatus(403);
  }
}

function requireRole(role) {
  return (req, res, next) => {
    if (req.user.role !== role) {
      return res.status(403).json({ message: 'Forbidden' });
    }
    next();
  };
}

/**
 * ======================================================
 * PROTECTED ROUTES
 * ======================================================
 */
app.get('/secure', authMiddleware, (req, res) => {
  res.json({ message: 'Secure data', user: req.user });
});

app.get('/admin', authMiddleware, requireRole('admin'), (req, res) => {
  res.json({ message: 'Admin access granted' });
});

app.get('/user', authMiddleware, (req, res) => {
  res.json({ message: 'User access granted' });
});

/**
 * ======================================================
 * HEALTH CHECK
 * ======================================================
 */
app.get('/health', (req, res) => {
  res.json({ status: 'ok' });
});

/**
 * ======================================================
 * GLOBAL ERROR HANDLER
 * ======================================================
 */
app.use((err, req, res, next) => {
  console.error('🔥 Unhandled error:', err);
  res.status(500).json({ message: 'Internal Server Error' });
});

/**
 * ======================================================
 * SERVER STARTUP
 * ======================================================
 */
app.listen(3000, () => {
  console.log('✅ API listening on port 3000');
});
