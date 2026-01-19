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
 * ======================================================
 * Database Connection Pool
 * ======================================================
 */
const pool = mysql.createPool({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASS,
  database: process.env.DB_NAME
});

/**
 * ======================================================
 * Temporary In-Memory Users (Demo Auth Only)
 * ======================================================
 */
const users = [
  {
    id: 1,
    email: "admin@lifamin.site",
    passwordHash: bcrypt.hashSync("StrongPassword123", 10),
    role: "admin"
  }
];

/**
 * ======================================================
 * Authentication Routes
 * ======================================================
 */
app.post('/login', (req, res) => {
  const { email, password } = req.body;

  const user = users.find(u => u.email === email);
  if (!user) {
    return res.status(401).json({ message: "Invalid credentials" });
  }

  const valid = bcrypt.compareSync(password, user.passwordHash);
  if (!valid) {
    return res.status(401).json({ message: "Invalid credentials" });
  }

  const token = jwt.sign(
    { id: user.id, role: user.role },
    process.env.JWT_SECRET,
    { expiresIn: "1h" }
  );

  res.json({ token });
});

/**
 * ======================================================
 * Authentication Middleware
 * ======================================================
 */
function authMiddleware(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader) {
    return res.sendStatus(401);
  }

  const token = authHeader.split(" ")[1];
  try {
    req.user = jwt.verify(token, process.env.JWT_SECRET);
    next();
  } catch (err) {
    return res.sendStatus(403);
  }
}

/**
 * ======================================================
 * Protected Routes
 * ======================================================
 */
app.get('/secure', authMiddleware, (req, res) => {
  res.json({
    message: "Secure data",
    user: req.user
  });
});

/**
 * ======================================================
 * Public / Health Routes
 * ======================================================
 */
app.get('/health', (req, res) => {
  res.json({ status: 'ok' });
});

/**
 * ======================================================
 * Server Startup (LAST)
 * ======================================================
 */
app.listen(3000, () => {
  console.log('API listening on port 3000');
});
