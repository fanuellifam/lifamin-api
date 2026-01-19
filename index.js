require('dotenv').config();
const express = require('express');
const mysql = require('mysql2/promise');
const app = express();

app.use(express.json());
app.use(require('cors')());

const pool = mysql.createPool({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASS,
  database: process.env.DB_NAME
});

app.get('/health', (req, res) => {
  res.json({ status: 'ok' });
});

app.listen(3000, () => {
  console.log('API listening on port 3000');
});
