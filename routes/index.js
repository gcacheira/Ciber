const express = require('express');
const router = express.Router();
const mysql = require('mysql');
const config = require('../config');
const { exec } = require('child_process');

const crypto = require('crypto');
const fs = require('fs');
const jwt = require('jsonwebtoken');

const connection = mysql.createConnection({
  host: 'localhost',
  user: config.dbUser,
  password: config.dbPassword,
  database: 'test'
});

router.get('/', (req, res) => {
  res.send(`
    <form method="POST" action="/search">
      <input name="q" placeholder="Search..." />
      <button type="submit">Search</button>
    </form>
  `);
});

// SQL Injection
router.post('/search', (req, res) => {
  const query = req.body.q;
  const sql = `SELECT * FROM users WHERE name = '${query}'`;  // vulnerable
  connection.query(sql, (err, results) => {
    if (err) return res.send('Error');
    res.json(results);
  });
});

// Command Injection
router.get('/ping', (req, res) => {
  const host = req.query.host;
  exec(`ping -c 1 ${host}`, (err, stdout, stderr) => {
    console.log(stdout);
    if (err) return res.send('Command failed');
    res.send(`<pre>${stdout}</pre>`);
  });
});

// Insecure eval
router.get('/eval', (req, res) => {
  const code = req.query.code;
  const result = eval(code);  // dangerous
  res.send(`Result: ${result}`);
});

// routes/index.js
// Insecure Use of crypto.createHash() with User Input
router.post('/hash', (req, res) => {
  const algorithm = req.body.alg; // user controls algorithm
  const hash = crypto.createHash(algorithm);  // vulnerable to algorithm downgrading
  hash.update('sensitive_data');
  res.send(hash.digest('hex'));
});


// routes/index.js
// Path Traversal via fs.readFile
router.get('/read', (req, res) => {
  const file = req.query.file;
  fs.readFile(`./public/${file}`, 'utf8', (err, data) => {
    if (err) return res.send('Error reading file');
    res.send(`<pre>${data}</pre>`);
  });
});

// routes/index.js
// Exposing Stack Traces
router.get('/debug', (req, res) => {
  try {
    throw new Error('Test error');
  } catch (e) {
    res.send(`<pre>${e.stack}</pre>`);  // exposes stack trace
  }
});

// routes/index.js
// 4. JWT Without Verification
router.get('/jwt', (req, res) => {
  const token = req.query.token;
  const decoded = jwt.decode(token); // doesn't verify signature!
  res.json(decoded);
});


module.exports = router;
