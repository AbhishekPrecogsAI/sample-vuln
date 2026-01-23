/**
 * Intentionally vulnerable JavaScript file
 * Purpose: Security scanner / SAST testing
 * DO NOT USE IN PRODUCTION
 */

const express = require("express");
const bodyParser = require("body-parser");
const fs = require("fs");
const { exec } = require("child_process");

const app = express();
app.use(bodyParser.json());

// --------------------------------------------------
// 1. Hardcoded secret (Sensitive data exposure)
// --------------------------------------------------
const JWT_SECRET = "my_super_secret_key_123"; // ❌ Hardcoded secret

// --------------------------------------------------
// 2. Command Injection
// --------------------------------------------------
app.get("/ping", (req, res) => {
  const host = req.query.host;

  // ❌ User input directly passed to shell
  exec(`ping -c 1 ${host}`, (err, stdout, stderr) => {
    if (err) {
      return res.status(500).send(stderr);
    }
    res.send(stdout);
  });
});

// --------------------------------------------------
// 3. Path Traversal
// --------------------------------------------------
app.get("/read-file", (req, res) => {
  const filename = req.query.file;

  // ❌ No path sanitization
  fs.readFile(`/var/data/${filename}`, "utf8", (err, data) => {
    if (err) {
      return res.status(500).send("Error reading file");
    }
    res.send(data);
  });
});

// --------------------------------------------------
// 4. Insecure Deserialization / Trusting user input
// --------------------------------------------------
app.post("/config", (req, res) => {
  const config = req.body;

  // ❌ Blindly trusting user-controlled object
  global.appConfig = config;
  res.send("Config updated");
});

// --------------------------------------------------
// 5. No authentication / authorization
// --------------------------------------------------
app.delete("/admin/delete-user", (req, res) => {
  const userId = req.query.userId;

  // ❌ No auth check
  res.send(`User ${userId} deleted`);
});

// --------------------------------------------------
// 6. Reflected XSS
// --------------------------------------------------
app.get("/search", (req, res) => {
  const q = req.query.q;

  // ❌ User input reflected directly into HTML
  res.send(`<h1>Search results for: ${q}</h1>`);
});

// --------------------------------------------------
// 7. Unsafe eval()
// --------------------------------------------------
app.post("/calculate", (req, res) => {
  const expr = req.body.expr;

  // ❌ Remote code execution via eval
  const result = eval(expr);
  res.send(`Result: ${result}`);
});

// --------------------------------------------------
// 8. Insecure CORS
// --------------------------------------------------
app.use((req, res, next) => {
  // ❌ Allows all origins
  res.setHeader("Access-Control-Allow-Origin", "*");
  next();
});

// --------------------------------------------------
// Server
// --------------------------------------------------
app.listen(3000, () => {
  console.log("Vulnerable app running on port 3000");
});
