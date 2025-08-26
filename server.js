// ==== Imports ====
const express = require("express");
const path = require("path");
const { Pool } = require("pg");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const cookieParser = require("cookie-parser");
const nodemailer = require("nodemailer");
const http = require("http");
const { Server } = require("socket.io");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");

// ==== Config ====
const app = express();
const server = http.createServer(app);
const io = new Server(server);
const PORT = process.env.PORT || 3000;
const SECRET = process.env.JWT_SECRET || "supersecretkey";

// ==== Middleware ====
app.use(express.json());
app.use(cookieParser());
app.use(express.static(__dirname));
app.use(helmet()); // adds secure headers

// Rate limiter (100 requests per 15 min per IP)
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  message: { error: "Too many requests, slow down." }
});
app.use("/api/", limiter);

// ==== Postgres Connection ====
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

// ==== Init Tables ====
async function initTables() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      username TEXT UNIQUE,
      email TEXT UNIQUE,
      password TEXT,
      is_admin BOOLEAN DEFAULT false,
      banned BOOLEAN DEFAULT false
    )
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS posts (
      id SERIAL PRIMARY KEY,
      user_id INT,
      username TEXT,
      title TEXT,
      description TEXT,
      budget TEXT,
      payment TEXT,
      timeline TEXT,
      category TEXT,
      mode TEXT,
      created_at BIGINT,
      suspended BOOLEAN DEFAULT false
    )
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS messages (
      id SERIAL PRIMARY KEY,
      from_user TEXT,
      to_user TEXT,
      text TEXT,
      created_at TIMESTAMP DEFAULT NOW()
    )
  `);
}
initTables();

// ==== Nodemailer (Reports) ====
const transporter = nodemailer.createTransport({
  service: "gmail",
  auth: {
    user: "bloxworksreports@gmail.com",
    pass: "wnhx gcdt zqtj evsk" // Gmail App Password
  }
});

// ==== Helpers ====
function generateToken(user) {
  return jwt.sign(user, SECRET, { expiresIn: "7d" }); // auto-expire in 7 days
}

function setAuthCookie(res, token) {
  res.cookie("token", token, {
    httpOnly: true,
    secure: true,       // only over HTTPS
    sameSite: "strict", // prevents CSRF
    maxAge: 7 * 24 * 60 * 60 * 1000 // 7 days
  });
}

function requireAuth(req, res, next) {
  const token = req.cookies.token;
  if (!token) return res.status(401).json({ error: "Not logged in" });
  try {
    req.user = jwt.verify(token, SECRET);
    next();
  } catch {
    return res.status(403).json({ error: "Invalid token" });
  }
}

function requireAdmin(req, res, next) {
  requireAuth(req, res, () => {
    if (!req.user.is_admin) return res.status(403).json({ error: "Not admin" });
    next();
  });
}

// ==== Routes ====

// Root
app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "index.html"));
});

// Health check
app.get("/healthz", (req, res) => res.status(200).send("OK"));

// ===== Auth =====
app.post("/api/signup", async (req, res) => {
  const { username, email, password } = req.body;
  if (!username || !email || !password)
    return res.status(400).json({ error: "Missing fields" });

  const hash = await bcrypt.hash(password, 12);
  const is_admin = (email === "bloxworksreports@gmail.com");

  try {
    const result = await pool.query(
      "INSERT INTO users (username,email,password,is_admin) VALUES ($1,$2,$3,$4) RETURNING id,username,email,is_admin",
      [username, email, hash, is_admin]
    );
    const user = result.rows[0];
    const token = generateToken(user);
    setAuthCookie(res, token);
    res.json(user);
  } catch (err) {
    res.status(400).json({ error: "User exists" });
  }
});

app.post("/api/login", async (req, res) => {
  const { username, password } = req.body;
  const result = await pool.query("SELECT * FROM users WHERE username=$1", [username]);
  const user = result.rows[0];
  if (!user) return res.status(400).json({ error: "No user" });
  if (user.banned) return res.status(403).json({ error: "User banned" });

  const ok = await bcrypt.compare(password, user.password);
  if (!ok) return res.status(400).json({ error: "Wrong password" });

  const token = generateToken(user);
  setAuthCookie(res, token);
  res.json({
    id: user.id,
    username: user.username,
    email: user.email,
    is_admin: user.is_admin
  });
});

app.get("/api/loginStatus", (req, res) => {
  const token = req.cookies.token;
  if (!token) return res.status(401).end();
  try {
    const user = jwt.verify(token, SECRET);
    res.json(user);
  } catch {
    res.status(401).end();
  }
});

// ===== Posts =====
app.get("/api/posts", async (req, res) => {
  const now = Date.now();
  const expiry = 72 * 60 * 60 * 1000; // 72h

  const { rows } = await pool.query("SELECT * FROM posts WHERE suspended=false");
  for (const r of rows) {
    if (now - r.created_at > expiry) {
      await pool.query("DELETE FROM posts WHERE id=$1", [r.id]);
    }
  }
  const { rows: fresh } = await pool.query("SELECT * FROM posts WHERE suspended=false");
  res.json(fresh);
});

app.post("/api/posts", requireAuth, async (req, res) => {
  const { mode, title, description, budget, payment, timeline, category } = req.body;
  if (!title || !description)
    return res.status(400).json({ error: "Missing fields" });

  const existing = await pool.query("SELECT * FROM posts WHERE user_id=$1", [req.user.id]);
  if (existing.rows.length > 0)
    return res.status(400).json({ error: "Already have a post" });

  await pool.query(
    `INSERT INTO posts (user_id,username,mode,title,description,budget,payment,timeline,category,created_at)
     VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`,
    [req.user.id, req.user.username, mode, title, description, budget, payment, timeline, category, Date.now()]
  );
  res.json({ ok: true });
});

// ===== Messages =====
app.get("/api/messages/:me/:other", requireAuth, async (req, res) => {
  const { me, other } = req.params;
  const { rows } = await pool.query(
    "SELECT * FROM messages WHERE (from_user=$1 AND to_user=$2) OR (from_user=$2 AND to_user=$1) ORDER BY created_at ASC",
    [me, other]
  );
  res.json(rows);
});

io.on("connection", (socket) => {
  socket.on("message", async (msg) => {
    await pool.query("INSERT INTO messages (from_user,to_user,text) VALUES ($1,$2,$3)", 
      [msg.user, msg.to, msg.text]);
    io.emit("message", msg);
  });
});

// ===== Reports =====
app.post("/api/report", async (req, res) => {
  const { accused, reason, reporter } = req.body;
  if (!accused || !reason || !reporter)
    return res.status(400).json({ error: "Missing fields" });

  transporter.sendMail({
    from: "bloxworksreports@gmail.com",
    to: "bloxworksreports@gmail.com",
    subject: "🚨 Scam Report",
    text: `Reporter: ${reporter}\nAccused: ${accused}\nReason: ${reason}`
  }, (err) => {
    if (err) return res.status(500).json({ error: "Failed to send" });
    res.json({ ok: true });
  });
});

// ===== Admin =====
app.get("/api/admin/users", requireAdmin, async (req, res) => {
  const { rows } = await pool.query("SELECT username,email,banned FROM users");
  res.json(rows);
});

app.get("/api/admin/posts", requireAdmin, async (req, res) => {
  const { rows } = await pool.query("SELECT * FROM posts");
  res.json(rows);
});

app.post("/api/deletePostAdmin", requireAdmin, async (req, res) => {
  await pool.query("DELETE FROM posts WHERE id=$1", [req.body.id]);
  res.json({ ok: true });
});

app.post("/api/suspendPost", requireAdmin, async (req, res) => {
  await pool.query("UPDATE posts SET suspended=true WHERE id=$1", [req.body.id]);
  res.json({ ok: true });
});

app.post("/api/banUser", requireAdmin, async (req, res) => {
  await pool.query("UPDATE users SET banned=true WHERE username=$1", [req.body.username]);
  res.json({ ok: true });
});

app.post("/api/deleteUser", requireAdmin, async (req, res) => {
  await pool.query("DELETE FROM users WHERE username=$1", [req.body.username]);
  res.json({ ok: true });
});

// ==== Start Server ====
server.listen(PORT, () => {
  console.log(`🚀 BloxWorks running on http://localhost:${PORT}`);
});
