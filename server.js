// ===== BloxWorks Backend =====
const express = require("express");
const sqlite3 = require("sqlite3").verbose();
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const cookieParser = require("cookie-parser");
const http = require("http");
const { Server } = require("socket.io");
const nodemailer = require("nodemailer");
const path = require("path");

const app = express();
const server = http.createServer(app);
const io = new Server(server);

const PORT = 3000;
const JWT_SECRET = "super_secret_key_here";

app.use(express.json());
app.use(cookieParser());
app.use(express.static(path.join(__dirname)));

const db = new sqlite3.Database("data.db");

// ===== Ensure Tables =====
db.serialize(() => {
  db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE,
    email TEXT UNIQUE,
    password_hash TEXT,
    is_admin INTEGER DEFAULT 0,
    banned INTEGER DEFAULT 0
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS posts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    username TEXT,
    mode TEXT,
    title TEXT,
    description TEXT,
    budget TEXT,
    payment TEXT,
    timeline TEXT,
    category TEXT,
    created_at INTEGER,
    suspended INTEGER DEFAULT 0
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    from_user TEXT,
    to_user TEXT,
    text TEXT,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);
});

// ===== Mailer (Reports) =====
const transporter = nodemailer.createTransport({
  service: "gmail",
  auth: {
    user: "bloxworksreports@gmail.com",
    pass: "wnhx gcdt zqtj evsk" // your Gmail app password
  }
});

function generateToken(user) {
  return jwt.sign({
    id: user.id,
    username: user.username,
    email: user.email,
    is_admin: user.is_admin
  }, JWT_SECRET);
}

function requireAuth(req, res, next) {
  const token = req.cookies.token;
  if (!token) return res.status(401).json({ error: "Not logged in" });
  try {
    req.user = jwt.verify(token, JWT_SECRET);
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

// ===== Signup =====
app.post("/api/signup", async (req, res) => {
  const { username, email, password } = req.body;
  if (!username || !email || !password) return res.status(400).json({ error: "Missing fields" });

  const hash = await bcrypt.hash(password, 10);
  const is_admin = (email === "bloxworksreports@gmail.com") ? 1 : 0;

  db.run("INSERT INTO users (username,email,password_hash,is_admin) VALUES (?,?,?,?)",
    [username, email, hash, is_admin],
    function (err) {
      if (err) return res.status(400).json({ error: "User exists" });
      const user = { id: this.lastID, username, email, is_admin };
      const token = generateToken(user);
      res.cookie("token", token).json(user);
    });
});

// ===== Login =====
app.post("/api/login", (req, res) => {
  const { username, password } = req.body;
  db.get("SELECT * FROM users WHERE username=?", [username], async (err, user) => {
    if (!user) return res.status(400).json({ error: "No user" });
    if (user.banned) return res.status(403).json({ error: "User banned" });

    const ok = await bcrypt.compare(password, user.password_hash);
    if (!ok) return res.status(400).json({ error: "Wrong password" });

    const is_admin = (user.email === "bloxworksreports@gmail.com") ? 1 : user.is_admin;
    const token = generateToken({ ...user, is_admin });
    res.cookie("token", token).json({
      id: user.id,
      username: user.username,
      email: user.email,
      is_admin
    });
  });
});

// ===== Stay Logged In =====
app.get("/api/loginStatus", (req,res)=>{
  const token = req.cookies.token;
  if(!token) return res.status(401).end();
  try {
    const user = jwt.verify(token, JWT_SECRET);
    res.json(user);
  } catch {
    res.status(401).end();
  }
});

// ===== Delete Account =====
app.post("/api/deleteAccount", requireAuth, (req, res) => {
  const username = req.user.username;
  db.run("DELETE FROM users WHERE username=?", [username], (err) => {
    if (err) return res.status(500).json({ error: "Failed" });
    db.run("DELETE FROM posts WHERE username=?", [username]);
    db.run("DELETE FROM messages WHERE from_user=? OR to_user=?", [username, username]);
    res.clearCookie("token");
    res.json({ ok: true });
  });
});

// ===== Posts =====
app.get("/api/posts", (req, res) => {
  const now = Date.now();
  const expiry = 72*60*60*1000;
  db.all("SELECT * FROM posts WHERE suspended=0", (err, rows) => {
    if (err) {
      console.error("DB error:", err.message);
      return res.status(500).json({ error: err.message });
    }
    if (!rows) rows = [];
    rows.forEach(r=>{
      if(now - r.created_at > expiry){
        db.run("DELETE FROM posts WHERE id=?",[r.id]);
      }
    });
    db.all("SELECT * FROM posts WHERE suspended=0", (err2, rows2) => {
      if(err2) {
        console.error("DB error after cleanup:", err2.message);
        return res.status(500).json({ error: err2.message });
      }
      res.json(rows2 || []);
    });
  });
});

app.post("/api/posts", requireAuth, (req, res) => {
  const { mode, title, description, budget, payment, timeline, category } = req.body;
  if(!title || !description) return res.status(400).json({error:"Missing fields"});

  db.get("SELECT * FROM posts WHERE user_id=?", [req.user.id], (err, existing) => {
    if (err) return res.status(500).json({ error: err.message });
    if (existing) return res.status(400).json({ error: "Already have a post" });

    db.run(`INSERT INTO posts (user_id,username,mode,title,description,budget,payment,timeline,category,created_at)
            VALUES (?,?,?,?,?,?,?,?,?,?)`,
      [req.user.id, req.user.username, mode, title, description, budget, payment, timeline, category, Date.now()],
      function (err) {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ ok: true });
      });
  });
});

// ===== Messages =====
app.get("/api/messages/:me/:other", requireAuth, (req, res) => {
  const { me, other } = req.params;
  db.all("SELECT * FROM messages WHERE (from_user=? AND to_user=?) OR (from_user=? AND to_user=?) ORDER BY timestamp ASC",
    [me, other, other, me],
    (err, rows) => {
      if (err) return res.status(500).json({ error: "Failed" });
      res.json(rows || []);
    });
});

io.on("connection", (socket) => {
  socket.on("message", (msg) => {
    db.run("INSERT INTO messages (from_user,to_user,text) VALUES (?,?,?)",
      [msg.user, msg.to, msg.text]);
    io.emit("message", msg);
  });
});

// ===== Reports =====
app.post("/api/report", (req, res) => {
  const { accused, reason, reporter } = req.body;
  if(!accused || !reason || !reporter) return res.status(400).json({error:"Missing fields"});
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

// ===== Admin Endpoints =====
app.get("/api/admin/users", requireAdmin, (req,res)=>{
  db.all("SELECT username,email,banned FROM users",(err,rows)=>{
    if(err) return res.status(500).json({error:"Failed"});
    res.json(rows||[]);
  });
});
app.get("/api/admin/posts", requireAdmin, (req,res)=>{
  db.all("SELECT * FROM posts",(err,rows)=>{
    if(err) return res.status(500).json({error:"Failed"});
    res.json(rows||[]);
  });
});
app.post("/api/deletePostAdmin", requireAdmin,(req,res)=>{
  db.run("DELETE FROM posts WHERE id=?",[req.body.id],(err)=>{
    if(err) return res.status(500).json({error:"Failed"});
    res.json({ok:true});
  });
});
app.post("/api/suspendPost", requireAdmin,(req,res)=>{
  db.run("UPDATE posts SET suspended=1 WHERE id=?",[req.body.id],(err)=>{
    if(err) return res.status(500).json({error:"Failed"});
    res.json({ok:true});
  });
});
app.post("/api/banUser", requireAdmin,(req,res)=>{
  db.run("UPDATE users SET banned=1 WHERE username=?",[req.body.username],(err)=>{
    if(err) return res.status(500).json({error:"Failed"});
    res.json({ok:true});
  });
});
app.post("/api/deleteUser", requireAdmin,(req,res)=>{
  db.run("DELETE FROM users WHERE username=?",[req.body.username],(err)=>{
    if(err) return res.status(500).json({error:"Failed"});
    res.json({ok:true});
  });
});

server.listen(PORT, () => console.log(`🚀 BloxWorks running at http://localhost:${PORT}`));
