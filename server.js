import express from "express";
import cors from "cors";
import dotenv from "dotenv";
import jwt from "jsonwebtoken";
import bcrypt from "bcryptjs";
import Database from "better-sqlite3";
import crypto from "crypto";

dotenv.config();

const app = express();

const PORT = process.env.PORT || 3000;
const SECRET = process.env.JWT_SECRET || "change-this-secret";
const ADMIN_USER = process.env.ADMIN_USER || "Raiyan";
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || "raiyan123";

app.use(cors({
  origin: process.env.CORS_ORIGIN || "*"
}));

app.use(express.json());

// Serve index.html and admin.html
app.use(express.static("."));

// =========================
// DATABASE
// =========================

const db = new Database("data.sqlite");

db.pragma("journal_mode = WAL");

db.exec(`
CREATE TABLE IF NOT EXISTS users (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  email TEXT UNIQUE NOT NULL,
  password TEXT NOT NULL,
  balance REAL DEFAULT 0,
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS orders (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL,
  data TEXT NOT NULL,
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS services (
  id TEXT PRIMARY KEY,
  data TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS settings (
  id TEXT PRIMARY KEY,
  data TEXT NOT NULL
);
`);

// =========================
// HELPERS
// =========================

const uid = () => crypto.randomUUID();

const now = () => new Date().toISOString();

function createToken(payload, expiresIn = "12h") {
  return jwt.sign(payload, SECRET, {
    expiresIn
  });
}

// =========================
// ADMIN AUTH
// =========================

function adminAuth(req, res, next) {
  try {
    const header = req.headers.authorization || "";

    const authToken = header.startsWith("Bearer ")
      ? header.substring(7)
      : "";

    const payload = jwt.verify(authToken, SECRET);

    if (payload.role !== "admin") {
      return res.status(401).json({
        error: "Admin login required"
      });
    }

    req.admin = payload;

    next();

  } catch (error) {
    res.status(401).json({
      error: "Admin login required"
    });
  }
}

// =========================
// USER AUTH
// =========================

function userAuth(req, res, next) {
  try {
    const header = req.headers.authorization || "";

    const authToken = header.startsWith("Bearer ")
      ? header.substring(7)
      : "";

    const payload = jwt.verify(authToken, SECRET);

    if (payload.role !== "user") {
      return res.status(401).json({
        error: "User login required"
      });
    }

    req.user = payload;

    next();

  } catch (error) {
    res.status(401).json({
      error: "Login required"
    });
  }
}

// =========================
// HEALTH CHECK
// =========================

app.get("/api/health", (req, res) => {
  res.json({
    ok: true,
    message: "Raiyan server is running"
  });
});

// =========================
// ADMIN LOGIN
// =========================

app.post("/api/admin/login", (req, res) => {

  const { user, password } = req.body || {};

  if (
    user === ADMIN_USER &&
    password === ADMIN_PASSWORD
  ) {

    const authToken = createToken({
      role: "admin"
    });

    return res.json({
      success: true,
      token: authToken
    });
  }

  res.status(401).json({
    error: "Wrong admin username or password"
  });
});

// =========================
// USER REGISTER
// =========================

app.post("/api/auth/register", async (req, res) => {

  try {

    const {
      name,
      email,
      password
    } = req.body || {};

    if (!name || !email || !password) {
      return res.status(400).json({
        error: "Name, email and password are required"
      });
    }

    if (password.length < 6) {
      return res.status(400).
