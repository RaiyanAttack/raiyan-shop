import express from "express";
import cors from "cors";
import dotenv from "dotenv";
import jwt from "jsonwebtoken";
import bcrypt from "bcryptjs";
import Database from "better-sqlite3";
import crypto from "crypto";
import path from "path";
import { fileURLToPath } from "url";

dotenv.config();

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = process.env.PORT || 3000;

const SECRET = process.env.JWT_SECRET || "change-this-secret";
const ADMIN_USER = process.env.ADMIN_USER || "Raiyan";
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || "raiyan123";

app.use(cors({
  origin: process.env.CORS_ORIGIN || "*"
}));

app.use(express.json({ limit: "10mb" }));
app.use(express.urlencoded({ extended: true }));

// ===============================
// DATABASE
// ===============================

const db = new Database(path.join(__dirname, "data.sqlite"));

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

// ===============================
// HELPERS
// ===============================

const uid = () => crypto.randomUUID();

const now = () => new Date().toISOString();

function createToken(payload, expiresIn = "12h") {
  return jwt.sign(payload, SECRET, { expiresIn });
}

// ===============================
// AUTH MIDDLEWARE
// ===============================

function adminAuth(req, res, next) {
  try {
    const header = req.headers.authorization || "";

    if (!header.startsWith("Bearer ")) {
      return res.status(401).json({
        error: "Admin login required"
      });
    }

    const token = header.substring(7);
    const payload = jwt.verify(token, SECRET);

    if (payload.role !== "admin") {
      return res.status(401).json({
        error: "Admin access denied"
      });
    }

    req.admin = payload;
    next();

  } catch (error) {
    return res.status(401).json({
      error: "Invalid admin token"
    });
  }
}

function userAuth(req, res, next) {
  try {
    const header = req.headers.authorization || "";

    if (!header.startsWith("Bearer ")) {
      return res.status(401).json({
        error: "Login required"
      });
    }

    const token = header.substring(7);
    const payload = jwt.verify(token, SECRET);

    if (payload.role !== "user") {
      return res.status(401).json({
        error: "User access denied"
      });
    }

    req.user = payload;
    next();

  } catch (error) {
    return res.status(401).json({
      error: "Invalid login token"
    });
  }
}

// ===============================
// FRONTEND
// ===============================

// IMPORTANT:
// index.html and admin.html must be
// in the same root folder as server.js.

app.use(express.static(__dirname));

app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "index.html"));
});

app.get("/admin", (req, res) => {
  res.sendFile(path.join(__dirname, "admin.html"));
});

app.get("/admin.html", (req, res) => {
  res.sendFile(path.join(__dirname, "admin.html"));
});

// ===============================
// HEALTH
// ===============================

app.get("/api/health", (req, res) => {
  res.json({
    ok: true,
    message: "Raiyan Shop backend is running"
  });
});

// ===============================
// ADMIN LOGIN
// ===============================

app.post("/api/admin/login", (req, res) => {
  const { user, password } = req.body || {};

  if (
    user === ADMIN_USER &&
    password === ADMIN_PASSWORD
  ) {
    return res.json({
      success: true,
      token: createToken({
        role: "admin"
      })
    });
  }

  return res.status(401).json({
    error: "Wrong admin username or password"
  });
});

// ===============================
// USER REGISTER
// ===============================

app.post("/api/auth/register", async (req, res) => {
  try {
    const { name, email, password } = req.body || {};

    if (!name || !email || !password) {
      return res.status(400).json({
        error: "Please fill all fields"
      });
    }

    if (password.length < 6) {
      return res.status(400).json({
        error: "Password must be at least 6 characters"
      });
    }

    const normalizedEmail = email.trim().toLowerCase();

    const existing = db
      .prepare("SELECT id FROM users WHERE email = ?")
      .get(normalizedEmail);

    if (existing) {
      return res.status(409).json({
        error: "Email already exists"
      });
    }

    const id = uid();

    const hash = await bcrypt.hash(password, 10);

    db.prepare(`
      INSERT INTO users
      (id, name, email, password, balance, created_at)
      VALUES (?, ?, ?, ?, ?, ?)
    `).run(
      id,
      name.trim(),
      normalizedEmail,
      hash,
      0,
      now()
    );

    const token = createToken(
      {
        role: "user",
        id
      },
      "30d"
    );

    res.json({
      success: true,
      token,
      user: {
        id,
        name: name.trim(),
        email: normalizedEmail,
        balance: 0
      }
    });

  } catch (error) {
    console.error(error);

    res.status(500).json({
      error: "Registration failed"
    });
  }
});

// ===============================
// USER LOGIN
// ===============================

app.post("/api/auth/login", async (req, res) => {
  try {
    const { email, password } = req.body || {};

    const normalizedEmail =
      (email || "").trim().toLowerCase();

    const user = db
      .prepare("SELECT * FROM users WHERE email = ?")
      .get(normalizedEmail);

    if (!user) {
      return res.status(401).json({
        error: "Invalid email or password"
      });
    }

    const valid = await bcrypt.compare(
      password || "",
      user.password
    );

    if (!valid) {
      return res.status(401).json({
        error: "Invalid email or password"
      });
    }

    const token = createToken(
      {
        role: "user",
        id: user.id
      },
      "30d"
    );

    res.json({
      success: true,
      token,
      user: {
        id: user.id,
        name: user.name,
        email: user.email,
        balance: user.balance
      }
    });

  } catch (error) {
    console.error(error);

    res.status(500).json({
      error: "Login failed"
    });
  }
});

// ===============================
// CURRENT USER
// ===============================

app.get("/api/me", userAuth, (req, res) => {
  const user = db
    .prepare(`
      SELECT id, name, email, balance
      FROM users
      WHERE id = ?
    `)
    .get(req.user.id);

  if (!user) {
    return res.status(404).json({
      error: "User not found"
    });
  }

  res.json(user);
});

// ===============================
// SERVICES
// ===============================

app.get("/api/services", (req, res) => {
  const rows = db
    .prepare("SELECT id, data FROM services")
    .all();

  const services = rows.map(row => {
    try {
      return {
        id: row.id,
        ...JSON.parse(row.data)
      };
    } catch {
      return {
        id: row.id
      };
    }
  });

  res.json(services);
});

app.post("/api/services", adminAuth, (req, res) => {
  try {
    const id = req.body.id || uid();

    const data = {
      ...req.body
    };

    delete data.id;

    db.prepare(`
      INSERT OR REPLACE INTO services
      (id, data)
      VALUES (?, ?)
    `).run(
      id,
      JSON.stringify(data)
    );

    res.json({
      success: true,
      id,
      ...data
    });

  } catch (error) {
    console.error(error);

    res.status(500).json({
      error: "Could not save service"
    });
  }
});

app.delete("/api/services/:id", adminAuth, (req, res) => {
  db.prepare(
    "DELETE FROM services WHERE id = ?"
  ).run(req.params.id);

  res.json({
    success: true
  });
});

// ===============================
// SETTINGS
// ===============================

app.get("/api/settings/:id", (req, res) => {
  const row = db
    .prepare(
      "SELECT data FROM settings WHERE id = ?"
    )
    .get(req.params.id);

  if (!row) {
    return res.json({});
  }

  try {
    res.json(JSON.parse(row.data));
  } catch {
    res.json({});
  }
});

app.put("/api/settings/:id", adminAuth, (req, res) => {
  db.prepare(`
    INSERT OR REPLACE INTO settings
    (id, data)
    VALUES (?, ?)
  `).run(
    req.params.id,
    JSON.stringify(req.body || {})
  );

  res.json({
    success: true,
    ...req.body
  });
});

// ===============================
// ORDERS - ADMIN
// ===============================

app.get("/api/orders", adminAuth, (req, res) => {
  const rows = db
    .prepare(`
      SELECT id, user_id, data, created_at
      FROM orders
      ORDER BY created_at DESC
    `)
    .all();

  const orders = rows.map(row => {
    let data = {};

    try {
      data = JSON.parse(row.data);
    } catch {}

    return {
      id: row.id,
      userId: row.user_id,
      ...data,
      createdAt: row.created_at
    };
  });

  res.json(orders);
});

// ===============================
// USER ORDERS
// ===============================

app.get("/api/my-orders", userAuth, (req, res) => {
  const rows = db
    .prepare(`
      SELECT id, data, created_at
      FROM orders
      WHERE user_id = ?
      ORDER BY created_at DESC
    `)
    .all(req.user.id);

  const orders = rows.map(row => {
    let data = {};

    try {
      data = JSON.parse(row.data);
    } catch {}

    return {
      id: row.id,
      ...data,
      createdAt: row.created_at
    };
  });

  res.json(orders);
});

// ===============================
// CREATE ORDER
// ===============================

app.post("/api/orders", userAuth, (req, res) => {
  try {
    const user = db
      .prepare("SELECT * FROM users WHERE id = ?")
      .get(req.user.id);

    if (!user) {
      return res.status(404).json({
        error: "User not found"
      });
    }

    const price = Number(req.body.price || 0);

    if (!Number.isFinite(price) || price < 0) {
      return res.status(400).json({
        error: "Invalid price"
      });
    }

    if (user.balance < price) {
      return res.status(400).json({
        error: "Insufficient balance"
      });
    }

    const id = uid();

    const data = {
      ...req.body,
      status: "pending",
      date: now()
    };

    const transaction = db.transaction(() => {

      db.prepare(`
        UPDATE users
        SET balance = balance - ?
        WHERE id = ?
      `).run(
        price,
        user.id
      );

      db.prepare(`
        INSERT INTO orders
        (id, user_id, data, created_at)
        VALUES (?, ?, ?, ?)
      `).run(
        id,
        user.id,
        JSON.stringify(data),
        now()
      );

    });

    transaction();

    res.json({
      success: true,
      id,
      ...data
    });

  } catch (error) {
    console.error(error);

    res.status(500).json({
      error: "Order creation failed"
    });
  }
});

// ===============================
// UPDATE ORDER
// ===============================

app.patch("/api/orders/:id", adminAuth, (req, res) => {
  const row = db
    .prepare(
      "SELECT data FROM orders WHERE id = ?"
    )
    .get(req.params.id);

  if (!row) {
    return res.status(404).json({
      error: "Order not found"
    });
  }

  let oldData = {};

  try {
    oldData = JSON.parse(row.data);
  } catch {}

  const newData = {
    ...oldData,
    ...req.body
  };

  db.prepare(`
    UPDATE orders
    SET data = ?
    WHERE id = ?
  `).run(
    JSON.stringify(newData),
    req.params.id
  );

  res.json({
    success: true,
    id: req.params.id,
    ...newData
  });
});

// ===============================
// USERS - ADMIN
// ===============================

app.get("/api/users", adminAuth, (req, res) => {
  const users = db
    .prepare(`
      SELECT
        id,
        name,
        email,
        balance,
        created_at
      FROM users
      ORDER BY created_at DESC
    `)
    .all();

  res.json(users);
});

// ===============================
// UPDATE USER BALANCE
// ===============================

app.patch(
  "/api/users/:id/balance",
  adminAuth,
  (req, res) => {

    const balance = Number(req.body.balance);

    if (!Number.isFinite(balance) || balance < 0) {
      return res.status(400).json({
        error: "Invalid balance"
      });
    }

    const result = db.prepare(`
      UPDATE users
      SET balance = ?
      WHERE id = ?
    `).run(
      balance,
      req.params.id
    );

    if (result.changes === 0) {
      return res.status(404).json({
        error: "User not found"
      });
    }

    res.json({
      success: true,
      balance
    });
  }
);

// ===============================
// ADMIN STATS
// ===============================

app.get("/api/admin/stats", adminAuth, (req, res) => {

  const users = db
    .prepare("SELECT COUNT(*) AS n FROM users")
    .get().n;

  const orders = db
    .prepare("SELECT COUNT(*) AS n FROM orders")
    .get().n;

  const services = db
    .prepare("SELECT COUNT(*) AS n FROM services")
    .get().n;

  res.json({
    users,
    orders,
    services
  });
});

// ===============================
// 404 API
// ===============================

app.use("/api", (req, res) => {
  res.status(404).json({
    error: "API endpoint not found"
  });
});

// ===============================
// ERROR HANDLER
// ===============================

app.use((err, req, res, next) => {
  console.error(err);

  res.status(500).json({
    error: "Internal server error"
  });
});

// ===============================
// START SERVER
// ===============================

app.listen(PORT, "0.0.0.0", () => {
  console.log(
    `Raiyan Shop server running on port ${PORT}`
  );
});
