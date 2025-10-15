import express from "express";
import helmet from "helmet";
import cors from "cors";
import sqlite3 from "sqlite3";
import { open } from "sqlite";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";

const app = express();
app.use(express.json({ limit: "32kb" }));
app.use(helmet());
app.use(cors({ origin: true }));

// ===== env =====
const PORT = process.env.PORT || 3000;
const DB_FILE = process.env.DB_FILE || "/tmp/rank.db";
const JWT_SECRET = process.env.JWT_SECRET || "CHANGE_ME_JWT_SECRET";
const JWT_EXPIRES = process.env.JWT_EXPIRES || "1d";

// ===== db & schema =====
const db = await open({ filename: DB_FILE, driver: sqlite3.Database });
await db.exec("PRAGMA foreign_keys = ON;");
await db.exec(`
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT UNIQUE NOT NULL,
  pass_hash TEXT NOT NULL,
  created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS leaderboard (
  player_id INTEGER NOT NULL,
  map TEXT NOT NULL,                  -- "plain" | "rain" | "snow"
  best_score INTEGER NOT NULL,
  best_stats TEXT NOT NULL DEFAULT '{}',
  updated_at INTEGER NOT NULL,
  PRIMARY KEY(player_id, map),
  FOREIGN KEY(player_id) REFERENCES users(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_map_score ON leaderboard(map, best_score DESC);
`);

const MAPS = new Set(["plain", "rain", "snow"]);
const isValidMap = (m) => typeof m === "string" && MAPS.has(m);

const signJwt = (payload) => jwt.sign(payload, JWT_SECRET, { expiresIn: JWT_EXPIRES });
const auth = (req, res, next) => {
  const h = req.headers.authorization || "";
  const token = h.startsWith("Bearer ") ? h.slice(7) : null;
  if (!token) return res.status(401).json({ err: "no token" });
  try { req.user = jwt.verify(token, JWT_SECRET); next(); }
  catch { return res.status(401).json({ err: "invalid token" }); }
};

function isValidStats(obj) {
  if (typeof obj !== "object" || obj === null || Array.isArray(obj)) return false;
  const keys = Object.keys(obj);
  if (keys.length > 32) return false;
  for (const k of keys) {
    if (typeof k !== "string" || k.length > 24) return false;
    const v = obj[k];
    if (typeof v !== "number" || !Number.isFinite(v) || v < 0 || v > 9999) return false;
  }
  return true;
}

// ===== health =====
app.get("/health", (_, res) => res.json({ ok: true }));

// ===== auth =====
app.post("/auth/register", async (req, res) => {
  const { username, password } = req.body || {};
  if (!username || !password) return res.status(400).json({ err: "username/password required" });
  if (username.length < 3 || username.length > 24) return res.status(400).json({ err: "bad username" });
  if (password.length < 4 || password.length > 64) return res.status(400).json({ err: "bad password" });

  const hash = await bcrypt.hash(password, 10);
  try {
    const r = await db.run(
      `INSERT INTO users(username, pass_hash, created_at) VALUES(?, ?, ?)`,
      [username, hash, Date.now()]
    );
    const uid = r.lastID;
    const token = signJwt({ uid, username });
    res.json({ token, uid, username });
  } catch (e) {
    if (String(e).includes("UNIQUE")) return res.status(409).json({ err: "username taken" });
    console.error(e); res.status(500).json({ err: "server error" });
  }
});

app.post("/auth/login", async (req, res) => {
  const { username, password } = req.body || {};
  if (!username || !password) return res.status(400).json({ err: "username/password required" });
  const row = await db.get(`SELECT id, pass_hash FROM users WHERE username = ?`, username);
  if (!row) return res.status(401).json({ err: "invalid credentials" });
  const ok = await bcrypt.compare(password, row.pass_hash);
  if (!ok) return res.status(401).json({ err: "invalid credentials" });
  const token = signJwt({ uid: row.id, username });
  res.json({ token, uid: row.id, username });
});

app.post("/auth/logout", (_, res) => res.json({ ok: true })); // 최소 구현
app.get("/me", auth, async (req, res) => {
  const me = await db.get(`SELECT id, username, created_at FROM users WHERE id = ?`, req.user.uid);
  res.json({ user: me });
});

// ===== submit (계정당 맵별 1개 최고기록 + 스탯) =====
app.post("/submit", auth, async (req, res) => {
  const { map, score, stats } = req.body || {};
  if (!isValidMap(map)) return res.status(400).json({ err: "bad map" });
  if (typeof score !== "number" || !Number.isInteger(score) || score < 0)
    return res.status(400).json({ err: "bad score" });
  if (!isValidStats(stats || {})) return res.status(400).json({ err: "bad stats" });

  const uid = req.user.uid;
  const now = Date.now();
  const cur = await db.get(
    `SELECT best_score FROM leaderboard WHERE player_id = ? AND map = ?`,
    [uid, map]
  );

  if (!cur) {
    await db.run(
      `INSERT INTO leaderboard(player_id, map, best_score, best_stats, updated_at)
       VALUES(?, ?, ?, ?, ?)`,
      [uid, map, score, JSON.stringify(stats || {}), now]
    );
    return res.json({ ok: true, updated: true });
  }

  if (score > cur.best_score) {
    await db.run(
      `UPDATE leaderboard
       SET best_score = ?, best_stats = ?, updated_at = ?
       WHERE player_id = ? AND map = ?`,
      [score, JSON.stringify(stats || {}), now, uid, map]
    );
    return res.json({ ok: true, updated: true });
  }

  res.json({ ok: true, updated: false }); // 낮은 점수는 무시
});

// ===== 내 최고기록(Top10에 없어도 항상 조회 가능) =====
app.get("/me/best", auth, async (req, res) => {
  const map = req.query.map;
  if (!isValidMap(map)) return res.status(400).json({ err: "bad map" });

  const row = await db.get(
    `SELECT best_score, best_stats, updated_at
     FROM leaderboard
     WHERE player_id = ? AND map = ?`,
    [req.user.uid, map]
  );
  if (!row) return res.json({ best: null });

  res.json({
    best: {
      map,
      score: row.best_score,
      stats: JSON.parse(row.best_stats || "{}"),
      updated_at: row.updated_at
    }
  });
});

// ===== 맵별 TopN =====
app.get("/top", async (req, res) => {
  const map = req.query.map;
  if (!isValidMap(map)) return res.status(400).json({ err: "bad map" });
  const limit = Math.min(parseInt(req.query.limit || "10"), 100);

  const rows = await db.all(
    `SELECT u.username, l.best_score
     FROM leaderboard l
     JOIN users u ON u.id = l.player_id
     WHERE l.map = ?
     ORDER BY l.best_score DESC, l.updated_at ASC
     LIMIT ?`,
    [map, limit]
  );
  res.json(rows);
});

// ===== (선택) 맵별 내 순위 =====
app.get("/myrank", auth, async (req, res) => {
  const map = req.query.map;
  if (!isValidMap(map)) return res.status(400).json({ err: "bad map" });

  const me = await db.get(
    `SELECT best_score FROM leaderboard WHERE player_id = ? AND map = ?`,
    [req.user.uid, map]
  );
  if (!me) return res.json({ map, rank: null, score: null });

  const higher = await db.get(
    `SELECT COUNT(*) AS c FROM leaderboard WHERE map = ? AND best_score > ?`,
    [map, me.best_score]
  );
  res.json({ map, rank: higher.c + 1, score: me.best_score });
});

app.listen(PORT, () => console.log(`rank api listening on :${PORT}`));
