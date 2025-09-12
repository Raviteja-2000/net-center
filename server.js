// server.js
require('dotenv').config();
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const morgan = require('morgan');
const path = require('path');

let Database;
try {
  Database = require('better-sqlite3');
} catch {
  console.error('better-sqlite3 not installed. Run: npm i better-sqlite3');
  process.exit(1);
}

const app = express();
app.set('trust proxy', 1);

app.use(helmet());
app.use(morgan('tiny'));
app.use(express.json({ limit: '100kb' }));

const allowedOrigin = process.env.ALLOWED_ORIGIN;
app.use(
  cors({
    origin: function (origin, cb) {
      if (!origin) return cb(null, true);
      if (!allowedOrigin) return cb(null, true);
      if (origin === allowedOrigin) return cb(null, true);
      return cb(new Error('Not allowed by CORS'));
    },
  })
);

app.use(
  rateLimit({
    windowMs: 60 * 1000,
    max: 60,
    standardHeaders: true,
    legacyHeaders: false,
  })
);

const DB_PATH = process.env.DB_PATH || path.join(process.cwd(), 'data.db');
const db = new Database(DB_PATH);
db.pragma('journal_mode = WAL');

db.exec(`
CREATE TABLE IF NOT EXISTS inquiries (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  phone TEXT NOT NULL,
  service TEXT,
  message TEXT,
  page_url TEXT,
  created_at TEXT NOT NULL,
  ip TEXT
);
CREATE TABLE IF NOT EXISTS events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  type TEXT NOT NULL,
  page_url TEXT,
  ua TEXT,
  created_at TEXT NOT NULL,
  ip TEXT
);
`);

const insertInquiry = db.prepare(
  `INSERT INTO inquiries (name, phone, service, message, page_url, created_at, ip)
   VALUES (?,?,?,?,?,datetime('now'),?)`
);
const listInquiries = db.prepare(
  `SELECT * FROM inquiries ORDER BY id DESC LIMIT ? OFFSET ?`
);
const insertEvent = db.prepare(
  `INSERT INTO events (type, page_url, ua, created_at, ip)
   VALUES (?,?,?,datetime('now'),?)`
);
const countEventsByType = db.prepare(
  `SELECT type, COUNT(*) as count FROM events GROUP BY type`
);
const eventsLast7 = db.prepare(
  `SELECT date(created_at) as day, type, COUNT(*) as count
   FROM events
   WHERE created_at >= datetime('now','-7 day')
   GROUP BY day, type
   ORDER BY day`
);

function clientIp(req) {
  return (req.headers['x-forwarded-for'] || '').split(',')[0] || req.ip || '';
}
function cleanPhone(p) {
  const digits = String(p || '').replace(/\D/g, '');
  if (digits.length < 10 || digits.length > 15) return null;
  return digits;
}

app.get('/api/ping', (req, res) =>
  res.json({ ok: true, time: new Date().toISOString() })
);

app.post('/api/inquiry', (req, res) => {
  const { name, phone, service = '', message = '', page_url = '' } = req.body || {};
  if (!name || !phone) return res.status(400).json({ ok: false, error: 'name and phone are required' });
  const cleaned = cleanPhone(phone);
  if (!cleaned) return res.status(400).json({ ok: false, error: 'invalid phone' });

  try {
    insertInquiry.run(
      String(name).trim().slice(0, 100),
      cleaned,
      String(service).trim().slice(0, 80),
      String(message).trim().slice(0, 2000),
      String(page_url).slice(0, 400),
      clientIp(req)
    );
    res.json({ ok: true, message: 'Inquiry saved' });
  } catch (e) {
    console.error(e);
    res.status(500).json({ ok: false, error: 'db_error' });
  }
});

const allowedTypes = new Set(['whatsapp', 'call', 'map', 'copy_address', 'form_submit']);
app.post('/api/analytics/click', (req, res) => {
  const { type, page_url = '' } = req.body || {};
  if (!type || !allowedTypes.has(type)) return res.status(400).json({ ok: false, error: 'invalid type' });

  try {
    insertEvent.run(
      type,
      String(page_url).slice(0, 400),
      String(req.headers['user-agent'] || '').slice(0, 255),
      clientIp(req)
    );
    res.json({ ok: true });
  } catch (e) {
    console.error(e);
    res.status(500).json({ ok: false });
  }
});

function requireKey(req, res, next) {
  const key = req.get('x-api-key');
  if (!process.env.API_KEY) return res.status(500).json({ ok: false, error: 'API_KEY not set' });
  if (key !== process.env.API_KEY) return res.status(401).json({ ok: false, error: 'unauthorized' });
  next();
}

app.get('/api/inquiries', requireKey, (req, res) => {
  const limit = Math.min(parseInt(req.query.limit || '100', 10), 500);
  const rows = listInquiries.all(limit, 0);
  res.json({ ok: true, count: rows.length, data: rows });
});

app.get('/api/export.csv', requireKey, (req, res) => {
  const rows = db.prepare('SELECT * FROM inquiries ORDER BY id DESC').all();
  const headers = Object.keys(rows[0] || { id: 1, name: 1, phone: 1, service: 1, message: 1, page_url: 1, created_at: 1, ip: 1 });
  const esc = (v) => `"${String(v ?? '').replace(/"/g, '""')}"`;
  const csv = [headers.join(',')]
    .concat(rows.map((r) => headers.map((h) => esc(r[h])).join(',')))
    .join('\n');

  res.setHeader('Content-Type', 'text/csv');
  res.setHeader('Content-Disposition', 'attachment; filename="inquiries.csv"');
  res.send(csv);
});

app.get('/api/analytics/summary', requireKey, (req, res) => {
  const byType = countEventsByType.all();
  const last7 = eventsLast7.all();
  res.json({ ok: true, byType, last7 });
});

const port = process.env.PORT || 3000;
app.listen(port, () => console.log(`✅ API listening on :${port}`));
