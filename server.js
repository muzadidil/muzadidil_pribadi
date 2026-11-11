const express = require('express');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

// ---- .env sederhana (tanpa dependency) ----
try {
  for (const l of fs.readFileSync(path.join(__dirname, '.env'), 'utf8').split(/\r?\n/)) {
    const m = l.match(/^\s*([A-Z_]+)\s*=\s*(.*?)\s*$/);
    if (m && !(m[1] in process.env)) process.env[m[1]] = m[2];
  }
} catch (_) {}
const { PORT = 3000, ADMIN_USER = 'admin', ADMIN_HASH, SESSION_SECRET, DATA_KEY } = process.env;
if (!ADMIN_HASH || !SESSION_SECRET || !DATA_KEY || DATA_KEY.length !== 64) {
  console.error('Konfigurasi belum lengkap. Jalankan: node setup.js <password-login>');
  process.exit(1);
}
const KEY = Buffer.from(DATA_KEY, 'hex');

// ---- enkripsi kolom password: AES-256-GCM ----
function enc(text) {
  const iv = crypto.randomBytes(12);
  const c = crypto.createCipheriv('aes-256-gcm', KEY, iv);
  const ct = Buffer.concat([c.update(String(text), 'utf8'), c.final()]);
  return [iv, c.getAuthTag(), ct].map(b => b.toString('base64')).join('.');
}
function dec(s) {
  const [iv, tag, ct] = s.split('.').map(x => Buffer.from(x, 'base64'));
  const d = crypto.createDecipheriv('aes-256-gcm', KEY, iv);
  d.setAuthTag(tag);
  return Buffer.concat([d.update(ct), d.final()]).toString('utf8');
}

// ---- penyimpanan: MySQL bila DB_NAME diisi, jika tidak pakai file JSON ----
// Antarmuka: init(), all(), insert(e), update(e), remove(id)  -> semua async
function fileStore() {
  const dir = process.env.DATA_DIR || path.join(__dirname, 'data');
  const file = path.join(dir, 'vault.json');
  let rows = [];
  const save = () => {
    const tmp = file + '.tmp';
    fs.writeFileSync(tmp, JSON.stringify(rows), { mode: 0o600 });
    fs.renameSync(tmp, file);
  };
  return {
    name: 'file ' + file,
    async init() { fs.mkdirSync(dir, { recursive: true }); try { rows = JSON.parse(fs.readFileSync(file, 'utf8')); } catch (_) {} },
    async all() { return rows; },
    async insert(es) { rows.push(...[].concat(es)); save(); },
    async update(e) { const i = rows.findIndex(x => x.id === e.id); if (i >= 0) { rows[i] = e; save(); } },
    async remove(id) { const n = rows.length; rows = rows.filter(x => x.id !== id); if (rows.length !== n) save(); return rows.length !== n; },
  };
}
function mysqlStore() {
  const mysql = require('mysql2/promise');
  const pool = mysql.createPool({
    host: process.env.DB_HOST || 'localhost',
    port: Number(process.env.DB_PORT || 3306),
    user: process.env.DB_USER,
    password: process.env.DB_PASS,
    database: process.env.DB_NAME,
    waitForConnections: true,
    connectionLimit: 5,
    charset: 'utf8mb4',
  });
  const toRow = r => ({ id: r.id, kind: r.kind, website: r.website, user: r.username, password: r.password, tech: r.tech, createdAt: r.created_at, updatedAt: r.updated_at });
  const vals = e => [e.id, e.kind || 'password', e.website, e.user, e.password, e.tech, e.createdAt, e.updatedAt];
  return {
    name: `mysql ${process.env.DB_USER}@${process.env.DB_HOST || 'localhost'}/${process.env.DB_NAME}`,
    async init() {
      await pool.query(`CREATE TABLE IF NOT EXISTS vault_entries (
        id CHAR(36) PRIMARY KEY,
        website VARCHAR(300) NOT NULL,
        username VARCHAR(200) NOT NULL DEFAULT '',
        password TEXT NOT NULL,
        tech VARCHAR(100) NOT NULL DEFAULT '',
        created_at VARCHAR(30) NOT NULL,
        updated_at VARCHAR(30) NOT NULL
      ) CHARACTER SET utf8mb4`);
      // migrasi otomatis: kolom "kind" (password / ssh) untuk tabel lama
      try { await pool.query("ALTER TABLE vault_entries ADD COLUMN kind VARCHAR(20) NOT NULL DEFAULT 'password'"); }
      catch (e) { if (e.errno !== 1060) throw e; } // 1060 = kolom sudah ada
    },
    async all() { const [r] = await pool.query('SELECT * FROM vault_entries'); return r.map(toRow); },
    async insert(es) {
      for (const e of [].concat(es))
        await pool.query('INSERT INTO vault_entries (id,kind,website,username,password,tech,created_at,updated_at) VALUES (?,?,?,?,?,?,?,?)', vals(e));
    },
    async update(e) {
      await pool.query('UPDATE vault_entries SET website=?, username=?, password=?, tech=?, updated_at=? WHERE id=?',
        [e.website, e.user, e.password, e.tech, e.updatedAt, e.id]);
    },
    async remove(id) { const [r] = await pool.query('DELETE FROM vault_entries WHERE id=?', [id]); return r.affectedRows > 0; },
  };
}
const store = process.env.DB_NAME ? mysqlStore() : fileStore();

// ---- sesi: cookie bertanda tangan ----
const sign = v => crypto.createHmac('sha256', SESSION_SECRET).update(v).digest('base64url');
const eq = (a, b) => a.length === b.length && crypto.timingSafeEqual(Buffer.from(a), Buffer.from(b));
function parseCookies(req) {
  const o = {};
  (req.headers.cookie || '').split(';').forEach(p => {
    const i = p.indexOf('=');
    if (i > 0) o[p.slice(0, i).trim()] = decodeURIComponent(p.slice(i + 1));
  });
  return o;
}
function isAuthed(req) {
  const t = parseCookies(req).sid;
  if (!t) return false;
  const [exp, sig] = t.split('.');
  return !!sig && eq(sign(exp), sig) && Number(exp) > Date.now();
}
function checkPassword(pass) {
  const [salt, hash] = ADMIN_HASH.split(':');
  const h = crypto.scryptSync(String(pass), salt, 64).toString('hex');
  return eq(h, hash);
}
const attempts = new Map(); // batas percobaan login per IP
function limited(ip) {
  const a = attempts.get(ip);
  return a && a.n >= 5 && Date.now() - a.t < 15 * 60 * 1000;
}

const app = express();
app.set('trust proxy', 1);
app.disable('x-powered-by');
app.use((req, res, next) => {
  res.set({
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY',
    'Referrer-Policy': 'no-referrer',
    'Cache-Control': 'no-store',
    'X-Robots-Tag': 'noindex, nofollow',
  });
  next();
});
app.use(express.json({ limit: '2mb' }));
const wrap = fn => (req, res) => Promise.resolve(fn(req, res)).catch(err => {
  console.error(err);
  res.status(500).json({ error: 'Kesalahan server / database' });
});

app.post('/api/login', (req, res) => {
  if (limited(req.ip)) return res.status(429).json({ error: 'Terlalu banyak percobaan. Coba lagi 15 menit lagi.' });
  const { user, password } = req.body || {};
  const ok = typeof user === 'string' && typeof password === 'string' && eq(user, ADMIN_USER) && checkPassword(password);
  if (!ok) {
    const a = attempts.get(req.ip) || { n: 0, t: Date.now() };
    attempts.set(req.ip, { n: a.n + 1, t: Date.now() });
    return res.status(401).json({ error: 'User atau password salah.' });
  }
  attempts.delete(req.ip);
  const exp = String(Date.now() + 12 * 3600 * 1000);
  const secure = req.secure ? '; Secure' : '';
  res.set('Set-Cookie', `sid=${exp}.${sign(exp)}; HttpOnly; SameSite=Strict; Path=/; Max-Age=43200${secure}`);
  res.json({ ok: true });
});
app.post('/api/logout', (req, res) => {
  res.set('Set-Cookie', 'sid=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0');
  res.json({ ok: true });
});

// halaman login terbuka; sisanya wajib login
app.get('/login', (req, res) => res.sendFile(path.join(__dirname, 'public', 'login.html')));
app.use((req, res, next) => {
  if (isAuthed(req)) return next();
  if (req.path.startsWith('/api/')) return res.status(401).json({ error: 'Belum login' });
  res.redirect('/login');
});

const kindOf = k => (k === 'ssh' ? 'ssh' : 'password');
const clean = (b = {}) => ({
  kind: kindOf(b.kind),
  website: String(b.website || '').trim().slice(0, 300),
  user: String(b.user || '').trim().slice(0, 200),
  password: String(b.password ?? ''),
  tech: String(b.tech || '').trim().slice(0, 100),
});
const pub = e => ({ id: e.id, kind: kindOf(e.kind), website: e.website, user: e.user, tech: e.tech, createdAt: e.createdAt, updatedAt: e.updatedAt });
const newEntry = b => { const now = new Date().toISOString(); return { id: crypto.randomUUID(), ...b, password: enc(b.password), createdAt: now, updatedAt: now }; };

app.get('/api/entries', wrap(async (req, res) => {
  const k = kindOf(req.query.kind);
  res.json((await store.all()).filter(e => kindOf(e.kind) === k).map(pub));
}));
app.get('/api/entries/:id/password', wrap(async (req, res) => {
  const e = (await store.all()).find(x => x.id === req.params.id);
  if (!e) return res.status(404).json({ error: 'Tidak ditemukan' });
  res.json({ password: dec(e.password) });
}));
app.post('/api/entries', wrap(async (req, res) => {
  const b = clean(req.body);
  if (!b.website) return res.status(400).json({ error: 'Website wajib diisi' });
  const e = newEntry(b);
  await store.insert(e);
  res.status(201).json(pub(e));
}));
app.put('/api/entries/:id', wrap(async (req, res) => {
  const e = (await store.all()).find(x => x.id === req.params.id);
  if (!e) return res.status(404).json({ error: 'Tidak ditemukan' });
  const b = clean(req.body);
  if (!b.website) return res.status(400).json({ error: 'Website wajib diisi' });
  const u = { ...e, website: b.website, user: b.user, tech: b.tech, updatedAt: new Date().toISOString() };
  // password tidak dikirim / null = tidak diubah
  if (req.body.password !== undefined && req.body.password !== null) u.password = enc(b.password);
  await store.update(u);
  res.json(pub(u));
}));
app.delete('/api/entries/:id', wrap(async (req, res) => {
  if (!(await store.remove(req.params.id))) return res.status(404).json({ error: 'Tidak ditemukan' });
  res.json({ ok: true });
}));
// impor massal: [{website,user,password,tech}, ...] (untuk 100+ aplikasi sekaligus)
app.post('/api/import', wrap(async (req, res) => {
  const rows = (Array.isArray(req.body) ? req.body : []).slice(0, 2000).map(clean).filter(b => b.website).map(newEntry);
  if (rows.length) await store.insert(rows);
  res.json({ imported: rows.length });
}));
app.get('/api/stats', wrap(async (req, res) => {
  const everything = await store.all();
  const sshTotal = everything.filter(e => kindOf(e.kind) === 'ssh').length;
  const entries = everything.filter(e => kindOf(e.kind) === 'password');
  const byTech = {};
  for (const e of entries) { const t = e.tech || '(tanpa teknologi)'; byTech[t] = (byTech[t] || 0) + 1; }
  const recent = [...entries].sort((a, b) => b.updatedAt.localeCompare(a.updatedAt)).slice(0, 8).map(pub);
  res.json({
    total: entries.length,
    sshTotal,
    techCount: Object.keys(byTech).length,
    noPassword: entries.filter(e => dec(e.password) === '').length,
    byTech: Object.entries(byTech).sort((a, b) => b[1] - a[1]).map(([name, count]) => ({ name, count })),
    recent,
  });
}));

app.use(express.static(path.join(__dirname, 'public'), { index: 'index.html' }));
store.init()
  .then(() => app.listen(PORT, () => console.log(`Vault berjalan di port ${PORT} - penyimpanan: ${store.name}`)))
  .catch(err => { console.error('Gagal menyiapkan penyimpanan:', err.message); process.exit(1); });
