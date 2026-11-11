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

// ---- penyimpanan terenkripsi (kolom password: AES-256-GCM) ----
const DB_DIR = path.join(__dirname, 'data');
const DB_FILE = path.join(DB_DIR, 'vault.json');
fs.mkdirSync(DB_DIR, { recursive: true });
let entries = [];
try { entries = JSON.parse(fs.readFileSync(DB_FILE, 'utf8')); } catch (_) {}
function save() {
  const tmp = DB_FILE + '.tmp';
  fs.writeFileSync(tmp, JSON.stringify(entries), { mode: 0o600 });
  fs.renameSync(tmp, DB_FILE);
}
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

const clean = (b = {}) => ({
  website: String(b.website || '').trim().slice(0, 300),
  user: String(b.user || '').trim().slice(0, 200),
  password: String(b.password ?? ''),
  tech: String(b.tech || '').trim().slice(0, 100),
});
const pub = e => ({ id: e.id, website: e.website, user: e.user, tech: e.tech, createdAt: e.createdAt, updatedAt: e.updatedAt });

app.get('/api/entries', (req, res) => res.json(entries.map(pub)));
app.get('/api/entries/:id/password', (req, res) => {
  const e = entries.find(x => x.id === req.params.id);
  if (!e) return res.status(404).json({ error: 'Tidak ditemukan' });
  res.json({ password: dec(e.password) });
});
app.post('/api/entries', (req, res) => {
  const b = clean(req.body);
  if (!b.website) return res.status(400).json({ error: 'Website wajib diisi' });
  const now = new Date().toISOString();
  const e = { id: crypto.randomUUID(), ...b, password: enc(b.password), createdAt: now, updatedAt: now };
  entries.push(e); save();
  res.status(201).json(pub(e));
});
app.put('/api/entries/:id', (req, res) => {
  const e = entries.find(x => x.id === req.params.id);
  if (!e) return res.status(404).json({ error: 'Tidak ditemukan' });
  const b = clean(req.body);
  if (!b.website) return res.status(400).json({ error: 'Website wajib diisi' });
  Object.assign(e, { website: b.website, user: b.user, tech: b.tech, updatedAt: new Date().toISOString() });
  // password tidak dikirim / null = tidak diubah
  if (req.body.password !== undefined && req.body.password !== null) e.password = enc(b.password);
  save();
  res.json(pub(e));
});
app.delete('/api/entries/:id', (req, res) => {
  const n = entries.length;
  entries = entries.filter(x => x.id !== req.params.id);
  if (entries.length === n) return res.status(404).json({ error: 'Tidak ditemukan' });
  save();
  res.json({ ok: true });
});
// impor massal: [{website,user,password,tech}, ...] (untuk 100+ aplikasi sekaligus)
app.post('/api/import', (req, res) => {
  const rows = Array.isArray(req.body) ? req.body : [];
  const now = new Date().toISOString();
  let n = 0;
  for (const r of rows.slice(0, 2000)) {
    const b = clean(r);
    if (!b.website) continue;
    entries.push({ id: crypto.randomUUID(), ...b, password: enc(b.password), createdAt: now, updatedAt: now });
    n++;
  }
  if (n) save();
  res.json({ imported: n });
});
app.get('/api/stats', (req, res) => {
  const byTech = {};
  for (const e of entries) { const t = e.tech || '(tanpa teknologi)'; byTech[t] = (byTech[t] || 0) + 1; }
  const recent = [...entries].sort((a, b) => b.updatedAt.localeCompare(a.updatedAt)).slice(0, 8).map(pub);
  res.json({
    total: entries.length,
    techCount: Object.keys(byTech).length,
    noPassword: entries.filter(e => dec(e.password) === '').length,
    byTech: Object.entries(byTech).sort((a, b) => b[1] - a[1]).map(([name, count]) => ({ name, count })),
    recent,
  });
});

app.use(express.static(path.join(__dirname, 'public'), { index: 'index.html' }));
app.listen(PORT, () => console.log(`Vault berjalan di http://localhost:${PORT}`));
