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
  const sfile = path.join(dir, 'settings.json');
  let rows = [], settings = {};
  const write = (f, data) => {
    const tmp = f + '.tmp';
    fs.writeFileSync(tmp, JSON.stringify(data), { mode: 0o600 });
    fs.renameSync(tmp, f);
  };
  const save = () => write(file, rows);
  return {
    name: 'file ' + file,
    async init() {
      fs.mkdirSync(dir, { recursive: true });
      try { rows = JSON.parse(fs.readFileSync(file, 'utf8')); } catch (_) {}
      try { settings = JSON.parse(fs.readFileSync(sfile, 'utf8')); } catch (_) {}
    },
    async getSetting(k) { return settings[k]; },
    async setSetting(k, v) { settings[k] = v; write(sfile, settings); },
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
      await pool.query('CREATE TABLE IF NOT EXISTS vault_settings (k VARCHAR(50) PRIMARY KEY, v TEXT NOT NULL) CHARACTER SET utf8mb4');
      // migrasi otomatis: kolom "kind" (password / ssh) untuk tabel lama
      try { await pool.query("ALTER TABLE vault_entries ADD COLUMN kind VARCHAR(20) NOT NULL DEFAULT 'password'"); }
      catch (e) { if (e.errno !== 1060) throw e; } // 1060 = kolom sudah ada
    },
    async getSetting(k) { const [r] = await pool.query('SELECT v FROM vault_settings WHERE k=?', [k]); return r[0] ? r[0].v : undefined; },
    async setSetting(k, v) { await pool.query('INSERT INTO vault_settings (k,v) VALUES (?,?) ON DUPLICATE KEY UPDATE v=VALUES(v)', [k, v]); },
    async all() { const [r] = await pool.query('SELECT * FROM vault_entries'); return r.map(toRow); },
    async insert(es) {
      for (const e of [].concat(es))
        await pool.query('INSERT INTO vault_entries (id,kind,website,username,password,tech,created_at,updated_at) VALUES (?,?,?,?,?,?,?,?)', vals(e));
    },
    async update(e) {
      await pool.query('UPDATE vault_entries SET kind=?, website=?, username=?, password=?, tech=?, updated_at=? WHERE id=?',
        [e.kind || 'password', e.website, e.user, e.password, e.tech, e.updatedAt, e.id]);
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
// kredensial login: dari environment, ditimpa oleh yang disimpan lewat menu Akun
let cred = { user: ADMIN_USER, hash: ADMIN_HASH };
function checkPassword(pass) {
  const [salt, hash] = cred.hash.split(':');
  const h = crypto.scryptSync(String(pass), salt, 64).toString('hex');
  return eq(h, hash);
}
function makeHash(pass) {
  const salt = crypto.randomBytes(16).toString('hex');
  return salt + ':' + crypto.scryptSync(String(pass), salt, 64).toString('hex');
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
  if (err && err.status) return res.status(err.status).json({ error: err.message });
  console.error(err);
  res.status(500).json({ error: 'Kesalahan server / database' });
});

app.post('/api/login', (req, res) => {
  if (limited(req.ip)) return res.status(429).json({ error: 'Terlalu banyak percobaan. Coba lagi 15 menit lagi.' });
  const { user, password } = req.body || {};
  const ok = typeof user === 'string' && typeof password === 'string' && eq(user, cred.user) && checkPassword(password);
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

// berkas PWA (manifest, service worker, ikon) harus bisa diambil tanpa login
app.use(express.static(path.join(__dirname, 'pwa'), { index: false }));

// halaman login terbuka; sisanya wajib login
app.get('/login', (req, res) => res.sendFile(path.join(__dirname, 'public', 'login.html')));
app.use((req, res, next) => {
  if (req.path === '/mcp' || req.path.startsWith('/mcp/')) return next(); // MCP memakai token sendiri
  if (isAuthed(req)) return next();
  if (req.path.startsWith('/api/')) return res.status(401).json({ error: 'Belum login' });
  res.redirect('/login');
});

// ganti user / password login (disimpan di penyimpanan, menimpa environment)
app.get('/api/account', (req, res) => res.json({ user: cred.user }));
app.post('/api/account', wrap(async (req, res) => {
  const { currentPassword, newUser, newPassword } = req.body || {};
  if (typeof currentPassword !== 'string' || !checkPassword(currentPassword))
    return res.status(403).json({ error: 'Password saat ini salah.' });
  const u = String(newUser || '').trim();
  if (u.length < 3 || u.length > 50) return res.status(400).json({ error: 'User 3-50 karakter.' });
  if (typeof newPassword !== 'string' || newPassword.length < 8 || newPassword.length > 200)
    return res.status(400).json({ error: 'Password baru minimal 8 karakter.' });
  const next = { user: u, hash: makeHash(newPassword) };
  await store.setSetting('admin', JSON.stringify(next));
  cred = next;
  res.json({ ok: true, user: u });
}));

// ---- struktur menu sidebar (induk + sub), disimpan di penyimpanan ----
// Tiap menu "daun" (tanpa sub) adalah satu daftar data; entri menyimpan id-nya di kolom kind.
const kindOf = k => (typeof k === 'string' && /^[a-z0-9_-]{1,30}$/.test(k) ? k : 'password');
const DEFAULT_MENU = [
  { id: 'password', label: 'Password', site: 'Website', children: [] },
  { id: 'ssh', label: 'SSH', site: 'Host / IP', children: [] },
];
async function getMenu() {
  const s = await store.getSetting('menu');
  if (s) { try { const m = JSON.parse(s); if (Array.isArray(m) && m.length) return m; } catch (_) {} }
  return DEFAULT_MENU;
}
const leavesOf = menu => menu.flatMap(p => p.children && p.children.length
  ? p.children.map(c => ({ id: c.id, label: c.label, site: c.site, path: p.label + ' › ' + c.label }))
  : [{ id: p.id, label: p.label, site: p.site, path: p.label }]);
const cleanNode = (n, withKids) => {
  const o = {
    id: kindOf(n && n.id) === (n && n.id) ? n.id : null,
    label: String((n && n.label) || '').trim().slice(0, 40),
    site: String((n && n.site) || 'Website').trim().slice(0, 30) || 'Website',
  };
  if (withKids) o.children = (Array.isArray(n.children) ? n.children : []).slice(0, 50).map(c => cleanNode(c, false));
  return o;
};
app.get('/api/menu', wrap(async (req, res) => res.json(await getMenu())));
const fail = (status, message) => Object.assign(new Error(message), { status });
// validasi + simpan susunan menu; melempar fail(status,pesan) bila tidak valid
async function saveMenu(raw) {
  if (!Array.isArray(raw) || !raw.length || raw.length > 50) throw fail(400, 'Menu tidak valid.');
  const menu = raw.map(n => cleanNode(n, true));
  const seen = new Set();
  for (const n of menu.flatMap(p => [p, ...p.children])) {
    if (!n.id || !n.label) throw fail(400, 'Setiap menu wajib punya nama.');
    if (seen.has(n.id)) throw fail(400, 'ID menu ganda.');
    seen.add(n.id);
  }
  // menu yang tidak lagi jadi "daftar data" tidak boleh masih berisi data
  const oldLeaves = leavesOf(await getMenu()), newIds = new Set(leavesOf(menu).map(l => l.id));
  const all = await store.all();
  for (const l of oldLeaves) {
    if (newIds.has(l.id)) continue;
    const n = all.filter(e => kindOf(e.kind) === l.id).length;
    if (n) throw fail(409, `Menu "${l.path}" masih berisi ${n} data. Pindahkan dulu lewat tombol Ubah (pilih menu lain).`);
  }
  await store.setSetting('menu', JSON.stringify(menu));
  return menu;
}
app.put('/api/menu', wrap(async (req, res) => res.json(await saveMenu(req.body))));
const isLeaf = async k => leavesOf(await getMenu()).some(l => l.id === k);
const clean = (b = {}) => ({
  kind: kindOf(b.kind),
  website: String(b.website || '').trim().slice(0, 300),
  user: String(b.user || '').trim().slice(0, 200),
  password: String(b.password ?? ''),
  tech: String(b.tech || '').trim().slice(0, 100),
});
const pub = e => ({ id: e.id, kind: kindOf(e.kind), website: e.website, user: e.user, tech: e.tech, createdAt: e.createdAt, updatedAt: e.updatedAt });
const newEntry = b => { const now = new Date().toISOString(); return { id: crypto.randomUUID(), ...b, password: enc(b.password), createdAt: now, updatedAt: now }; };

// MCP: biarkan AI mengelola data lewat /mcp (butuh MCP_TOKEN di environment)
require('./mcp')(app, { store, kindOf, getMenu, saveMenu, leavesOf, isLeaf, clean, pub, newEntry, enc, dec, eq, limited, attempts, fail });

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
  if (!b.website) return res.status(400).json({ error: 'Isian pertama wajib diisi' });
  if (!(await isLeaf(b.kind))) return res.status(400).json({ error: 'Menu tujuan tidak valid' });
  const e = newEntry(b);
  await store.insert(e);
  res.status(201).json(pub(e));
}));
app.put('/api/entries/:id', wrap(async (req, res) => {
  const e = (await store.all()).find(x => x.id === req.params.id);
  if (!e) return res.status(404).json({ error: 'Tidak ditemukan' });
  const b = clean(req.body);
  if (!b.website) return res.status(400).json({ error: 'Isian pertama wajib diisi' });
  if (req.body.kind !== undefined && !(await isLeaf(b.kind))) return res.status(400).json({ error: 'Menu tujuan tidak valid' });
  const u = { ...e, kind: req.body.kind !== undefined ? b.kind : kindOf(e.kind), website: b.website, user: b.user, tech: b.tech, updatedAt: new Date().toISOString() };
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
  const ok = new Set(leavesOf(await getMenu()).map(l => l.id));
  const rows = (Array.isArray(req.body) ? req.body : []).slice(0, 2000).map(clean).filter(b => b.website && ok.has(b.kind)).map(newEntry);
  if (rows.length) await store.insert(rows);
  res.json({ imported: rows.length });
}));
app.get('/api/stats', wrap(async (req, res) => {
  const entries = await store.all();
  const leaves = leavesOf(await getMenu());
  const byMenu = leaves.map(l => ({ name: l.path, count: entries.filter(e => kindOf(e.kind) === l.id).length }));
  const byTech = {};
  for (const e of entries) { const t = e.tech || '(tanpa teknologi)'; byTech[t] = (byTech[t] || 0) + 1; }
  const recent = [...entries].sort((a, b) => b.updatedAt.localeCompare(a.updatedAt)).slice(0, 8).map(pub);
  res.json({
    total: entries.length,
    menuCount: leaves.length,
    byMenu,
    techCount: Object.keys(byTech).length,
    noPassword: entries.filter(e => dec(e.password) === '').length,
    byTech: Object.entries(byTech).sort((a, b) => b[1] - a[1]).map(([name, count]) => ({ name, count })),
    recent,
  });
}));

app.use(express.static(path.join(__dirname, 'public'), { index: 'index.html' }));
store.init()
  .then(async () => {
    const saved = await store.getSetting('admin');
    if (saved) { try { const c = JSON.parse(saved); if (c.user && c.hash) cred = c; } catch (_) {} }
  })
  .then(() => app.listen(PORT, () => console.log(`Vault berjalan di port ${PORT} - penyimpanan: ${store.name}`)))
  .catch(err => { console.error('Gagal menyiapkan penyimpanan:', err.message); process.exit(1); });
