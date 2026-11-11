// Server MCP (Streamable HTTP, tanpa SDK) untuk mengelola gudang password lewat AI.
// Aktif hanya bila MCP_TOKEN diisi (min. 24 karakter).
// Menampilkan password asli ke AI dimatikan, kecuali MCP_ALLOW_REVEAL=1.
const crypto = require('crypto');

module.exports = function mountMcp(app, ctx) {
  const { store, kindOf, getMenu, saveMenu, leavesOf, isLeaf, clean, pub, newEntry, enc, dec, eq, limited, attempts, fail } = ctx;
  const TOKEN = process.env.MCP_TOKEN || '';
  const REVEAL = process.env.MCP_ALLOW_REVEAL === '1';
  if (TOKEN.length < 24) { console.log('MCP nonaktif (MCP_TOKEN belum diisi / kurang dari 24 karakter)'); return; }
  console.log('MCP aktif di /mcp' + (REVEAL ? ' (get_password DIIZINKAN)' : ''));

  const str = v => (v === undefined || v === null ? undefined : String(v));
  const need = (v, name) => { if (typeof v !== 'string' || !v.trim()) throw fail(400, `${name} wajib diisi`); return v.trim(); };
  const findEntry = async id => {
    const e = (await store.all()).find(x => x.id === id);
    if (!e) throw fail(404, 'Data tidak ditemukan');
    return e;
  };
  const withPath = async () => { const m = {}; leavesOf(await getMenu()).forEach(l => (m[l.id] = l.path)); return m; };
  const entryOut = (e, paths) => ({ ...pub(e), menu_id: kindOf(e.kind), menu: paths[kindOf(e.kind)] || kindOf(e.kind), has_password: dec(e.password) !== '' });
  const newMenuId = label => (String(label).toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '').slice(0, 20) || 'm') + '-' + crypto.randomBytes(2).toString('hex');

  const S = (props, required = []) => ({ type: 'object', properties: props, required, additionalProperties: false });
  const tools = [
    {
      name: 'list_menus',
      description: 'Daftar menu sidebar (induk dan sub) beserta jumlah data. Pakai id menu "daftar data" sebagai menu_id di tool lain.',
      inputSchema: S({}),
      run: async () => {
        const all = await store.all(), menu = await getMenu();
        const count = id => all.filter(e => kindOf(e.kind) === id).length;
        return menu.map(p => ({
          id: p.id, label: p.label,
          ...(p.children.length ? { children: p.children.map(c => ({ id: c.id, label: c.label, column_title: c.site, count: count(c.id) })) } : { column_title: p.site, count: count(p.id) }),
        }));
      },
    },
    {
      name: 'list_entries',
      description: 'Daftar data (tanpa password). Filter opsional per menu_id dan kata kunci. Password tidak pernah ikut.',
      inputSchema: S({ menu_id: { type: 'string' }, search: { type: 'string' }, limit: { type: 'integer', minimum: 1, maximum: 500 } }),
      run: async a => {
        const paths = await withPath(), q = (a.search || '').toLowerCase();
        let rows = await store.all();
        if (a.menu_id) rows = rows.filter(e => kindOf(e.kind) === a.menu_id);
        if (q) rows = rows.filter(e => [e.website, e.user, e.tech].some(v => (v || '').toLowerCase().includes(q)));
        rows = rows.sort((x, y) => x.website.localeCompare(y.website));
        const limit = Math.min(Number(a.limit) || 200, 500);
        return { total: rows.length, shown: Math.min(rows.length, limit), entries: rows.slice(0, limit).map(e => entryOut(e, paths)) };
      },
    },
    {
      name: 'add_entry',
      description: 'Tambah satu data (website/host, user, password, teknologi) ke sebuah menu.',
      inputSchema: S({ menu_id: { type: 'string' }, website: { type: 'string' }, user: { type: 'string' }, password: { type: 'string' }, tech: { type: 'string' } }, ['menu_id', 'website']),
      run: async a => {
        const b = clean({ kind: a.menu_id, website: need(a.website, 'website'), user: a.user, password: a.password, tech: a.tech });
        if (!(await isLeaf(b.kind))) throw fail(400, 'menu_id tidak valid (lihat list_menus)');
        const e = newEntry(b); await store.insert(e);
        return entryOut(e, await withPath());
      },
    },
    {
      name: 'bulk_add_entries',
      description: 'Tambah banyak data sekaligus ke satu menu (maks 500 baris).',
      inputSchema: S({
        menu_id: { type: 'string' },
        rows: { type: 'array', maxItems: 500, items: S({ website: { type: 'string' }, user: { type: 'string' }, password: { type: 'string' }, tech: { type: 'string' } }, ['website']) },
      }, ['menu_id', 'rows']),
      run: async a => {
        if (!(await isLeaf(kindOf(a.menu_id)))) throw fail(400, 'menu_id tidak valid (lihat list_menus)');
        if (!Array.isArray(a.rows) || !a.rows.length) throw fail(400, 'rows kosong');
        const rows = a.rows.slice(0, 500).map(r => clean({ ...r, kind: a.menu_id })).filter(b => b.website).map(newEntry);
        if (rows.length) await store.insert(rows);
        return { added: rows.length, skipped: a.rows.length - rows.length };
      },
    },
    {
      name: 'update_entry',
      description: 'Ubah data berdasarkan id. Hanya field yang dikirim yang berubah. Kirim menu_id untuk memindahkan ke menu lain.',
      inputSchema: S({ id: { type: 'string' }, menu_id: { type: 'string' }, website: { type: 'string' }, user: { type: 'string' }, password: { type: 'string' }, tech: { type: 'string' } }, ['id']),
      run: async a => {
        const e = await findEntry(need(a.id, 'id'));
        const u = { ...e, updatedAt: new Date().toISOString() };
        if (a.menu_id !== undefined) { if (!(await isLeaf(kindOf(a.menu_id)))) throw fail(400, 'menu_id tidak valid'); u.kind = a.menu_id; }
        if (a.website !== undefined) u.website = need(a.website, 'website').slice(0, 300);
        if (a.user !== undefined) u.user = str(a.user).trim().slice(0, 200);
        if (a.tech !== undefined) u.tech = str(a.tech).trim().slice(0, 100);
        if (a.password !== undefined) u.password = enc(str(a.password));
        await store.update(u);
        return entryOut(u, await withPath());
      },
    },
    {
      name: 'delete_entry',
      description: 'Hapus satu data berdasarkan id. Wajib confirm=true, dan konfirmasikan ke pengguna dulu.',
      inputSchema: S({ id: { type: 'string' }, confirm: { type: 'boolean' } }, ['id', 'confirm']),
      run: async a => {
        if (a.confirm !== true) throw fail(400, 'Set confirm=true setelah pengguna setuju menghapus');
        const e = await findEntry(need(a.id, 'id'));
        await store.remove(e.id);
        return { deleted: e.id, website: e.website };
      },
    },
    {
      name: 'create_menu',
      description: 'Buat menu baru. Tanpa parent_id = menu utama; dengan parent_id = sub-menu dari menu induk itu. column_title = judul kolom pertama tabel (mis. Website atau Host / IP).',
      inputSchema: S({ label: { type: 'string' }, parent_id: { type: 'string' }, column_title: { type: 'string' } }, ['label']),
      run: async a => {
        const label = need(a.label, 'label'), menu = JSON.parse(JSON.stringify(await getMenu()));
        const node = { id: newMenuId(label), label, site: str(a.column_title) || 'Website', children: [] };
        if (a.parent_id) {
          const p = menu.find(x => x.id === a.parent_id);
          if (!p) throw fail(400, 'parent_id harus id menu utama (lihat list_menus)');
          p.children.push({ id: node.id, label, site: node.site });
        } else menu.push(node);
        return saveMenu(menu).then(() => ({ created: node.id, label }));
      },
    },
    {
      name: 'rename_menu',
      description: 'Ganti nama dan/atau judul kolom sebuah menu berdasarkan id.',
      inputSchema: S({ id: { type: 'string' }, label: { type: 'string' }, column_title: { type: 'string' } }, ['id']),
      run: async a => {
        const menu = JSON.parse(JSON.stringify(await getMenu()));
        const n = menu.flatMap(p => [p, ...p.children]).find(x => x.id === a.id);
        if (!n) throw fail(404, 'Menu tidak ditemukan');
        if (a.label !== undefined) n.label = need(a.label, 'label');
        if (a.column_title !== undefined) n.site = need(a.column_title, 'column_title');
        await saveMenu(menu);
        return { renamed: n.id, label: n.label, column_title: n.site };
      },
    },
    {
      name: 'delete_menu',
      description: 'Hapus menu (dan sub-menunya) berdasarkan id. Ditolak bila masih berisi data. Wajib confirm=true.',
      inputSchema: S({ id: { type: 'string' }, confirm: { type: 'boolean' } }, ['id', 'confirm']),
      run: async a => {
        if (a.confirm !== true) throw fail(400, 'Set confirm=true setelah pengguna setuju menghapus');
        let menu = JSON.parse(JSON.stringify(await getMenu()));
        const before = JSON.stringify(menu);
        menu = menu.filter(p => p.id !== a.id).map(p => ({ ...p, children: p.children.filter(c => c.id !== a.id) }));
        if (JSON.stringify(menu) === before) throw fail(404, 'Menu tidak ditemukan');
        await saveMenu(menu);
        return { deleted: a.id };
      },
    },
  ];
  if (REVEAL) tools.push({
    name: 'get_password',
    description: 'Ambil password asli satu data. Sensitif: hanya pakai bila pengguna jelas memintanya.',
    inputSchema: S({ id: { type: 'string' } }, ['id']),
    run: async a => { const e = await findEntry(need(a.id, 'id')); return { id: e.id, website: e.website, user: e.user, password: dec(e.password) }; },
  });
  const byName = Object.fromEntries(tools.map(t => [t.name, t]));

  const SUPPORTED = ['2025-06-18', '2025-03-26', '2024-11-05'];
  async function handle(msg) {
    const { id, method, params } = msg || {};
    const ok = result => ({ jsonrpc: '2.0', id, result });
    const err = (code, message) => ({ jsonrpc: '2.0', id: id ?? null, error: { code, message } });
    if (!msg || msg.jsonrpc !== '2.0' || typeof method !== 'string') return err(-32600, 'Invalid Request');
    if (id === undefined) return null; // notifikasi: tanpa balasan
    switch (method) {
      case 'initialize': {
        const v = params && SUPPORTED.includes(params.protocolVersion) ? params.protocolVersion : SUPPORTED[0];
        return ok({ protocolVersion: v, capabilities: { tools: { listChanged: false } }, serverInfo: { name: 'gudang-password', version: '1.0.0' },
          instructions: 'Kelola gudang password: menu, dan data (website/host, user, password, teknologi). Password asli tidak dikirim ke AI.' });
      }
      case 'ping': return ok({});
      case 'tools/list': return ok({ tools: tools.map(({ name, description, inputSchema }) => ({ name, description, inputSchema })) });
      case 'tools/call': {
        const t = byName[params && params.name];
        if (!t) return err(-32602, 'Tool tidak dikenal');
        try {
          const out = await t.run((params.arguments && typeof params.arguments === 'object') ? params.arguments : {});
          return ok({ content: [{ type: 'text', text: JSON.stringify(out, null, 1) }] });
        } catch (e) {
          if (!e.status) console.error('MCP error:', e);
          return ok({ isError: true, content: [{ type: 'text', text: e.status ? e.message : 'Kesalahan server / database' }] });
        }
      }
      default: return err(-32601, 'Method not found');
    }
  }

  const authed = req => {
    const bearer = (req.headers.authorization || '').replace(/^Bearer\s+/i, '');
    const given = req.params.token || bearer;
    return !!given && eq(given, TOKEN);
  };
  const paths = ['/mcp', '/mcp/:token'];
  app.post(paths, async (req, res) => {
    const key = 'mcp:' + req.ip;
    if (limited(key)) return res.status(429).json({ error: 'Terlalu banyak percobaan' });
    if (!authed(req)) {
      const a = attempts.get(key) || { n: 0, t: Date.now() };
      attempts.set(key, { n: a.n + 1, t: Date.now() });
      return res.status(401).json({ error: 'Unauthorized' });
    }
    attempts.delete(key);
    const batch = Array.isArray(req.body);
    const out = (await Promise.all((batch ? req.body : [req.body]).map(handle))).filter(Boolean);
    if (!out.length) return res.status(202).end();
    res.json(batch ? out : out[0]);
  });
  app.all(paths, (req, res) => res.set('Allow', 'POST').status(405).json({ error: 'Gunakan POST' }));
};
