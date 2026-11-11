# Gudang Password — muzadidil.zasha.online

Penyimpan password demo semua aplikasi. Express.js, tanpa database eksternal.
Dua menu: **Dashboard** (ringkasan) dan **Password** (website, user, password, teknologi).

## Keamanan
- Wajib login (password di-hash scrypt, sesi cookie HttpOnly + SameSite=Strict, batas 5 percobaan/15 menit/IP).
- Kolom password dienkripsi AES-256-GCM di `data/vault.json` dengan kunci `DATA_KEY` dari `.env`.
- `.env` dan `data/` ada di `.gitignore` — **jangan pernah di-commit**.
- **Backup `.env` (terutama `DATA_KEY`) dan `data/vault.json`.** Kunci hilang = password tidak bisa dibuka.
- Pasang HTTPS (Nginx/Cloudflare) di domain.

## Jalankan
```bash
npm install
node setup.js "PasswordLoginAnda"   # membuat .env (rahasia acak)
npm start                            # http://localhost:3000
```

## Deploy (VPS)
```bash
npm install --omit=dev
npm i -g pm2 && pm2 start server.js --name vault && pm2 save
```
Nginx: `proxy_pass http://127.0.0.1:3000;` untuk `muzadidil.zasha.online` + SSL (certbot).

## Impor 100+ aplikasi
Menu Password → **Impor** → tempel dari Excel/CSV dengan urutan kolom `website, user, password, teknologi`.

## MCP (kelola lewat AI)
Aplikasi ini juga menyediakan server MCP di `https://muzadidil.zasha.online/mcp/<MCP_TOKEN>`
(atau `/mcp` dengan header `Authorization: Bearer <MCP_TOKEN>`). Aktif hanya jika `MCP_TOKEN` (min. 24 karakter) diisi.

Tool: `list_menus`, `list_entries`, `add_entry`, `bulk_add_entries`, `update_entry`, `delete_entry`,
`create_menu`, `rename_menu`, `delete_menu`. Password asli **tidak** dikirim ke AI.
`get_password` baru tersedia bila `MCP_ALLOW_REVEAL=1` (tidak disarankan).
Perlakukan token seperti password; ganti nilainya di environment bila bocor.
