// Membuat file .env berisi rahasia acak.  Pakai: node setup.js <password-login> [user]
const crypto = require('crypto'), fs = require('fs');
const pass = process.argv[2], user = process.argv[3] || 'admin';
if (!pass || pass.length < 8) { console.error('Pakai: node setup.js <password-login-min-8-karakter> [user]'); process.exit(1); }
if (fs.existsSync('.env')) { console.error('.env sudah ada. Hapus dulu jika ingin membuat ulang (DATA_KEY lama hilang = data lama tak terbaca!)'); process.exit(1); }
const salt = crypto.randomBytes(16).toString('hex');
const hash = crypto.scryptSync(pass, salt, 64).toString('hex');
fs.writeFileSync('.env', [
  'PORT=3000',
  'ADMIN_USER=' + user,
  'ADMIN_HASH=' + salt + ':' + hash,
  'SESSION_SECRET=' + crypto.randomBytes(32).toString('hex'),
  'DATA_KEY=' + crypto.randomBytes(32).toString('hex'),
  ''
].join('\n'), { mode: 0o600 });
console.log('.env dibuat. BACKUP file .env (terutama DATA_KEY) di tempat aman.');
