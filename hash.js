// Membuat nilai ADMIN_HASH dari password baru, di komputer sendiri.
// Pakai: node hash.js "PasswordBaruAnda"
const crypto = require('crypto');
const pass = process.argv[2];
if (!pass || pass.length < 8) { console.error('Pakai: node hash.js "PasswordBaru" (minimal 8 karakter)'); process.exit(1); }
const salt = crypto.randomBytes(16).toString('hex');
console.log('ADMIN_HASH=' + salt + ':' + crypto.scryptSync(pass, salt, 64).toString('hex'));
