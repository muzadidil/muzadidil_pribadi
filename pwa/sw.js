// Service worker: hanya menyimpan cangkang statis (ikon, manifest, halaman offline).
// Data dan halaman aplikasi TIDAK disimpan, karena berisi password dan butuh login.
const V = 'vault-v1';
const PRE = ['/offline.html', '/icon-192.png', '/icon-512.png', '/manifest.webmanifest'];

self.addEventListener('install', e => {
  e.waitUntil(caches.open(V).then(c => c.addAll(PRE)).then(() => self.skipWaiting()));
});
self.addEventListener('activate', e => {
  e.waitUntil(caches.keys().then(ks => Promise.all(ks.filter(k => k !== V).map(k => caches.delete(k)))).then(() => self.clients.claim()));
});
self.addEventListener('fetch', e => {
  const r = e.request;
  if (r.method !== 'GET') return;
  const u = new URL(r.url);
  if (u.origin !== location.origin) return;
  if (r.mode === 'navigate') {
    e.respondWith(fetch(r).catch(() => caches.match('/offline.html')));
    return;
  }
  if (PRE.includes(u.pathname)) e.respondWith(caches.match(r).then(m => m || fetch(r)));
  // permintaan lain (termasuk /api) langsung ke jaringan, tanpa cache
});
