const CACHE_NAME = 'lara-v2';
const PRECACHE_URLS = [
  '/',
  '/static/manifest.json',
  'https://cdn.tailwindcss.com',
  'https://unpkg.com/lucide@latest',
  'https://cdnjs.cloudflare.com/ajax/libs/qrcodejs/1.0.0/qrcode.min.js',
  'https://fonts.googleapis.com/css2?family=Inter:wght@400;500;700&display=swap'
];

// Install: precache shell
self.addEventListener('install', event => {
  event.waitUntil(
    caches.open(CACHE_NAME).then(cache => cache.addAll(PRECACHE_URLS))
      .then(() => self.skipWaiting())
  );
});

// Activate: clean old caches
self.addEventListener('activate', event => {
  event.waitUntil(
    caches.keys().then(keys =>
      Promise.all(keys.filter(k => k !== CACHE_NAME).map(k => caches.delete(k)))
    ).then(() => self.clients.claim())
  );
});

// Handle share target: intercept POST to /share-target, stash files, redirect to app
self.addEventListener('fetch', event => {
  const url = new URL(event.request.url);

  if (url.pathname === '/share-target' && event.request.method === 'POST') {
    event.respondWith((async () => {
      const formData = await event.request.formData();
      const files = formData.getAll('files');

      // Store shared files temporarily in a special cache
      const cache = await caches.open('lara-share-target');
      const fileData = [];
      for (let i = 0; i < files.length; i++) {
        const file = files[i];
        const stashKey = `/share-stash/${i}-${file.name}`;
        await cache.put(stashKey, new Response(file, {
          headers: { 'X-File-Name': file.name, 'Content-Type': file.type || 'application/octet-stream' }
        }));
        fileData.push(stashKey);
      }

      // Also stash the file list
      await cache.put('/share-stash/manifest', new Response(JSON.stringify(fileData), {
        headers: { 'Content-Type': 'application/json' }
      }));

      // Redirect to the main app with a flag
      return Response.redirect('/?shared=1', 303);
    })());
    return;
  }

  // Never cache API calls or uploads
  if (url.pathname.startsWith('/api/')) {
    return;
  }

  event.respondWith(
    caches.match(event.request).then(cached => {
      const fetchPromise = fetch(event.request).then(response => {
        // Update cache with fresh version
        if (response.ok) {
          const clone = response.clone();
          caches.open(CACHE_NAME).then(cache => cache.put(event.request, clone));
        }
        return response;
      }).catch(() => cached); // Offline fallback to cache

      return cached || fetchPromise;
    })
  );
});
