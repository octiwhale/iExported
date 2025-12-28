const CACHE_NAME = 'iexported-v1';
const URLS_TO_CACHE = [
  '/',
  '/style.css',
  '/script.js'
];

self.addEventListener('install', event => {
  event.waitUntil(
    caches.open(CACHE_NAME).then(cache => {
      return cache.addAll(URLS_TO_CACHE);
    })
  );
});

self.addEventListener('activate', event => {
  event.waitUntil(
    caches.keys().then(cacheNames => {
      return Promise.all(
        cacheNames.map(cacheName => {
          if (cacheName !== CACHE_NAME) {
            return caches.delete(cacheName);
          }
        })
      );
    })
  );
});

self.addEventListener('fetch', event => {
  const { request } = event;
  const url = new URL(request.url);

  // Only cache GET requests for our static assets
  if (request.method !== 'GET') {
    return;
  }

  // Check if this is one of our cacheable URLs
  const isCacheable = URLS_TO_CACHE.some(cacheUrl => {
    return url.pathname === cacheUrl || url.pathname.endsWith(cacheUrl);
  });

  if (isCacheable) {
    event.respondWith(
      caches.match(request).then(response => {
        return response || fetch(request);
      })
    );
  }
});
