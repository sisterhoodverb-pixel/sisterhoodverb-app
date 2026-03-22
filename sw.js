const CACHE_NAME = ‘sisterhoodverb-v5’;
const STATIC_ASSETS = [
‘/app.html’,
‘/manifest.json’
];

// Install — cache static assets
self.addEventListener(‘install’, event => {
event.waitUntil(
caches.open(CACHE_NAME).then(cache => {
return cache.addAll(STATIC_ASSETS);
})
);
self.skipWaiting();
});

// Activate — clean up old caches
self.addEventListener(‘activate’, event => {
event.waitUntil(
caches.keys().then(keys =>
Promise.all(
keys.filter(key => key !== CACHE_NAME).map(key => caches.delete(key))
)
)
);
self.clients.claim();
});

// Fetch — network first, fall back to cache
self.addEventListener(‘fetch’, event => {
// Skip non-GET and Supabase API calls
if (event.request.method !== ‘GET’) return;
if (event.request.url.includes(‘supabase.co’)) return;
if (event.request.url.includes(‘giphy.com’)) return;

event.respondWith(
fetch(event.request)
.then(response => {
// Cache successful responses
if (response.ok) {
const responseClone = response.clone();
caches.open(CACHE_NAME).then(cache => {
cache.put(event.request, responseClone);
});
}
return response;
})
.catch(() => {
// Fall back to cache when offline
return caches.match(event.request).then(cached => {
if (cached) return cached;
// Return app shell for navigation requests
if (event.request.mode === ‘navigate’) {
return caches.match(’/app.html’);
}
});
})
);
});