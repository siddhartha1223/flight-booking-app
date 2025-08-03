const CACHE_NAME = 'travel-booking-v1';
const urlsToCache = [
    '/',
    '/admin',
    '/book_flight',
    '/static/css/styles.css',
    '/static/images/flight-bg.jpg',
    '/static/images/train-bg.jpg',
    '/static/images/home-bg.jpg',
    '/static/images/icon-192.png',
    '/static/images/icon-512.png'
];

self.addEventListener('install', event => {
    event.waitUntil(
        caches.open(CACHE_NAME)
            .then(cache => cache.addAll(urlsToCache))
    );
});

self.addEventListener('fetch', event => {
    event.respondWith(
        caches.match(event.request)
            .then(response => response || fetch(event.request))
    );
});