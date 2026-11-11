// Service worker بسيط: بيخلي المتجر قابل للتثبيت كتطبيق. ما بيخزّن أي بيانات (دايماً بيجيب الجديد).
self.addEventListener('install', function(){ self.skipWaiting(); });
self.addEventListener('activate', function(e){ e.waitUntil(self.clients.claim()); });
self.addEventListener('fetch', function(){});
