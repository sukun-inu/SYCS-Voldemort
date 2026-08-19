const CACHE_NAME = "metal-tracker-v7";

function scopedUrl(path) {
  return new URL(path, self.registration.scope).toString();
}

const APP_SHELL = [
  scopedUrl("./"),
  scopedUrl("index.html"),
  scopedUrl("manifest.webmanifest"),
  scopedUrl("static/icons/metal-logo-192.png"),
  scopedUrl("static/icons/metal-logo-512.png"),
  scopedUrl("static/icons/metal-logo-maskable-192.png"),
  scopedUrl("static/icons/metal-logo-maskable-512.png"),
  scopedUrl("static/icons/apple-touch-icon.png"),
  scopedUrl("static/icons/metal-logo.svg"),
];

self.addEventListener("install", (event) => {
  event.waitUntil(
    caches.open(CACHE_NAME).then((cache) => cache.addAll(APP_SHELL)).then(() => self.skipWaiting())
  );
});

self.addEventListener("activate", (event) => {
  event.waitUntil(
    caches.keys().then((keys) =>
      Promise.all(
        keys.filter((key) => key !== CACHE_NAME).map((key) => caches.delete(key))
      )
    ).then(() => self.clients.claim())
  );
});

self.addEventListener("fetch", (event) => {
  const request = event.request;
  if (request.method !== "GET") {
    return;
  }

  const url = new URL(request.url);
  const scopeUrl = new URL(self.registration.scope);
  if (url.origin !== scopeUrl.origin) {
    return;
  }

  const scopePath = scopeUrl.pathname.endsWith("/") ? scopeUrl.pathname : `${scopeUrl.pathname}/`;
  if (url.pathname.startsWith(`${scopePath}api/`)) {
    return;
  }

  const inScopePath = url.pathname.startsWith(scopePath)
    ? url.pathname.slice(scopePath.length)
    : url.pathname.replace(/^\//, "");
  const useNetworkFirst =
    request.mode === "navigate" ||
    inScopePath === "" ||
    inScopePath === "index.html" ||
    inScopePath === "manifest.webmanifest" ||
    inScopePath === "static/app.js" ||
    inScopePath === "static/styles.css";

  if (useNetworkFirst) {
    event.respondWith(
      fetch(request)
        .then((response) => {
          if (response.ok && response.type === "basic") {
            const copy = response.clone();
            caches.open(CACHE_NAME).then((cache) => cache.put(request, copy));
          }
          return response;
        })
        .catch(async () => {
          const cached = await caches.match(request);
          return cached || caches.match(scopedUrl("./"));
        })
    );
    return;
  }

  event.respondWith(
    caches.match(request).then((cached) => {
      if (cached) {
        return cached;
      }
      return fetch(request)
        .then((response) => {
          if (response.ok && response.type === "basic") {
            const copy = response.clone();
            caches.open(CACHE_NAME).then((cache) => cache.put(request, copy));
          }
          return response;
        })
        .catch(() => caches.match(scopedUrl("./")));
    })
  );
});

self.addEventListener("push", (event) => {
  let payload = { title: "価格通知", body: "本日の通知があります。", url: "./" };
  if (event.data) {
    try {
      payload = event.data.json();
    } catch (_) {
      payload.body = event.data.text();
    }
  }

  event.waitUntil(
    self.registration.showNotification(payload.title || "価格通知", {
      body: payload.body || "",
      icon: scopedUrl("static/icons/metal-logo-192.png"),
      badge: scopedUrl("static/icons/metal-logo-192.png"),
      data: { url: payload.url || "./" },
      tag: payload.tag || "metal-notify",
    })
  );
});

self.addEventListener("notificationclick", (event) => {
  event.notification.close();
  const targetUrl = event.notification?.data?.url || "./";
  event.waitUntil(
    self.clients.matchAll({ type: "window", includeUncontrolled: true }).then((clients) => {
      for (const client of clients) {
        if ("focus" in client) {
          client.navigate(new URL(targetUrl, self.registration.scope).toString());
          return client.focus();
        }
      }
      return self.clients.openWindow(new URL(targetUrl, self.registration.scope).toString());
    })
  );
});
