const CACHE_NAME = "rickyy-chat-cache-v8";

const APP_SHELL = [
  "/",
  "/index.html",
  "/chat.html",
  "/profile.html",
  "/manifest.json",
  "/icons/icon-192.png",
  "/icons/icon-512.png",
  "/default.png",
  "/default-group.png"
];

/* =========================
   INSTALL
========================= */
self.addEventListener("install", event => {
  event.waitUntil(
    caches.open(CACHE_NAME).then(async cache => {
      for (const url of APP_SHELL) {
        try {
          await cache.add(url);
        } catch (err) {
          console.log("SW cache add failed:", url, err);
        }
      }
    })
  );
  self.skipWaiting();
});

/* =========================
   ACTIVATE
========================= */
self.addEventListener("activate", event => {
  event.waitUntil(
    caches.keys().then(keys =>
      Promise.all(
        keys.map(key => {
          if (key !== CACHE_NAME) {
            return caches.delete(key);
          }
        })
      )
    )
  );
  self.clients.claim();
});

/* =========================
   HELPERS
========================= */
function isBypassRequest(req) {
  const url = new URL(req.url);

  if (req.method !== "GET") return true;
  if (req.headers.has("range")) return true;

  return (
    url.pathname.startsWith("/socket.io") ||
    url.pathname.startsWith("/api/") ||
    url.pathname.startsWith("/upload") ||
    url.pathname.startsWith("/uploads/") ||
    url.pathname.startsWith("/users-data") ||
    url.pathname.startsWith("/groups") ||
    url.pathname.startsWith("/group/") ||
    url.pathname.startsWith("/statuses") ||
    url.pathname.startsWith("/status-") ||
    url.pathname.startsWith("/search-messages") ||
    url.pathname.startsWith("/admin/") ||
    url.pathname.startsWith("/messages/") ||
    url.pathname.startsWith("/profile/") ||
    url.pathname.startsWith("/message-seen-info/")
  );
}

async function networkFirst(req, fallbackUrl = "/index.html") {
  try {
    const fresh = await fetch(req);
    if (fresh && fresh.status === 200) {
      const cache = await caches.open(CACHE_NAME);
      cache.put(req, fresh.clone());
    }
    return fresh;
  } catch (err) {
    const cached = await caches.match(req);
    if (cached) return cached;
    return caches.match(fallbackUrl);
  }
}

async function staleWhileRevalidate(req) {
  const cache = await caches.open(CACHE_NAME);
  const cached = await cache.match(req);

  const networkFetch = fetch(req)
    .then(res => {
      if (res && res.status === 200 && res.type === "basic") {
        cache.put(req, res.clone());
      }
      return res;
    })
    .catch(() => null);

  return cached || networkFetch || fetch(req);
}

/* =========================
   FETCH
========================= */
self.addEventListener("fetch", event => {
  const req = event.request;
  const accept = req.headers.get("accept") || "";

  if (isBypassRequest(req)) {
    return;
  }

  if (accept.includes("text/html")) {
    event.respondWith(networkFirst(req, "/index.html"));
    return;
  }

  event.respondWith(staleWhileRevalidate(req));
});

/* =========================
   PUSH
========================= */
self.addEventListener("push", event => {
  let data = {};

  try {
    data = event.data ? event.data.json() : {};
  } catch (err) {
    data = {
      title: "RickyY Chat",
      body: event.data ? event.data.text() : "New notification"
    };
  }

  const title = data.title || "RickyY Chat";
  const body = data.body || "You have a new message";
  const url = data.url || "/chat.html";
  const icon = data.icon || "/icons/icon-192.png";
  const badge = data.badge || "/icons/icon-192.png";

  event.waitUntil(
    self.registration.showNotification(title, {
      body,
      icon,
      badge,
      data: { url },
      tag: data.tag || "rickyy-chat-notification",
      renotify: true
    })
  );
});

/* =========================
   NOTIFICATION CLICK
========================= */
self.addEventListener("notificationclick", event => {
  event.notification.close();

  const targetUrl = event.notification?.data?.url || "/";

  event.waitUntil(
    clients.matchAll({ type: "window", includeUncontrolled: true }).then(clientList => {
      for (const client of clientList) {
        try {
          const clientUrl = new URL(client.url);

          if (clientUrl.origin === self.location.origin) {
            client.navigate(targetUrl);
            return client.focus();
          }
        } catch (err) {}
      }

      if (clients.openWindow) {
        return clients.openWindow(targetUrl);
      }
    })
  );
});

/* =========================
   NOTIFICATION CLOSE
========================= */
self.addEventListener("notificationclose", () => {
  // optional analytics / cleanup future use
});