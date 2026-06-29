const CACHE_NAME = "rickyy-chat-cache-v25-final-notification";

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

self.addEventListener("activate", event => {
  event.waitUntil(
    caches.keys().then(keys =>
      Promise.all(keys.map(key => key !== CACHE_NAME ? caches.delete(key) : null))
    )
  );
  self.clients.claim();
});

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
      await cache.put(req, fresh.clone());
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
    .then(async res => {
      if (res && res.status === 200 && res.type === "basic") {
        await cache.put(req, res.clone());
      }
      return res;
    })
    .catch(() => null);

  if (cached) return cached;
  return networkFetch || fetch(req);
}

function buildReplyUrl(data = {}) {
  if (data.replyUrl) return data.replyUrl;

  const groupId = String(data.group || data.groupId || "").trim();
  const from = String(data.from || "").trim();

  if (groupId) {
    return `/chat.html?group=${encodeURIComponent(groupId)}&quickReply=1`;
  }

  if (from) {
    return `/chat.html?user=${encodeURIComponent(from)}&quickReply=1`;
  }

  return data.url || "/chat.html";
}

async function openOrFocusUrl(targetUrl = "/chat.html", data = {}) {
  const finalUrl = new URL(targetUrl, self.location.origin).href;

  const clientList = await clients.matchAll({
    type: "window",
    includeUncontrolled: true
  });

  for (const client of clientList) {
    try {
      const clientUrl = new URL(client.url);

      if (clientUrl.origin === self.location.origin) {
        client.postMessage({
          type: "OPEN_CHAT_FROM_NOTIFICATION",
          url: finalUrl,
          from: data.from || "",
          user: data.from || "",
          group: data.group || data.groupId || "",
          groupId: data.group || data.groupId || "",
          replyMode: true,
          quickReply: true
        });

        if ("navigate" in client) {
          await client.navigate(finalUrl);
        }

        return client.focus();
      }
    } catch (err) {}
  }

  if (clients.openWindow) {
    return clients.openWindow(finalUrl);
  }

  return null;
}

self.addEventListener("fetch", event => {
  const req = event.request;
  const accept = req.headers.get("accept") || "";

  if (isBypassRequest(req)) return;

  if (accept.includes("text/html")) {
    event.respondWith(networkFirst(req, "/index.html"));
    return;
  }

  event.respondWith(staleWhileRevalidate(req));
});

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

  const isCall =
    data.notificationType === "call" ||
    data.type === "call" ||
    String(data.tag || "").includes("call") ||
    String(data.title || "").toLowerCase().includes("incoming");

  const title = data.title || (isCall ? "Incoming call" : "RickyY Chat");
  const body = data.body || (isCall ? "Someone is calling you" : "You have a new message");

  const actions = isCall
    ? [
        { action: "open", title: "Open" },
        { action: "dismiss", title: "Dismiss" }
      ]
    : [
        { action: "reply", title: "Reply", type: "text", placeholder: "Type a reply" },
        { action: "open", title: "Open" }
      ];

  const groupId = String(data.group || data.groupId || "").trim();
  const from = String(data.from || "").trim();
  const url = data.url || buildReplyUrl({ ...data, groupId, from });

  event.waitUntil(
    self.registration.showNotification(title, {
      body,
      icon: data.icon || "/icons/icon-192.png",
      badge: data.badge || "/icons/icon-192.png",
      tag: data.tag || (isCall ? "rickyy-call" : "rickyy-chat-" + (groupId || from || "message")),
      renotify: true,
      requireInteraction: !!isCall || !!data.requireInteraction,
      vibrate: isCall ? [300, 120, 300, 120, 600] : [180, 80, 180],
      actions,
      data: {
        ...data,
        isCall,
        url,
        from,
        group: groupId,
        groupId,
        messageId: data.messageId || "",
        replyToken: data.replyToken || "",
        replyUrl: data.replyUrl || ""
      }
    })
  );
});

self.addEventListener("notificationclick", event => {
  const data = event.notification.data || {};
  const action = event.action || "open";
  const replyText = String(event.reply || "").trim();

  event.notification.close();

  if (action === "dismiss") return;

  async function sendInlineReply() {
    if (!replyText) {
      return openOrFocusUrl(data.replyUrl || data.url || buildReplyUrl(data), data);
    }

    const replyToken = String(data.replyToken || "").trim();

    if (!replyToken) {
      return openOrFocusUrl(data.replyUrl || data.url || buildReplyUrl(data), data);
    }

    try {
      const res = await fetch("/api/notification-reply", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Authorization": "Bearer " + replyToken
        },
        body: JSON.stringify({
          to: data.from || data.to || "",
          group: data.group || data.groupId || "",
          text: replyText
        })
      });

      if (!res.ok) {
        return openOrFocusUrl(data.replyUrl || data.url || buildReplyUrl(data), data);
      }

      return self.registration.showNotification("Reply sent", {
        body: replyText,
        icon: "/icons/icon-192.png",
        badge: "/icons/icon-192.png",
        tag: "rickyy-chat-reply-sent",
        silent: true,
        data: {
          url: data.url || "/chat.html"
        }
      });
    } catch (err) {
      return self.registration.showNotification("Reply failed", {
        body: "Open RickyY Chat and try again.",
        icon: "/icons/icon-192.png",
        badge: "/icons/icon-192.png",
        tag: "rickyy-chat-reply-failed",
        data: {
          url: data.url || "/chat.html"
        }
      });
    }
  }

  if (action === "reply") {
    event.waitUntil(sendInlineReply());
    return;
  }

  event.waitUntil(openOrFocusUrl(data.replyUrl || data.url || buildReplyUrl(data), data));
});

self.addEventListener("notificationclose", () => {});

self.addEventListener("message", event => {
  if (event.data && event.data.type === "SKIP_WAITING") {
    self.skipWaiting();
  }
});

self.addEventListener("error", event => {
  console.log("SW ERROR:", event.message);
});

self.addEventListener("unhandledrejection", event => {
  console.log("SW PROMISE ERROR:", event.reason);
});