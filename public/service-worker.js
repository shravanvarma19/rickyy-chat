const CACHE_NAME = "rickyy-chat-cache-v21";

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
          return null;
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

async function openOrFocusUrl(targetUrl = "/") {
  const clientList = await clients.matchAll({
    type: "window",
    includeUncontrolled: true
  });

  for (const client of clientList) {
    try {
      const clientUrl = new URL(client.url);
      if (clientUrl.origin === self.location.origin) {
        await client.navigate(targetUrl);
        return client.focus();
      }
    } catch (err) {}
  }

  if (clients.openWindow) {
    return clients.openWindow(targetUrl);
  }
  return null;
}

function buildReplyUrl(data = {}) {
  if (data.replyUrl) return data.replyUrl;

  if (data.groupId) {
    return `/chat.html?group=${encodeURIComponent(String(data.groupId))}&quickReply=1`;
  }

  if (data.from) {
    return `/chat.html?user=${encodeURIComponent(String(data.from))}&quickReply=1`;
  }

  return data.url || "/chat.html";
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

  const groupId = String(data.group || data.groupId || "").trim();
  const from = String(data.from || "").trim();

  const title = data.title || "RickyY Chat";
  const body = data.body || "You have a new message";
  const url = data.url || buildReplyUrl({ from, groupId });
  const icon = data.icon || "/icons/icon-192.png";
  const badge = data.badge || "/icons/icon-192.png";

  const actions = [
    {
      action: "reply",
      type: "text",
      title: "Reply",
      placeholder: "Type a message"
    },
    {
      action: "open",
      title: "Open"
    }
  ];

  event.waitUntil(
    self.registration.showNotification(title, {
      body,
      icon,
      badge,
      actions,
      data: {
        url,
        from,
        group: groupId,
        groupId,
        messageId: data.messageId || "",
        replyToken: data.replyToken || "",
        replyUrl: data.replyUrl || "",
        notificationType: data.notificationType || "message"
      },
      tag: data.tag || ("rickyy-chat-" + (groupId || from || "message")),
      renotify: true,
      requireInteraction: !!data.requireInteraction
    })
  );
});

/* =========================
   NOTIFICATION CLICK
========================= */
self.addEventListener("notificationclick", (event) => {
  event.notification.close();

  const data = event.notification.data || {};
  const action = event.action || "";
  const replyText = String(event.reply || "").trim();

  async function openChat() {
    const url = data.replyUrl || data.url || buildReplyUrl(data);

    const allClients = await clients.matchAll({
      type: "window",
      includeUncontrolled: true
    });

    for (const client of allClients) {
      try {
        const clientUrl = new URL(client.url);
        if (clientUrl.origin === self.location.origin) {
          client.postMessage({
            type: "OPEN_CHAT_FROM_NOTIFICATION",
            url,
            from: data.from || "",
            group: data.group || data.groupId || "",
            groupId: data.group || data.groupId || "",
            replyMode: true
          });

          if ("navigate" in client) {
            await client.navigate(url);
          }

          return client.focus();
        }
      } catch (err) {}
    }

    if (clients.openWindow) {
      return clients.openWindow(url);
    }

    return null;
  }

  async function sendInlineReply() {
    if (!replyText) {
      return openChat();
    }

    const replyToken = String(data.replyToken || "").trim();

    if (!replyToken) {
      return openChat();
    }

    const res = await fetch("/api/notification-reply", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Authorization": "Bearer " + replyToken
      },
      body: JSON.stringify({
        to: data.from || "",
        group: data.group || data.groupId || "",
        text: replyText
      })
    });

    if (!res.ok) {
      return openChat();
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
  }

  if (action === "reply") {
    event.waitUntil(sendInlineReply());
    return;
  }

  event.waitUntil(openChat());
});
/* =========================
   NOTIFICATION CLOSE
========================= */
self.addEventListener("notificationclose", () => {
  // optional analytics / cleanup future use
});


/* =========================
   RickyY Phase 1 Native/PWA Notifications
========================= */
self.addEventListener("push", event => {
  let data = {};
  try {
    data = event.data ? event.data.json() : {};
  } catch (err) {
    data = { title: "RickyY Chat", body: event.data ? event.data.text() : "New message" };
  }

  const isCall =
    data.notificationType === "call" ||
    data.type === "call" ||
    String(data.tag || "").includes("call") ||
    String(data.title || "").toLowerCase().includes("incoming");

  const title = data.title || (isCall ? "Incoming call" : "RickyY Chat");
  const body = data.body || (isCall ? "Someone is calling you" : "New message");

  const actions = isCall
    ? [
        { action: "open", title: "Open" },
        { action: "dismiss", title: "Dismiss" }
      ]
    : (data.canReply
        ? [
            { action: "reply", title: "Reply", type: "text", placeholder: "Type a reply" },
            { action: "open", title: "Open" }
          ]
        : [{ action: "open", title: "Open" }]);

  const options = {
    body,
    icon: data.icon || "/icons/icon-192.png",
    badge: data.badge || "/icons/icon-192.png",
    tag: data.tag || (isCall ? "rickyy-call" : "rickyy-message"),
    renotify: true,
    requireInteraction: !!isCall || !!data.requireInteraction,
    vibrate: isCall ? [300, 120, 300, 120, 600] : [180, 80, 180],
    data: {
      ...data,
      isCall,
      url: data.url || "/chat.html",
      replyToken: data.replyToken || ""
    },
    actions
  };

  event.waitUntil(self.registration.showNotification(title, options));
});

self.addEventListener("notificationclick", event => {
  const data = event.notification.data || {};
  const action = event.action || "open";

  if (action === "dismiss") {
    event.notification.close();
    return;
  }

  if (action === "reply") {
    event.notification.close();

    const replyText =
      event.reply ||
      event.notification?.data?.reply ||
      "";

    if (replyText && data.replyToken) {
      const payload = {
        text: replyText,
        to: data.to || "",
        group: data.group || ""
      };

      event.waitUntil(
        fetch("/api/notification-reply", {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            "Authorization": "Bearer " + data.replyToken
          },
          body: JSON.stringify(payload)
        }).then(() => self.registration.showNotification("Reply sent", {
          body: replyText,
          icon: "/icons/icon-192.png",
          badge: "/icons/icon-192.png",
          tag: "reply-sent"
        })).catch(() => self.registration.showNotification("Reply failed", {
          body: "Open RickyY Chat and try again.",
          icon: "/icons/icon-192.png",
          badge: "/icons/icon-192.png",
          tag: "reply-failed"
        }))
      );
      return;
    }
  }

  event.notification.close();

  const targetUrl = new URL(data.url || "/chat.html", self.location.origin).href;

  event.waitUntil(
    clients.matchAll({ type: "window", includeUncontrolled: true }).then(clientList => {
      for (const client of clientList) {
        if ("focus" in client) {
          client.navigate(targetUrl);
          return client.focus();
        }
      }
      return clients.openWindow(targetUrl);
    })
  );
});

self.addEventListener("message", event => {
  if (event.data && event.data.type === "SKIP_WAITING") {
    self.skipWaiting();
  }
});
