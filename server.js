require("dotenv").config();

const fs = require("fs");
const bcrypt = require("bcryptjs");
const multer = require("multer");
const path = require("path");
const express = require("express");
const http = require("http");
const cors = require("cors");
const { Server } = require("socket.io");
const mongoose = require("mongoose");
const crypto = require("crypto");
const webpush = require("web-push");
const adminSdk = require("firebase-admin");
const {
  verifyRegistrationResponse,
  verifyAuthenticationResponse,
} = require("@simplewebauthn/server");

const ADMIN_NAME = "shravan";
const MAX_FILE_SIZE = 15 * 1024 * 1024;


const app = express();
const server = http.createServer(app);

app.use(cors({
  origin: true,
  methods: ["GET", "POST", "OPTIONS"],
  credentials: false
}));

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static("public"));
app.use("/uploads", express.static(path.join(__dirname, "public", "uploads")));
app.use(express.static(path.join(__dirname, "public")));

const loginOtpStore = new Map();

function generateOtp(){
  return String(Math.floor(100000 + Math.random() * 900000));
}

function otpKey(name){
  return String(name || "").trim().toLowerCase();
}
const uploadDir = path.join(__dirname, "public", "uploads");
if (!fs.existsSync(uploadDir)) {
  fs.mkdirSync(uploadDir, { recursive: true });
}


if (!process.env.MONGODB_URI) {
  console.log("MongoDB Error: MONGODB_URI is missing in .env file");
} else {
  mongoose.connect(process.env.MONGODB_URI, {
    serverSelectionTimeoutMS: 30000
  })
    .then(() => console.log("MongoDB Connected"))
    .catch(err => console.log("MongoDB Error:", err));
}
if (
  process.env.VAPID_PUBLIC_KEY &&
  process.env.VAPID_PRIVATE_KEY &&
  process.env.VAPID_SUBJECT
) {
  webpush.setVapidDetails(
    process.env.VAPID_SUBJECT,
    process.env.VAPID_PUBLIC_KEY,
    process.env.VAPID_PRIVATE_KEY
  );
} else {
  console.log("WEB PUSH WARNING: VAPID keys missing");
}


/* =========================
   FIREBASE ADMIN / NATIVE FCM
========================= */
let firebaseAdminReady = false;

try {
  const rawServiceAccount =
    process.env.FIREBASE_SERVICE_ACCOUNT_JSON ||
    process.env.FIREBASE_SERVICE_ACCOUNT ||
    "";

  const rawBase64 =
    process.env.FIREBASE_SERVICE_ACCOUNT_BASE64 ||
    "";

  let serviceAccount = null;

  if (rawServiceAccount) {
    serviceAccount = JSON.parse(rawServiceAccount);
  } else if (rawBase64) {
    serviceAccount = JSON.parse(Buffer.from(rawBase64, "base64").toString("utf8"));
  }

  if (serviceAccount) {
    if (serviceAccount.private_key) {
      serviceAccount.private_key = String(serviceAccount.private_key).replace(/\\n/g, "\n");
    }

    if (!adminSdk.apps.length) {
      adminSdk.initializeApp({
        credential: adminSdk.credential.cert(serviceAccount)
      });
    }

    firebaseAdminReady = true;
    console.log("Firebase Admin Connected");
  } else {
    console.log("FCM WARNING: FIREBASE_SERVICE_ACCOUNT_JSON missing");
  }
} catch (err) {
  console.log("FCM INIT ERROR:", err.message);
}

function formatTime(date = new Date()) {
  let hours = date.getHours();
  const minutes = String(date.getMinutes()).padStart(2, "0");
  const ampm = hours >= 12 ? "PM" : "AM";
  hours = hours % 12;
  hours = hours === 0 ? 12 : hours;
  return `${String(hours).padStart(2, "0")}:${minutes} ${ampm}`;
}

function generateAuthToken() {
  return crypto.randomBytes(32).toString("hex");
}

function generateSessionId() {
  return crypto.randomBytes(16).toString("hex");
}

function tokenPreview(token = "") {
  const value = String(token || "");
  if (!value) return "";
  return value.slice(0, 10) + "..." + value.slice(-6);
}

function detectBrowser(userAgent = "") {
  const ua = String(userAgent || "");
  if (/Edg\//i.test(ua)) return "Microsoft Edge";
  if (/OPR\//i.test(ua) || /Opera/i.test(ua)) return "Opera";
  if (/CriOS/i.test(ua)) return "Chrome iOS";
  if (/Chrome\//i.test(ua)) return "Chrome";
  if (/Firefox\//i.test(ua)) return "Firefox";
  if (/Safari\//i.test(ua) && !/Chrome\//i.test(ua)) return "Safari";
  return "Browser";
}

function detectOS(userAgent = "") {
  const ua = String(userAgent || "");
  if (/Android/i.test(ua)) return "Android";
  if (/iPhone|iPad|iPod/i.test(ua)) return "iOS";
  if (/Windows/i.test(ua)) return "Windows";
  if (/Mac OS X/i.test(ua)) return "macOS";
  if (/Linux/i.test(ua)) return "Linux";
  return "Unknown OS";
}

function buildDeviceName(userAgent = "") {
  const browser = detectBrowser(userAgent);
  const os = detectOS(userAgent);
  return `${browser} on ${os}`;
}

function getRequestIp(req) {
  return (
    req.headers["x-forwarded-for"]?.split(",")[0]?.trim() ||
    req.headers["x-real-ip"] ||
    req.socket?.remoteAddress ||
    "unknown"
  );
}

function createSessionRecord(req, token) {
  const ua = String(req.headers["user-agent"] || "").slice(0, 500);
  const now = new Date();

  return {
    sessionId: generateSessionId(),
    tokenPreview: tokenPreview(token),
    deviceName: buildDeviceName(ua),
    browserName: detectBrowser(ua),
    osName: detectOS(ua),
    ip: getRequestIp(req),
    userAgent: ua,
    loginAt: now,
    lastActiveAt: now,
    loggedOutAt: null,
    forceLoggedOut: false,
    active: true
  };
}

function attachNewSession(user, req, token) {
  const session = createSessionRecord(req, token);
  const sessions = Array.isArray(user.activeSessions) ? user.activeSessions : [];

  const cleaned = sessions
    .map(s => {
      if (s && s.active !== false) {
        s.active = false;
        s.loggedOutAt = s.loggedOutAt || new Date();
      }
      return s;
    })
    .slice(-12);

  cleaned.push(session);
  user.activeSessions = cleaned;
  return session;
}

async function touchSessionByToken(token) {
  const preview = tokenPreview(token);
  if (!preview) return;

  await User.updateOne(
    { authToken: token, "activeSessions.tokenPreview": preview },
    {
      $set: {
        "activeSessions.$.lastActiveAt": new Date(),
        "activeSessions.$.active": true
      }
    }
  ).catch(() => {});
}

function serializeSessionsForUser(user) {
  const sessions = Array.isArray(user.activeSessions) ? user.activeSessions : [];
  const currentPreview = tokenPreview(user.authToken || "");
  return sessions
    .slice()
    .sort((a, b) => new Date(b.lastActiveAt || b.loginAt || 0) - new Date(a.lastActiveAt || a.loginAt || 0))
    .map(s => {
      const isCurrent = !!currentPreview && s.tokenPreview === currentPreview;
      const active = !!isCurrent && s.active !== false && !s.forceLoggedOut;
      return {
        sessionId: s.sessionId || "",
        deviceName: s.deviceName || buildDeviceName(s.userAgent || ""),
        browserName: s.browserName || "",
        osName: s.osName || "",
        ip: s.ip || "",
        loginAt: s.loginAt || null,
        lastActiveAt: s.lastActiveAt || null,
        loggedOutAt: s.loggedOutAt || null,
        forceLoggedOut: !!s.forceLoggedOut,
        active,
        current: isCurrent
      };
    });
}

function forceLogoutSockets(username, msg = "You have been logged out by admin.") {
  if (!username) return;
  io.to(username).emit("force-logout", {
    msg,
    reason: "admin_force_logout",
    at: new Date()
  });
}
function getExpectedOrigin(req) {
  const proto = req.headers["x-forwarded-proto"] || req.protocol || "http";
  return `${proto}://${req.get("host")}`;
}

function getExpectedRPID(req) {
  return req.hostname;
}
function isValidUsername(name) {
  return typeof name === "string" && /^[a-zA-Z0-9_ ]{3,20}$/.test(name.trim());
}

function normalizeUsername(name) {
  return String(name || "").trim();
}

function isValidPin(pin) {
  return /^\d{4}$/.test(String(pin || ""));
}
function isValidContact(contact) {
  return /^\d{10}$/.test(String(contact || "").trim());
}

function isValidPassword(password) {
  return typeof password === "string" && password.trim().length >= 4;
}

function generateOtp() {
  return Math.floor(1000 + Math.random() * 9000).toString();
}

function generateCaptchaValue() {
  return crypto.randomBytes(3).toString("hex").toUpperCase();
}
function isImageFile(file) {
  return file && file.mimetype && file.mimetype.startsWith("image/");
}


const userSchema = new mongoose.Schema({
  name: { type: String, unique: true },
  contact: { type: String, default: "", unique: true, sparse: true },
  password: { type: String, default: "" },
  pin: { type: String, default: "" },

  online: { type: Boolean, default: false },
  lastSeen: { type: Date, default: null },
  dp: { type: String, default: "/default.png" },
  coverImage: { type: String, default: "" },
  role: { type: String, default: "user" },
  approvalStatus: { type: String, default: "pending" },
  blocked: { type: Boolean, default: false },
  muted: { type: Boolean, default: false },
  bio: { type: String, default: "" },
  about: { type: String, default: "" },
  loginAttempts: { type: Number, default: 0 },
  lockUntil: { type: Date, default: null },
  authToken: { type: String, default: null },
  activeSessions: {
    type: [{
      sessionId: { type: String, default: "" },
      tokenPreview: { type: String, default: "" },
      deviceName: { type: String, default: "" },
      browserName: { type: String, default: "" },
      osName: { type: String, default: "" },
      ip: { type: String, default: "" },
      userAgent: { type: String, default: "" },
      loginAt: { type: Date, default: Date.now },
      lastActiveAt: { type: Date, default: Date.now },
      loggedOutAt: { type: Date, default: null },
      forceLoggedOut: { type: Boolean, default: false },
      active: { type: Boolean, default: true }
    }],
    default: []
  },
  pushSubscriptions: { type: [Object], default: [] },
  fcmTokens: { type: [Object], default: [] },
  rejectCooldownUntil: { type: Date, default: null },
  lastRejectedAt: { type: Date, default: null },

  otp: { type: String, default: "" },
  otpExpiresAt: { type: Date, default: null },
  resetOtp: { type: String, default: "" },
  resetOtpExpiresAt: { type: Date, default: null },

  passkeys: {
    type: [{
      credentialID: String,
      publicKey: String,
      counter: { type: Number, default: 0 },
      transports: { type: [String], default: [] },
      backedUp: { type: Boolean, default: false }
    }],
    default: []
  },

  webauthnChallenge: { type: String, default: "" },

  notifications: {
    type: [{
      text: { type: String, default: "" },
      read: { type: Boolean, default: false },
      createdAt: { type: Date, default: Date.now }
    }],
    default: []
  }
});


const groupSchema = new mongoose.Schema({
  name: String,
  description: { type: String, default: "" },
  dp: { type: String, default: "/default-group.png" },
  admin: String,
  admins: { type: [String], default: [] },
  members: [String],
  inviteCode: { type: String, default: "" },
  createdAt: { type: Date, default: Date.now }
});

const messageSchema = new mongoose.Schema({
  from: String,
  to: String,
  group: String,
  text: String,
  file: String,
  fileType: String,
  replyTo: {
    messageId: String,
    from: String,
    text: String,
    file: String,
    fileType: String,
    replyTo: Object
  },
  mentions: { type: [String], default: [] },
  time: String,
  status: String,
  reaction: String,
  seenBy: [String],
  deliveredTo: [String],

  edited: { type: Boolean, default: false },
  editedAt: { type: Date, default: null },
  deleted: { type: Boolean, default: false },
  deletedAt: { type: Date, default: null },
  deletedBy: { type: String, default: null },

  createdAt: { type: Date, default: Date.now }
});

const callSchema = new mongoose.Schema({
  from: String,
  to: String,
  type: String,
  status: String,
  time: String
});

const statusSchema = new mongoose.Schema({
  user: String,
  file: String,
  fileType: String,
  viewers: [String],
  reactions: [{ user: String, emoji: String }],
  createdAt: { type: Date, default: Date.now },
  expiresAt: { type: Date, default: () => new Date(Date.now() + 24 * 60 * 60 * 1000) }
});

statusSchema.index({ expiresAt: 1 }, { expireAfterSeconds: 0 });

const User = mongoose.model("User", userSchema);
const Group = mongoose.model("Group", groupSchema);
const Message = mongoose.model("Message", messageSchema);
const Call = mongoose.model("Call", callSchema);
const Status = mongoose.model("Status", statusSchema);

const pollSchema = new mongoose.Schema({
  groupId: String,
  question: String,
  options: [{
    text: String,
    votes: [String]
  }],
  createdBy: String,
  createdAt: { type: Date, default: Date.now }
});

const Poll = mongoose.model("Poll", pollSchema);

const activityLogSchema = new mongoose.Schema({
  type: { type: String, default: "" },
  actor: { type: String, default: "" },
  target: { type: String, default: "" },
  text: { type: String, default: "" },
  meta: { type: Object, default: {} },
  createdAt: { type: Date, default: Date.now }
});

const reportSchema = new mongoose.Schema({
  reporter: { type: String, default: "" },
  reportedUser: { type: String, default: "" },
  messageId: { type: String, default: "" },
  messageText: { type: String, default: "" },
  reason: { type: String, default: "" },
  chatType: { type: String, default: "" },
  groupId: { type: String, default: "" },
  peer: { type: String, default: "" },
  status: { type: String, default: "open" },
  actionBy: { type: String, default: "" },
  actionNote: { type: String, default: "" },
  createdAt: { type: Date, default: Date.now },
  actionAt: { type: Date, default: null }
});

const ActivityLog = mongoose.models.ActivityLog || mongoose.model("ActivityLog", activityLogSchema);
const Report = mongoose.models.Report || mongoose.model("Report", reportSchema);

async function logActivity(type, actor, target, text = "", meta = {}) {
  try {
    await ActivityLog.create({
      type: String(type || ""),
      actor: String(actor || ""),
      target: String(target || ""),
      text: String(text || "").slice(0, 500),
      meta: meta || {}
    });
  } catch (err) {
    console.log("ACTIVITY LOG ERROR:", err.message);
  }
}

app.post("/group/:id/polls", async (req, res) => {
  try {
    const groupId = req.params.id;
    const { createdBy, question, options } = req.body;

    const group = await Group.findById(groupId);
    if (!group) return res.status(404).json({ ok: false, msg: "Group not found" });
    if (!(group.members || []).includes(createdBy)) {
      return res.status(403).json({ ok: false, msg: "Only group members can create poll" });
    }

    const cleanQuestion = sanitizeText(question || "", 140);
    const cleanOptions = (Array.isArray(options) ? options : [])
      .map(o => sanitizeText(o, 60))
      .filter(Boolean)
      .slice(0, 6);

    if (!cleanQuestion || cleanOptions.length < 2) {
      return res.status(400).json({ ok: false, msg: "Question and at least 2 options required" });
    }

    const poll = await Poll.create({
      groupId: String(groupId),
      question: cleanQuestion,
      options: cleanOptions.map(text => ({ text, votes: [] })),
      createdBy
    });

    io.to(roomNameForGroup(groupId)).emit("group-poll-created", poll);
    return res.json({ ok: true, poll });
  } catch (err) {
    console.log("CREATE POLL ERROR:", err);
    return res.status(500).json({ ok: false, msg: "Create poll failed" });
  }
});

app.get("/group/:id/polls", async (req, res) => {
  try {
    const list = await Poll.find({ groupId: String(req.params.id) }).sort({ createdAt: -1 });
    return res.json({ ok: true, polls: list });
  } catch (err) {
    console.log("GET POLLS ERROR:", err);
    return res.status(500).json({ ok: false, polls: [] });
  }
});

app.post("/poll/:id/vote", async (req, res) => {
  try {
    const { user, optionIndex } = req.body;
    const poll = await Poll.findById(req.params.id);
    if (!poll) return res.status(404).json({ ok: false, msg: "Poll not found" });

    poll.options.forEach(opt => {
      opt.votes = (opt.votes || []).filter(v => v !== user);
    });

    if (poll.options[optionIndex]) {
      poll.options[optionIndex].votes.push(user);
    }

    await poll.save();

    io.to(roomNameForGroup(poll.groupId)).emit("group-poll-updated", poll);
    return res.json({ ok: true, poll });
  } catch (err) {
    console.log("VOTE POLL ERROR:", err);
    return res.status(500).json({ ok: false, msg: "Vote failed" });
  }
});
app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

app.get("/debug-files", (req, res) => {
  fs.readdir(uploadDir, (err, files) => {
    if (err) return res.status(500).json({ ok: false, error: err.message });
    res.json({ ok: true, files });
  });
});


const io = new Server(server, {
  cors: {
    origin: true,
    methods: ["GET", "POST", "OPTIONS"],
    credentials: false
  }
});


const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, uploadDir),
  filename: (req, file, cb) => {
    const safeExt = path.extname(file.originalname || "").toLowerCase();
    const unique = `${Date.now()}-${crypto.randomBytes(6).toString("hex")}${safeExt}`;
    cb(null, unique);
  }
});

const fileFilter = (req, file, cb) => {
  const ext = path.extname(file.originalname || "").toLowerCase();

  const imageExts = [".jpg", ".jpeg", ".png", ".webp", ".gif"];
  const videoExts = [".mp4", ".webm", ".mov"];
  const audioExts = [".mp3", ".wav", ".ogg", ".webm"];
  const docExts = [".pdf", ".doc", ".docx", ".ppt", ".pptx", ".xls", ".xlsx", ".txt", ".zip", ".rar"];

  const mime = file.mimetype || "";

  const isImage = mime.startsWith("image/") && imageExts.includes(ext);
  const isVideo = mime.startsWith("video/") && videoExts.includes(ext);
  const isAudio = mime.startsWith("audio/") && audioExts.includes(ext);

  const docMimeAllowed = [
    "application/pdf",
    "application/msword",
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    "application/vnd.ms-powerpoint",
    "application/vnd.openxmlformats-officedocument.presentationml.presentation",
    "application/vnd.ms-excel",
    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    "application/zip",
    "application/x-rar-compressed",
    "text/plain"
  ];

  const isDoc = docExts.includes(ext) && docMimeAllowed.includes(mime);

  if (isImage || isVideo || isAudio || isDoc) {
    return cb(null, true);
  }

  return cb(new Error("Unsupported or mismatched file type"));
};

const upload = multer({
  storage,
  limits: { fileSize: MAX_FILE_SIZE },
  fileFilter
});


async function getUsers() {
  return await User.find({
    blocked: { $ne: true },
    approvalStatus: "approved"
  });
}
function isStrongPassword(password) {
  const value = String(password || "").trim();

  return /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[^A-Za-z\d]).{8,}$/.test(value);
}
async function findUserByNameOrContact(identifier) {
  const value = String(identifier || "").trim();

  if (!value) return null;

  return await User.findOne({
    $or: [
      { name: normalizeUsername(value) },
      { contact: value }
    ]
  });
}

async function isRealAdmin(username) {
  if (!username) return false;

  const user = await User.findOne({ name: username }).select("name role approvalStatus blocked");
  if (!user) return false;

  return (
    user.name === ADMIN_NAME &&
    user.role === "admin" &&
    user.approvalStatus === "approved" &&
    !user.blocked
  );
}
async function isUserOnline(username) {
  return !!(userSocketIds[username] && userSocketIds[username].size > 0);
}
async function setAdminPasswordOnce() {
  try {
    const hashedPassword = await bcrypt.hash("1234", 10); // ikkad new password pettu

    const result = await User.updateOne(
      { name: "shravan" },
      {
        $set: {
          password: hashedPassword,
          role: "admin",
          approvalStatus: "approved"
        }
      }
    );

    console.log("Admin password updated:", result);
  } catch (err) {
    console.log("ADMIN PASSWORD UPDATE ERROR:", err);
  }
}
async function calculateUnread(username) {
  const msgs = await Message.find({
    to: username,
    status: { $ne: "seen" }
  });

  const counts = {};
  msgs.forEach(m => {
    if (!counts[m.from]) counts[m.from] = 0;
    counts[m.from]++;
  });

  return counts;
}

async function calculateGroupUnread(username) {
  const groups = await Group.find({ members: username }).select("_id");
  const counts = {};

  for (const g of groups) {
    const c = await Message.countDocuments({
      group: String(g._id),
      from: { $ne: username },
      seenBy: { $ne: username }
    });
    if (c > 0) counts[String(g._id)] = c;
  }

  return counts;
}

async function pushCallMessage(from, to, text) {
  const msg = new Message({
    from,
    to,
    text,
    file: null,
    fileType: null,
    status: "sent",
    reaction: null,
    seenBy: [],
    deliveredTo: [],
    createdAt: new Date()
  });

  await msg.save();
  io.to(from).emit("private-message", msg);
  io.to(to).emit("private-message", msg);
}

async function emitUsersToAll() {
  const allUsers = await getUsers();
  io.emit("users", allUsers);
}

const presenceOfflineTimers = new Map();
const presenceHttpPings = new Map();
const PRESENCE_OFFLINE_GRACE_MS = 12000;
const PRESENCE_HTTP_STALE_MS = 35000;

function hasActiveSocketForUser(username) {
  return !!(username && userSocketIds[username] && userSocketIds[username].size > 0);
}

function cancelPresenceOfflineTimer(username) {
  if (!username) return;
  const oldTimer = presenceOfflineTimers.get(username);
  if (oldTimer) clearTimeout(oldTimer);
  presenceOfflineTimers.delete(username);
}

function hasFreshProfilePresence(username) {
  const lastPing = Number(presenceHttpPings.get(username) || 0);
  return !!lastPing && (Date.now() - lastPing) < PRESENCE_HTTP_STALE_MS;
}

function schedulePresenceOffline(username) {
  if (!username) return;

  cancelPresenceOfflineTimer(username);

  const timer = setTimeout(async () => {
    try {
      if (hasActiveSocketForUser(username) || hasFreshProfilePresence(username)) {
        return;
      }

      await User.findOneAndUpdate(
        { name: username },
        { online: false, lastSeen: new Date() }
      );

      await emitUsersToAll();
    } catch (err) {
      console.log("PRESENCE OFFLINE TIMER ERROR:", err);
    } finally {
      presenceOfflineTimers.delete(username);
    }
  }, PRESENCE_OFFLINE_GRACE_MS);

  presenceOfflineTimers.set(username, timer);
}

async function emitGroupUnreadForUser(username) {
  const counts = await calculateGroupUnread(username);
  io.to(username).emit("group-unread-counts", counts);
}

async function emitGroupUnreadForMembers(groupId) {
  const group = await Group.findById(groupId);
  if (!group) return;

  for (const member of group.members) {
    await emitGroupUnreadForUser(member);
  }
}

function generateInviteCode(length = 10) {
  const chars = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789";
  let out = "";
  for (let i = 0; i < length; i++) {
    out += chars.charAt(Math.floor(Math.random() * chars.length));
  }
  return out;
}
function formatMessageTime(dateString){
  if(!dateString) return "";

  const d = new Date(dateString);
  if(isNaN(d.getTime())) return "";

  return d.toLocaleTimeString([], {
    hour: "2-digit",
    minute: "2-digit",
    hour12: true
  });
}

function roomNameForGroup(groupId) {
  return "group_" + String(groupId);
}

function roomNameForGroupCall(groupId) {
  return "group_call_" + String(groupId);
}

function sendUploadError(res, err) {
  if (err instanceof multer.MulterError) {
    return res.status(400).json({ status: "error", msg: err.message });
  }
  return res.status(400).json({ status: "error", msg: err.message || "Upload failed" });
}
function getAbsoluteUploadPath(filePath = "") {
  const clean = String(filePath || "").replace(/^\/+uploads\/+/i, "").trim();
  return path.join(uploadDir, clean);
}

function publicUploadFileExists(filePath = "") {
  try {
    const abs = getAbsoluteUploadPath(filePath);
    return fs.existsSync(abs);
  } catch (err) {
    return false;
  }
}

function removeUploadFileIfExists(filePath = "") {
  try {
    const abs = getAbsoluteUploadPath(filePath);
    if (fs.existsSync(abs)) {
      fs.unlinkSync(abs);
    }
  } catch (err) {
    console.log("REMOVE FILE ERROR:", err.message);
  }
}
function getClientIp(req) {
  return (
    req.headers["x-forwarded-for"]?.split(",")[0]?.trim() ||
    req.socket?.remoteAddress ||
    "unknown"
  );
}

function isLockedUser(user) {
  return !!(user && user.lockUntil && new Date(user.lockUntil) > new Date());
}

function minutesRemaining(lockUntil) {
  const diff = new Date(lockUntil).getTime() - Date.now();
  return Math.max(1, Math.ceil(diff / 60000));
}

function sanitizeText(input, maxLen = 1000) {
  return String(input || "").replace(/\s+/g, " ").trim().slice(0, maxLen);
}

function isAllowedExt(filename, allowedExts = []) {
  const ext = path.extname(filename || "").toLowerCase();
  return allowedExts.includes(ext);
}
function safeNotificationBody(msg) {
  if (msg?.text) return String(msg.text).slice(0, 120);
  if (msg?.fileType === "image") return "📷 Photo";
  if (msg?.fileType === "video") return "🎥 Video";
  if (msg?.fileType === "audio") return "🎤 Voice message";
  if (msg?.fileType === "doc" || msg?.fileType === "file") return "📄 Document";
  return "New message";
}

async function sendPushToUser(username, payload) {
  try {
    const user = await User.findOne({ name: username }).select("pushSubscriptions authToken name");
    if (!user || !Array.isArray(user.pushSubscriptions) || !user.pushSubscriptions.length) return;

    const validSubs = [];
    const finalPayload = {
      ...payload,
      receiver: username,
      replyToken: user.authToken || ""
    };

    for (const sub of user.pushSubscriptions) {
      try {
        await webpush.sendNotification(sub, JSON.stringify(finalPayload));
        validSubs.push(sub);
      } catch (err) {
        const status = err?.statusCode;

        if (status === 404 || status === 410) {
          console.log(`Removed invalid push subscription for ${username}`);
          continue;
        }

        console.log("PUSH SEND ERROR:", username, status || "", err?.message || err);
        validSubs.push(sub);
      }
    }

    await User.updateOne(
      { name: username },
      { $set: { pushSubscriptions: validSubs } }
    );
  } catch (err) {
    console.log("sendPushToUser ERROR:", err);
  }
}

async function sendFcmToUser(username, payload = {}) {
  const result = {
    ok: false,
    username,
    firebaseAdminReady,
    totalTokens: 0,
    successCount: 0,
    failureCount: 0,
    errors: []
  };

  try {
    if (!firebaseAdminReady) {
      result.errors.push("firebaseAdminReady=false");
      return result;
    }

    const user = await User.findOne({ name: username }).select("fcmTokens name");
    if (!user || !Array.isArray(user.fcmTokens) || !user.fcmTokens.length) {
      result.errors.push("no_fcm_tokens");
      return result;
    }

    const validTokens = [];
    const isCall =
      String(payload.notificationType || "").toLowerCase() === "call" ||
      String(payload.type || "").toLowerCase() === "call" ||
      String(payload.tag || "").toLowerCase().includes("call");

    const title = String(payload.title || (isCall ? "Incoming call" : "Shravan Chat"));
    const body = String(payload.body || (isCall ? "Someone is calling you" : "New message"));

    for (const item of user.fcmTokens) {
      const token = typeof item === "string" ? item : item?.token;
      if (!token) continue;

      result.totalTokens++;

      try {
        await adminSdk.messaging().send({
          token,

          // IMPORTANT: data-only payload.
          // This forces native FirebaseMessagingService to build the notification,
          // so actions like Reply and Mark as read appear from the APK, not Chrome.
          data: {
            title,
            body,
            sender: String(payload.from || payload.sender || ""),
            to: String(payload.to || ""),
            group: String(payload.group || payload.groupId || ""),
            url: String(payload.url || "/chat.html"),
            tag: String(payload.tag || (isCall ? "shravan-call" : "shravan-message")),
            type: String(payload.type || (isCall ? "call" : "message")),
            notificationType: String(payload.notificationType || (isCall ? "call" : "message")),
            canReply: String(payload.canReply !== false && !isCall),
            canMarkRead: String(payload.canMarkRead !== false && !isCall),
            requireInteraction: String(!!payload.requireInteraction || isCall),
            sound: String(payload.sound || (isCall ? "ring" : "default")),
            callType: String(payload.callType || ""),
            messageId: String(payload.messageId || payload._id || "")
          },

          android: {
            priority: "high",
            ttl: 60 * 60 * 1000,
            directBootOk: true
          }
        });

        result.successCount++;

        validTokens.push(
          typeof item === "string"
            ? { token, platform: "android-native", lastSeenAt: new Date() }
            : { ...item, lastSeenAt: new Date() }
        );
      } catch (err) {
        result.failureCount++;
        const code = String(err?.errorInfo?.code || err?.code || "");
        result.errors.push({ code, message: err.message });

        if (
          code.includes("registration-token-not-registered") ||
          code.includes("invalid-registration-token")
        ) {
          console.log("Removed invalid FCM token for", username, code);
          continue;
        }

        console.log("FCM SEND ERROR:", username, code, err.message);
        validTokens.push(item);
      }
    }

    await User.updateOne(
      { name: username },
      { $set: { fcmTokens: validTokens } }
    );

    result.ok = result.successCount > 0;
    return result;
  } catch (err) {
    result.errors.push({ code: "sendFcmToUser_exception", message: err.message });
    console.log("sendFcmToUser ERROR:", err);
    return result;
  }
}

async function sendAppNotification(username, payload = {}) {
  // Native app only. Do NOT send web push, so Chrome/PWA notifications stop.
  const fcmResult = await sendFcmToUser(username, payload);
  return { fcmResult };
}

async function requireAdmin(req, res, next) {
  try {
    const adminName =
      normalizeUsername(req.body?.admin) ||
      normalizeUsername(req.query?.admin) ||
      normalizeUsername(req.headers["x-admin-user"]);

    if (!adminName) {
      return res.status(403).json({ ok: false, msg: "Admin required" });
    }

    const adminUser = await User.findOne({ name: adminName });

    if (
      !adminUser ||
      adminUser.name !== ADMIN_NAME ||
      adminUser.role !== "admin" ||
      adminUser.approvalStatus !== "approved" ||
      adminUser.blocked
    ) {
      return res.status(403).json({ ok: false, msg: "Only admin allowed" });
    }

    req.adminUser = adminUser;
    next();
  } catch (err) {
    console.log("ADMIN MIDDLEWARE ERROR:", err);
    res.status(500).json({ ok: false, msg: "Admin verification failed" });
  }
}

function isGroupOwner(group, username) {
  return group && group.admin === username;
}


app.post("/upload-media", (req, res) => {
  upload.single("file")(req, res, err => {
    if (err) {
      console.log("UPLOAD ERROR:", err);
      return sendUploadError(res, err);
    }

    try {
      if (!req.file) {
        return res.status(400).json({ status: "no_file" });
      }

      const fullPath = path.join(uploadDir, req.file.filename);

      if (!fs.existsSync(fullPath)) {
        return res.status(500).json({
          status: "error",
          msg: "File not saved properly"
        });
      }

      return res.json({
        status: "ok",
        filePath: "/uploads/" + req.file.filename
      });
    } catch (e) {
      console.log("UPLOAD ROUTE ERROR:", e);
      return res.status(500).json({ status: "error", msg: "Upload failed" });
    }
  });
});
app.post("/chat/clear", async (req, res) => {
  try {
    const { type, me: user, peer, groupId } = req.body;

    if (type === "private") {
      await Message.deleteMany({
        $or: [
          { from: user, to: peer },
          { from: peer, to: user }
        ]
      });
      return res.json({ ok: true });
    }

    if (type === "group") {
      const group = await Group.findById(groupId);
      if (!group) return res.status(404).json({ ok: false, msg: "Group not found" });

      const isAdminUser = group.admin === user || (group.admins || []).includes(user);
      if (!isAdminUser) {
        return res.status(403).json({ ok: false, msg: "Only group admin can clear group chat" });
      }

      await Message.deleteMany({ group: String(groupId) });
      io.to(roomNameForGroup(groupId)).emit("group-chat-cleared", { groupId });
      return res.json({ ok: true });
    }

    return res.status(400).json({ ok: false, msg: "Invalid type" });
  } catch (err) {
    console.log("CLEAR CHAT ERROR:", err);
    return res.status(500).json({ ok: false, msg: "Clear chat failed" });
  }
});
app.post("/api/webauthn/register/options", async (req, res) => {
  try {
    const token = String(req.headers.authorization || "").replace("Bearer ", "").trim();
    const user = await User.findOne({ authToken: token });

    if (!user) {
      return res.status(401).json({ ok: false, msg: "Unauthorized" });
    }

    const challenge = crypto.randomBytes(32).toString("base64url");
    user.webauthnChallenge = challenge;
    await user.save();

    return res.json({
      ok: true,
      options: {
        challenge,
        rp: {
          name: "RickyY Chat",
          id: req.hostname
        },
        user: {
          id: Buffer.from(user.name).toString("base64url"),
          name: user.name,
          displayName: user.name
        },
        pubKeyCredParams: [
          { type: "public-key", alg: -7 },
          { type: "public-key", alg: -257 }
        ],
        authenticatorSelection: {
          userVerification: "preferred",
          residentKey: "preferred"
        },
        timeout: 60000,
        attestation: "none"
      }
    });
  } catch (err) {
    console.log("WEBAUTHN REGISTER OPTIONS ERROR:", err);
    return res.status(500).json({ ok: false, msg: "Server error" });
  }
});
app.post("/api/webauthn/auth/options", async (req, res) => {
  try {
    const token = String(req.headers.authorization || "").replace("Bearer ", "").trim();
    const user = await User.findOne({ authToken: token });

    if (!user) {
      return res.status(401).json({ ok: false, msg: "Unauthorized" });
    }

    const challenge = crypto.randomBytes(32).toString("base64url");
    user.webauthnChallenge = challenge;
    await user.save();

    return res.json({
      ok: true,
      options: {
        challenge,
        rpId: req.hostname,
        allowCredentials: (user.passkeys || []).map(p => ({
          id: p.credentialID,
          type: "public-key",
          transports: p.transports || []
        })),
        userVerification: "preferred",
        timeout: 60000
      }
    });
  } catch (err) {
    console.log("WEBAUTHN AUTH OPTIONS ERROR:", err);
    return res.status(500).json({ ok: false, msg: "Server error" });
  }
});
app.post("/api/webauthn/register/verify", async (req, res) => {
  try {
    const token = String(req.headers.authorization || "").replace("Bearer ", "").trim();
    const user = await User.findOne({ authToken: token });

    if (!user) {
      return res.status(401).json({ ok: false, msg: "Unauthorized" });
    }

    if (!user.webauthnChallenge) {
      return res.status(400).json({ ok: false, msg: "Missing registration challenge" });
    }

    let verification;
    try {
      verification = await verifyRegistrationResponse({
        response: req.body,
        expectedChallenge: user.webauthnChallenge,
        expectedOrigin: getExpectedOrigin(req),
        expectedRPID: getExpectedRPID(req),
        requireUserVerification: false,
      });
    } catch (err) {
      console.log("WEBAUTHN REGISTER VERIFY ERROR:", err);
      return res.status(400).json({ ok: false, msg: err.message || "Registration verification failed" });
    }

    const { verified, registrationInfo } = verification;

    if (!verified || !registrationInfo) {
      user.webauthnChallenge = "";
      await user.save();
      return res.status(400).json({ ok: false, msg: "Registration verification failed" });
    }

    const {
      credential,
      credentialBackedUp,
    } = registrationInfo;

    const alreadyExists = (user.passkeys || []).some(
      p => p.credentialID === credential.id
    );

    if (!alreadyExists) {
      user.passkeys.push({
        credentialID: credential.id,
        publicKey: Buffer.from(credential.publicKey).toString("base64"),
        counter: credential.counter,
        transports: credential.transports || [],
        backedUp: !!credentialBackedUp,
      });
    }

    user.webauthnChallenge = "";
    await user.save();

    return res.json({
      ok: true,
      verified: true,
      msg: "Fingerprint / Face ID enabled successfully",
    });
  } catch (err) {
    console.log("WEBAUTHN REGISTER VERIFY FATAL ERROR:", err);
    return res.status(500).json({ ok: false, msg: "Server error" });
  }
});
app.post("/api/webauthn/auth/verify", async (req, res) => {
  try {
    const token = String(req.headers.authorization || "").replace("Bearer ", "").trim();
    const user = await User.findOne({ authToken: token });

    if (!user) {
      return res.status(401).json({ ok: false, msg: "Unauthorized" });
    }

    if (!user.webauthnChallenge) {
      return res.status(400).json({ ok: false, msg: "Missing authentication challenge" });
    }

    const credentialID = String(req.body?.id || "");
    const passkey = (user.passkeys || []).find(p => p.credentialID === credentialID);

    if (!passkey) {
      user.webauthnChallenge = "";
      await user.save();
      return res.status(404).json({ ok: false, msg: "Passkey not found" });
    }

    let verification;
    try {
      verification = await verifyAuthenticationResponse({
        response: req.body,
        expectedChallenge: user.webauthnChallenge,
        expectedOrigin: getExpectedOrigin(req),
        expectedRPID: getExpectedRPID(req),
        credential: {
          id: passkey.credentialID,
          publicKey: Buffer.from(passkey.publicKey, "base64"),
          counter: Number(passkey.counter || 0),
          transports: passkey.transports || [],
        },
        requireUserVerification: false,
      });
    } catch (err) {
      console.log("WEBAUTHN AUTH VERIFY ERROR:", err);
      return res.status(400).json({ ok: false, msg: err.message || "Authentication verification failed" });
    }

    const { verified, authenticationInfo } = verification;

    if (!verified) {
      user.webauthnChallenge = "";
      await user.save();
      return res.status(400).json({ ok: false, msg: "Biometric unlock failed" });
    }

    passkey.counter = authenticationInfo.newCounter;
    user.webauthnChallenge = "";
    await user.save();

    return res.json({
      ok: true,
      verified: true,
      msg: "Biometric unlock successful",
    });
  } catch (err) {
    console.log("WEBAUTHN AUTH VERIFY FATAL ERROR:", err);
    return res.status(500).json({ ok: false, msg: "Server error" });
  }
});
app.get("/chat/export", async (req, res) => {
  try {
    const { type, me: user, peer, groupId } = req.query;
    let messages = [];

    if (type === "private") {
      messages = await Message.find({
        $or: [
          { from: user, to: peer },
          { from: peer, to: user }
        ]
      }).sort({ createdAt: 1 });
    } else if (type === "group") {
      messages = await Message.find({ group: String(groupId) }).sort({ createdAt: 1 });
    } else {
      return res.status(400).send("Invalid export type");
    }

    const lines = messages.map(m => {
      const when = formatMessageTime(m.createdAt || m.time);
      const who = m.from || "User";
      const text = m.text || (
        m.fileType === "image" ? "📷 Photo" :
        m.fileType === "video" ? "🎥 Video" :
        m.fileType === "audio" ? "🎤 Voice message" :
        m.fileType ? "📄 File" : ""
      );
      return `[${when}] ${who}: ${text}`;
    });

    res.setHeader("Content-Type", "text/plain; charset=utf-8");
    res.setHeader("Content-Disposition", `attachment; filename="chat-export-${Date.now()}.txt"`);
    return res.send(lines.join("\n"));
  } catch (err) {
    console.log("EXPORT CHAT ERROR:", err);
    return res.status(500).send("Export failed");
  }
});
app.post("/admin/cleanup-missing-message-files", async (req, res) => {
  try {
    const allMessages = await Message.find({
      file: { $exists: true, $ne: null, $ne: "" }
    });

    let fixed = 0;

    for (const msg of allMessages) {
      if (!publicUploadFileExists(msg.file)) {
        msg.file = "";
        msg.fileType = "";
        msg.text = msg.text || "Media not available";
        await msg.save();
        fixed++;
      }
    }

    return res.json({ ok: true, fixed });
  } catch (err) {
    console.log("CLEANUP MISSING MESSAGE FILES ERROR:", err);
    return res.status(500).json({ ok: false, fixed: 0 });
  }
});
app.get("/private-last-msg", async (req, res) => {
  try {
    const user = normalizeUsername(req.query.user);
    if (!isValidUsername(user)) return res.json([]);

    const peers = await Message.aggregate([
      {
        $match: {
          $or: [{ from: user }, { to: user }],
          group: { $in: [null, "", undefined] }
        }
      },
      { $sort: { createdAt: -1 } },
      {
        $addFields: {
          peer: { $cond: [{ $eq: ["$from", user] }, "$to", "$from"] }
        }
      },
      {
        $group: {
          _id: "$peer",
          peer: { $first: "$peer" },
          from: { $first: "$from" },
          text: { $first: "$text" },
          fileType: { $first: "$fileType" },
          createdAt: { $first: "$createdAt" }
        }
      },
      { $sort: { createdAt: -1 } }
    ]);

    res.json(peers);
  } catch (err) {
    console.log("PRIVATE LAST MSG ERROR:", err);
    res.json([]);
  }
});
app.post("/admin/cleanup-missing-status-files", async (req, res) => {
  try {
    const allStatuses = await Status.find({});
    let removed = 0;

    for (const st of allStatuses) {
      const filename = String(st.file || "").replace("/uploads/", "").trim();
      const abs = path.join(uploadDir, filename);

      if (!filename || !fs.existsSync(abs)) {
        await Status.deleteOne({ _id: st._id });
        removed++;
      }
    }

    io.emit("status-update");
    res.json({ ok: true, removed });
  } catch (err) {
    console.log("CLEANUP STATUS ERROR:", err);
    res.status(500).json({ ok: false, removed: 0 });
  }
});

app.post("/upload-dp", (req, res) => {
  upload.single("dp")(req, res, async err => {
    if (err) return sendUploadError(res, err);

    try {
      if (!req.file) return res.json({ status: "no_file" });

      const username = normalizeUsername(req.body.username);
      if (!isValidUsername(username)) {
        return res.status(400).json({ status: "error", msg: "Invalid username" });
      }

      if (!isImageFile(req.file)) {
        return res.status(400).json({ status: "error", msg: "Only images allowed" });
      }

      const filePath = "/uploads/" + req.file.filename;

      await User.findOneAndUpdate(
        { name: username },
        { dp: filePath },
        { upsert: false }
      );

      await emitUsersToAll();
      res.json({ status: "ok", dp: filePath });
    } catch (e) {
      console.log(e);
      res.json({ status: "error" });
    }
  });
});


app.post("/upload-status", (req, res) => {
  upload.single("file")(req, res, async err => {
    if (err) return sendUploadError(res, err);

    try {
      const username = normalizeUsername(req.body.username);

      if (!isValidUsername(username)) {
        return res.status(400).json({ status: "error", msg: "Invalid username" });
      }

      if (!req.file) {
        return res.status(400).json({ status: "no_file" });
      }

      const mime = String(req.file.mimetype || "").toLowerCase();
      const ext = path.extname(req.file.filename || "").toLowerCase();

      const imageExts = [".jpg", ".jpeg", ".png", ".webp", ".gif"];
      const videoExts = [".mp4", ".webm", ".mov"];

      const isImage = mime.startsWith("image/") || imageExts.includes(ext);
      const isVideo = mime.startsWith("video/") || videoExts.includes(ext);

      if (!isImage && !isVideo) {
        removeUploadFileIfExists("/uploads/" + req.file.filename);
        return res.status(400).json({
          status: "error",
          msg: "Only image or video allowed for status"
        });
      }

      const filePath = "/uploads/" + req.file.filename;
      const absoluteFilePath = getAbsoluteUploadPath(filePath);

      if (!fs.existsSync(absoluteFilePath)) {
        return res.status(500).json({
          status: "error",
          msg: "Uploaded file not found on server"
        });
      }

      const fileType = isVideo ? "video" : "image";

      const newStatus = await Status.create({
        user: username,
        file: filePath,
        fileType,
        viewers: [],
        reactions: []
      });

      console.log("STATUS STORED:", {
        user: username,
        filePath,
        fileType,
        exists: fs.existsSync(absoluteFilePath)
      });

      io.emit("status-update");

      return res.json({
        status: "ok",
        filePath,
        fileType,
        statusId: newStatus._id,
        createdAt: newStatus.createdAt
      });
    } catch (e) {
      console.log("UPLOAD STATUS ERROR:", e);
      return res.status(500).json({ status: "error", msg: "Status upload failed" });
    }
  });
});

app.get("/statuses", async (req, res) => {
  try {
    const now = new Date();

    const rawList = await Status.find({
      expiresAt: { $gt: now }
    }).sort({ createdAt: 1 });

    const validList = [];
    const invalidIds = [];

    for (const st of rawList) {
      if (publicUploadFileExists(st.file)) {
        validList.push(st);
      } else {
        console.log("MISSING STATUS FILE AUTO CLEAN:", st.file, String(st._id));
        invalidIds.push(st._id);
      }
    }

    if (invalidIds.length) {
      await Status.deleteMany({ _id: { $in: invalidIds } });
    }

    return res.json(validList);
  } catch (err) {
    console.log("GET STATUSES ERROR:", err);
    return res.status(500).json([]);
  }
});
app.get("/debug-statuses", async (req, res) => {
  try {
    const list = await Status.find({}).sort({ createdAt: -1 });
    res.json(list.map(s => ({
      id: s._id,
      user: s.user,
      file: s.file,
      fileType: s.fileType,
      createdAt: s.createdAt
    })));
  } catch (err) {
    console.log(err);
    res.status(500).json([]);
  }
}); 
app.post("/status-view", async (req, res) => {
  try {
    const { statusId, viewer } = req.body;
    const st = await Status.findById(statusId);
    if (!st) return res.status(404).json({ ok: false });

    if (st.user !== viewer) {
      await Status.updateOne(
        { _id: statusId },
        { $addToSet: { viewers: viewer } }
      );
    }

    res.json({ ok: true });
  } catch (err) {
    console.log(err);
    res.status(500).json({ ok: false });
  }
});

app.post("/status-react", async (req, res) => {
  try {
    const { statusId, user, emoji } = req.body;
    const st = await Status.findById(statusId);
    if (!st) return res.status(404).json({ ok: false });

    st.reactions = (st.reactions || []).filter(r => r.user !== user);
    st.reactions.push({ user, emoji });
    await st.save();

    res.json({ ok: true });
  } catch (err) {
    console.log(err);
    res.status(500).json({ ok: false });
  }
});

app.post("/status-reply", async (req, res) => {
  try {
    const { from, to, text } = req.body;

    await Message.create({
      from,
      to,
      text,
      file: null,
      fileType: null,
      
      status: "sent",
      reaction: null,
      seenBy: [],
      deliveredTo: [],
      createdAt: new Date()
    });

    io.to(to).emit("new-status-reply", { from, to, text });
    res.json({ ok: true });
  } catch (err) {
    console.log(err);
    res.status(500).json({ ok: false });
  }
});

app.post("/status-delete", async (req, res) => {
  try {
    const { statusId, user } = req.body;

    if (!statusId || !user) {
      return res.status(400).json({ ok: false });
    }

    const st = await Status.findById(statusId);
    if (!st) return res.json({ ok: false, msg: "not_found" });
    if (st.user !== user) return res.status(403).json({ ok: false, msg: "not_owner" });

    const filePath = st.file;

    await Status.deleteOne({ _id: statusId });
    removeUploadFileIfExists(filePath);

    io.emit("status-update");
    return res.json({ ok: true });
  } catch (err) {
    console.log("STATUS DELETE ERROR:", err);
    res.status(500).json({ ok: false });
  }
});


app.post("/api/logout", async (req, res) => {
  try {
    const { name } = req.body;
    const token = String(req.headers.authorization || "").replace("Bearer ", "");

    if (name) {
      await User.findOneAndUpdate(
        { name },
        {
          online: false,
          lastSeen: new Date()
        }
      );
    }

    if (token) {
      const userByToken = await User.findOne({ authToken: token });
      if (userByToken) {
        const preview = tokenPreview(token);
        userByToken.activeSessions = (Array.isArray(userByToken.activeSessions) ? userByToken.activeSessions : []).map(s => {
          if (s.tokenPreview === preview) {
            s.active = false;
            s.loggedOutAt = new Date();
          }
          return s;
        });
        userByToken.authToken = null;
        await userByToken.save();
      }
    }

    await emitUsersToAll();
    res.json({ ok: true });
  } catch (err) {
    console.log("LOGOUT ERROR:", err);
    res.status(500).json({ ok: false });
  }
});
app.get("/api/push-public-key", (req, res) => {
  if (!process.env.VAPID_PUBLIC_KEY) {
    return res.status(500).json({ ok: false, msg: "Missing public key" });
  }
  res.json({ ok: true, publicKey: process.env.VAPID_PUBLIC_KEY });
});


app.post("/api/fcm/register", async (req, res) => {
  try {
    const token = String(req.headers.authorization || "").replace("Bearer ", "").trim();
    const username = normalizeUsername(req.body.username);
    const fcmToken = String(req.body.fcmToken || "").trim();
    const device = String(req.body.device || "Android").trim().slice(0, 120);
    const platform = String(req.body.platform || "android-native").trim().slice(0, 80);

    if (!username || !fcmToken) {
      return res.status(400).json({ ok: false, msg: "Missing FCM register data" });
    }

    let user = null;
    if (token) {
      user = await User.findOne({ authToken: token, name: username });
    }
    if (!user) {
      user = await User.findOne({ name: username, approvalStatus: "approved" });
    }

    if (!user || user.blocked || user.approvalStatus !== "approved") {
      return res.status(401).json({ ok: false, msg: "Unauthorized" });
    }

    const current = Array.isArray(user.fcmTokens) ? user.fcmTokens : [];
    const filtered = current.filter(item => {
      const oldToken = typeof item === "string" ? item : item?.token;
      return oldToken && oldToken !== fcmToken;
    });

    filtered.push({
      token: fcmToken,
      device,
      platform,
      createdAt: new Date(),
      lastSeenAt: new Date()
    });

    user.fcmTokens = filtered.slice(-8);
    await user.save();

    return res.json({ ok: true, msg: "FCM registered", fcmTokenCount: user.fcmTokens.length });
  } catch (err) {
    console.log("FCM REGISTER ERROR:", err);
    return res.status(500).json({ ok: false, msg: "FCM register failed" });
  }
});



app.post("/api/call/decline", async (req, res) => {
  try {
    const from = normalizeUsername(req.body.from); // caller
    const to = normalizeUsername(req.body.to);     // receiver
    if (!from || !to) {
      return res.status(400).json({ ok: false, msg: "from/to required" });
    }

    io.to(from).emit("call-unavailable", { to, reason: "declined" });
    io.to(from).emit("call-end", { from: to });

    clearCall(from);
    clearCall(to);
    delete pendingCallOffers[from];
    delete pendingCallOffers[to];

    await Call.create({
      from,
      to,
      type: String(req.body.callType || "voice"),
      status: "declined",
      time: formatTime()
    });

    return res.json({ ok: true });
  } catch (err) {
    console.log("CALL DECLINE API ERROR:", err);
    return res.status(500).json({ ok: false, msg: "decline failed" });
  }
});


app.post("/api/fcm/test-call", requireAdmin, async (req, res) => {
  try {
    const username = normalizeUsername(req.body.username || req.body.user);
    const from = normalizeUsername(req.body.from || req.adminUser?.name || ADMIN_NAME);
    if (!username) return res.status(400).json({ ok: false, msg: "username required" });

    const result = await sendFcmToUser(username, {
      title: "📞 Incoming voice call",
      body: `${from} is calling you`,
      url: `/chat.html?user=${encodeURIComponent(from)}&call=1`,
      tag: `incoming-call-test-${Date.now()}`,
      type: "call",
      notificationType: "call",
      callType: "voice",
      canReply: false,
      requireInteraction: true,
      from,
      to: username,
      sound: "ring"
    });

    return res.json({
      ok: !!result.ok,
      msg: result.ok ? "Call notification test sent" : "Call notification failed",
      result
    });
  } catch (err) {
    console.log("FCM TEST CALL ERROR:", err);
    return res.status(500).json({ ok: false, msg: "Call test failed", error: err.message });
  }
});


app.get("/api/fcm/debug", async (req, res) => {
  try {
    const username = normalizeUsername(req.query.user);
    if (!username) {
      return res.status(400).json({ ok: false, msg: "user query required" });
    }

    const user = await User.findOne({ name: username }).select("name fcmTokens pushSubscriptions approvalStatus blocked online");

    if (!user) {
      return res.status(404).json({ ok: false, msg: "User not found" });
    }

    return res.json({
      ok: true,
      firebaseAdminReady,
      user: user.name,
      approved: user.approvalStatus === "approved",
      blocked: !!user.blocked,
      online: !!user.online,
      fcmTokenCount: Array.isArray(user.fcmTokens) ? user.fcmTokens.length : 0,
      pushSubscriptionCount: Array.isArray(user.pushSubscriptions) ? user.pushSubscriptions.length : 0,
      lastFcmSeenAt: Array.isArray(user.fcmTokens) && user.fcmTokens.length
        ? user.fcmTokens.map(t => t.lastSeenAt || t.createdAt || null).filter(Boolean).slice(-1)[0]
        : null
    });
  } catch (err) {
    console.log("FCM DEBUG ERROR:", err);
    return res.status(500).json({ ok: false, msg: "FCM debug failed" });
  }
});

app.post("/api/fcm/test", requireAdmin, async (req, res) => {
  try {
    const username = normalizeUsername(req.body.username || req.body.user);
    const title = String(req.body.title || "Shravan Chat Test");
    const body = String(req.body.body || "Native notification with Reply + Mark read ✅");
    const kind = String(req.body.kind || "message");

    if (!username) return res.status(400).json({ ok: false, msg: "username required" });

    const result = await sendFcmToUser(username, {
      title,
      body,
      url: "/chat.html",
      tag: `native-test-${Date.now()}`,
      type: kind === "call" ? "call" : "private",
      notificationType: kind === "call" ? "call" : "message",
      callType: kind === "call" ? "voice" : "",
      canReply: kind !== "call",
      canMarkRead: kind !== "call",
      requireInteraction: kind === "call",
      from: req.adminUser?.name || ADMIN_NAME,
      to: username,
      sound: kind === "call" ? "ring" : "default"
    });

    return res.json({ ok: !!result.ok, msg: result.ok ? "Native FCM sent" : "Native FCM failed", result });
  } catch (err) {
    console.log("FCM TEST ERROR:", err);
    return res.status(500).json({ ok: false, msg: "FCM test failed", error: err.message });
  }
});

app.post("/api/push/subscribe", async (req, res) => {
  try {
    const { username, subscription } = req.body;

    if (!username || !subscription?.endpoint) {
      return res.status(400).json({ ok: false, msg: "Invalid subscription" });
    }

    const user = await User.findOne({ name: username });
    if (!user) {
      return res.status(404).json({ ok: false, msg: "User not found" });
    }

    const current = Array.isArray(user.pushSubscriptions) ? user.pushSubscriptions : [];
    const exists = current.some(s => s?.endpoint === subscription.endpoint);

    if (!exists) {
      current.push(subscription);
      user.pushSubscriptions = current;
      await user.save();
    }

    return res.json({ ok: true });
  } catch (err) {
    console.log("PUSH SUBSCRIBE ERROR:", err);
    res.status(500).json({ ok: false, msg: "Subscribe failed" });
  }
});

app.post("/api/push/unsubscribe", async (req, res) => {
  try {
    const { username, endpoint } = req.body;

    if (!username || !endpoint) {
      return res.status(400).json({ ok: false, msg: "Invalid unsubscribe data" });
    }

    await User.updateOne(
      { name: username },
      { $pull: { pushSubscriptions: { endpoint } } }
    );

    return res.json({ ok: true });
  } catch (err) {
    console.log("PUSH UNSUBSCRIBE ERROR:", err);
    res.status(500).json({ ok: false, msg: "Unsubscribe failed" });
  }
});


app.post("/api/notification-read", async (req, res) => {
  try {
    const token = String(req.headers.authorization || "").replace("Bearer ", "").trim();
    let user = null;

    if (token) {
      user = await User.findOne({ authToken: token }).select("name");
    }

    const username = normalizeUsername(req.body.user || req.body.username);
    if (!user && username) {
      user = await User.findOne({ name: username, approvalStatus: "approved" }).select("name");
    }

    if (!user) return res.status(401).json({ ok: false, msg: "Unauthorized" });

    const from = normalizeUsername(req.body.from || req.body.peer);
    const group = String(req.body.group || req.body.groupId || "").trim();

    if (group) {
      await Message.updateMany(
        { group, from: { $ne: user.name } },
        { $addToSet: { seenBy: user.name } }
      );

      const gCounts = await calculateGroupUnread(user.name);
      io.to(user.name).emit("group-unread-counts", gCounts);
      return res.json({ ok: true, type: "group", group });
    }

    if (from) {
      await Message.updateMany(
        { from, to: user.name, status: { $ne: "seen" } },
        { status: "seen" }
      );

      io.to(from).emit("messages-seen", { by: user.name });
      const counts = await calculateUnread(user.name);
      io.to(user.name).emit("unread-counts", counts);

      return res.json({ ok: true, type: "private", from });
    }

    return res.status(400).json({ ok: false, msg: "from or group required" });
  } catch (err) {
    console.log("NOTIFICATION READ ERROR:", err);
    return res.status(500).json({ ok: false, msg: "Mark read failed" });
  }
});


app.post("/api/notification-reply", async (req, res) => {
  try {
    const token = String(req.headers.authorization || "")
      .replace("Bearer ", "")
      .trim();

    const text = sanitizeText(req.body.text || "", 2000);
    const to = normalizeUsername(req.body.to);
    const groupId = String(req.body.group || "").trim();

    if (!token) {
      return res.status(401).json({ ok: false, msg: "No token" });
    }

    if (!text) {
      return res.status(400).json({ ok: false, msg: "Message empty" });
    }

    const sender = await User.findOne({ authToken: token });

    if (!sender || sender.blocked || sender.approvalStatus !== "approved") {
      return res.status(401).json({ ok: false, msg: "Unauthorized" });
    }

    if (sender.muted) {
      return res.status(403).json({ ok: false, msg: "Shravan muted you. You cannot send messages." });
    }

    if (groupId) {
      const group = await Group.findById(groupId);

      if (!group) {
        return res.status(404).json({ ok: false, msg: "Group not found" });
      }

      if (!(group.members || []).includes(sender.name)) {
        return res.status(403).json({ ok: false, msg: "Not a group member" });
      }

      const mentionNames = extractMentionNames(text).filter(name => (group.members || []).includes(name));

      const msg = await Message.create({
        from: sender.name,
        to: null,
        group: String(groupId),
        text,
        file: null,
        fileType: null,
        replyTo: null,
        mentions: mentionNames,
        status: "sent",
        reaction: null,
        seenBy: [],
        deliveredTo: [],
        createdAt: new Date()
      });

      io.to(roomNameForGroup(groupId)).emit("group-message", msg);
      await emitGroupUnreadForMembers(groupId).catch(() => {});

      const notificationMembers = (group.members || []).filter(member => {
        return member !== sender.name;
      });

      for (const member of notificationMembers) {
        await sendAppNotification(member, {
          title: `👥 ${group.name || "Group"}`,
          body: `${sender.name}: ${safeNotificationBody(msg)}`,
          url: `/chat.html?group=${encodeURIComponent(String(groupId))}`,
          tag: `group-${groupId}`,
          icon: "/icons/icon-192.png",
          badge: "/icons/icon-192.png",
          type: "group",
          notificationType: "message",
          canReply: true,
          from: sender.name,
          group: String(groupId),
          sound: "default"
        });
      }

      return res.json({ ok: true, msg });
    }

    if (!to) {
      return res.status(400).json({ ok: false, msg: "Receiver missing" });
    }

    const receiver = await User.findOne({ name: to });

    if (!receiver || receiver.blocked || receiver.approvalStatus !== "approved") {
      return res.status(404).json({ ok: false, msg: "Receiver not found" });
    }

    const receiverOnline = !!(userSocketIds[to] && userSocketIds[to].size);

    const msg = await Message.create({
      from: sender.name,
      to,
      text,
      file: null,
      fileType: null,
      replyTo: null,
      mentions: [],
      status: receiverOnline ? "delivered" : "sent",
      reaction: null,
      seenBy: [],
      deliveredTo: receiverOnline ? [to] : [],
      createdAt: new Date()
    });

    io.to(sender.name).emit("private-message", msg);
    io.to(to).emit("private-message", msg);

    if (receiverOnline) {
      const counts = await calculateUnread(to);
      io.to(to).emit("unread-counts", counts);
    }

    await sendAppNotification(to, {
      title: sender.name,
      body: safeNotificationBody(msg),
      url: `/chat.html?user=${encodeURIComponent(sender.name)}`,
      tag: `private-${sender.name}`,
      icon: "/icons/icon-192.png",
      badge: "/icons/icon-192.png",
      type: "private",
      notificationType: "message",
      canReply: true,
      from: sender.name,
      to,
      sound: "default"
    });

    return res.json({ ok: true, msg });
  } catch (err) {
    console.log("NOTIFICATION REPLY ERROR:", err);
    return res.status(500).json({ ok: false, msg: "Reply failed" });
  }
});

app.post("/api/presence/ping", async (req, res) => {
  try {
    const token = String(req.headers.authorization || "").replace("Bearer ", "").trim();
    const bodyName = normalizeUsername(req.body?.name);

    let user = null;

    if (token) {
      user = await User.findOne({ authToken: token }).select("name blocked approvalStatus");
    }

    if (!user && bodyName) {
      user = await User.findOne({ name: bodyName }).select("name blocked approvalStatus");
    }

    if (!user || user.blocked || user.approvalStatus !== "approved") {
      return res.status(401).json({ ok: false, msg: "Unauthorized" });
    }

    cancelPresenceOfflineTimer(user.name);
    presenceHttpPings.set(user.name, Date.now());

    await User.updateOne(
      { _id: user._id },
      { online: true, lastSeen: new Date() }
    );

    await emitUsersToAll();
    return res.json({ ok: true });
  } catch (err) {
    console.log("PRESENCE PING ERROR:", err);
    return res.status(500).json({ ok: false, msg: "Presence failed" });
  }
});

setInterval(async () => {
  try {
    const now = Date.now();

    for (const [username, lastPing] of presenceHttpPings.entries()) {
      if (hasActiveSocketForUser(username)) continue;

      if ((now - Number(lastPing || 0)) > PRESENCE_HTTP_STALE_MS) {
        presenceHttpPings.delete(username);
        await User.updateOne(
          { name: username },
          { online: false, lastSeen: new Date() }
        );
      }
    }

    await emitUsersToAll();
  } catch (err) {
    console.log("PRESENCE CLEANUP ERROR:", err);
  }
}, 20000);


app.get("/admin/user-sessions", requireAdmin, async (req, res) => {
  try {
    const users = await User.find({
      approvalStatus: "approved"
    }).select("name dp role online lastSeen blocked muted activeSessions authToken");

    const result = users.map(user => {
      const socketCount = userSocketIds[user.name] ? userSocketIds[user.name].size : 0;
      const sessions = serializeSessionsForUser(user);

      return {
        name: user.name,
        dp: user.dp || "/default.png",
        role: user.role || "user",
        online: !!user.online || socketCount > 0,
        socketCount,
        blocked: !!user.blocked,
        muted: !!user.muted,
        lastSeen: user.lastSeen || null,
        sessions
      };
    }).sort((a, b) => {
      if (a.name === ADMIN_NAME) return -1;
      if (b.name === ADMIN_NAME) return 1;
      if (a.online !== b.online) return a.online ? -1 : 1;
      return String(a.name).localeCompare(String(b.name));
    });

    return res.json({ ok: true, users: result });
  } catch (err) {
    console.log("ADMIN USER SESSIONS ERROR:", err);
    return res.status(500).json({ ok: false, msg: "Failed to load sessions" });
  }
});

app.post("/admin/force-logout-user", requireAdmin, async (req, res) => {
  try {
    const username = normalizeUsername(req.body.username);

    if (!isValidUsername(username)) {
      return res.status(400).json({ ok: false, msg: "Invalid username" });
    }

    if (username === ADMIN_NAME) {
      return res.status(400).json({ ok: false, msg: "Admin account cannot be force logged out" });
    }

    const user = await User.findOne({ name: username });
    if (!user) return res.status(404).json({ ok: false, msg: "User not found" });

    user.authToken = null;
    user.online = false;
    user.lastSeen = new Date();
    user.activeSessions = (Array.isArray(user.activeSessions) ? user.activeSessions : []).map(s => {
      s.active = false;
      s.forceLoggedOut = true;
      s.loggedOutAt = new Date();
      return s;
    });

    await user.save();

    forceLogoutSockets(username, "Admin logged you out from RickyY Chat.");
    await emitUsersToAll().catch(() => {});

    return res.json({ ok: true, msg: `${username} logged out from all devices` });
  } catch (err) {
    console.log("ADMIN FORCE LOGOUT USER ERROR:", err);
    return res.status(500).json({ ok: false, msg: "Force logout failed" });
  }
});

app.post("/admin/force-logout-session", requireAdmin, async (req, res) => {
  try {
    const username = normalizeUsername(req.body.username);
    const sessionId = String(req.body.sessionId || "").trim();

    if (!isValidUsername(username) || !sessionId) {
      return res.status(400).json({ ok: false, msg: "Username and session required" });
    }

    if (username === ADMIN_NAME) {
      return res.status(400).json({ ok: false, msg: "Admin session cannot be force logged out" });
    }

    const user = await User.findOne({ name: username });
    if (!user) return res.status(404).json({ ok: false, msg: "User not found" });

    let wasCurrent = false;
    const currentPreview = tokenPreview(user.authToken || "");

    user.activeSessions = (Array.isArray(user.activeSessions) ? user.activeSessions : []).map(s => {
      if (String(s.sessionId || "") === sessionId) {
        if (currentPreview && s.tokenPreview === currentPreview) wasCurrent = true;
        s.active = false;
        s.forceLoggedOut = true;
        s.loggedOutAt = new Date();
      }
      return s;
    });

    if (wasCurrent) {
      user.authToken = null;
      user.online = false;
      user.lastSeen = new Date();
      forceLogoutSockets(username, "Admin logged out this device.");
    }

    await user.save();
    await emitUsersToAll().catch(() => {});

    return res.json({ ok: true, msg: "Session logged out" });
  } catch (err) {
    console.log("ADMIN FORCE LOGOUT SESSION ERROR:", err);
    return res.status(500).json({ ok: false, msg: "Force logout session failed" });
  }
});



app.post("/api/report-message", async (req, res) => {
  try {
    const reporter = normalizeUsername(req.body.reporter);
    const messageId = String(req.body.messageId || "").trim();
    const reason = sanitizeText(req.body.reason || "", 300);
    const chatType = sanitizeText(req.body.chatType || "", 30);
    const groupId = String(req.body.groupId || "").trim();
    const peer = normalizeUsername(req.body.peer);

    if (!isValidUsername(reporter)) {
      return res.status(400).json({ ok: false, msg: "Invalid reporter" });
    }

    if (!messageId || !reason) {
      return res.status(400).json({ ok: false, msg: "Message and reason required" });
    }

    const reporterUser = await User.findOne({ name: reporter }).select("name approvalStatus blocked");
    if (!reporterUser || reporterUser.blocked || reporterUser.approvalStatus !== "approved") {
      return res.status(401).json({ ok: false, msg: "Unauthorized" });
    }

    const msg = await Message.findById(messageId);
    if (!msg) {
      return res.status(404).json({ ok: false, msg: "Message not found" });
    }

    const report = await Report.create({
      reporter,
      reportedUser: msg.from || "",
      messageId: String(msg._id),
      messageText: safeNotificationBody(msg),
      reason,
      chatType,
      groupId,
      peer,
      status: "open"
    });

    await logActivity("report_message", reporter, msg.from || "", reason, {
      messageId: String(msg._id),
      reportId: String(report._id),
      chatType,
      groupId,
      peer
    });

    io.to(ADMIN_NAME).emit("admin-report-added", {
      id: String(report._id),
      reporter,
      reportedUser: msg.from || "",
      reason,
      messageText: report.messageText,
      createdAt: report.createdAt
    });

    return res.json({ ok: true, report });
  } catch (err) {
    console.log("REPORT MESSAGE ERROR:", err);
    return res.status(500).json({ ok: false, msg: "Report failed" });
  }
});


app.post("/admin/broadcast", requireAdmin, async (req, res) => {
  try {
    const text = sanitizeText(req.body.text || "", 2000);
    const title = sanitizeText(req.body.title || "📢 Admin Broadcast", 120);

    if (!text) {
      return res.status(400).json({ ok: false, msg: "Broadcast message required" });
    }

    const users = await User.find({
      approvalStatus: "approved",
      blocked: { $ne: true },
      name: { $ne: req.adminUser.name }
    }).select("name notifications");

    const saved = [];

    for (const u of users) {
      u.notifications = Array.isArray(u.notifications) ? u.notifications : [];
      u.notifications.push({
        text: `${title}: ${text}`,
        read: false,
        createdAt: new Date()
      });
      await u.save();

      io.to(u.name).emit("admin-broadcast", {
        title,
        text,
        from: req.adminUser.name,
        createdAt: new Date()
      });

      await sendAppNotification(u.name, {
        title,
        body: text,
        url: "/chat.html",
        tag: `admin-broadcast-${Date.now()}-${u.name}`,
        icon: "/icons/icon-192.png",
        badge: "/icons/icon-192.png",
        type: "admin",
        notificationType: "message",
        canReply: false,
        from: req.adminUser.name,
        to: u.name,
        sound: "default"
      });

      saved.push(u.name);
    }

    await logActivity("admin_broadcast", req.adminUser.name, "all_users", text, {
      count: saved.length,
      title
    });

    return res.json({ ok: true, sent: saved.length });
  } catch (err) {
    console.log("ADMIN BROADCAST ERROR:", err);
    return res.status(500).json({ ok: false, msg: "Broadcast failed" });
  }
});

app.get("/admin/activity-logs", requireAdmin, async (req, res) => {
  try {
    const limit = Math.min(200, Math.max(20, Number(req.query.limit || 80)));
    const logs = await ActivityLog.find({})
      .sort({ createdAt: -1 })
      .limit(limit);

    return res.json({ ok: true, logs });
  } catch (err) {
    console.log("ADMIN ACTIVITY LOGS ERROR:", err);
    return res.status(500).json({ ok: false, logs: [] });
  }
});

app.get("/admin/reports", requireAdmin, async (req, res) => {
  try {
    const status = String(req.query.status || "").trim();
    const q = status && status !== "all" ? { status } : {};

    const reports = await Report.find(q)
      .sort({ createdAt: -1 })
      .limit(150);

    return res.json({ ok: true, reports });
  } catch (err) {
    console.log("ADMIN REPORTS ERROR:", err);
    return res.status(500).json({ ok: false, reports: [] });
  }
});

app.post("/admin/report/action", requireAdmin, async (req, res) => {
  try {
    const reportId = String(req.body.reportId || "").trim();
    const status = String(req.body.status || "reviewed").trim();
    const note = sanitizeText(req.body.note || "", 300);

    if (!reportId) {
      return res.status(400).json({ ok: false, msg: "Report id required" });
    }

    const report = await Report.findById(reportId);
    if (!report) {
      return res.status(404).json({ ok: false, msg: "Report not found" });
    }

    report.status = ["open", "reviewed", "dismissed", "action_taken"].includes(status) ? status : "reviewed";
    report.actionBy = req.adminUser.name;
    report.actionNote = note;
    report.actionAt = new Date();
    await report.save();

    await logActivity("admin_report_action", req.adminUser.name, report.reportedUser, note || report.status, {
      reportId: String(report._id),
      status: report.status
    });

    return res.json({ ok: true, report });
  } catch (err) {
    console.log("ADMIN REPORT ACTION ERROR:", err);
    return res.status(500).json({ ok: false, msg: "Report update failed" });
  }
});

app.get("/api/me", async (req, res) => {
  try {
    const token = String(req.headers.authorization || "").replace("Bearer ", "").trim();

    if (!token) {
      return res.status(401).json({ ok: false, msg: "No token" });
    }

    const user = await User.findOne({ authToken: token }).select("name dp role approvalStatus blocked");

    if (!user) {
      return res.status(401).json({ ok: false, msg: "Invalid token" });
    }

    if (user.blocked) {
      return res.status(403).json({ ok: false, msg: "Blocked user" });
    }

    if (user.approvalStatus === "rejected") {
      return res.status(403).json({ ok: false, msg: "Rejected user" });
    }

    await touchSessionByToken(token);

    return res.json({
      ok: true,
      user: {
        name: user.name,
        dp: user.dp,
        role: user.role || "user",
        approvalStatus: user.approvalStatus || "approved"
      }
    });
  } catch (err) {
    console.log("API ME ERROR:", err);
    res.status(500).json({ ok: false, msg: "Server error" });
  }
});
app.get("/api/captcha", (req, res) => {
  try {
    const captcha = generateCaptchaValue();
    return res.json({ ok: true, captcha });
  } catch (err) {
    return res.status(500).json({ ok: false, msg: "Captcha error" });
  }
});
app.post("/api/signup-request", async (req, res) => {
  try {
    const name = normalizeUsername(req.body.name);
    const contact = String(req.body.contact || "").trim();
    const password = String(req.body.password || "");
    const confirmPassword = String(req.body.confirmPassword || "");
    const acceptedTerms = !!req.body.acceptedTerms;

    if (!isValidUsername(name)) {
      return res.json({ ok: false, msg: "Enter valid name" });
    }

    if (!isValidContact(contact)) {
      return res.json({ ok: false, msg: "Contact must be 10 digits" });
    }

   if (!isStrongPassword(password)) {
  return res.json({
    ok: false,
    msg: "Password must be at least 8 characters and include uppercase, lowercase, number and special character."
  });
}

    if (password !== confirmPassword) {
      return res.json({ ok: false, msg: "Passwords do not match" });
    }

    if (!acceptedTerms) {
      return res.json({ ok: false, msg: "Accept all terms to continue" });
    }

    const existingName = await User.findOne({ name });
    if (existingName) {
      return res.json({ ok: false, msg: "Username already exists" });
    }

    const existingContact = await User.findOne({ contact });
    if (existingContact) {
      return res.json({ ok: false, msg: "Contact already exists" });
    }

    const otp = generateOtp();

    return res.json({
      ok: true,
      otp,
      tempData: {
        name,
        contact,
        password,
        otp,
        otpExpiresAt: Date.now() + (4 * 60 * 1000)
      }
    });
  } catch (err) {
    console.log("SIGNUP REQUEST ERROR:", err);
    return res.status(500).json({ ok: false, msg: "Server error" });
  }
});
app.post("/api/verify-signup-otp", async (req, res) => {
  try {
    const name = normalizeUsername(req.body.name);
    const contact = String(req.body.contact || "").trim();
    const password = String(req.body.password || "");
    const otp = String(req.body.otp || "").trim();
    const originalOtp = String(req.body.originalOtp || "").trim();
    const otpExpiresAt = Number(req.body.otpExpiresAt || 0);

    if (!name || !contact || !password || !otp || !originalOtp || !otpExpiresAt) {
      return res.json({ ok: false, msg: "Missing OTP data" });
    }

    if (Date.now() > otpExpiresAt) {
      return res.json({ ok: false, msg: "OTP expired. Generate again." });
    }

    if (otp !== originalOtp) {
      return res.json({ ok: false, msg: "Invalid OTP" });
    }

    const existingName = await User.findOne({ name });
    if (existingName) {
      return res.json({ ok: false, msg: "Username already exists" });
    }

    const existingContact = await User.findOne({ contact });
    if (existingContact) {
      return res.json({ ok: false, msg: "Contact already exists" });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    const user = new User({
      name,
      contact,
      password: hashedPassword,
      pin: "",
      online: false,
      lastSeen: null,
      dp: "/default.png",
      role: "user",
      approvalStatus: "pending",
      notifications: [
        { text: "Request sent to admin. Wait for approval from Shravan." }
      ]
    });

    await user.save();

    io.to(ADMIN_NAME).emit("approval-request-added", {
      name: user.name,
      dp: user.dp
    });

    io.to(ADMIN_NAME).emit("approval-list-updated");

    await logActivity("signup_request", user.name, ADMIN_NAME, "Signup request sent", { contact: user.contact }).catch(() => {});

    return res.json({
      ok: true,
      msg: "Request sent to admin. Wait for approval from Shravan."
    });
  } catch (err) {
    console.log("VERIFY SIGNUP OTP ERROR:", err);
    return res.status(500).json({ ok: false, msg: "Server error" });
  }
});
app.get("/api/notifications", async (req, res) => {
  try {
    const token = String(req.headers.authorization || "").replace("Bearer ", "").trim();

    if (!token) {
      return res.status(401).json({ ok: false, msg: "No token" });
    }

    const user = await User.findOne({ authToken: token }).select("name notifications approvalStatus role");
    if (!user) {
      return res.status(401).json({ ok: false, msg: "Invalid token" });
    }

    return res.json({
      ok: true,
      notifications: Array.isArray(user.notifications) ? user.notifications : [],
      approvalStatus: user.approvalStatus,
      role: user.role || "user"
    });
  } catch (err) {
    console.log("NOTIFICATIONS ERROR:", err);
    return res.status(500).json({ ok: false, msg: "Server error" });
  }
});

app.get("/users-data", async (req, res) => {
  try {
    const allUsers = await User.find({
      blocked: { $ne: true },
      approvalStatus: "approved"
    }).select("name dp role online lastSeen muted bio about");

    res.json(allUsers);
  } catch (err) {
    console.log(err);
    res.status(500).json([]);
  }
});

app.get("/user/:name", async (req, res) => {
  try {
    const user = await User.findOne({ name: req.params.name }).select(
      "name dp role online lastSeen muted blocked approvalStatus bio about"
    );

    if (!user) {
      return res.status(404).json({ ok: false, msg: "User not found" });
    }

    res.json({ ok: true, user });
  } catch (err) {
    console.log(err);
    res.status(500).json({ ok: false, msg: "Failed to load user" });
  }
});

app.post("/update-profile", async (req, res) => {
  try {
    const username = normalizeUsername(req.body.username);
    let bio = String(req.body.bio || "").trim();
    let about = String(req.body.about || "").trim();

    if (!isValidUsername(username)) {
      return res.status(400).json({ ok: false, msg: "Invalid username" });
    }

    if (bio.length > 120) bio = bio.slice(0, 120);
    if (about.length > 250) about = about.slice(0, 250);

    const user = await User.findOneAndUpdate(
      { name: username },
      { bio, about },
      { new: true }
    ).select("name dp role bio about");

    if (!user) {
      return res.status(404).json({ ok: false, msg: "User not found" });
    }

    await emitUsersToAll();

    return res.json({
      ok: true,
      msg: "Profile updated successfully",
      user
    });
  } catch (err) {
    console.log(err);
    res.status(500).json({ ok: false, msg: "Profile update failed" });
  }
});

app.get("/profile/:username", async (req, res) => {
  try {
    const username = normalizeUsername(req.params.username);

    if (!isValidUsername(username)) {
      return res.status(400).json({ ok: false, msg: "Invalid username" });
    }

    const user = await User.findOne({ name: username }).select(
      "name dp role bio about online lastSeen"
    );

    if (!user) {
      return res.status(404).json({ ok: false, msg: "User not found" });
    }

    return res.json({ ok: true, user });
  } catch (err) {
    console.log(err);
    res.status(500).json({ ok: false, msg: "Failed to fetch profile" });
  }
});


app.post("/create-group", async (req, res) => {
  try {
    const { name, admin, members, description } = req.body;

    if (!name || !String(name).trim() || !isValidUsername(admin)) {
      return res.status(400).json({ ok: false, msg: "Missing or invalid group name/admin" });
    }

    const groupName = sanitizeText(name, 60);
    const groupDescription = sanitizeText(description || "", 180);

    const cleanMembers = Array.isArray(members) ? members.filter(m => isValidUsername(m)) : [];
    const uniqueMembers = [...new Set([admin, ...cleanMembers])];

    const group = new Group({
      name: groupName,
      description: groupDescription,
      admin,
      admins: [admin],
      members: uniqueMembers,
      inviteCode: generateInviteCode()
    });

    await group.save();

    for (const member of uniqueMembers) {
      io.to(member).emit("group-created", group);
    }

    res.json({ ok: true, group });
  } catch (err) {
    console.log(err);
    res.status(500).json({ ok: false, msg: "Create group failed" });
  }
});

app.get("/groups", async (req, res) => {
  try {
    const user = req.query.user;
    if (!user) return res.json([]);
    const groups = await Group.find({ members: user }).sort({ createdAt: -1 });
    res.json(groups);
  } catch (err) {
    console.log(err);
    res.json([]);
  }
});

app.post("/group/:id/make-admin", async (req, res) => {
  try {
    const groupId = req.params.id;
    const { owner, member } = req.body;

    if (!groupId || !owner || !member) {
      return res.status(400).json({ ok: false, msg: "Missing groupId, owner or member" });
    }

    const group = await Group.findById(groupId);
    if (!group) return res.status(404).json({ ok: false, msg: "Group not found" });

    if (!isGroupOwner(group, owner)) {
      return res.status(403).json({ ok: false, msg: "Only owner can make admins" });
    }

    if (!(group.members || []).includes(member)) {
      return res.status(400).json({ ok: false, msg: "Member not in group" });
    }

    if (!Array.isArray(group.admins)) {
      group.admins = group.admin ? [group.admin] : [];
    }

    if (!group.admins.includes(member)) {
      group.admins.push(member);
    }

    await group.save();

    for (const m of group.members) {
      io.to(m).emit("group-updated", group);
    }

    return res.json({ ok: true, group, msg: `${member} is now an admin` });
  } catch (err) {
    console.log(err);
    res.status(500).json({ ok: false, msg: "Make admin failed" });
  }
});

app.get("/message-seen-info/:id", async (req, res) => {
  try {
    const msg = await Message.findById(req.params.id);

    if (!msg) {
      return res.status(404).json({ ok: false, msg: "Message not found" });
    }

    return res.json({
      ok: true,
      seenBy: Array.isArray(msg.seenBy) ? msg.seenBy : [],
      deliveredTo: Array.isArray(msg.deliveredTo) ? msg.deliveredTo : [],
      from: msg.from || "",
      group: msg.group || null
    });
  } catch (err) {
    console.log("MESSAGE SEEN INFO ERROR:", err);
    return res.status(500).json({ ok: false, msg: "Failed to load message info" });
  }
});

app.post("/group/:id/remove-admin", async (req, res) => {
  try {
    const groupId = req.params.id;
    const { owner, member } = req.body;

    if (!groupId || !owner || !member) {
      return res.status(400).json({ ok: false, msg: "Missing groupId, owner or member" });
    }

    const group = await Group.findById(groupId);
    if (!group) return res.status(404).json({ ok: false, msg: "Group not found" });

    if (!isGroupOwner(group, owner)) {
      return res.status(403).json({ ok: false, msg: "Only owner can remove admins" });
    }

    if (member === group.admin) {
      return res.status(400).json({ ok: false, msg: "Owner admin rights cannot be removed" });
    }

    if (!Array.isArray(group.admins)) {
      group.admins = group.admin ? [group.admin] : [];
    }

    group.admins = group.admins.filter(a => a !== member);
    await group.save();

    for (const m of group.members) {
      io.to(m).emit("group-updated", group);
    }

    return res.json({ ok: true, group, msg: `${member} is no longer an admin` });
  } catch (err) {
    console.log(err);
    res.status(500).json({ ok: false, msg: "Remove admin failed" });
  }
});

app.get("/group/:id", async (req, res) => {
  try {
    const group = await Group.findById(req.params.id);
    if (!group) return res.status(404).json({ ok: false, msg: "Group not found" });

    res.json({ ok: true, group });
  } catch (err) {
    console.log(err);
    res.status(500).json({ ok: false, msg: "Failed to fetch group" });
  }
});

app.post("/fix-groups-admins", async (req, res) => {
  try {
    const groups = await Group.find({});
    for (const g of groups) {
      if (!Array.isArray(g.admins) || g.admins.length === 0) {
        g.admins = g.admin ? [g.admin] : [];
        if (!g.inviteCode) g.inviteCode = generateInviteCode();
        if (typeof g.description !== "string") g.description = "";
        await g.save();
      }
    }
    res.json({ ok: true, msg: "Groups fixed" });
  } catch (err) {
    console.log(err);
    res.status(500).json({ ok: false, msg: "Fix failed" });
  }
});

app.post("/leave-group", async (req, res) => {
  try {
    const { groupId, user } = req.body;

    if (!groupId || !user) {
      return res.status(400).json({ ok: false, msg: "Missing groupId or user" });
    }

    const group = await Group.findById(groupId);
    if (!group) return res.status(404).json({ ok: false, msg: "Group not found" });

    if (group.admin === user) {
      await Message.deleteMany({ group: String(groupId) });
      await Group.deleteOne({ _id: groupId });

      io.to(roomNameForGroup(groupId)).emit("group-deleted", { groupId });

      for (const member of group.members) {
        io.to(member).emit("group-deleted", { groupId });
      }

      return res.json({
        ok: true,
        deleted: true,
        msg: "Admin left, so group deleted"
      });
    }

    group.members = (group.members || []).filter(member => member !== user);
    await group.save();

    io.to(roomNameForGroup(groupId)).emit("group-updated", group);
    for (const member of group.members) {
      io.to(member).emit("group-updated", group);
    }

    return res.json({ ok: true, group });
  } catch (err) {
    console.log(err);
    res.status(500).json({ ok: false, msg: "Leave group failed" });
  }
});

app.post("/group/:id/add-members", async (req, res) => {
  try {
    const { admin, members } = req.body;
    const groupId = req.params.id;

    const group = await Group.findById(groupId);
    if (!group) return res.status(404).json({ ok: false, msg: "Group not found" });

    const isOwnerUser = group.admin === admin;
    const isAdminUser = Array.isArray(group.admins) && group.admins.includes(admin);

    if (!isOwnerUser && !isAdminUser) {
      return res.status(403).json({ ok: false, msg: "Only owner/admin allowed" });
    }

    const addMembers = Array.isArray(members) ? members.filter(Boolean) : [];
    group.members = [...new Set([...(group.members || []), ...addMembers])];

    await group.save();

    for (const member of group.members) {
      io.to(member).emit("group-updated", group);
    }

    return res.json({ ok: true, group });
  } catch (err) {
    console.log(err);
    res.status(500).json({ ok: false, msg: "Add members failed" });
  }
});

app.post("/group/:id/remove-member", async (req, res) => {
  try {
    const { admin, member } = req.body;
    const groupId = req.params.id;

    const group = await Group.findById(groupId);
    if (!group) return res.status(404).json({ ok: false, msg: "Group not found" });

    const isOwnerUser = group.admin === admin;
    const isAdminUser = Array.isArray(group.admins) && group.admins.includes(admin);

    if (!isOwnerUser && !isAdminUser) {
      return res.status(403).json({ ok: false, msg: "Only owner/admin allowed" });
    }

    if (member === group.admin) {
      return res.status(400).json({ ok: false, msg: "Owner cannot be removed" });
    }

    group.members = (group.members || []).filter(m => m !== member);

    if (Array.isArray(group.admins)) {
      group.admins = group.admins.filter(a => a !== member || a === group.admin);
    }

    await group.save();

    for (const m of group.members) {
      io.to(m).emit("group-updated", group);
    }
    io.to(member).emit("group-updated", group);

    return res.json({ ok: true, group });
  } catch (err) {
    console.log(err);
    res.status(500).json({ ok: false, msg: "Remove member failed" });
  }
});

app.post("/group/:id/edit-name", async (req, res) => {
  try {
    const { admin, name } = req.body;
    const groupId = req.params.id;

    if (!name || !name.trim()) {
      return res.status(400).json({ ok: false, msg: "Group name required" });
    }

    const group = await Group.findById(groupId);
    if (!group) return res.status(404).json({ ok: false, msg: "Group not found" });
    if (group.admin !== admin) return res.status(403).json({ ok: false, msg: "Only admin allowed" });

    group.name = name.trim();
    await group.save();

    for (const m of group.members) {
      io.to(m).emit("group-updated", group);
    }

    return res.json({ ok: true, group });
  } catch (err) {
    console.log(err);
    res.status(500).json({ ok: false, msg: "Edit name failed" });
  }
});

app.post("/group/:id/edit-dp", (req, res) => {
  upload.single("dp")(req, res, async err => {
    if (err) return sendUploadError(res, err);

    try {
      const { admin } = req.body;
      const groupId = req.params.id;

      if (!req.file) return res.status(400).json({ ok: false, msg: "No file uploaded" });
      if (!isImageFile(req.file)) return res.status(400).json({ ok: false, msg: "Only images allowed" });

      const group = await Group.findById(groupId);
      if (!group) return res.status(404).json({ ok: false, msg: "Group not found" });
      if (group.admin !== admin) return res.status(403).json({ ok: false, msg: "Only admin allowed" });

      group.dp = "/uploads/" + req.file.filename;
      await group.save();

      for (const m of group.members) {
        io.to(m).emit("group-updated", group);
      }

      return res.json({ ok: true, group });
    } catch (e) {
      console.log(e);
      res.status(500).json({ ok: false, msg: "Edit group dp failed" });
    }
  });
});

app.post("/delete-group", async (req, res) => {
  try {
    const { groupId, admin } = req.body;

    if (!groupId || !admin) {
      return res.status(400).json({ ok: false, msg: "Missing groupId or admin" });
    }

    const group = await Group.findById(groupId);
    if (!group) {
      return res.status(404).json({ ok: false, msg: "Group not found" });
    }

    if (group.admin !== admin) {
      return res.status(403).json({ ok: false, msg: "Only admin can delete group" });
    }

    await Message.deleteMany({ group: String(groupId) });
    await Group.deleteOne({ _id: groupId });

    io.to(roomNameForGroup(groupId)).emit("group-deleted", { groupId });

    for (const member of group.members) {
      io.to(member).emit("group-deleted", { groupId });
    }

    return res.json({ ok: true, msg: "Group deleted successfully" });
  } catch (err) {
    console.log(err);
    res.status(500).json({ ok: false, msg: "Delete group failed" });
  }
});


app.post("/group/add-members", async (req, res) => {
  try {
    const { groupId, admin, members } = req.body;
    const group = await Group.findById(groupId);
    if (!group) return res.status(404).json({ ok: false, msg: "Group not found" });
    if (group.admin !== admin) return res.status(403).json({ ok: false, msg: "Only admin allowed" });

    const addMembers = Array.isArray(members) ? members.filter(m => isValidUsername(m)) : [];
    group.members = [...new Set([...(group.members || []), ...addMembers])];
    await group.save();

    for (const member of group.members) {
      io.to(member).emit("group-updated", group);
    }

    return res.json({ ok: true, group });
  } catch (err) {
    console.log(err);
    res.status(500).json({ ok: false, msg: "Add members failed" });
  }
});

app.post("/group/remove-member", async (req, res) => {
  try {
    const { groupId, admin, member } = req.body;
    const group = await Group.findById(groupId);
    if (!group) return res.status(404).json({ ok: false, msg: "Group not found" });
    if (group.admin !== admin) return res.status(403).json({ ok: false, msg: "Only admin allowed" });
    if (member === group.admin) return res.status(400).json({ ok: false, msg: "Admin cannot be removed" });

    group.members = (group.members || []).filter(m => m !== member);
    await group.save();

    for (const m of group.members) {
      io.to(m).emit("group-updated", group);
    }
    io.to(member).emit("group-updated", group);

    return res.json({ ok: true, group });
  } catch (err) {
    console.log(err);
    res.status(500).json({ ok: false, msg: "Remove member failed" });
  }
});


app.get("/groups-last-msg", async (req, res) => {
  try {
    const user = req.query.user;
    const groups = await Group.find({ members: user });
    const result = [];

    for (const g of groups) {
      const last = await Message.findOne({ group: String(g._id) }).sort({ createdAt: -1 });
      result.push({
        groupId: String(g._id),
        text: last?.text || "",
        from: last?.from || "",
        fileType: last?.fileType || null
      });
    }

    res.json(result);
  } catch (err) {
    console.log(err);
    res.json([]);
  }
});

app.post("/join-group-by-invite", async (req, res) => {
  try {
    const { inviteCode, user } = req.body;

    if (!inviteCode || !user) {
      return res.status(400).json({ ok: false, msg: "Missing invite code or user" });
    }

    if (!isValidUsername(user)) {
      return res.status(400).json({ ok: false, msg: "Invalid user" });
    }

    const group = await Group.findOne({ inviteCode: String(inviteCode).trim() });
    if (!group) {
      return res.status(404).json({ ok: false, msg: "Invalid invite code" });
    }

    if (!Array.isArray(group.members)) {
      group.members = [];
    }

    if (!group.members.includes(user)) {
      group.members.push(user);
      group.members = [...new Set(group.members)];
      await group.save();
    }

    io.to(user).emit("group-created", group);

    for (const member of group.members) {
      io.to(member).emit("group-updated", group);
    }

    return res.json({ ok: true, group, msg: "Joined group successfully" });
  } catch (err) {
    console.log(err);
    res.status(500).json({ ok: false, msg: "Join group failed" });
  }
});

app.post("/group/:id/regenerate-invite", async (req, res) => {
  try {
    const groupId = req.params.id;
    const { owner } = req.body;

    if (!groupId || !owner) {
      return res.status(400).json({ ok: false, msg: "Missing groupId or owner" });
    }

    const group = await Group.findById(groupId);
    if (!group) {
      return res.status(404).json({ ok: false, msg: "Group not found" });
    }

    if (!isGroupOwner(group, owner)) {
      return res.status(403).json({ ok: false, msg: "Only owner can regenerate invite code" });
    }

    group.inviteCode = generateInviteCode();
    await group.save();

    for (const member of group.members || []) {
      io.to(member).emit("group-updated", group);
    }

    return res.json({ ok: true, group, inviteCode: group.inviteCode, msg: "Invite code regenerated" });
  } catch (err) {
    console.log(err);
    res.status(500).json({ ok: false, msg: "Regenerate invite failed" });
  }
});


app.get("/search-messages", async (req, res) => {
  try {
    const { type, user, peer, groupId, q } = req.query;
    const query = (q || "").trim();

    if (!query) return res.json({ ok: true, messages: [] });

    let filter = { text: { $regex: query, $options: "i" } };

    if (type === "private") {
      filter.$or = [{ from: user, to: peer }, { from: peer, to: user }];
    } else if (type === "group") {
      filter.group = groupId;
    } else {
      return res.status(400).json({ ok: false, msg: "Invalid search type" });
    }

    const messages = await Message.find(filter).sort({ createdAt: -1 }).limit(100);
    res.json({ ok: true, messages });
  } catch (err) {
    console.log(err);
    res.status(500).json({ ok: false, msg: "Search failed" });
  }
});

app.get("/messages/private", async (req, res) => {
  try {
    const user1 = normalizeUsername(req.query.user1);
    const user2 = normalizeUsername(req.query.user2);
    const before = req.query.before ? new Date(req.query.before) : null;
    const limit = Math.min(parseInt(req.query.limit, 10) || 30, 100);

    if (!isValidUsername(user1) || !isValidUsername(user2)) {
      return res.status(400).json({ ok: false, msg: "Invalid users" });
    }

    const filter = {
      $or: [
        { from: user1, to: user2 },
        { from: user2, to: user1 }
      ]
    };

    if (before && !isNaN(before.getTime())) {
      filter.createdAt = { $lt: before };
    }

    const messages = await Message.find(filter)
      .sort({ createdAt: -1 })
      .limit(limit);

    const ordered = messages.reverse();
    const hasMore = messages.length === limit;

    return res.json({
      ok: true,
      messages: ordered,
      hasMore
    });
  } catch (err) {
    console.log("PRIVATE PAGINATION ERROR:", err);
    res.status(500).json({ ok: false, msg: "Failed to load private messages" });
  }
});

app.get("/messages/group", async (req, res) => {
  try {
    const groupId = String(req.query.groupId || "").trim();
    const before = req.query.before ? new Date(req.query.before) : null;
    const limit = Math.min(parseInt(req.query.limit, 10) || 30, 100);

    if (!groupId) {
      return res.status(400).json({ ok: false, msg: "Missing groupId" });
    }

    const filter = { group: groupId };

    if (before && !isNaN(before.getTime())) {
      filter.createdAt = { $lt: before };
    }

    const messages = await Message.find(filter)
      .sort({ createdAt: -1 })
      .limit(limit);

    const ordered = messages.reverse();
    const hasMore = messages.length === limit;

    return res.json({
      ok: true,
      messages: ordered,
      hasMore
    });
  } catch (err) {
    console.log("GROUP PAGINATION ERROR:", err);
    res.status(500).json({ ok: false, msg: "Failed to load group messages" });
  }
});


app.get("/admin/blocked-users", requireAdmin, async (req, res) => {
  try {
    const users = await User.find({ blocked: true }).select("name dp blocked muted");
    res.json({ ok: true, users });
  } catch (err) {
    console.log(err);
    res.status(500).json({ ok: false, users: [] });
  }
});

app.get("/admin/muted-users", requireAdmin, async (req, res) => {
  try {
    const users = await User.find({
      muted: true,
      blocked: { $ne: true }
    }).select("name dp muted");

    res.json({ ok: true, users });
  } catch (err) {
    console.log(err);
    res.status(500).json({ ok: false, users: [] });
  }
});
app.get("/admin/approved-users", requireAdmin, async (req, res) => {
  try {
    const users = await User.find({
      approvalStatus: "approved",
      blocked: { $ne: true },
      name: { $ne: ADMIN_NAME }
    }).select("name dp approvalStatus blocked muted online lastSeen");

    return res.json({ ok: true, users });
  } catch (err) {
    console.log("APPROVED USERS ERROR:", err);
    return res.status(500).json({ ok: false, users: [] });
  }
});
app.get("/admin/pending-users", requireAdmin, async (req, res) => {
  try {
    const users = await User.find({
      approvalStatus: "pending",
      name: { $ne: ADMIN_NAME }
    }).select("name contact dp role approvalStatus");

    res.json({ ok: true, users });
  } catch (err) {
    console.log(err);
    res.status(500).json({ ok: false, users: [] });
  }
});
app.post("/admin/clear-push-subscriptions", async (req, res) => {
  try {
    const { username } = req.body;
    await User.updateOne(
      { name: username },
      { $set: { pushSubscriptions: [] } }
    );
    res.json({ ok: true });
  } catch (err) {
    console.log("CLEAR PUSH SUBSCRIPTIONS ERROR:", err);
    res.status(500).json({ ok: false });
  }
});
app.post("/admin/approve-user", requireAdmin, async (req, res) => {
  try {
    const { username } = req.body;

    const user = await User.findOne({ name: username });
    if (!user) return res.json({ ok: false, msg: "User not found" });

    user.approvalStatus = "approved";
    user.role = "user";
    user.blocked = false;
    user.rejectCooldownUntil = null;
    user.lastRejectedAt = null;

    user.notifications = Array.isArray(user.notifications) ? user.notifications : [];
    user.notifications.push({
      text: "Shravan accepted your request",
      read: false,
      createdAt: new Date()
    });

    await user.save();

    io.to(username).emit("approval-approved", {
      msg: "Shravan accepted your request"
    });

    io.to(ADMIN_NAME).emit("approval-list-updated");
    await emitUsersToAll();

    res.json({ ok: true });
  } catch (err) {
    console.log("APPROVE USER ERROR:", err);
    res.status(500).json({ ok: false });
  }
});
app.post("/admin/reject-user", requireAdmin, async (req, res) => {
  try {
    const { username } = req.body;

    if (!username || username === ADMIN_NAME) {
      return res.status(400).json({ ok: false, msg: "Invalid user" });
    }

    const cooldownUntil = new Date(Date.now() + 60 * 60 * 1000);

    const user = await User.findOne({ name: username });
    if (!user) {
      return res.json({ ok: false, msg: "User not found" });
    }

    user.approvalStatus = "rejected";
    user.role = "user";
    user.online = false;
    user.authToken = null;
    user.rejectCooldownUntil = cooldownUntil;
    user.lastRejectedAt = new Date();

    user.notifications = Array.isArray(user.notifications) ? user.notifications : [];
    user.notifications.push({
      text: "Shravan rejected your request",
      read: false,
      createdAt: new Date()
    });

    await user.save();

    io.to(username).emit("approval-rejected", {
      msg: "Shravan rejected your request. 1 hour tharuvatha malli request pettu."
    });

    io.to(username).emit("force-logout", {
      msg: "Shravan rejected your access"
    });

    io.to(ADMIN_NAME).emit("approval-list-updated");
    await emitUsersToAll();

    res.json({ ok: true });
  } catch (err) {
    console.log("REJECT USER ERROR:", err);
    res.status(500).json({ ok: false });
  }
});
app.post("/admin/message/edit", requireAdmin, async (req, res) => {
  try {
    const { messageId, text } = req.body;

    if (!messageId) {
      return res.status(400).json({ ok: false, msg: "Message ID missing" });
    }

    const cleanText = sanitizeText(text || "", 2000);
    if (!cleanText) {
      return res.status(400).json({ ok: false, msg: "Message text required" });
    }

    const msg = await Message.findById(messageId);
    if (!msg) {
      return res.status(404).json({ ok: false, msg: "Message not found" });
    }

    if (msg.file) {
      return res.status(400).json({ ok: false, msg: "Media messages cannot be edited" });
    }

    msg.text = cleanText;
    await msg.save();

    if (msg.group) {
      io.to(roomNameForGroup(msg.group)).emit("message-admin-updated", {
        type: "edit",
        messageId: msg._id,
        groupId: msg.group
      });
    } else {
      io.to(msg.from).emit("message-admin-updated", {
        type: "edit",
        messageId: msg._id,
        userA: msg.from,
        userB: msg.to
      });
      io.to(msg.to).emit("message-admin-updated", {
        type: "edit",
        messageId: msg._id,
        userA: msg.from,
        userB: msg.to
      });
    }

    return res.json({ ok: true, msg: "Message edited" });
  } catch (err) {
    console.log("ADMIN MESSAGE EDIT ERROR:", err);
    return res.status(500).json({ ok: false, msg: "Edit failed" });
  }
});

app.post("/admin/message/delete", requireAdmin, async (req, res) => {
  try {
    const { messageId } = req.body;

    if (!messageId) {
      return res.status(400).json({ ok: false, msg: "Message ID missing" });
    }

    const msg = await Message.findById(messageId);
    if (!msg) {
      return res.status(404).json({ ok: false, msg: "Message not found" });
    }

    const filePath = msg.file ? path.join(__dirname, "public", msg.file.replace(/^\/+/, "")) : null;
    const groupId = msg.group || null;
    const fromUser = msg.from || null;
    const toUser = msg.to || null;

    await Message.deleteOne({ _id: messageId });

    if (filePath && fs.existsSync(filePath)) {
      try {
        fs.unlinkSync(filePath);
      } catch (e) {
        console.log("DELETE MESSAGE FILE ERROR:", e);
      }
    }

    if (groupId) {
      io.to(roomNameForGroup(groupId)).emit("message-admin-updated", {
        type: "delete",
        messageId,
        groupId
      });
    } else {
      if (fromUser) {
        io.to(fromUser).emit("message-admin-updated", {
          type: "delete",
          messageId,
          userA: fromUser,
          userB: toUser
        });
      }

      if (toUser) {
        io.to(toUser).emit("message-admin-updated", {
          type: "delete",
          messageId,
          userA: fromUser,
          userB: toUser
        });
      }
    }

    return res.json({ ok: true, msg: "Message deleted" });
  } catch (err) {
    console.log("ADMIN MESSAGE DELETE ERROR:", err);
    return res.status(500).json({ ok: false, msg: "Delete failed" });
  }
});
app.post("/admin/block-user", async (req, res) => {
  try {
    const { admin, username } = req.body;
    if (admin !== ADMIN_NAME) return res.status(403).json({ ok: false, msg: "Only admin allowed" });

    const user = await User.findOneAndUpdate(
      { name: username },
      { blocked: true, online: false },
      { new: true }
    );

    if (!user) return res.json({ ok: false, msg: "User not found" });

    io.to(username).emit("force-logout", { msg: "Admin blocked your account" });
    await emitUsersToAll();
    return res.json({ ok: true });
  } catch (err) {
    console.log(err);
    res.status(500).json({ ok: false });
  }
});
app.get("/api/call-history", async (req, res) => {
  try {
    const user = normalizeUsername(req.query.user);

    if (!isValidUsername(user)) {
      return res.status(400).json({ ok: false, calls: [] });
    }

    const calls = await Call.find({
      $or: [{ from: user }, { to: user }]
    })
      .sort({ createdAt: -1 })
      .limit(100);

    return res.json({ ok: true, calls });
  } catch (err) {
    console.log("CALL HISTORY ERROR:", err);
    return res.status(500).json({ ok: false, calls: [] });
  }
});
app.post("/admin/unblock-user", async (req, res) => {
  try {
    const { admin, username } = req.body;
    if (admin !== ADMIN_NAME) return res.status(403).json({ ok: false, msg: "Only admin allowed" });

    const user = await User.findOneAndUpdate(
      { name: username },
      { blocked: false, approvalStatus: "approved" },
      { new: true }
    );

    if (!user) return res.json({ ok: false, msg: "User not found" });

    io.to(username).emit("unblocked", { msg: "Shravan unblocked your account" });
    await emitUsersToAll();
    return res.json({ ok: true });
  } catch (err) {
    console.log(err);
    res.status(500).json({ ok: false });
  }
});

app.post("/admin/mute-user", async (req, res) => {
  try {
    const { admin, username } = req.body;
    if (admin !== ADMIN_NAME) return res.status(403).json({ ok: false, msg: "Only admin allowed" });

    const user = await User.findOneAndUpdate(
      { name: username },
      { muted: true },
      { new: true }
    );

    if (!user) return res.json({ ok: false, msg: "User not found" });

    io.to(username).emit("muted-by-admin", { msg: "Shravan muted your account" });
    await emitUsersToAll();
    return res.json({ ok: true });
  } catch (err) {
    console.log(err);
    res.status(500).json({ ok: false });
  }
});

app.post("/admin/unmute-user", async (req, res) => {
  try {
    const { admin, username } = req.body;
    if (admin !== ADMIN_NAME) return res.status(403).json({ ok: false, msg: "Only Shravan allowed" });

    const user = await User.findOneAndUpdate(
      { name: username },
      { muted: false },
      { new: true }
    );

    if (!user) return res.json({ ok: false, msg: "User not found" });

    io.to(username).emit("unmuted-by-admin", { msg: "Shravan unmuted your account" });
    await emitUsersToAll();
    return res.json({ ok: true });
  } catch (err) {
    console.log(err);
    res.status(500).json({ ok: false });
  }
});

app.get("/test", (req, res) => {
  res.send("SERVER OK");
});

app.get("/api-check", (req, res) => {
  res.json({ ok: true, msg: "API working" });
});

app.post("/api/forgot-password/request", async (req, res) => {
  try {
    const identifier = String(req.body.identifier || "").trim();

    if (!identifier) {
      return res.json({ ok: false, msg: "Enter username or contact" });
    }

    const user = await findUserByNameOrContact(identifier);

    if (!user) {
      return res.json({ ok: false, msg: "User not found" });
    }

    if (user.blocked) {
      return res.json({ ok: false, msg: "This account is blocked" });
    }

    const otp = generateOtp();
    user.resetOtp = otp;
    user.resetOtpExpiresAt = new Date(Date.now() + 5 * 60 * 1000);
    await user.save();

    console.log(`FORGOT PASSWORD OTP for ${user.name}: ${otp}`);

    return res.json({
      ok: true,
      msg: "OTP sent successfully",
      otp, // production lo remove cheyyi
      username: user.name,
      contact: user.contact || ""
    });
  } catch (err) {
    console.log("FORGOT PASSWORD REQUEST ERROR:", err);
    return res.status(500).json({ ok: false, msg: "Server error" });
  }
});

app.post("/api/forgot-password/verify", async (req, res) => {
  try {
    const identifier = String(req.body.identifier || "").trim();
    const otp = String(req.body.otp || "").trim();

    if (!identifier || !otp) {
      return res.json({ ok: false, msg: "Enter username/contact and OTP" });
    }

    const user = await findUserByNameOrContact(identifier);

    if (!user) {
      return res.json({ ok: false, msg: "User not found" });
    }

    if (!user.resetOtp || !user.resetOtpExpiresAt) {
      return res.json({ ok: false, msg: "Generate OTP first" });
    }

    if (Date.now() > new Date(user.resetOtpExpiresAt).getTime()) {
      user.resetOtp = "";
      user.resetOtpExpiresAt = null;
      await user.save();
      return res.json({ ok: false, msg: "OTP expired. Request again." });
    }

    if (otp !== user.resetOtp) {
      return res.json({ ok: false, msg: "Invalid OTP" });
    }

    return res.json({
      ok: true,
      msg: "OTP verified successfully"
    });
  } catch (err) {
    console.log("FORGOT PASSWORD VERIFY ERROR:", err);
    return res.status(500).json({ ok: false, msg: "Server error" });
  }
});

app.post("/api/forgot-password/reset", async (req, res) => {
  try {
    const identifier = String(req.body.identifier || "").trim();
    const otp = String(req.body.otp || "").trim();
    const newPassword = String(req.body.newPassword || "");
    const confirmPassword = String(req.body.confirmPassword || "");

    if (!identifier || !otp || !newPassword || !confirmPassword) {
      return res.json({ ok: false, msg: "Fill all fields" });
    }

    const user = await findUserByNameOrContact(identifier);

    if (!user) {
      return res.json({ ok: false, msg: "User not found" });
    }

    if (!user.resetOtp || !user.resetOtpExpiresAt) {
      return res.json({ ok: false, msg: "Generate OTP first" });
    }

    if (Date.now() > new Date(user.resetOtpExpiresAt).getTime()) {
      user.resetOtp = "";
      user.resetOtpExpiresAt = null;
      await user.save();
      return res.json({ ok: false, msg: "OTP expired. Request again." });
    }

    if (otp !== user.resetOtp) {
      return res.json({ ok: false, msg: "Invalid OTP" });
    }

    if (!isStrongPassword(newPassword)) {
      return res.json({
        ok: false,
        msg: "Password must be at least 8 characters and include uppercase, lowercase, number and special character."
      });
    }

    if (newPassword !== confirmPassword) {
      return res.json({ ok: false, msg: "Passwords do not match" });
    }

    user.password = await bcrypt.hash(newPassword, 10);
    user.pin = "";
    user.resetOtp = "";
    user.resetOtpExpiresAt = null;
    user.loginAttempts = 0;
    user.lockUntil = null;
    user.authToken = null;

    user.notifications = Array.isArray(user.notifications) ? user.notifications : [];
    user.notifications.push({
      text: "Your password was reset successfully",
      read: false,
      createdAt: new Date()
    });

    await user.save();

    return res.json({
      ok: true,
      msg: "Password reset successful"
    });
  } catch (err) {
    console.log("FORGOT PASSWORD RESET ERROR:", err);
    return res.status(500).json({ ok: false, msg: "Server error" });
  }
});
function makeLoginOtp(){
  return String(Math.floor(100000 + Math.random() * 900000));
}

function loginOtpKey(name){
  return String(name || "").trim().toLowerCase();
}

function escapeLoginRegex(text){
  return String(text || "").replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

async function findLoginUserByName(name){
  const clean = normalizeUsername(name);
  if(!clean) return null;

  return await User.findOne({
    name: { $regex: new RegExp("^" + escapeLoginRegex(clean) + "$", "i") }
  });
}

async function isLoginPasswordMatched(user, password){
  if(!user || !password) return false;

  const candidate = String(password || "");

  if(user.password && String(user.password).startsWith("$2")){
    return await bcrypt.compare(candidate, user.password);
  }

  if(user.pin && String(user.pin).startsWith("$2")){
    return await bcrypt.compare(candidate, user.pin);
  }

  return false;
}

function sendOtpLoginError(res, status, msg, extra = {}){
  return res.status(status).json({
    ok:false,
    msg,
    message:msg,
    ...extra
  });
}

app.post("/api/login/request-otp", async (req, res) => {
  try{
    const name = normalizeUsername(req.body.name);
    const password = String(req.body.password || "");

    if(!isValidUsername(name) || !password){
      return sendOtpLoginError(res, 400, "Enter username and password");
    }

    const user = await findLoginUserByName(name);

    if(!user){
      return sendOtpLoginError(res, 404, "User not found. Send request first.");
    }

    if(isLockedUser(user)){
      return sendOtpLoginError(
        res,
        423,
        `Too many wrong attempts. Try again in ${minutesRemaining(user.lockUntil)} minute(s).`
      );
    }

    if(user.blocked){
      return sendOtpLoginError(res, 403, "Shravan blocked your account");
    }

    if(user.approvalStatus === "pending"){
      return sendOtpLoginError(res, 403, "Your request is waiting for Shravan's approval.", { pending:true });
    }

    if(user.approvalStatus === "rejected"){
      return sendOtpLoginError(res, 403, "Your request was rejected by Shravan.");
    }

    const passwordMatched = await isLoginPasswordMatched(user, password);

    if(!passwordMatched){
      user.loginAttempts = (user.loginAttempts || 0) + 1;

      if(user.loginAttempts >= 3){
        user.lockUntil = new Date(Date.now() + 24 * 60 * 1000);
        user.loginAttempts = 0;
        await user.save();

        return sendOtpLoginError(
          res,
          423,
          "Enduku endukuuu koduthavu anni sarluu worng gaa😏. Try again after 24 minutes."
        );
      }

      const attemptsLeft = 3 - user.loginAttempts;
      await user.save();
      return sendOtpLoginError(res, 401, `Wrong password. ${attemptsLeft} attempt(s) left.`);
    }

    user.loginAttempts = 0;
    user.lockUntil = null;
    await user.save();

    const otp = makeLoginOtp();

    loginOtpStore.set(loginOtpKey(user.name), {
      otp,
      userId:user._id.toString(),
      requestedAt:Date.now(),
      expiresAt:Date.now() + 30 * 1000
    });

    console.log(`LOGIN OTP for ${user.name}: ${otp}`);

    return res.json({
      ok:true,
      msg:"OTP sent successfully",
      message:"OTP sent successfully",
      otp,
      devOtp:otp,
      expiresIn:30
    });
  }catch(err){
    console.log("LOGIN REQUEST OTP ERROR:", err);
    return sendOtpLoginError(res, 500, "Server error");
  }
});

app.post("/api/login/verify-otp", async (req, res) => {
  try{
    const name = normalizeUsername(req.body.name);
    const password = String(req.body.password || "");
    const otp = String(req.body.otp || "").trim();

    if(!isValidUsername(name) || !password || !otp){
      return sendOtpLoginError(res, 400, "Username, password and OTP required");
    }

    const savedOtp = loginOtpStore.get(loginOtpKey(name));

    if(!savedOtp){
      return sendOtpLoginError(res, 400, "OTP not requested. Click Get OTP first.");
    }

    if(Date.now() > savedOtp.expiresAt){
      loginOtpStore.delete(loginOtpKey(name));
      return sendOtpLoginError(res, 400, "OTP expired. Request again.");
    }

    if(String(savedOtp.otp) !== otp){
      return sendOtpLoginError(res, 400, "Invalid OTP");
    }

    const user = await User.findById(savedOtp.userId);

    if(!user){
      loginOtpStore.delete(loginOtpKey(name));
      return sendOtpLoginError(res, 404, "User not found");
    }

    if(user.blocked){
      loginOtpStore.delete(loginOtpKey(name));
      return sendOtpLoginError(res, 403, "Shravan blocked your account");
    }

    if(user.approvalStatus === "pending"){
      loginOtpStore.delete(loginOtpKey(name));
      return sendOtpLoginError(res, 403, "Your request is waiting for Shravan's approval.", { pending:true });
    }

    if(user.approvalStatus === "rejected"){
      loginOtpStore.delete(loginOtpKey(name));
      return sendOtpLoginError(res, 403, "Your request was rejected by Shravan.");
    }

    const passwordMatched = await isLoginPasswordMatched(user, password);

    if(!passwordMatched){
      return sendOtpLoginError(res, 401, "Wrong password");
    }

    if(user.name === ADMIN_NAME || user.role === "admin"){
      user.role = "admin";
      user.approvalStatus = "approved";
    }

    const token = generateAuthToken();
    const session = attachNewSession(user, req, token);
    user.authToken = token;
    user.online = true;
    user.lastSeen = new Date();
    user.loginAttempts = 0;
    user.lockUntil = null;

    await user.save();
    loginOtpStore.delete(loginOtpKey(name));

    await emitUsersToAll().catch(() => {});

    return res.json({
      ok:true,
      msg:"Login successful",
      message:"Login successful",
      token,
      sessionId: session.sessionId,
      user:{
        id:user._id,
        name:user.name,
        role:user.role || "user",
        dp:user.dp || "/default.png",
        approvalStatus:user.approvalStatus || "approved"
      }
    });
  }catch(err){
    console.log("LOGIN VERIFY OTP ERROR:", err);
    return sendOtpLoginError(res, 500, "Server error");
  }
});

app.post("/api/login", async (req, res) => {
  try {
    const rawName = normalizeUsername(req.body.name);
    const password = String(req.body.password || "");
    const captchaInput = String(req.body.captchaInput || "").trim().toUpperCase();
    const captchaValue = String(req.body.captchaValue || "").trim().toUpperCase();

    if (!isValidUsername(rawName) || !password || !captchaInput || !captchaValue) {
      return res.json({ ok: false, msg: "Enter username, password and captcha" });
    }

    if (captchaInput !== captchaValue) {
      return res.json({ ok: false, msg: "Captcha does not match" });
    }

    const user = await User.findOne({ name: rawName });

    if (!user) {
      return res.json({ ok: false, msg: "User not found. Send request first." });
    }

    if (isLockedUser(user)) {
      return res.json({
        ok: false,
        msg: `chala sarlu try chesavu so, Try again in ${minutesRemaining(user.lockUntil)} minute(s).`
      });
    }

    let passwordMatched = false;

if (!user.password || !String(user.password).startsWith("$2")) {
  return res.json({
    ok: false,
    msg: "Password aithe match aithalee ee account. Please contact Shravan or create a new request."
  });
}

passwordMatched = await bcrypt.compare(password, user.password);
    if (!passwordMatched) {
  user.loginAttempts = (user.loginAttempts || 0) + 1;

  if (user.loginAttempts >= 3) {
    user.lockUntil = new Date(Date.now() + 24 * 60 * 1000);
    user.loginAttempts = 0;
    await user.save();

    return res.json({
      ok: false,
      msg: "Enduku endukuuu koduthavu anni sarluu worng gaa😏. Try again after 24 minutes."
    });
  }

  const attemptsLeft = 3 - user.loginAttempts;

  await user.save();
  return res.json({
    ok: false,
    msg: `Wrong password. ${attemptsLeft} attempt(s) left.`
  });
}

    user.loginAttempts = 0;
    user.lockUntil = null;

    if (user.blocked) {
      await user.save();
      return res.json({
        ok: false,
        msg: "Shravan blocked your account"
      });
    }

    if (user.approvalStatus === "pending") {
      await user.save();
      return res.json({
        ok: false,
        pending: true,
        msg: "Your request is waiting for Shravan's approval."
      });
    }

    if (user.approvalStatus === "rejected") {
      await user.save();
      return res.json({
        ok: false,
        msg: "Your request was rejected by Shravan."
      });
    }

    if (user.name === ADMIN_NAME || user.role === "admin") {
      user.role = "admin";
      user.approvalStatus = "approved";
    }

    const token = generateAuthToken();
    const session = attachNewSession(user, req, token);
    user.authToken = token;
    user.online = true;
    user.lastSeen = new Date();
    await user.save();

    return res.json({
      ok: true,
      user: {
        name: user.name,
        dp: user.dp,
        role: user.role || "user",
        approvalStatus: user.approvalStatus
      },
      token,
      sessionId: session.sessionId
    });
  } catch (err) {
    console.log("LOGIN ERROR:", err);
    return res.status(500).json({ ok: false, msg: "Server error" });
  }
});


let sockets = {};
let userSocketIds = {};


let callState = {};
let pendingCallOffers = {};
const activeGroupCalls = new Map();

function isBusy(user) {
  return !!callState[user];
}

function setCall(userA, userB, status, type) {
  callState[userA] = { peer: userB, status, type, startedAt: new Date() };
  callState[userB] = { peer: userA, status, type, startedAt: new Date() };
}

function clearCall(user) {
  if (!user) return;
  const st = callState[user];
  if (!st) return;
  const peer = st.peer;
  delete callState[user];
  if (peer && callState[peer] && callState[peer].peer === user) {
    delete callState[peer];
  }
}

function extractMentionNames(text = "") {
  const matches = String(text || "").match(/@\[(.*?)\]/g) || [];
  return [...new Set(
    matches
      .map(m => m.replace(/^@\[/, "").replace(/\]$/, "").trim())
      .filter(Boolean)
  )];
}

io.on("connection", socket => {
  socket.on("join", async username => {
    try {
      if (!isValidUsername(username)) return;

      sockets[socket.id] = username;
      socket.join(username);

      if (!userSocketIds[username]) userSocketIds[username] = new Set();
      userSocketIds[username].add(socket.id);
      cancelPresenceOfflineTimer(username);
      presenceHttpPings.set(username, Date.now());

      let user = await User.findOne({ name: username });

      if (!user) {
        user = new User({
          name: username,
          online: true,
          lastSeen: new Date(),
          dp: "/default.png",
          role: username === ADMIN_NAME ? "admin" : "user",
          approvalStatus: username === ADMIN_NAME ? "approved" : "pending"
        });
        await user.save();
      } else {
        user.online = true;
        user.lastSeen = new Date();
        await user.save();
      }

      const myGroups = await Group.find({ members: username }).select("_id");
      myGroups.forEach(g => socket.join(roomNameForGroup(g._id.toString())));

      await emitUsersToAll();
      await emitGroupUnreadForUser(username);
      const pending = callState[username];
      if (pending && pending.status === "ringing" && pending.peer) {
        socket.emit("incoming-call", {
          from: pending.peer,
          type: pending.type || "voice"
        });
      }

      const pendingOffer = pendingCallOffers[username];
      if (pendingOffer) {
        socket.emit("call-offer", {
          from: pendingOffer.from,
          offer: pendingOffer.offer,
          type: pendingOffer.type || "voice"
        });
      }

      for (const [gid, call] of activeGroupCalls.entries()) {
        try {
          const group = await Group.findById(gid).select("name members");
          const members = Array.isArray(group?.members) ? group.members : [];
          if (call && members.includes(username) && !call.members.has(username)) {
            socket.emit("group-call-invite", {
              groupId: gid,
              groupName: group?.name || "Group",
              from: call.host,
              type: call.type || "voice"
            });
          }
        } catch (e) {}
      }
    } catch (err) {
      console.log("JOIN ERROR:", err);
    }
  });

  socket.on("heartbeat", async username => {
    try {
      if (!isValidUsername(username)) return;

      await User.findOneAndUpdate(
        { name: username },
        {
          online: true,
          lastSeen: new Date()
        }
      );
    } catch (err) {
      console.log("HEARTBEAT ERROR:", err);
    }
  });
  socket.on("edit-message", async data => {
  try {
    const { admin, messageId, text } = data || {};

    if (!(await isRealAdmin(admin))) {
      socket.emit("admin-action-error", { msg: "Only admin can edit messages" });
      return;
    }

    const cleanText = sanitizeText(text, 2000);
    if (!cleanText) {
      socket.emit("admin-action-error", { msg: "Message text empty ga undakudadhu" });
      return;
    }

    const msg = await Message.findById(messageId);
    if (!msg) {
      socket.emit("admin-action-error", { msg: "Message not found" });
      return;
    }

    msg.text = cleanText;
    msg.file = null;
    msg.fileType = null;
    msg.edited = true;
    msg.editedAt = new Date();
    msg.deleted = false;
    msg.deletedAt = null;
    msg.deletedBy = null;

    await msg.save();

    if (msg.group) {
      io.to(roomNameForGroup(msg.group)).emit("message-updated", msg);
    } else {
      io.to(msg.from).emit("message-updated", msg);
      io.to(msg.to).emit("message-updated", msg);
    }
  } catch (err) {
    console.log("EDIT MESSAGE ERROR:", err);
    socket.emit("admin-action-error", { msg: "Edit failed" });
  }
});

socket.on("delete-message", async data => {
  try {
    const { admin, messageId } = data || {};

    if (!(await isRealAdmin(admin))) {
      socket.emit("admin-action-error", { msg: "Only admin can delete messages" });
      return;
    }

    const msg = await Message.findById(messageId);
    if (!msg) {
      socket.emit("admin-action-error", { msg: "Message not found" });
      return;
    }

    msg.text = "This message was deleted by admin";
    msg.file = null;
    msg.fileType = null;
    msg.replyTo = null;
    msg.reaction = null;
    msg.edited = false;
    msg.editedAt = null;
    msg.deleted = true;
    msg.deletedAt = new Date();
    msg.deletedBy = admin;

    await msg.save();

    if (msg.group) {
      io.to(roomNameForGroup(msg.group)).emit("message-updated", msg);
    } else {
      io.to(msg.from).emit("message-updated", msg);
      io.to(msg.to).emit("message-updated", msg);
    }
  } catch (err) {
    console.log("DELETE MESSAGE ERROR:", err);
    socket.emit("admin-action-error", { msg: "Delete failed" });
  }
});
  socket.on("join-group", groupId => {
    try {
      if (!groupId) return;
      socket.join(roomNameForGroup(groupId));
    } catch (err) {
      console.log("JOIN GROUP ERROR:", err);
    }
  });

  socket.on("get-unread", async username => {
    try {
      const counts = await calculateUnread(username);
      socket.emit("unread-counts", counts);
      await emitGroupUnreadForUser(username);
    } catch (err) {
      console.log(err);
    }
  });

  socket.on("load-history", async data => {
    try {
      const msgs = await Message.find({
        $or: [
          { from: data.from, to: data.to },
          { from: data.to, to: data.from }
        ]
      }).sort({ createdAt: -1 }).limit(50);

      socket.emit("history", msgs.reverse());
    } catch (err) {
      console.log(err);
    }
  });

  socket.on("load-group-history", async groupId => {
    try {
      const msgs = await Message.find({ group: String(groupId) })
        .sort({ createdAt: -1 })
        .limit(50);

      socket.emit("group-history", msgs.reverse());

      const username = sockets[socket.id];
      if (username) {
        await Message.updateMany(
          {
            group: String(groupId),
            from: { $ne: username },
            seenBy: { $ne: username }
          },
          { $addToSet: { seenBy: username } }
        );

        io.to(roomNameForGroup(groupId)).emit("group-seen-updated", { groupId: String(groupId) });
        await emitGroupUnreadForMembers(groupId);
      }
    } catch (err) {
      console.log("GROUP HISTORY ERROR:", err);
    }
  });

  socket.on("private-message", async data => {
    try {
      const senderUser = await User.findOne({ name: data.from });

      if (senderUser && senderUser.muted) {
        io.to(data.from).emit("user-muted", {
          msg: "Shravan muted you. You cannot send messages."
        });
        return;
      }

      const receiverOnline = !!userSocketIds[data.to]?.size;
      const mentionNames = extractMentionNames(data.text || "");
      const newMsg = new Message({
        from: data.from,
        to: data.to,
        text: data.text ? sanitizeText(data.text, 2000) : null,
        file: data.file || null,
        fileType: data.fileType || null,
        replyTo: data.replyTo || null,
        mentions: mentionNames,
        
        status: receiverOnline ? "delivered" : "sent",
        reaction: null,
        seenBy: [],
        deliveredTo: receiverOnline ? [data.to] : [],
        createdAt: new Date()
        
      });

      await newMsg.save();

      // Native APK background socket sometimes stays "online", so always send FCM/PWA notification.
      // Android app will show real notification with sound; sender never receives duplicate.
      if (data.to !== data.from) {
        await sendAppNotification(data.to, {
          title: data.from,
          body: safeNotificationBody(newMsg),
          url: `/chat.html?user=${encodeURIComponent(data.from)}`,
          tag: `private-${data.from}`,
          icon: "/icons/icon-192.png",
          badge: "/icons/icon-192.png",
          type: "private",
          notificationType: "message",
          canReply: true,
          from: data.from,
          to: data.to,
          sound: "default"
        });
      }

      io.to(data.from).emit("private-message", newMsg);
      io.to(data.to).emit("private-message", newMsg);

      if (receiverOnline) {
        const counts = await calculateUnread(data.to);
        io.to(data.to).emit("unread-counts", counts);
      }
    } catch (err) {
      console.log("PRIVATE MESSAGE ERROR:", err);
    }
  });

  socket.on("group-message", async data => {
    try {
      const senderUser = await User.findOne({ name: data.from });

      if (senderUser && senderUser.muted) {
        io.to(data.from).emit("user-muted", { msg: "Shravan muted you. yevariki messages cheyaniki ledhu." });
        return;
      }

      if (!data.group) return;

      const group = await Group.findById(data.group);
      if (!group) return;
      if (!group.members.includes(data.from)) return;

      const onlineRecipients = group.members.filter(
        member => member !== data.from && userSocketIds[member]?.size
      );
      const rawMentions = extractMentionNames(data.text || "");
      const validMentions = rawMentions.filter(name => group.members.includes(name));
      const newMsg = new Message({
        from: data.from,
        to: null,
        group: String(data.group),
        text: data.text ? sanitizeText(data.text, 2000) : null,
        file: data.file || null,
        fileType: data.fileType || null,
        replyTo: data.replyTo || null,
        mentions: validMentions,
        
        status: "sent",
        reaction: null,
        deliveredTo: onlineRecipients,
        seenBy: [],
        createdAt: new Date()
      });

      await newMsg.save();
      // Native APK may keep socket online in background, so notify every group member except sender.
      const notificationRecipients = group.members.filter(
        member => member !== data.from
      );
      for (const member of notificationRecipients) {
  const isMentioned = validMentions.includes(member);

  await sendAppNotification(member, {
    title: isMentioned ? `🔔 Mention in ${group.name}` : `👥 ${group.name}`,
    body: isMentioned
      ? `${data.from} mentioned you: ${safeNotificationBody(newMsg)}`
      : `${data.from}: ${safeNotificationBody(newMsg)}`,
    url: `/chat.html?group=${encodeURIComponent(String(data.group))}`,
    tag: isMentioned ? `mention-${data.group}-${member}` : `group-${data.group}-${member}`,
    icon: "/icons/icon-192.png",
    badge: "/icons/icon-192.png",
    type: "group",
    notificationType: "message",
    canReply: true,
    from: data.from,
    group: String(data.group),
    sound: "default"
  });
}
// Duplicate offline group push removed. The mention-aware loop above already sends the notification.
      io.to(roomNameForGroup(data.group)).emit("group-message", newMsg);

      

      await emitGroupUnreadForMembers(data.group);
    } catch (err) {
      console.log("GROUP MESSAGE ERROR:", err);
    }
  });

  socket.on("seen", async data => {
    try {
      await Message.updateMany(
        { from: data.from, to: data.to, status: { $ne: "seen" } },
        { status: "seen", $addToSet: { seenBy: data.to } }
      );

      const updated = await Message.find({
        $or: [
          { from: data.from, to: data.to },
          { from: data.to, to: data.from }
        ]
      }).sort({ _id: 1 }).limit(1000);

      io.to(data.from).emit("history", updated);
      io.to(data.to).emit("history", updated);

      const counts = await calculateUnread(data.to);
      io.to(data.to).emit("unread-counts", counts);
    } catch (err) {
      console.log(err);
    }
  });

  socket.on("reaction", async data => {
    try {
      await Message.findByIdAndUpdate(data.messageId, { reaction: data.emoji });
      const updated = await Message.findById(data.messageId);

      if (updated) {
        if (updated.group) {
          io.to(roomNameForGroup(updated.group)).emit("reaction-update", updated);
        } else {
          io.to(updated.from).emit("reaction-update", updated);
          io.to(updated.to).emit("reaction-update", updated);
        }
      }
    } catch (err) {
      console.log(err);
    }
  });

  socket.on("typing", data => {
    if (data.group) {
      io.to(roomNameForGroup(data.group)).emit("group-typing", { from: data.from, group: data.group });
    } else if (data.to) {
      io.to(data.to).emit("typing", data.from);
    }
  });

  socket.on("stop-typing", data => {
    if (data.group) {
      io.to(roomNameForGroup(data.group)).emit("group-stop-typing", { from: data.from, group: data.group });
    } else if (data.to) {
      io.to(data.to).emit("stop-typing", data.from);
    }
  });


  socket.on("start-group-call", async ({ groupId, from, type }) => {
    try {
      if (!groupId || !from) return;

      const group = await Group.findById(groupId).select("name members");
      if (!group) return;

      const members = Array.isArray(group.members) ? group.members : [];
      if (!members.includes(from)) return;

      const callType = type === "video" ? "video" : "voice";

      activeGroupCalls.set(String(groupId), {
        host: from,
        type: callType,
        members: new Set([from]),
        startedAt: Date.now()
      });

      for (const member of members) {
        if (!member || member === from) continue;

        io.to(member).emit("group-call-invite", {
          groupId: String(group._id),
          groupName: group.name || "Group",
          from,
          type: callType
        });

        await sendAppNotification(member, {
          title: callType === "video" ? "📹 Incoming group video call" : "📞 Incoming group voice call",
          body: `${from} is calling in ${group.name || "your group"}`,
          url: `/chat.html?group=${encodeURIComponent(String(group._id))}`,
          tag: `group-call-${group._id}`,
          icon: "/icons/icon-192.png",
          badge: "/icons/icon-192.png",
          type: "call",
          notificationType: "call",
          callType,
          requireInteraction: true,
          sound: "ring",
          vibrate: [300, 120, 300, 120, 500]
        });
      }
    } catch (err) {
      console.log("START GROUP CALL ERROR:", err);
    }
  });

  socket.on("join-group-call", async ({ groupId, user }) => {
    try {
      if (!groupId || !user) return;

      const call = activeGroupCalls.get(String(groupId));
      if (!call) return;

      socket.join(roomNameForGroupCall(groupId));

      const existingMembers = [...call.members].filter(name => name !== user);
      call.members.add(user);
      activeGroupCalls.set(String(groupId), call);

      socket.emit("group-call-members", {
        groupId: String(groupId),
        type: call.type,
        members: existingMembers
      });

      socket.to(roomNameForGroupCall(groupId)).emit("group-call-peer-joined", {
        groupId: String(groupId),
        user
      });
    } catch (err) {
      console.log("JOIN GROUP CALL ERROR:", err);
    }
  });

  socket.on("group-call-offer", ({ groupId, to, from, offer, type }) => {
    io.to(to).emit("group-call-offer", { groupId, from, offer, type });
  });

  socket.on("group-call-answer", ({ groupId, to, from, answer }) => {
    io.to(to).emit("group-call-answer", { groupId, from, answer });
  });

  socket.on("group-call-ice", ({ groupId, to, from, candidate }) => {
    io.to(to).emit("group-call-ice", { groupId, from, candidate });
  });

  socket.on("end-group-call", async ({ groupId, from }) => {
    try {
      const gid = String(groupId || "");
      const active = activeGroupCalls.get(gid);
      activeGroupCalls.delete(gid);

      io.to(roomNameForGroupCall(gid)).emit("group-call-ended", { groupId: gid, from });

      const group = await Group.findById(gid).select("members");
      const members = Array.isArray(group?.members) ? group.members : [...(active?.members || [])];

      for (const member of members) {
        if (!member) continue;
        io.to(member).emit("group-call-ended", { groupId: gid, from });
      }
    } catch (err) {
      console.log("END GROUP CALL ERROR:", err);
    }
  });

  socket.on("leave-group-call", ({ groupId, user }) => {
    try {
      const call = activeGroupCalls.get(String(groupId));
      if (!call) return;

      call.members.delete(user);
      socket.leave(roomNameForGroupCall(groupId));
      io.to(roomNameForGroupCall(groupId)).emit("group-call-peer-left", {
        groupId: String(groupId),
        user
      });

      if (call.members.size === 0) {
        activeGroupCalls.delete(String(groupId));
      } else {
        activeGroupCalls.set(String(groupId), call);
      }
    } catch (err) {
      console.log("LEAVE GROUP CALL ERROR:", err);
    }
  });

  socket.on("call-user", async ({ to, from, type }) => {
  try {
    to = normalizeUsername(to);
    from = normalizeUsername(from);
    const callType = type === "video" ? "video" : "voice";

    if (!to || !from || to === from) {
      socket.emit("call-unavailable", { to, reason: "invalid" });
      return;
    }

    if (isBusy(from)) {
      socket.emit("call-busy", { to, reason: "you_busy" });
      socket.emit("call-unavailable", { to, reason: "you_busy" });
      return;
    }

    if (isBusy(to)) {
      socket.emit("call-busy", { to, reason: "user_busy" });
      socket.emit("call-unavailable", { to, reason: "user_busy" });
      return;
    }

    setCall(from, to, "ringing", callType);

    io.to(from).emit("call-ringing", { to, type: callType });

    // socket online unte immediate app popup; offline/background ki FCM full-screen notification.
    io.to(to).emit("incoming-call", { from, type: callType });

    await sendAppNotification(to, {
      title: callType === "video" ? "📹 Incoming video call" : "📞 Incoming voice call",
      body: `${from} is calling you`,
      url: `/chat.html?user=${encodeURIComponent(from)}&call=1`,
      tag: `incoming-call-${from}-${Date.now()}`,
      icon: "/icons/icon-192.png",
      badge: "/icons/icon-192.png",
      type: "call",
      notificationType: "call",
      callType,
      requireInteraction: true,
      sound: "ring",
      from,
      to
    });

    setTimeout(async () => {
      try {
        if (callState[from] && callState[from].status === "ringing") {
          clearCall(from);
          delete pendingCallOffers[to];
          delete pendingCallOffers[from];

          await Call.create({
            from,
            to,
            type: callType,
            status: "missed",
            time: formatTime()
          });

          await pushCallMessage(
            from,
            to,
            callType === "video" ? "🎥 Missed video call" : "📞 Missed voice call"
          );

          io.to(from).emit("call-unavailable", { to, reason: "missed" });

          await sendAppNotification(to, {
            title: "Missed call",
            body: `${from} called you`,
            url: `/chat.html?user=${encodeURIComponent(from)}`,
            tag: `missed-call-${from}-${Date.now()}`,
            icon: "/icons/icon-192.png",
            badge: "/icons/icon-192.png",
            type: "call",
            notificationType: "call",
            callType,
            sound: "default",
            from,
            to
          });
        }
      } catch (err) {
        console.log("MISSED CALL TIMER ERROR:", err);
      }
    }, 30000);
  } catch (e) {
    console.log("call-user error", e);
    socket.emit("call-unavailable", { to, reason: "error" });
  }
});

 socket.on("call-offer", ({ to, from, offer, type }) => {
  to = normalizeUsername(to);
  from = normalizeUsername(from);
  if (!to || !from || !offer) return;

  const callType =
    (callState[from] && callState[from].type) ||
    (type === "video" ? "video" : "voice");

  if (!callState[from] || callState[from].peer !== to) {
    setCall(from, to, "ringing", callType);
  }

  pendingCallOffers[to] = {
    from,
    offer,
    type: callType,
    createdAt: Date.now()
  };

  io.to(to).emit("call-offer", { from, offer, type: callType });
});

  socket.on("call-answer", async ({ to, from, answer, type }) => {
  try {
    to = normalizeUsername(to);
    from = normalizeUsername(from);
    if (!to || !from || !answer) return;

    const callType =
      (callState[from] && callState[from].type) ||
      (callState[to] && callState[to].type) ||
      (type === "video" ? "video" : "voice");

    if (!callState[from] || callState[from].peer !== to) {
      setCall(from, to, "in_call", callType);
    }

    if (callState[from]) callState[from].status = "in_call";
    if (callState[to]) callState[to].status = "in_call";

    delete pendingCallOffers[from];
    delete pendingCallOffers[to];

    io.to(to).emit("call-answer", { from, answer, type: callType });

    await Call.create({
      from: to,
      to: from,
      type: callType,
      status: "completed",
      time: formatTime()
    });
  } catch (err) {
    console.log("CALL ANSWER ERROR:", err);
  }
});

  socket.on("call-ice", ({ to, from, candidate, type }) => {
    to = normalizeUsername(to);
    from = normalizeUsername(from);
    if (!to || !from || !candidate) return;
    const callType =
      (callState[from] && callState[from].type) ||
      (type === "video" ? "video" : "voice");
    io.to(to).emit("call-ice", { from, candidate, type: callType });
  });

  socket.on("call-decline", async ({ to, from }) => {
  try {
    to = normalizeUsername(to);
    from = normalizeUsername(from);
    if (!to || !from) return;

    io.to(to).emit("call-unavailable", { to: from, reason: "declined" });
    io.to(to).emit("call-end", { from });

    clearCall(from);
    clearCall(to);
    delete pendingCallOffers[from];
    delete pendingCallOffers[to];

    await Call.create({
      from: to,
      to: from,
      type: "voice",
      status: "declined",
      time: formatTime()
    });
  } catch (err) {
    console.log("CALL DECLINE ERROR:", err);
  }
});

  socket.on("call-end", async ({ to, from }) => {
  try {
    io.to(to).emit("call-end", { from });

    const st = callState[from];
    const callType = st?.type || "voice";

    delete pendingCallOffers[from];
    delete pendingCallOffers[to];

    clearCall(from);

    await Call.create({
      from,
      to,
      type: callType,
      status: "ended",
      time: formatTime()
    });

    await pushCallMessage(
      from,
      to,
      callType === "video" ? "🎥 Call ended" : "📞 Call ended"
    );
  } catch (err) {
    console.log(err);
  }
});

  socket.on("disconnect", async () => {
    try {
      const username = sockets[socket.id];

      if (username) {
        if (userSocketIds[username]) {
          userSocketIds[username].delete(socket.id);
          if (userSocketIds[username].size === 0) {
            delete userSocketIds[username];
          }
        }

        if (callState[username]) {
          const peer = callState[username].peer;
          io.to(peer).emit("call-end", { from: username });
          clearCall(username);
          delete pendingCallOffers[username];
          if (peer) delete pendingCallOffers[peer];
        }

        for (const [gid, call] of activeGroupCalls.entries()) {
          if (!call?.members?.has(username)) continue;

          if (call.host === username) {
            io.to(roomNameForGroupCall(gid)).emit("group-call-ended", {
              groupId: String(gid),
              from: username
            });
            activeGroupCalls.delete(gid);
          } else {
            call.members.delete(username);
            io.to(roomNameForGroupCall(gid)).emit("group-call-peer-left", {
              groupId: String(gid),
              user: username
            });

            if (call.members.size === 0) {
              activeGroupCalls.delete(gid);
            } else {
              activeGroupCalls.set(gid, call);
            }
          }
        }

        delete sockets[socket.id];

        if (!userSocketIds[username] || userSocketIds[username].size === 0) {
          schedulePresenceOffline(username);
        } else {
          await emitUsersToAll();
        }
      }
    } catch (err) {
      console.log(err);
    }
  });
});


const PORT = process.env.PORT || 5000;
server.listen(PORT, "0.0.0.0", () => {
  console.log(`Server running on port ${PORT}`);
});