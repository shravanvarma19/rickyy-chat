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
/* ---------- CONFIG ---------- */
const ADMIN_NAME = "shravan";
const MAX_FILE_SIZE = 15 * 1024 * 1024;

/* ---------- EXPRESS APP ---------- */
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

/* ---------- ENSURE UPLOADS FOLDER ---------- */
const uploadDir = path.join(__dirname, "public", "uploads");
if (!fs.existsSync(uploadDir)) {
  fs.mkdirSync(uploadDir, { recursive: true });
}

/* ---------- MONGODB CONNECT ---------- */
if (!process.env.MONGODB_URI) {
  console.log("MongoDB Error: MONGODB_URI is missing in .env file");
} else {
  mongoose.connect(process.env.MONGODB_URI, {
    serverSelectionTimeoutMS: 30000
  })
    .then(() => console.log("MongoDB Connected"))
    .catch(err => console.log("MongoDB Error:", err));
}

function formatTime(date = new Date()) {
  let hours = date.getHours();
  const minutes = String(date.getMinutes()).padStart(2, "0");
  const ampm = hours >= 12 ? "PM" : "AM";
  hours = hours % 12;
  hours = hours === 0 ? 12 : hours;
  return `${String(hours).padStart(2, "0")}:${minutes} ${ampm}`;
}
function generateAuthToken(){
  return crypto.randomBytes(32).toString("hex");
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

function isImageFile(file) {
  return file && file.mimetype && file.mimetype.startsWith("image/");
}

/* ---------- SCHEMAS ---------- */
const userSchema = new mongoose.Schema({
  name: { type: String, unique: true },
  pin: String,
  online: { type: Boolean, default: false },
  lastSeen: { type: Date, default: null },
  dp: { type: String, default: "/default.png" },
  role: { type: String, default: "user" },
  approvalStatus: { type: String, default: "pending" },
  blocked: { type: Boolean, default: false },
  muted: { type: Boolean, default: false },
  bio: { type: String, default: "" },
  about: { type: String, default: "" },
  loginAttempts: { type: Number, default: 0 },
  lockUntil: { type: Date, default: null },
   authToken: { type: String, default: null }
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
  time: String,
  status: String,
  reaction: String,
  seenBy: [String],
  deliveredTo: [String],
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

/* ---------- HOME ROUTE ---------- */
app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

app.get("/debug-files", (req, res) => {
  fs.readdir(uploadDir, (err, files) => {
    if (err) return res.status(500).json({ ok: false, error: err.message });
    res.json({ ok: true, files });
  });
});

/* ---------- SERVER + SOCKET ---------- */
const io = new Server(server, {
  cors: {
    origin: true,
    methods: ["GET", "POST", "OPTIONS"],
    credentials: false
  }
});

/* ---------- MULTER ---------- */
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, uploadDir),
  filename: (req, file, cb) => {
    const safeExt = path.extname(file.originalname || "").toLowerCase();
    cb(null, Date.now() + safeExt);
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

/* ---------- HELPERS ---------- */
async function getUsers() {
  return await User.find({ blocked: { $ne: true } });
}

async function isUserOnline(username) {
  const u = await User.findOne({ name: username });
  return !!(u && u.online);
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
    time: formatTime(),
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

function roomNameForGroup(groupId) {
  return "group_" + String(groupId);
}

function sendUploadError(res, err) {
  if (err instanceof multer.MulterError) {
    return res.status(400).json({ status: "error", msg: err.message });
  }
  return res.status(400).json({ status: "error", msg: err.message || "Upload failed" });
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

/* ---------- MEDIA UPLOAD ---------- */
app.post("/upload-media", (req, res) => {
  upload.single("file")(req, res, err => {
    if (err) return sendUploadError(res, err);
    try {
      if (!req.file) return res.status(400).json({ status: "no_file" });
      res.json({ status: "ok", filePath: "/uploads/" + req.file.filename });
    } catch (e) {
      console.log(e);
      res.status(500).json({ status: "error" });
    }
  });
});

/* ---------- USER DP UPLOAD ---------- */
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

/* ---------- STATUS ---------- */
app.post("/upload-status", (req, res) => {
  upload.single("file")(req, res, async err => {
    if (err) return sendUploadError(res, err);

    try {
      const username = normalizeUsername(req.body.username);
      if (!isValidUsername(username)) {
        return res.status(400).json({ status: "error", msg: "Invalid username" });
      }

      if (!req.file) return res.status(400).json({ status: "no_file" });

      const filePath = "/uploads/" + req.file.filename;
      const ext = (req.file.originalname.split(".").pop() || "").toLowerCase();
      const fileType = ["mp4", "webm", "mov"].includes(ext) ? "video" : "image";

      await Status.create({
        user: username,
        file: filePath,
        fileType,
        viewers: [],
        reactions: []
      });

      io.emit("status-update");
      res.json({ status: "ok", filePath, fileType });
    } catch (e) {
      console.log(e);
      res.status(500).json({ status: "error" });
    }
  });
});

app.get("/statuses", async (req, res) => {
  try {
    const now = new Date();
    const list = await Status.find({ expiresAt: { $gt: now } }).sort({ createdAt: -1 });
    res.json(list);
  } catch (err) {
    console.log(err);
    res.status(500).json([]);
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
      await User.findOneAndUpdate(
        { authToken: token },
        { $unset: { authToken: 1 } }
      );
    }

    await emitUsersToAll();
    res.json({ ok: true });
  } catch (err) {
    console.log("LOGOUT ERROR:", err);
    res.status(500).json({ ok: false });
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

    return res.json({
      ok: true,
      user: {
        name: user.name,
        dp: user.dp,
        role: user.role || "user"
      }
    });
  } catch (err) {
    console.log("API ME ERROR:", err);
    res.status(500).json({ ok: false, msg: "Server error" });
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
      time: formatTime(),
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
    if (!statusId || !user) return res.status(400).json({ ok: false });

    const st = await Status.findById(statusId);
    if (!st) return res.json({ ok: false, msg: "not_found" });
    if (st.user !== user) return res.status(403).json({ ok: false, msg: "not_owner" });

    await Status.deleteOne({ _id: statusId });
    io.emit("status-update");
    return res.json({ ok: true });
  } catch (err) {
    console.log(err);
    res.status(500).json({ ok: false });
  }
});

/* ---------- USERS ---------- */
app.get("/users-data", async (req, res) => {
  try {
    const allUsers = await User.find({ blocked: { $ne: true } }).select(
      "name dp role online lastSeen muted bio about"
    );
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

/* ---------- GROUPS ---------- */
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

/* ---------- FRONTEND COMPATIBILITY ROUTES ---------- */
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

/* ---------- GROUP LAST MESSAGE PREVIEW ---------- */
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

/* ---------- MESSAGE SEARCH ---------- */
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

/* ---------- ADMIN ROUTES ---------- */
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

app.get("/admin/pending-users", requireAdmin, async (req, res) => {
  try {
    const users = await User.find({
      approvalStatus: "pending",
      name: { $ne: ADMIN_NAME }
    }).select("name dp role approvalStatus");

    res.json({ ok: true, users });
  } catch (err) {
    console.log(err);
    res.status(500).json({ ok: false, users: [] });
  }
});

app.post("/admin/approve-user", requireAdmin, async (req, res) => {
  try {
    const { username } = req.body;

    const user = await User.findOneAndUpdate(
      { name: username },
      { approvalStatus: "approved", role: "user" },
      { new: true }
    );

    if (!user) return res.json({ ok: false, msg: "User not found" });

    io.to(username).emit("approval-approved", {
      msg: "Admin approved your request"
    });

    io.to(ADMIN_NAME).emit("approval-list-updated");

    res.json({ ok: true });
  } catch (err) {
    console.log(err);
    res.status(500).json({ ok: false });
  }
});

app.post("/admin/reject-user", requireAdmin, async (req, res) => {
  try {
    const { username } = req.body;

    const user = await User.findOneAndUpdate(
      { name: username },
      { approvalStatus: "rejected", role: "user" },
      { new: true }
    );

    if (!user) return res.json({ ok: false, msg: "User not found" });

    io.to(username).emit("approval-rejected", {
      msg: "Admin rejected your request"
    });

    io.to(ADMIN_NAME).emit("approval-list-updated");

    res.json({ ok: true });
  } catch (err) {
    console.log(err);
    res.status(500).json({ ok: false });
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

    io.to(username).emit("unblocked", { msg: "Admin unblocked your account" });
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

    io.to(username).emit("muted-by-admin", { msg: "Admin muted your account" });
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
    if (admin !== ADMIN_NAME) return res.status(403).json({ ok: false, msg: "Only admin allowed" });

    const user = await User.findOneAndUpdate(
      { name: username },
      { muted: false },
      { new: true }
    );

    if (!user) return res.json({ ok: false, msg: "User not found" });

    io.to(username).emit("unmuted-by-admin", { msg: "Admin unmuted your account" });
    await emitUsersToAll();
    return res.json({ ok: true });
  } catch (err) {
    console.log(err);
    res.status(500).json({ ok: false });
  }
});

/* ---------- TEST ---------- */
app.get("/test", (req, res) => {
  res.send("SERVER OK");
});

app.get("/api-check", (req, res) => {
  res.json({ ok: true, msg: "API working" });
});

/* ---------- AUTH ---------- */
app.post("/api/login", async (req, res) => {
  try {
    const rawName = normalizeUsername(req.body.name);
    const pin = String(req.body.pin || "");

    if (!isValidUsername(rawName) || !isValidPin(pin)) {
      return res.json({ ok: false, msg: "Enter valid username and 4 digit PIN" });
    }

    let user = await User.findOne({ name: rawName });

    if (!user) {
      const isAdmin = rawName === ADMIN_NAME;
      const hashedPin = await bcrypt.hash(pin, 10);

      user = new User({
        name: rawName,
        pin: hashedPin,
        online: false,
        lastSeen: null,
        dp: "/default.png",
        role: isAdmin ? "admin" : "user",
        approvalStatus: isAdmin ? "approved" : "pending",
        loginAttempts: 0,
        lockUntil: null,
        authToken: null
      });

      await user.save();

      if (!isAdmin) {
        io.to(ADMIN_NAME).emit("approval-request-added", {
          name: user.name,
          dp: user.dp
        });

        return res.json({
          ok: false,
          pending: true,
          msg: "Request sent to admin. Wait for approval."
        });
      }

      const token = generateAuthToken();
      user.authToken = token;
      await user.save();

      return res.json({
        ok: true,
        user: {
          name: user.name,
          dp: user.dp,
          role: user.role
        },
        token
      });
    }

    if (isLockedUser(user)) {
      return res.json({
        ok: false,
        msg: `Chala sarluu wrong PIN attempts chesavu. ${minutesRemaining(user.lockUntil)} minutes.Tharuvatha try cheai`
      });
    }

    let pinMatched = false;

    if (user.pin && user.pin.startsWith("$2")) {
      pinMatched = await bcrypt.compare(pin, user.pin);
    } else {
      pinMatched = user.pin === pin;
      if (pinMatched) {
        user.pin = await bcrypt.hash(pin, 10);
      }
    }

    if (!pinMatched) {
      user.loginAttempts = (user.loginAttempts || 0) + 1;

      if (user.loginAttempts >= 5) {
        user.lockUntil = new Date(Date.now() + 10 * 60 * 1000);
        user.loginAttempts = 0;
        await user.save();

        return res.json({
          ok: false,
          msg: "Too many wrong PIN attempts. Account locked for 10 minutes."
        });
      }

      await user.save();
      return res.json({
        ok: false,
        msg: `Wrong PIN. ${5 - user.loginAttempts} attempt(s) left.`
      });
    }

    user.loginAttempts = 0;
    user.lockUntil = null;

    if (user.blocked) {
      await user.save();
      return res.json({
        ok: false,
        msg: "Admin blocked your account"
      });
    }

    if (user.name === ADMIN_NAME || user.role === "admin") {
      if (user.role !== "admin" || user.approvalStatus !== "approved") {
        user.role = "admin";
        user.approvalStatus = "approved";
      }

      const token = generateAuthToken();
      user.authToken = token;
      await user.save();

      return res.json({
        ok: true,
        user: {
          name: user.name,
          dp: user.dp,
          role: user.role
        },
        token
      });
    }

    if (user.approvalStatus === "pending") {
      await user.save();
      return res.json({
        ok: false,
        pending: true,
        msg: "Still waiting for admin approval."
      });
    }

    if (user.approvalStatus === "rejected") {
      await user.save();
      return res.json({
        ok: false,
        msg: "Admin rejected your request."
      });
    }

    const token = generateAuthToken();
    user.authToken = token;
    await user.save();

    return res.json({
      ok: true,
      user: {
        name: user.name,
        dp: user.dp,
        role: user.role
      },
      token
    });
  } catch (err) {
    console.log("LOGIN ERROR:", err);
    return res.status(500).json({ ok: false, msg: "Server error" });
  }
});

app.post("/api/logout", async (req, res) => {
  try {
    const { name } = req.body;
    if (!name) return res.json({ ok: false });

    await User.findOneAndUpdate(
      { name },
      { online: false, lastSeen: new Date(), authToken: null }
    );

    await emitUsersToAll();
    res.json({ ok: true });
  } catch (err) {
    console.log(err);
    res.status(500).json({ ok: false });
  }
});

app.get("/api/me", async (req, res) => {
  try {
    const token = String(req.headers.authorization || "")
      .replace("Bearer ", "")
      .trim();

    if (!token) {
      return res.status(401).json({ ok: false, msg: "No token" });
    }

    const user = await User.findOne({
      authToken: token,
      blocked: { $ne: true }
    }).select("name dp role approvalStatus blocked");

    if (!user) {
      return res.status(401).json({ ok: false, msg: "Invalid token" });
    }

    if (user.approvalStatus === "rejected") {
      return res.status(403).json({ ok: false, msg: "Rejected user" });
    }

    return res.json({
      ok: true,
      user: {
        name: user.name,
        dp: user.dp,
        role: user.role
      }
    });
  } catch (err) {
    console.log("API ME ERROR:", err);
    res.status(500).json({ ok: false, msg: "Server error" });
  }
});
/* ---------- SOCKET USERS STORE ---------- */
let sockets = {};
let userSocketIds = {};

/* ---------- CALL STATE ---------- */
let callState = {};

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

/* ---------- SOCKET ---------- */
io.on("connection", socket => {
  socket.on("join", async username => {
    try {
      if (!isValidUsername(username)) return;

      sockets[socket.id] = username;
      socket.join(username);

      if (!userSocketIds[username]) userSocketIds[username] = new Set();
      userSocketIds[username].add(socket.id);

      let user = await User.findOne({ name: username });

      if (!user) {
        user = new User({
          name: username,
          online: true,
          lastSeen: null,
          dp: "/default.png",
          role: username === ADMIN_NAME ? "admin" : "user",
          approvalStatus: username === ADMIN_NAME ? "approved" : "pending"
        });
        await user.save();
      } else {
        user.online = true;
        user.lastSeen = null;
        await user.save();
      }

      const myGroups = await Group.find({ members: username }).select("_id");
      myGroups.forEach(g => socket.join(roomNameForGroup(g._id.toString())));

      await emitUsersToAll();
      await emitGroupUnreadForUser(username);
    } catch (err) {
      console.log("JOIN ERROR:", err);
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
        io.to(data.from).emit("user-muted", { msg: "Admin muted you. You cannot send messages." });
        return;
      }

      const newMsg = new Message({
        from: data.from,
        to: data.to,
        text: data.text ? sanitizeText(data.text, 2000) : null,
        file: data.file || null,
        fileType: data.fileType || null,
        replyTo: data.replyTo || null,
        time: formatTime(),
        status: "sent",
        reaction: null,
        seenBy: [],
        deliveredTo: [],
        createdAt: new Date()
      });

      await newMsg.save();
      io.to(data.from).emit("private-message", newMsg);

      const receiver = await User.findOne({ name: data.to });
      if (receiver && receiver.online) {
        await Message.findByIdAndUpdate(newMsg._id, {
          status: "delivered",
          $addToSet: { deliveredTo: data.to }
        });

        const updatedMsg = await Message.findById(newMsg._id);
        io.to(data.to).emit("private-message", updatedMsg);
        io.to(data.from).emit("private-message", updatedMsg);

        const counts = await calculateUnread(data.to);
        io.to(data.to).emit("unread-counts", counts);
      }
    } catch (err) {
      console.log(err);
    }
  });

  socket.on("group-message", async data => {
    try {
      const senderUser = await User.findOne({ name: data.from });

      if (senderUser && senderUser.muted) {
        io.to(data.from).emit("user-muted", { msg: "Admin muted you. You cannot send messages." });
        return;
      }

      if (!data.group) return;

      const group = await Group.findById(data.group);
      if (!group) return;
      if (!group.members.includes(data.from)) return;

      const onlineRecipients = group.members.filter(
        member => member !== data.from && userSocketIds[member]?.size
      );

      const newMsg = new Message({
        from: data.from,
        to: null,
        group: String(data.group),
        text: data.text ? sanitizeText(data.text, 2000) : null,
        file: data.file || null,
        fileType: data.fileType || null,
        replyTo: data.replyTo || null,
        time: formatTime(),
        status: "sent",
        reaction: null,
        deliveredTo: onlineRecipients,
        seenBy: [],
        createdAt: new Date()
      });

      await newMsg.save();

      io.to(roomNameForGroup(data.group)).emit("group-message", newMsg);

      const onlineSeenMembers = group.members.filter(
        member => member !== data.from && userSocketIds[member]?.size
      );

      if (onlineSeenMembers.length) {
        await Message.findByIdAndUpdate(newMsg._id, {
          $addToSet: { seenBy: { $each: onlineSeenMembers } }
        });
      }

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

  socket.on("call-user", async ({ to, from, type }) => {
    try {
      const callType = type === "video" ? "video" : "voice";

      if (isBusy(from)) {
        socket.emit("call-busy", { to, reason: "you_busy" });
        return;
      }

      const online = await isUserOnline(to);
      if (!online) {
        socket.emit("call-unavailable", { to, reason: "offline" });
        return;
      }

      if (isBusy(to)) {
        socket.emit("call-busy", { to, reason: "user_busy" });
        return;
      }

      setCall(from, to, "ringing", callType);
      io.to(from).emit("call-ringing", { to, type: callType });
      io.to(to).emit("incoming-call", { from, type: callType });

      setTimeout(async () => {
        try {
          if (callState[from] && callState[from].status === "ringing") {
            clearCall(from);

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
          }
        } catch (err) {
          console.log(err);
        }
      }, 25000);
    } catch (e) {
      console.log("call-user error", e);
      socket.emit("call-unavailable", { to, reason: "error" });
    }
  });

  socket.on("call-offer", ({ to, from, offer, type }) => {
    if (!callState[from] || callState[from].peer !== to) return;
    const callType = callState[from].type || (type === "video" ? "video" : "voice");
    io.to(to).emit("call-offer", { from, offer, type: callType });
  });

  socket.on("call-answer", async ({ to, from, answer, type }) => {
    try {
      if (!callState[from] || callState[from].peer !== to) return;

      callState[from].status = "in_call";
      if (callState[to]) callState[to].status = "in_call";

      const callType = callState[from].type || (type === "video" ? "video" : "voice");
      io.to(to).emit("call-answer", { from, answer, type: callType });

      await Call.create({
        from: to,
        to: from,
        type: callType,
        status: "completed",
        time: formatTime()
      });
    } catch (err) {
      console.log(err);
    }
  });

  socket.on("call-ice", ({ to, from, candidate, type }) => {
    if (!callState[from] || callState[from].peer !== to) return;
    const callType = callState[from].type || (type === "video" ? "video" : "voice");
    io.to(to).emit("call-ice", { from, candidate, type: callType });
  });

  socket.on("call-end", async ({ to, from }) => {
    try {
      io.to(to).emit("call-end", { from });

      const st = callState[from];
      const callType = st?.type || "voice";
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
        }

        await User.findOneAndUpdate(
          { name: username },
          { online: false, lastSeen: new Date() }
        );

        delete sockets[socket.id];
        await emitUsersToAll();
      }
    } catch (err) {
      console.log(err);
    }
  });
});

/* ---------- START SERVER ---------- */
const PORT = process.env.PORT || 5000;
server.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});