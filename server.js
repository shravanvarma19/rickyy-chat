const multer = require("multer");
const path = require("path");
const express = require("express");
const http = require("http");
const { Server } = require("socket.io");
const mongoose = require("mongoose");


const ADMIN_NAME = "shravan";


const PORT = process.env.PORT || 3000;

mongoose.connect(process.env.MONGODB_URI)
  .then(() => console.log("MongoDB Connected"))
  .catch(err => console.log("MongoDB Error:", err));

server.listen(PORT, () => {
  console.log(`Chat running on port ${PORT}`);
});

const userSchema = new mongoose.Schema({
  name: { type: String, unique: true },
  pin: String,
  online: { type: Boolean, default: false },
  lastSeen: String,
  dp: { type: String, default: "/default.png" },
  role: { type: String, default: "user" },
  approvalStatus: { type: String, default: "pending" },
  blocked: { type: Boolean, default: false },
  muted: { type: Boolean, default: false }
});

const User = mongoose.model("User", userSchema);


const messageSchema = new mongoose.Schema({
  from: String,
  to: String,
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
  reaction: String
});
const Message = mongoose.model("Message", messageSchema);

/* ---------- CALL LOG SCHEMA ---------- */
const callSchema = new mongoose.Schema({
  from: String,
  to: String,
  type: String,   // voice | video
  status: String, // missed | completed | rejected | ended
  time: String
});
const Call = mongoose.model("Call", callSchema);

/* ---------- STATUS SCHEMA (24h TTL) ---------- */
const statusSchema = new mongoose.Schema({
  user: String,
  file: String,
  fileType: String, // image | video
  viewers: [String],
  reactions: [{ user: String, emoji: String }],
  createdAt: { type: Date, default: Date.now },
  expiresAt: { type: Date, default: () => new Date(Date.now() + 24 * 60 * 60 * 1000) }
});
statusSchema.index({ expiresAt: 1 }, { expireAfterSeconds: 0 });
const Status = mongoose.model("Status", statusSchema);

/* ---------- EXPRESS APP ---------- */
const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static("public"));
app.use("/uploads", express.static("public/uploads"));

/* ---------- SERVER + SOCKET ---------- */
const server = http.createServer(app);
const io = new Server(server);

/* ---------- MULTER SETUP ---------- */
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, "public/uploads/"),
  filename: (req, file, cb) => cb(null, Date.now() + path.extname(file.originalname))
});
const upload = multer({ storage });

/* ---------- HELPERS ---------- */
async function getUsers() {
  return await User.find({ blocked: { $ne: true } });
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

async function isUserOnline(username) {
  const u = await User.findOne({ name: username });
  return !!(u && u.online);
}

async function pushCallMessage(from, to, text) {
  const msg = new Message({
    from,
    to,
    text,
    file: null,
    fileType: null,
    time: new Date().toLocaleTimeString(),
    status: "sent",
    reaction: null
  });

  await msg.save();
  io.to(from).emit("private-message", msg);
  io.to(to).emit("private-message", msg);
}
async function loadBlockedUsers(){
  const admin = localStorage.getItem("user");
  const res = await fetch("/admin/blocked-users?admin=" + encodeURIComponent(admin));
  const data = await res.json();
  console.log(data.users);
}
/* ---------- MEDIA UPLOAD ---------- */
app.post("/upload-media", upload.single("file"), (req, res) => {
  try {
    if (!req.file) return res.status(400).json({ status: "no_file" });
    res.json({ status: "ok", filePath: "/uploads/" + req.file.filename });
  } catch (err) {
    console.log(err);
    res.status(500).json({ status: "error" });
  }
});

app.get("/admin/blocked-users", async (req,res)=>{
  try{
    const admin = req.query.admin;

    if(admin !== ADMIN_NAME){
      return res.status(403).json({ ok:false, users:[] });
    }

    const users = await User.find({ blocked: true }).select("name dp blocked muted");
    res.json({ ok:true, users });
  }catch(err){
    console.log(err);
    res.status(500).json({ ok:false, users:[] });
  }
});
app.get("/admin/muted-users", async (req,res)=>{
  try{
    const admin = req.query.admin;

    if(admin !== ADMIN_NAME){
      return res.status(403).json({ ok:false, users:[] });
    }

    const users = await User.find({ muted: true, blocked: { $ne: true } })
      .select("name dp muted");

    res.json({ ok:true, users });
  }catch(err){
    console.log(err);
    res.status(500).json({ ok:false, users:[] });
  }
});
/* ---------- DP UPLOAD ---------- */
app.post("/upload-dp", upload.single("dp"), async (req, res) => {
  try {
    if (!req.file) return res.json({ status: "no_file" });

    const username = req.body.username;
    const filePath = "/uploads/" + req.file.filename;

    await User.findOneAndUpdate(
      { name: username },
      { dp: filePath },
      { upsert: false }
    );

    const allUsers = await getUsers();
    io.emit("users", allUsers);

    res.json({ status: "ok", dp: filePath });
  } catch (err) {
    console.log(err);
    res.json({ status: "error" });
  }
});

/* ---------- STATUS UPLOAD ---------- */
app.post("/upload-status", upload.single("file"), async (req, res) => {
  try {
    const username = req.body.username;
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
  } catch (err) {
    console.log(err);
    res.status(500).json({ status: "error" });
  }
});

/* ---------- STATUS ROUTES ---------- */
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

app.post("/status-view", async (req, res) => {
  try {
    const { statusId, viewer } = req.body;
    await Status.updateOne({ _id: statusId }, { $addToSet: { viewers: viewer } });
    res.json({ ok: true });
  } catch (err) {
    console.log(err);
    res.status(500).json({ ok: false });
  }
});

app.post("/status-react", async (req, res) => {
  try {
    const { statusId, user, emoji } = req.body;
    await Status.updateOne({ _id: statusId }, { $push: { reactions: { user, emoji } } });
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
      time: new Date().toLocaleTimeString(),
      status: "sent",
      reaction: null
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
  const allUsers = await getUsers();
  res.json(allUsers);
});

/* ---------- ADMIN APPROVAL ROUTES ---------- */
app.get("/admin/pending-users", async (req, res) => {
  try {
    const admin = req.query.admin;
    if (admin !== ADMIN_NAME) {
      return res.status(403).json({ ok: false, msg: "Only admin allowed" });
    }

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

app.post("/admin/approve-user", async (req, res) => {
  try {
    const { admin, username } = req.body;

    if (admin !== ADMIN_NAME) {
      return res.status(403).json({ ok: false, msg: "Only admin allowed" });
    }

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

app.post("/admin/reject-user", async (req, res) => {
  try {
    const { admin, username } = req.body;

    if (admin !== ADMIN_NAME) {
      return res.status(403).json({ ok: false, msg: "Only admin allowed" });
    }

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
app.post("/admin/block-user", async (req,res)=>{
  try{
    const { admin, username } = req.body;

    if(admin !== ADMIN_NAME){
      return res.status(403).json({ ok:false, msg:"Only admin allowed" });
    }

    const user = await User.findOneAndUpdate(
      { name: username },
      { blocked: true, online: false },
      { new: true }
    );

    if(!user){
      return res.json({ ok:false, msg:"User not found" });
    }

    // instant ban event to blocked user
    io.to(username).emit("force-logout", {
      msg: "Admin blocked your account"
    });

    // refresh user list everywhere
    const allUsers = await getUsers();
    io.emit("users", allUsers);

    return res.json({ ok:true });

  }catch(err){
    console.log(err);
    res.status(500).json({ ok:false });
  }
});
app.post("/admin/unblock-user", async (req,res)=>{
  try{
    const { admin, username } = req.body;

    if(admin !== ADMIN_NAME){
      return res.status(403).json({ ok:false, msg:"Only admin allowed" });
    }

    const user = await User.findOneAndUpdate(
      { name: username },
      { blocked: false, approvalStatus: "approved" },
      { new: true }
    );

    if(!user){
      return res.json({ ok:false, msg:"User not found" });
    }

    io.to(username).emit("unblocked", {
      msg: "Admin unblocked your account"
    });

    const allUsers = await getUsers();
    io.emit("users", allUsers);

    return res.json({ ok:true });
  }catch(err){
    console.log(err);
    res.status(500).json({ ok:false });
  }
});
app.post("/admin/mute-user", async (req,res)=>{
  try{
    const { admin, username } = req.body;

    if(admin !== ADMIN_NAME){
      return res.status(403).json({ ok:false, msg:"Only admin allowed" });
    }

    const user = await User.findOneAndUpdate(
      { name: username },
      { muted: true },
      { new: true }
    );

    if(!user){
      return res.json({ ok:false, msg:"User not found" });
    }

    io.to(username).emit("muted-by-admin", {
      msg: "Admin muted your account"
    });

    const allUsers = await getUsers();
    io.emit("users", allUsers);

    return res.json({ ok:true });
  }catch(err){
    console.log(err);
    res.status(500).json({ ok:false });
  }
});

app.post("/admin/unmute-user", async (req,res)=>{
  try{
    const { admin, username } = req.body;

    if(admin !== ADMIN_NAME){
      return res.status(403).json({ ok:false, msg:"Only admin allowed" });
    }

    const user = await User.findOneAndUpdate(
      { name: username },
      { muted: false },
      { new: true }
    );

    if(!user){
      return res.json({ ok:false, msg:"User not found" });
    }

    io.to(username).emit("unmuted-by-admin", {
      msg: "Admin unmuted your account"
    });

    const allUsers = await getUsers();
    io.emit("users", allUsers);

    return res.json({ ok:true });
  }catch(err){
    console.log(err);
    res.status(500).json({ ok:false });
  }
});
/* ---------- TEST ROUTES ---------- */
app.get("/test", (req, res) => {
  res.send("SERVER OK");
});

app.get("/api-check", (req, res) => {
  res.json({ ok: true, msg: "API working" });
});

/* ---------- AUTH ---------- */
app.post("/api/login", async (req, res) => {
  try {
    const { name, pin } = req.body;

    if (!name || !pin) {
      return res.json({ ok: false, msg: "Enter username & pin" });
    }

    if (!/^\d{4}$/.test(pin)) {
      return res.json({ ok: false, msg: "PIN must be 4 digits" });
    }

    let user = await User.findOne({ name });

    // New user
    if (!user) {
      const isAdmin = name === ADMIN_NAME;

      user = new User({
        name,
        pin,
        online: false,
        lastSeen: null,
        dp: "/default.png",
        role: isAdmin ? "admin" : "user",
        approvalStatus: isAdmin ? "approved" : "pending"
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

      return res.json({
        ok: true,
        user: { name: user.name, dp: user.dp, role: user.role }
      });
    }

    // Existing user without pin
    if (!user.pin) {
      user.pin = pin;
      await user.save();
    }

    if (user.pin !== pin) {
      return res.json({ ok: false, msg: "Wrong PIN" });
    }
    if(user.blocked){
  return res.json({
    ok:false,
    msg:"Admin blocked your account"
  });
}

    // Admin
    if (user.name === ADMIN_NAME || user.role === "admin") {
      if (user.role !== "admin" || user.approvalStatus !== "approved") {
        user.role = "admin";
        user.approvalStatus = "approved";
        await user.save();
      }

      return res.json({
        ok: true,
        user: { name: user.name, dp: user.dp, role: user.role }
      });
    }

    // Normal user approval
    if (user.approvalStatus === "pending") {
      return res.json({
        ok: false,
        pending: true,
        msg: "Still waiting for admin approval."
      });
    }
    if(user.blocked){
  return res.json({
    ok:false,
    msg:"Admin blocked your account"
  });
}
    if (user.approvalStatus === "rejected") {
      return res.json({
        ok: false,
        msg: "Admin rejected your request."
      });
    }

    return res.json({
      ok: true,
      user: { name: user.name, dp: user.dp, role: user.role }
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
      { online: false, lastSeen: new Date().toLocaleString() }
    );

    const allUsers = await getUsers();
    io.emit("users", allUsers);

    res.json({ ok: true });
  } catch (err) {
    console.log(err);
    res.status(500).json({ ok: false });
  }
});

/* ---------- SOCKET USERS STORE ---------- */
let sockets = {};          // socket.id -> username
let userSocketIds = {};    // username -> Set(socket.id)

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

  /* JOIN */
  socket.on("join", async username => {
    try {
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

      const allUsers = await getUsers();
      io.emit("users", allUsers);
    } catch (err) {
      console.log("JOIN ERROR:", err);
    }
  });

  socket.on("get-unread", async username => {
    try {
      const counts = await calculateUnread(username);
      socket.emit("unread-counts", counts);
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
      }).sort({ _id: 1 });

      socket.emit("history", msgs);
    } catch (err) {
      console.log(err);
    }
  });

  socket.on("private-message", async data => {
    const senderUser = await User.findOne({ name: data.from });

if(senderUser && senderUser.muted){
  io.to(data.from).emit("user-muted", {
    msg: "Admin muted you. You cannot send messages."
  });
  return;
}
    try {
      const newMsg = new Message({
        from: data.from,
        to: data.to,
        text: data.text || null,
        file: data.file || null,
        fileType: data.fileType || null,
        replyTo: data.replyTo || null,
        time: new Date().toLocaleTimeString(),
        status: "sent",
        reaction: null
      });

      await newMsg.save();

      io.to(data.from).emit("private-message", newMsg);

      const receiver = await User.findOne({ name: data.to });
      if (receiver && receiver.online) {
        await Message.findByIdAndUpdate(newMsg._id, { status: "delivered" });
        const updatedMsg = await Message.findById(newMsg._id);

        io.to(data.to).emit("private-message", updatedMsg);

        const counts = await calculateUnread(data.to);
        io.to(data.to).emit("unread-counts", counts);
      }
    } catch (err) {
      console.log(err);
    }
  });

  socket.on("seen", async data => {
    try {
      await Message.updateMany(
        { from: data.from, to: data.to, status: { $ne: "seen" } },
        { status: "seen" }
      );

      const updated = await Message.find({
        $or: [
          { from: data.from, to: data.to },
          { from: data.to, to: data.from }
        ]
      }).sort({ _id: 1 });

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
        io.to(updated.from).emit("reaction-update", updated);
        io.to(updated.to).emit("reaction-update", updated);
      }
    } catch (err) {
      console.log(err);
    }
  });

  socket.on("typing", data => {
    io.to(data.to).emit("typing", data.from);
  });

  socket.on("stop-typing", data => {
    io.to(data.to).emit("stop-typing", data.from);
  });

  /* ---------- CALLS ---------- */
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
              time: new Date().toLocaleTimeString()
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
        time: new Date().toLocaleTimeString()
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
        time: new Date().toLocaleTimeString()
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

  /* DISCONNECT */
  socket.on("disconnect", async () => {
    try {
      const username = sockets[socket.id];

      if (username) {
        if (userSocketIds[username]) {
          userSocketIds[username].delete(socket.id);
          if (userSocketIds[username].size === 0) delete userSocketIds[username];
        }

        if (callState[username]) {
          const peer = callState[username].peer;
          io.to(peer).emit("call-end", { from: username });
          clearCall(username);
        }

        await User.findOneAndUpdate(
          { name: username },
          { online: false, lastSeen: new Date().toLocaleString() }
        );

        delete sockets[socket.id];

        const allUsers = await getUsers();
        io.emit("users", allUsers);
      }
    } catch (err) {
      console.log(err);
    }
  });
});

/* ---------- START SERVER ---------- */
server.listen(3000, () => {
  console.log("Chat running 👉 http://localhost:3000");
});