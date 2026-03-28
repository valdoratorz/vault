/*auth, files, inbox, votes, pins, descriptions, DMs, profiles, bans, warnings*/

const express  = require('express');
const multer   = require('multer');
const cors     = require('cors');
const path     = require('path');
const fs       = require('fs');
const crypto   = require('crypto');
const { v4: uuidv4 } = require('uuid');

const CONFIG = {
  port:        process.env.PORT        || 3000,
  apiKey:      process.env.API_KEY     || 'YOURAPIKEY',
  frontendUrl: process.env.FRONTEND_URL || 'https://your-domain.com',
  useHttps:    process.env.USE_HTTPS !== 'false',
  filesDir:    path.join(__dirname, 'files'),
  dbPath:      path.join(__dirname, 'db.json'),
  avatarsDir:  path.join(__dirname, 'avatars'),
  usersPath:   path.join(__dirname, 'users.json'),
  certPath:    path.join(__dirname, 'cert.pem'),
  keyPath:     path.join(__dirname, 'key.pem'),
};

[CONFIG.filesDir, CONFIG.avatarsDir].forEach(d => {
  if (!fs.existsSync(d)) fs.mkdirSync(d, { recursive: true });
});

function readDB() {
  try { return JSON.parse(fs.readFileSync(CONFIG.dbPath, 'utf8')); }
  catch { return { files: [], inbox: [], dms: [] }; }
}
function writeDB(data) { fs.writeFileSync(CONFIG.dbPath, JSON.stringify(data, null, 2)); }

function readUsers() {
  try { return JSON.parse(fs.readFileSync(CONFIG.usersPath, 'utf8')); }
  catch { return { users: [] }; }
}
function writeUsers(data) { fs.writeFileSync(CONFIG.usersPath, JSON.stringify(data, null, 2)); }
function getUser(username) {
  return readUsers().users.find(u => u.username === username.toLowerCase()) || null;
}
function ownerExists() { return readUsers().users.some(u => u.role === 'owner'); }
function getOwnerBackendUrl() {
  const o = readUsers().users.find(u => u.role === 'owner');
  return o?.backendUrl || '';
}
function setOwnerBackendUrl(url) {
  const data = readUsers();
  const o = data.users.find(u => u.role === 'owner');
  if (o) { o.backendUrl = url; writeUsers(data); }
}
function addUser(username, hash, role) {
  const data = readUsers();
  if (!data.users.find(u => u.username === username.toLowerCase())) {
    data.users.push({
      username: username.toLowerCase(), hash, role,
      nickname: '', bio: '', avatarColor: '#7c6fff',
      banned: false, warnings: 0,
      created: Date.now(),
    });
    writeUsers(data);
  }
}
function updateUser(username, fields) {
  const data = readUsers();
  const u = data.users.find(u => u.username === username.toLowerCase());
  if (u) { Object.assign(u, fields); writeUsers(data); }
}

function makeToken(username) {
  const p = Buffer.from(JSON.stringify({ u: username.toLowerCase() })).toString('base64url');
  const s = crypto.createHmac('sha256', CONFIG.apiKey).update(p).digest('base64url');
  return `${p}.${s}`;
}
function verifyToken(token) {
  try {
    const [p, s] = (token || '').split('.');
    if (!p || !s) return null;
    const e = crypto.createHmac('sha256', CONFIG.apiKey).update(p).digest('base64url');
    if (s !== e) return null;
    const { u } = JSON.parse(Buffer.from(p, 'base64url').toString());
    return u || null;
  } catch { return null; }
}

const app = express();
app.use(cors({
  origin: CONFIG.frontendUrl,
  methods: ['GET', 'POST', 'DELETE', 'PATCH', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'x-api-key', 'x-token'],
}));
app.use(express.json());

function requireApiKey(req, res, next) {
  if (req.headers['x-api-key'] !== CONFIG.apiKey)
    return res.status(401).json({ error: 'Invalid API key.' });
  next();
}
function requireAuth(req, res, next) {
  const username = verifyToken(req.headers['x-token']);
  if (!username) return res.status(401).json({ error: 'Invalid or missing token.' });
  const user = getUser(username);
  if (!user) return res.status(401).json({ error: 'User not found.' });
  if (user.banned && user.role !== 'owner') return res.status(403).json({ error: 'Account banned.' });
  req.username = user.username;
  req.role     = user.role;
  next();
}
function requireOwner(req, res, next) {
  if (req.role !== 'owner') return res.status(403).json({ error: 'Owner only.' });
  next();
}

const fileStorage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, CONFIG.filesDir),
  filename:    (req, file, cb) => cb(null, uuidv4()),
});
const avatarStorage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, CONFIG.avatarsDir),
  filename:    (req, file, cb) => cb(null, req.username + path.extname(file.originalname).toLowerCase()),
});
const upload       = multer({ storage: fileStorage,   limits: { fileSize: 512 * 1024 * 1024 } });
const uploadAvatar = multer({ storage: avatarStorage, limits: { fileSize: 4  * 1024 * 1024 } });

app.get('/health', (req, res) => res.json({ ok: true }));

app.get('/avatars/:file', (req, res) => {
  const fp = path.join(CONFIG.avatarsDir, path.basename(req.params.file));
  if (fs.existsSync(fp)) res.sendFile(fp);
  else res.status(404).end();
});

function publicProfile(user) {
  return {
    username:    user.username,
    nickname:    user.nickname || '',
    bio:         user.bio      || '',
    avatarColor: user.avatarColor || '#7c6fff',
    role:        user.role,
    banned:      user.banned || false,
    warnings:    user.warnings || 0,
    created:     user.created || 0,
  };
}

app.post('/signup', requireApiKey, (req, res) => {
  const { username, hash } = req.body;
  if (!username || !hash) return res.status(400).json({ error: 'username and hash required.' });
  const u = username.toLowerCase().trim();
  if (!/^[a-z0-9_]{3,20}$/.test(u)) return res.status(400).json({ error: 'Username: 3-20 chars, a-z/0-9/_.' });
  if (getUser(u)) return res.status(409).json({ error: 'Username already taken.' });
  const role = ownerExists() ? 'user' : 'owner';
  addUser(u, hash, role);
  const token = makeToken(u);
  res.json({ ok: true, username: u, role, token, backendUrl: getOwnerBackendUrl(), profile: publicProfile(getUser(u)) });
});

app.post('/login', requireApiKey, (req, res) => {
  const { username, hash } = req.body;
  if (!username || !hash) return res.status(400).json({ error: 'username and hash required.' });
  const user = getUser(username);
  if (!user)              return res.status(404).json({ error: 'Account not found.' });
  if (user.hash !== hash) return res.status(401).json({ error: 'Incorrect password.' });
  if (user.banned && user.role !== 'owner') return res.status(403).json({ error: 'Account banned.' });
  const token = makeToken(user.username);
  res.json({ ok: true, username: user.username, role: user.role, token, backendUrl: getOwnerBackendUrl(), profile: publicProfile(user) });
});

app.get('/me', requireApiKey, requireAuth, (req, res) => {
  const user = getUser(req.username);
  res.json({ ok: true, username: req.username, role: req.role, backendUrl: getOwnerBackendUrl(), profile: publicProfile(user) });
});

app.get('/profile/:username', requireApiKey, requireAuth, (req, res) => {
  const user = getUser(req.params.username);
  if (!user) return res.status(404).json({ error: 'User not found.' });
  const db = readDB();
  const publicFiles = db.files.filter(f => !f.pendingRequest && f.public && f.owner === user.username);
  res.json({ profile: publicProfile(user), files: publicFiles });
});

app.patch('/profile', requireApiKey, requireAuth, (req, res) => {
  const { nickname, bio, avatarColor } = req.body;
  const fields = {};
  if (nickname !== undefined) fields.nickname    = String(nickname).slice(0, 32);
  if (bio      !== undefined) fields.bio         = String(bio).slice(0, 300);
  if (avatarColor !== undefined && /^#[0-9a-fA-F]{6}$/.test(avatarColor)) fields.avatarColor = avatarColor;
  updateUser(req.username, fields);
  res.json({ ok: true, profile: publicProfile(getUser(req.username)) });
});

app.post('/profile/avatar', requireApiKey, requireAuth, uploadAvatar.single('avatar'), (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'No file.' });
  const url = `/avatars/${req.file.filename}`;
  updateUser(req.username, { avatarUrl: url });
  res.json({ ok: true, avatarUrl: url });
});

app.get('/users', requireApiKey, requireAuth, requireOwner, (req, res) => {
  const data = readUsers();
  res.json({ users: data.users.map(publicProfile) });
});

app.post('/users/:username/ban', requireApiKey, requireAuth, requireOwner, (req, res) => {
  const user = getUser(req.params.username);
  if (!user) return res.status(404).json({ error: 'Not found.' });
  if (user.role === 'owner') return res.status(400).json({ error: 'Cannot ban owner.' });
  updateUser(req.params.username, { banned: !user.banned });
  res.json({ ok: true, banned: !user.banned });
});

app.post('/users/:username/warn', requireApiKey, requireAuth, requireOwner, (req, res) => {
  const { message } = req.body;
  const user = getUser(req.params.username);
  if (!user) return res.status(404).json({ error: 'Not found.' });
  updateUser(req.params.username, { warnings: (user.warnings || 0) + 1 });
  const db = readDB();
  if (!db.dms) db.dms = [];
  const threadId = [req.username, req.params.username].sort().join('::');
  let thread = db.dms.find(t => t.id === threadId);
  if (!thread) {
    thread = { id: threadId, participants: [req.username, req.params.username], messages: [], accepted: true };
    db.dms.push(thread);
  }
  thread.messages.push({ id: uuidv4(), from: '__system__', text: `⚠️ Warning from owner: ${message || 'No reason given.'}`, ts: Date.now(), read: false });
  writeDB(db);
  res.json({ ok: true, warnings: (user.warnings || 0) + 1 });
});

app.patch('/users/:username/nickname', requireApiKey, requireAuth, requireOwner, (req, res) => {
  const { nickname } = req.body;
  const user = getUser(req.params.username);
  if (!user) return res.status(404).json({ error: 'Not found.' });
  updateUser(req.params.username, { nickname: String(nickname || '').slice(0, 32) });
  res.json({ ok: true });
});

app.post('/settings/backend-url', requireApiKey, requireAuth, requireOwner, (req, res) => {
  const { url } = req.body;
  if (typeof url !== 'string') return res.status(400).json({ error: 'url required.' });
  setOwnerBackendUrl(url.trim().replace(/\/$/, ''));
  res.json({ ok: true, backendUrl: getOwnerBackendUrl() });
});

app.get('/files', requireApiKey, requireAuth, (req, res) => {
  const db = readDB();
  const visible = req.role === 'owner'
    ? db.files.filter(f => !f.pendingRequest)
    : db.files.filter(f => !f.pendingRequest && (f.public || f.owner === req.username));
  res.json({ files: visible, role: req.role });
});

app.post('/upload', requireApiKey, requireAuth, upload.array('files', 50), (req, res) => {
  if (!req.files?.length) return res.status(400).json({ error: 'No files received.' });
  const db = readDB();
  if (!db.files) db.files = [];
  if (!db.inbox) db.inbox = [];
  const added = req.files.map(file => {
    const ext = file.originalname.includes('.') ? file.originalname.split('.').pop().toLowerCase() : '';
    return { id: file.filename, name: file.originalname, ext, size: file.size, mimeType: file.mimetype, owner: req.username, public: false, pinned: false, description: '', votes: { up: [], down: [] }, uploaded: Date.now() };
  });
  db.files.push(...added);
  writeDB(db);
  res.json({ uploaded: added.map(f => ({ id: f.id, name: f.name })) });
});

app.get('/download/:id', requireApiKey, requireAuth, (req, res) => {
  const db = readDB();
  const file = db.files.find(f => f.id === req.params.id);
  if (!file) return res.status(404).json({ error: 'File not found.' });
  if (!file.public && file.owner !== req.username && req.role !== 'owner')
    return res.status(403).json({ error: 'Access denied.' });
  const fp = path.join(CONFIG.filesDir, file.id);
  if (!fs.existsSync(fp)) return res.status(404).json({ error: 'File missing from disk.' });
  res.setHeader('Content-Disposition', `attachment; filename="${encodeURIComponent(file.name)}"`);
  res.setHeader('Content-Type', file.mimeType || 'application/octet-stream');
  fs.createReadStream(fp).pipe(res);
});

app.post('/files/:id/visibility', requireApiKey, requireAuth, requireOwner, (req, res) => {
  const db = readDB(); const file = db.files.find(f => f.id === req.params.id);
  if (!file) return res.status(404).json({ error: 'Not found.' });
  file.public = !file.public; writeDB(db); res.json({ id: file.id, public: file.public });
});

app.post('/files/:id/pin', requireApiKey, requireAuth, requireOwner, (req, res) => {
  const db = readDB(); const file = db.files.find(f => f.id === req.params.id);
  if (!file) return res.status(404).json({ error: 'Not found.' });
  file.pinned = !file.pinned; writeDB(db); res.json({ id: file.id, pinned: file.pinned });
});

app.post('/files/:id/vote', requireApiKey, requireAuth, (req, res) => {
  const { vote } = req.body;
  const db = readDB(); const file = db.files.find(f => f.id === req.params.id);
  if (!file) return res.status(404).json({ error: 'Not found.' });
  if (!file.public && file.owner !== req.username && req.role !== 'owner')
    return res.status(403).json({ error: 'Can only vote on public files.' });
  if (!file.votes) file.votes = { up: [], down: [] };
  file.votes.up   = file.votes.up.filter(u => u !== req.username);
  file.votes.down = file.votes.down.filter(u => u !== req.username);
  if (vote === 'up')   file.votes.up.push(req.username);
  if (vote === 'down') file.votes.down.push(req.username);
  writeDB(db); res.json({ id: file.id, up: file.votes.up.length, down: file.votes.down.length });
});

app.delete('/files/:id', requireApiKey, requireAuth, (req, res) => {
  const db = readDB(); const idx = db.files.findIndex(f => f.id === req.params.id);
  if (idx === -1) return res.status(404).json({ error: 'Not found.' });
  const file = db.files[idx];
  if (file.owner !== req.username && req.role !== 'owner') return res.status(403).json({ error: 'Access denied.' });
  const fp = path.join(CONFIG.filesDir, file.id);
  if (fs.existsSync(fp)) fs.unlinkSync(fp);
  db.files.splice(idx, 1); writeDB(db); res.json({ deleted: file.id });
});

app.post('/files/:id/description', requireApiKey, requireAuth, (req, res) => {
  const { description } = req.body;
  const db = readDB(); const file = db.files.find(f => f.id === req.params.id);
  if (!file) return res.status(404).json({ error: 'Not found.' });
  if (file.owner !== req.username && req.role !== 'owner') return res.status(403).json({ error: 'Access denied.' });
  file.description = (description || '').trim().slice(0, 1000);
  writeDB(db); res.json({ ok: true, description: file.description });
});

app.post('/inbox/request', requireApiKey, requireAuth, upload.single('file'), (req, res) => {
  const reason = req.body?.reason?.trim();
  if (!reason) return res.status(400).json({ error: 'Reason is required.' });
  const db = readDB();
  if (!db.inbox) db.inbox = [];
  if (!db.files) db.files = [];
  let fileId = null, filename = null;
  if (req.file) {
    const ext = req.file.originalname.includes('.') ? req.file.originalname.split('.').pop().toLowerCase() : '';
    const entry = { id: req.file.filename, name: req.file.originalname, ext, size: req.file.size, mimeType: req.file.mimetype, owner: req.username, public: false, pinned: false, pendingRequest: true, description: '', votes: { up: [], down: [] }, uploaded: Date.now() };
    db.files.push(entry);
    fileId = entry.id; filename = entry.name;
  }
  db.inbox.push({ id: uuidv4(), from: req.username, filename, fileId, reason, date: Date.now(), read: false });
  writeDB(db);
  res.json({ ok: true, fileId, filename });
});

app.post('/inbox/request/finalize', requireApiKey, requireAuth, (req, res) => {
  const { fileId, reason } = req.body;
  if (!fileId || !reason?.trim()) return res.status(400).json({ error: 'fileId and reason required.' });
  const db = readDB();
  const item = (db.inbox||[]).find(i => i.fileId === fileId && i.from === req.username);
  if (!item) return res.status(404).json({ error: 'Request not found.' });
  item.reason = reason.trim();
  item.read   = false;
  writeDB(db);
  res.json({ ok: true });
});

app.get('/inbox', requireApiKey, requireAuth, requireOwner, (req, res) => {
  const db = readDB();
  res.json({ inbox: (db.inbox || []).slice().sort((a, b) => b.date - a.date) });
});

app.post('/inbox/:id/approve', requireApiKey, requireAuth, requireOwner, (req, res) => {
  const db = readDB();
  const idx = (db.inbox || []).findIndex(i => i.id === req.params.id);
  if (idx === -1) return res.status(404).json({ error: 'Not found.' });
  const item = db.inbox[idx];
  if (item.fileId) {
    const file = db.files.find(f => f.id === item.fileId);
    if (file) { file.public = true; file.pendingRequest = false; }
  }
  db.inbox.splice(idx, 1); writeDB(db); res.json({ ok: true });
});

app.post('/inbox/:id/decline', requireApiKey, requireAuth, requireOwner, (req, res) => {
  const db = readDB();
  const idx = (db.inbox || []).findIndex(i => i.id === req.params.id);
  if (idx === -1) return res.status(404).json({ error: 'Not found.' });
  const item = db.inbox[idx];
  if (item.fileId) {
    const fidx = db.files.findIndex(f => f.id === item.fileId);
    if (fidx !== -1) {
      const fp = path.join(CONFIG.filesDir, item.fileId);
      if (fs.existsSync(fp)) fs.unlinkSync(fp);
      db.files.splice(fidx, 1);
    }
  }
  db.inbox.splice(idx, 1); writeDB(db); res.json({ ok: true });
});

app.post('/inbox/:id/read', requireApiKey, requireAuth, requireOwner, (req, res) => {
  const db = readDB();
  const item = (db.inbox || []).find(i => i.id === req.params.id);
  if (!item) return res.status(404).json({ error: 'Not found.' });
  item.read = true; writeDB(db); res.json({ ok: true });
});

app.delete('/inbox/:id', requireApiKey, requireAuth, requireOwner, (req, res) => {
  const db = readDB();
  const idx = (db.inbox || []).findIndex(i => i.id === req.params.id);
  if (idx === -1) return res.status(404).json({ error: 'Not found.' });
  db.inbox.splice(idx, 1); writeDB(db); res.json({ ok: true });
});

app.post('/inbox/read-all', requireApiKey, requireAuth, requireOwner, (req, res) => {
  const db = readDB(); (db.inbox || []).forEach(i => { i.read = true; }); writeDB(db); res.json({ ok: true });
});

app.delete('/inbox/delete-all', requireApiKey, requireAuth, requireOwner, (req, res) => {
  const db = readDB(); db.inbox = []; writeDB(db); res.json({ ok: true });
});

function getThreadId(a, b) { return [a, b].sort().join('::'); }

app.get('/dms', requireApiKey, requireAuth, (req, res) => {
  const db = readDB();
  if (!db.dms) db.dms = [];
  const threads = db.dms
    .filter(t => t.participants.includes(req.username))
    .map(t => {
      const other  = t.participants.find(p => p !== req.username);
      const unread = t.messages.filter(m => m.from !== req.username && !m.read).length;
      const last   = t.messages[t.messages.length - 1] || null;
      return { id: t.id, with: other, accepted: t.accepted, unread, lastMessage: last };
    });
  res.json({ threads });
});

app.get('/dms/:threadId', requireApiKey, requireAuth, (req, res) => {
  const db = readDB();
  if (!db.dms) db.dms = [];
  const thread = db.dms.find(t => t.id === req.params.threadId);
  if (!thread || !thread.participants.includes(req.username))
    return res.status(404).json({ error: 'Thread not found.' });
  thread.messages.forEach(m => { if (m.from !== req.username) m.read = true; });
  writeDB(db);
  res.json({ thread });
});

app.post('/dms/:toUsername', requireApiKey, requireAuth, (req, res) => {
  const { text } = req.body;
  if (!text?.trim()) return res.status(400).json({ error: 'Message text required.' });
  const to = req.params.toUsername.toLowerCase();
  if (to === req.username) return res.status(400).json({ error: 'Cannot message yourself.' });
  if (!getUser(to)) return res.status(404).json({ error: 'User not found.' });

  const db = readDB();
  if (!db.dms) db.dms = [];
  const threadId = getThreadId(req.username, to);
  let thread = db.dms.find(t => t.id === threadId);

  if (!thread) {
    thread = { id: threadId, participants: [req.username, to], messages: [], accepted: false, initiator: req.username };
    db.dms.push(thread);
  }
  if (!thread.accepted && thread.initiator !== req.username)
    return res.status(403).json({ error: 'DM request not yet accepted.' });

  thread.messages.push({ id: uuidv4(), from: req.username, text: text.trim().slice(0, 2000), ts: Date.now(), read: false });
  writeDB(db);
  res.json({ ok: true, threadId });
});

app.post('/dms/:threadId/accept', requireApiKey, requireAuth, (req, res) => {
  const db = readDB(); if (!db.dms) db.dms = [];
  const thread = db.dms.find(t => t.id === req.params.threadId);
  if (!thread || !thread.participants.includes(req.username)) return res.status(404).json({ error: 'Not found.' });
  thread.accepted = true; writeDB(db); res.json({ ok: true });
});

app.delete('/dms/:threadId', requireApiKey, requireAuth, (req, res) => {
  const db = readDB(); if (!db.dms) db.dms = [];
  const idx = db.dms.findIndex(t => t.id === req.params.threadId && t.participants.includes(req.username));
  if (idx === -1) return res.status(404).json({ error: 'Not found.' });
  db.dms.splice(idx, 1); writeDB(db); res.json({ ok: true });
});

if (CONFIG.useHttps && fs.existsSync(CONFIG.certPath) && fs.existsSync(CONFIG.keyPath)) {
  const https = require('https');
  const opts  = { cert: fs.readFileSync(CONFIG.certPath), key: fs.readFileSync(CONFIG.keyPath) };
  https.createServer(opts, app).listen(CONFIG.port, () => {
    console.log(`\n  ⬡  Vault backend (HTTPS) → port ${CONFIG.port}\n     CORS: ${CONFIG.frontendUrl}\n`);
  });
} else {
  if (CONFIG.useHttps) console.warn('  [!] cert.pem/key.pem missing — using HTTP');
  app.listen(CONFIG.port, () => {
    console.log(`\n  ⬡  Vault backend (HTTP) → port ${CONFIG.port}\n     CORS: ${CONFIG.frontendUrl}\n`);
  });
}
