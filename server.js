/**
 * backend server
 * auth, inbox, votes, pins, https support
 *
 * 
 * Setup:
 *   npm install express multer cors uuid
 * 
 *   generate self-signed cert:
 *   openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem -days 3650 -nodes -subj "/CN=localhost"
 * 
 *   node server.js
 *
 * env vars:
 *   PORT         default 3000
 *   API_KEY      shared secret with frontend
 *   FRONTEND_URL your domain
 *   USE_HTTPS    set to "false" to run plain http (e.g. behind a reverse proxy)
 */

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
  usersPath:   path.join(__dirname, 'users.json'),
  certPath:    path.join(__dirname, 'cert.pem'),
  keyPath:     path.join(__dirname, 'key.pem'),
};

if (!fs.existsSync(CONFIG.filesDir)) fs.mkdirSync(CONFIG.filesDir, { recursive: true });

function readDB() {
  try { return JSON.parse(fs.readFileSync(CONFIG.dbPath, 'utf8')); }
  catch { return { files: [], inbox: [] }; }
}
function writeDB(data) {
  fs.writeFileSync(CONFIG.dbPath, JSON.stringify(data, null, 2));
}

function readUsers() {
  try { return JSON.parse(fs.readFileSync(CONFIG.usersPath, 'utf8')); }
  catch { return { users: [] }; }
}
function writeUsers(data) {
  fs.writeFileSync(CONFIG.usersPath, JSON.stringify(data, null, 2));
}
function getUser(username) {
  return readUsers().users.find(u => u.username === username.toLowerCase()) || null;
}
function ownerExists() {
  return readUsers().users.some(u => u.role === 'owner');
}
function getOwnerBackendUrl() {
  const owner = readUsers().users.find(u => u.role === 'owner');
  return owner?.backendUrl || '';
}
function setOwnerBackendUrl(url) {
  const data  = readUsers();
  const owner = data.users.find(u => u.role === 'owner');
  if (owner) { owner.backendUrl = url; writeUsers(data); }
}
function addUser(username, hash, role) {
  const data = readUsers();
  if (!data.users.find(u => u.username === username.toLowerCase())) {
    data.users.push({ username: username.toLowerCase(), hash, role, created: Date.now() });
    writeUsers(data);
  }
}

function makeToken(username) {
  const payload = Buffer.from(JSON.stringify({ u: username.toLowerCase() })).toString('base64url');
  const sig     = crypto.createHmac('sha256', CONFIG.apiKey).update(payload).digest('base64url');
  return `${payload}.${sig}`;
}

function verifyToken(token) {
  try {
    const [payload, sig] = (token || '').split('.');
    if (!payload || !sig) return null;
    const expected = crypto.createHmac('sha256', CONFIG.apiKey).update(payload).digest('base64url');
    if (sig !== expected) return null;
    const { u } = JSON.parse(Buffer.from(payload, 'base64url').toString());
    return u || null;
  } catch { return null; }
}

const app = express();

app.use(cors({
  origin: CONFIG.frontendUrl,
  methods: ['GET', 'POST', 'DELETE', 'OPTIONS'],
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
  req.username = user.username;
  req.role     = user.role;
  next();
}

function requireOwner(req, res, next) {
  if (req.role !== 'owner') return res.status(403).json({ error: 'Owner only.' });
  next();
}

const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, CONFIG.filesDir),
  filename:    (req, file, cb) => cb(null, uuidv4()),
});
const upload = multer({ storage, limits: { fileSize: 512 * 1024 * 1024 } });

app.get('/health', (req, res) => res.json({ ok: true }));

app.post('/signup', requireApiKey, (req, res) => {
  const { username, hash } = req.body;
  if (!username || !hash) return res.status(400).json({ error: 'username and hash required.' });
  const u = username.toLowerCase().trim();
  if (!/^[a-z0-9_]{3,20}$/.test(u)) return res.status(400).json({ error: 'Username: 3-20 chars, a-z/0-9/_.' });
  if (getUser(u)) return res.status(409).json({ error: 'Username already taken.' });
  const role  = ownerExists() ? 'user' : 'owner';
  addUser(u, hash, role);
  const token = makeToken(u);
  res.json({ ok: true, username: u, role, token, backendUrl: getOwnerBackendUrl() });
});

app.post('/login', requireApiKey, (req, res) => {
  const { username, hash } = req.body;
  if (!username || !hash) return res.status(400).json({ error: 'username and hash required.' });
  const user = getUser(username);
  if (!user)              return res.status(404).json({ error: 'Account not found.' });
  if (user.hash !== hash) return res.status(401).json({ error: 'Incorrect password.' });
  const token = makeToken(user.username);
  res.json({ ok: true, username: user.username, role: user.role, token, backendUrl: getOwnerBackendUrl() });
});

app.get('/me', requireApiKey, requireAuth, (req, res) => {
  res.json({ ok: true, username: req.username, role: req.role, backendUrl: getOwnerBackendUrl() });
});

app.post('/settings/backend-url', requireApiKey, requireAuth, requireOwner, (req, res) => {
  const { url } = req.body;
  if (typeof url !== 'string') return res.status(400).json({ error: 'url required.' });
  setOwnerBackendUrl(url.trim().replace(/\/$/, ''));
  res.json({ ok: true, backendUrl: getOwnerBackendUrl() });
});

app.get('/files', requireApiKey, requireAuth, (req, res) => {
  const db = readDB();
  const visible = (req.role === 'owner')
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
    return {
      id:       file.filename,
      name:     file.originalname,
      ext,
      size:     file.size,
      mimeType: file.mimetype,
      owner:    req.username,
      public:      false,
      pinned:      false,
      description: '',
      votes:       { up: [], down: [] },
      uploaded:    Date.now(),
    };
  });
  db.files.push(...added);
  writeDB(db);
  res.json({ uploaded: added.map(f => ({ id: f.id, name: f.name })) });
});

app.get('/download/:id', requireApiKey, requireAuth, (req, res) => {
  const db   = readDB();
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
  const db   = readDB();
  const file = db.files.find(f => f.id === req.params.id);
  if (!file) return res.status(404).json({ error: 'Not found.' });
  file.public = !file.public;
  writeDB(db);
  res.json({ id: file.id, public: file.public });
});

app.post('/files/:id/pin', requireApiKey, requireAuth, requireOwner, (req, res) => {
  const db   = readDB();
  const file = db.files.find(f => f.id === req.params.id);
  if (!file) return res.status(404).json({ error: 'Not found.' });
  file.pinned = !file.pinned;
  writeDB(db);
  res.json({ id: file.id, pinned: file.pinned });
});

app.post('/files/:id/vote', requireApiKey, requireAuth, (req, res) => {
  const { vote } = req.body;
  const db   = readDB();
  const file = db.files.find(f => f.id === req.params.id);
  if (!file) return res.status(404).json({ error: 'Not found.' });
  if (!file.public && file.owner !== req.username && req.role !== 'owner')
    return res.status(403).json({ error: 'Can only vote on public files.' });
  if (!file.votes) file.votes = { up: [], down: [] };
  file.votes.up   = file.votes.up.filter(u => u !== req.username);
  file.votes.down = file.votes.down.filter(u => u !== req.username);
  if (vote === 'up')   file.votes.up.push(req.username);
  if (vote === 'down') file.votes.down.push(req.username);
  writeDB(db);
  res.json({ id: file.id, up: file.votes.up.length, down: file.votes.down.length, myVote: vote || null });
});

app.delete('/files/:id', requireApiKey, requireAuth, (req, res) => {
  const db  = readDB();
  const idx = db.files.findIndex(f => f.id === req.params.id);
  if (idx === -1) return res.status(404).json({ error: 'Not found.' });
  const file = db.files[idx];
  if (file.owner !== req.username && req.role !== 'owner')
    return res.status(403).json({ error: 'Access denied.' });
  const fp = path.join(CONFIG.filesDir, file.id);
  if (fs.existsSync(fp)) fs.unlinkSync(fp);
  db.files.splice(idx, 1);
  writeDB(db);
  res.json({ deleted: file.id });
});

app.post('/files/:id/description', requireApiKey, requireAuth, (req, res) => {
  const { description } = req.body;
  const db   = readDB();
  const file = db.files.find(f => f.id === req.params.id);
  if (!file) return res.status(404).json({ error: 'Not found.' });
  // Only the file owner or the vault owner can set description
  if (file.owner !== req.username && req.role !== 'owner')
    return res.status(403).json({ error: 'Access denied.' });
  file.description = (description || '').trim().slice(0, 1000);
  writeDB(db);
  res.json({ ok: true, description: file.description });
});

app.post('/inbox/request', requireApiKey, requireAuth, upload.single('file'), (req, res) => {
  const reason = req.body?.reason?.trim();
  if (!reason) return res.status(400).json({ error: 'Reason is required.' });

  const db = readDB();
  if (!db.inbox) db.inbox = [];
  if (!db.files) db.files = [];
  let fileId   = null;
  let filename = null;
  if (req.file) {
    const ext = req.file.originalname.includes('.') ? req.file.originalname.split('.').pop().toLowerCase() : '';
    const entry = {
      id:             req.file.filename,
      name:           req.file.originalname,
      ext,
      size:           req.file.size,
      mimeType:       req.file.mimetype,
      owner:          req.username,
      public:         false,
      pinned:         false,
      pendingRequest: true,
      description:    '',
      votes:          { up: [], down: [] },
      uploaded:       Date.now(),
    };
    db.files.push(entry);
    fileId   = entry.id;
    filename = entry.name;
  }

  db.inbox.push({
    id: uuidv4(),
    from: req.username,
    filename,
    fileId,
    reason,
    date: Date.now(),
    read: false,
  });
  writeDB(db);
  res.json({ ok: true, fileId, filename });
});

app.get('/inbox', requireApiKey, requireAuth, requireOwner, (req, res) => {
  const db = readDB();
  const inbox = (db.inbox || []).slice().sort((a, b) => b.date - a.date);
  res.json({ inbox });
});

app.post('/inbox/:id/approve', requireApiKey, requireAuth, requireOwner, (req, res) => {
  const db   = readDB();
  const idx  = (db.inbox || []).findIndex(i => i.id === req.params.id);
  if (idx === -1) return res.status(404).json({ error: 'Not found.' });
  const item = db.inbox[idx];

  if (item.fileId) {
    const file = db.files.find(f => f.id === item.fileId);
    if (file) {
      file.public         = true;
      file.pendingRequest = false;
    }
  }

  db.inbox.splice(idx, 1);
  writeDB(db);
  res.json({ ok: true });
});

app.post('/inbox/:id/decline', requireApiKey, requireAuth, requireOwner, (req, res) => {
  const db  = readDB();
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

  db.inbox.splice(idx, 1);
  writeDB(db);
  res.json({ ok: true });
});

app.post('/inbox/:id/read', requireApiKey, requireAuth, requireOwner, (req, res) => {
  const db   = readDB();
  const item = (db.inbox || []).find(i => i.id === req.params.id);
  if (!item) return res.status(404).json({ error: 'Not found.' });
  item.read = true;
  writeDB(db);
  res.json({ ok: true });
});

app.delete('/inbox/:id', requireApiKey, requireAuth, requireOwner, (req, res) => {
  const db  = readDB();
  const idx = (db.inbox || []).findIndex(i => i.id === req.params.id);
  if (idx === -1) return res.status(404).json({ error: 'Not found.' });
  db.inbox.splice(idx, 1);
  writeDB(db);
  res.json({ ok: true });
});

app.post('/inbox/read-all', requireApiKey, requireAuth, requireOwner, (req, res) => {
  const db = readDB();
  (db.inbox || []).forEach(i => { i.read = true; });
  writeDB(db);
  res.json({ ok: true });
});

app.delete('/inbox/delete-all', requireApiKey, requireAuth, requireOwner, (req, res) => {
  const db = readDB();
  db.inbox = [];
  writeDB(db);
  res.json({ ok: true });
});

if (CONFIG.useHttps && fs.existsSync(CONFIG.certPath) && fs.existsSync(CONFIG.keyPath)) {
  const https = require('https');
  const opts  = { cert: fs.readFileSync(CONFIG.certPath), key: fs.readFileSync(CONFIG.keyPath) };
  https.createServer(opts, app).listen(CONFIG.port, () => {
    console.log(`\n  ⬡  Vault backend (HTTPS) → port ${CONFIG.port}`);
    console.log(`     CORS: ${CONFIG.frontendUrl}\n`);
  });
} else {
  if (CONFIG.useHttps) console.warn('  [!] cert.pem/key.pem missing — using HTTP');
  app.listen(CONFIG.port, () => {
    console.log(`\n  ⬡  Vault backend (HTTP) → port ${CONFIG.port}`);
    console.log(`     CORS: ${CONFIG.frontendUrl}\n`);
  });
}
