const express = require('express');
const session = require('express-session');
const bcrypt = require('bcryptjs');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');

const { users, orders, settings, db } = require('./database');

const app = express();
const PORT = process.env.PORT || 3000;

// ============= MIDDLEWARE =============
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Session setup (using file-based SQLite for session store)
const SqliteStore = require('better-sqlite3-session-store')(session);
const sessionDb = require('better-sqlite3')(path.join(__dirname, 'sessions.db'));

app.use(session({
  store: new SqliteStore({ client: sessionDb, expired: { clear: true, intervalMs: 900000 } }),
  secret: process.env.SESSION_SECRET || crypto.randomBytes(32).toString('hex'),
  resave: false,
  saveUninitialized: false,
  cookie: { maxAge: 7 * 24 * 60 * 60 * 1000 } // 7 days
}));

// File upload config
const uploadsDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadsDir)) fs.mkdirSync(uploadsDir);

const storage = multer.diskStorage({
  destination: uploadsDir,
  filename: (req, file, cb) => {
    const unique = Date.now() + '-' + crypto.randomBytes(4).toString('hex');
    const ext = path.extname(file.originalname);
    cb(null, unique + ext);
  }
});
const upload = multer({
  storage,
  limits: { fileSize: 100 * 1024 * 1024 }, // 100MB
  fileFilter: (req, file, cb) => {
    const allowed = ['.stl', '.obj', '.3mf', '.step', '.stp', '.gcode', '.ply', '.amf'];
    const ext = path.extname(file.originalname).toLowerCase();
    cb(null, allowed.includes(ext));
  }
});

// Static files
app.use(express.static(path.join(__dirname, 'public')));

// ============= AUTH MIDDLEWARE =============
function requireAuth(req, res, next) {
  if (!req.session.userId) return res.status(401).json({ error: 'Not authenticated' });
  const user = users.findById.get(req.session.userId);
  if (!user) return res.status(401).json({ error: 'User not found' });
  req.user = user;
  next();
}

function requireAdmin(req, res, next) {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Admin access required' });
  next();
}

// ============= AUTH ROUTES =============
app.post('/api/auth/register', (req, res) => {
  const { username, password, name, contact } = req.body;
  if (!username || !password || !name) {
    return res.status(400).json({ error: 'Username, password, and name are required' });
  }
  if (username.length < 3) return res.status(400).json({ error: 'Username must be at least 3 characters' });
  if (password.length < 4) return res.status(400).json({ error: 'Password must be at least 4 characters' });

  const existing = users.findByUsername.get(username);
  if (existing) return res.status(409).json({ error: 'Username already taken' });

  const hash = bcrypt.hashSync(password, 10);
  const result = users.create.run(username, hash, 'customer', name, contact || '');

  req.session.userId = result.lastInsertRowid;
  res.json({ ok: true, user: { id: result.lastInsertRowid, username, role: 'customer', name } });
});

app.post('/api/auth/login', (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: 'Username and password required' });

  const user = users.findByUsername.get(username);
  if (!user || !bcrypt.compareSync(password, user.password_hash)) {
    return res.status(401).json({ error: 'Invalid username or password' });
  }

  req.session.userId = user.id;
  res.json({
    ok: true,
    user: { id: user.id, username: user.username, role: user.role, name: user.name },
    passwordChange: user.username === 'admin' && bcrypt.compareSync('admin', user.password_hash)
  });
});

app.post('/api/auth/logout', (req, res) => {
  req.session.destroy(() => res.json({ ok: true }));
});

app.get('/api/auth/me', requireAuth, (req, res) => {
  const pwDefault = req.user.username === 'admin' &&
    bcrypt.compareSync('admin', users.findByUsername.get('admin').password_hash);
  res.json({ user: req.user, passwordChange: pwDefault });
});

app.post('/api/auth/change-password', requireAuth, (req, res) => {
  const { currentPassword, newPassword } = req.body;
  if (!newPassword || newPassword.length < 4) {
    return res.status(400).json({ error: 'New password must be at least 4 characters' });
  }
  const full = users.findByUsername.get(req.user.username);
  if (!bcrypt.compareSync(currentPassword, full.password_hash)) {
    return res.status(401).json({ error: 'Current password is incorrect' });
  }
  users.updatePassword.run(bcrypt.hashSync(newPassword, 10), req.user.id);
  res.json({ ok: true });
});

// ============= ORDERS ROUTES =============
app.get('/api/orders', requireAuth, (req, res) => {
  let rows;
  if (req.user.role === 'admin') {
    rows = orders.getAll.all();
  } else {
    rows = orders.getByUser.all(req.user.id);
  }
  res.json(rows);
});

app.post('/api/orders', requireAuth, upload.single('file'), (req, res) => {
  const b = req.body;
  const isAdmin = req.user.role === 'admin';

  if (!b.item_description) return res.status(400).json({ error: 'Item description is required' });

  // Customers must provide description; admin can also provide costs
  const order = {
    user_id: isAdmin ? (b.user_id || req.user.id) : req.user.id,
    status: b.status || 'pending',
    customer_name: isAdmin ? (b.customer_name || req.user.name) : req.user.name,
    customer_contact: isAdmin ? (b.customer_contact || req.user.contact) : req.user.contact,
    item_description: b.item_description,
    file_name: req.file ? req.file.filename : '',
    file_original_name: req.file ? req.file.originalname : '',
    material: b.material || 'PLA',
    color: b.color || '',
    infill: b.infill || '20',
    layer_height: b.layer_height || '0.2',
    weight: parseFloat(b.weight) || 0,
    print_time: parseFloat(b.print_time) || 0,
    quantity: parseInt(b.quantity) || 1,
    post_process: b.post_process || 'none',
    due_date: b.due_date || '',
    notes: b.notes || '',
    cost_material: parseFloat(b.cost_material) || 0,
    cost_electricity: parseFloat(b.cost_electricity) || 0,
    cost_wear: parseFloat(b.cost_wear) || 0,
    cost_post: parseFloat(b.cost_post) || 0,
    cost_subtotal: parseFloat(b.cost_subtotal) || 0,
    cost_markup: parseFloat(b.cost_markup) || 0,
    cost_calculated: parseFloat(b.cost_calculated) || 0,
    cost_final: parseFloat(b.cost_final) || 0,
  };

  const result = orders.create.run(order);
  res.json({ ok: true, id: result.lastInsertRowid });
});

app.patch('/api/orders/:id', requireAuth, requireAdmin, (req, res) => {
  const order = orders.getById.get(req.params.id);
  if (!order) return res.status(404).json({ error: 'Order not found' });

  // Only allow updating known fields
  const allowed = [
    'status', 'customer_name', 'customer_contact', 'item_description',
    'material', 'color', 'infill', 'layer_height', 'weight', 'print_time',
    'quantity', 'post_process', 'due_date', 'notes',
    'cost_material', 'cost_electricity', 'cost_wear', 'cost_post',
    'cost_subtotal', 'cost_markup', 'cost_calculated', 'cost_final'
  ];

  const fields = {};
  for (const key of allowed) {
    if (req.body[key] !== undefined) fields[key] = req.body[key];
  }

  if (Object.keys(fields).length === 0) return res.status(400).json({ error: 'No fields to update' });
  orders.update(req.params.id, fields);
  res.json({ ok: true });
});

app.delete('/api/orders/:id', requireAuth, requireAdmin, (req, res) => {
  const order = orders.getById.get(req.params.id);
  if (!order) return res.status(404).json({ error: 'Order not found' });

  // Delete associated file if exists
  if (order.file_name) {
    const filePath = path.join(uploadsDir, order.file_name);
    if (fs.existsSync(filePath)) fs.unlinkSync(filePath);
  }

  orders.delete.run(req.params.id);
  res.json({ ok: true });
});

// ============= SETTINGS ROUTES =============
app.get('/api/settings', requireAuth, requireAdmin, (req, res) => {
  res.json(settings.get());
});

app.put('/api/settings', requireAuth, requireAdmin, (req, res) => {
  settings.set(req.body);
  res.json({ ok: true });
});

// ============= FILE DOWNLOAD =============
app.get('/api/files/:filename', requireAuth, requireAdmin, (req, res) => {
  const filename = path.basename(req.params.filename); // prevent path traversal
  const filePath = path.join(uploadsDir, filename);
  if (!fs.existsSync(filePath)) return res.status(404).json({ error: 'File not found' });

  // Find original name from orders
  const order = db.prepare('SELECT file_original_name FROM orders WHERE file_name = ?').get(filename);
  const downloadName = order ? order.file_original_name : filename;
  res.download(filePath, downloadName);
});

// ============= CATCH-ALL: serve index.html for SPA =============
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.get('/login', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

// ============= START =============
app.listen(PORT, () => {
  console.log(`3D Print Shop running at http://localhost:${PORT}`);
});
