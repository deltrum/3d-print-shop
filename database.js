const Database = require('better-sqlite3');
const bcrypt = require('bcryptjs');
const path = require('path');

const DB_PATH = path.join(__dirname, 'data.db');

const db = new Database(DB_PATH);
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');

// ============= SCHEMA =============
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'customer' CHECK(role IN ('admin','customer')),
    name TEXT NOT NULL,
    contact TEXT DEFAULT '',
    created_at TEXT DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS orders (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    date TEXT DEFAULT (datetime('now')),
    status TEXT DEFAULT 'pending',
    customer_name TEXT NOT NULL,
    customer_contact TEXT DEFAULT '',
    item_description TEXT NOT NULL,
    file_name TEXT DEFAULT '',
    file_original_name TEXT DEFAULT '',
    material TEXT DEFAULT 'PLA',
    color TEXT DEFAULT '',
    infill TEXT DEFAULT '20',
    layer_height TEXT DEFAULT '0.2',
    weight REAL DEFAULT 0,
    print_time REAL DEFAULT 0,
    quantity INTEGER DEFAULT 1,
    post_process TEXT DEFAULT 'none',
    due_date TEXT DEFAULT '',
    notes TEXT DEFAULT '',
    cost_material REAL DEFAULT 0,
    cost_electricity REAL DEFAULT 0,
    cost_wear REAL DEFAULT 0,
    cost_post REAL DEFAULT 0,
    cost_subtotal REAL DEFAULT 0,
    cost_markup REAL DEFAULT 0,
    cost_calculated REAL DEFAULT 0,
    cost_final REAL DEFAULT 0,
    FOREIGN KEY (user_id) REFERENCES users(id)
  );

  CREATE TABLE IF NOT EXISTS settings (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
  );
`);

// ============= SEED ADMIN =============
const adminExists = db.prepare('SELECT id FROM users WHERE username = ?').get('admin');
if (!adminExists) {
  const hash = bcrypt.hashSync('admin', 10);
  db.prepare('INSERT INTO users (username, password_hash, role, name, contact) VALUES (?, ?, ?, ?, ?)')
    .run('admin', hash, 'admin', 'Admin', '');
  console.log('Default admin account created (username: admin, password: admin)');
}

// ============= SEED DEFAULT SETTINGS =============
const DEFAULT_SETTINGS = {
  currency: '$',
  materialPrices: { PLA: 20, ABS: 22, PETG: 25, TPU: 30, Nylon: 40, Resin: 35 },
  elecRate: 0.12,
  printerWatt: 200,
  printerCost: 300,
  printerLife: 5000,
  markup: 50,
  postProcessCost: { none: 0, supports: 2, sanding: 5, painting: 8, full: 12 }
};

const settingsExist = db.prepare('SELECT key FROM settings WHERE key = ?').get('pricing');
if (!settingsExist) {
  db.prepare('INSERT INTO settings (key, value) VALUES (?, ?)').run('pricing', JSON.stringify(DEFAULT_SETTINGS));
}

// ============= HELPERS =============
const users = {
  findByUsername: db.prepare('SELECT * FROM users WHERE username = ?'),
  findById: db.prepare('SELECT id, username, role, name, contact, created_at FROM users WHERE id = ?'),
  create: db.prepare('INSERT INTO users (username, password_hash, role, name, contact) VALUES (?, ?, ?, ?, ?)'),
  updatePassword: db.prepare('UPDATE users SET password_hash = ? WHERE id = ?'),
};

const ordersDb = {
  getAll: db.prepare('SELECT * FROM orders ORDER BY id DESC'),
  getByUser: db.prepare('SELECT * FROM orders WHERE user_id = ? ORDER BY id DESC'),
  getById: db.prepare('SELECT * FROM orders WHERE id = ?'),
  create: db.prepare(`INSERT INTO orders (
    user_id, status, customer_name, customer_contact,
    item_description, file_name, file_original_name, material, color,
    infill, layer_height, weight, print_time, quantity, post_process,
    due_date, notes, cost_material, cost_electricity, cost_wear,
    cost_post, cost_subtotal, cost_markup, cost_calculated, cost_final
  ) VALUES (
    @user_id, @status, @customer_name, @customer_contact,
    @item_description, @file_name, @file_original_name, @material, @color,
    @infill, @layer_height, @weight, @print_time, @quantity, @post_process,
    @due_date, @notes, @cost_material, @cost_electricity, @cost_wear,
    @cost_post, @cost_subtotal, @cost_markup, @cost_calculated, @cost_final
  )`),
  update: (id, fields) => {
    const sets = Object.keys(fields).map(k => `${k} = @${k}`).join(', ');
    return db.prepare(`UPDATE orders SET ${sets} WHERE id = @id`).run({ ...fields, id });
  },
  delete: db.prepare('DELETE FROM orders WHERE id = ?'),
};

const settingsDb = {
  get: () => {
    const row = db.prepare('SELECT value FROM settings WHERE key = ?').get('pricing');
    return row ? JSON.parse(row.value) : DEFAULT_SETTINGS;
  },
  set: (value) => {
    db.prepare('INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)').run('pricing', JSON.stringify(value));
  },
};

module.exports = { db, users, orders: ordersDb, settings: settingsDb, DEFAULT_SETTINGS };
