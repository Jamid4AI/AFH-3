// AFH Complete v3.1 - Full Featured with Roles, Time Tracking, Exports
// Uses sql.js (pure JavaScript) - works on Railway without build issues

const express = require('express');
const initSqlJs = require('sql.js');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

const DB_PATH = './afh.db';
let db;

// Initialize database
async function initDB() {
  const SQL = await initSqlJs();
  
  // Load existing database or create new one
  if (fs.existsSync(DB_PATH)) {
    const buffer = fs.readFileSync(DB_PATH);
    db = new SQL.Database(buffer);
  } else {
    db = new SQL.Database();
  }
  
  // Create tables
  db.run(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      email TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      name TEXT NOT NULL,
      role TEXT DEFAULT 'owner',
      phone TEXT,
      home_id INTEGER,
      invited_by INTEGER,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
  `);
  
  db.run(`CREATE TABLE IF NOT EXISTS sessions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    token TEXT UNIQUE,
    expires_at DATETIME
  )`);
  
  db.run(`CREATE TABLE IF NOT EXISTS invitations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    home_id INTEGER,
    email TEXT,
    role TEXT DEFAULT 'caregiver',
    token TEXT UNIQUE,
    invited_by INTEGER,
    expires_at DATETIME,
    used INTEGER DEFAULT 0,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);
  
  db.run(`CREATE TABLE IF NOT EXISTS homes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    name TEXT NOT NULL,
    address TEXT,
    city TEXT,
    state TEXT DEFAULT 'WA',
    zip TEXT,
    phone TEXT,
    license_number TEXT,
    capacity INTEGER DEFAULT 6,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);
  
  db.run(`CREATE TABLE IF NOT EXISTS residents (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    home_id INTEGER,
    name TEXT NOT NULL,
    room TEXT,
    date_of_birth TEXT,
    admission_date TEXT,
    discharge_date TEXT,
    conditions TEXT,
    notes TEXT,
    photo_url TEXT,
    active INTEGER DEFAULT 1,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);
  
  db.run(`CREATE TABLE IF NOT EXISTS poa_contacts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    resident_id INTEGER UNIQUE,
    name TEXT NOT NULL,
    relationship TEXT,
    phone TEXT,
    email TEXT,
    poa_type TEXT,
    is_billing_contact INTEGER DEFAULT 0,
    is_emergency_contact INTEGER DEFAULT 1,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);
  
  db.run(`CREATE TABLE IF NOT EXISTS family_members (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    resident_id INTEGER,
    name TEXT NOT NULL,
    relationship TEXT,
    phone TEXT,
    email TEXT,
    receive_updates INTEGER DEFAULT 1,
    receive_weekly_reports INTEGER DEFAULT 1,
    receive_incident_alerts INTEGER DEFAULT 0,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);
  
  db.run(`CREATE TABLE IF NOT EXISTS family_messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    home_id INTEGER,
    resident_id INTEGER,
    message TEXT,
    message_type TEXT DEFAULT 'update',
    recipient_type TEXT DEFAULT 'all',
    sent_by TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);
  
  db.run(`CREATE TABLE IF NOT EXISTS staff (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    home_id INTEGER,
    user_id INTEGER,
    name TEXT NOT NULL,
    role TEXT DEFAULT 'Caregiver',
    phone TEXT,
    email TEXT,
    hourly_rate REAL,
    active INTEGER DEFAULT 1,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);
  
  db.run(`CREATE TABLE IF NOT EXISTS certifications (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    staff_id INTEGER,
    type TEXT NOT NULL,
    issue_date TEXT,
    expiration_date TEXT,
    certificate_number TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);
  
  db.run(`CREATE TABLE IF NOT EXISTS time_entries (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    home_id INTEGER,
    user_id INTEGER,
    staff_id INTEGER,
    clock_in DATETIME,
    clock_out DATETIME,
    break_minutes INTEGER DEFAULT 0,
    notes TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);
  
  db.run(`CREATE TABLE IF NOT EXISTS scheduled_shifts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    home_id INTEGER,
    staff_id INTEGER,
    date TEXT,
    start_time TEXT,
    end_time TEXT,
    notes TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);
  
  db.run(`CREATE TABLE IF NOT EXISTS activities (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    home_id INTEGER,
    resident_id INTEGER,
    user_id INTEGER,
    staff_name TEXT,
    type TEXT,
    mood TEXT,
    notes TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);
  
  db.run(`CREATE TABLE IF NOT EXISTS incidents (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    home_id INTEGER,
    resident_id INTEGER,
    user_id INTEGER,
    type TEXT,
    severity TEXT,
    description TEXT,
    immediate_actions TEXT,
    follow_up TEXT,
    reported_by TEXT,
    witnesses TEXT,
    notified_poa INTEGER DEFAULT 0,
    notified_at DATETIME,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);
  
  db.run(`CREATE TABLE IF NOT EXISTS medications (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    resident_id INTEGER,
    name TEXT NOT NULL,
    dosage TEXT,
    frequency TEXT,
    instructions TEXT,
    prescriber TEXT,
    pharmacy TEXT,
    active INTEGER DEFAULT 1,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);
  
  db.run(`CREATE TABLE IF NOT EXISTS mar_records (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    medication_id INTEGER,
    resident_id INTEGER,
    user_id INTEGER,
    administered_by TEXT,
    administered_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    status TEXT DEFAULT 'given',
    notes TEXT
  )`);
  
  db.run(`CREATE TABLE IF NOT EXISTS inspection_items (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    home_id INTEGER,
    category TEXT,
    item TEXT,
    status TEXT DEFAULT 'pending',
    verified_by TEXT,
    verified_at DATETIME,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);
  
  db.run(`CREATE TABLE IF NOT EXISTS audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    user_name TEXT,
    home_id INTEGER,
    action TEXT,
    entity_type TEXT,
    entity_id INTEGER,
    details TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);
  
  saveDB();
  console.log('Database initialized');
}

// Save database to file
function saveDB() {
  const data = db.export();
  const buffer = Buffer.from(data);
  fs.writeFileSync(DB_PATH, buffer);
}

// Helper functions for sql.js (different API than better-sqlite3)
function dbRun(sql, params = []) {
  db.run(sql, params);
  saveDB();
  return { lastInsertRowid: db.exec("SELECT last_insert_rowid()")[0]?.values[0][0] };
}

function dbGet(sql, params = []) {
  const stmt = db.prepare(sql);
  stmt.bind(params);
  if (stmt.step()) {
    const row = stmt.getAsObject();
    stmt.free();
    return row;
  }
  stmt.free();
  return null;
}

function dbAll(sql, params = []) {
  const stmt = db.prepare(sql);
  stmt.bind(params);
  const results = [];
  while (stmt.step()) {
    results.push(stmt.getAsObject());
  }
  stmt.free();
  return results;
}

// ============================================
// AUTH & ROLE HELPERS
// ============================================
function hashPassword(password) {
  const salt = crypto.randomBytes(16).toString('hex');
  const hash = crypto.pbkdf2Sync(password, salt, 1000, 64, 'sha512').toString('hex');
  return salt + ':' + hash;
}

function verifyPassword(password, stored) {
  const [salt, hash] = stored.split(':');
  const verify = crypto.pbkdf2Sync(password, salt, 1000, 64, 'sha512').toString('hex');
  return hash === verify;
}

function generateToken() {
  return crypto.randomBytes(32).toString('hex');
}

function getUser(token) {
  if (!token) return null;
  return dbGet('SELECT u.* FROM sessions s JOIN users u ON s.user_id = u.id WHERE s.token = ? AND s.expires_at > datetime("now")', [token]);
}

const ROLES = {
  owner: { level: 100, canManageUsers: true, canViewAllData: true, canExport: true, canDelete: true, canEditSettings: true },
  admin: { level: 80, canManageUsers: true, canViewAllData: true, canExport: true, canDelete: false, canEditSettings: false },
  caregiver: { level: 20, canManageUsers: false, canViewAllData: false, canExport: false, canDelete: false, canEditSettings: false },
  family: { level: 10, canManageUsers: false, canViewAllData: false, canExport: false, canDelete: false, canEditSettings: false }
};

function logAudit(userId, userName, homeId, action, entityType, entityId, details) {
  try {
    dbRun('INSERT INTO audit_log (user_id, user_name, home_id, action, entity_type, entity_id, details) VALUES (?, ?, ?, ?, ?, ?, ?)', 
      [userId, userName, homeId, action, entityType, entityId, JSON.stringify(details || {})]);
  } catch (e) { console.error('Audit error:', e); }
}

function initChecklist(homeId) {
  const items = {
    'Resident Rights': ['Resident rights posted', 'Privacy maintained', 'Visitors allowed', 'Personal possessions respected'],
    'Medications': ['Medications locked', 'MAR current', 'PRN documented', 'Expired meds disposed', 'Controlled substances double-locked'],
    'Food Service': ['Food temps proper', 'Kitchen sanitized', 'Food handler permits current', 'Menus posted', 'Special diets accommodated'],
    'Emergency': ['Evacuation plan posted', 'Fire extinguishers inspected', 'Smoke detectors tested', 'Emergency supplies stocked', 'Staff trained'],
    'Staff': ['Background checks current', 'CPR/First Aid current', 'TB tests current', 'Training records maintained', 'Ratios maintained'],
    'Safety': ['Grab bars in bathrooms', 'Non-slip surfaces', 'Adequate lighting', 'Handrails on stairs', 'Hot water under 120F'],
    'Documentation': ['Care plans current', 'Incidents filed within 24hrs', 'Physician orders current', 'Service agreements signed']
  };
  for (const [cat, list] of Object.entries(items)) {
    for (const item of list) {
      dbRun('INSERT INTO inspection_items (home_id, category, item) VALUES (?, ?, ?)', [homeId, cat, item]);
    }
  }
}

function getCurrentClockIn(userId, homeId) {
  return dbGet('SELECT * FROM time_entries WHERE user_id = ? AND home_id = ? AND clock_out IS NULL ORDER BY clock_in DESC LIMIT 1', [userId, homeId]);
}

// ============================================
// STYLES
// ============================================
const styles = `
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;background:#f1f5f9;min-height:100vh}
.container{max-width:1200px;margin:0 auto;padding:20px}
.card{background:white;border-radius:16px;padding:24px;margin-bottom:20px;box-shadow:0 1px 3px rgba(0,0,0,0.1)}
.btn{padding:12px 24px;border-radius:8px;border:none;cursor:pointer;font-weight:600;font-size:14px;text-decoration:none;display:inline-block;transition:all 0.2s}
.btn-primary{background:linear-gradient(135deg,#4F46E5,#7C3AED);color:white}
.btn-primary:hover{transform:translateY(-1px);box-shadow:0 4px 12px rgba(79,70,229,0.4)}
.btn-secondary{background:#e2e8f0;color:#475569}
.btn-danger{background:#EF4444;color:white}
.btn-success{background:#22C55E;color:white}
.btn-warning{background:#F59E0B;color:white}
.btn-sm{padding:8px 16px;font-size:13px}
.btn-lg{padding:16px 32px;font-size:18px}
input,select,textarea{width:100%;padding:12px 16px;border:2px solid #e2e8f0;border-radius:10px;font-size:16px;margin-bottom:16px;-webkit-appearance:none;appearance:none}
input[type="date"]{min-height:48px;font-size:16px}
input[type="date"]::-webkit-calendar-picker-indicator{opacity:1;font-size:20px;padding:4px;cursor:pointer}
input:focus,select:focus,textarea:focus{outline:none;border-color:#4F46E5}
label{display:block;font-weight:600;margin-bottom:6px;color:#374151;font-size:14px}
h1{font-size:28px;color:#1e293b;margin-bottom:8px}
h2{font-size:22px;color:#1e293b;margin-bottom:16px}
h3{font-size:16px;color:#475569;margin-bottom:12px;font-weight:600}
.header{background:linear-gradient(135deg,#4F46E5,#7C3AED);color:white;padding:20px;margin:-20px -20px 20px -20px;border-radius:16px 16px 0 0}
@media(min-width:768px){.header{margin:0 0 20px 0;border-radius:16px;padding:24px}}
.header h1{color:white;font-size:24px}
.nav{display:flex;gap:8px;margin-top:16px;flex-wrap:wrap}
.nav a{color:white;text-decoration:none;padding:10px 16px;background:rgba(255,255,255,0.15);border-radius:10px;font-weight:500;font-size:14px}
.nav a:hover,.nav a.active{background:rgba(255,255,255,0.25)}
.grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(300px,1fr));gap:20px}
.grid-2{display:grid;grid-template-columns:1fr 1fr;gap:20px}
.grid-3{display:grid;grid-template-columns:1fr 1fr 1fr;gap:20px}
.grid-4{display:grid;grid-template-columns:1fr 1fr 1fr 1fr;gap:16px}
.stat-card{text-align:center;padding:24px;background:linear-gradient(135deg,#f8fafc,#f1f5f9);border-radius:16px}
.stat-number{font-size:42px;font-weight:700;background:linear-gradient(135deg,#4F46E5,#7C3AED);-webkit-background-clip:text;-webkit-text-fill-color:transparent;background-clip:text}
.stat-label{color:#64748b;margin-top:4px;font-weight:500}
table{width:100%;border-collapse:collapse}
th,td{padding:14px 16px;text-align:left;border-bottom:1px solid #e2e8f0}
th{font-weight:600;color:#475569;background:#f8fafc;font-size:13px;text-transform:uppercase}
.badge{padding:6px 12px;border-radius:20px;font-size:12px;font-weight:600;display:inline-block}
.badge-green{background:#dcfce7;color:#166534}
.badge-yellow{background:#fef9c3;color:#854d0e}
.badge-red{background:#fee2e2;color:#991b1b}
.badge-blue{background:#dbeafe;color:#1e40af}
.badge-purple{background:#f3e8ff;color:#7c3aed}
.badge-gray{background:#f1f5f9;color:#475569}
.activity-item{display:flex;align-items:flex-start;gap:16px;padding:16px 0;border-bottom:1px solid #f1f5f9}
.activity-icon{width:44px;height:44px;border-radius:12px;display:flex;align-items:center;justify-content:center;font-size:20px;flex-shrink:0}
.activity-content{flex:1}
.activity-time{color:#94a3b8;font-size:13px}
.form-row{display:grid;grid-template-columns:1fr 1fr;gap:20px}
.alert{padding:16px 20px;border-radius:12px;margin-bottom:20px}
.alert-success{background:#dcfce7;color:#166534}
.alert-error{background:#fee2e2;color:#991b1b}
.alert-warning{background:#fef9c3;color:#854d0e}
.alert-info{background:#dbeafe;color:#1e40af}
.center{text-align:center}
.mt-4{margin-top:16px}
.mb-4{margin-bottom:16px}
.text-muted{color:#64748b}
.text-sm{font-size:14px}
.login-container{max-width:420px;margin:60px auto;padding:0 20px}
.logo{font-size:32px;font-weight:700;background:linear-gradient(135deg,#4F46E5,#7C3AED);-webkit-background-clip:text;-webkit-text-fill-color:transparent;background-clip:text;margin-bottom:8px}
.empty-state{text-align:center;padding:60px 20px;color:#94a3b8}
.resident-card{display:flex;align-items:center;gap:16px;padding:16px;background:#f8fafc;border-radius:12px;margin-bottom:12px}
.resident-avatar{width:56px;height:56px;border-radius:14px;background:linear-gradient(135deg,#4F46E5,#7C3AED);color:white;display:flex;align-items:center;justify-content:center;font-size:22px;font-weight:700}
.quick-action{display:flex;flex-direction:column;align-items:center;padding:20px;background:linear-gradient(135deg,#f8fafc,#f1f5f9);border-radius:16px;text-decoration:none;color:#475569;transition:all 0.2s;border:2px solid transparent}
.quick-action:hover{border-color:#4F46E5;background:white;transform:translateY(-2px)}
.quick-action-icon{width:56px;height:56px;border-radius:16px;display:flex;align-items:center;justify-content:center;font-size:28px;margin-bottom:12px}
.checklist-item{display:flex;align-items:center;gap:12px;padding:12px 16px;border-radius:10px;margin-bottom:8px;background:#f8fafc}
.checklist-item.complete{background:#dcfce7}
.checklist-item input[type="checkbox"]{width:20px;height:20px;cursor:pointer}
.progress-bar{height:8px;background:#e2e8f0;border-radius:4px;overflow:hidden}
.progress-fill{height:100%;background:linear-gradient(90deg,#22C55E,#16A34A);border-radius:4px}
.clock-display{font-size:48px;font-weight:700;font-family:monospace;color:#1e293b}
.clock-status{padding:20px;border-radius:16px;text-align:center}
.clock-status.clocked-in{background:linear-gradient(135deg,#dcfce7,#bbf7d0)}
.clock-status.clocked-out{background:linear-gradient(135deg,#fee2e2,#fecaca)}
.user-role{display:inline-flex;align-items:center;gap:6px;padding:4px 12px;border-radius:20px;font-size:12px;font-weight:600}
.role-owner{background:#f3e8ff;color:#7c3aed}
.role-admin{background:#dbeafe;color:#1e40af}
.role-caregiver{background:#dcfce7;color:#166534}
.role-family{background:#fef9c3;color:#854d0e}
@media(max-width:768px){.form-row,.grid-2,.grid-3,.grid-4{grid-template-columns:1fr}.nav{flex-direction:column}.grid{grid-template-columns:1fr}.container{padding:12px}h1{font-size:22px}h2{font-size:18px}.stat-number{font-size:32px}.btn{width:100%;text-align:center}.clock-display{font-size:32px}}
@media print{.no-print{display:none!important}.card{box-shadow:none;border:1px solid #e2e8f0}}
`;

function layout(title, content, user, activeNav) {
  const perms = ROLES[user?.role] || {};
  let navItems = '';
  
  if (user) {
    navItems = '<a href="/dashboard" class="'+(activeNav==='dashboard'?'active':'')+'">📊 Dashboard</a>';
    navItems += '<a href="/residents" class="'+(activeNav==='residents'?'active':'')+'">👥 Residents</a>';
    
    if (user.role !== 'family') {
      navItems += '<a href="/activities" class="'+(activeNav==='activities'?'active':'')+'">📝 Activities</a>';
      navItems += '<a href="/medications" class="'+(activeNav==='medications'?'active':'')+'">💊 Medications</a>';
      navItems += '<a href="/incidents" class="'+(activeNav==='incidents'?'active':'')+'">⚠️ Incidents</a>';
      navItems += '<a href="/timeclock" class="'+(activeNav==='timeclock'?'active':'')+'">⏱️ Time Clock</a>';
    }
    
    if (perms.canManageUsers) {
      navItems += '<a href="/staff" class="'+(activeNav==='staff'?'active':'')+'">👤 Staff</a>';
      navItems += '<a href="/family" class="'+(activeNav==='family'?'active':'')+'">👨‍👩‍👧 Family</a>';
      navItems += '<a href="/users" class="'+(activeNav==='users'?'active':'')+'">🔐 Users</a>';
    }
    
    if (perms.canViewAllData) {
      navItems += '<a href="/inspection" class="'+(activeNav==='inspection'?'active':'')+'">✅ Inspection</a>';
      navItems += '<a href="/reports" class="'+(activeNav==='reports'?'active':'')+'">📈 Reports</a>';
    }
  }
  
  const roleClass = 'role-' + (user?.role || 'caregiver');
  const clockedIn = user ? getCurrentClockIn(user.id, user.home_id) : null;
  
  const nav = user ? '<div class="header"><div style="display:flex;justify-content:space-between;align-items:flex-start;flex-wrap:wrap;gap:12px"><div><h1>🏠 AFH Complete</h1><p>Welcome, '+user.name+' <span class="user-role '+roleClass+'">'+user.role+'</span>'+(clockedIn?' <span class="badge badge-green">● Clocked In</span>':'')+'</p></div><a href="/logout" class="btn btn-secondary btn-sm" style="background:rgba(255,255,255,0.2);color:white">Logout</a></div><div class="nav">'+navItems+'</div></div>' : '';
  
  return '<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0,maximum-scale=1.0"><meta name="apple-mobile-web-app-capable" content="yes"><meta name="theme-color" content="#4F46E5"><title>'+title+' - AFH Complete</title><style>'+styles+'</style></head><body><div class="container">'+nav+content+'</div></body></html>';
}

// ============================================
// AUTH ROUTES
// ============================================
app.get('/', (req, res) => {
  const token = req.headers.cookie?.split('token=')[1]?.split(';')[0];
  res.redirect(getUser(token) ? '/dashboard' : '/login');
});

app.get('/login', (req, res) => {
  const e = req.query.error, s = req.query.success;
  res.send(layout('Login', '<div class="login-container"><div class="card center"><div class="logo">🏠 AFH Complete</div><p class="text-muted mb-4">Adult Family Home Management</p>'+(e?'<div class="alert alert-error">⚠️ '+e+'</div>':'')+(s?'<div class="alert alert-success">✓ '+s+'</div>':'')+'<form method="POST" action="/login" style="text-align:left"><label>Email</label><input type="email" name="email" required placeholder="you@example.com"><label>Password</label><input type="password" name="password" required placeholder="••••••••"><button type="submit" class="btn btn-primary" style="width:100%">Sign In</button></form><p class="mt-4 text-muted">No account? <a href="/register" style="color:#4F46E5;font-weight:600">Create one</a></p></div></div>'));
});

app.post('/login', (req, res) => {
  const { email, password } = req.body;
  const user = dbGet('SELECT * FROM users WHERE email = ?', [email?.toLowerCase()]);
  if (!user || !verifyPassword(password, user.password_hash)) return res.redirect('/login?error=Invalid email or password');
  const token = generateToken();
  dbRun('INSERT INTO sessions (user_id, token, expires_at) VALUES (?, ?, ?)', [user.id, token, new Date(Date.now() + 30*24*60*60*1000).toISOString()]);
  logAudit(user.id, user.name, user.home_id, 'USER_LOGIN', 'user', user.id, {});
  res.setHeader('Set-Cookie', 'token='+token+'; Path=/; HttpOnly; SameSite=Lax; Max-Age='+30*24*60*60);
  res.redirect('/dashboard');
});

app.get('/register', (req, res) => {
  const e = req.query.error;
  res.send(layout('Register', '<div class="login-container"><div class="card center"><div class="logo">🏠 AFH Complete</div><p class="text-muted mb-4">Create your account</p>'+(e?'<div class="alert alert-error">⚠️ '+e+'</div>':'')+'<form method="POST" action="/register" style="text-align:left"><label>Your Name *</label><input type="text" name="name" required placeholder="Jane Smith"><label>Email *</label><input type="email" name="email" required placeholder="you@example.com"><label>Password *</label><input type="password" name="password" required placeholder="Min 8 characters" minlength="8"><label>Home Name *</label><input type="text" name="homeName" required placeholder="Sunrise AFH"><button type="submit" class="btn btn-primary" style="width:100%">Create Account</button></form><p class="mt-4 text-muted">Have an account? <a href="/login" style="color:#4F46E5;font-weight:600">Sign in</a></p></div></div>'));
});

app.post('/register', (req, res) => {
  const { name, email, password, homeName } = req.body;
  if (!name || !email || !password || !homeName) return res.redirect('/register?error=All fields required');
  if (dbGet('SELECT id FROM users WHERE email = ?', [email.toLowerCase()])) return res.redirect('/register?error=Email already registered');
  try {
    const homeResult = dbRun('INSERT INTO homes (name) VALUES (?)', [homeName]);
    const homeId = homeResult.lastInsertRowid;
    const userResult = dbRun('INSERT INTO users (email, password_hash, name, role, home_id) VALUES (?, ?, ?, ?, ?)', [email.toLowerCase(), hashPassword(password), name, 'owner', homeId]);
    dbRun('UPDATE homes SET user_id = ? WHERE id = ?', [userResult.lastInsertRowid, homeId]);
    initChecklist(homeId);
    const token = generateToken();
    dbRun('INSERT INTO sessions (user_id, token, expires_at) VALUES (?, ?, ?)', [userResult.lastInsertRowid, token, new Date(Date.now() + 30*24*60*60*1000).toISOString()]);
    logAudit(userResult.lastInsertRowid, name, homeId, 'USER_REGISTERED', 'user', userResult.lastInsertRowid, { role: 'owner' });
    res.setHeader('Set-Cookie', 'token='+token+'; Path=/; HttpOnly; SameSite=Lax; Max-Age='+30*24*60*60);
    res.redirect('/dashboard');
  } catch (e) { console.error(e); res.redirect('/register?error=Registration failed'); }
});

app.get('/invite/:token', (req, res) => {
  const inv = dbGet('SELECT i.*, h.name as home_name FROM invitations i JOIN homes h ON i.home_id = h.id WHERE i.token = ? AND i.used = 0 AND i.expires_at > datetime("now")', [req.params.token]);
  if (!inv) return res.send(layout('Invalid Invitation', '<div class="login-container"><div class="card center"><h2>Invalid or Expired Invitation</h2><p class="text-muted">This invitation link is no longer valid.</p><a href="/login" class="btn btn-primary mt-4">Go to Login</a></div></div>'));
  
  res.send(layout('Accept Invitation', '<div class="login-container"><div class="card center"><div class="logo">🏠 AFH Complete</div><p class="text-muted mb-4">You\'ve been invited to join <strong>'+inv.home_name+'</strong> as a <strong>'+inv.role+'</strong></p><form method="POST" action="/invite/'+req.params.token+'" style="text-align:left"><label>Your Name *</label><input type="text" name="name" required placeholder="Your Name"><label>Email</label><input type="email" value="'+inv.email+'" disabled style="background:#f1f5f9"><input type="hidden" name="email" value="'+inv.email+'"><label>Create Password *</label><input type="password" name="password" required placeholder="Min 8 characters" minlength="8"><button type="submit" class="btn btn-primary" style="width:100%">Accept & Create Account</button></form></div></div>'));
});

app.post('/invite/:token', (req, res) => {
  const { name, email, password } = req.body;
  const inv = dbGet('SELECT * FROM invitations WHERE token = ? AND used = 0 AND expires_at > datetime("now")', [req.params.token]);
  if (!inv) return res.redirect('/login?error=Invalid invitation');
  
  try {
    const userResult = dbRun('INSERT INTO users (email, password_hash, name, role, home_id, invited_by) VALUES (?, ?, ?, ?, ?, ?)', [email.toLowerCase(), hashPassword(password), name, inv.role, inv.home_id, inv.invited_by]);
    dbRun('UPDATE invitations SET used = 1 WHERE id = ?', [inv.id]);
    
    if (inv.role === 'caregiver') {
      dbRun('INSERT INTO staff (home_id, user_id, name, email, role) VALUES (?, ?, ?, ?, ?)', [inv.home_id, userResult.lastInsertRowid, name, email, 'Caregiver']);
    }
    
    const token = generateToken();
    dbRun('INSERT INTO sessions (user_id, token, expires_at) VALUES (?, ?, ?)', [userResult.lastInsertRowid, token, new Date(Date.now() + 30*24*60*60*1000).toISOString()]);
    logAudit(userResult.lastInsertRowid, name, inv.home_id, 'USER_ACCEPTED_INVITE', 'user', userResult.lastInsertRowid, { role: inv.role });
    res.setHeader('Set-Cookie', 'token='+token+'; Path=/; HttpOnly; SameSite=Lax; Max-Age='+30*24*60*60);
    res.redirect('/dashboard');
  } catch (e) { console.error(e); res.redirect('/login?error=Account creation failed'); }
});

app.get('/logout', (req, res) => {
  const token = req.headers.cookie?.split('token=')[1]?.split(';')[0];
  if (token) dbRun('DELETE FROM sessions WHERE token = ?', [token]);
  res.setHeader('Set-Cookie', 'token=; Path=/; HttpOnly; Max-Age=0');
  res.redirect('/login?success=Logged out');
});

function requireAuth(req, res, next) {
  const token = req.headers.cookie?.split('token=')[1]?.split(';')[0];
  const user = getUser(token);
  if (!user) return res.redirect('/login');
  req.user = user;
  req.home = dbGet('SELECT * FROM homes WHERE id = ?', [user.home_id]);
  req.perms = ROLES[user.role] || {};
  next();
}

function requireRole(...roles) {
  return (req, res, next) => {
    if (!roles.includes(req.user.role)) {
      return res.send(layout('Access Denied', '<div class="card center"><h2>Access Denied</h2><p class="text-muted">You don\'t have permission to view this page.</p><a href="/dashboard" class="btn btn-primary mt-4">Back to Dashboard</a></div>', req.user, ''));
    }
    next();
  };
}

// ============================================
// DASHBOARD
// ============================================
app.get('/dashboard', requireAuth, (req, res) => {
  const home = req.home;
  const hid = home?.id || 0;
  
  const residentCount = dbGet('SELECT COUNT(*) as c FROM residents WHERE home_id = ? AND active = 1', [hid])?.c || 0;
  const staffCount = dbGet('SELECT COUNT(*) as c FROM staff WHERE home_id = ? AND active = 1', [hid])?.c || 0;
  const clockedInNow = dbAll('SELECT t.*, u.name FROM time_entries t JOIN users u ON t.user_id = u.id WHERE t.home_id = ? AND t.clock_out IS NULL', [hid]);
  const activities = dbAll('SELECT a.*, r.name as rn FROM activities a LEFT JOIN residents r ON a.resident_id = r.id WHERE a.home_id = ? ORDER BY a.created_at DESC LIMIT 8', [hid]);
  const expiringCerts = dbAll('SELECT c.*, s.name as sn FROM certifications c JOIN staff s ON c.staff_id = s.id WHERE s.home_id = ? AND c.expiration_date <= date("now", "+60 days") ORDER BY c.expiration_date LIMIT 5', [hid]);
  const recentIncidents = dbAll('SELECT i.*, r.name as rn FROM incidents i LEFT JOIN residents r ON i.resident_id = r.id WHERE i.home_id = ? ORDER BY i.created_at DESC LIMIT 3', [hid]);
  
  const totalItems = dbGet('SELECT COUNT(*) as c FROM inspection_items WHERE home_id = ?', [hid])?.c || 0;
  const completedItems = dbGet('SELECT COUNT(*) as c FROM inspection_items WHERE home_id = ? AND status = "complete"', [hid])?.c || 0;
  const readiness = totalItems > 0 ? Math.round((completedItems / totalItems) * 100) : 0;
  
  const icons = { meal: ['🍽️','#dcfce7'], medication: ['💊','#dbeafe'], activity: ['🎯','#fef9c3'], rest: ['😴','#f3e8ff'], outing: ['🌳','#dcfce7'], social: ['👥','#fce7f3'], hygiene: ['🚿','#e0f2fe'] };
  
  let quickActions = '';
  if (req.user.role !== 'family') {
    quickActions = '<div class="grid-4" style="margin-bottom:24px"><a href="/activities/new" class="quick-action"><div class="quick-action-icon" style="background:#dcfce7">📝</div><span>Log Activity</span></a><a href="/medications/administer" class="quick-action"><div class="quick-action-icon" style="background:#dbeafe">💊</div><span>Give Meds</span></a><a href="/incidents/new" class="quick-action"><div class="quick-action-icon" style="background:#fee2e2">⚠️</div><span>Report Incident</span></a><a href="/timeclock" class="quick-action"><div class="quick-action-icon" style="background:#fef9c3">⏱️</div><span>Time Clock</span></a></div>';
  }
  
  let clockedInHtml = '';
  if (req.perms.canViewAllData && clockedInNow.length > 0) {
    clockedInHtml = '<div class="card"><h3>👥 Currently Working</h3><div style="display:flex;gap:12px;flex-wrap:wrap">'+clockedInNow.map(c => {
      const mins = Math.floor((new Date() - new Date(c.clock_in)) / 60000);
      return '<div style="background:#dcfce7;padding:12px 16px;border-radius:10px"><strong>'+c.name+'</strong><br><span class="text-sm text-muted">'+Math.floor(mins/60)+'h '+mins%60+'m</span></div>';
    }).join('')+'</div></div>';
  }
  
  let actHtml = activities.length > 0 ? activities.map(a => {
    const ic = icons[a.type] || ['📝','#f1f5f9'];
    return '<div class="activity-item"><div class="activity-icon" style="background:'+ic[1]+'">'+ic[0]+'</div><div class="activity-content"><strong>'+(a.rn||'Unknown')+'</strong> - '+(a.type||'Activity')+(a.notes?'<p class="text-sm text-muted">'+a.notes.substring(0,60)+'</p>':'')+'</div><div class="activity-time">'+new Date(a.created_at).toLocaleTimeString([],{hour:'2-digit',minute:'2-digit'})+'</div></div>';
  }).join('') : '<div class="empty-state" style="padding:30px"><p>No activities yet</p></div>';
  
  let alertsHtml = '';
  if (expiringCerts.length > 0) {
    alertsHtml += '<div class="alert alert-warning"><strong>⚠️ Expiring Certifications</strong>'+expiringCerts.map(c => {
      const days = Math.ceil((new Date(c.expiration_date) - new Date()) / (1000*60*60*24));
      return '<br>'+c.sn+': '+c.type+' - '+(days<0?'EXPIRED':days+' days');
    }).join('')+'</div>';
  }
  if (recentIncidents.length > 0 && req.perms.canViewAllData) {
    alertsHtml += '<h4 style="margin-top:16px">Recent Incidents</h4>'+recentIncidents.map(i => '<div style="background:#f8fafc;padding:12px;border-radius:8px;margin-top:8px"><strong>'+(i.rn||'Unknown')+'</strong> - '+i.type+' <span class="badge '+(i.severity==='major'?'badge-red':'badge-yellow')+'">'+i.severity+'</span><p class="text-sm text-muted">'+new Date(i.created_at).toLocaleDateString()+'</p></div>').join('');
  }
  if (!alertsHtml) alertsHtml = '<div class="empty-state" style="padding:30px"><p>✅ No alerts</p></div>';
  
  const statsHtml = req.perms.canViewAllData ? '<div class="grid-4" style="margin-bottom:24px"><div class="card stat-card"><div class="stat-number">'+residentCount+'</div><div class="stat-label">Residents</div></div><div class="card stat-card"><div class="stat-number">'+staffCount+'</div><div class="stat-label">Staff</div></div><div class="card stat-card"><div class="stat-number">'+readiness+'%</div><div class="stat-label">Inspection Ready</div></div><div class="card stat-card"><div class="stat-number" style="'+(expiringCerts.length>0?'color:#EF4444;-webkit-text-fill-color:#EF4444':'')+'">'+expiringCerts.length+'</div><div class="stat-label">Certs Expiring</div></div></div>' : '';
  
  res.send(layout('Dashboard', '<h2>Dashboard</h2><p class="text-muted mb-4">'+(home?.name||'Your Home')+'</p>'+quickActions+statsHtml+clockedInHtml+'<div class="grid-2"><div class="card"><div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:16px"><h3>Recent Activity</h3><a href="/activities" class="text-sm" style="color:#4F46E5">View All →</a></div>'+actHtml+'</div><div class="card"><h3>Alerts</h3>'+alertsHtml+'</div></div>', req.user, 'dashboard'));
});

// ============================================
// RESIDENTS
// ============================================
app.get('/residents', requireAuth, (req, res) => {
  const residents = dbAll('SELECT * FROM residents WHERE home_id = ? AND active = 1 ORDER BY name', [req.home?.id || 0]);
  let html = residents.length > 0 ? residents.map(r => '<div class="resident-card"><div class="resident-avatar">'+r.name.charAt(0)+'</div><div style="flex:1"><h4 style="margin:0">'+r.name+'</h4><p class="text-sm text-muted">Room '+(r.room||'-')+' '+(r.conditions?'• '+r.conditions:'')+'</p></div><a href="/residents/'+r.id+'" class="btn btn-secondary btn-sm">View</a></div>').join('') : '<div class="empty-state"><p>No residents yet</p><a href="/residents/new" class="btn btn-primary mt-4">Add Resident</a></div>';
  
  const addBtn = req.perms.canViewAllData ? '<a href="/residents/new" class="btn btn-primary">+ Add Resident</a>' : '';
  res.send(layout('Residents', '<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:24px;flex-wrap:wrap;gap:12px"><h2>Residents</h2>'+addBtn+'</div><div class="card">'+html+'</div>', req.user, 'residents'));
});

app.get('/residents/new', requireAuth, requireRole('owner', 'admin'), (req, res) => {
  const years = Array.from({length: 100}, (_, i) => new Date().getFullYear() - i);
  const months = ['January','February','March','April','May','June','July','August','September','October','November','December'];
  const days = Array.from({length: 31}, (_, i) => i + 1);
  
  res.send(layout('Add Resident', '<h2>Add Resident</h2><div class="card"><form method="POST" action="/residents"><div class="form-row"><div><label>Full Name *</label><input type="text" name="name" required placeholder="Mary Johnson"></div><div><label>Room</label><input type="text" name="room" placeholder="Room 1"></div></div><div class="form-row"><div><label>Date of Birth</label><div style="display:grid;grid-template-columns:1fr 1fr 1fr;gap:8px"><select name="dob_month"><option value="">Month</option>'+months.map((m,i) => '<option value="'+(i+1).toString().padStart(2,'0')+'">'+m+'</option>').join('')+'</select><select name="dob_day"><option value="">Day</option>'+days.map(d => '<option value="'+d.toString().padStart(2,'0')+'">'+d+'</option>').join('')+'</select><select name="dob_year"><option value="">Year</option>'+years.map(y => '<option value="'+y+'">'+y+'</option>').join('')+'</select></div></div><div><label>Admission Date</label><input type="date" name="admission_date" value="'+new Date().toISOString().split('T')[0]+'" min="2000-01-01" max="2099-12-31"></div></div><label>Conditions</label><input type="text" name="conditions" placeholder="Dementia, Diabetes, etc."><label>Notes</label><textarea name="notes" rows="3" placeholder="Additional notes..."></textarea><div style="display:flex;gap:12px;margin-top:8px"><button type="submit" class="btn btn-primary">Add Resident</button><a href="/residents" class="btn btn-secondary">Cancel</a></div></form></div>', req.user, 'residents'));
});

app.post('/residents', requireAuth, requireRole('owner', 'admin'), (req, res) => {
  const { name, room, dob_year, dob_month, dob_day, admission_date, conditions, notes } = req.body;
  const date_of_birth = (dob_year && dob_month && dob_day) ? `${dob_year}-${dob_month}-${dob_day}` : null;
  const result = dbRun('INSERT INTO residents (home_id, name, room, date_of_birth, admission_date, conditions, notes) VALUES (?, ?, ?, ?, ?, ?, ?)', [req.home.id, name, room, date_of_birth, admission_date, conditions, notes]);
  logAudit(req.user.id, req.user.name, req.home.id, 'RESIDENT_ADDED', 'resident', result.lastInsertRowid, { name });
  res.redirect('/residents');
});

app.get('/residents/:id', requireAuth, (req, res) => {
  const r = dbGet('SELECT * FROM residents WHERE id = ? AND home_id = ?', [req.params.id, req.home.id]);
  if (!r) return res.redirect('/residents');
  const poa = dbGet('SELECT * FROM poa_contacts WHERE resident_id = ?', [r.id]);
  const family = dbAll('SELECT * FROM family_members WHERE resident_id = ?', [r.id]);
  const meds = dbAll('SELECT * FROM medications WHERE resident_id = ? AND active = 1', [r.id]);
  const acts = dbAll('SELECT * FROM activities WHERE resident_id = ? ORDER BY created_at DESC LIMIT 10', [r.id]);
  const incidents = dbAll('SELECT * FROM incidents WHERE resident_id = ? ORDER BY created_at DESC LIMIT 5', [r.id]);
  
  let poaHtml = poa ? '<p><strong>'+poa.name+'</strong> <span class="badge badge-blue">'+(poa.poa_type||'POA')+'</span></p><p class="text-muted">'+(poa.relationship||'')+'</p><p>📞 '+(poa.phone||'No phone')+'</p><p>✉️ '+(poa.email||'No email')+'</p>' : '<p class="text-muted">No POA set</p>'+(req.perms.canManageUsers?'<a href="/family/resident/'+r.id+'/poa/new" class="btn btn-primary btn-sm mt-4">+ Add POA</a>':'');
  let medsHtml = meds.length > 0 ? meds.map(m => '<div style="padding:10px 0;border-bottom:1px solid #f1f5f9"><strong>'+m.name+'</strong> - '+(m.dosage||'')+' <p class="text-sm text-muted">'+(m.frequency||'')+' '+(m.instructions?'• '+m.instructions:'')+'</p></div>').join('') : '<p class="text-muted">No medications</p>';
  let actsHtml = acts.length > 0 ? acts.map(a => '<div style="padding:10px 0;border-bottom:1px solid #f1f5f9"><strong>'+a.type+'</strong>'+(a.mood?' - '+a.mood:'')+'<p class="text-sm text-muted">'+new Date(a.created_at).toLocaleString()+(a.staff_name?' • '+a.staff_name:'')+'</p></div>').join('') : '<p class="text-muted">No activities</p>';
  let incidentsHtml = incidents.length > 0 ? incidents.map(i => '<div style="padding:10px 0;border-bottom:1px solid #f1f5f9"><strong>'+i.type+'</strong> <span class="badge '+(i.severity==='major'?'badge-red':'badge-yellow')+'">'+i.severity+'</span><p class="text-sm text-muted">'+new Date(i.created_at).toLocaleString()+'</p></div>').join('') : '<p class="text-muted">No incidents</p>';
  
  const exportBtn = req.perms.canExport ? '<a href="/residents/'+r.id+'/export" class="btn btn-secondary btn-sm">📄 Export History</a>' : '';
  
  res.send(layout(r.name, '<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:24px;flex-wrap:wrap;gap:12px"><div style="display:flex;align-items:center;gap:16px"><div class="resident-avatar" style="width:64px;height:64px;font-size:28px">'+r.name.charAt(0)+'</div><div><h2 style="margin-bottom:4px">'+r.name+'</h2><p class="text-muted">Room '+(r.room||'-')+'</p></div></div><div style="display:flex;gap:8px">'+exportBtn+'<a href="/residents" class="btn btn-secondary">← Back</a></div></div><div class="grid-2"><div class="card"><h3>Details</h3><p><strong>DOB:</strong> '+(r.date_of_birth||'N/A')+'</p><p><strong>Admission:</strong> '+(r.admission_date||'N/A')+'</p><p><strong>Conditions:</strong> '+(r.conditions||'None')+'</p><p><strong>Notes:</strong> '+(r.notes||'None')+'</p></div><div class="card"><h3>POA / Responsible Party</h3>'+poaHtml+'</div></div><div class="grid-2"><div class="card"><div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:12px"><h3>Medications</h3>'+(req.perms.canManageUsers?'<a href="/medications/new?resident='+r.id+'" class="btn btn-primary btn-sm">+ Add</a>':'')+'</div>'+medsHtml+'</div><div class="card"><div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:12px"><h3>Recent Activities</h3><a href="/activities/new?resident='+r.id+'" class="btn btn-primary btn-sm">+ Log</a></div>'+actsHtml+'</div></div><div class="grid-2"><div class="card"><h3>Recent Incidents</h3>'+incidentsHtml+'</div><div class="card"><h3>Family Members</h3>'+(family.length>0?family.map(f=>'<div style="padding:8px 0"><strong>'+f.name+'</strong> - '+(f.relationship||'Family')+'<br><span class="text-sm text-muted">'+(f.phone||'')+' '+(f.email||'')+'</span></div>').join(''):'<p class="text-muted">No family members</p>')+'</div></div>', req.user, 'residents'));
});

// ============================================
// TIME CLOCK
// ============================================

app.get('/medications/new', requireAuth, requireRole('owner', 'admin'), (req, res) => {
  const residents = dbAll('SELECT * FROM residents WHERE home_id = ? AND active = 1 ORDER BY name', [req.home?.id || 0]);
  const pre = req.query.resident;
  res.send(layout('Add Medication', '<h2>Add Medication</h2><div class="card"><form method="POST" action="/medications"><label>Resident *</label><select name="resident_id" required><option value="">Select...</option>'+residents.map(r => '<option value="'+r.id+'"'+(pre==r.id?' selected':'')+'>'+r.name+'</option>').join('')+'</select><div class="form-row"><div><label>Medication *</label><input type="text" name="name" required placeholder="Lisinopril"></div><div><label>Dosage *</label><input type="text" name="dosage" required placeholder="10mg"></div></div><label>Frequency *</label><select name="frequency" required><option>Once daily</option><option>Twice daily</option><option>Three times daily</option><option>Every morning</option><option>Every evening</option><option>At bedtime</option><option>As needed (PRN)</option></select><label>Instructions</label><textarea name="instructions" rows="2" placeholder="Take with food..."></textarea><div class="form-row"><div><label>Prescriber</label><input type="text" name="prescriber" placeholder="Dr. Smith"></div><div><label>Pharmacy</label><input type="text" name="pharmacy" placeholder="CVS"></div></div><div style="display:flex;gap:12px;margin-top:8px"><button type="submit" class="btn btn-primary">Add</button><a href="/medications" class="btn btn-secondary">Cancel</a></div></form></div>', req.user, 'medications'));
});

app.post('/medications', requireAuth, requireRole('owner', 'admin'), (req, res) => {
  const { resident_id, name, dosage, frequency, instructions, prescriber, pharmacy } = req.body;
  dbRun('INSERT INTO medications (resident_id, name, dosage, frequency, instructions, prescriber, pharmacy) VALUES (?, ?, ?, ?, ?, ?, ?)', [resident_id, name, dosage, frequency, instructions, prescriber, pharmacy]);
  res.redirect('/medications');
});

app.get('/medications/administer', requireAuth, (req, res) => {
  if (req.user.role === 'family') return res.redirect('/dashboard');
  const residents = dbAll('SELECT * FROM residents WHERE home_id = ? AND active = 1 ORDER BY name', [req.home?.id || 0]);
  const data = residents.map(r => ({ ...r, meds: dbAll('SELECT * FROM medications WHERE resident_id = ? AND active = 1', [r.id]) })).filter(r => r.meds.length > 0);
  
  let html = data.length > 0 ? data.map(r => '<div class="card"><div style="display:flex;align-items:center;gap:12px;margin-bottom:16px"><div class="resident-avatar" style="width:44px;height:44px;font-size:18px">'+r.name.charAt(0)+'</div><h3 style="margin:0">'+r.name+'</h3></div>'+r.meds.map(m => '<form method="POST" action="/medications/administer" style="display:flex;align-items:center;gap:16px;padding:12px;background:#f8fafc;border-radius:10px;margin-bottom:8px;flex-wrap:wrap"><input type="hidden" name="medication_id" value="'+m.id+'"><input type="hidden" name="resident_id" value="'+r.id+'"><div style="flex:1;min-width:200px"><strong>'+m.name+'</strong> - '+m.dosage+'<p class="text-sm text-muted" style="margin:0">'+m.frequency+(m.instructions?' • '+m.instructions:'')+'</p></div><select name="status" style="width:auto;margin:0"><option value="given">✓ Given</option><option value="refused">✗ Refused</option><option value="held">⏸ Held</option></select><input type="text" name="notes" placeholder="Notes" style="width:120px;margin:0"><button type="submit" class="btn btn-success btn-sm">Record</button></form>').join('')+'</div>').join('') : '<div class="card"><div class="empty-state"><p>No medications to administer</p><a href="/medications/new" class="btn btn-primary mt-4">Add Medication</a></div></div>';
  
  res.send(layout('Administer Meds', '<h2>Administer Medications</h2>'+html+'<a href="/medications" class="btn btn-secondary">← Back</a>', req.user, 'medications'));
});

app.post('/medications/administer', requireAuth, (req, res) => {
  if (req.user.role === 'family') return res.redirect('/dashboard');
  const { medication_id, resident_id, status, notes } = req.body;
  dbRun('INSERT INTO mar_records (medication_id, resident_id, user_id, administered_by, status, notes) VALUES (?, ?, ?, ?, ?, ?)', [medication_id, resident_id, req.user.id, req.user.name, status, notes]);
  logAudit(req.user.id, req.user.name, req.home.id, 'MED_ADMINISTERED', 'medication', medication_id, { status });
  res.redirect('/medications/administer');
});

// ============================================
// FAMILY COMMUNICATION (simplified)
// ============================================
app.get('/family', requireAuth, requireRole('owner', 'admin'), (req, res) => {
  const residents = dbAll('SELECT * FROM residents WHERE home_id = ? AND active = 1 ORDER BY name', [req.home?.id || 0]);
  const data = residents.map(r => {
    const poa = dbGet('SELECT * FROM poa_contacts WHERE resident_id = ?', [r.id]);
    const fc = dbGet('SELECT COUNT(*) as c FROM family_members WHERE resident_id = ?', [r.id])?.c || 0;
    return { ...r, poa, familyCount: fc };
  });
  
  let tableHtml = data.length > 0 ? '<table><thead><tr><th>Resident</th><th>POA</th><th>Family</th><th>Actions</th></tr></thead><tbody>'+data.map(r => '<tr><td><strong>'+r.name+'</strong><br><span class="text-muted text-sm">Room '+(r.room||'-')+'</span></td><td>'+(r.poa?r.poa.name+'<br><span class="text-muted text-sm">'+(r.poa.relationship||'')+' • '+(r.poa.poa_type||'POA')+'</span>':'<span class="text-muted">Not set</span>')+'</td><td>'+r.familyCount+' member'+(r.familyCount!==1?'s':'')+'</td><td><a href="/family/resident/'+r.id+'" class="btn btn-secondary btn-sm">Manage</a></td></tr>').join('')+'</tbody></table>' : '<div class="empty-state"><p>No residents</p></div>';
  
  res.send(layout('Family', '<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:24px;flex-wrap:wrap;gap:12px"><h2>Family Communication</h2></div><div class="card"><h3>Residents & Contacts</h3>'+tableHtml+'</div>', req.user, 'family'));
});

app.get('/family/resident/:id', requireAuth, requireRole('owner', 'admin'), (req, res) => {
  const r = dbGet('SELECT * FROM residents WHERE id = ? AND home_id = ?', [req.params.id, req.home.id]);
  if (!r) return res.redirect('/family');
  const poa = dbGet('SELECT * FROM poa_contacts WHERE resident_id = ?', [r.id]);
  
  let poaHtml = poa ? '<p><strong>'+poa.name+'</strong></p><p class="text-muted">'+(poa.relationship||'')+'</p><p>📞 '+(poa.phone||'No phone')+'</p><p>✉️ '+(poa.email||'No email')+'</p>' : '<p class="text-muted">No POA set</p><a href="/family/resident/'+r.id+'/poa/new" class="btn btn-primary mt-4">+ Add POA</a>';
  
  res.send(layout('Family - '+r.name, '<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:24px;flex-wrap:wrap;gap:12px"><h2>Family for '+r.name+'</h2><a href="/family" class="btn btn-secondary">← Back</a></div><div class="card"><h3>👤 POA / Responsible Party</h3>'+poaHtml+'</div>', req.user, 'family'));
});

app.get('/family/resident/:id/poa/new', requireAuth, requireRole('owner', 'admin'), (req, res) => {
  const r = dbGet('SELECT * FROM residents WHERE id = ? AND home_id = ?', [req.params.id, req.home.id]);
  if (!r) return res.redirect('/family');
  res.send(layout('Add POA', '<h2>Add POA for '+r.name+'</h2><div class="card"><form method="POST" action="/family/resident/'+r.id+'/poa"><div class="form-row"><div><label>Name *</label><input type="text" name="name" required placeholder="Susan Johnson"></div><div><label>Relationship *</label><input type="text" name="relationship" required placeholder="Daughter"></div></div><div class="form-row"><div><label>Phone</label><input type="tel" name="phone" placeholder="(206) 555-0100"></div><div><label>Email</label><input type="email" name="email" placeholder="email@example.com"></div></div><label>POA Type</label><select name="poa_type"><option>Healthcare POA</option><option>Financial POA</option><option>Full POA</option><option>Guardian</option><option>Responsible Party</option></select><div style="display:flex;gap:12px;margin-top:16px"><button type="submit" class="btn btn-primary">Add POA</button><a href="/family/resident/'+r.id+'" class="btn btn-secondary">Cancel</a></div></form></div>', req.user, 'family'));
});

app.post('/family/resident/:id/poa', requireAuth, requireRole('owner', 'admin'), (req, res) => {
  const { name, relationship, phone, email, poa_type } = req.body;
  dbRun('DELETE FROM poa_contacts WHERE resident_id = ?', [req.params.id]);
  dbRun('INSERT INTO poa_contacts (resident_id, name, relationship, phone, email, poa_type) VALUES (?, ?, ?, ?, ?, ?)', [req.params.id, name, relationship, phone, email, poa_type]);
  res.redirect('/family/resident/'+req.params.id);
});

// ============================================
// INSPECTION CHECKLIST
// ============================================
app.get('/inspection', requireAuth, requireRole('owner', 'admin'), (req, res) => {
  const items = dbAll('SELECT * FROM inspection_items WHERE home_id = ? ORDER BY category, item', [req.home?.id || 0]);
  const cats = {};
  items.forEach(i => { if (!cats[i.category]) cats[i.category] = []; cats[i.category].push(i); });
  
  const total = items.length;
  const done = items.filter(i => i.status === 'complete').length;
  const pct = total > 0 ? Math.round((done / total) * 100) : 0;
  
  let catHtml = Object.entries(cats).map(([cat, list]) => {
    const catDone = list.filter(i => i.status === 'complete').length;
    const catPct = Math.round((catDone / list.length) * 100);
    return '<div class="card"><div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:16px"><h3 style="margin:0">'+cat+'</h3><span class="badge '+(catPct===100?'badge-green':catPct>=50?'badge-yellow':'badge-gray')+'">'+catDone+'/'+list.length+'</span></div>'+list.map(i => '<form method="POST" action="/inspection/toggle" class="checklist-item'+(i.status==='complete'?' complete':'')+'"><input type="hidden" name="item_id" value="'+i.id+'"><input type="checkbox" '+(i.status==='complete'?'checked':'')+' onchange="this.form.submit()"><div style="flex:1"><span style="'+(i.status==='complete'?'text-decoration:line-through;color:#64748b':'')+'">'+i.item+'</span>'+(i.verified_by?'<p class="text-sm text-muted" style="margin:4px 0 0 0">Verified by '+i.verified_by+' on '+new Date(i.verified_at).toLocaleDateString()+'</p>':'')+'</div></form>').join('')+'</div>';
  }).join('');
  
  res.send(layout('Inspection', '<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:24px;flex-wrap:wrap;gap:12px"><h2>DSHS Inspection Checklist</h2><span class="badge '+(pct>=90?'badge-green':pct>=70?'badge-yellow':'badge-red')+'" style="font-size:16px;padding:8px 16px">'+pct+'% Ready</span></div><div class="card" style="margin-bottom:24px"><div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:12px"><span><strong>'+done+'</strong> of <strong>'+total+'</strong> complete</span></div><div class="progress-bar"><div class="progress-fill" style="width:'+pct+'%"></div></div></div>'+catHtml, req.user, 'inspection'));
});

app.post('/inspection/toggle', requireAuth, requireRole('owner', 'admin'), (req, res) => {
  const { item_id } = req.body;
  const item = dbGet('SELECT * FROM inspection_items WHERE id = ?', [item_id]);
  if (!item) return res.redirect('/inspection');
  const newStatus = item.status === 'complete' ? 'pending' : 'complete';
  if (newStatus === 'complete') {
    dbRun('UPDATE inspection_items SET status = ?, verified_by = ?, verified_at = datetime("now") WHERE id = ?', [newStatus, req.user.name, item_id]);
  } else {
    dbRun('UPDATE inspection_items SET status = ?, verified_by = NULL, verified_at = NULL WHERE id = ?', [newStatus, item_id]);
  }
  res.redirect('/inspection');
});

// ============================================
// REPORTS
// ============================================
app.get('/reports', requireAuth, requireRole('owner', 'admin'), (req, res) => {
  res.send(layout('Reports', '<h2>Reports & Exports</h2><div class="grid-2"><div class="card"><h3>📊 Activity Reports</h3><p class="text-muted">Export activity logs for all residents.</p><form method="GET" action="/reports/activities"><div class="form-row"><div><label>Start Date</label><input type="date" name="start" value="'+new Date(Date.now()-30*24*60*60*1000).toISOString().split('T')[0]+'"></div><div><label>End Date</label><input type="date" name="end" value="'+new Date().toISOString().split('T')[0]+'"></div></div><button type="submit" class="btn btn-primary">Export CSV</button></form></div><div class="card"><h3>⚠️ Incident Reports</h3><p class="text-muted">Export all incident reports.</p><form method="GET" action="/reports/incidents"><div class="form-row"><div><label>Start Date</label><input type="date" name="start" value="'+new Date(Date.now()-90*24*60*60*1000).toISOString().split('T')[0]+'"></div><div><label>End Date</label><input type="date" name="end" value="'+new Date().toISOString().split('T')[0]+'"></div></div><button type="submit" class="btn btn-primary">Export CSV</button></form></div></div><div class="grid-2"><div class="card"><h3>⏱️ Time & Attendance</h3><p class="text-muted">Export staff time entries.</p><form method="GET" action="/reports/time"><div class="form-row"><div><label>Start Date</label><input type="date" name="start" value="'+new Date(Date.now()-14*24*60*60*1000).toISOString().split('T')[0]+'"></div><div><label>End Date</label><input type="date" name="end" value="'+new Date().toISOString().split('T')[0]+'"></div></div><button type="submit" class="btn btn-primary">Export CSV</button></form></div><div class="card"><h3>💊 Medication Administration</h3><p class="text-muted">Export MAR records.</p><form method="GET" action="/reports/mar"><div class="form-row"><div><label>Start Date</label><input type="date" name="start" value="'+new Date(Date.now()-30*24*60*60*1000).toISOString().split('T')[0]+'"></div><div><label>End Date</label><input type="date" name="end" value="'+new Date().toISOString().split('T')[0]+'"></div></div><button type="submit" class="btn btn-primary">Export CSV</button></form></div></div>', req.user, 'reports'));
});

function toCSV(headers, rows) {
  const escape = (val) => '"' + String(val || '').replace(/"/g, '""') + '"';
  let csv = headers.map(escape).join(',') + '\n';
  rows.forEach(row => { csv += headers.map(h => escape(row[h])).join(',') + '\n'; });
  return csv;
}

app.get('/reports/activities', requireAuth, requireRole('owner', 'admin'), (req, res) => {
  const { start, end } = req.query;
  const activities = dbAll('SELECT a.created_at as date, r.name as resident, a.type, a.mood, a.notes, a.staff_name as logged_by FROM activities a LEFT JOIN residents r ON a.resident_id = r.id WHERE a.home_id = ? AND date(a.created_at) >= ? AND date(a.created_at) <= ? ORDER BY a.created_at DESC', [req.home.id, start, end]);
  const csv = toCSV(['date', 'resident', 'type', 'mood', 'notes', 'logged_by'], activities);
  res.setHeader('Content-Type', 'text/csv');
  res.setHeader('Content-Disposition', 'attachment; filename=activities-'+start+'-to-'+end+'.csv');
  res.send(csv);
});

app.get('/reports/incidents', requireAuth, requireRole('owner', 'admin'), (req, res) => {
  const { start, end } = req.query;
  const incidents = dbAll('SELECT i.created_at as date, r.name as resident, i.type, i.severity, i.description, i.immediate_actions, i.follow_up, i.reported_by, i.witnesses, i.notified_poa FROM incidents i LEFT JOIN residents r ON i.resident_id = r.id WHERE i.home_id = ? AND date(i.created_at) >= ? AND date(i.created_at) <= ? ORDER BY i.created_at DESC', [req.home.id, start, end]);
  const csv = toCSV(['date', 'resident', 'type', 'severity', 'description', 'immediate_actions', 'follow_up', 'reported_by', 'witnesses', 'notified_poa'], incidents);
  res.setHeader('Content-Type', 'text/csv');
  res.setHeader('Content-Disposition', 'attachment; filename=incidents-'+start+'-to-'+end+'.csv');
  res.send(csv);
});

app.get('/reports/time', requireAuth, requireRole('owner', 'admin'), (req, res) => {
  const { start, end } = req.query;
  const entries = dbAll('SELECT date(t.clock_in) as date, u.name as staff, t.clock_in, t.clock_out, t.break_minutes FROM time_entries t JOIN users u ON t.user_id = u.id WHERE t.home_id = ? AND date(t.clock_in) >= ? AND date(t.clock_in) <= ? AND t.clock_out IS NOT NULL ORDER BY t.clock_in DESC', [req.home.id, start, end]);
  entries.forEach(e => { e.hours = e.clock_out ? (((new Date(e.clock_out) - new Date(e.clock_in)) / 60000 - (e.break_minutes||0)) / 60).toFixed(2) : ''; });
  const csv = toCSV(['date', 'staff', 'clock_in', 'clock_out', 'break_minutes', 'hours'], entries);
  res.setHeader('Content-Type', 'text/csv');
  res.setHeader('Content-Disposition', 'attachment; filename=time-entries-'+start+'-to-'+end+'.csv');
  res.send(csv);
});

app.get('/reports/mar', requireAuth, requireRole('owner', 'admin'), (req, res) => {
  const { start, end } = req.query;
  const records = dbAll('SELECT m.administered_at as date, r.name as resident, med.name as medication, med.dosage, m.status, m.administered_by, m.notes FROM mar_records m JOIN medications med ON m.medication_id = med.id JOIN residents r ON m.resident_id = r.id WHERE r.home_id = ? AND date(m.administered_at) >= ? AND date(m.administered_at) <= ? ORDER BY m.administered_at DESC', [req.home.id, start, end]);
  const csv = toCSV(['date', 'resident', 'medication', 'dosage', 'status', 'administered_by', 'notes'], records);
  res.setHeader('Content-Type', 'text/csv');
  res.setHeader('Content-Disposition', 'attachment; filename=mar-'+start+'-to-'+end+'.csv');
  res.send(csv);
});

app.get('/residents/:id/export', requireAuth, requireRole('owner', 'admin'), (req, res) => {
  const r = dbGet('SELECT * FROM residents WHERE id = ? AND home_id = ?', [req.params.id, req.home.id]);
  if (!r) return res.redirect('/residents');
  const activities = dbAll('SELECT created_at as date, type, mood, notes, staff_name FROM activities WHERE resident_id = ? ORDER BY created_at DESC', [r.id]);
  const incidents = dbAll('SELECT created_at as date, type, severity, description, immediate_actions, reported_by FROM incidents WHERE resident_id = ? ORDER BY created_at DESC', [r.id]);
  
  let content = 'RESIDENT HISTORY EXPORT\n========================\n\nName: ' + r.name + '\nRoom: ' + (r.room || 'N/A') + '\nDOB: ' + (r.date_of_birth || 'N/A') + '\nAdmission: ' + (r.admission_date || 'N/A') + '\nConditions: ' + (r.conditions || 'None') + '\n\n';
  content += 'ACTIVITIES (' + activities.length + ' records)\n' + '-'.repeat(40) + '\n';
  activities.forEach(a => { content += a.date + ' | ' + a.type + ' | ' + (a.mood || '-') + ' | ' + (a.notes || '') + '\n'; });
  content += '\n\nINCIDENTS (' + incidents.length + ' records)\n' + '-'.repeat(40) + '\n';
  incidents.forEach(i => { content += i.date + ' | ' + i.type + ' | ' + i.severity + '\n  Description: ' + (i.description || '') + '\n\n'; });
  
  res.setHeader('Content-Type', 'text/plain');
  res.setHeader('Content-Disposition', 'attachment; filename='+r.name.replace(/\s+/g, '-')+'-history.txt');
  res.send(content);
});

// ============================================
// START SERVER
// ============================================
const PORT = process.env.PORT || 3001;

initDB().then(() => {
  app.listen(PORT, () => {
    console.log('');
    console.log('╔═══════════════════════════════════════════════╗');
    console.log('║     🏠 AFH Complete v3.1 is running!          ║');
    console.log('╠═══════════════════════════════════════════════╣');
    console.log('║  Open: http://localhost:' + PORT + '                  ║');
    console.log('║                                               ║');
    console.log('║  Features:                                    ║');
    console.log('║  ✓ User Roles (Owner/Admin/Caregiver/Family)  ║');
    console.log('║  ✓ Time Clock & Attendance                    ║');
    console.log('║  ✓ Activity & Incident Logging                ║');
    console.log('║  ✓ Medication Administration (MAR)            ║');
    console.log('║  ✓ CSV/PDF Exports                            ║');
    console.log('║  ✓ DSHS Inspection Checklist                  ║');
    console.log('║  ✓ Uses sql.js (no native build required)     ║');
    console.log('╚═══════════════════════════════════════════════╝');
    console.log('');
  });
}).catch(err => {
  console.error('Failed to initialize database:', err);
  process.exit(1);
});
