// AFH Complete v3.0 - Full Featured with Roles, Time Tracking, Exports
// All features included - works immediately on Railway

const express = require('express');
const Database = require('better-sqlite3');
const crypto = require('crypto');

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

const db = new Database('afh.db');

// ============================================
// DATABASE SETUP
// ============================================
db.exec(`
  -- Users with roles
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
  );
  
  CREATE TABLE IF NOT EXISTS sessions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    token TEXT UNIQUE,
    expires_at DATETIME
  );
  
  CREATE TABLE IF NOT EXISTS invitations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    home_id INTEGER,
    email TEXT,
    role TEXT DEFAULT 'caregiver',
    token TEXT UNIQUE,
    invited_by INTEGER,
    expires_at DATETIME,
    used INTEGER DEFAULT 0,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );
  
  CREATE TABLE IF NOT EXISTS homes (
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
  );
  
  CREATE TABLE IF NOT EXISTS residents (
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
  );
  
  CREATE TABLE IF NOT EXISTS poa_contacts (
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
  );
  
  CREATE TABLE IF NOT EXISTS family_members (
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
  );
  
  CREATE TABLE IF NOT EXISTS family_messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    home_id INTEGER,
    resident_id INTEGER,
    message TEXT,
    message_type TEXT DEFAULT 'update',
    recipient_type TEXT DEFAULT 'all',
    sent_by TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );
  
  CREATE TABLE IF NOT EXISTS staff (
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
  );
  
  CREATE TABLE IF NOT EXISTS certifications (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    staff_id INTEGER,
    type TEXT NOT NULL,
    issue_date TEXT,
    expiration_date TEXT,
    certificate_number TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );
  
  -- Time Tracking
  CREATE TABLE IF NOT EXISTS time_entries (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    home_id INTEGER,
    user_id INTEGER,
    staff_id INTEGER,
    clock_in DATETIME,
    clock_out DATETIME,
    break_minutes INTEGER DEFAULT 0,
    notes TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );
  
  CREATE TABLE IF NOT EXISTS scheduled_shifts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    home_id INTEGER,
    staff_id INTEGER,
    date TEXT,
    start_time TEXT,
    end_time TEXT,
    notes TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );
  
  CREATE TABLE IF NOT EXISTS activities (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    home_id INTEGER,
    resident_id INTEGER,
    user_id INTEGER,
    staff_name TEXT,
    type TEXT,
    mood TEXT,
    notes TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );
  
  CREATE TABLE IF NOT EXISTS incidents (
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
  );
  
  CREATE TABLE IF NOT EXISTS medications (
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
  );
  
  CREATE TABLE IF NOT EXISTS mar_records (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    medication_id INTEGER,
    resident_id INTEGER,
    user_id INTEGER,
    administered_by TEXT,
    administered_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    status TEXT DEFAULT 'given',
    notes TEXT
  );
  
  CREATE TABLE IF NOT EXISTS inspection_items (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    home_id INTEGER,
    category TEXT,
    item TEXT,
    status TEXT DEFAULT 'pending',
    verified_by TEXT,
    verified_at DATETIME,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );
  
  CREATE TABLE IF NOT EXISTS audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    user_name TEXT,
    home_id INTEGER,
    action TEXT,
    entity_type TEXT,
    entity_id INTEGER,
    details TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );
`);

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
  return db.prepare('SELECT u.* FROM sessions s JOIN users u ON s.user_id = u.id WHERE s.token = ? AND s.expires_at > datetime("now")').get(token);
}

// Role permissions
const ROLES = {
  owner: { level: 100, canManageUsers: true, canViewAllData: true, canExport: true, canDelete: true, canEditSettings: true },
  admin: { level: 80, canManageUsers: true, canViewAllData: true, canExport: true, canDelete: false, canEditSettings: false },
  caregiver: { level: 20, canManageUsers: false, canViewAllData: false, canExport: false, canDelete: false, canEditSettings: false },
  family: { level: 10, canManageUsers: false, canViewAllData: false, canExport: false, canDelete: false, canEditSettings: false }
};

function canAccess(userRole, requiredLevel) {
  return (ROLES[userRole]?.level || 0) >= requiredLevel;
}

function logAudit(userId, userName, homeId, action, entityType, entityId, details) {
  try {
    db.prepare('INSERT INTO audit_log (user_id, user_name, home_id, action, entity_type, entity_id, details) VALUES (?, ?, ?, ?, ?, ?, ?)').run(userId, userName, homeId, action, entityType, entityId, JSON.stringify(details || {}));
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
      db.prepare('INSERT INTO inspection_items (home_id, category, item) VALUES (?, ?, ?)').run(homeId, cat, item);
    }
  }
}

// Get current time entry for user
function getCurrentClockIn(userId, homeId) {
  return db.prepare('SELECT * FROM time_entries WHERE user_id = ? AND home_id = ? AND clock_out IS NULL ORDER BY clock_in DESC LIMIT 1').get(userId, homeId);
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
  const user = db.prepare('SELECT * FROM users WHERE email = ?').get(email?.toLowerCase());
  if (!user || !verifyPassword(password, user.password_hash)) return res.redirect('/login?error=Invalid email or password');
  const token = generateToken();
  db.prepare('INSERT INTO sessions (user_id, token, expires_at) VALUES (?, ?, ?)').run(user.id, token, new Date(Date.now() + 30*24*60*60*1000).toISOString());
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
  if (db.prepare('SELECT id FROM users WHERE email = ?').get(email.toLowerCase())) return res.redirect('/register?error=Email already registered');
  try {
    const homeResult = db.prepare('INSERT INTO homes (name) VALUES (?)').run(homeName);
    const homeId = homeResult.lastInsertRowid;
    const userResult = db.prepare('INSERT INTO users (email, password_hash, name, role, home_id) VALUES (?, ?, ?, ?, ?)').run(email.toLowerCase(), hashPassword(password), name, 'owner', homeId);
    db.prepare('UPDATE homes SET user_id = ? WHERE id = ?').run(userResult.lastInsertRowid, homeId);
    initChecklist(homeId);
    const token = generateToken();
    db.prepare('INSERT INTO sessions (user_id, token, expires_at) VALUES (?, ?, ?)').run(userResult.lastInsertRowid, token, new Date(Date.now() + 30*24*60*60*1000).toISOString());
    logAudit(userResult.lastInsertRowid, name, homeId, 'USER_REGISTERED', 'user', userResult.lastInsertRowid, { role: 'owner' });
    res.setHeader('Set-Cookie', 'token='+token+'; Path=/; HttpOnly; SameSite=Lax; Max-Age='+30*24*60*60);
    res.redirect('/dashboard');
  } catch (e) { console.error(e); res.redirect('/register?error=Registration failed'); }
});

// Accept invitation route
app.get('/invite/:token', (req, res) => {
  const inv = db.prepare('SELECT i.*, h.name as home_name FROM invitations i JOIN homes h ON i.home_id = h.id WHERE i.token = ? AND i.used = 0 AND i.expires_at > datetime("now")').get(req.params.token);
  if (!inv) return res.send(layout('Invalid Invitation', '<div class="login-container"><div class="card center"><h2>Invalid or Expired Invitation</h2><p class="text-muted">This invitation link is no longer valid.</p><a href="/login" class="btn btn-primary mt-4">Go to Login</a></div></div>'));
  
  res.send(layout('Accept Invitation', '<div class="login-container"><div class="card center"><div class="logo">🏠 AFH Complete</div><p class="text-muted mb-4">You\'ve been invited to join <strong>'+inv.home_name+'</strong> as a <strong>'+inv.role+'</strong></p><form method="POST" action="/invite/'+req.params.token+'" style="text-align:left"><label>Your Name *</label><input type="text" name="name" required placeholder="Your Name"><label>Email</label><input type="email" value="'+inv.email+'" disabled style="background:#f1f5f9"><input type="hidden" name="email" value="'+inv.email+'"><label>Create Password *</label><input type="password" name="password" required placeholder="Min 8 characters" minlength="8"><button type="submit" class="btn btn-primary" style="width:100%">Accept & Create Account</button></form></div></div>'));
});

app.post('/invite/:token', (req, res) => {
  const { name, email, password } = req.body;
  const inv = db.prepare('SELECT * FROM invitations WHERE token = ? AND used = 0 AND expires_at > datetime("now")').get(req.params.token);
  if (!inv) return res.redirect('/login?error=Invalid invitation');
  
  try {
    const userResult = db.prepare('INSERT INTO users (email, password_hash, name, role, home_id, invited_by) VALUES (?, ?, ?, ?, ?, ?)').run(email.toLowerCase(), hashPassword(password), name, inv.role, inv.home_id, inv.invited_by);
    db.prepare('UPDATE invitations SET used = 1 WHERE id = ?').run(inv.id);
    
    // If caregiver, also create staff record
    if (inv.role === 'caregiver') {
      db.prepare('INSERT INTO staff (home_id, user_id, name, email, role) VALUES (?, ?, ?, ?, ?)').run(inv.home_id, userResult.lastInsertRowid, name, email, 'Caregiver');
    }
    
    const token = generateToken();
    db.prepare('INSERT INTO sessions (user_id, token, expires_at) VALUES (?, ?, ?)').run(userResult.lastInsertRowid, token, new Date(Date.now() + 30*24*60*60*1000).toISOString());
    logAudit(userResult.lastInsertRowid, name, inv.home_id, 'USER_ACCEPTED_INVITE', 'user', userResult.lastInsertRowid, { role: inv.role });
    res.setHeader('Set-Cookie', 'token='+token+'; Path=/; HttpOnly; SameSite=Lax; Max-Age='+30*24*60*60);
    res.redirect('/dashboard');
  } catch (e) { console.error(e); res.redirect('/login?error=Account creation failed'); }
});

app.get('/logout', (req, res) => {
  const token = req.headers.cookie?.split('token=')[1]?.split(';')[0];
  if (token) db.prepare('DELETE FROM sessions WHERE token = ?').run(token);
  res.setHeader('Set-Cookie', 'token=; Path=/; HttpOnly; Max-Age=0');
  res.redirect('/login?success=Logged out');
});

function requireAuth(req, res, next) {
  const token = req.headers.cookie?.split('token=')[1]?.split(';')[0];
  const user = getUser(token);
  if (!user) return res.redirect('/login');
  req.user = user;
  req.home = db.prepare('SELECT * FROM homes WHERE id = ?').get(user.home_id);
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
// TIME CLOCK
// ============================================
app.get('/timeclock', requireAuth, (req, res) => {
  const clockedIn = getCurrentClockIn(req.user.id, req.home.id);
  const today = new Date().toISOString().split('T')[0];
  
  // Get today's entries for this user
  const todayEntries = db.prepare('SELECT * FROM time_entries WHERE user_id = ? AND home_id = ? AND date(clock_in) = ? ORDER BY clock_in DESC').all(req.user.id, req.home.id, today);
  
  // Calculate total hours today
  let totalMinutes = 0;
  todayEntries.forEach(e => {
    if (e.clock_out) {
      const mins = (new Date(e.clock_out) - new Date(e.clock_in)) / 60000 - (e.break_minutes || 0);
      totalMinutes += mins;
    }
  });
  const totalHours = (totalMinutes / 60).toFixed(2);
  
  // Get this week's summary
  const weekStart = new Date();
  weekStart.setDate(weekStart.getDate() - weekStart.getDay());
  const weekEntries = db.prepare('SELECT * FROM time_entries WHERE user_id = ? AND home_id = ? AND date(clock_in) >= ? AND clock_out IS NOT NULL').all(req.user.id, req.home.id, weekStart.toISOString().split('T')[0]);
  let weekMinutes = 0;
  weekEntries.forEach(e => {
    weekMinutes += (new Date(e.clock_out) - new Date(e.clock_in)) / 60000 - (e.break_minutes || 0);
  });
  const weekHours = (weekMinutes / 60).toFixed(2);
  
  const now = new Date();
  const timeStr = now.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
  
  let statusHtml = '';
  if (clockedIn) {
    const clockInTime = new Date(clockedIn.clock_in);
    const elapsed = Math.floor((now - clockInTime) / 60000);
    const elapsedHrs = Math.floor(elapsed / 60);
    const elapsedMins = elapsed % 60;
    statusHtml = '<div class="clock-status clocked-in"><p class="text-sm text-muted">Clocked in at '+clockInTime.toLocaleTimeString([], {hour:'2-digit',minute:'2-digit'})+'</p><p class="clock-display">'+elapsedHrs+'h '+elapsedMins+'m</p><form method="POST" action="/timeclock/out" style="margin-top:20px"><label>Break Minutes (optional)</label><input type="number" name="break_minutes" value="0" min="0" style="width:100px;display:inline;margin-right:10px"><button type="submit" class="btn btn-danger btn-lg">Clock Out</button></form></div>';
  } else {
    statusHtml = '<div class="clock-status clocked-out"><p class="clock-display">'+timeStr+'</p><form method="POST" action="/timeclock/in" style="margin-top:20px"><button type="submit" class="btn btn-success btn-lg">Clock In</button></form></div>';
  }
  
  let entriesHtml = todayEntries.length > 0 ? '<table><thead><tr><th>Clock In</th><th>Clock Out</th><th>Break</th><th>Hours</th></tr></thead><tbody>'+todayEntries.map(e => {
    const inTime = new Date(e.clock_in).toLocaleTimeString([], {hour:'2-digit',minute:'2-digit'});
    const outTime = e.clock_out ? new Date(e.clock_out).toLocaleTimeString([], {hour:'2-digit',minute:'2-digit'}) : '<span class="badge badge-green">Active</span>';
    const hrs = e.clock_out ? (((new Date(e.clock_out) - new Date(e.clock_in)) / 60000 - (e.break_minutes||0)) / 60).toFixed(2) : '-';
    return '<tr><td>'+inTime+'</td><td>'+outTime+'</td><td>'+(e.break_minutes||0)+' min</td><td>'+hrs+'</td></tr>';
  }).join('')+'</tbody></table>' : '<p class="text-muted">No entries today</p>';
  
  res.send(layout('Time Clock', '<h2>Time Clock</h2><div class="grid-2"><div class="card">'+statusHtml+'</div><div class="card"><h3>Summary</h3><div class="grid-2"><div class="stat-card"><div class="stat-number">'+totalHours+'</div><div class="stat-label">Hours Today</div></div><div class="stat-card"><div class="stat-number">'+weekHours+'</div><div class="stat-label">Hours This Week</div></div></div></div></div><div class="card"><h3>Today\'s Entries</h3>'+entriesHtml+'</div>', req.user, 'timeclock'));
});

app.post('/timeclock/in', requireAuth, (req, res) => {
  const existing = getCurrentClockIn(req.user.id, req.home.id);
  if (existing) return res.redirect('/timeclock');
  
  db.prepare('INSERT INTO time_entries (home_id, user_id, clock_in) VALUES (?, ?, datetime("now"))').run(req.home.id, req.user.id);
  logAudit(req.user.id, req.user.name, req.home.id, 'CLOCK_IN', 'time_entry', null, {});
  res.redirect('/timeclock');
});

app.post('/timeclock/out', requireAuth, (req, res) => {
  const { break_minutes } = req.body;
  const entry = getCurrentClockIn(req.user.id, req.home.id);
  if (!entry) return res.redirect('/timeclock');
  
  db.prepare('UPDATE time_entries SET clock_out = datetime("now"), break_minutes = ? WHERE id = ?').run(break_minutes || 0, entry.id);
  logAudit(req.user.id, req.user.name, req.home.id, 'CLOCK_OUT', 'time_entry', entry.id, { break_minutes });
  res.redirect('/timeclock');
});

// ============================================
// USER MANAGEMENT (Owner/Admin only)
// ============================================
app.get('/users', requireAuth, requireRole('owner', 'admin'), (req, res) => {
  const users = db.prepare('SELECT * FROM users WHERE home_id = ? ORDER BY role, name').all(req.home.id);
  const invitations = db.prepare('SELECT * FROM invitations WHERE home_id = ? AND used = 0 AND expires_at > datetime("now") ORDER BY created_at DESC').all(req.home.id);
  
  let usersHtml = '<table><thead><tr><th>Name</th><th>Email</th><th>Role</th><th>Created</th><th>Actions</th></tr></thead><tbody>'+users.map(u => {
    const roleClass = 'role-'+u.role;
    return '<tr><td><strong>'+u.name+'</strong></td><td>'+u.email+'</td><td><span class="user-role '+roleClass+'">'+u.role+'</span></td><td>'+new Date(u.created_at).toLocaleDateString()+'</td><td>'+(u.id !== req.user.id && u.role !== 'owner' ? '<a href="/users/'+u.id+'/edit" class="btn btn-secondary btn-sm">Edit</a>':'')+'</td></tr>';
  }).join('')+'</tbody></table>';
  
  let invHtml = invitations.length > 0 ? '<table><thead><tr><th>Email</th><th>Role</th><th>Expires</th><th>Link</th></tr></thead><tbody>'+invitations.map(i => '<tr><td>'+i.email+'</td><td>'+i.role+'</td><td>'+new Date(i.expires_at).toLocaleDateString()+'</td><td><input type="text" value="'+req.headers.host+'/invite/'+i.token+'" readonly style="font-size:12px;padding:4px" onclick="this.select()"></td></tr>').join('')+'</tbody></table>' : '<p class="text-muted">No pending invitations</p>';
  
  res.send(layout('Users', '<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:24px;flex-wrap:wrap;gap:12px"><h2>User Management</h2><a href="/users/invite" class="btn btn-primary">+ Invite User</a></div><div class="card"><h3>Active Users</h3>'+usersHtml+'</div><div class="card"><h3>Pending Invitations</h3>'+invHtml+'</div>', req.user, 'users'));
});

app.get('/users/invite', requireAuth, requireRole('owner', 'admin'), (req, res) => {
  res.send(layout('Invite User', '<h2>Invite User</h2><div class="card"><form method="POST" action="/users/invite"><label>Email *</label><input type="email" name="email" required placeholder="user@example.com"><label>Role *</label><select name="role"><option value="caregiver">Caregiver - Can log activities, give meds, clock in/out</option><option value="admin">Admin - Can manage staff, view reports, export data</option>'+(req.user.role === 'owner' ? '<option value="owner">Owner - Full access</option>' : '')+'</select><p class="text-sm text-muted mb-4">An invitation link will be generated. Share it with the user to allow them to create their account.</p><div style="display:flex;gap:12px"><button type="submit" class="btn btn-primary">Generate Invitation</button><a href="/users" class="btn btn-secondary">Cancel</a></div></form></div>', req.user, 'users'));
});

app.post('/users/invite', requireAuth, requireRole('owner', 'admin'), (req, res) => {
  const { email, role } = req.body;
  
  // Check if user already exists
  if (db.prepare('SELECT id FROM users WHERE email = ?').get(email.toLowerCase())) {
    return res.send(layout('Error', '<div class="card"><div class="alert alert-error">A user with this email already exists.</div><a href="/users/invite" class="btn btn-secondary">Back</a></div>', req.user, 'users'));
  }
  
  const token = generateToken();
  const expires = new Date(Date.now() + 7*24*60*60*1000); // 7 days
  
  db.prepare('INSERT INTO invitations (home_id, email, role, token, invited_by, expires_at) VALUES (?, ?, ?, ?, ?, ?)').run(req.home.id, email.toLowerCase(), role, token, req.user.id, expires.toISOString());
  
  logAudit(req.user.id, req.user.name, req.home.id, 'USER_INVITED', 'invitation', null, { email, role });
  
  const inviteUrl = (req.headers.host.includes('localhost') ? 'http://' : 'https://') + req.headers.host + '/invite/' + token;
  
  res.send(layout('Invitation Created', '<div class="card center"><h2>✅ Invitation Created</h2><p>Share this link with <strong>'+email+'</strong>:</p><div style="background:#f1f5f9;padding:16px;border-radius:8px;margin:20px 0;word-break:break-all"><code>'+inviteUrl+'</code></div><p class="text-sm text-muted">This link expires in 7 days.</p><a href="/users" class="btn btn-primary mt-4">Back to Users</a></div>', req.user, 'users'));
});

// ============================================
// DASHBOARD
// ============================================
app.get('/dashboard', requireAuth, (req, res) => {
  const home = req.home;
  const hid = home?.id || 0;
  
  const residentCount = db.prepare('SELECT COUNT(*) as c FROM residents WHERE home_id = ? AND active = 1').get(hid)?.c || 0;
  const staffCount = db.prepare('SELECT COUNT(*) as c FROM staff WHERE home_id = ? AND active = 1').get(hid)?.c || 0;
  
  // Who's clocked in now
  const clockedInNow = db.prepare('SELECT t.*, u.name FROM time_entries t JOIN users u ON t.user_id = u.id WHERE t.home_id = ? AND t.clock_out IS NULL').all(hid);
  
  const activities = db.prepare('SELECT a.*, r.name as rn FROM activities a LEFT JOIN residents r ON a.resident_id = r.id WHERE a.home_id = ? ORDER BY a.created_at DESC LIMIT 8').all(hid);
  const expiringCerts = db.prepare('SELECT c.*, s.name as sn FROM certifications c JOIN staff s ON c.staff_id = s.id WHERE s.home_id = ? AND c.expiration_date <= date("now", "+60 days") ORDER BY c.expiration_date LIMIT 5').all(hid);
  const recentIncidents = db.prepare('SELECT i.*, r.name as rn FROM incidents i LEFT JOIN residents r ON i.resident_id = r.id WHERE i.home_id = ? ORDER BY i.created_at DESC LIMIT 3').all(hid);
  
  const totalItems = db.prepare('SELECT COUNT(*) as c FROM inspection_items WHERE home_id = ?').get(hid)?.c || 0;
  const completedItems = db.prepare('SELECT COUNT(*) as c FROM inspection_items WHERE home_id = ? AND status = "complete"').get(hid)?.c || 0;
  const readiness = totalItems > 0 ? Math.round((completedItems / totalItems) * 100) : 0;
  
  const icons = { meal: ['🍽️','#dcfce7'], medication: ['💊','#dbeafe'], activity: ['🎯','#fef9c3'], rest: ['😴','#f3e8ff'], outing: ['🌳','#dcfce7'], social: ['👥','#fce7f3'], hygiene: ['🚿','#e0f2fe'] };
  
  // Quick actions based on role
  let quickActions = '';
  if (req.user.role !== 'family') {
    quickActions = '<div class="grid-4" style="margin-bottom:24px"><a href="/activities/new" class="quick-action"><div class="quick-action-icon" style="background:#dcfce7">📝</div><span>Log Activity</span></a><a href="/medications/administer" class="quick-action"><div class="quick-action-icon" style="background:#dbeafe">💊</div><span>Give Meds</span></a><a href="/incidents/new" class="quick-action"><div class="quick-action-icon" style="background:#fee2e2">⚠️</div><span>Report Incident</span></a><a href="/timeclock" class="quick-action"><div class="quick-action-icon" style="background:#fef9c3">⏱️</div><span>Time Clock</span></a></div>';
  }
  
  // Who's working now
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
  const residents = db.prepare('SELECT * FROM residents WHERE home_id = ? AND active = 1 ORDER BY name').all(req.home?.id || 0);
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
  const result = db.prepare('INSERT INTO residents (home_id, name, room, date_of_birth, admission_date, conditions, notes) VALUES (?, ?, ?, ?, ?, ?, ?)').run(req.home.id, name, room, date_of_birth, admission_date, conditions, notes);
  logAudit(req.user.id, req.user.name, req.home.id, 'RESIDENT_ADDED', 'resident', result.lastInsertRowid, { name });
  res.redirect('/residents');
});

app.get('/residents/:id', requireAuth, (req, res) => {
  const r = db.prepare('SELECT * FROM residents WHERE id = ? AND home_id = ?').get(req.params.id, req.home.id);
  if (!r) return res.redirect('/residents');
  const poa = db.prepare('SELECT * FROM poa_contacts WHERE resident_id = ?').get(r.id);
  const family = db.prepare('SELECT * FROM family_members WHERE resident_id = ?').all(r.id);
  const meds = db.prepare('SELECT * FROM medications WHERE resident_id = ? AND active = 1').all(r.id);
  const acts = db.prepare('SELECT * FROM activities WHERE resident_id = ? ORDER BY created_at DESC LIMIT 10').all(r.id);
  const incidents = db.prepare('SELECT * FROM incidents WHERE resident_id = ? ORDER BY created_at DESC LIMIT 5').all(r.id);
  
  let poaHtml = poa ? '<p><strong>'+poa.name+'</strong> <span class="badge badge-blue">'+(poa.poa_type||'POA')+'</span></p><p class="text-muted">'+(poa.relationship||'')+'</p><p>📞 '+(poa.phone||'No phone')+'</p><p>✉️ '+(poa.email||'No email')+'</p>' : '<p class="text-muted">No POA set</p>'+(req.perms.canManageUsers?'<a href="/family/resident/'+r.id+'/poa/new" class="btn btn-primary btn-sm mt-4">+ Add POA</a>':'');
  
  let medsHtml = meds.length > 0 ? meds.map(m => '<div style="padding:10px 0;border-bottom:1px solid #f1f5f9"><strong>'+m.name+'</strong> - '+(m.dosage||'')+' <p class="text-sm text-muted">'+(m.frequency||'')+' '+(m.instructions?'• '+m.instructions:'')+'</p></div>').join('') : '<p class="text-muted">No medications</p>';
  
  let actsHtml = acts.length > 0 ? acts.map(a => '<div style="padding:10px 0;border-bottom:1px solid #f1f5f9"><strong>'+a.type+'</strong>'+(a.mood?' - '+a.mood:'')+'<p class="text-sm text-muted">'+new Date(a.created_at).toLocaleString()+(a.staff_name?' • '+a.staff_name:'')+'</p></div>').join('') : '<p class="text-muted">No activities</p>';
  
  let incidentsHtml = incidents.length > 0 ? incidents.map(i => '<div style="padding:10px 0;border-bottom:1px solid #f1f5f9"><strong>'+i.type+'</strong> <span class="badge '+(i.severity==='major'?'badge-red':'badge-yellow')+'">'+i.severity+'</span><p class="text-sm text-muted">'+new Date(i.created_at).toLocaleString()+'</p></div>').join('') : '<p class="text-muted">No incidents</p>';
  
  const exportBtn = req.perms.canExport ? '<a href="/residents/'+r.id+'/export" class="btn btn-secondary btn-sm">📄 Export History</a>' : '';
  
  res.send(layout(r.name, '<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:24px;flex-wrap:wrap;gap:12px"><div style="display:flex;align-items:center;gap:16px"><div class="resident-avatar" style="width:64px;height:64px;font-size:28px">'+r.name.charAt(0)+'</div><div><h2 style="margin-bottom:4px">'+r.name+'</h2><p class="text-muted">Room '+(r.room||'-')+'</p></div></div><div style="display:flex;gap:8px">'+exportBtn+'<a href="/residents" class="btn btn-secondary">← Back</a></div></div><div class="grid-2"><div class="card"><h3>Details</h3><p><strong>DOB:</strong> '+(r.date_of_birth||'N/A')+'</p><p><strong>Admission:</strong> '+(r.admission_date||'N/A')+'</p><p><strong>Conditions:</strong> '+(r.conditions||'None')+'</p><p><strong>Notes:</strong> '+(r.notes||'None')+'</p></div><div class="card"><h3>POA / Responsible Party</h3>'+poaHtml+'</div></div><div class="grid-2"><div class="card"><div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:12px"><h3>Medications</h3>'+(req.perms.canManageUsers?'<a href="/medications/new?resident='+r.id+'" class="btn btn-primary btn-sm">+ Add</a>':'')+'</div>'+medsHtml+'</div><div class="card"><div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:12px"><h3>Recent Activities</h3><a href="/activities/new?resident='+r.id+'" class="btn btn-primary btn-sm">+ Log</a></div>'+actsHtml+'</div></div><div class="grid-2"><div class="card"><h3>Recent Incidents</h3>'+incidentsHtml+'</div><div class="card"><h3>Family Members</h3>'+(family.length>0?family.map(f=>'<div style="padding:8px 0"><strong>'+f.name+'</strong> - '+(f.relationship||'Family')+'<br><span class="text-sm text-muted">'+(f.phone||'')+' '+(f.email||'')+'</span></div>').join(''):'<p class="text-muted">No family members</p>')+'</div></div>', req.user, 'residents'));
});

// ============================================
// REPORTS & EXPORTS
// ============================================
app.get('/reports', requireAuth, requireRole('owner', 'admin'), (req, res) => {
  res.send(layout('Reports', '<h2>Reports & Exports</h2><div class="grid-2"><div class="card"><h3>📊 Activity Reports</h3><p class="text-muted">Export activity logs for all residents.</p><form method="GET" action="/reports/activities"><div class="form-row"><div><label>Start Date</label><input type="date" name="start" value="'+new Date(Date.now()-30*24*60*60*1000).toISOString().split('T')[0]+'"></div><div><label>End Date</label><input type="date" name="end" value="'+new Date().toISOString().split('T')[0]+'"></div></div><button type="submit" class="btn btn-primary">Export CSV</button></form></div><div class="card"><h3>⚠️ Incident Reports</h3><p class="text-muted">Export all incident reports.</p><form method="GET" action="/reports/incidents"><div class="form-row"><div><label>Start Date</label><input type="date" name="start" value="'+new Date(Date.now()-90*24*60*60*1000).toISOString().split('T')[0]+'"></div><div><label>End Date</label><input type="date" name="end" value="'+new Date().toISOString().split('T')[0]+'"></div></div><button type="submit" class="btn btn-primary">Export CSV</button></form></div></div><div class="grid-2"><div class="card"><h3>⏱️ Time & Attendance</h3><p class="text-muted">Export staff time entries.</p><form method="GET" action="/reports/time"><div class="form-row"><div><label>Start Date</label><input type="date" name="start" value="'+new Date(Date.now()-14*24*60*60*1000).toISOString().split('T')[0]+'"></div><div><label>End Date</label><input type="date" name="end" value="'+new Date().toISOString().split('T')[0]+'"></div></div><button type="submit" class="btn btn-primary">Export CSV</button></form></div><div class="card"><h3>💊 Medication Administration</h3><p class="text-muted">Export MAR records.</p><form method="GET" action="/reports/mar"><div class="form-row"><div><label>Start Date</label><input type="date" name="start" value="'+new Date(Date.now()-30*24*60*60*1000).toISOString().split('T')[0]+'"></div><div><label>End Date</label><input type="date" name="end" value="'+new Date().toISOString().split('T')[0]+'"></div></div><button type="submit" class="btn btn-primary">Export CSV</button></form></div></div>', req.user, 'reports'));
});

// CSV Export helper
function toCSV(headers, rows) {
  const escape = (val) => '"' + String(val || '').replace(/"/g, '""') + '"';
  let csv = headers.map(escape).join(',') + '\n';
  rows.forEach(row => {
    csv += headers.map(h => escape(row[h])).join(',') + '\n';
  });
  return csv;
}

app.get('/reports/activities', requireAuth, requireRole('owner', 'admin'), (req, res) => {
  const { start, end } = req.query;
  const activities = db.prepare(`
    SELECT a.created_at as date, r.name as resident, a.type, a.mood, a.notes, a.staff_name as logged_by
    FROM activities a 
    LEFT JOIN residents r ON a.resident_id = r.id 
    WHERE a.home_id = ? AND date(a.created_at) >= ? AND date(a.created_at) <= ?
    ORDER BY a.created_at DESC
  `).all(req.home.id, start, end);
  
  const csv = toCSV(['date', 'resident', 'type', 'mood', 'notes', 'logged_by'], activities);
  res.setHeader('Content-Type', 'text/csv');
  res.setHeader('Content-Disposition', 'attachment; filename=activities-'+start+'-to-'+end+'.csv');
  res.send(csv);
});

app.get('/reports/incidents', requireAuth, requireRole('owner', 'admin'), (req, res) => {
  const { start, end } = req.query;
  const incidents = db.prepare(`
    SELECT i.created_at as date, r.name as resident, i.type, i.severity, i.description, i.immediate_actions, i.follow_up, i.reported_by, i.witnesses, i.notified_poa
    FROM incidents i 
    LEFT JOIN residents r ON i.resident_id = r.id 
    WHERE i.home_id = ? AND date(i.created_at) >= ? AND date(i.created_at) <= ?
    ORDER BY i.created_at DESC
  `).all(req.home.id, start, end);
  
  const csv = toCSV(['date', 'resident', 'type', 'severity', 'description', 'immediate_actions', 'follow_up', 'reported_by', 'witnesses', 'notified_poa'], incidents);
  res.setHeader('Content-Type', 'text/csv');
  res.setHeader('Content-Disposition', 'attachment; filename=incidents-'+start+'-to-'+end+'.csv');
  res.send(csv);
});

app.get('/reports/time', requireAuth, requireRole('owner', 'admin'), (req, res) => {
  const { start, end } = req.query;
  const entries = db.prepare(`
    SELECT date(t.clock_in) as date, u.name as staff, t.clock_in, t.clock_out, t.break_minutes,
           ROUND((julianday(t.clock_out) - julianday(t.clock_in)) * 24 - t.break_minutes/60.0, 2) as hours
    FROM time_entries t 
    JOIN users u ON t.user_id = u.id 
    WHERE t.home_id = ? AND date(t.clock_in) >= ? AND date(t.clock_in) <= ? AND t.clock_out IS NOT NULL
    ORDER BY t.clock_in DESC
  `).all(req.home.id, start, end);
  
  const csv = toCSV(['date', 'staff', 'clock_in', 'clock_out', 'break_minutes', 'hours'], entries);
  res.setHeader('Content-Type', 'text/csv');
  res.setHeader('Content-Disposition', 'attachment; filename=time-entries-'+start+'-to-'+end+'.csv');
  res.send(csv);
});

app.get('/reports/mar', requireAuth, requireRole('owner', 'admin'), (req, res) => {
  const { start, end } = req.query;
  const records = db.prepare(`
    SELECT m.administered_at as date, r.name as resident, med.name as medication, med.dosage, m.status, m.administered_by, m.notes
    FROM mar_records m 
    JOIN medications med ON m.medication_id = med.id
    JOIN residents r ON m.resident_id = r.id 
    WHERE r.home_id = ? AND date(m.administered_at) >= ? AND date(m.administered_at) <= ?
    ORDER BY m.administered_at DESC
  `).all(req.home.id, start, end);
  
  const csv = toCSV(['date', 'resident', 'medication', 'dosage', 'status', 'administered_by', 'notes'], records);
  res.setHeader('Content-Type', 'text/csv');
  res.setHeader('Content-Disposition', 'attachment; filename=mar-'+start+'-to-'+end+'.csv');
  res.send(csv);
});

// Individual resident export
app.get('/residents/:id/export', requireAuth, requireRole('owner', 'admin'), (req, res) => {
  const r = db.prepare('SELECT * FROM residents WHERE id = ? AND home_id = ?').get(req.params.id, req.home.id);
  if (!r) return res.redirect('/residents');
  
  const activities = db.prepare('SELECT created_at as date, type, mood, notes, staff_name FROM activities WHERE resident_id = ? ORDER BY created_at DESC').all(r.id);
  const incidents = db.prepare('SELECT created_at as date, type, severity, description, immediate_actions, reported_by FROM incidents WHERE resident_id = ? ORDER BY created_at DESC').all(r.id);
  const mar = db.prepare('SELECT m.administered_at as date, med.name as medication, med.dosage, m.status, m.administered_by FROM mar_records m JOIN medications med ON m.medication_id = med.id WHERE m.resident_id = ? ORDER BY m.administered_at DESC').all(r.id);
  
  let content = 'RESIDENT HISTORY EXPORT\n';
  content += '========================\n\n';
  content += 'Name: ' + r.name + '\n';
  content += 'Room: ' + (r.room || 'N/A') + '\n';
  content += 'DOB: ' + (r.date_of_birth || 'N/A') + '\n';
  content += 'Admission: ' + (r.admission_date || 'N/A') + '\n';
  content += 'Conditions: ' + (r.conditions || 'None') + '\n\n';
  
  content += 'ACTIVITIES (' + activities.length + ' records)\n';
  content += '-'.repeat(40) + '\n';
  activities.forEach(a => {
    content += a.date + ' | ' + a.type + ' | ' + (a.mood || '-') + ' | ' + (a.notes || '') + '\n';
  });
  
  content += '\n\nINCIDENTS (' + incidents.length + ' records)\n';
  content += '-'.repeat(40) + '\n';
  incidents.forEach(i => {
    content += i.date + ' | ' + i.type + ' | ' + i.severity + '\n';
    content += '  Description: ' + (i.description || '') + '\n';
    content += '  Actions: ' + (i.immediate_actions || '') + '\n\n';
  });
  
  content += '\n\nMEDICATION ADMINISTRATION (' + mar.length + ' records)\n';
  content += '-'.repeat(40) + '\n';
  mar.forEach(m => {
    content += m.date + ' | ' + m.medication + ' ' + m.dosage + ' | ' + m.status + ' | ' + m.administered_by + '\n';
  });
  
  res.setHeader('Content-Type', 'text/plain');
  res.setHeader('Content-Disposition', 'attachment; filename='+r.name.replace(/\s+/g, '-')+'-history.txt');
  res.send(content);
});

// Single incident PDF-style export
app.get('/incidents/:id/export', requireAuth, (req, res) => {
  const i = db.prepare('SELECT i.*, r.name as resident_name FROM incidents i LEFT JOIN residents r ON i.resident_id = r.id WHERE i.id = ? AND i.home_id = ?').get(req.params.id, req.home.id);
  if (!i) return res.redirect('/incidents');
  
  const poa = db.prepare('SELECT * FROM poa_contacts WHERE resident_id = ?').get(i.resident_id);
  
  const html = `<!DOCTYPE html>
<html><head><title>Incident Report #${i.id}</title>
<style>
  body { font-family: Arial, sans-serif; max-width: 800px; margin: 40px auto; padding: 20px; }
  h1 { color: #991b1b; border-bottom: 2px solid #991b1b; padding-bottom: 10px; }
  .header { display: flex; justify-content: space-between; margin-bottom: 20px; }
  .field { margin-bottom: 16px; }
  .label { font-weight: bold; color: #475569; }
  .value { margin-top: 4px; }
  .severity { display: inline-block; padding: 4px 12px; border-radius: 4px; font-weight: bold; }
  .severity.major { background: #fee2e2; color: #991b1b; }
  .severity.moderate { background: #fef9c3; color: #854d0e; }
  .severity.minor { background: #f1f5f9; color: #475569; }
  .section { background: #f8fafc; padding: 16px; border-radius: 8px; margin: 16px 0; }
  @media print { body { margin: 0; } }
</style></head><body>
<h1>⚠️ Incident Report</h1>
<div class="header">
  <div><strong>Report #:</strong> ${i.id}</div>
  <div><strong>Date:</strong> ${new Date(i.created_at).toLocaleString()}</div>
</div>
<div class="field"><div class="label">Resident</div><div class="value">${i.resident_name || 'Unknown'}</div></div>
<div class="field"><div class="label">Incident Type</div><div class="value">${i.type}</div></div>
<div class="field"><div class="label">Severity</div><div class="value"><span class="severity ${i.severity}">${i.severity?.toUpperCase()}</span></div></div>
<div class="section">
  <div class="field"><div class="label">Description</div><div class="value">${i.description || 'N/A'}</div></div>
</div>
<div class="field"><div class="label">Immediate Actions Taken</div><div class="value">${i.immediate_actions || 'N/A'}</div></div>
<div class="field"><div class="label">Follow-up Required</div><div class="value">${i.follow_up || 'N/A'}</div></div>
<div class="field"><div class="label">Reported By</div><div class="value">${i.reported_by || 'N/A'}</div></div>
<div class="field"><div class="label">Witnesses</div><div class="value">${i.witnesses || 'None'}</div></div>
<div class="section">
  <div class="label">POA/Responsible Party Contact</div>
  ${poa ? `<div class="value">${poa.name} (${poa.relationship || 'POA'})<br>Phone: ${poa.phone || 'N/A'}<br>Email: ${poa.email || 'N/A'}</div>` : '<div class="value">Not on file</div>'}
  <div style="margin-top:8px"><strong>POA Notified:</strong> ${i.notified_poa ? 'Yes' + (i.notified_at ? ' on ' + new Date(i.notified_at).toLocaleString() : '') : 'No'}</div>
</div>
<div style="margin-top:40px;padding-top:20px;border-top:1px solid #e2e8f0;">
  <p><strong>Signature:</strong> ___________________________ <strong>Date:</strong> _______________</p>
</div>
<script>window.print();</script>
</body></html>`;
  
  res.send(html);
});

// ============================================
// STAFF
// ============================================
app.get('/staff', requireAuth, requireRole('owner', 'admin'), (req, res) => {
  const staff = db.prepare('SELECT * FROM staff WHERE home_id = ? AND active = 1 ORDER BY name').all(req.home?.id || 0);
  const staffData = staff.map(s => {
    const certs = db.prepare('SELECT * FROM certifications WHERE staff_id = ?').all(s.id);
    const exp = certs.filter(c => (new Date(c.expiration_date) - new Date()) / (1000*60*60*24) < 60).length;
    return { ...s, certCount: certs.length, expiring: exp };
  });
  let html = staffData.length > 0 ? '<table><thead><tr><th>Name</th><th>Role</th><th>Contact</th><th>Certifications</th><th>Actions</th></tr></thead><tbody>'+staffData.map(s => '<tr><td><strong>'+s.name+'</strong></td><td>'+(s.role||'Caregiver')+'</td><td>'+(s.phone?'📞 '+s.phone:'')+(s.email?'<br>✉️ '+s.email:'')+'</td><td>'+s.certCount+' certs'+(s.expiring>0?' <span class="badge badge-red">'+s.expiring+' expiring</span>':'')+'</td><td><a href="/staff/'+s.id+'" class="btn btn-secondary btn-sm">View</a></td></tr>').join('')+'</tbody></table>' : '<div class="empty-state"><p>No staff yet</p><a href="/staff/new" class="btn btn-primary mt-4">Add Staff</a></div>';
  res.send(layout('Staff', '<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:24px;flex-wrap:wrap;gap:12px"><h2>Staff</h2><a href="/staff/new" class="btn btn-primary">+ Add Staff</a></div><div class="card">'+html+'</div>', req.user, 'staff'));
});

app.get('/staff/new', requireAuth, requireRole('owner', 'admin'), (req, res) => {
  res.send(layout('Add Staff', '<h2>Add Staff Member</h2><div class="card"><form method="POST" action="/staff"><div class="form-row"><div><label>Full Name *</label><input type="text" name="name" required placeholder="Sarah Martinez"></div><div><label>Role</label><select name="role"><option>Caregiver</option><option>Lead Caregiver</option><option>Administrator</option><option>Cook</option></select></div></div><div class="form-row"><div><label>Phone</label><input type="tel" name="phone" placeholder="(206) 555-0100"></div><div><label>Email</label><input type="email" name="email" placeholder="staff@email.com"></div></div><label>Hourly Rate</label><input type="number" name="hourly_rate" step="0.01" placeholder="18.00"><div style="display:flex;gap:12px;margin-top:8px"><button type="submit" class="btn btn-primary">Add Staff</button><a href="/staff" class="btn btn-secondary">Cancel</a></div></form></div>', req.user, 'staff'));
});

app.post('/staff', requireAuth, requireRole('owner', 'admin'), (req, res) => {
  const { name, role, phone, email, hourly_rate } = req.body;
  db.prepare('INSERT INTO staff (home_id, name, role, phone, email, hourly_rate) VALUES (?, ?, ?, ?, ?, ?)').run(req.home.id, name, role, phone, email, hourly_rate || null);
  res.redirect('/staff');
});

app.get('/staff/:id', requireAuth, requireRole('owner', 'admin'), (req, res) => {
  const s = db.prepare('SELECT * FROM staff WHERE id = ? AND home_id = ?').get(req.params.id, req.home.id);
  if (!s) return res.redirect('/staff');
  const certs = db.prepare('SELECT * FROM certifications WHERE staff_id = ? ORDER BY expiration_date').all(s.id);
  let certHtml = certs.length > 0 ? '<table><thead><tr><th>Type</th><th>Expires</th><th>Status</th></tr></thead><tbody>'+certs.map(c => {
    const days = Math.ceil((new Date(c.expiration_date) - new Date()) / (1000*60*60*24));
    let st = 'badge-green', txt = 'Current';
    if (days < 0) { st = 'badge-red'; txt = 'EXPIRED'; }
    else if (days < 30) { st = 'badge-red'; txt = days+' days'; }
    else if (days < 60) { st = 'badge-yellow'; txt = days+' days'; }
    return '<tr><td>'+c.type+'</td><td>'+c.expiration_date+'</td><td><span class="badge '+st+'">'+txt+'</span></td></tr>';
  }).join('')+'</tbody></table>' : '<p class="text-muted">No certifications</p>';
  res.send(layout(s.name, '<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:24px;flex-wrap:wrap;gap:12px"><div><h2>'+s.name+'</h2><p class="text-muted">'+(s.role||'Caregiver')+(s.hourly_rate?' • $'+s.hourly_rate+'/hr':'')+'</p></div><a href="/staff" class="btn btn-secondary">← Back</a></div><div class="grid-2"><div class="card"><h3>Contact</h3><p><strong>Phone:</strong> '+(s.phone||'N/A')+'</p><p><strong>Email:</strong> '+(s.email||'N/A')+'</p></div><div class="card"><div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:16px"><h3>Certifications</h3><a href="/staff/'+s.id+'/certs/new" class="btn btn-primary btn-sm">+ Add</a></div>'+certHtml+'</div></div>', req.user, 'staff'));
});

app.get('/staff/:id/certs/new', requireAuth, requireRole('owner', 'admin'), (req, res) => {
  const s = db.prepare('SELECT * FROM staff WHERE id = ? AND home_id = ?').get(req.params.id, req.home.id);
  if (!s) return res.redirect('/staff');
  res.send(layout('Add Certification', '<h2>Add Certification for '+s.name+'</h2><div class="card"><form method="POST" action="/staff/'+s.id+'/certs"><label>Type *</label><select name="type" required><option>CPR/First Aid</option><option>Food Handler\'s Card</option><option>Dementia Training</option><option>TB Test</option><option>Background Check</option><option>Nurse Delegation</option><option>HIV/AIDS Training</option><option>Mental Health Training</option></select><div class="form-row"><div><label>Issue Date</label><input type="date" name="issue_date" min="2000-01-01" max="'+new Date().toISOString().split('T')[0]+'"></div><div><label>Expiration Date *</label><input type="date" name="expiration_date" required min="'+new Date().toISOString().split('T')[0]+'" max="2099-12-31"></div></div><label>Certificate Number</label><input type="text" name="certificate_number" placeholder="Optional"><div style="display:flex;gap:12px;margin-top:8px"><button type="submit" class="btn btn-primary">Add Certification</button><a href="/staff/'+s.id+'" class="btn btn-secondary">Cancel</a></div></form></div>', req.user, 'staff'));
});

app.post('/staff/:id/certs', requireAuth, requireRole('owner', 'admin'), (req, res) => {
  const { type, issue_date, expiration_date, certificate_number } = req.body;
  db.prepare('INSERT INTO certifications (staff_id, type, issue_date, expiration_date, certificate_number) VALUES (?, ?, ?, ?, ?)').run(req.params.id, type, issue_date, expiration_date, certificate_number);
  res.redirect('/staff/'+req.params.id);
});

// ============================================
// ACTIVITIES
// ============================================
app.get('/activities', requireAuth, (req, res) => {
  const acts = db.prepare('SELECT a.*, r.name as rn FROM activities a LEFT JOIN residents r ON a.resident_id = r.id WHERE a.home_id = ? ORDER BY a.created_at DESC LIMIT 50').all(req.home?.id || 0);
  let html = acts.length > 0 ? '<table><thead><tr><th>Date/Time</th><th>Resident</th><th>Type</th><th>Mood</th><th>Logged By</th><th>Notes</th></tr></thead><tbody>'+acts.map(a => '<tr><td class="text-sm">'+new Date(a.created_at).toLocaleString()+'</td><td><strong>'+(a.rn||'Unknown')+'</strong></td><td>'+a.type+'</td><td>'+(a.mood?(a.mood==='great'?'😄':a.mood==='good'?'🙂':a.mood==='okay'?'😐':'😔')+' '+a.mood:'-')+'</td><td>'+(a.staff_name||'-')+'</td><td class="text-sm text-muted">'+(a.notes||'-')+'</td></tr>').join('')+'</tbody></table>' : '<div class="empty-state"><p>No activities yet</p><a href="/activities/new" class="btn btn-primary mt-4">Log Activity</a></div>';
  res.send(layout('Activities', '<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:24px;flex-wrap:wrap;gap:12px"><h2>Activities</h2><a href="/activities/new" class="btn btn-primary">+ Log Activity</a></div><div class="card">'+html+'</div>', req.user, 'activities'));
});

app.get('/activities/new', requireAuth, (req, res) => {
  if (req.user.role === 'family') return res.redirect('/dashboard');
  const residents = db.prepare('SELECT * FROM residents WHERE home_id = ? AND active = 1 ORDER BY name').all(req.home?.id || 0);
  const pre = req.query.resident;
  res.send(layout('Log Activity', '<h2>Log Activity</h2><div class="card"><form method="POST" action="/activities"><label>Resident *</label><select name="resident_id" required><option value="">Select...</option>'+residents.map(r => '<option value="'+r.id+'"'+(pre==r.id?' selected':'')+'>'+r.name+'</option>').join('')+'</select><label>Type *</label><select name="type" required><option value="meal">🍽️ Meal</option><option value="medication">💊 Medication</option><option value="activity">🎯 Activity/Exercise</option><option value="rest">😴 Rest</option><option value="outing">🌳 Outing</option><option value="social">👥 Social</option><option value="hygiene">🚿 Personal Care</option></select><label>Mood</label><select name="mood"><option value="great">😄 Great</option><option value="good" selected>🙂 Good</option><option value="okay">😐 Okay</option><option value="low">😔 Low</option></select><label>Notes</label><textarea name="notes" rows="3" placeholder="Details..."></textarea><div style="display:flex;gap:12px;margin-top:8px"><button type="submit" class="btn btn-primary">Log Activity</button><a href="/activities" class="btn btn-secondary">Cancel</a></div></form></div>', req.user, 'activities'));
});

app.post('/activities', requireAuth, (req, res) => {
  if (req.user.role === 'family') return res.redirect('/dashboard');
  const { resident_id, type, mood, notes } = req.body;
  db.prepare('INSERT INTO activities (home_id, resident_id, user_id, type, mood, notes, staff_name) VALUES (?, ?, ?, ?, ?, ?, ?)').run(req.home.id, resident_id, req.user.id, type, mood, notes, req.user.name);
  logAudit(req.user.id, req.user.name, req.home.id, 'ACTIVITY_LOGGED', 'activity', null, { type });
  res.redirect('/activities');
});

// ============================================
// INCIDENTS
// ============================================
app.get('/incidents', requireAuth, (req, res) => {
  if (req.user.role === 'family') return res.redirect('/dashboard');
  const incs = db.prepare('SELECT i.*, r.name as rn FROM incidents i LEFT JOIN residents r ON i.resident_id = r.id WHERE i.home_id = ? ORDER BY i.created_at DESC').all(req.home?.id || 0);
  let html = incs.length > 0 ? '<table><thead><tr><th>Date</th><th>Resident</th><th>Type</th><th>Severity</th><th>Reported By</th><th>POA Notified</th><th>Actions</th></tr></thead><tbody>'+incs.map(i => '<tr><td>'+new Date(i.created_at).toLocaleDateString()+'</td><td><strong>'+(i.rn||'Unknown')+'</strong></td><td>'+i.type+'</td><td><span class="badge '+(i.severity==='major'?'badge-red':i.severity==='moderate'?'badge-yellow':'badge-gray')+'">'+(i.severity||'minor')+'</span></td><td>'+(i.reported_by||'-')+'</td><td>'+(i.notified_poa?'<span class="badge badge-green">✓ Yes</span>':'<span class="badge badge-gray">No</span>')+'</td><td><a href="/incidents/'+i.id+'/export" class="btn btn-secondary btn-sm">📄 Export</a></td></tr>').join('')+'</tbody></table>' : '<div class="empty-state"><p>No incidents</p></div>';
  res.send(layout('Incidents', '<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:24px;flex-wrap:wrap;gap:12px"><h2>Incidents</h2><a href="/incidents/new" class="btn btn-danger">+ Report Incident</a></div><div class="card">'+html+'</div>', req.user, 'incidents'));
});

app.get('/incidents/new', requireAuth, (req, res) => {
  if (req.user.role === 'family') return res.redirect('/dashboard');
  const residents = db.prepare('SELECT * FROM residents WHERE home_id = ? AND active = 1 ORDER BY name').all(req.home?.id || 0);
  res.send(layout('Report Incident', '<h2>Report Incident</h2><div class="card"><form method="POST" action="/incidents"><label>Resident *</label><select name="resident_id" required><option value="">Select...</option>'+residents.map(r => '<option value="'+r.id+'">'+r.name+'</option>').join('')+'</select><div class="form-row"><div><label>Type *</label><select name="type" required><option value="fall">Fall</option><option value="medication_error">Medication Error</option><option value="behavior">Behavior</option><option value="injury">Injury</option><option value="illness">Illness</option><option value="elopement">Elopement</option><option value="other">Other</option></select></div><div><label>Severity *</label><select name="severity" required><option value="minor">Minor</option><option value="moderate">Moderate</option><option value="major">Major</option></select></div></div><label>Description *</label><textarea name="description" rows="4" required placeholder="What happened..."></textarea><label>Immediate Actions Taken</label><textarea name="immediate_actions" rows="2" placeholder="What was done..."></textarea><label>Follow-up Required</label><textarea name="follow_up" rows="2" placeholder="Follow-up needed..."></textarea><label>Witnesses</label><input type="text" name="witnesses" placeholder="Names"><div style="margin:16px 0"><label style="display:flex;align-items:center;gap:8px;cursor:pointer;margin-bottom:0"><input type="checkbox" name="notify_poa" value="1" style="width:auto;margin:0"> Notify POA/Responsible Party</label></div><div style="display:flex;gap:12px;margin-top:8px"><button type="submit" class="btn btn-danger">Submit Report</button><a href="/incidents" class="btn btn-secondary">Cancel</a></div></form></div>', req.user, 'incidents'));
});

app.post('/incidents', requireAuth, (req, res) => {
  if (req.user.role === 'family') return res.redirect('/dashboard');
  const { resident_id, type, severity, description, immediate_actions, follow_up, witnesses, notify_poa } = req.body;
  const result = db.prepare('INSERT INTO incidents (home_id, resident_id, user_id, type, severity, description, immediate_actions, follow_up, witnesses, reported_by, notified_poa, notified_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)').run(
    req.home.id, resident_id, req.user.id, type, severity, description, immediate_actions, follow_up, witnesses, req.user.name, 
    notify_poa ? 1 : 0, notify_poa ? new Date().toISOString() : null
  );
  logAudit(req.user.id, req.user.name, req.home.id, 'INCIDENT_REPORTED', 'incident', result.lastInsertRowid, { type, severity });
  res.redirect('/incidents');
});

// ============================================
// MEDICATIONS
// ============================================
app.get('/medications', requireAuth, (req, res) => {
  if (req.user.role === 'family') return res.redirect('/dashboard');
  const residents = db.prepare('SELECT * FROM residents WHERE home_id = ? AND active = 1 ORDER BY name').all(req.home?.id || 0);
  let html = residents.map(r => {
    const meds = db.prepare('SELECT * FROM medications WHERE resident_id = ? AND active = 1').all(r.id);
    let medsHtml = meds.length > 0 ? '<table><thead><tr><th>Medication</th><th>Dosage</th><th>Frequency</th><th>Instructions</th></tr></thead><tbody>'+meds.map(m => '<tr><td><strong>'+m.name+'</strong></td><td>'+(m.dosage||'-')+'</td><td>'+(m.frequency||'-')+'</td><td class="text-sm text-muted">'+(m.instructions||'-')+'</td></tr>').join('')+'</tbody></table>' : '<p class="text-muted">No medications</p>';
    return '<div class="card"><div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:16px"><div style="display:flex;align-items:center;gap:12px"><div class="resident-avatar" style="width:44px;height:44px;font-size:18px">'+r.name.charAt(0)+'</div><h3 style="margin:0">'+r.name+'</h3></div>'+(req.perms.canManageUsers?'<a href="/medications/new?resident='+r.id+'" class="btn btn-secondary btn-sm">+ Add</a>':'')+'</div>'+medsHtml+'</div>';
  }).join('');
  if (residents.length === 0) html = '<div class="card"><div class="empty-state"><p>No residents</p><a href="/residents/new" class="btn btn-primary mt-4">Add Resident</a></div></div>';
  
  const addBtn = req.perms.canManageUsers ? '<a href="/medications/new" class="btn btn-primary">+ Add</a>' : '';
  res.send(layout('Medications', '<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:24px;flex-wrap:wrap;gap:12px"><h2>Medications</h2><div style="display:flex;gap:12px"><a href="/medications/administer" class="btn btn-success">💊 Administer</a>'+addBtn+'</div></div>'+html, req.user, 'medications'));
});

app.get('/medications/new', requireAuth, requireRole('owner', 'admin'), (req, res) => {
  const residents = db.prepare('SELECT * FROM residents WHERE home_id = ? AND active = 1 ORDER BY name').all(req.home?.id || 0);
  const pre = req.query.resident;
  res.send(layout('Add Medication', '<h2>Add Medication</h2><div class="card"><form method="POST" action="/medications"><label>Resident *</label><select name="resident_id" required><option value="">Select...</option>'+residents.map(r => '<option value="'+r.id+'"'+(pre==r.id?' selected':'')+'>'+r.name+'</option>').join('')+'</select><div class="form-row"><div><label>Medication *</label><input type="text" name="name" required placeholder="Lisinopril"></div><div><label>Dosage *</label><input type="text" name="dosage" required placeholder="10mg"></div></div><label>Frequency *</label><select name="frequency" required><option>Once daily</option><option>Twice daily</option><option>Three times daily</option><option>Every morning</option><option>Every evening</option><option>At bedtime</option><option>As needed (PRN)</option></select><label>Instructions</label><textarea name="instructions" rows="2" placeholder="Take with food..."></textarea><div class="form-row"><div><label>Prescriber</label><input type="text" name="prescriber" placeholder="Dr. Smith"></div><div><label>Pharmacy</label><input type="text" name="pharmacy" placeholder="CVS"></div></div><div style="display:flex;gap:12px;margin-top:8px"><button type="submit" class="btn btn-primary">Add</button><a href="/medications" class="btn btn-secondary">Cancel</a></div></form></div>', req.user, 'medications'));
});

app.post('/medications', requireAuth, requireRole('owner', 'admin'), (req, res) => {
  const { resident_id, name, dosage, frequency, instructions, prescriber, pharmacy } = req.body;
  db.prepare('INSERT INTO medications (resident_id, name, dosage, frequency, instructions, prescriber, pharmacy) VALUES (?, ?, ?, ?, ?, ?, ?)').run(resident_id, name, dosage, frequency, instructions, prescriber, pharmacy);
  res.redirect('/medications');
});

app.get('/medications/administer', requireAuth, (req, res) => {
  if (req.user.role === 'family') return res.redirect('/dashboard');
  const residents = db.prepare('SELECT * FROM residents WHERE home_id = ? AND active = 1 ORDER BY name').all(req.home?.id || 0);
  const data = residents.map(r => ({ ...r, meds: db.prepare('SELECT * FROM medications WHERE resident_id = ? AND active = 1').all(r.id) })).filter(r => r.meds.length > 0);
  
  let html = data.length > 0 ? data.map(r => '<div class="card"><div style="display:flex;align-items:center;gap:12px;margin-bottom:16px"><div class="resident-avatar" style="width:44px;height:44px;font-size:18px">'+r.name.charAt(0)+'</div><h3 style="margin:0">'+r.name+'</h3></div>'+r.meds.map(m => '<form method="POST" action="/medications/administer" style="display:flex;align-items:center;gap:16px;padding:12px;background:#f8fafc;border-radius:10px;margin-bottom:8px;flex-wrap:wrap"><input type="hidden" name="medication_id" value="'+m.id+'"><input type="hidden" name="resident_id" value="'+r.id+'"><div style="flex:1;min-width:200px"><strong>'+m.name+'</strong> - '+m.dosage+'<p class="text-sm text-muted" style="margin:0">'+m.frequency+(m.instructions?' • '+m.instructions:'')+'</p></div><select name="status" style="width:auto;margin:0"><option value="given">✓ Given</option><option value="refused">✗ Refused</option><option value="held">⏸ Held</option></select><input type="text" name="notes" placeholder="Notes" style="width:120px;margin:0"><button type="submit" class="btn btn-success btn-sm">Record</button></form>').join('')+'</div>').join('') : '<div class="card"><div class="empty-state"><p>No medications to administer</p><a href="/medications/new" class="btn btn-primary mt-4">Add Medication</a></div></div>';
  
  res.send(layout('Administer Meds', '<h2>Administer Medications</h2>'+html+'<a href="/medications" class="btn btn-secondary">← Back</a>', req.user, 'medications'));
});

app.post('/medications/administer', requireAuth, (req, res) => {
  if (req.user.role === 'family') return res.redirect('/dashboard');
  const { medication_id, resident_id, status, notes } = req.body;
  db.prepare('INSERT INTO mar_records (medication_id, resident_id, user_id, administered_by, status, notes) VALUES (?, ?, ?, ?, ?, ?)').run(medication_id, resident_id, req.user.id, req.user.name, status, notes);
  logAudit(req.user.id, req.user.name, req.home.id, 'MED_ADMINISTERED', 'medication', medication_id, { status });
  res.redirect('/medications/administer');
});

// ============================================
// FAMILY COMMUNICATION
// ============================================
app.get('/family', requireAuth, requireRole('owner', 'admin'), (req, res) => {
  const residents = db.prepare('SELECT * FROM residents WHERE home_id = ? AND active = 1 ORDER BY name').all(req.home?.id || 0);
  const data = residents.map(r => {
    const poa = db.prepare('SELECT * FROM poa_contacts WHERE resident_id = ?').get(r.id);
    const fc = db.prepare('SELECT COUNT(*) as c FROM family_members WHERE resident_id = ?').get(r.id)?.c || 0;
    return { ...r, poa, familyCount: fc };
  });
  const msgs = db.prepare('SELECT m.*, r.name as rn FROM family_messages m LEFT JOIN residents r ON m.resident_id = r.id WHERE m.home_id = ? ORDER BY m.created_at DESC LIMIT 10').all(req.home?.id || 0);
  
  let tableHtml = data.length > 0 ? '<table><thead><tr><th>Resident</th><th>POA</th><th>Family</th><th>Actions</th></tr></thead><tbody>'+data.map(r => '<tr><td><strong>'+r.name+'</strong><br><span class="text-muted text-sm">Room '+(r.room||'-')+'</span></td><td>'+(r.poa?r.poa.name+'<br><span class="text-muted text-sm">'+(r.poa.relationship||'')+' • '+(r.poa.poa_type||'POA')+'</span>':'<span class="text-muted">Not set</span>')+'</td><td>'+r.familyCount+' member'+(r.familyCount!==1?'s':'')+'</td><td><a href="/family/resident/'+r.id+'" class="btn btn-secondary btn-sm">Manage</a></td></tr>').join('')+'</tbody></table>' : '<div class="empty-state"><p>No residents</p><a href="/residents/new" class="btn btn-primary mt-4">Add Resident</a></div>';
  
  let msgHtml = msgs.length > 0 ? msgs.map(m => '<div class="activity-item"><div class="activity-icon" style="background:'+(m.recipient_type==='poa'?'#DBEAFE':'#FCE7F3')+'">'+(m.recipient_type==='poa'?'👤':'👨‍👩‍👧‍👦')+'</div><div class="activity-content"><strong>'+(m.rn||'All')+'</strong> <span class="badge '+(m.recipient_type==='poa'?'badge-blue':'badge-purple')+'">'+(m.recipient_type==='poa'?'POA Only':'All Family')+'</span><p class="text-sm text-muted">'+(m.message?.substring(0,80)||'')+'</p></div><div class="activity-time">'+new Date(m.created_at).toLocaleDateString()+'</div></div>').join('') : '<p class="text-muted">No messages yet</p>';
  
  res.send(layout('Family', '<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:24px;flex-wrap:wrap;gap:12px"><h2>Family Communication</h2><a href="/family/messages/new" class="btn btn-primary">+ Send Message</a></div><div class="card"><h3>Residents & Contacts</h3>'+tableHtml+'</div><div class="card"><h3>Recent Messages</h3>'+msgHtml+'</div>', req.user, 'family'));
});

app.get('/family/resident/:id', requireAuth, requireRole('owner', 'admin'), (req, res) => {
  const r = db.prepare('SELECT * FROM residents WHERE id = ? AND home_id = ?').get(req.params.id, req.home.id);
  if (!r) return res.redirect('/family');
  const poa = db.prepare('SELECT * FROM poa_contacts WHERE resident_id = ?').get(r.id);
  const family = db.prepare('SELECT * FROM family_members WHERE resident_id = ? ORDER BY name').all(r.id);
  
  let poaHtml = poa ? '<p><strong>'+poa.name+'</strong></p><p class="text-muted">'+(poa.relationship||'')+'</p><p>📞 '+(poa.phone||'No phone')+'</p><p>✉️ '+(poa.email||'No email')+'</p><p style="margin-top:12px">'+(poa.poa_type?'<span class="badge badge-blue">'+poa.poa_type+'</span> ':'')+(poa.is_billing_contact?'<span class="badge badge-green">Billing</span> ':'')+(poa.is_emergency_contact?'<span class="badge badge-red">Emergency</span>':'')+'</p><a href="/family/poa/'+poa.id+'/edit" class="btn btn-secondary btn-sm mt-4">Edit POA</a>' : '<p class="text-muted">No POA set</p><a href="/family/resident/'+r.id+'/poa/new" class="btn btn-primary mt-4">+ Add POA</a>';
  
  let familyHtml = family.length > 0 ? family.map(f => '<div style="padding:16px;background:#f8fafc;border-radius:12px;margin-bottom:12px"><strong>'+f.name+'</strong> <span class="text-muted">- '+(f.relationship||'Family')+'</span><br><span class="text-sm text-muted">📞 '+(f.phone||'No phone')+' • ✉️ '+(f.email||'No email')+'</span><div style="margin-top:8px">'+(f.receive_updates?'<span class="badge badge-green">Updates</span> ':'')+(f.receive_weekly_reports?'<span class="badge badge-blue">Weekly</span> ':'')+(f.receive_incident_alerts?'<span class="badge badge-red">Incidents</span>':'')+'</div></div>').join('') : '<p class="text-muted">No family members</p>';
  
  res.send(layout('Family - '+r.name, '<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:24px;flex-wrap:wrap;gap:12px"><h2>Family for '+r.name+'</h2><a href="/family" class="btn btn-secondary">← Back</a></div><div class="grid-2"><div class="card"><h3>👤 POA / Responsible Party</h3>'+poaHtml+'</div><div class="card"><div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:16px"><h3>👨‍👩‍👧‍👦 Family Members</h3><a href="/family/resident/'+r.id+'/member/new" class="btn btn-primary btn-sm">+ Add</a></div>'+familyHtml+'</div></div>', req.user, 'family'));
});

app.get('/family/resident/:id/poa/new', requireAuth, requireRole('owner', 'admin'), (req, res) => {
  const r = db.prepare('SELECT * FROM residents WHERE id = ? AND home_id = ?').get(req.params.id, req.home.id);
  if (!r) return res.redirect('/family');
  res.send(layout('Add POA', '<h2>Add POA for '+r.name+'</h2><div class="card"><form method="POST" action="/family/resident/'+r.id+'/poa"><div class="form-row"><div><label>Name *</label><input type="text" name="name" required placeholder="Susan Johnson"></div><div><label>Relationship *</label><input type="text" name="relationship" required placeholder="Daughter"></div></div><div class="form-row"><div><label>Phone</label><input type="tel" name="phone" placeholder="(206) 555-0100"></div><div><label>Email</label><input type="email" name="email" placeholder="email@example.com"></div></div><label>POA Type</label><select name="poa_type"><option>Healthcare POA</option><option>Financial POA</option><option>Full POA</option><option>Guardian</option><option>Responsible Party</option></select><div style="margin:16px 0"><label style="display:flex;align-items:center;gap:8px;cursor:pointer;margin-bottom:0"><input type="checkbox" name="is_billing_contact" value="1" style="width:auto;margin:0"> Billing Contact</label><label style="display:flex;align-items:center;gap:8px;cursor:pointer;margin-top:12px;margin-bottom:0"><input type="checkbox" name="is_emergency_contact" value="1" checked style="width:auto;margin:0"> Emergency Contact</label></div><div style="display:flex;gap:12px"><button type="submit" class="btn btn-primary">Add POA</button><a href="/family/resident/'+r.id+'" class="btn btn-secondary">Cancel</a></div></form></div>', req.user, 'family'));
});

app.post('/family/resident/:id/poa', requireAuth, requireRole('owner', 'admin'), (req, res) => {
  const { name, relationship, phone, email, poa_type, is_billing_contact, is_emergency_contact } = req.body;
  db.prepare('DELETE FROM poa_contacts WHERE resident_id = ?').run(req.params.id);
  db.prepare('INSERT INTO poa_contacts (resident_id, name, relationship, phone, email, poa_type, is_billing_contact, is_emergency_contact) VALUES (?, ?, ?, ?, ?, ?, ?, ?)').run(req.params.id, name, relationship, phone, email, poa_type, is_billing_contact?1:0, is_emergency_contact?1:0);
  res.redirect('/family/resident/'+req.params.id);
});

app.get('/family/resident/:id/member/new', requireAuth, requireRole('owner', 'admin'), (req, res) => {
  const r = db.prepare('SELECT * FROM residents WHERE id = ? AND home_id = ?').get(req.params.id, req.home.id);
  if (!r) return res.redirect('/family');
  res.send(layout('Add Family', '<h2>Add Family Member for '+r.name+'</h2><div class="card"><form method="POST" action="/family/resident/'+r.id+'/member"><div class="form-row"><div><label>Name *</label><input type="text" name="name" required placeholder="Michael Johnson"></div><div><label>Relationship</label><input type="text" name="relationship" placeholder="Son"></div></div><div class="form-row"><div><label>Phone</label><input type="tel" name="phone" placeholder="(206) 555-0100"></div><div><label>Email</label><input type="email" name="email" placeholder="email@example.com"></div></div><h3 style="margin-top:24px">Notification Preferences</h3><div style="margin:16px 0"><label style="display:flex;align-items:center;gap:8px;cursor:pointer;margin-bottom:12px"><input type="checkbox" name="receive_updates" value="1" checked style="width:auto;margin:0"> Receive general updates</label><label style="display:flex;align-items:center;gap:8px;cursor:pointer;margin-bottom:12px"><input type="checkbox" name="receive_weekly_reports" value="1" checked style="width:auto;margin:0"> Receive weekly reports</label><label style="display:flex;align-items:center;gap:8px;cursor:pointer"><input type="checkbox" name="receive_incident_alerts" value="1" style="width:auto;margin:0"> Receive incident alerts (recommended for emergencies)</label></div><div style="display:flex;gap:12px"><button type="submit" class="btn btn-primary">Add Family Member</button><a href="/family/resident/'+r.id+'" class="btn btn-secondary">Cancel</a></div></form></div>', req.user, 'family'));
});

app.post('/family/resident/:id/member', requireAuth, requireRole('owner', 'admin'), (req, res) => {
  const { name, relationship, phone, email, receive_updates, receive_weekly_reports, receive_incident_alerts } = req.body;
  db.prepare('INSERT INTO family_members (resident_id, name, relationship, phone, email, receive_updates, receive_weekly_reports, receive_incident_alerts) VALUES (?, ?, ?, ?, ?, ?, ?, ?)').run(req.params.id, name, relationship, phone, email, receive_updates?1:0, receive_weekly_reports?1:0, receive_incident_alerts?1:0);
  res.redirect('/family/resident/'+req.params.id);
});

app.get('/family/messages/new', requireAuth, requireRole('owner', 'admin'), (req, res) => {
  const residents = db.prepare('SELECT * FROM residents WHERE home_id = ? AND active = 1 ORDER BY name').all(req.home?.id || 0);
  res.send(layout('Send Message', '<h2>Send Family Message</h2><div class="card"><form method="POST" action="/family/messages"><label>Resident</label><select name="resident_id"><option value="">All Residents</option>'+residents.map(r => '<option value="'+r.id+'">'+r.name+'</option>').join('')+'</select><label>Send To *</label><select name="recipient_type" required><option value="all">All Family Members</option><option value="poa">POA Only</option></select><label>Message Type</label><select name="message_type"><option value="update">General Update</option><option value="weekly">Weekly Report</option><option value="incident">Incident Notification</option><option value="billing">Billing</option></select><label>Message *</label><textarea name="message" rows="6" required placeholder="Type your message..."></textarea><div class="card" style="background:#EEF2FF;margin-bottom:20px;padding:16px"><strong>💡 Quick Messages</strong><div style="display:grid;gap:8px;margin-top:12px"><button type="button" onclick="document.querySelector(\'textarea[name=message]\').value=\'Having a great day! Active and engaged in activities. Eating well and in good spirits.\'" class="btn btn-secondary btn-sm">😊 Great day update</button><button type="button" onclick="document.querySelector(\'textarea[name=message]\').value=\'Enjoyed their meal today. Good appetite and socialized well during mealtime.\'" class="btn btn-secondary btn-sm">🍽️ Good meal</button><button type="button" onclick="document.querySelector(\'textarea[name=message]\').value=\'Resting comfortably. No concerns at this time. Will continue to monitor.\'" class="btn btn-secondary btn-sm">😴 Resting well</button></div></div><div style="display:flex;gap:12px"><button type="submit" class="btn btn-primary">Send Message</button><a href="/family" class="btn btn-secondary">Cancel</a></div></form></div>', req.user, 'family'));
});

app.post('/family/messages', requireAuth, requireRole('owner', 'admin'), (req, res) => {
  const { resident_id, recipient_type, message_type, message } = req.body;
  db.prepare('INSERT INTO family_messages (home_id, resident_id, message, message_type, recipient_type, sent_by) VALUES (?, ?, ?, ?, ?, ?)').run(req.home.id, resident_id||null, message, message_type, recipient_type, req.user.name);
  logAudit(req.user.id, req.user.name, req.home.id, 'MESSAGE_SENT', 'message', null, { recipient_type, message_type });
  res.redirect('/family');
});

// ============================================
// INSPECTION CHECKLIST
// ============================================
app.get('/inspection', requireAuth, requireRole('owner', 'admin'), (req, res) => {
  const items = db.prepare('SELECT * FROM inspection_items WHERE home_id = ? ORDER BY category, item').all(req.home?.id || 0);
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
  const item = db.prepare('SELECT * FROM inspection_items WHERE id = ?').get(item_id);
  if (!item) return res.redirect('/inspection');
  const newStatus = item.status === 'complete' ? 'pending' : 'complete';
  if (newStatus === 'complete') {
    db.prepare('UPDATE inspection_items SET status = ?, verified_by = ?, verified_at = datetime("now") WHERE id = ?').run(newStatus, req.user.name, item_id);
  } else {
    db.prepare('UPDATE inspection_items SET status = ?, verified_by = NULL, verified_at = NULL WHERE id = ?').run(newStatus, item_id);
  }
  res.redirect('/inspection');
});

// ============================================
// START SERVER
// ============================================
const PORT = process.env.PORT || 3001;
app.listen(PORT, () => {
  console.log('');
  console.log('╔═══════════════════════════════════════════════╗');
  console.log('║     🏠 AFH Complete v3.0 is running!          ║');
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
  console.log('╚═══════════════════════════════════════════════╝');
  console.log('');
});
