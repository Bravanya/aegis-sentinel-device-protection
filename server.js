/* Aegis Sentinel — dependency-free real-time SOC portfolio platform.
 * Accounts, sessions, contact messages, and server-sent telemetry are real.
 * All cybersecurity telemetry and response actions are safe simulations.
 * Requires Node.js 22.5+ for the built-in node:sqlite module. */
const path = require('node:path');
const fs = require('node:fs');
const http = require('node:http');
const tls = require('node:tls');
const crypto = require('node:crypto');
const { promisify } = require('node:util');
const { DatabaseSync } = require('node:sqlite');

function loadEnvFile(filename = path.join(__dirname, '.env')) {
  if (!fs.existsSync(filename)) return;
  for (const raw of fs.readFileSync(filename, 'utf8').split(/\r?\n/)) {
    const line = raw.trim();
    if (!line || line.startsWith('#')) continue;
    const separator = line.indexOf('=');
    if (separator < 1) continue;
    const key = line.slice(0, separator).trim();
    const value = line.slice(separator + 1).trim().replace(/^['"]|['"]$/g, '');
    if (!process.env[key]) process.env[key] = value;
  }
}
loadEnvFile();

const PORT = Number(process.env.PORT || 3000);
const NODE_ENV = process.env.NODE_ENV || 'development';
const DATA_DIR = path.resolve(process.env.DATA_DIR || path.join(__dirname, 'data'));
const SESSION_DAYS = Number(process.env.SESSION_DAYS || 7);
const SITE_OWNER_NAME = process.env.SITE_OWNER_NAME || 'Bravanya Mohawannan';
const CONTACT_EMAIL = process.env.CONTACT_EMAIL || 'mohanbravanya15@gmail.com';
const CONTACT_PHONE_PRIMARY = process.env.CONTACT_PHONE_PRIMARY || '+94 729412345';
const CONTACT_PHONE_SECONDARY = process.env.CONTACT_PHONE_SECONDARY || '+94 721509250';
const GMAIL_USER = String(process.env.GMAIL_USER || '').trim();
const GMAIL_APP_PASSWORD = String(process.env.GMAIL_APP_PASSWORD || '').replace(/\s+/g, '');
const GMAIL_RECIPIENT = String(process.env.GMAIL_RECIPIENT || CONTACT_EMAIL).trim();
const GMAIL_CONFIGURED = Boolean(GMAIL_USER && GMAIL_APP_PASSWORD && GMAIL_RECIPIENT && !GMAIL_APP_PASSWORD.includes('PASTE_'));
const APP_LINKEDIN_URL = process.env.APP_LINKEDIN_URL || 'https://www.linkedin.com/in/bravanya-mohawannan/';
const APP_LINKEDIN_LABEL = process.env.APP_LINKEDIN_LABEL || 'Bravanya Mohawannan on LinkedIn';
const ADMIN_EMAIL = String(process.env.ADMIN_EMAIL || 'mohanbravanya15@gmail.com').trim().toLowerCase();
const PUBLIC_DIR = path.join(__dirname, 'public');

fs.mkdirSync(DATA_DIR, { recursive: true });
const db = new DatabaseSync(path.join(DATA_DIR, 'aegis-sentinel.sqlite'));
db.exec(`
  PRAGMA journal_mode = WAL;
  PRAGMA foreign_keys = ON;
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    email TEXT NOT NULL UNIQUE,
    role TEXT NOT NULL DEFAULT 'SOC Analyst',
    password_hash TEXT NOT NULL,
    is_admin INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL
  );
  CREATE TABLE IF NOT EXISTS sessions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    token_hash TEXT NOT NULL UNIQUE,
    user_id INTEGER NOT NULL,
    expires_at TEXT NOT NULL,
    created_at TEXT NOT NULL,
    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
  );
  CREATE TABLE IF NOT EXISTS contact_messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    email TEXT NOT NULL,
    subject TEXT NOT NULL,
    message TEXT NOT NULL,
    user_id INTEGER,
    created_at TEXT NOT NULL,
    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE SET NULL
  );
  CREATE TABLE IF NOT EXISTS audit_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    action_type TEXT NOT NULL,
    details_json TEXT NOT NULL,
    created_at TEXT NOT NULL,
    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE SET NULL
  );
`);

const scrypt = promisify(crypto.scrypt);
const now = () => new Date().toISOString();
const tokenHash = token => crypto.createHash('sha256').update(token).digest('hex');
const clean = (value, limit) => String(value || '').trim().replace(/\s+/g, ' ').slice(0, limit);
const cleanMessage = (value, limit) => String(value || '').trim().slice(0, limit);
const safeUser = row => row ? ({ id: row.id, name: row.name, email: row.email, role: row.role, isAdmin: Boolean(row.is_admin), createdAt: row.created_at }) : null;

async function hashPassword(password) {
  const salt = crypto.randomBytes(16).toString('hex');
  const derived = await scrypt(password, salt, 64);
  return `${salt}:${Buffer.from(derived).toString('hex')}`;
}
async function verifyPassword(password, stored) {
  const [salt, expected] = String(stored || '').split(':');
  if (!salt || !expected) return false;
  const actual = Buffer.from(await scrypt(password, salt, 64));
  const expectedBuffer = Buffer.from(expected, 'hex');
  return expectedBuffer.length === actual.length && crypto.timingSafeEqual(expectedBuffer, actual);
}
function parseCookies(header = '') {
  return Object.fromEntries(String(header).split(';').map(part => {
    const index = part.indexOf('=');
    return index === -1 ? [] : [decodeURIComponent(part.slice(0, index).trim()), decodeURIComponent(part.slice(index + 1).trim())];
  }).filter(pair => pair.length));
}
function getSessionFromCookie(cookieHeader) {
  const token = parseCookies(cookieHeader).aegis_sid;
  if (!token) return null;
  const row = db.prepare(`SELECT users.* FROM sessions JOIN users ON users.id = sessions.user_id WHERE sessions.token_hash = ? AND sessions.expires_at > ?`).get(tokenHash(token), now());
  return row ? { token, user: safeUser(row) } : null;
}
function createSession(userId) {
  const raw = crypto.randomBytes(36).toString('base64url');
  const expires = new Date(Date.now() + SESSION_DAYS * 86_400_000).toISOString();
  db.prepare('INSERT INTO sessions (token_hash, user_id, expires_at, created_at) VALUES (?, ?, ?, ?)').run(tokenHash(raw), userId, expires, now());
  return { raw, expires };
}
function sessionCookie(token) {
  return `aegis_sid=${encodeURIComponent(token)}; HttpOnly; Path=/; SameSite=Lax; Max-Age=${SESSION_DAYS * 86400}${NODE_ENV === 'production' ? '; Secure' : ''}`;
}
function clearCookie() {
  return `aegis_sid=; HttpOnly; Path=/; SameSite=Lax; Max-Age=0${NODE_ENV === 'production' ? '; Secure' : ''}`;
}
function cleanupSessions() { db.prepare('DELETE FROM sessions WHERE expires_at <= ?').run(now()); }
function clientIp(req) { return String(req.headers['x-forwarded-for'] || '').split(',')[0].trim() || req.socket.remoteAddress || 'unknown'; }
function json(res, status, payload, extraHeaders={}) {
  res.writeHead(status, {
    'Content-Type':'application/json; charset=utf-8',
    'Cache-Control':'no-store',
    ...extraHeaders,
  });
  res.end(JSON.stringify(payload));
}
function noContent(res, status=204, extraHeaders={}) { res.writeHead(status, extraHeaders); res.end(); }
function securityHeaders(res) {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  res.setHeader('Cross-Origin-Opener-Policy', 'same-origin');
}
function sameOrigin(req) {
  if (['GET','HEAD','OPTIONS'].includes(req.method)) return true;
  const origin = req.headers.origin;
  if (!origin) return true;
  try { return new URL(origin).host === req.headers.host; } catch { return false; }
}
function smtpResponseCode(lines) {
  const line = Array.isArray(lines) ? lines[lines.length - 1] : String(lines || '');
  return Number(String(line).slice(0, 3));
}
function smtpText(lines) { return Array.isArray(lines) ? lines.join(' | ') : String(lines || ''); }
function smtpDataSafe(value) { return String(value || '').replace(/\r?\n/g, '\r\n').replace(/^\./gm, '..'); }
function smtpHeaderSafe(value) { return String(value || '').replace(/[\r\n]+/g, ' ').replace(/[^\x20-\x7E]/g, '').slice(0, 180); }
function deliverContactEmail({ name, email, subject, message }) {
  if (!GMAIL_CONFIGURED) return Promise.resolve({ delivered:false, configured:false });
  return new Promise((resolve, reject) => {
    const socket = tls.connect({ host:'smtp.gmail.com', port:465, servername:'smtp.gmail.com', timeout:15_000 });
    let buffer = ''; let current = []; const waiting = []; const completed = [];
    const failAll = error => { while (waiting.length) waiting.shift().reject(error); };
    const nextResponse = () => new Promise((resolveResponse, rejectResponse) => {
      if (completed.length) return resolveResponse(completed.shift());
      waiting.push({ resolve:resolveResponse, reject:rejectResponse });
    });
    const pushResponse = lines => { const waiter = waiting.shift(); if (waiter) waiter.resolve(lines); else completed.push(lines); };
    const expect = async (command, expectedCodes) => {
      const pending = nextResponse(); socket.write(command + '\r\n');
      const lines = await pending; const code = smtpResponseCode(lines);
      if (!expectedCodes.includes(code)) throw new Error(`SMTP ${code || 'error'}: ${smtpText(lines)}`);
      return lines;
    };
    socket.setEncoding('utf8');
    socket.on('data', chunk => {
      buffer += chunk;
      while (buffer.includes('\r\n')) {
        const index = buffer.indexOf('\r\n'); const line = buffer.slice(0,index); buffer = buffer.slice(index+2);
        current.push(line);
        if (/^\d{3} /.test(line)) { const lines = current; current = []; pushResponse(lines); }
      }
    });
    socket.on('timeout', () => socket.destroy(new Error('Gmail SMTP connection timed out.')));
    socket.on('error', error => { failAll(error); reject(error); });
    socket.on('secureConnect', async () => {
      try {
        let lines = await nextResponse();
        if (smtpResponseCode(lines) !== 220) throw new Error(`SMTP greeting failed: ${smtpText(lines)}`);
        await expect('EHLO aegis-sentinel.local', [250]);
        await expect('AUTH LOGIN', [334]);
        await expect(Buffer.from(GMAIL_USER, 'utf8').toString('base64'), [334]);
        await expect(Buffer.from(GMAIL_APP_PASSWORD, 'utf8').toString('base64'), [235]);
        await expect(`MAIL FROM:<${GMAIL_USER}>`, [250]);
        await expect(`RCPT TO:<${GMAIL_RECIPIENT}>`, [250, 251]);
        await expect('DATA', [354]);
        const body = [
          `From: "Aegis Sentinel Contact" <${GMAIL_USER}>`,
          `To: <${GMAIL_RECIPIENT}>`,
          `Reply-To: <${email}>`,
          `Subject: [Aegis Contact] ${smtpHeaderSafe(subject)}`,
          'MIME-Version: 1.0',
          'Content-Type: text/plain; charset=UTF-8',
          '',
          'A contact message was submitted through Aegis Sentinel.',
          '',
          `Name: ${smtpHeaderSafe(name)}`,
          `Email: ${smtpHeaderSafe(email)}`,
          `Subject: ${smtpHeaderSafe(subject)}`,
          '',
          smtpDataSafe(message),
          '',
          `Received (UTC): ${now()}`,
        ].join('\r\n');
        const pending = nextResponse(); socket.write(body + '\r\n.\r\n');
        lines = await pending;
        if (smtpResponseCode(lines) !== 250) throw new Error(`SMTP delivery failed: ${smtpText(lines)}`);
        try { await expect('QUIT', [221]); } catch { /* connection is already usable; ignore quit failure */ }
        socket.end(); resolve({ delivered:true, configured:true });
      } catch (error) { socket.destroy(); reject(error); }
    });
  });
}

function readJson(req, limit=32_768) {
  return new Promise((resolve, reject) => {
    let total = 0; const chunks = [];
    req.on('data', chunk => {
      total += chunk.length;
      if (total > limit) { reject(Object.assign(new Error('Request body is too large.'), { status:413 })); req.destroy(); return; }
      chunks.push(chunk);
    });
    req.on('end', () => {
      if (!chunks.length) return resolve({});
      try { resolve(JSON.parse(Buffer.concat(chunks).toString('utf8'))); }
      catch { reject(Object.assign(new Error('Request body must contain valid JSON.'), { status:400 })); }
    });
    req.on('error', reject);
  });
}

const windows = new Map();
function allowRequest(key, max, duration=15*60_000) {
  const current = windows.get(key) || { count:0, reset:Date.now()+duration };
  if (Date.now() > current.reset) { current.count=0; current.reset=Date.now()+duration; }
  current.count += 1; windows.set(key, current);
  return current.count <= max;
}
function requireAuth(req, res) {
  const session = getSessionFromCookie(req.headers.cookie);
  if (!session) { json(res, 401, { error:'Please sign in to continue.' }); return null; }
  return session;
}
function requireAdmin(req, res) {
  const session = requireAuth(req, res);
  if (!session) return null;
  if (!session.user.isAdmin) { json(res, 403, { error:'Administrator access is required.' }); return null; }
  return session;
}

const sseClients = new Set();
function emitSSE(event, payload) {
  const message = `event: ${event}\ndata: ${JSON.stringify(payload)}\n\n`;
  for (const client of [...sseClients]) {
    if (client.writableEnded || client.destroyed) sseClients.delete(client);
    else client.write(message);
  }
}
function startSSE(req, res, session) {
  res.writeHead(200, {
    'Content-Type':'text/event-stream; charset=utf-8',
    'Cache-Control':'no-cache, no-transform',
    'Connection':'keep-alive',
    'X-Accel-Buffering':'no',
  });
  res.write(': connected\n\n');
  res.write(`event: telemetry:bootstrap\ndata: ${JSON.stringify({ metrics:metricSnapshot(), events:[freshEvent(),freshEvent(),freshEvent()] })}\n\n`);
  sseClients.add(res);
  const heartbeat = setInterval(() => { if (!res.writableEnded) res.write(': ping\n\n'); }, 20_000);
  req.on('close', () => { clearInterval(heartbeat); sseClients.delete(res); });
}

const mime = {
  '.html':'text/html; charset=utf-8', '.css':'text/css; charset=utf-8', '.js':'text/javascript; charset=utf-8',
  '.svg':'image/svg+xml', '.png':'image/png', '.jpg':'image/jpeg', '.jpeg':'image/jpeg', '.webp':'image/webp',
  '.ico':'image/x-icon', '.json':'application/json; charset=utf-8', '.txt':'text/plain; charset=utf-8'
};
function serveStatic(req, res, pathname) {
  const requested = pathname === '/' ? '/index.html' : pathname;
  const absolute = path.resolve(PUBLIC_DIR, '.' + requested);
  if (!absolute.startsWith(PUBLIC_DIR + path.sep) && absolute !== path.join(PUBLIC_DIR, 'index.html')) {
    json(res, 403, { error:'Forbidden' }); return;
  }
  fs.stat(absolute, (err, stat) => {
    if (err || !stat.isFile()) { json(res, 404, { error:'Not found' }); return; }
    const ext = path.extname(absolute).toLowerCase();
    res.writeHead(200, { 'Content-Type':mime[ext] || 'application/octet-stream', 'Cache-Control': ext === '.html' ? 'no-cache' : 'public, max-age=3600' });
    if (req.method === 'HEAD') return res.end();
    fs.createReadStream(absolute).pipe(res);
  });
}

const state = { eventsProcessed:2_840_000_000, activeIncidents:12, threatsDisrupted:48_291, protectedAssets:243, exposureScore:34, blockedFlows:4_821, ingestRate:128_400, riskScore:72 };
const eventTemplates = [
  ['critical','Privilege escalation chain','idp-prod-02','T1078 · Valid Accounts','INC-2048'],
  ['high','Suspicious cloud API enumeration','aws-prod-billing','T1528 · Cloud Accounts','INC-2041'],
  ['critical','Rapid file encryption behavior','fin-ws-047','T1486 · Data Encrypted','INC-2046'],
  ['high','Encoded PowerShell execution','eng-lt-112','T1059.001 · PowerShell','INC-2038'],
  ['medium','Internet-facing service scan','vpn-gw-01','T1595 · Active Scanning','INC-2031'],
  ['low','New device enrollment observed','mktg-tenant','T1098 · Account Manipulation','INC-2022'],
];
function freshEvent() { const e = eventTemplates[Math.floor(Math.random()*eventTemplates.length)]; return { severity:e[0], detection:e[1], entity:e[2], mitre:e[3], incident:e[4], time:'just now' }; }
function metricSnapshot() { return { ...state }; }

async function handler(req, res) {
  securityHeaders(res);
  if (!sameOrigin(req)) return json(res, 403, { error:'Cross-site requests are not allowed.' });
  if (req.method === 'OPTIONS') return noContent(res, 204, { Allow:'GET, HEAD, POST, OPTIONS' });
  const url = new URL(req.url, `http://${req.headers.host || 'localhost'}`);
  const pathname = decodeURIComponent(url.pathname);

  try {
    if (req.method === 'GET' && pathname === '/api/health') return json(res, 200, { ok:true, service:'aegis-sentinel-realtime', time:now() });
    if (req.method === 'GET' && pathname === '/api/public/config') return json(res, 200, { ownerName:SITE_OWNER_NAME, contactEmail:CONTACT_EMAIL, contactPhonePrimary:CONTACT_PHONE_PRIMARY, contactPhoneSecondary:CONTACT_PHONE_SECONDARY, linkedinUrl:APP_LINKEDIN_URL, linkedinLabel:APP_LINKEDIN_LABEL, emailDeliveryConfigured:GMAIL_CONFIGURED });
    if (req.method === 'GET' && pathname === '/api/auth/me') {
      const session = getSessionFromCookie(req.headers.cookie);
      return json(res, 200, { user:session?.user || null });
    }
    if (req.method === 'GET' && pathname === '/api/telemetry/stream') {
      const session = requireAuth(req, res);
      if (!session) return;
      return startSSE(req, res, session);
    }
    if (req.method === 'POST' && pathname === '/api/auth/register') {
      if (!allowRequest(`auth:${clientIp(req)}`, 25)) return json(res, 429, { error:'Too many account requests. Please wait 15 minutes and try again.' });
      const body = await readJson(req);
      const name = clean(body.name, 80);
      const email = clean(body.email, 160).toLowerCase();
      const role = ['SOC Analyst','Threat Hunter','Security Manager'].includes(body.role) ? body.role : 'SOC Analyst';
      const password = String(body.password || '');
      if (name.length < 2) return json(res, 400, { error:'Enter a name with at least 2 characters.' });
      if (!/^\S+@\S+\.\S+$/.test(email)) return json(res, 400, { error:'Enter a valid email address.' });
      if (password.length < 8 || password.length > 256) return json(res, 400, { error:'Use a password between 8 and 256 characters.' });
      if (db.prepare('SELECT id FROM users WHERE email = ?').get(email)) return json(res, 409, { error:'An account already exists for this email address. Please sign in.' });
      const passwordHash = await hashPassword(password);
      const isAdmin = ADMIN_EMAIL && email === ADMIN_EMAIL ? 1 : 0;
      const result = db.prepare('INSERT INTO users (name, email, role, password_hash, is_admin, created_at) VALUES (?, ?, ?, ?, ?, ?)').run(name, email, role, passwordHash, isAdmin, now());
      const row = db.prepare('SELECT * FROM users WHERE id = ?').get(result.lastInsertRowid);
      const session = createSession(row.id);
      return json(res, 201, { user:safeUser(row) }, { 'Set-Cookie':sessionCookie(session.raw) });
    }
    if (req.method === 'POST' && pathname === '/api/auth/login') {
      if (!allowRequest(`auth:${clientIp(req)}`, 25)) return json(res, 429, { error:'Too many account requests. Please wait 15 minutes and try again.' });
      const body = await readJson(req);
      const email = clean(body.email, 160).toLowerCase();
      const password = String(body.password || '');
      const row = db.prepare('SELECT * FROM users WHERE email = ?').get(email);
      if (!row || !(await verifyPassword(password, row.password_hash))) return json(res, 401, { error:'Email or password was not accepted.' });
      const session = createSession(row.id);
      return json(res, 200, { user:safeUser(row) }, { 'Set-Cookie':sessionCookie(session.raw) });
    }
    if (req.method === 'POST' && pathname === '/api/auth/demo-login') {
      if (!allowRequest(`auth:${clientIp(req)}`, 25)) return json(res, 429, { error:'Too many account requests. Please wait 15 minutes and try again.' });
      const row = db.prepare('SELECT * FROM users WHERE email = ?').get('demo@aegis.local');
      if (!row) return json(res, 503, { error:'The demo workspace is initializing. Please retry in a moment.' });
      const session = createSession(row.id);
      return json(res, 200, { user:safeUser(row) }, { 'Set-Cookie':sessionCookie(session.raw) });
    }
    if (req.method === 'POST' && pathname === '/api/auth/logout') {
      const session = requireAuth(req, res);
      if (!session) return;
      db.prepare('DELETE FROM sessions WHERE token_hash = ?').run(tokenHash(session.token));
      return json(res, 200, { ok:true }, { 'Set-Cookie':clearCookie() });
    }
    if (req.method === 'POST' && pathname === '/api/contact') {
      if (!allowRequest(`contact:${clientIp(req)}`, 8)) return json(res, 429, { error:'Too many messages from this address. Please try again later.' });
      const body = await readJson(req);
      const session = getSessionFromCookie(req.headers.cookie);
      const name = clean(body.name, 80), email = clean(body.email, 160).toLowerCase();
      const subject = clean(body.subject, 140), message = cleanMessage(body.message, 2000);
      if (name.length < 2 || !/^\S+@\S+\.\S+$/.test(email) || subject.length < 3 || message.length < 10) return json(res, 400, { error:'Complete the name, email, subject, and a message of at least 10 characters.' });
      db.prepare('INSERT INTO contact_messages (name, email, subject, message, user_id, created_at) VALUES (?, ?, ?, ?, ?, ?)').run(name, email, subject, message, session?.user?.id || null, now());
      let emailDelivery = { delivered:false, configured:GMAIL_CONFIGURED };
      if (emailDelivery.configured) {
        try { emailDelivery = await deliverContactEmail({ name, email, subject, message }); }
        catch (mailError) { console.error('[gmail delivery]', mailError.message); }
      }
      return json(res, 201, { ok:true, message:'Your message was received.', emailDelivery });
    }
    if (req.method === 'POST' && pathname === '/api/simulations/action') {
      const session = requireAuth(req, res);
      if (!session) return;
      const body = await readJson(req);
      const type = clean(body.type, 80);
      const details = body.details && typeof body.details === 'object' ? body.details : {};
      if (!type) return json(res, 400, { error:'An action type is required.' });
      db.prepare('INSERT INTO audit_logs (user_id, action_type, details_json, created_at) VALUES (?, ?, ?, ?)').run(session.user.id, type, JSON.stringify(details).slice(0,4000), now());
      const entry = { actor:session.user.name, type, details, time:now() };
      emitSSE('simulation:action', entry);
      return json(res, 200, { ok:true });
    }
    if (req.method === 'GET' && pathname === '/api/admin/messages') {
      const session = requireAdmin(req, res); if (!session) return;
      const messages = db.prepare('SELECT id, name, email, subject, message, created_at FROM contact_messages ORDER BY id DESC LIMIT 100').all();
      return json(res, 200, { messages });
    }
    if (req.method === 'GET' && pathname === '/api/admin/audit') {
      const session = requireAdmin(req, res); if (!session) return;
      const logs = db.prepare('SELECT audit_logs.id, users.name AS actor, action_type, details_json, audit_logs.created_at FROM audit_logs LEFT JOIN users ON users.id = audit_logs.user_id ORDER BY audit_logs.id DESC LIMIT 100').all();
      return json(res, 200, { logs });
    }
    if (req.method === 'GET' || req.method === 'HEAD') return serveStatic(req, res, pathname);
    return json(res, 404, { error:'Not found' });
  } catch (error) {
    console.error('[server]', error);
    return json(res, error?.status || 500, { error:error?.status ? error.message : 'The server encountered an unexpected problem.' });
  }
}

async function seedDemoUser() {
  const email = 'demo@aegis.local';
  if (db.prepare('SELECT id FROM users WHERE email = ?').get(email)) return;
  const passwordHash = await hashPassword('Demo@123');
  db.prepare('INSERT INTO users (name, email, role, password_hash, is_admin, created_at) VALUES (?, ?, ?, ?, ?, ?)').run('Aegis Analyst', email, 'SOC Analyst', passwordHash, 1, now());
}

setInterval(() => {
  state.eventsProcessed += Math.floor(Math.random()*190_000) + 80_000;
  state.threatsDisrupted += Math.floor(Math.random()*8) + 1;
  state.blockedFlows = Math.max(4_500, state.blockedFlows + Math.floor(Math.random()*70) - 28);
  state.ingestRate = Math.max(90_000, 128_000 + Math.floor(Math.random()*31_000) - 15_000);
  state.riskScore = Math.max(60, Math.min(89, state.riskScore + Math.floor(Math.random()*5) - 2));
  state.exposureScore = Math.max(28, Math.min(42, state.exposureScore + Math.floor(Math.random()*3) - 1));
  emitSSE('telemetry:metrics', metricSnapshot());
  if (Math.random() > 0.28) emitSSE('telemetry:event', freshEvent());
}, 4_000);
setInterval(cleanupSessions, 3_600_000).unref();

seedDemoUser().then(() => {
  http.createServer(handler).listen(PORT, '0.0.0.0', () => {
    console.log(`Aegis Sentinel is running at http://localhost:${PORT}`);
    console.log('No npm installation is required for this edition.');
  });
}).catch(error => {
  console.error('Unable to initialize the database:', error);
  process.exit(1);
});
