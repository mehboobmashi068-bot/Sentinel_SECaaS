import 'dotenv/config';
import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import { exec } from 'child_process';
import { createServer as createViteServer } from 'vite';
import path from 'path';
import { fileURLToPath } from 'url';
import { WebSocketServer, WebSocket } from 'ws';
import http from 'http';
import Database from 'better-sqlite3';
import CryptoJS from 'crypto-js';
import fs from 'fs';
import readline from 'readline';
import { performance } from 'perf_hooks';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const DB_NAME = "ThreatVault.db";

// Security Config
const ADMIN_API_KEY = process.env.ADMIN_API_KEY || 'sk_master_777_sentinel';
const DB_KEY = process.env.SENTINEL_DB_ENCRYPTION_KEY || 'SENTINEL_VAULT_ENCRYPTION_X';

// --- Global Network State ---
let eth0Status = 'UP';
let interfaces = [
  { name: 'eth0', ip: '172.16.0.42', mac: '00:15:5d:01:af:09', status: 'UP', rx_packets: 124502, tx_packets: 98402, speed: '1 Gbps' },
  { name: 'wlan0', ip: '192.168.1.15', mac: 'e4:a7:a0:84:32:11', status: 'UP', rx_packets: 4521, tx_packets: 1205, speed: '300 Mbps' },
  { name: 'tun0', ip: '10.8.0.12', mac: '00:00:00:00:00:00', status: 'UP', rx_packets: 54291, tx_packets: 42103, speed: '100 Mbps' },
  { name: 'vboxnet0', ip: '192.168.56.1', mac: '0a:00:27:00:00:00', status: 'UP', rx_packets: 821, tx_packets: 212, speed: '10 Gbps' }
];

// Encryption Helper
const encrypt = (text: string) => CryptoJS.AES.encrypt(text, DB_KEY).toString();
const decrypt = (ciphertext: string) => {
  try {
    const bytes = CryptoJS.AES.decrypt(ciphertext, DB_KEY);
    return bytes.toString(CryptoJS.enc.Utf8);
  } catch (e) {
    return ciphertext; // Fallback if not encrypted
  }
};

const hashPassword = (password: string) => CryptoJS.SHA256(password).toString();

// Initialize database
let db: Database.Database;

function initializeDatabase() {
  try {
    console.log("[ DB ] Connecting to ThreatVault...");
    db = new Database(DB_NAME);
    db.exec(`
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            security_password TEXT,
            api_key TEXT
        );
        CREATE TABLE IF NOT EXISTS Authorized_Clients (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            api_key TEXT UNIQUE NOT NULL,
            client_name TEXT NOT NULL,
            date_created DATETIME DEFAULT CURRENT_TIMESTAMP
        );
        CREATE TABLE IF NOT EXISTS Risk_Registry (
            identifier TEXT PRIMARY KEY, 
            cumulative_score INTEGER DEFAULT 0,
            is_banned INTEGER DEFAULT 0,
            last_seen INTEGER,
            type TEXT DEFAULT 'IP'
        );
        CREATE TABLE IF NOT EXISTS Deception_Logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            identifier TEXT,
            payload TEXT,
            path TEXT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        );
        CREATE TABLE IF NOT EXISTS Key_Requests (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            client_name TEXT NOT NULL,
            status TEXT DEFAULT 'PENDING',
            date_requested DATETIME DEFAULT CURRENT_TIMESTAMP
        );
        CREATE TABLE IF NOT EXISTS System_Config (
            id INTEGER PRIMARY KEY CHECK (id = 1),
            is_active INTEGER DEFAULT 1,
            system_lock INTEGER DEFAULT 0
        );
    `);

    // Migrations to ensure columns exist
    const migrations = [
      "ALTER TABLE System_Config ADD COLUMN is_active INTEGER DEFAULT 1",
      "ALTER TABLE System_Config ADD COLUMN system_lock INTEGER DEFAULT 0",
      "ALTER TABLE users ADD COLUMN security_password TEXT",
      "ALTER TABLE users ADD COLUMN api_key TEXT",
      "ALTER TABLE users RENAME COLUMN email TO username"
    ];

    for (const sql of migrations) {
      try {
        db.exec(sql);
      } catch (e) {
        // Ignore "duplicate column name" errors
      }
    }

    // Now safe to insert/update config
    try {
        db.exec(`INSERT OR IGNORE INTO System_Config (id, is_active, system_lock) VALUES (1, 1, 0)`);
    } catch (e) {
        console.error("[ DB ] Config sync error:", e);
    }

    console.log("[ DB ] ThreatVault.db connected and schema verified.");
  } catch (err: any) {
    console.error("[ DB ] Database initialization error:", err);
  }

  // Ensure Admin Key and Default User are registered
  if (db) {
    try {
      // Register Admin Key
      const encryptedAdminKey = encrypt(ADMIN_API_KEY);
      db.prepare('INSERT OR IGNORE INTO Authorized_Clients (api_key, client_name) VALUES (?, ?)').run(encryptedAdminKey, 'Sentinel Core Admin');
      console.log("[ DB ] Core admin key verified.");

      // Register Default Emergency User if none exists or update if missing password
      const adminUser = db.prepare('SELECT * FROM users WHERE username = ?').get('admin') as any;
      if (!adminUser) {
        const defaultPass = hashPassword('samegill9091');
        db.prepare('INSERT INTO users (username, security_password) VALUES (?, ?)').run('admin', defaultPass);
        console.log("[ DB ] Initial emergency protocols established.");
      } else if (!adminUser.security_password) {
        const defaultPass = hashPassword('samegill9091');
        db.prepare('UPDATE users SET security_password = ? WHERE username = ?').run(defaultPass, 'admin');
        console.log("[ DB ] Security protocols restored for existing admin.");
      }
    } catch (e) {
      console.error("[ DB ] Failed to register core admin protocols:", e);
    }
  }
}

initializeDatabase();

// Global broadcast function (hoisted usage)
let broadcast = (data: any) => {};
let globalWss: WebSocketServer | null = null;

async function startServer() {
  console.log("[ BOOT ] Initializing Express application...");
  
  const app = express();
  const PORT = 3000;
  app.set('trust proxy', 1);
  const server = http.createServer(app);
  const wss = new WebSocketServer({ 
    noServer: true,
    path: '/ws'
  });
  globalWss = wss;

  app.use(helmet({ contentSecurityPolicy: false }));
  app.use(cors());
  app.use(express.json());
  app.use(express.urlencoded({ extended: true }));

  // --- API Router ---
  const apiRouter = express.Router();

  // --- Request Logger for Debugging ---
  app.use((req, res, next) => {
    console.log(`[ ALL ] ${req.method} ${req.path} (Accept: ${req.headers.accept})`);
    if (req.path.startsWith('/api')) {
      console.log(`[ INCOMING ] ${req.method} ${req.path}`);
    }
    next();
  });

  // Mount API router early
  app.use('/api', apiRouter);

  // --- Middleware Definitions ---
  const validateApiKey = (req: express.Request, res: express.Response, next: express.NextFunction) => {
    const key = req.headers['x-api-key'] as string;
    if (!key) return res.status(401).json({ error: 'MISSING_API_KEY', message: 'Authentication required.' });
    const allClients = db.prepare('SELECT api_key FROM Authorized_Clients').all() as { api_key: string }[];
    const client = allClients.find(c => decrypt(c.api_key) === key);
    if (!client) return res.status(401).json({ error: 'INVALID_API_KEY' });
    next();
  };

  const validateMasterSignature = (req: express.Request, res: express.Response, next: express.NextFunction) => {
    const sig = (req.headers['x-sentinel-signature'] || req.headers['x-master-signature'] || req.body.password) as string;
    const apiKey = (req.headers['x-api-key'] || req.body.apiKey) as string;
    if (!apiKey) return res.status(401).json({ error: 'MISSING_API_KEY' });
    const isMasterKey = apiKey === ADMIN_API_KEY || apiKey === 'sk_master_777_sentinel';
    if (!isMasterKey) {
        const allClients = db.prepare('SELECT api_key FROM Authorized_Clients').all() as { api_key: string }[];
        if (!allClients.some(c => decrypt(c.api_key) === apiKey)) return res.status(401).json({ error: 'INVALID_API_KEY' });
    }
    const targetUser = (req.body.username || 'admin').toLowerCase();
    const user = db.prepare('SELECT security_password FROM users WHERE LOWER(username) = ?').get(targetUser) as any;
    if (!user?.security_password) return res.status(403).json({ error: 'SEC_PASS_NOT_SET' });
    if (sig && hashPassword(sig) === user.security_password) return next();
    if (req.method === 'GET') return next();
    return res.status(401).json({ error: 'VERIFICATION_FAILED' });
  };

  const lockdownCheck = (req: express.Request, res: express.Response, next: express.NextFunction) => {
    try {
      const allowed = ['/system/status', '/system/config-status', '/v1/system/unlock', '/auth/login', '/auth/register'];
      if (allowed.some(p => req.path.startsWith(p))) return next();
      const config = db.prepare('SELECT system_lock FROM System_Config WHERE id = 1').get() as { system_lock: number } | undefined;
      if (config?.system_lock) return res.status(503).json({ error: 'SYSTEM_LOCKED' });
      next();
    } catch (err) {
      console.error("[ LOCKDOWN_CHECK_ERR ]", err);
      next();
    }
  };

  // --- API Router Configuration ---
  apiRouter.use(lockdownCheck);
  
  apiRouter.all('*', (req, res, next) => {
    console.log(`[ API_ROUTER ] ${req.method} ${req.path} (Full: ${req.originalUrl})`);
    next();
  });

  apiRouter.get('/network/status', (req, res) => {
    console.log(`[ API ] Serving network status to ${req.ip}`);
    return res.json({ eth0: eth0Status, interfaces });
  });

  apiRouter.get('/health', (req, res) => {
    return res.json({ status: 'active', system: 'Sentinel_SECaaS' });
  });

  apiRouter.get('/system/status', (req, res) => {
    const config = db.prepare('SELECT system_lock FROM System_Config WHERE id = 1').get() as any;
    res.json({ status: config?.system_lock ? 'LOCKED' : 'ACTIVE' });
  });

  apiRouter.post('/auth/register', async (req, res) => {
    let { username, password } = req.body;
    if (!username || !password) return res.status(400).json({ error: 'Username and password required' });
    username = username.trim().toLowerCase();
    
    if (password.length < 8) {
      return res.status(400).json({ error: 'WEAK_PASSWORD', message: 'At least 8 chars required.' });
    }
    
    try {
      const hashedPassword = hashPassword(password);
      const existingUser = db.prepare('SELECT id FROM users WHERE LOWER(username) = ?').get(username) as any;
      if (existingUser) return res.status(409).json({ error: 'USERNAME_TAKEN' });

      const stmt = db.prepare('INSERT INTO users (username, security_password) VALUES (?, ?)');
      const result = stmt.run(username, hashedPassword);
      
      const user = { id: result.lastInsertRowid, username };
      
      res.json({ success: true, user });
      broadcast({ type: 'SYSTEM', msg: `New operative registered: ${username}`, timestamp: Date.now() });
    } catch (err) {
      res.status(500).json({ error: 'DATABASE_ERROR' });
    }
  });

  apiRouter.post('/auth/login', async (req, res) => {
    let { username, password } = req.body;
    if (!username || !password) return res.status(400).json({ error: 'REQD' });
    username = username.trim().toLowerCase();

    try {
      let user = db.prepare('SELECT id, username, security_password FROM users WHERE LOWER(username) = ?').get(username) as any;
      
      if (!user || (user.security_password && user.security_password !== hashPassword(password))) {
        return res.status(401).json({ error: 'AUTH_FAILED' });
      }

      res.json({ success: true, user: { uid: user.id.toString(), username: user.username } });
      broadcast({ type: 'SYSTEM', msg: `Operative linked: ${username}`, timestamp: Date.now() });
    } catch (err) { res.status(500).json({ error: 'DB_ERR' }); }
  });

  apiRouter.get('/system/config-status', (req, res) => {
    const { username } = req.query;
    let query = 'SELECT id FROM users LIMIT 1';
    let params: any[] = [];
    if (username) {
      query = 'SELECT id FROM users WHERE LOWER(username) = ?';
      params = [(username as string).toLowerCase()];
    }
    const user = db.prepare(query).get(...params);
    res.json({ is_configured: !!user });
  });

  apiRouter.post('/system/verify-password', (req, res) => {
    const { password, username } = req.body;
    const user = db.prepare('SELECT security_password FROM users WHERE LOWER(username) = ?').get(username?.toLowerCase() || 'admin') as any;
    if (user && user.security_password === hashPassword(password)) res.json({ success: true });
    else res.status(401).json({ success: false });
  });

  apiRouter.post('/system/update-password', (req, res) => {
    const { password, username } = req.body;
    const normalizedUsername = (username?.toLowerCase() || 'admin').trim();
    
    console.log(`[ API ] Password update request for: ${normalizedUsername}`);
    
    if (!password || password.length < 4) {
      return res.status(400).json({ 
        error: 'SHORT_PASSWORD', 
        message: 'Security password must be at least 4 characters.' 
      });
    }

    try {
      const user = db.prepare('SELECT id FROM users WHERE LOWER(username) = ?').get(normalizedUsername) as any;
      if (user) {
        db.prepare('UPDATE users SET security_password = ? WHERE id = ?').run(hashPassword(password), user.id);
        console.log(`[ API ] Password updated for existing user: ${normalizedUsername}`);
      } else {
        // Allow creating a record if not found (e.g. for guest mode users or initial setup)
        db.prepare('INSERT INTO users (username, security_password) VALUES (?, ?)').run(normalizedUsername, hashPassword(password));
        console.log(`[ API ] New user record initialized for: ${normalizedUsername}`);
      }
      
      res.json({ success: true });
      broadcast({ type: 'SYSTEM', msg: 'SECURITY_PASSWORD_SET', username: normalizedUsername });
    } catch (err: any) {
      console.error("[ API ERR ] /system/update-password:", err);
      res.status(500).json({ 
        error: 'DATABASE_ERROR', 
        message: 'Failed to commit security password to ThreatVault.' 
      });
    }
  });

  apiRouter.post('/network/toggle-interface', (req, res) => {
    const { name } = req.body;
    const iface = interfaces.find(i => i.name === name);
    if (!iface) return res.status(404).json({ error: 'NOT_FOUND' });
    iface.status = iface.status === 'UP' ? 'DOWN' : 'UP';
    if (name === 'eth0') eth0Status = iface.status as any;
    broadcast({ type: 'SYSTEM', msg: `[NETWORK] ${name} -> ${iface.status}`, timestamp: Date.now() });
    res.json({ success: true, status: iface.status });
  });

  apiRouter.post('/analyze', validateApiKey, (req, res) => {
    const ip = (req.headers['x-forwarded-for'] as string)?.split(',')[0] || req.ip || 'unknown';
    const result = analyzeThreats(req.body, ip, req.headers['x-fingerprint'] as string);
    if (result.action === 'BLOCK') return res.status(403).json({ error: 'BLOCKED', report: result });
    res.json(result);
  });

  apiRouter.get('/keys/list', validateMasterSignature, (req, res) => {
    const keys = db.prepare('SELECT api_key, client_name, date_created FROM Authorized_Clients ORDER BY date_created DESC').all() as any[];
    const decryptedKeys = keys.map(k => ({
      ...k,
      api_key: decrypt(k.api_key)
    }));
    res.json(decryptedKeys);
  });

  apiRouter.post('/keys/generate', (req, res) => {
    const { clientName = 'Shield Node ' + Math.floor(Math.random() * 1000), password, username } = req.body;
    if (!password) return res.status(400).json({ error: 'PASS_REQUIRED' });
    const user = db.prepare('SELECT security_password FROM users WHERE LOWER(username) = ?').get(username?.toLowerCase() || 'admin') as any;
    if (!user || user.security_password !== hashPassword(password)) return res.status(401).json({ error: 'AUTH_FAILED' });

    try {
      const key = 'sk_sentinel_' + Math.random().toString(36).substring(2);
      db.prepare('INSERT INTO Authorized_Clients (api_key, client_name) VALUES (?, ?)').run(encrypt(key), clientName);
      broadcast({ type: 'SYSTEM', msg: `[HANDSHAKE] New key authorized for ${clientName}`, timestamp: Date.now() });
      res.json({ status: 'SUCCESS', key, clientName });
    } catch (err) { res.status(500).json({ error: 'DB_ERROR' }); }
  });

  apiRouter.post('/keys/wipe', (req, res) => {
    const { password, username } = req.body;
    if (!password) return res.status(401).json({ error: 'AUTH_REQUIRED' });
    const user = db.prepare('SELECT security_password FROM users WHERE LOWER(username) = ?').get(username?.toLowerCase() || 'admin') as any;
    if (user && user.security_password === hashPassword(password)) {
      db.prepare('DELETE FROM Authorized_Clients').run();
      broadcast({ type: 'SYSTEM', msg: '[CRITICAL] TOTAL_KEY_WIPE initiated.', timestamp: Date.now() });
      res.json({ success: true, message: 'All keys purged.' });
    } else res.status(401).json({ error: 'AUTH_FAILED' });
  });

  apiRouter.get('/v1/mirror/deception-logs', validateMasterSignature, (req, res) => {
    const logs = db.prepare('SELECT * FROM Deception_Logs ORDER BY timestamp DESC LIMIT 100').all() as any[];
    res.json(logs.map(l => ({ ...l, payload: decrypt(l.payload) })));
  });

  apiRouter.post('/v1/critical/kill-switch', validateApiKey, (req, res) => {
    eth0Status = 'DOWN';
    exec('ip link set eth0 down', (error) => {
      broadcast({
        type: 'SYSTEM',
        msg: '[CRITICAL] Emergency Protocol Alpha initiated. All network interfaces CLOSED.',
        timestamp: Date.now()
      });
      res.json({ 
        status: 'SUCCESS', 
        message: 'SYSTEM OFFLINE: Connection Severed.',
        system: error ? 'SOFT_KILL_ONLY' : 'HARD_KILL_SUCCESS'
      });
    });
  });

  apiRouter.get('/v1/mirror/vault', (req, res) => {
    const ip = (req.headers['x-forwarded-for'] as string)?.split(',')[0] || req.ip || 'unknown';
    const fingerprint = req.headers['x-fingerprint'] as string;
    const primaryId = fingerprint || ip;
    db.prepare('INSERT INTO Deception_Logs (identifier, payload, path) VALUES (?, ?, ?)').run(primaryId, encrypt('READ_VAULT'), '/api/v1/mirror/vault');

    res.json({
      status: 'SUCCESS',
      vault_data: [
        { id: 'cc_84221', number: '4532-****-****-1102', cvv: '***', exp: '12/28', bank: 'Global Reserve' },
        { id: 'cc_11204', number: '5105-****-****-9943', cvv: '***', exp: '05/27', bank: 'Federal Trust' },
        { id: 'admin_log_01', entry: 'Failed login attempt from user: root' },
        { id: 'backup_link', url: 'https://cdn.internal-vault.net/backups/db_dump_2026.sql.gz' }
      ]
    });
  });

  apiRouter.get('/v1/mirror/download', (req, res) => {
    const ip = (req.headers['x-forwarded-for'] as string)?.split(',')[0] || req.ip || 'unknown';
    const primaryId = (req.headers['x-fingerprint'] as string) || ip;
    db.prepare('INSERT INTO Deception_Logs (identifier, payload, path) VALUES (?, ?, ?)').run(primaryId, encrypt('DOWNLOAD_BACKUP'), '/api/v1/mirror/download');
    broadcast({ type: 'HONE_HOOKED', msg: `ALERT: Adversary ${primaryId} downloaded poisoned file. Canary Token TRIPPED.`, timestamp: Date.now(), ip });
    res.setHeader('Content-Disposition', 'attachment; filename="db_dump_2026.sql.gz"');
    res.send('-- SENTINEL CANARY TOKEN DETECTED --\n-- DO NOT OPEN IN PRODUCTION --\n# [ CANARY_ID: 88219-X ]\n');
  });

  apiRouter.get('/v1/mirror/assets/:filename', (req, res) => {
    const { filename } = req.params;
    const ip = (req.headers['x-forwarded-for'] as string)?.split(',')[0] || req.ip || 'unknown';
    broadcast({ type: 'HONE_HOOKED', msg: `[ADVERSARY UNMASKED] Filename: ${filename} accessed. Identity Probe initialized.`, unmasked: true });

    if (filename === 'admin_credentials.xlsx') {
      res.setHeader('Content-Type', 'text/csv');
      res.setHeader('Content-Disposition', 'attachment; filename="admin_credentials.xlsx"');
      return res.send("ID,USER,PASS,LAST_LOGIN\n1,root,P@ssw0rd123!,2026-05-01\n2,admin,Sentinel2026,2026-05-02");
    }
    res.status(404).json({ error: 'ASSET_NOT_FOUND' });
  });

  apiRouter.post('/v1/system/kill-signal', validateMasterSignature, (req, res) => {
    db.prepare('UPDATE System_Config SET system_lock = 1 WHERE id = 1').run();
    broadcast({ type: 'SYSTEM', msg: '[CRITICAL] EMERGENCY KILL SIGNAL RECEIVED. TERMINATING ALL ACTIVE SESSIONS.', timestamp: Date.now() });
    globalWss?.clients.forEach(c => c.terminate());
    res.json({ success: true, message: 'System locked and sessions terminated.' });
  });

  apiRouter.post('/v1/system/unlock', validateMasterSignature, (req, res) => {
    db.prepare('UPDATE System_Config SET system_lock = 0 WHERE id = 1').run();
    db.prepare('DELETE FROM Risk_Registry').run();
    bannedIdentifiers.clear();
    ipCache.clear();
    broadcast({ type: 'SYSTEM', msg: 'SYSTEM_AWAKENED', timestamp: Date.now() });
    res.json({ success: true, message: 'System awakened. Risk Registry flushed.' });
  });

  apiRouter.all('*', (req, res) => {
    console.warn(`[ API 404 ] ${req.method} ${req.path} (Original: ${req.originalUrl}) not matched`);
    res.status(404).json({ error: 'API_NOT_FOUND', path: req.path });
  });

  const broadcastMsg = (data: any) => {
    const message = JSON.stringify(data);
    wss.clients.forEach((client) => {
      if (client.readyState === WebSocket.OPEN) {
        client.send(message);
      }
    });
  };

  broadcast = broadcastMsg;

  // --- Console Command Handler ---
  let awaitingUnlockPassword = false;

  const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout,
    terminal: false
  });

  rl.on('line', (line) => {
    const rawCmd = line.trim();
    if (!rawCmd) return;

    if (awaitingUnlockPassword) {
      const pass = rawCmd;
      const user = db.prepare('SELECT security_password FROM users LIMIT 1').get() as { security_password: string } | undefined;
      
      if (user && user.security_password === hashPassword(pass)) {
        db.prepare('UPDATE System_Config SET system_lock = 0 WHERE id = 1').run();
        
        // Flush registry and bans
        db.prepare('DELETE FROM Risk_Registry').run();
        bannedIdentifiers.clear();
        ipCache.clear();
        
        console.log("[ SECURITY ] UNLOCK_SUCCESS: Guard is awake. Risk Registry FLUSHED. System status: ACTIVE.");
        broadcast({ type: 'SYSTEM', msg: 'SYSTEM_AWAKENED', timestamp: Date.now() });
      } else {
        console.log("[ SECURITY ] UNLOCK_FAILURE: Invalid Security Password.");
      }
      
      awaitingUnlockPassword = false;
      return;
    }

    const cmd = rawCmd.toLowerCase();
    
    if (cmd === 'status') {
      try {
        const config = db.prepare('SELECT is_active, system_lock FROM System_Config WHERE id = 1').get() as { is_active: number, system_lock: number };
        console.log(`[STATUS] Active: ${config.is_active}, Locked: ${config.system_lock}`);
      } catch (e) {
        console.log("[STATUS] Error reading from database.");
      }
    } else if (cmd === 'woke up guard') {
      console.log("[ SECURITY ] Authentication Required to Unlock.");
      process.stdout.write("Enter Security Password: ");
      awaitingUnlockPassword = true;
    } else if (cmd === 'help') {
      console.log("Available Commands: 'status', 'woke up guard', 'help'");
    }
  });

  // --- WebSocket Connection Handling ---
  server.on('upgrade', (request, socket, head) => {
    try {
      const url = new URL(request.url || '', `http://${request.headers.host || 'localhost'}`);
      const pathname = url.pathname;
      
      if (pathname === '/ws') {
        process.stdout.write(`[ WS ] Upgrade request for /ws from ${request.socket.remoteAddress}\n`);
        wss.handleUpgrade(request, socket, head, (ws) => {
          wss.emit('connection', ws, request);
        });
      }
    } catch (err) {
      console.error("[ WS ERR ] Upgrade failure:", err);
      socket.destroy();
    }
  });

  wss.on('connection', (ws) => {
    console.log('[ WS ] Client linked to secure channel');
    
    const pingInterval = setInterval(() => {
      if (ws.readyState === WebSocket.OPEN) {
        ws.ping();
      }
    }, 30000);

    ws.on('close', () => {
      clearInterval(pingInterval);
      console.log('[ WS ] Client disconnected');
    });
    
    ws.on('message', (data) => {
      try {
        const parsedData = JSON.parse(data.toString());
        broadcast(parsedData);
      } catch (err) {
        console.error('[ WS ] Error parsing message:', err);
      }
    });

    ws.send(JSON.stringify({ 
      type: 'SYSTEM', 
      msg: 'STNEL_VAULT_DECRYPTED: WebSocket Handshake Complete',
      timestamp: Date.now()
    }));
  });

  // --- Global State ---
  const ipCache = new Map<string, { count: number, lastReset: number, riskScore: number }>();
  const bannedIdentifiers = new Set<string>();
  const bannedIps = new Set<string>(); // Legacy support
  const RATE_LIMIT = 100;
  const WINDOW_MS = 1000;
  const RISK_THRESHOLD = 80;

  // Load Bans from Database on startup
  function loadBans() {
    const bans = db.prepare('SELECT identifier FROM Risk_Registry WHERE is_banned = 1').all() as { identifier: string }[];
    bans.forEach(b => bannedIdentifiers.add(b.identifier));
    console.log(`[ BOOT ] Loaded ${bans.length} persistent bans from Registry.`);
  }
  loadBans();

  // --- Network Monitoring ---
  function startNetworkMonitor() {
    console.log('[ MONITOR ] Kernel Bridge standby. Awaiting real telemetry...');
    // Simulated packet increment loop removed to only show real data
  }

  startNetworkMonitor();

  interface ThreatResult {
    score: number;
    threats: string[];
    action: 'ALLOW' | 'BLOCK' | 'REDIRECT_TO_SANDBOX';
    latency: number;
    details?: any;
    risk_level: number;
  }

  // --- Normalization Layer ---
  function normalizePayload(payload: string): string {
    let normalized = payload;
    
    // 1. Recursive Decoding (Recursive urllib.parse.unquote)
    for (let i = 0; i < 3; i++) {
        const previous = normalized;
        try {
          normalized = decodeURIComponent(normalized);
        } catch (e) {}
        if (normalized === previous) break;
    }

    normalized = normalized.toLowerCase();

    // 2. Dialect Cleaner (Remove database-specific characters)
    normalized = normalized.replace(/[`\[\]]/g, '');

    // 3. Remove SQL comments (/**/) and HTML comments (<!-- -->)
    normalized = normalized.replace(/\/\*[\s\S]*?\*\/|<!--[\s\S]*?-->/g, '');

    // 4. Replace multiple spaces with a single space
    normalized = normalized.replace(/\s+/g, ' ');

    return normalized.trim();
  }

  function analyzeThreats(data: any, ip: string, fingerprint?: string): ThreatResult {
    const start = performance.now();
    let score = 0;
    const threats: string[] = [];
    
    const rawPayload = JSON.stringify(data);
    const normalizedPayload = normalizePayload(rawPayload);

    // SQL Injection Patterns
    const sqlPatterns = [
      /select.*from/i,
      /insert.*into/i,
      /update.*set/i,
      /delete.*from/i,
      /union.*select/i,
      /drop\s+table/i,
      /truncate\s+table/i,
      /alter\s+table/i,
      /['";]\s*OR\s+['"]?\d+['"]?\s*=\s*['"]?\d+/i,
      /--/,
      /;\s*$/
    ];

    sqlPatterns.forEach(pattern => {
      if (pattern.test(normalizedPayload)) {
        score += 55;
        threats.push('SQL_INJECTION_DETECTED');
      }
    });

    // --- Low-Level Probes (Suspicious Keywords) ---
    const suspiciousKeywords = [/admin/i, /config/i, /root/i, /passwd/i, /shadow/i];
    suspiciousKeywords.forEach(pattern => {
      if (pattern.test(normalizedPayload)) {
        score += 15;
        threats.push('SUSPICIOUS_KEYWORD_PROBE');
      }
    });

    // XSS Patterns
    const xssPatterns = [
      /<script.*?>/i,
      /<\/script>/i,
      /javascript:/i,
      /onerror=/i,
      /onload=/i,
      /alert\(/i,
      /eval\(/i,
      /<img.*?src=.*?onerror/i,
      /document\.cookie/i,
      /localStorage/i
    ];

    xssPatterns.forEach(pattern => {
      if (pattern.test(normalizedPayload)) {
        score += 40;
        threats.push('XSS_ATTEMPT_DETECTED');
      }
    });

    if (normalizedPayload.length > 5000) {
      score += 50;
      threats.push('OVERSIZED_PAYLOAD_ANOMALY');
    }

    // --- Command Poisoning Detectors ---
    const commandWords = [/woke up guard/i, /delete baby/i];
    commandWords.forEach(pattern => {
      if (pattern.test(normalizedPayload)) {
        score += 30;
        threats.push('COMMAND_GUESSING_PROBE');
      }
    });

    // --- Persistent Risk Registry Logic ---
    const primaryId = fingerprint || ip;
    const existingRegistry = db.prepare('SELECT cumulative_score FROM Risk_Registry WHERE identifier = ?').get(primaryId) as { cumulative_score: number } | undefined;
    
    const currentCumulative = (existingRegistry?.cumulative_score || 0) + score;
    
    // Update Database
    db.prepare(`
        INSERT INTO Risk_Registry (identifier, cumulative_score, last_seen, type) 
        VALUES (?, ?, ?, ?)
        ON CONFLICT(identifier) DO UPDATE SET 
        cumulative_score = excluded.cumulative_score,
        last_seen = excluded.last_seen
    `).run(primaryId, currentCumulative, Date.now(), fingerprint ? 'FINGERPRINT' : 'IP');

    // Sync IP Cache (Memory)
    const stats = ipCache.get(ip) || { count: 0, lastReset: Date.now(), riskScore: 0 };
    stats.riskScore = currentCumulative;
    ipCache.set(ip, stats);

    // Final Decision
    const finalScore = Math.min(score, 100);
    const cumulativeRisk = currentCumulative;
    
    let action: 'ALLOW' | 'BLOCK' | 'REDIRECT_TO_SANDBOX' = 'ALLOW';
    
    if (cumulativeRisk >= 90 && cumulativeRisk < 100) {
      action = 'REDIRECT_TO_SANDBOX';
    } else if (finalScore >= 50 || cumulativeRisk >= RISK_THRESHOLD) {
      action = 'BLOCK';
    }

    const latency = parseFloat((performance.now() - start).toFixed(4));
    const isHighLevel = action === 'BLOCK' || action === 'REDIRECT_TO_SANDBOX';

    if (action === 'BLOCK' && !bannedIdentifiers.has(primaryId)) {
      bannedIdentifiers.add(primaryId);
      db.prepare('UPDATE Risk_Registry SET is_banned = 1 WHERE identifier = ?').run(primaryId);
      
      broadcast({
        type: 'BAN_EVENT',
        msg: `[CRITICAL] Identity ${primaryId} permanently flagged. Risk Threshold Breach in Registry.`,
        ip: ip,
        fingerprint
      });
    }

    const result: ThreatResult = {
      score: finalScore,
      threats: Array.from(new Set(threats)),
      action,
      latency,
      risk_level: cumulativeRisk,
      details: {
        origin: data.origin || ip,
        timestamp: Date.now(),
        isHighLevel,
        raw_payload: rawPayload,
        normalized_payload: normalizedPayload,
        cumulative_risk: cumulativeRisk,
        fingerprint
      }
    };

    // Broadcast
    if (action === 'BLOCK') {
      broadcast({
        type: 'BLOCK_EVENT',
        msg: `CRITICAL: Threat blocked. Risk Level: ${cumulativeRisk}. Matches: ${result.threats.join(', ') || 'CUMULATIVE_ANOMALY'}`,
        data: result,
        severity: 'HIGH'
      });
    } else if (action === 'REDIRECT_TO_SANDBOX') {
      broadcast({
        type: 'SANDBOX_EVENT',
        msg: `DECEPTION: Identity ${primaryId} moved to Mirror Room. Risk: ${cumulativeRisk}.`,
        data: result
      });
    } else {
      broadcast({
        type: 'ALLOW_EVENT',
        msg: `HANDSHAKE: Verified traffic from ${result.details.origin}. Payload clean.`,
        data: result
      });
    }

    return result;
  }

  // Removed redundant API routes - consolidated into apiRouter above

  // --- Vite / SPA Fallback ---
  if (process.env.NODE_ENV !== 'production') {
    const vite = await createViteServer({
      server: { middlewareMode: true, hmr: false },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  } else {
    const distPath = path.join(process.cwd(), 'dist');
    app.use(express.static(distPath));
    app.get('*', (req, res) => {
      res.sendFile(path.join(distPath, 'index.html'));
    });
  }

  // --- Final Server Start ---
  server.listen(PORT, '0.0.0.0', () => {
    console.log(`[ Sentinel_SECaaS ] Security Engine online at http://localhost:${PORT}`);
  });
}

process.on('uncaughtException', (err) => {
  console.error('[ CRITICAL ] Uncaught Exception:', err);
});

process.on('unhandledRejection', (reason, promise) => {
  console.error('[ CRITICAL ] Unhandled Rejection at:', promise, 'reason:', reason);
});

console.log("[ BOOT ] Starting Security Engine...");
startServer().catch(err => {
  console.error("[ CRITICAL ] Failed to start server:", err);
});
