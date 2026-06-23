import 'dotenv/config';
import crypto from 'crypto';
import fs from 'fs';
import express from 'express';
import session from 'express-session';
import sessionFileStore from 'session-file-store';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const FileStore = sessionFileStore(session);

const app = express();
const PORT = process.env.PORT || 3000;
const APP_NAME = process.env.APP_NAME || 'Fenix';
const APP_URL = (process.env.APP_URL || `http://localhost:${PORT}`).replace(/\/$/, '');
const KICK_CLIENT_ID = process.env.KICK_CLIENT_ID || '';
const KICK_CLIENT_SECRET = process.env.KICK_CLIENT_SECRET || '';
const KICK_REDIRECT_URI = process.env.KICK_REDIRECT_URI || `${APP_URL}/auth/kick/callback`;
const KICK_SCOPES = process.env.KICK_SCOPES || 'user:read channel:read';
const FENIX_SESSION_DIR = process.env.FENIX_SESSION_DIR ||
  (fs.existsSync('/data') ? '/data/sessions' : path.join(__dirname, 'railway-data', 'sessions'));
const FENIX_SESSION_SECRET = process.env.SESSION_SECRET ||
  (APP_URL.startsWith('http://localhost') ? 'fenix-local-development-only' : '');

if (!FENIX_SESSION_SECRET) {
  throw new Error('SESSION_SECRET não configurado para este ambiente.');
}

fs.mkdirSync(FENIX_SESSION_DIR, { recursive: true });

const KICK_ID_URL = 'https://id.kick.com';
const KICK_API_URL = 'https://api.kick.com/public/v1';


app.use(express.json({ limit: '5mb' }));

// FENIX_URLENCODED_LIMIT_FINAL
app.use(express.urlencoded({ limit: '5mb', extended: true }));
app.set('trust proxy', 1);
app.use(
  session({
    name: 'fenix.sid',
    store: new FileStore({
      path: FENIX_SESSION_DIR,
      ttl: 60 * 60 * 24 * 7,
      retries: 1,
      reapInterval: 60 * 60,
      logFn: () => {}
    }),
    secret: FENIX_SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    proxy: true,
    cookie: {
      httpOnly: true,
      sameSite: 'lax',
      secure: APP_URL.startsWith('https://'),
      maxAge: 1000 * 60 * 60 * 24 * 7
    }
  })
);

app.use(express.static(path.join(__dirname, 'public')));

function base64Url(input) {
  return Buffer.from(input)
    .toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/g, '');
}

function sha256(input) {
  return crypto.createHash('sha256').update(input).digest();
}

function randomString(size = 64) {
  return base64Url(crypto.randomBytes(size));
}

function requireKickConfig(req, res, next) {
  if (!KICK_CLIENT_ID || !KICK_CLIENT_SECRET) {
    return res.status(400).json({
      ok: false,
      message: 'Configure KICK_CLIENT_ID e KICK_CLIENT_SECRET nas variaveis da Railway ou no .env local.'
    });
  }
  next();
}

async function kickTokenRequest(body) {
  const response = await fetch(`${KICK_ID_URL}/oauth/token`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams(body)
  });

  const text = await response.text();
  let data;
  try {
    data = JSON.parse(text);
  } catch {
    data = { raw: text };
  }

  if (!response.ok) {
    const err = new Error(data?.error || data?.message || 'Erro ao conectar na Kick.');
    err.status = response.status;
    err.data = data;
    throw err;
  }

  return data;
}

async function getAppAccessToken() {
  const cached = globalThis.__fenixAppToken;
  const now = Date.now();

  if (cached?.access_token && cached.expires_at > now + 60_000) {
    return cached.access_token;
  }

  const token = await kickTokenRequest({
    grant_type: 'client_credentials',
    client_id: KICK_CLIENT_ID,
    client_secret: KICK_CLIENT_SECRET
  });

  globalThis.__fenixAppToken = {
    access_token: token.access_token,
    expires_at: now + Number(token.expires_in || 3600) * 1000
  };

  return token.access_token;
}

async function kickApi(pathname, token, searchParams = {}) {
  const url = new URL(`${KICK_API_URL}${pathname}`);
  for (const [key, value] of Object.entries(searchParams)) {
    if (Array.isArray(value)) {
      value.forEach((v) => url.searchParams.append(key, v));
    } else if (value !== undefined && value !== null && value !== '') {
      url.searchParams.append(key, value);
    }
  }

  const response = await fetch(url, {
    headers: {
      Authorization: `Bearer ${token}`,
      Accept: 'application/json'
    }
  });

  const text = await response.text();
  let data;
  try {
    data = JSON.parse(text);
  } catch {
    data = { raw: text };
  }

  if (!response.ok) {
    const err = new Error(data?.message || data?.error || 'Erro na API Kick.');
    err.status = response.status;
    err.data = data;
    throw err;
  }

  return data;
}

// FENIX_REQUEST_PROTECTION_FINAL
const FENIX_RATE_BUCKETS_FINAL = new Map();

function fenixCreateRateLimiterFinal(name, maxRequests, windowMs, keyResolver) {
  return (req, res, next) => {
    const now = Date.now();
    const rawKey = keyResolver(req);
    const key = name + ':' + String(rawKey || req.ip || 'unknown');
    const current = FENIX_RATE_BUCKETS_FINAL.get(key);

    if (!current || now >= current.resetAt) {
      FENIX_RATE_BUCKETS_FINAL.set(key, {
        count: 1,
        resetAt: now + windowMs
      });

      return next();
    }

    current.count += 1;

    if (current.count > maxRequests) {
      const retryAfterSeconds = Math.max(1, Math.ceil((current.resetAt - now) / 1000));

      res.setHeader('Retry-After', String(retryAfterSeconds));

      return res.status(429).json({
        ok: false,
        message: 'Muitas requisicoes. Aguarde alguns segundos.',
        retryAfterSeconds
      });
    }

    next();
  };
}

const fenixCycleRateLimitFinal = fenixCreateRateLimiterFinal(
  'cycle',
  12,
  60 * 1000,
  (req) => req.body?.sessionId || req.ip
);

const fenixHeartbeatRateLimitFinal = fenixCreateRateLimiterFinal(
  'heartbeat',
  20,
  60 * 1000,
  (req) => req.body?.sessionId || req.body?.deviceId || req.ip
);

const fenixAdminReadRateLimitFinal = fenixCreateRateLimiterFinal(
  'admin-online',
  120,
  60 * 1000,
  (req) => req.ip
);

const fenixRateCleanupTimerFinal = setInterval(() => {
  const now = Date.now();

  for (const [key, bucket] of FENIX_RATE_BUCKETS_FINAL.entries()) {
    if (!bucket || now >= bucket.resetAt) {
      FENIX_RATE_BUCKETS_FINAL.delete(key);
    }
  }
}, 5 * 60 * 1000);

fenixRateCleanupTimerFinal.unref?.();

// FENIX_HEALTH_MONITOR_FINAL
app.get('/health', (req, res) => {
  const memory = process.memoryUsage();

  res.setHeader('Cache-Control', 'no-store');
  res.json({
    ok: true,
    app: APP_NAME,
    time: new Date().toISOString(),
    uptimeSeconds: Math.floor(process.uptime()),
    memoryMb: {
      rss: Math.round(memory.rss / 1024 / 1024),
      heapUsed: Math.round(memory.heapUsed / 1024 / 1024),
      heapTotal: Math.round(memory.heapTotal / 1024 / 1024)
    },
    rateLimitKeys: FENIX_RATE_BUCKETS_FINAL.size
  });
});

app.get('/api/config', (req, res) => {
  res.json({
    ok: true,
    appName: APP_NAME,
    appUrl: APP_URL,
    redirectUri: KICK_REDIRECT_URI,
    kickConfigured: Boolean(KICK_CLIENT_ID && KICK_CLIENT_SECRET),
    loggedIn: Boolean(req.session.kick?.access_token),
    user: req.session.kick?.user || null
  });
});

app.get('/auth/kick', requireKickConfig, (req, res) => {
  const state = randomString(24);
  const codeVerifier = randomString(64);
  const codeChallenge = base64Url(sha256(codeVerifier));

  req.session.oauth = { state, codeVerifier, createdAt: Date.now() };

  const url = new URL(`${KICK_ID_URL}/oauth/authorize`);
  url.searchParams.set('response_type', 'code');
  url.searchParams.set('client_id', KICK_CLIENT_ID);
  url.searchParams.set('redirect_uri', KICK_REDIRECT_URI);
  url.searchParams.set('scope', KICK_SCOPES);
  url.searchParams.set('code_challenge', codeChallenge);
  url.searchParams.set('code_challenge_method', 'S256');
  url.searchParams.set('state', state);

  res.redirect(url.toString());
});

app.get('/auth/kick/callback', requireKickConfig, async (req, res) => {
  try {
    const { code, state, error } = req.query;

    if (error) {
      return res.redirect(`/?error=${encodeURIComponent(String(error))}`);
    }

    if (!code || !state || state !== req.session.oauth?.state) {
      return res.redirect('/?error=state_invalido');
    }

    const token = await kickTokenRequest({
      grant_type: 'authorization_code',
      client_id: KICK_CLIENT_ID,
      client_secret: KICK_CLIENT_SECRET,
      redirect_uri: KICK_REDIRECT_URI,
      code_verifier: req.session.oauth.codeVerifier,
      code: String(code)
    });

    req.session.kick = {
      access_token: token.access_token,
      refresh_token: token.refresh_token,
      expires_at: Date.now() + Number(token.expires_in || 3600) * 1000,
      scope: token.scope || KICK_SCOPES,
      user: null
    };
    req.session.oauth = null;

    try {
      const channel = await kickApi('/channels', token.access_token);
      req.session.kick.user = channel?.data?.[0] || null;
    } catch {
      req.session.kick.user = null;
    }

    res.redirect('/dashboard.html');
  } catch (err) {
    console.error('Kick callback error:', err?.data || err);
    res.redirect(`/?error=${encodeURIComponent(err.message || 'erro_login_kick')}`);
  }
});

app.post('/auth/logout', (req, res) => {
  req.session.destroy(() => {
    res.json({ ok: true });
  });
});

app.get('/api/me', async (req, res) => {
  try {
    if (!req.session.kick?.access_token) {
      return res.status(401).json({ ok: false, message: 'Nao logado na Kick.' });
    }

    const data = await kickApi('/channels', req.session.kick.access_token);
    req.session.kick.user = data?.data?.[0] || null;

    res.json({ ok: true, user: req.session.kick.user, raw: data });
  } catch (err) {
    res.status(err.status || 500).json({ ok: false, message: err.message, details: err.data || null });
  }
});

app.get('/api/channel/:slug', requireKickConfig, async (req, res) => {
  try {
    const token = req.session.kick?.access_token || (await getAppAccessToken());
    const data = await kickApi('/channels', token, { slug: req.params.slug });
    res.json({ ok: true, channel: data?.data?.[0] || null, raw: data });
  } catch (err) {
    res.status(err.status || 500).json({ ok: false, message: err.message, details: err.data || null });
  }
});

app.get('/api/livestreams', requireKickConfig, async (req, res) => {
  try {
    const token = req.session.kick?.access_token || (await getAppAccessToken());
    const data = await kickApi('/livestreams', token, {
      limit: req.query.limit || 25,
      sort: req.query.sort || 'viewer_count',
      language: req.query.language || undefined
    });

    res.json({ ok: true, livestreams: data?.data || [], raw: data });
  } catch (err) {
    res.status(err.status || 500).json({ ok: false, message: err.message, details: err.data || null });
  }
});

app.get('/api/livestreams/stats', requireKickConfig, async (req, res) => {
  try {
    const token = req.session.kick?.access_token || (await getAppAccessToken());
    const data = await kickApi('/livestreams/stats', token);
    res.json({ ok: true, stats: data?.data || null, raw: data });
  } catch (err) {
    res.status(err.status || 500).json({ ok: false, message: err.message, details: err.data || null });
  }
});



// FENIX_LURK_CORE_API
const FENIX_ADMIN_USER = 'GokuuMods';
const FENIX_ADMIN_SECRET = process.env.FENIX_ADMIN_SECRET || '';
const FENIX_MIN_CYCLE_INTERVAL_MS = Number(process.env.FENIX_MIN_CYCLE_INTERVAL_MS || 1000 * 60 * 9);
const FENIX_MIN_POINTS_APP_VERSION = String(process.env.FENIX_MIN_POINTS_APP_VERSION || '1.0.7').trim();
const FENIX_DATA_DIR = process.env.FENIX_DATA_DIR || (fs.existsSync('/data') ? '/data' : path.join(__dirname, 'backend', 'data'));
const FENIX_DATA_FILE = path.join(FENIX_DATA_DIR, 'fenix-data.json');
const FENIX_BACKUP_DIR = path.join(FENIX_DATA_DIR, 'backups');
const FENIX_MAX_BACKUPS = Number(process.env.FENIX_MAX_BACKUPS || 30);
let FENIX_LAST_BACKUP_AT = 0;
console.log('Fenix data file:', FENIX_DATA_FILE);
console.log('Fenix backup dir:', FENIX_BACKUP_DIR);
const FENIX_MEMORY_HEARTBEATS = new Map();
const FENIX_MEMORY_EXTRA_TABS = new Map();

function fenixParseAppVersion(value) {
  const match = String(value || '').trim().match(/^v?(\d+)\.(\d+)\.(\d+)$/i);
  return match ? [Number(match[1]), Number(match[2]), Number(match[3])] : null;
}

function fenixAppVersionCanEarnPoints(value) {
  const current = fenixParseAppVersion(value);
  const minimum = fenixParseAppVersion(FENIX_MIN_POINTS_APP_VERSION);

  if (!current || !minimum) return false;

  for (let index = 0; index < 3; index += 1) {
    if (current[index] > minimum[index]) return true;
    if (current[index] < minimum[index]) return false;
  }

  return true;
}

// FENIX_APP_ME_RESPONSE_CACHE_116
const FENIX_APP_ME_RESPONSE_CACHE = new Map();
const FENIX_APP_ME_CACHE_MS = 15000;

fs.mkdirSync(FENIX_DATA_DIR, { recursive: true });

function createDefaultFenixData() {
  return {
    users: [],
    sessions: [],
    schedule: [],
    notices: [
      {
        id: crypto.randomUUID(),
        message: 'COMEÃ‡AR A LIVE 5 MINUTOS ANTES DO SEU HORARIO PROGRAMADO NO FENIX LURK',
        active: true,
        createdBy: FENIX_ADMIN_USER,
        createdAt: new Date().toISOString()
      }
    ],
    cycles: [],
    deviceLocks: [],
    kickLocks: [],
    extraTargets: {}
  };
}

/* FENIX_DATA_PROTECTION_20260612 */
function normalizeFenixDataShape(parsed) {
  const base = parsed && typeof parsed === 'object' ? parsed : {};

  return {
    ...base,
    users: Array.isArray(base.users) ? base.users : [],
    sessions: Array.isArray(base.sessions) ? base.sessions : [],
    schedule: Array.isArray(base.schedule) ? base.schedule : [],
    notices: Array.isArray(base.notices) ? base.notices : [],
    cycles: Array.isArray(base.cycles) ? base.cycles : [],
    deviceLocks: Array.isArray(base.deviceLocks) ? base.deviceLocks : [],
    kickLocks: Array.isArray(base.kickLocks) ? base.kickLocks : [],
    farmHeartbeats: Array.isArray(base.farmHeartbeats) ? base.farmHeartbeats : [],
    extraTargets: base.extraTargets && typeof base.extraTargets === 'object'
      ? base.extraTargets
      : {}
  };
}

function fenixBackupTimestamp() {
  return new Date().toISOString().replace(/[:.]/g, '-');
}

function fenixSafeReadJsonFile(file) {
  try {
    if (!fs.existsSync(file)) return null;
    return JSON.parse(fs.readFileSync(file, 'utf8'));
  } catch {
    return null;
  }
}

function cleanupFenixBackups() {
  try {
    fs.mkdirSync(FENIX_BACKUP_DIR, { recursive: true });

    const files = fs.readdirSync(FENIX_BACKUP_DIR)
      .filter((name) => name.startsWith('fenix-data-') && name.endsWith('.json'))
      .sort();

    while (files.length > FENIX_MAX_BACKUPS) {
      const oldFile = files.shift();
      fs.unlinkSync(path.join(FENIX_BACKUP_DIR, oldFile));
    }
  } catch (error) {
    console.error('Erro limpando backups Fenix:', error);
  }
}

function createFenixDataBackup(reason = 'auto', force = false) {
  try {
    if (!fs.existsSync(FENIX_DATA_FILE)) return null;

    const now = Date.now();

    if (!force && now - FENIX_LAST_BACKUP_AT < 1000 * 60 * 5) {
      return null;
    }

    const currentRaw = fs.readFileSync(FENIX_DATA_FILE, 'utf8');
    JSON.parse(currentRaw);

    fs.mkdirSync(FENIX_BACKUP_DIR, { recursive: true });

    const safeReason = String(reason || 'auto')
      .replace(/[^a-z0-9_-]/gi, '-')
      .slice(0, 40);

    const backupFile = path.join(
      FENIX_BACKUP_DIR,
      `fenix-data-${fenixBackupTimestamp()}-${safeReason}.json`
    );

    fs.writeFileSync(backupFile, currentRaw, 'utf8');
    FENIX_LAST_BACKUP_AT = now;

    cleanupFenixBackups();

    console.log('Backup Fenix criado:', backupFile);
    return backupFile;
  } catch (error) {
    console.error('Erro criando backup Fenix:', error);
    return null;
  }
}

function readLatestFenixBackup() {
  try {
    if (!fs.existsSync(FENIX_BACKUP_DIR)) return null;

    const files = fs.readdirSync(FENIX_BACKUP_DIR)
      .filter((name) => name.startsWith('fenix-data-') && name.endsWith('.json'))
      .sort()
      .reverse();

    for (const name of files) {
      const file = path.join(FENIX_BACKUP_DIR, name);
      const parsed = fenixSafeReadJsonFile(file);

      if (parsed) {
        console.log('Fenix recuperado do backup:', file);
        return normalizeFenixDataShape(parsed);
      }
    }

    return null;
  } catch (error) {
    console.error('Erro lendo backups Fenix:', error);
    return null;
  }
}

// FENIX_DATA_MEMORY_CACHE_115
let FENIX_DATA_MEMORY_CACHE = null;

function fenixCloneData(data) {
  return JSON.parse(JSON.stringify(data));
}

function readFenixData() {
  try {
    if (FENIX_DATA_MEMORY_CACHE) {
      return fenixCloneData(FENIX_DATA_MEMORY_CACHE);
    }

    if (!fs.existsSync(FENIX_DATA_FILE)) {
      const initial = createDefaultFenixData();
      fs.mkdirSync(FENIX_DATA_DIR, { recursive: true });
      fs.writeFileSync(FENIX_DATA_FILE, JSON.stringify(initial, null, 2), 'utf8');
      createFenixDataBackup('initial', true);
      FENIX_DATA_MEMORY_CACHE = normalizeFenixDataShape(initial);
      return fenixCloneData(FENIX_DATA_MEMORY_CACHE);
    }

    const parsed = JSON.parse(fs.readFileSync(FENIX_DATA_FILE, 'utf8'));
    FENIX_DATA_MEMORY_CACHE = normalizeFenixDataShape(parsed);
    return fenixCloneData(FENIX_DATA_MEMORY_CACHE);
  } catch (error) {
    console.error('Erro lendo fenix-data.json:', error);

    const backup = readLatestFenixBackup();

    if (backup) {
      FENIX_DATA_MEMORY_CACHE = normalizeFenixDataShape(backup);
      return fenixCloneData(FENIX_DATA_MEMORY_CACHE);
    }

    throw error;
  }
}

function writeFenixData(data) {
  const nextData = normalizeFenixDataShape(data);
  const allowDangerousShrink = nextData.__allowDangerousShrink === true;

  if (Object.prototype.hasOwnProperty.call(nextData, '__allowDangerousShrink')) {
    delete nextData.__allowDangerousShrink;
  }

  const currentData = FENIX_DATA_MEMORY_CACHE
    ? normalizeFenixDataShape(FENIX_DATA_MEMORY_CACHE)
    : (fs.existsSync(FENIX_DATA_FILE) ? normalizeFenixDataShape(JSON.parse(fs.readFileSync(FENIX_DATA_FILE, 'utf8'))) : null);

  if (currentData && !allowDangerousShrink) {
    const currentUsers = currentData.users.length;
    const nextUsers = nextData.users.length;
    const currentSchedule = currentData.schedule.length;
    const nextSchedule = nextData.schedule.length;

    if (currentUsers > 0 && nextUsers < currentUsers) {
      createFenixDataBackup('blocked-users-shrink', true);

      throw new Error(
        `PROTECAO FENIX: salvamento bloqueado porque reduziria contas de ${currentUsers} para ${nextUsers}.`
      );
    }

    if (currentSchedule > 0 && nextSchedule === 0) {
      createFenixDataBackup('blocked-schedule-empty', true);

      throw new Error(
        `PROTECAO FENIX: salvamento bloqueado porque zeraria a grade de ${currentSchedule} para 0.`
      );
    }
  }

  const forceBackup =
    currentData &&
    (
      nextData.users.length !== currentData.users.length ||
      nextData.schedule.length !== currentData.schedule.length ||
      nextData.cycles.length < currentData.cycles.length
    );

  // FENIX_FAST_WRITE_BACKUP_ONLY_WHEN_FORCED_114
  if (forceBackup) {
    createFenixDataBackup('before-write', true);
  }

  fs.mkdirSync(FENIX_DATA_DIR, { recursive: true });

  const tempFile = `${FENIX_DATA_FILE}.tmp-${process.pid}-${Date.now()}`;
  const json = JSON.stringify(nextData, null, 2);

  JSON.parse(json);

  fs.writeFileSync(tempFile, json, 'utf8');
  JSON.parse(fs.readFileSync(tempFile, 'utf8'));

  fs.renameSync(tempFile, FENIX_DATA_FILE);

  FENIX_DATA_MEMORY_CACHE = normalizeFenixDataShape(nextData);
}
/* FIM_FENIX_DATA_PROTECTION_20260612 */

function hashFenixPassword(password, salt = crypto.randomBytes(16).toString('hex')) {
  const hash = crypto.pbkdf2Sync(String(password || ''), salt, 120000, 64, 'sha512').toString('hex');
  return salt + ':' + hash;
}

function verifyFenixPassword(password, saved) {
  const [salt, hash] = String(saved || '').split(':');

  if (!salt || !hash) return false;

  const check = crypto.pbkdf2Sync(String(password || ''), salt, 120000, 64, 'sha512').toString('hex');

  try {
    return crypto.timingSafeEqual(Buffer.from(hash, 'hex'), Buffer.from(check, 'hex'));
  } catch {
    return false;
  }
}

function normalizeFenixUsername(username) {
  return String(username || '').trim();
}

function getBrazilParts(date = new Date()) {
  const parts = new Intl.DateTimeFormat('en-CA', {
    timeZone: 'America/Sao_Paulo',
    year: 'numeric',
    month: '2-digit',
    day: '2-digit',
    hour: '2-digit',
    hour12: false
  }).formatToParts(date);

  const get = (type) => parts.find((part) => part.type === type)?.value || '';

  return {
    year: get('year'),
    month: get('month'),
    day: get('day'),
    hour: get('hour')
  };
}

function getFenixDateKey(date = new Date()) {
  const parts = getBrazilParts(date);
  return parts.year + '-' + parts.month + '-' + parts.day;
}

function getFenixHourKey(date = new Date()) {
  const parts = getBrazilParts(date);
  return String(parts.hour || '00').padStart(2, '0') + ':00';
}


// FENIX_WEEKLY_HISTORY_AND_EXTRA_TARGET_FINAL
const FENIX_WEEKLY_V107_START_DATE_FINAL = process.env.FENIX_WEEKLY_V107_START_DATE || '2026-06-21';
const FENIX_WEEKLY_LEGACY_GOAL_POINTS_FINAL = 2592;
const FENIX_WEEKLY_LEGACY_MINIMUM_POINTS_FINAL = 1815;
const FENIX_WEEKLY_GOAL_POINTS_FINAL = 3024;
const FENIX_WEEKLY_MINIMUM_POINTS_FINAL = 2722;

function fenixWeeklyDateFromKeyFinal(dateKey) {
  return new Date(String(dateKey || getFenixDateKey()) + 'T12:00:00-03:00');
}

function fenixWeeklyAddDaysFinal(dateKey, days) {
  const date = fenixWeeklyDateFromKeyFinal(dateKey);
  date.setUTCDate(date.getUTCDate() + Number(days || 0));
  return getFenixDateKey(date);
}

function fenixWeeklyDayOfWeekFinal(dateKey) {
  return fenixWeeklyDateFromKeyFinal(dateKey).getUTCDay();
}

function fenixWeeklyInfoFinal(now = new Date()) {
  const todayKey = getFenixDateKey(now);
  const day = fenixWeeklyDayOfWeekFinal(todayKey);
  const v107Active = todayKey >= FENIX_WEEKLY_V107_START_DATE_FINAL;

  if (!v107Active) {
    if (day === 0) {
      const previousWeekStart = fenixWeeklyAddDaysFinal(todayKey, -6);
      const previousWeekEnd = fenixWeeklyAddDaysFinal(todayKey, -1);
      const nextWeekStart = fenixWeeklyAddDaysFinal(todayKey, 1);

      return {
        todayKey,
        day,
        isSunday: true,
        countsWeekly: false,
        weekId: nextWeekStart,
        weekStart: nextWeekStart,
        weekEnd: fenixWeeklyAddDaysFinal(nextWeekStart, 5),
        previousWeekStart,
        previousWeekEnd,
        goal: FENIX_WEEKLY_LEGACY_GOAL_POINTS_FINAL,
        minimum: FENIX_WEEKLY_LEGACY_MINIMUM_POINTS_FINAL,
        ruleVersion: '1.0.6',
        message: 'Domingo nao conta. A semana valida vai de segunda 00:00 ate sabado 23:59.'
      };
    }

    const legacyWeekStart = fenixWeeklyAddDaysFinal(todayKey, -(day - 1));

    return {
      todayKey,
      day,
      isSunday: false,
      countsWeekly: true,
      weekId: legacyWeekStart,
      weekStart: legacyWeekStart,
      weekEnd: fenixWeeklyAddDaysFinal(legacyWeekStart, 5),
      previousWeekStart: fenixWeeklyAddDaysFinal(legacyWeekStart, -7),
      previousWeekEnd: fenixWeeklyAddDaysFinal(legacyWeekStart, -2),
      goal: FENIX_WEEKLY_LEGACY_GOAL_POINTS_FINAL,
      minimum: FENIX_WEEKLY_LEGACY_MINIMUM_POINTS_FINAL,
      ruleVersion: '1.0.6',
      message: 'Conta de segunda 00:00 ate sabado 23:59. Domingo nao conta.'
    };
  }

  const weekStart = fenixWeeklyAddDaysFinal(todayKey, -day);

  return {
    todayKey,
    day,
    isSunday: day === 0,
    countsWeekly: true,
    weekId: weekStart,
    weekStart,
    weekEnd: fenixWeeklyAddDaysFinal(weekStart, 6),
    previousWeekStart: fenixWeeklyAddDaysFinal(weekStart, -7),
    previousWeekEnd: fenixWeeklyAddDaysFinal(weekStart, -1),
    goal: FENIX_WEEKLY_GOAL_POINTS_FINAL,
    minimum: FENIX_WEEKLY_MINIMUM_POINTS_FINAL,
    ruleVersion: '1.0.7',
    message: 'Conta de domingo 00:00 ate sabado 23:59. Funcionamento e pontuacao 24/7.'
  };
}
function fenixWeeklyPercentFinal(points, goal = FENIX_WEEKLY_GOAL_POINTS_FINAL) {
  const value = Number(points || 0);
  const target = Math.max(1, Number(goal || FENIX_WEEKLY_GOAL_POINTS_FINAL));
  return Math.min(100, Math.floor((value / target) * 100));
}

function fenixEnsureWeeklyContainersFinal(data) {
  data.weeklyHistory = Array.isArray(data.weeklyHistory) ? data.weeklyHistory : [];
  data.fenixWeeklyState = data.fenixWeeklyState && typeof data.fenixWeeklyState === 'object' ? data.fenixWeeklyState : {};
  data.users = Array.isArray(data.users) ? data.users : [];
}

function fenixCloseWeeklySnapshotFinal(data, weekStart, weekEnd, reason, goal, minimum) {
  fenixEnsureWeeklyContainersFinal(data);

  const weekId = String(weekStart || '').trim();
  if (!weekId) return false;

  const exists = data.weeklyHistory.some((item) => String(item.weekId || '') === weekId);
  if (exists) return false;

  const snapshotGoal = Math.max(1, Number(goal || FENIX_WEEKLY_GOAL_POINTS_FINAL));
  const snapshotMinimum = Math.max(0, Number(minimum || FENIX_WEEKLY_MINIMUM_POINTS_FINAL));

  const users = data.users.map((user) => {
    const weeklyPoints = Number(user.weeklyPoints || 0);
    const weeklyMinutes = Number(user.weeklyMinutes || 0);
    const percent = fenixWeeklyPercentFinal(weeklyPoints, snapshotGoal);

    return {
      userId: user.id || '',
      username: user.username || '',
      kickUsername: user.kickUsername || user.kickName || '',
      points: weeklyPoints,
      minutes: weeklyMinutes,
      percent,
      approved: weeklyPoints >= snapshotMinimum
    };
  }).sort((a, b) => {
    return Number(b.points || 0) - Number(a.points || 0) || String(a.username || '').localeCompare(String(b.username || ''));
  });

  data.weeklyHistory.push({
    id: crypto.randomUUID(),
    weekId,
    weekStart,
    weekEnd,
    goal: snapshotGoal,
    minimum: snapshotMinimum,
    closedAt: new Date().toISOString(),
    reason: reason || 'auto',
    users
  });

  data.weeklyHistory = data.weeklyHistory
    .slice()
    .sort((a, b) => String(b.weekStart || '').localeCompare(String(a.weekStart || '')))
    .slice(0, 30);

  return true;
}
function fenixResetWeeklyUsersFinal(data) {
  fenixEnsureWeeklyContainersFinal(data);

  data.users.forEach((user) => {
    user.weeklyPoints = 0;
    user.weeklyMinutes = 0;
    user.updatedAt = new Date().toISOString();
  });
}

function ensureFenixWeeklyControlFinal(data, now = new Date()) {
  fenixEnsureWeeklyContainersFinal(data);

  const info = fenixWeeklyInfoFinal(now);
  const state = data.fenixWeeklyState;
  let changed = false;

  if (!state.currentWeekId) {
    if (info.isSunday && !info.countsWeekly) {
      fenixCloseWeeklySnapshotFinal(
        data,
        info.previousWeekStart,
        info.previousWeekEnd,
        'domingo-fechamento',
        FENIX_WEEKLY_LEGACY_GOAL_POINTS_FINAL,
        FENIX_WEEKLY_LEGACY_MINIMUM_POINTS_FINAL
      );
      fenixResetWeeklyUsersFinal(data);
    }

    state.currentWeekId = info.weekId;
    state.weekStart = info.weekStart;
    state.weekEnd = info.weekEnd;
    state.goal = info.goal;
    state.minimum = info.minimum;
    state.ruleVersion = info.ruleVersion;
    state.updatedAt = new Date().toISOString();
    changed = true;
  } else if (String(state.currentWeekId || '') !== String(info.weekId || '')) {
    const oldWeekStart = String(state.weekStart || state.currentWeekId || info.previousWeekStart || '').trim();
    const oldStartDay = oldWeekStart ? fenixWeeklyDayOfWeekFinal(oldWeekStart) : 1;
    const oldWeekEnd = String(
      state.weekEnd ||
      (oldWeekStart ? fenixWeeklyAddDaysFinal(oldWeekStart, oldStartDay === 0 ? 6 : 5) : info.previousWeekEnd)
    ).trim();
    const oldGoal = Number(state.goal || FENIX_WEEKLY_LEGACY_GOAL_POINTS_FINAL);
    const oldMinimum = Number(state.minimum || FENIX_WEEKLY_LEGACY_MINIMUM_POINTS_FINAL);

    fenixCloseWeeklySnapshotFinal(
      data,
      oldWeekStart,
      oldWeekEnd,
      'virada-de-semana',
      oldGoal,
      oldMinimum
    );
    fenixResetWeeklyUsersFinal(data);

    state.currentWeekId = info.weekId;
    state.weekStart = info.weekStart;
    state.weekEnd = info.weekEnd;
    state.goal = info.goal;
    state.minimum = info.minimum;
    state.ruleVersion = info.ruleVersion;
    state.updatedAt = new Date().toISOString();
    changed = true;
  } else {
    const stateChanged =
      String(state.weekStart || '') !== String(info.weekStart || '') ||
      String(state.weekEnd || '') !== String(info.weekEnd || '') ||
      Number(state.goal || 0) !== Number(info.goal || 0) ||
      Number(state.minimum || 0) !== Number(info.minimum || 0) ||
      String(state.ruleVersion || '') !== String(info.ruleVersion || '');

    state.weekStart = info.weekStart;
    state.weekEnd = info.weekEnd;
    state.goal = info.goal;
    state.minimum = info.minimum;
    state.ruleVersion = info.ruleVersion;

    if (stateChanged) {
      state.updatedAt = new Date().toISOString();
      changed = true;
    }
  }

  return { changed, info, state };
}
function fenixBuildKickUrlFinal(value) {
  const clean = String(value || '')
    .trim()
    .replace(/^https?:\/\/kick\.com\//i, '')
    .replace(/^https?:\/\/www\.kick\.com\//i, '')
    .replace(/^kick\.com\//i, '')
    .replace(/^@/, '')
    .trim();

  return clean ? 'https://kick.com/' + clean : '';
}

const FENIX_EXTRA_TAB_NUMBERS_FINAL = [4, 5, 6];

function fenixNormalizeExtraTargetFinal(number, value) {
  const extra = value && typeof value === "object" ? value : {};
  const name = String(extra.name || extra.channel || "").trim();
  const url = String(extra.url || fenixBuildKickUrlFinal(name)).trim();
  const enabled = Boolean(extra.enabled && url);

  return {
    number,
    enabled,
    name,
    url: enabled ? url : "",
    updatedAt: extra.updatedAt || "",
    updatedBy: extra.updatedBy || ""
  };
}

function fenixSetExtraTargetFinal(data, number, payload, updatedBy) {
  const tabNumber = Number(number);

  if (!FENIX_EXTRA_TAB_NUMBERS_FINAL.includes(tabNumber)) {
    throw new Error("Número de aba extra inválido.");
  }

  data.extraTargets =
    data.extraTargets &&
    typeof data.extraTargets === "object" &&
    !Array.isArray(data.extraTargets)
      ? data.extraTargets
      : {};

  const name = String(payload?.name || payload?.channel || "").trim();
  const url = String(payload?.url || fenixBuildKickUrlFinal(name)).trim();
  const enabled = Boolean(payload?.enabled) && Boolean(url);

  const saved = {
    enabled,
    name,
    url: enabled ? url : "",
    updatedAt: new Date().toISOString(),
    updatedBy: String(updatedBy || FENIX_ADMIN_USER)
  };

  data.extraTargets[String(tabNumber)] = saved;

  if (tabNumber === 4) {
    data.extraTarget = { ...saved };
  }

  return fenixNormalizeExtraTargetFinal(tabNumber, saved);
}
function fenixGetExtraTargetsFinal(data) {
  const source =
    data.extraTargets &&
    typeof data.extraTargets === "object" &&
    !Array.isArray(data.extraTargets)
      ? data.extraTargets
      : {};

  const legacy =
    data.extraTarget &&
    typeof data.extraTarget === "object"
      ? data.extraTarget
      : {};

  return FENIX_EXTRA_TAB_NUMBERS_FINAL.map((number) => {
    const saved = source[String(number)] || source[number];
    const value = saved && typeof saved === "object"
      ? saved
      : number === 4
        ? legacy
        : {};

    return fenixNormalizeExtraTargetFinal(number, value);
  });
}

function fenixGetExtraTargetFinal(data) {
  const target = fenixGetExtraTargetsFinal(data).find((item) => item.number === 4);

  return target || fenixNormalizeExtraTargetFinal(4, {});
}
function publicFenixUserSafe(user) {
  return {
    id: user.id,
    username: user.username,
    role: user.role,
    isAdmin: user.role === 'ADMIN',
    points: Number(user.points || 0),
    weeklyPoints: Number(user.weeklyPoints || 0),
    totalMinutes: Number(user.totalMinutes || 0),
    weeklyMinutes: Number(user.weeklyMinutes || 0),
    kickLoggedIn: Boolean(user.kickLoggedIn || user.kickConnected),
    kickConnected: Boolean(user.kickConnected || user.kickLoggedIn),
    kickUsername: user.kickUsername || user.kickName || '',
    kickUserId: user.kickUserId || user.kickId || ''
  };
}

function getCurrentFenixSlot(data, now = new Date()) {
  const slotDate = getFenixDateKey(now);
  const slotHour = getFenixHourKey(now);

  const found = data.schedule.find((slot) => {
    return slot.active !== false && slot.slotDate === slotDate && slot.slotHour === slotHour;
  });

  if (found) return found;

  return {
    id: 'maintenance-' + slotDate + '-' + slotHour,
    slotDate,
    slotHour,
    active: true,
    screen1Name: '',
    screen1Url: '',
    screen1Maintenance: true,
    screen2Name: '',
    screen2Url: '',
    screen2Maintenance: true,
    screen3Name: '',
    screen3Url: '',
    screen3Maintenance: true
  };
}

function fenixSlotToDesktopSlots(slot) {
  return [1, 2, 3].map((number) => {
    const name = slot['screen' + number + 'Name'] || '';
    const url = slot['screen' + number + 'Url'] || '';
    const maintenance = Boolean(slot['screen' + number + 'Maintenance']);

    return {
      id: number,
      title: 'Tela ' + number,
      channel: name,
      url,
      active: !maintenance && Boolean(url || name),
      maintenance
    };
  });
}


function fenixBase64Url(buffer) {
  return Buffer.from(buffer)
    .toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/g, '');
}

function createKickCodeVerifier() {
  return fenixBase64Url(crypto.randomBytes(32));
}

function createKickCodeChallenge(verifier) {
  return fenixBase64Url(crypto.createHash('sha256').update(verifier).digest());
}

function safeKickUserPayload(payload) {
  const rawUser = Array.isArray(payload?.data) ? payload.data[0] : payload?.data || payload?.user || payload;

  return {
    id: String(rawUser?.id || rawUser?.user_id || ''),
    username: String(rawUser?.username || rawUser?.name || rawUser?.slug || rawUser?.channel_slug || ''),
    slug: String(rawUser?.slug || rawUser?.channel_slug || rawUser?.username || '')
  };
}

function publicFenixUser(user, weeklyInfo = fenixWeeklyInfoFinal()) {
  const weeklyPoints = Number(user.weeklyPoints || 0);
  const weeklyMinutes = Number(user.weeklyMinutes || 0);
  const weeklyGoal = Math.max(1, Number(weeklyInfo?.goal || FENIX_WEEKLY_GOAL_POINTS_FINAL));
  const weeklyMinimum = Math.max(0, Number(weeklyInfo?.minimum || FENIX_WEEKLY_MINIMUM_POINTS_FINAL));
  const weeklyPercent = fenixWeeklyPercentFinal(weeklyPoints, weeklyGoal);

  return {
    username: user.username,
    role: user.role,
    isAdmin: user.role === 'ADMIN',
    points: Number(user.points || 0),
    weeklyPoints,
    totalMinutes: Number(user.totalMinutes || 0),
    weeklyMinutes,
    weeklyGoal,
    weeklyMinimum,
    weeklyPercent,
    weeklyMissing: Math.max(0, weeklyMinimum - weeklyPoints),
    weeklyApproved: weeklyPoints >= weeklyMinimum,
    weeklyActive: Boolean(weeklyInfo?.countsWeekly),
    weeklyWeekStart: weeklyInfo?.weekStart || '',
    weeklyWeekEnd: weeklyInfo?.weekEnd || '',
    weeklyRuleVersion: weeklyInfo?.ruleVersion || '1.0.7',
    weeklyMessage: weeklyInfo?.message || 'Conta de domingo 00:00 ate sabado 23:59. Funcionamento e pontuacao 24/7.',
    kickLoggedIn: Boolean(user.kickLoggedIn),
    kickConnected: Boolean(user.kickConnected),
    kickUsername: user.kickUsername || ''
  };
}
function requireFenixAdmin(req, res, next) {
  const adminUsername = String(
    req.headers['x-fenix-admin'] ||
    req.body?.adminUsername ||
    req.query?.adminUsername ||
    ''
  ).trim();

  const adminSecret = String(
    req.headers['x-fenix-admin-secret'] ||
    req.body?.adminSecret ||
    req.query?.adminSecret ||
    ''
  ).trim();

  if (adminUsername.toLowerCase() !== FENIX_ADMIN_USER.toLowerCase()) {
    return res.status(403).json({
      ok: false,
      message: 'Acesso admin negado.'
    });
  }

  if (!FENIX_ADMIN_SECRET || adminSecret !== FENIX_ADMIN_SECRET) {
    return res.status(403).json({
      ok: false,
      message: 'Senha admin invalida.'
    });
  }

  next();
}

app.post('/api/fenix/auth/register-or-login', (req, res) => {
  const username = normalizeFenixUsername(req.body?.username);
  const password = String(req.body?.password || '');
  const deviceId = String(req.body?.deviceId || '').trim();

  if (!username || username.length < 3) {
    return res.status(400).json({ ok: false, message: 'Username precisa ter pelo menos 3 caracteres.' });
  }

  if (!password || password.length < 3) {
    return res.status(400).json({ ok: false, message: 'Senha precisa ter pelo menos 3 caracteres.' });
  }

  const data = readFenixData();
  const now = new Date().toISOString();

  let user = data.users.find((item) => item.username.toLowerCase() === username.toLowerCase());
  let created = false;

  
  if (!user && deviceId) {
    data.deviceLocks = Array.isArray(data.deviceLocks) ? data.deviceLocks : [];

    const existingDeviceLock = data.deviceLocks.find((lock) => {
      return String(lock.deviceId || '') === deviceId;
    });

    if (existingDeviceLock) {
      const lockedUser = data.users.find((item) => item.id === existingDeviceLock.userId);

      return res.status(403).json({
        ok: false,
        message: 'Este app ja possui uma conta Fenix vinculada: ' + (lockedUser?.username || 'usuario existente') + '. Use essa conta ou fale com o admin.'
      });
    }
  }

  if (!user) {
    user = {
      id: crypto.randomUUID(),
      username,
      passwordHash: hashFenixPassword(password),
      role: username.toLowerCase() === FENIX_ADMIN_USER.toLowerCase() ? 'ADMIN' : 'USER',
      points: 0,
      weeklyPoints: 0,
      totalMinutes: 0,
      weeklyMinutes: 0,
      kickLoggedIn: false,
      isOnline: true,
      lastSeenAt: now,
      lastLoginAt: now,
      createdAt: now,
      updatedAt: now
    };

    data.users.push(user);

    if (deviceId) {
      data.deviceLocks = Array.isArray(data.deviceLocks) ? data.deviceLocks : [];
      data.deviceLocks.push({
        deviceId,
        userId: user.id,
        username: user.username,
        createdAt: now
      });
    }
    created = true;
  } else {
    // FENIX_LOGIN_BLOCKED_CHECK_120
    if (user.blocked || user.deleted) {
      return res.status(403).json({ ok: false, message: 'Conta bloqueada ou desativada.' });
    }

    if (!verifyFenixPassword(password, user.passwordHash)) {
      return res.status(401).json({ ok: false, message: 'Senha incorreta.' });
    }

    user.isOnline = true;
    user.lastSeenAt = now;
    user.lastLoginAt = now;
    user.updatedAt = now;
  }

  const session = {
    id: crypto.randomUUID(),
    userId: user.id,
    username: user.username,
    sessionId: crypto.randomUUID(),
    deviceId: String(req.body?.deviceId || crypto.randomUUID()),
    appVersion: String(req.body?.appVersion || '1.0.0'),
    kickLoggedIn: Boolean(user.kickLoggedIn),
    active: true,
    startedAt: now,
    lastSeenAt: now
  };

  data.sessions = data.sessions.filter((item) => !(item.userId === user.id && item.deviceId === session.deviceId));
  data.sessions.push(session);

  writeFenixData(data);

  res.json({
    ok: true,
    created,
    sessionId: session.sessionId,
    user: {
      id: user.id,
      username: user.username,
      role: user.role,
      isAdmin: user.role === 'ADMIN',
      points: user.points,
      weeklyPoints: user.weeklyPoints,
      totalMinutes: user.totalMinutes,
      weeklyMinutes: user.weeklyMinutes,
      kickLoggedIn: user.kickLoggedIn,
      kickConnected: Boolean(user.kickConnected),
      kickUsername: user.kickUsername || ''
    }
  });
});

// FENIX_KICK_OAUTH_ROUTES
app.get('/api/fenix/kick/connect-url', (req, res) => {
  const sessionId = String(req.query?.sessionId || '').trim();

  if (!KICK_CLIENT_ID || !KICK_CLIENT_SECRET) {
    return res.status(500).json({
      ok: false,
      message: 'Kick OAuth nao configurado no servidor.'
    });
  }

  const data = readFenixData();
  const session = data.sessions.find((item) => {
    return item.id === sessionId || item.sessionId === sessionId;
  });

  if (!session) {
    return res.status(401).json({
      ok: false,
      message: 'Sessao Fenix invalida.'
    });
  }

  const user = data.users.find((item) => item.id === session.userId);

  if (!user) {
    return res.status(404).json({
      ok: false,
      message: 'Usuario Fenix nao encontrado.'
    });
  }

  const state = crypto.randomUUID();
  const codeVerifier = createKickCodeVerifier();
  const codeChallenge = createKickCodeChallenge(codeVerifier);

  session.kickOAuthState = state;
  session.kickCodeVerifier = codeVerifier;
  session.kickOAuthStartedAt = new Date().toISOString();

  writeFenixData(data);

  const params = new URLSearchParams({
    response_type: 'code',
    client_id: KICK_CLIENT_ID,
    redirect_uri: KICK_REDIRECT_URI,
    scope: 'user:read',
    state,
    code_challenge: codeChallenge,
    code_challenge_method: 'S256'
  });

  res.json({
    ok: true,
    url: 'https://id.kick.com/oauth/authorize?' + params.toString()
  });
});

app.get('/api/fenix/kick/callback', async (req, res) => {
  const code = String(req.query?.code || '').trim();
  const state = String(req.query?.state || '').trim();

  if (!code || !state) {
    return res.status(400).send('Kick OAuth invalido. Pode fechar esta janela.');
  }

  const data = readFenixData();
  const session = data.sessions.find((item) => item.kickOAuthState === state);

  if (!session) {
    return res.status(401).send('Sessao Fenix nao encontrada. Volte ao app e tente novamente.');
  }

  const user = data.users.find((item) => item.id === session.userId);

  if (!user) {
    return res.status(404).send('Usuario Fenix nao encontrado. Volte ao app e tente novamente.');
  }

  try {
    const tokenRes = await fetch('https://id.kick.com/oauth/token', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded'
      },
      body: new URLSearchParams({
        grant_type: 'authorization_code',
        client_id: KICK_CLIENT_ID,
        client_secret: KICK_CLIENT_SECRET,
        redirect_uri: KICK_REDIRECT_URI,
        code,
        code_verifier: session.kickCodeVerifier || ''
      })
    });

    const tokenData = await tokenRes.json().catch(() => ({}));

    if (!tokenRes.ok || !tokenData.access_token) {
      return res.status(400).send('Erro ao conectar Kick. Volte ao app e tente novamente.');
    }

    const userRes = await fetch('https://api.kick.com/public/v1/users', {
      headers: {
        Authorization: 'Bearer ' + tokenData.access_token
      }
    });

    const kickUserData = await userRes.json().catch(() => ({}));

    if (!userRes.ok) {
      return res.status(400).send('Nao foi possivel ler usuario da Kick.');
    }

    const kickUser = safeKickUserPayload(kickUserData);

    
  // FENIX_ONE_KICK_ONE_FENIX_FINAL
  data.users = Array.isArray(data.users) ? data.users : [];

  const kickIdToLock = String(kickUser.id || kickUser.userId || kickUser.kickUserId || '').trim();
  const kickNameToLock = String(kickUser.username || kickUser.slug || kickUser.name || '').trim();

  const otherUserWithThisKick = data.users.find((item) => {
    if (!item || item.id === user.id) return false;

    const itemKickId = String(item.kickUserId || item.kickId || '').trim();
    const itemKickName = String(item.kickUsername || item.kickName || '').trim().toLowerCase();

    return (
      (kickIdToLock && itemKickId && itemKickId === kickIdToLock) ||
      (kickNameToLock && itemKickName && itemKickName === kickNameToLock.toLowerCase())
    );
  });

  if (otherUserWithThisKick) {
    return res.status(403).send(`
      <html>
        <body style="font-family:Arial;background:#080b12;color:#fff;text-align:center;padding:40px">
          <h1 style="color:#ff4d4d">Kick ja vinculada</h1>
          <p>Essa conta Kick ja esta vinculada em outra conta Fenix.</p>
          <p>Conta Fenix: <b>${otherUserWithThisKick.username}</b></p>
          <p>Use a conta Fenix correta ou fale com o admin.</p>
        </body>
      </html>
    `);
  }

user.kickConnected = true;
    user.kickLoggedIn = true;
    user.kickUserId = kickUser.id;
    user.kickUsername = kickUser.username || kickUser.slug || 'Kick conectada';
    user.kickLinkedAt = new Date().toISOString();

    session.kickOAuthState = '';
    session.kickCodeVerifier = '';
    session.kickOAuthFinishedAt = new Date().toISOString();

    writeFenixData(data);

    res.send(`
      <html>
        <body style="background:#050508;color:#38ff74;font-family:Arial;text-align:center;padding-top:80px;">
          <h1>Kick conectada com sucesso!</h1>
          <p>Conta Kick: ${user.kickUsername}</p>
          <p>Voce ja pode voltar para o Fenix Lurk.</p>
        </body>
      </html>
    `);
  } catch (error) {
    res.status(500).send('Erro interno ao conectar Kick. Volte ao app e tente novamente.');
  }
});

app.get('/api/fenix/app/me', (req, res) => {
  const sessionId = String(req.query?.sessionId || '').trim();

  if (!sessionId) {
    return res.status(400).json({ ok: false, message: 'Sessao Fenix nao informada.' });
  }

  const nowMs = Date.now();
  const cached = FENIX_APP_ME_RESPONSE_CACHE.get(sessionId);

  if (cached && nowMs - cached.time < FENIX_APP_ME_CACHE_MS) {
    return res.json({
      ...cached.payload,
      cached: true,
      memoryOnly: true
    });
  }

  const data = readFenixData();
  const weeklyControl = ensureFenixWeeklyControlFinal(data);

  const session = data.sessions.find((item) => {
    return item.id === sessionId || item.sessionId === sessionId;
  });

  if (!session) {
    if (weeklyControl.changed) writeFenixData(data);
    return res.status(401).json({ ok: false, message: 'Sessao invalida.' });
  }

  const user = data.users.find((item) => item.id === session.userId);

  if (!user) {
    if (weeklyControl.changed) writeFenixData(data);
    return res.status(404).json({ ok: false, message: 'Usuario nao encontrado.' });
  }

  user.isOnline = true;
  user.lastSeenAt = new Date().toISOString();

  if (weeklyControl.changed) {
    writeFenixData(data);
  }

  const payload = {
    ok: true,
    cached: false,
    memoryOnly: !weeklyControl.changed,
    weekly: weeklyControl.info,
    user: publicFenixUser(user, weeklyControl.info)
  };

  FENIX_APP_ME_RESPONSE_CACHE.set(sessionId, {
    time: nowMs,
    payload
  });

  res.json(payload);
});


// FENIX_RESET_ACCESS_FINAL
app.post('/api/fenix/auth/reset-access', (req, res) => {
  const sessionId = String(req.body?.sessionId || '').trim();
  const username = String(req.body?.username || req.body?.userName || '').trim();
  const deviceId = String(req.body?.deviceId || '').trim();

  if (!sessionId && !username && !deviceId) {
    return res.status(400).json({
      ok: false,
      message: 'Sessao, usuario ou dispositivo Fenix nao informado.'
    });
  }

  const data = readFenixData();

  data.sessions = Array.isArray(data.sessions) ? data.sessions : [];
  data.users = Array.isArray(data.users) ? data.users : [];
  data.deviceLocks = Array.isArray(data.deviceLocks) ? data.deviceLocks : [];
  data.kickLocks = Array.isArray(data.kickLocks) ? data.kickLocks : [];

  const session = sessionId
    ? data.sessions.find((item) => item.id === sessionId || item.sessionId === sessionId)
    : null;

  const targetUsername = String(username || session?.username || '').trim().toLowerCase();
  const targetDeviceId = String(deviceId || session?.deviceId || '').trim();

  const targetUsers = data.users.filter((item) => {
    const itemUsername = String(item.username || '').toLowerCase();

    return (
      (session && item.id === session.userId) ||
      (targetUsername && itemUsername === targetUsername)
    );
  });

  const targetUserIds = new Set(targetUsers.map((item) => String(item.id || '')).filter(Boolean));
  const targetKickIds = new Set();
  const targetKickNames = new Set();

  targetUsers.forEach((user) => {
    const kickId = String(user.kickUserId || user.kickId || '').trim();
    const kickName = String(user.kickUsername || user.kickName || '').trim().toLowerCase();

    if (kickId) targetKickIds.add(kickId);
    if (kickName) targetKickNames.add(kickName);

    user.kickLoggedIn = false;
    user.kickConnected = false;
    user.kickUsername = '';
    user.kickName = '';
    user.kickUserId = '';
    user.kickId = '';
    user.kickAccessToken = '';
    user.kickRefreshToken = '';
    user.kickLinkedAt = '';
    user.lastResetAccessAt = new Date().toISOString();
    user.updatedAt = new Date().toISOString();
  });

  const beforeSessions = data.sessions.length;
  data.sessions = data.sessions.filter((item) => {
    const itemSessionId = String(item.id || item.sessionId || '');
    const itemUserId = String(item.userId || '');
    const itemUsername = String(item.username || '').toLowerCase();
    const itemDeviceId = String(item.deviceId || '');

    return !(
      (sessionId && itemSessionId === sessionId) ||
      (itemUserId && targetUserIds.has(itemUserId)) ||
      (targetUsername && itemUsername === targetUsername) ||
      (targetDeviceId && itemDeviceId === targetDeviceId)
    );
  });

  const beforeDeviceLocks = data.deviceLocks.length;
  data.deviceLocks = data.deviceLocks.filter((lock) => {
    const lockUserId = String(lock.userId || '');
    const lockUsername = String(lock.username || '').toLowerCase();
    const lockDeviceId = String(lock.deviceId || '');

    return !(
      (lockUserId && targetUserIds.has(lockUserId)) ||
      (targetUsername && lockUsername === targetUsername) ||
      (targetDeviceId && lockDeviceId === targetDeviceId)
    );
  });

  const beforeKickLocks = data.kickLocks.length;
  data.kickLocks = data.kickLocks.filter((lock) => {
    const lockUserId = String(lock.userId || '');
    const lockUsername = String(lock.username || '').toLowerCase();
    const lockKickId = String(lock.kickUserId || lock.kickId || '').trim();
    const lockKickName = String(lock.kickUsername || lock.kickName || '').trim().toLowerCase();

    return !(
      (lockUserId && targetUserIds.has(lockUserId)) ||
      (targetUsername && lockUsername === targetUsername) ||
      (lockKickId && targetKickIds.has(lockKickId)) ||
      (lockKickName && targetKickNames.has(lockKickName))
    );
  });

  writeFenixData(data);

  return res.json({
    ok: true,
    message: 'Login, sessoes, dispositivo e vinculo Kick resetados. Entre novamente e vincule a Kick.',
    resetUsers: targetUsers.map((user) => user.username),
    resetUsersCount: targetUsers.length,
    removedSessions: beforeSessions - data.sessions.length,
    removedDeviceLocks: beforeDeviceLocks - data.deviceLocks.length,
    removedKickLocks: beforeKickLocks - data.kickLocks.length
  });
});


// FENIX_APP_CURRENT_SCHEDULE_COMPAT_107
app.get('/api/fenix/app/current-schedule', (req, res) => {
  try {
    const data = readFenixData();

    data.schedule = Array.isArray(data.schedule) ? data.schedule : [];
    data.notices = Array.isArray(data.notices) ? data.notices : [];

    const slot = getCurrentFenixSlot(data);
    const slots = fenixSlotToDesktopSlots(slot);
    const notice = data.notices.find((item) => item && item.active !== false && String(item.message || '').trim()) || null;

    res.json({
      ok: true,
      time: new Date().toISOString(),
      slot,
      slots,
      notice: notice
        ? {
            id: notice.id || null,
            message: notice.message || '',
            createdAt: notice.createdAt || null,
            updatedAt: notice.updatedAt || null
          }
        : null
    });
  } catch (error) {
    console.error('Erro em /api/fenix/app/current-schedule:', error);
    res.status(500).json({
      ok: false,
      message: 'Erro ao carregar grade atual.',
      error: error.message || String(error)
    });
  }
});

app.post('/api/fenix/app/complete-cycle', fenixCycleRateLimitFinal, (req, res) => {
  const sessionId = String(req.body?.sessionId || '').trim();
  const cycleKey = String(req.body?.cycleKey || '').trim();
  const kickLoggedIn = Boolean(req.body?.kickLoggedIn);
  const tabsKickLoggedIn = Boolean(req.body?.tabsKickLoggedIn);
  const appVersion = String(req.body?.appVersion || '').trim().slice(0, 30);

  if (!sessionId || !cycleKey) {
    return res.status(400).json({ ok: false, message: 'sessionId e cycleKey sao obrigatorios.' });
  }

  const data = readFenixData();
  const weeklyControl = ensureFenixWeeklyControlFinal(data);

  const session = data.sessions.find((item) => item.sessionId === sessionId && item.active !== false);

  if (!session) {
    if (weeklyControl.changed) writeFenixData(data);
    return res.status(401).json({ ok: false, message: 'Sessao Fenix invalida.' });
  }

  const user = data.users.find((item) => item.id === session.userId);

  if (!user) {
    if (weeklyControl.changed) writeFenixData(data);
    return res.status(404).json({ ok: false, message: 'Usuario Fenix nao encontrado.' });
  }

  if (!fenixAppVersionCanEarnPoints(appVersion)) {
    if (weeklyControl.changed) writeFenixData(data);

    return res.status(426).json({
      ok: false,
      paid: false,
      points: 0,
      updateRequired: true,
      currentVersion: appVersion || 'nao-informada',
      minimumVersion: FENIX_MIN_POINTS_APP_VERSION,
      message: 'Atualizacao obrigatoria. As abas continuam liberadas, mas esta versao nao gera pontos.'
    });
  }

  // FENIX_CYCLE_KICK_LINKED_OK_105
  const cycleKickOk = Boolean(
    kickLoggedIn ||
    tabsKickLoggedIn ||
    session.kickLoggedIn ||
    user.kickLoggedIn ||
    user.kickConnected ||
    user.kickUsername ||
    user.kickName
  );

  if (!cycleKickOk) {
    if (weeklyControl.changed) writeFenixData(data);

    return res.status(403).json({
      ok: false,
      paid: false,
      message: 'Kick nao vinculada ao Fenix. Pontos nao contabilizados.'
    });
  }

  const alreadyPaid = data.cycles.find((item) => item.userId === user.id && item.cycleKey === cycleKey);

  if (alreadyPaid) {
    if (weeklyControl.changed) writeFenixData(data);

    return res.json({
      ok: true,
      paid: false,
      duplicated: true,
      points: 0,
      user: publicFenixUser(user, weeklyControl.info)
    });
  }

  const lastCycleForUser = data.cycles
    .filter((cycle) => String(cycle.userId || '') === String(user.id))
    .map((cycle) => {
      return {
        createdAt: cycle.createdAt,
        time: cycle.createdAt ? new Date(cycle.createdAt).getTime() : 0
      };
    })
    .filter((cycle) => Number.isFinite(cycle.time) && cycle.time > 0)
    .sort((a, b) => b.time - a.time)[0] || null;

  if (lastCycleForUser) {
    const elapsedMs = Date.now() - lastCycleForUser.time;

    if (elapsedMs < FENIX_MIN_CYCLE_INTERVAL_MS) {
      const waitSeconds = Math.ceil((FENIX_MIN_CYCLE_INTERVAL_MS - elapsedMs) / 1000);

      if (weeklyControl.changed) writeFenixData(data);

      return res.status(429).json({
        ok: false,
        message: 'Ciclo ainda nao liberado. Aguarde o tempo minimo.',
        waitSeconds
      });
    }
  }

  const slot = getCurrentFenixSlot(data);
  const desktopSlots = fenixSlotToDesktopSlots(slot);
  const activeScreens = desktopSlots.filter((item) => item.active).length;
  const points = 3;
  const now = new Date().toISOString();
  const countsWeekly = Boolean(weeklyControl.info?.countsWeekly);

  const cycle = {
    id: crypto.randomUUID(),
    userId: user.id,
    username: user.username,
    sessionId,
    cycleKey,
    points,
    minutes: 10,
    activeScreens,
    weeklyCounted: countsWeekly,
    slotDate: slot.slotDate,
    slotHour: slot.slotHour,
    createdAt: now
  };

  data.cycles.push(cycle);

  // Pontuação válida somente no acumulado semanal.

  if (countsWeekly) {
    user.weeklyPoints += points;
    user.weeklyMinutes += 10;
  }

  user.totalMinutes += 10;
  user.isOnline = true;
  user.lastSeenAt = now;
  user.updatedAt = now;

  session.lastSeenAt = now;
  session.kickLoggedIn = true;

  writeFenixData(data);

  res.json({
    ok: true,
    paid: true,
    points,
    activeScreens,
    weeklyCounted: countsWeekly,
    weekly: weeklyControl.info,
    user: publicFenixUser(user, weeklyControl.info)
  });
});


// FENIX_ADMIN_ONLINE_USERS_LAST_CYCLE_FINAL


const FENIX_EXTRA_TAB_STATUS_FINAL = new Set([
  "disabled",
  "closed",
  "loading",
  "loaded",
  "playing",
  "paused",
  "stalled",
  "offline",
  "error"
]);

function fenixNormalizeExtraTabsHeartbeatFinal(value) {
  const list = Array.isArray(value) ? value : [];
  const byNumber = new Map();

  for (const raw of list) {
    const number = Number(raw?.number);
    if (!FENIX_EXTRA_TAB_NUMBERS_FINAL.includes(number)) continue;

    const rawStatus = String(raw?.status || "closed").toLowerCase();
    const status = FENIX_EXTRA_TAB_STATUS_FINAL.has(rawStatus)
      ? rawStatus
      : "error";

    const currentTime = Number(raw?.currentTime);
    const readyState = Number(raw?.readyState);

    byNumber.set(number, {
      number,
      enabled: Boolean(raw?.enabled),
      configured: Boolean(raw?.configured),
      name: String(raw?.name || "").slice(0, 100),
      url: String(raw?.url || "").slice(0, 500),
      currentUrl: String(raw?.currentUrl || "").slice(0, 500),
      status,
      detail: String(raw?.detail || "").slice(0, 200),
      pageLoaded: Boolean(raw?.pageLoaded),
      liveFound: Boolean(raw?.liveFound),
      playerFound: Boolean(raw?.playerFound),
      playing: Boolean(raw?.playing),
      stalled: Boolean(raw?.stalled),
      error: String(raw?.error || "").slice(0, 300),
      currentTime: Number.isFinite(currentTime) ? Math.max(0, currentTime) : 0,
      readyState: Number.isFinite(readyState) ? Math.max(0, Math.floor(readyState)) : 0,
      lastProgressAt: String(raw?.lastProgressAt || "").slice(0, 50),
      checkedAt: String(raw?.checkedAt || "").slice(0, 50)
    });
  }

  return FENIX_EXTRA_TAB_NUMBERS_FINAL.map((number) => {
    return byNumber.get(number) || {
      number,
      enabled: false,
      configured: false,
      name: "",
      url: "",
      currentUrl: "",
      status: "closed",
      detail: "Sem informação do app.",
      pageLoaded: false,
      liveFound: false,
      playerFound: false,
      playing: false,
      stalled: false,
      error: "",
      currentTime: 0,
      readyState: 0,
      lastProgressAt: "",
      checkedAt: ""
    };
  });
}
// FENIX_APP_FAST_HEARTBEAT_FINAL
app.post('/api/fenix/app/heartbeat', fenixHeartbeatRateLimitFinal, (req, res) => {
  const sessionId = String(req.body?.sessionId || '').trim();

  if (!sessionId) {
    return res.status(400).json({
      ok: false,
      message: 'Sessao Fenix nao informada.'
    });
  }

  const data = readFenixData();

  data.users = Array.isArray(data.users) ? data.users : [];
  data.sessions = Array.isArray(data.sessions) ? data.sessions : [];
  data.farmHeartbeats = Array.isArray(data.farmHeartbeats) ? data.farmHeartbeats : [];

  const session = data.sessions.find((item) => {
    return item.id === sessionId || item.sessionId === sessionId;
  });

  if (!session) {
    return res.status(401).json({
      ok: false,
      message: 'Sessao Fenix expirada.'
    });
  }

  const user = data.users.find((item) => {
    return item.id === session.userId ||
      String(item.username || '').toLowerCase() === String(session.username || '').toLowerCase();
  });

  if (!user) {
    return res.status(404).json({
      ok: false,
      message: 'Usuario Fenix nao encontrado.'
    });
  }

  const now = new Date().toISOString();
  const kickConnected = Boolean(user.kickConnected || user.kickLoggedIn || user.kickUsername || user.kickName);
  const tabsLoggedIn = Boolean(req.body?.tabsLoggedIn || req.body?.tabsKickLoggedIn);
  const farmOk = Boolean(kickConnected);
  const appVersion = String(req.body?.appVersion || '').trim().slice(0, 30);
  const deviceId = String(req.body?.deviceId || session.deviceId || '').trim().slice(0, 150);
  const extraTabs = fenixNormalizeExtraTabsHeartbeatFinal(req.body?.extraTabs);
  const versionCanEarnPoints = fenixAppVersionCanEarnPoints(appVersion);

  session.lastSeenAt = now;
  session.updatedAt = now;
  session.kickLoggedIn = kickConnected;
  session.tabsLoggedIn = tabsLoggedIn;

  user.isOnline = true;
  user.lastSeenAt = now;
  user.updatedAt = now;
  user.kickLoggedIn = kickConnected;

  const heartbeat = {
    userId: user.id,
    username: user.username,
    kickUsername: user.kickUsername || user.kickName || '',
    sessionId: session.id || session.sessionId || sessionId,
    appVersion,
    deviceId,
    extraTabs,
    appOnline: true,
    kickConnected,
    tabsLoggedIn,
    farmOk,
    reason: String(req.body?.reason || ''),
    lastSeenAt: now,
    updatedAt: now
  };

  const existingIndex = data.farmHeartbeats.findIndex((item) => {
    return item.userId === user.id ||
      String(item.username || '').toLowerCase() === String(user.username || '').toLowerCase();
  });

  const heartbeatKey = String(user.id || user.username || '').toLowerCase();

  if (heartbeatKey) {
    FENIX_MEMORY_HEARTBEATS.set(heartbeatKey, heartbeat);
    FENIX_MEMORY_HEARTBEATS.set(String(user.username || '').toLowerCase(), heartbeat);
    FENIX_MEMORY_EXTRA_TABS.set(heartbeatKey, heartbeat);
    FENIX_MEMORY_EXTRA_TABS.set(String(user.username || '').toLowerCase(), heartbeat);
  }

  return res.json({
    ok: true,
    saved: false,
    memoryOnly: true,
    updateRequired: !versionCanEarnPoints,
    pointsEnabled: versionCanEarnPoints,
    minimumVersion: FENIX_MIN_POINTS_APP_VERSION,
    heartbeat,
    extraTargets: fenixGetExtraTargetsFinal(data)
  });
});

// FENIX_ADMIN_ONLINE_USERS_FAST_HEARTBEAT_FINAL
app.get('/api/fenix/admin/online-users', requireFenixAdmin, fenixAdminReadRateLimitFinal, (req, res) => {
  const data = readFenixData();

  data.users = Array.isArray(data.users) ? data.users : [];
  data.cycles = Array.isArray(data.cycles) ? data.cycles : [];
  data.farmHeartbeats = Array.isArray(data.farmHeartbeats) ? data.farmHeartbeats : [];

  const weeklyControl = ensureFenixWeeklyControlFinal(data);
  const currentGoal = Number(weeklyControl.info?.goal || FENIX_WEEKLY_GOAL_POINTS_FINAL);
  const currentMinimum = Number(weeklyControl.info?.minimum || FENIX_WEEKLY_MINIMUM_POINTS_FINAL);
  if (weeklyControl.changed) {
    writeFenixData(data);
  }

  const nowMs = Date.now();

  function getTimeMs(value) {
    if (!value) return 0;
    const time = new Date(value).getTime();
    return Number.isFinite(time) ? time : 0;
  }

  function minutesAgo(value) {
    const time = getTimeMs(value);
    if (!time) return null;
    return Math.max(0, Math.floor((nowMs - time) / 60000));
  }

  function findHeartbeat(user) {
    const username = String(user.username || '').toLowerCase();
    const userIdKey = String(user.id || '').toLowerCase();

    const memoryHeartbeat =
      FENIX_MEMORY_HEARTBEATS.get(userIdKey) ||
      FENIX_MEMORY_HEARTBEATS.get(username);

    if (memoryHeartbeat) {
      return memoryHeartbeat;
    }

    return data.farmHeartbeats.find((item) => {
      return item.userId === user.id ||
        String(item.username || '').toLowerCase() === username;
    }) || null;
  }

  // FENIX_ADMIN_LINEAR_INDEX_FINAL
  const lastCycleByUserId = new Map();
  const lastCycleByUsername = new Map();
  const sessionByUserId = new Map();
  const sessionByUsername = new Map();

  function keepNewest(map, key, item, dateValue) {
    const normalizedKey = String(key || '').toLowerCase();
    if (!normalizedKey) return;

    const current = map.get(normalizedKey);
    const candidateTime = getTimeMs(dateValue);

    if (!current || candidateTime >= current.time) {
      map.set(normalizedKey, {
        item,
        time: candidateTime
      });
    }
  }

  for (const cycle of data.cycles) {
    const cycleUser =
      cycle.username ||
      cycle.userName ||
      cycle.farmerUserName ||
      cycle.fenixUsername ||
      cycle.name ||
      '';

    const cycleDate =
      cycle.completedAt ||
      cycle.createdAt ||
      cycle.updatedAt ||
      cycle.finishedAt;

    keepNewest(lastCycleByUserId, cycle.userId, cycle, cycleDate);
    keepNewest(lastCycleByUsername, cycleUser, cycle, cycleDate);
  }

  for (const item of data.sessions) {
    const sessionDate =
      item.lastSeenAt ||
      item.updatedAt ||
      item.createdAt;

    keepNewest(sessionByUserId, item.userId, item, sessionDate);
    keepNewest(sessionByUsername, item.username, item, sessionDate);
  }

  function findLastCycleForUser(user) {
    const byId = lastCycleByUserId.get(String(user.id || '').toLowerCase());
    const byUsername = lastCycleByUsername.get(String(user.username || '').toLowerCase());
    return byId?.item || byUsername?.item || null;
  }
  const users = data.users.map((user) => {
    const heartbeat = findHeartbeat(user);
    const lastCycle = findLastCycleForUser(user);

    const indexedSessionById = sessionByUserId.get(String(user.id || '').toLowerCase());
    const indexedSessionByUsername = sessionByUsername.get(String(user.username || '').toLowerCase());
    const userSession = indexedSessionById?.item || indexedSessionByUsername?.item || null;

    const lastSeenAt =
      heartbeat?.lastSeenAt ||
      heartbeat?.updatedAt ||
      userSession?.lastSeenAt ||
      user.lastSeenAt ||
      null;
    const lastSeenMinutes = minutesAgo(lastSeenAt);

    const lastCycleAt =
      lastCycle?.completedAt ||
      lastCycle?.createdAt ||
      lastCycle?.updatedAt ||
      lastCycle?.finishedAt ||
      user.lastCycleAt ||
      user.lastFarmAt ||
      null;

    const lastCycleMinutes = minutesAgo(lastCycleAt);

    const hasFastSignal = lastSeenMinutes !== null;

    const appOnline = hasFastSignal && lastSeenMinutes <= 2;
    const appWarning = hasFastSignal && lastSeenMinutes > 2 && lastSeenMinutes <= 5;

    const cycleActive = lastCycleMinutes !== null && lastCycleMinutes <= 15;
    const cycleWarning = lastCycleMinutes !== null && lastCycleMinutes > 15 && lastCycleMinutes <= 30;

    const kickConnected = Boolean(user.kickConnected || user.kickLoggedIn || heartbeat?.kickConnected);
    const tabsLoggedIn = Boolean(heartbeat?.tabsLoggedIn);

    const farmOk = Boolean(kickConnected && (appOnline || cycleActive));

    let farmStatus = 'Offline';

    if (farmOk) {
      farmStatus = 'Farm OK';
    } else if (appOnline && !tabsLoggedIn && !cycleActive) {
      farmStatus = 'Abas nao logadas';
    } else if (appOnline && !kickConnected) {
      farmStatus = 'Sem Kick';
    } else if (appWarning || cycleWarning) {
      farmStatus = 'Atenção';
    } else if (!hasFastSignal && cycleActive) {
      farmStatus = kickConnected ? 'Farm OK' : 'Sem Kick';
    }

    const lastTextBase = appOnline || appWarning ? lastSeenMinutes : lastCycleMinutes;
    const lastText = lastTextBase === null
      ? 'Nunca'
      : lastTextBase <= 0
        ? 'Agora'
        : lastTextBase + ' min atrás';

    return {
      id: user.id,
      username: user.username,
      // FENIX_ADMIN_DISABLED_USER_TABLE_126
      blocked: Boolean(user.blocked),
      deleted: Boolean(user.deleted),
      deletedAt: user.deletedAt || '',
      deletedReason: user.deletedReason || '',
      kickUsername: user.kickUsername || user.kickName || heartbeat?.kickUsername || '',
      points: Number(user.points || 0),
      weeklyPoints: Number(user.weeklyPoints || 0),
      totalMinutes: Number(user.totalMinutes || 0),
      weeklyMinutes: Number(user.weeklyMinutes || 0),
      weeklyGoal: currentGoal,
      weeklyMinimum: currentMinimum,
      weeklyPercent: fenixWeeklyPercentFinal(user.weeklyPoints, currentGoal),
      weeklyApproved: Number(user.weeklyPoints || 0) >= currentMinimum,
      weeklyRuleVersion: weeklyControl.info?.ruleVersion || '1.0.7',
      kickConnected,
      kickLoggedIn: kickConnected,
      tabsLoggedIn,
      appVersion: String(heartbeat?.appVersion || ''),
      deviceId: String(heartbeat?.deviceId || userSession?.deviceId || ''),
      extraTabs: Array.isArray(heartbeat?.extraTabs)
        ? heartbeat.extraTabs
        : fenixNormalizeExtraTabsHeartbeatFinal([]),
      extraTabsUpdatedAt: heartbeat?.updatedAt || heartbeat?.lastSeenAt || null,
      online: appOnline || (!hasFastSignal && cycleActive),
      appOnline,
      appWarning,
      farmActive: appOnline || (!hasFastSignal && cycleActive),
      farmOk,
      farmStatus,
      lastSeenAt,
      lastSeenMinutes,
      lastCycleAt,
      lastCycleMinutes,
      lastCycleText: lastText
    };
  });

  return res.json({
    ok: true,
    users
  });
});

app.post('/api/fenix/admin/user-points/reset', requireFenixAdmin, (req, res) => {
  const data = readFenixData();

  const username = normalizeFenixUsername(req.body?.username);

  if (!username) {
    return res.status(400).json({ ok: false, message: 'Usuario nao informado.' });
  }

  const user = data.users.find((item) => {
    return String(item.username || '').toLowerCase() === username.toLowerCase();
  });

  if (!user) {
    return res.status(404).json({ ok: false, message: 'Usuario nao encontrado.' });
  }

  user.points = Math.max(0, Number(req.body?.points || 0));
  user.weeklyPoints = Math.max(0, Number(req.body?.weeklyPoints || 0));
  user.totalMinutes = Math.max(0, Number(req.body?.totalMinutes || 0));
  user.weeklyMinutes = Math.max(0, Number(req.body?.weeklyMinutes || 0));
  user.updatedAt = new Date().toISOString();

  if (req.body?.clearCycles !== false) {
    data.cycles = data.cycles.filter((cycle) => {
      return String(cycle.username || '').toLowerCase() !== username.toLowerCase();
    });
  }

  writeFenixData(data);

  res.json({
    ok: true,
    message: 'Pontos resetados com sucesso.',
    user: {
      username: user.username,
      points: user.points,
      weeklyPoints: user.weeklyPoints,
      totalMinutes: user.totalMinutes,
      weeklyMinutes: user.weeklyMinutes
    }
  });
});

// FENIX_ADMIN_SCHEDULE_BY_DATE_FAST_112
app.get('/api/fenix/admin/schedule', requireFenixAdmin, (req, res) => {
  const data = readFenixData();
  const slotDate = String(req.query?.slotDate || '').trim();
  const startDate = String(req.query?.startDate || '').trim();
  const endDate = String(req.query?.endDate || '').trim();

  data.schedule = Array.isArray(data.schedule) ? data.schedule : [];

  // FENIX_ADMIN_SCHEDULE_WEEK_FILTER_118
  if (startDate && endDate) {
    const schedule = data.schedule.filter((item) => {
      const date = String(item?.slotDate || '');
      return item && date >= startDate && date <= endDate;
    });

    return res.json({ ok: true, schedule, filtered: true, startDate, endDate });
  }

  if (slotDate) {
    const schedule = data.schedule.filter((item) => item && item.slotDate === slotDate);
    return res.json({ ok: true, schedule, filtered: true, slotDate });
  }

  res.json({ ok: true, schedule: data.schedule, filtered: false });
});

app.post('/api/fenix/admin/schedule', requireFenixAdmin, (req, res) => {
  const data = readFenixData();

  const slotDate = String(req.body?.slotDate || getFenixDateKey()).trim();
  const slotHour = String(req.body?.slotHour || getFenixHourKey()).trim();

  let slot = data.schedule.find((item) => item.slotDate === slotDate && item.slotHour === slotHour);

  if (!slot) {
    slot = {
      id: crypto.randomUUID(),
      slotDate,
      slotHour,
      createdBy: FENIX_ADMIN_USER,
      createdAt: new Date().toISOString()
    };

    data.schedule.push(slot);
  }

  slot.screen1Name = String(req.body?.screen1Name || '').trim();
  slot.screen1Url = String(req.body?.screen1Url || '').trim();
  slot.screen1Maintenance = Boolean(req.body?.screen1Maintenance);

  slot.screen2Name = String(req.body?.screen2Name || '').trim();
  slot.screen2Url = String(req.body?.screen2Url || '').trim();
  slot.screen2Maintenance = Boolean(req.body?.screen2Maintenance);

  slot.screen3Name = String(req.body?.screen3Name || '').trim();
  slot.screen3Url = String(req.body?.screen3Url || '').trim();
  slot.screen3Maintenance = Boolean(req.body?.screen3Maintenance);

  slot.active = req.body?.active !== false;
  slot.updatedAt = new Date().toISOString();

  writeFenixData(data);

  res.json({ ok: true, slot });
});



// FENIX_FAST_BULK_SCHEDULE_BACKEND_110
app.post('/api/fenix/admin/schedule/bulk', requireFenixAdmin, (req, res) => {
  const data = readFenixData();

  data.schedule = Array.isArray(data.schedule) ? data.schedule : [];

  const scheduleIndex = new Map();
  for (const item of data.schedule) {
    if (!item) continue;
    scheduleIndex.set(String(item.slotDate || '') + '|' + String(item.slotHour || ''), item);
  }

  const startDate = String(req.body?.startDate || getFenixDateKey()).trim();
  const days = Math.max(1, Math.min(7, Number(req.body?.days || 1)));
  const rows = Array.isArray(req.body?.rows) ? req.body.rows : [];

  if (!rows.length) {
    return res.status(400).json({ ok: false, message: 'Nenhuma linha de grade enviada.' });
  }

  function addDays(dateText, amount) {
    const date = new Date(dateText + 'T12:00:00');
    date.setDate(date.getDate() + amount);
    return date.toISOString().slice(0, 10);
  }

  function buildUrl(name) {
    const value = String(name || '').trim();

    if (!value || value === '-') return '';

    if (value.startsWith('http://') || value.startsWith('https://')) {
      return value;
    }

    return 'https://kick.com/' + value.replace(/^@/, '');
  }

  let saved = 0;

  for (let dayIndex = 0; dayIndex < days; dayIndex++) {
    const slotDate = addDays(startDate, dayIndex);

    for (const row of rows) {
      const slotHour = String(row.slotHour || '').trim();
      if (!/^\d{2}:00$/.test(slotHour)) continue;

      const screen1Name = String(row.screen1Name || '').trim();
      const screen2Name = String(row.screen2Name || '').trim();
      const screen3Name = String(row.screen3Name || '').trim();

      const slotKey = slotDate + '|' + slotHour;
      let slot = scheduleIndex.get(slotKey);

      if (!slot) {
        slot = {
          id: crypto.randomUUID(),
          slotDate,
          slotHour,
          createdBy: FENIX_ADMIN_USER,
          createdAt: new Date().toISOString()
        };

        data.schedule.push(slot);
        scheduleIndex.set(slotKey, slot);
      }

      slot.screen1Name = screen1Name === '-' ? '' : screen1Name;
      slot.screen1Url = buildUrl(screen1Name);
      slot.screen1Maintenance = !slot.screen1Url;

      slot.screen2Name = screen2Name === '-' ? '' : screen2Name;
      slot.screen2Url = buildUrl(screen2Name);
      slot.screen2Maintenance = !slot.screen2Url;

      slot.screen3Name = screen3Name === '-' ? '' : screen3Name;
      slot.screen3Url = buildUrl(screen3Name);
      slot.screen3Maintenance = !slot.screen3Url;

      slot.active = true;
      slot.updatedAt = new Date().toISOString();

      saved++;
    }
  }

  writeFenixData(data);

  res.json({
    ok: true,
    saved,
    days,
    startDate
  });
});
// FENIX_ADMIN_BULK_SCHEDULE_API

app.post('/api/fenix/admin/notice', requireFenixAdmin, (req, res) => {
  const data = readFenixData();

  const message = String(req.body?.message || '').trim();

  if (!message) {
    return res.status(400).json({ ok: false, message: 'Aviso nao informado.' });
  }

  data.notices.forEach((notice) => {
    notice.active = false;
  });

  const notice = {
    id: crypto.randomUUID(),
    message,
    active: true,
    createdBy: FENIX_ADMIN_USER,
    createdAt: new Date().toISOString()
  };

  data.notices.unshift(notice);

  writeFenixData(data);

  res.json({ ok: true, notice });
});
// FIM_FENIX_LURK_CORE_API





// FENIX_WEB_ADMIN_PANEL_FINAL


// FENIX_ADMIN_RESET_PASSWORD_106
app.post('/api/fenix/admin/user-password/reset', requireFenixAdmin, (req, res) => {
  const data = readFenixData();

  const username = normalizeFenixUsername(req.body?.username);
  const newPassword = String(req.body?.newPassword || '').trim();

  if (!username) {
    return res.status(400).json({ ok: false, message: 'Usuario nao informado.' });
  }

  if (newPassword.length < 3) {
    return res.status(400).json({ ok: false, message: 'Nova senha precisa ter pelo menos 3 caracteres.' });
  }

  const user = data.users.find((item) => {
    return String(item.username || '').toLowerCase() === username.toLowerCase();
  });

  if (!user) {
    return res.status(404).json({ ok: false, message: 'Usuario nao encontrado.' });
  }

  user.passwordHash = hashFenixPassword(newPassword);
  user.passwordUpdatedAt = new Date().toISOString();
  user.updatedAt = new Date().toISOString();

  data.sessions = Array.isArray(data.sessions)
    ? data.sessions.filter((session) => session.userId !== user.id)
    : [];

  writeFenixData(data);

  res.json({
    ok: true,
    message: 'Senha resetada com sucesso. O usuario deve entrar novamente com a nova senha.',
    user: { username: user.username }
  });
});




// FENIX_ADMIN_USER_PROFILE_ROUTES_120
function findFenixUserForAdmin120(data, username) {
  const wanted = String(username || '').trim().toLowerCase();
  data.users = Array.isArray(data.users) ? data.users : [];

  return data.users.find((user) => {
    return String(user.username || '').trim().toLowerCase() === wanted;
  }) || null;
}

function publicFenixAdminUserProfile120(user) {
  return {
    id: user.id || '',
    username: user.username || '',
    role: user.role || 'USER',
    email: user.email || '',
    points: Number(user.points || 0),
    weeklyPoints: Number(user.weeklyPoints || 0),
    weeklyMinutes: Number(user.weeklyMinutes || 0),
    totalMinutes: Number(user.totalMinutes || 0),
    kickConnected: Boolean(user.kickConnected || user.kickLoggedIn),
    kickUsername: user.kickUsername || user.kickName || '',
    kickUserId: user.kickUserId || user.kickId || '',
    deviceId: user.deviceId || '',
    appVersion: user.appVersion || '',
    blocked: Boolean(user.blocked),
    deleted: Boolean(user.deleted),
    passwordProtected: Boolean(user.passwordHash),
    createdAt: user.createdAt || '',
    updatedAt: user.updatedAt || '',
    lastSeenAt: user.lastSeenAt || '',
    lastLoginAt: user.lastLoginAt || '',
    passwordUpdatedAt: user.passwordUpdatedAt || '',
    blockedAt: user.blockedAt || '',
    blockedReason: user.blockedReason || '',
    deletedAt: user.deletedAt || '',
    deletedReason: user.deletedReason || ''
  };
}

function clearFenixUserRuntime120(data, user) {
  const userId = String(user.id || '');
  const username = String(user.username || '').toLowerCase();

  data.sessions = Array.isArray(data.sessions)
    ? data.sessions.filter((session) => {
        return String(session.userId || '') !== userId &&
          String(session.username || '').toLowerCase() !== username;
      })
    : [];

  data.farmHeartbeats = Array.isArray(data.farmHeartbeats)
    ? data.farmHeartbeats.filter((item) => {
        return String(item.userId || '') !== userId &&
          String(item.username || '').toLowerCase() !== username;
      })
    : [];
}

app.get('/api/fenix/admin/user/:username', requireFenixAdmin, fenixAdminReadRateLimitFinal, (req, res) => {
  const data = readFenixData();
  const username = normalizeFenixUsername(req.params?.username);
  const user = findFenixUserForAdmin120(data, username);

  if (!user) {
    return res.status(404).json({ ok: false, message: 'Usuario nao encontrado.' });
  }

  // FENIX_ADMIN_USER_PROFILE_SESSION_121
  data.sessions = Array.isArray(data.sessions) ? data.sessions : [];
  data.farmHeartbeats = Array.isArray(data.farmHeartbeats) ? data.farmHeartbeats : [];

  const userId = String(user.id || '');
  const usernameLower = String(user.username || '').toLowerCase();

  function timeMs(value) {
    const time = new Date(value || 0).getTime();
    return Number.isFinite(time) ? time : 0;
  }

  const latestSession = data.sessions
    .filter((session) => {
      return String(session.userId || '') === userId ||
        String(session.username || '').toLowerCase() === usernameLower;
    })
    .sort((a, b) => {
      return timeMs(b.lastSeenAt || b.updatedAt || b.createdAt) -
        timeMs(a.lastSeenAt || a.updatedAt || a.createdAt);
    })[0] || null;

  // FENIX_ADMIN_USER_PROFILE_MEMORY_123
  const memoryHeartbeat =
    FENIX_MEMORY_HEARTBEATS.get(String(user.id || '').toLowerCase()) ||
    FENIX_MEMORY_HEARTBEATS.get(usernameLower) ||
    null;

  const persistedHeartbeat = data.farmHeartbeats
    .filter((item) => {
      return String(item.userId || '') === userId ||
        String(item.username || '').toLowerCase() === usernameLower;
    })
    .sort((a, b) => {
      return timeMs(b.lastSeenAt || b.updatedAt || b.createdAt) -
        timeMs(a.lastSeenAt || a.updatedAt || a.createdAt);
    })[0] || null;

  const latestHeartbeat = memoryHeartbeat || persistedHeartbeat;

  const profile = publicFenixAdminUserProfile120(user);

  // FENIX_ADMIN_USER_PROFILE_VERSION_PRIORITY_124
  profile.appVersion =
    latestHeartbeat?.appVersion ||
    latestSession?.appVersion ||
    profile.appVersion ||
    '';

  profile.deviceId =
    latestHeartbeat?.deviceId ||
    latestSession?.deviceId ||
    profile.deviceId ||
    '';

  profile.lastSeenAt =
    latestHeartbeat?.lastSeenAt ||
    latestHeartbeat?.updatedAt ||
    latestSession?.lastSeenAt ||
    profile.lastSeenAt ||
    '';

  res.json({
    ok: true,
    user: profile
  });
});

app.post('/api/fenix/admin/user/points', requireFenixAdmin, (req, res) => {
  const data = readFenixData();

  const username = normalizeFenixUsername(req.body?.username);
  const weeklyDelta = Number(req.body?.weeklyDelta || 0);
  const totalDelta = Number(req.body?.totalDelta || 0);
  const reason = String(req.body?.reason || '').trim();

  if (!username) {
    return res.status(400).json({ ok: false, message: 'Usuario nao informado.' });
  }

  if (!Number.isFinite(weeklyDelta) || !Number.isFinite(totalDelta)) {
    return res.status(400).json({ ok: false, message: 'Valor de pontos invalido.' });
  }

  if (weeklyDelta === 0 && totalDelta === 0) {
    return res.status(400).json({ ok: false, message: 'Informe pontos para adicionar ou remover.' });
  }

  const user = findFenixUserForAdmin120(data, username);

  if (!user) {
    return res.status(404).json({ ok: false, message: 'Usuario nao encontrado.' });
  }

  const beforeWeekly = Number(user.weeklyPoints || 0);
  const beforeTotal = Number(user.points || 0);

  user.weeklyPoints = Math.max(0, beforeWeekly + weeklyDelta);
  user.points = Math.max(0, beforeTotal + totalDelta);
  user.updatedAt = new Date().toISOString();

  data.adminUserActions = Array.isArray(data.adminUserActions) ? data.adminUserActions : [];
  data.adminUserActions.push({
    id: crypto.randomUUID(),
    type: 'POINTS_ADJUST',
    username: user.username,
    weeklyDelta,
    totalDelta,
    beforeWeekly,
    afterWeekly: user.weeklyPoints,
    beforeTotal,
    afterTotal: user.points,
    reason,
    adminUsername: FENIX_ADMIN_USER,
    createdAt: new Date().toISOString()
  });

  writeFenixData(data);

  res.json({
    ok: true,
    message: 'Pontos atualizados.',
    user: publicFenixAdminUserProfile120(user)
  });
});

app.post('/api/fenix/admin/user/block', requireFenixAdmin, (req, res) => {
  const data = readFenixData();

  const username = normalizeFenixUsername(req.body?.username);
  const blocked = Boolean(req.body?.blocked);
  const reason = String(req.body?.reason || '').trim();

  if (!username) {
    return res.status(400).json({ ok: false, message: 'Usuario nao informado.' });
  }

  const user = findFenixUserForAdmin120(data, username);

  if (!user) {
    return res.status(404).json({ ok: false, message: 'Usuario nao encontrado.' });
  }

  user.blocked = blocked;
  user.blockedReason = blocked ? reason : '';
  user.blockedAt = blocked ? new Date().toISOString() : '';
  user.updatedAt = new Date().toISOString();

  if (blocked) {
    clearFenixUserRuntime120(data, user);
  }

  data.adminUserActions = Array.isArray(data.adminUserActions) ? data.adminUserActions : [];
  data.adminUserActions.push({
    id: crypto.randomUUID(),
    type: blocked ? 'USER_BLOCK' : 'USER_UNBLOCK',
    username: user.username,
    reason,
    adminUsername: FENIX_ADMIN_USER,
    createdAt: new Date().toISOString()
  });

  writeFenixData(data);

  res.json({
    ok: true,
    message: blocked ? 'Conta bloqueada.' : 'Conta desbloqueada.',
    user: publicFenixAdminUserProfile120(user)
  });
});

app.post('/api/fenix/admin/user/delete', requireFenixAdmin, (req, res) => {
  const data = readFenixData();

  const username = normalizeFenixUsername(req.body?.username);
  const confirmUsername = normalizeFenixUsername(req.body?.confirmUsername);
  const permanent = Boolean(req.body?.permanent);
  const reason = String(req.body?.reason || '').trim();

  if (!username) {
    return res.status(400).json({ ok: false, message: 'Usuario nao informado.' });
  }

  if (username.toLowerCase() !== confirmUsername.toLowerCase()) {
    return res.status(400).json({ ok: false, message: 'Confirmacao invalida. Digite o nick exato.' });
  }

  const user = findFenixUserForAdmin120(data, username);

  if (!user) {
    return res.status(404).json({ ok: false, message: 'Usuario nao encontrado.' });
  }

  if (String(user.username || '').toLowerCase() === FENIX_ADMIN_USER.toLowerCase()) {
    return res.status(400).json({ ok: false, message: 'Nao e permitido excluir o admin principal.' });
  }

  data.adminUserActions = Array.isArray(data.adminUserActions) ? data.adminUserActions : [];
  data.adminUserActions.push({
    id: crypto.randomUUID(),
    type: permanent ? 'USER_DELETE_PERMANENT' : 'USER_DISABLE',
    username: user.username,
    reason,
    adminUsername: FENIX_ADMIN_USER,
    createdAt: new Date().toISOString()
  });

  clearFenixUserRuntime120(data, user);

  if (permanent) {
    const userId = String(user.id || '');
    const lowerUsername = String(user.username || '').toLowerCase();

    data.users = Array.isArray(data.users)
      ? data.users.filter((item) => {
          return String(item.id || '') !== userId &&
            String(item.username || '').toLowerCase() !== lowerUsername;
        })
      : [];

    data.deviceLocks = Array.isArray(data.deviceLocks)
      ? data.deviceLocks.filter((item) => {
          return String(item.userId || '') !== userId &&
            String(item.username || '').toLowerCase() !== lowerUsername;
        })
      : [];

    data.cycles = Array.isArray(data.cycles)
      ? data.cycles.filter((item) => {
          return String(item.userId || '') !== userId &&
            String(item.username || '').toLowerCase() !== lowerUsername;
        })
      : [];

    writeFenixData(data);

    return res.json({
      ok: true,
      message: 'Conta excluida definitivamente.'
    });
  }

  user.deleted = true;
  user.blocked = true;
  user.deletedAt = new Date().toISOString();
  user.deletedReason = reason;
  user.updatedAt = new Date().toISOString();

  writeFenixData(data);

  res.json({
    ok: true,
    message: 'Conta desativada.',
    user: publicFenixAdminUserProfile120(user)
  });
});


// FENIX_ADMIN_V2_ROUTE_001

app.get('/admin', (req, res) => {
  res.setHeader('Content-Type', 'text/html; charset=utf-8');
  res.end("<!doctype html>\n<html lang=\"pt-BR\">\n<head>\n  <meta charset=\"utf-8\" />\n  <meta name=\"viewport\" content=\"width=device-width,initial-scale=1\" />\n  <title>Fenix Lurk Admin</title>\n  <style>\n    *{box-sizing:border-box}\n    body{margin:0;font-family:Arial,Helvetica,sans-serif;background:#05070d;color:#fff}\n    header{padding:18px 24px;border-bottom:1px solid rgba(0,255,106,.25);background:#07110c;display:flex;justify-content:space-between;align-items:center;gap:14px}\n    h1{margin:0;color:#00ff6a;font-size:22px}\n    h2{margin:0 0 14px;color:#f5b22a}\n    main{padding:20px;display:grid;gap:16px}\n    .card{border:1px solid rgba(0,255,106,.25);background:rgba(10,15,25,.96);border-radius:16px;padding:16px}\n    .login{display:grid;grid-template-columns:1fr 1fr auto auto;gap:10px;align-items:end}\n    label{display:grid;gap:6px;color:#b8c6d8;font-size:12px;font-weight:900;text-transform:uppercase}\n    input,textarea{width:100%;border:1px solid rgba(255,255,255,.16);border-radius:10px;background:#080b12;color:#fff;padding:11px 12px;font-weight:800}\n    button{border:1px solid rgba(0,255,106,.65);border-radius:10px;background:rgba(0,255,106,.14);color:#fff;padding:11px 14px;cursor:pointer;font-weight:900}\n    button:hover{background:rgba(0,255,106,.25)}\n    .danger{border-color:rgba(255,70,70,.65);background:rgba(255,70,70,.12)}\n    .gold{border-color:rgba(245,178,42,.7);background:rgba(245,178,42,.13)}\n    .grid2{display:grid;grid-template-columns:1fr 1fr;gap:16px}\n    table{width:100%;border-collapse:collapse;font-size:13px}\n    th,td{padding:10px 8px;border-bottom:1px solid rgba(255,255,255,.08);text-align:left}\n    th{color:#00ff6a;background:rgba(0,255,106,.06)}\n    .pill{padding:4px 8px;border-radius:999px;font-size:11px;font-weight:900;display:inline-block}\n    .ok{color:#00ff6a;border:1px solid rgba(0,255,106,.5);background:rgba(0,255,106,.12)}\n    .bad{color:#ff5252;border:1px solid rgba(255,82,82,.5);background:rgba(255,82,82,.12)}\n    .warn{color:#f5b22a;border:1px solid rgba(245,178,42,.5);background:rgba(245,178,42,.12)}\n    .muted{color:#9ba8ba}\n    .row24{display:grid;grid-template-columns:80px 1fr 1fr 1fr auto;gap:8px;margin-bottom:8px;align-items:center}\n    .row24 b{color:#f5b22a}\n    .msg{color:#f5b22a;font-weight:900;margin-top:10px;min-height:20px}\n    @media(max-width:900px){.login,.grid2,.row24{grid-template-columns:1fr}header{display:block}}\n    /* FENIX_ADMIN_COMPACT_TABLES_107_FINAL */\n    main{padding:12px}\n    .grid2{grid-template-columns:1fr !important}\n    .card{padding:12px}\n    table{font-size:11px !important;min-width:980px}\n    th,td{padding:6px 5px !important;vertical-align:middle}\n    th{position:sticky;top:0;z-index:2}\n    .pill{font-size:10px !important;padding:3px 7px !important}\n    #activeUsers>div,#rankingUsers>div{max-height:520px;overflow:auto;border-radius:12px;border:1px solid rgba(255,255,255,.08)}\n    .fenixCompactActions107{display:flex;gap:8px;flex-wrap:wrap;margin:10px 0}\n    .fenixCompactActions107 button{padding:8px 11px;font-size:12px}\n    .fenixStatusSummary107{display:flex;gap:8px;flex-wrap:wrap;margin:10px 0 12px}\n    .fenixStatusBox107{max-height:520px;overflow:auto;border:1px solid rgba(255,255,255,.08);border-radius:12px}\n    @media(max-width:1400px){\n      main{padding:10px}\n      table{font-size:10.5px !important}\n      th,td{padding:5px 4px !important}\n    }\n    /* FENIX_ADMIN_USER_PROFILE_CSS_120 */\n    .fenixUserLink120{border:0;background:transparent;color:#00ff6a;padding:0;font-weight:900;text-decoration:underline;cursor:pointer}\n    .fenixModalBackdrop120{position:fixed;inset:0;background:rgba(0,0,0,.72);z-index:9999;display:none;align-items:flex-start;justify-content:center;padding:32px 14px;overflow:auto}\n    .fenixModal120{width:min(980px,100%);background:#080b12;border:1px solid rgba(0,255,106,.35);border-radius:18px;padding:16px;box-shadow:0 20px 80px rgba(0,0,0,.65)}\n    .fenixModalHead120{display:flex;justify-content:space-between;gap:12px;align-items:center;margin-bottom:12px}\n    .fenixProfileGrid120{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:10px}\n    .fenixProfileItem120{border:1px solid rgba(255,255,255,.09);border-radius:12px;padding:10px;background:rgba(255,255,255,.03);word-break:break-word}\n    .fenixProfileItem120 b{display:block;color:#f5b22a;font-size:11px;text-transform:uppercase;margin-bottom:5px}\n    .fenixActionsGrid120{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:10px;margin-top:12px}\n    .fenixActionsGrid120 input{margin-top:6px}\n    @media(max-width:800px){.fenixProfileGrid120,.fenixActionsGrid120{grid-template-columns:1fr}}\n\n\n  </style>\n</head>\n<body>\n  <header>\n    <div>\n      <h1>Fenix Lurk Admin</h1>\n      <div style=\"color:#f5b22a;font-weight:800;font-size:13px\">Painel externo · atualiza sem trocar o app dos usuarios</div>\n    </div>\n    <div id=\"topStatus\" style=\"color:#f5b22a;font-weight:900\">Desconectado</div>\n  </header>\n\n  <main>\n    <section class=\"card\">\n      <div class=\"login\">\n        <label>Usuario Admin<input id=\"adminUser\" value=\"GokuuMods\" /></label>\n        <label>Senha Admin<input id=\"adminSecret\" type=\"password\" placeholder=\"senha da Railway\" /></label>\n        <button onclick=\"saveLogin()\">Entrar / Salvar</button>\n        <button class=\"danger\" onclick=\"logout()\">Sair</button>\n      </div>\n      <div class=\"msg\" id=\"loginMsg\">Digite a senha admin para liberar o painel.</div>\n    </section>\n\n    <section class=\"grid2\">\n      <div class=\"card\">\n        <h2>Farm ativo agora</h2>\n        <button onclick=\"loadUsers()\">Atualizar usuarios</button>\n        <div id=\"activeUsers\"></div>\n      </div>\n      <div class=\"card\">\n        <h2>Ranking de pontos da semana</h2>\n        <button onclick=\"loadUsers()\">Atualizar ranking</button>\n        <div id=\"rankingUsers\"></div>\n      </div>\n    </section>\n\n    <section class=\"card\">\n      <h2>Grade de lives por horario</h2>\n      <div class=\"muted\">Vazio = app abre kick.com. Com canal = app abre a live agendada.</div>\n      <br />\n      <label>Data<input id=\"slotDate\" type=\"date\" /></label>\n      <br />\n      <button onclick=\"loadSchedule()\">Carregar grade</button>\n      <button class=\"gold\" onclick=\"saveAllVisible()\">Salvar grade inteira</button>\n      <div class=\"msg\" id=\"scheduleMsg\"></div>\n      <div id=\"scheduleRows\"></div>\n    </section>\n\n    <section class=\"card\">\n      <h2>Resetar senha de usuário</h2>\n      <div class=\"muted\">Use quando alguém esquecer a senha. A senha antiga não aparece; você cria uma nova.</div>\n      <br />\n      <div class=\"login\">\n        <label>Nick da conta<input id=\"resetPassUser\" placeholder=\"Ex: GokuuMods\" /></label>\n        <label>Nova senha<input id=\"resetPassNew\" type=\"text\" placeholder=\"Ex: 123456\" /></label>\n        <button class=\"gold\" onclick=\"resetUserPassword()\">Resetar senha</button>\n      </div>\n      <div class=\"msg\" id=\"resetPassMsg\"></div>\n    </section>\n\n    <section class=\"card\">\n      <h2>Aviso para o app</h2>\n      <textarea id=\"noticeText\" rows=\"3\" placeholder=\"Digite o aviso que aparece para os usuarios...\"></textarea>\n      <br /><br />\n      <button onclick=\"saveNotice()\">Salvar aviso</button>\n      <div class=\"msg\" id=\"noticeMsg\"></div>\n    </section>\n  </main>\n\n<script>\nconst API = location.origin;\nconst hours = Array.from({length:24}, (_,i)=>String(i).padStart(2,\"0\")+\":00\");\n\nfunction $(id){return document.getElementById(id)}\n// FENIX_ADMIN_LOCAL_DATE_FIX_110\nfunction today(){\n  const d = new Date();\n  const year = d.getFullYear();\n  const month = String(d.getMonth() + 1).padStart(2, \"0\");\n  const day = String(d.getDate()).padStart(2, \"0\");\n  return year + \"-\" + month + \"-\" + day;\n}\nfunction escapeHtml(v){\n  return String(v || \"\").replace(/[&<>\"']/g, function(m){\n    return {\"&\":\"&amp;\",\"<\":\"&lt;\",\">\":\"&gt;\",'\"':\"&quot;\",\"'\":\"&#039;\"}[m];\n  });\n}\nfunction adminHeaders(){\n  return {\n    \"Content-Type\":\"application/json\",\n    \"x-fenix-admin\": $(\"adminUser\").value.trim() || \"GokuuMods\",\n    \"x-fenix-admin-secret\": $(\"adminSecret\").value.trim()\n  };\n}\nfunction buildKickUrl(name){\n  const clean = String(name || \"\").trim().replace(/^https?:\\/\\/kick\\.com\\//i,\"\").replace(/^kick\\.com\\//i,\"\").replace(/^@/,\"\");\n  return clean ? \"https://kick.com/\" + clean : \"\";\n}\nfunction saveLogin(){\n  localStorage.setItem(\"fenixAdminUser\", $(\"adminUser\").value.trim() || \"GokuuMods\");\n  localStorage.setItem(\"fenixAdminSecret\", $(\"adminSecret\").value.trim());\n  $(\"topStatus\").textContent = \"Admin conectado\";\n  $(\"loginMsg\").textContent = \"Login salvo neste navegador.\";\n  // FENIX_ADMIN_NO_AUTO_LOAD_113\n  // Use os botoes manuais para carregar usuarios, ranking ou grade.\n}\nfunction logout(){\n  localStorage.removeItem(\"fenixAdminSecret\");\n  $(\"adminSecret\").value = \"\";\n  $(\"topStatus\").textContent = \"Desconectado\";\n  $(\"loginMsg\").textContent = \"Senha removida.\";\n}\nasync function apiGet(url){\n  const res = await fetch(API + url, { headers: adminHeaders(), cache:\"no-store\" });\n  const data = await res.json();\n  if(!res.ok || data.ok === false) throw new Error(data.message || \"Erro API\");\n  return data;\n}\nasync function apiPost(url, body){\n  const res = await fetch(API + url, {method:\"POST\",headers:adminHeaders(),body:JSON.stringify(body)});\n  const data = await res.json();\n  if(!res.ok || data.ok === false) throw new Error(data.message || \"Erro API\");\n  return data;\n}\nfunction farmPill(user){\n  if (user.farmOk) return '<span class=\"pill ok\">Farm OK</span>';\n  if (user.farmStatus === \"Atenção\" || user.farmStatus === \"Atencao\") return '<span class=\"pill warn\">Atenção</span>';\n  if (user.online || user.farmActive) return '<span class=\"pill warn\">Incompleto</span>';\n  return '<span class=\"pill bad\">Offline</span>';\n}\nfunction kickPill(user){\n  return (user.kickConnected || user.kickLoggedIn)\n    ? '<span class=\"pill ok\">Sim</span>'\n    : '<span class=\"pill bad\">Nao</span>';\n}\nfunction userTable(users, mode){\n  if(!users.length) return '<p class=\"muted\">Nenhum usuario encontrado.</p>';\n\n  return '<div style=\"overflow:auto\"><table><thead><tr>' +\n    '<th>#</th><th>Usuario</th><th>Kick</th><th>Versao</th><th>PC</th><th>App</th><th>Protecao VM</th><th>Farm</th><th>Kick vinculada</th><th>Ultimo ciclo</th><th>Semana</th><th>Status</th>' +\n    '</tr></thead><tbody>' +\n    users.map(function(u,i){\n      const weekly = Number(u.weeklyPoints || 0);\n      const approved = Boolean(u.weeklyApproved);\n      const version = String(u.appVersion || 'Nao informada');\n      const device = String(u.deviceId || '-');\n      const shortDevice = device === '-' ? '-' : device.slice(0, 20);\n      const parts = version.replace(/^v/i, '').split('.').map(function(value){ return Number(value); });\n      const protectionActive =\n        parts.length === 3 &&\n        parts.every(function(value){ return Number.isFinite(value); }) &&\n        (\n          parts[0] > 1 ||\n          (parts[0] === 1 && parts[1] > 0) ||\n          (parts[0] === 1 && parts[1] === 0 && parts[2] >= 7)\n        );\n\n      const rankingStatus = approved\n        ? '<span class=\"pill ok\">Aprovado 90%</span>'\n        : '<span class=\"pill bad\">Pendente</span>';\n\n      const isDisabled126 = Boolean(u.deleted || u.blocked);\n      const disabledStatus126 = '<span class=\"pill bad\">CONTA DESATIVADA</span>';\n      const status = isDisabled126 ? disabledStatus126 : (mode === 'ranking' ? rankingStatus : farmPill(u));\n\n      const appStatus = u.appOnline\n        ? '<span class=\"pill ok\">ONLINE</span>'\n        : u.appWarning\n          ? '<span class=\"pill warn\">ATENCAO</span>'\n          : '<span class=\"pill bad\">OFFLINE</span>';\n\n      const vmStatus = protectionActive\n        ? '<span class=\"pill ok\">ATIVA</span>'\n        : version === 'Nao informada'\n          ? '<span class=\"pill bad\">SEM SINAL</span>'\n          : '<span class=\"pill warn\">VERSAO ANTIGA</span>';\n\n      return '<tr>' +\n        '<td>'+(i+1)+'</td>' +\n        '<td><!-- FENIX_USER_TABLE_CLICKABLE_120 --><button class=\"fenixUserLink120\" onclick=\"openFenixUserProfile120(decodeURIComponent(\\''+encodeURIComponent(u.username || '-')+'\\'))\">'+escapeHtml(u.username || '-')+'</button></td>' +\n        '<td>'+escapeHtml(u.kickUsername || u.kickName || '-')+'</td>' +\n        '<td>'+escapeHtml(version)+'</td>' +\n        '<td title=\"'+escapeHtml(device)+'\">'+escapeHtml(shortDevice)+'</td>' +\n        '<td>'+appStatus+'</td>' +\n        '<td>'+vmStatus+'</td>' +\n        '<td>'+farmPill(u)+'</td>' +\n        '<td>'+kickPill(u)+'</td>' +\n        '<td>'+escapeHtml(u.lastCycleText || 'Nunca')+'</td>' +\n        '<td>'+weekly+' pts</td>' +\n        '<td>'+status+'</td>' +\n      '</tr>';\n    }).join('') + '</tbody></table></div>';\n}\nasync function loadUsers(){\n  try{\n    const data = await apiGet(\"/api/fenix/admin/online-users\");\n    const users = Array.isArray(data.users) ? data.users : [];\n    const active = users.filter(function(u){ return u.online || u.farmActive || u.farmOk; });\n    const ranking = users.slice().sort(function(a,b){\n      return Number(b.weeklyPoints||0)-Number(a.weeklyPoints||0);\n    });\n\n    $(\"activeUsers\").innerHTML = userTable(active, \"active\");\n    $(\"rankingUsers\").innerHTML = userTable(ranking, \"ranking\");\n    $(\"loginMsg\").textContent = \"Usuarios carregados.\";\n  }catch(e){ $(\"loginMsg\").textContent = e.message; }\n}\nfunction renderSchedule(schedule){\n  const date = $(\"slotDate\").value || today();\n  $(\"scheduleRows\").innerHTML = hours.map(function(hour){\n    const slot = schedule.find(function(s){ return s.slotDate === date && s.slotHour === hour; }) || {};\n    return '<div class=\"row24\" data-hour=\"'+hour+'\"><b>'+hour+'</b>' +\n      '<input data-screen=\"1\" placeholder=\"Tela 1 canal\" value=\"'+escapeHtml(slot.screen1Name || \"\")+'\" />' +\n      '<input data-screen=\"2\" placeholder=\"Tela 2 canal\" value=\"'+escapeHtml(slot.screen2Name || \"\")+'\" />' +\n      '<input data-screen=\"3\" placeholder=\"Tela 3 canal\" value=\"'+escapeHtml(slot.screen3Name || \"\")+'\" />' +\n      '<button onclick=\"saveHour(\\''+hour+'\\')\">Salvar</button></div>';\n  }).join(\"\");\n}\nfunction fenixAdminWeekRange118(dateText){\n  const base = new Date(String(dateText || today()) + \"T12:00:00\");\n  const day = base.getDay();\n  const diffToMonday = day === 0 ? -6 : 1 - day;\n  const monday = new Date(base);\n  monday.setDate(base.getDate() + diffToMonday);\n  const sunday = new Date(monday);\n  sunday.setDate(monday.getDate() + 6);\n\n  function fmt(d){\n    const y = d.getFullYear();\n    const m = String(d.getMonth() + 1).padStart(2, \"0\");\n    const dd = String(d.getDate()).padStart(2, \"0\");\n    return y + \"-\" + m + \"-\" + dd;\n  }\n\n  return { startDate: fmt(monday), endDate: fmt(sunday) };\n}\n\n// FENIX_ADMIN_WEEK_SEARCH_LOAD_118\nasync function loadSchedule(){\n  try{\n    const date = $(\"slotDate\").value || today();\n    const range = fenixAdminWeekRange118(date);\n    const data = await apiGet(\"/api/fenix/admin/schedule?startDate=\" + encodeURIComponent(range.startDate) + \"&endDate=\" + encodeURIComponent(range.endDate));\n    renderSchedule(Array.isArray(data.schedule) ? data.schedule : []);\n    $(\"scheduleMsg\").textContent = \"Grade carregada. Busca pesquisando a semana inteira: \" + range.startDate + \" até \" + range.endDate + \".\";\n  }catch(e){ $(\"scheduleMsg\").textContent = e.message; }\n}\nasync function saveHour(hour){\n  const row = document.querySelector('.row24[data-hour=\"'+hour+'\"]');\n  const date = $(\"slotDate\").value || today();\n  const s1 = row.querySelector('[data-screen=\"1\"]').value.trim();\n  const s2 = row.querySelector('[data-screen=\"2\"]').value.trim();\n  const s3 = row.querySelector('[data-screen=\"3\"]').value.trim();\n\n  try{\n    await apiPost(\"/api/fenix/admin/schedule\", {\n      adminUsername:$(\"adminUser\").value.trim() || \"GokuuMods\",\n      adminSecret:$(\"adminSecret\").value.trim(),\n      slotDate:date,\n      slotHour:hour,\n      screen1Name:s1, screen1Url:buildKickUrl(s1), screen1Maintenance:!s1,\n      screen2Name:s2, screen2Url:buildKickUrl(s2), screen2Maintenance:!s2,\n      screen3Name:s3, screen3Url:buildKickUrl(s3), screen3Maintenance:!s3\n    });\n    $(\"scheduleMsg\").textContent = \"Horario \" + hour + \" salvo.\";\n  }catch(e){ $(\"scheduleMsg\").textContent = e.message; }\n}\n// FENIX_ADMIN_FAST_SAVE_ALL_110\nasync function saveAllVisible(){\n  const date = $(\"slotDate\").value || today();\n\n  const rows = hours.map(function(hour){\n    const row = document.querySelector('.row24[data-hour=\"' + hour + '\"]');\n\n    if (!row) {\n      return {\n        slotHour: hour,\n        screen1Name: \"\",\n        screen2Name: \"\",\n        screen3Name: \"\"\n      };\n    }\n\n    return {\n      slotHour: hour,\n      screen1Name: row.querySelector('[data-screen=\"1\"]').value.trim(),\n      screen2Name: row.querySelector('[data-screen=\"2\"]').value.trim(),\n      screen3Name: row.querySelector('[data-screen=\"3\"]').value.trim()\n    };\n  });\n\n  try{\n    $(\"scheduleMsg\").textContent = \"Salvando grade inteira...\";\n\n    const data = await apiPost(\"/api/fenix/admin/schedule/bulk\", {\n      adminUsername: $(\"adminUser\").value.trim() || \"GokuuMods\",\n      adminSecret: $(\"adminSecret\").value.trim(),\n      startDate: date,\n      days: 1,\n      rows: rows\n    });\n\n    $(\"scheduleMsg\").textContent = data.message || (\"Grade inteira salva. Horarios: \" + rows.length);\n  }catch(e){\n    $(\"scheduleMsg\").textContent = e.message;\n  }\n}\n\nasync function resetUserPassword(){\n  const username = (document.getElementById(\"resetPassUser\") || {}).value || \"\";\n  const newPassword = (document.getElementById(\"resetPassNew\") || {}).value || \"\";\n  const msg = document.getElementById(\"resetPassMsg\");\n\n  if (msg) msg.textContent = \"Resetando senha...\";\n\n  try{\n    const data = await apiPost(\"/api/fenix/admin/user-password/reset\", {\n      adminUsername:$(\"adminUser\").value.trim() || \"GokuuMods\",\n      adminSecret:$(\"adminSecret\").value.trim(),\n      username:username.trim(),\n      newPassword:newPassword.trim()\n    });\n\n    if (msg) msg.textContent = data.message || \"Senha resetada com sucesso.\";\n\n    const passInput = document.getElementById(\"resetPassNew\");\n    if (passInput) passInput.value = \"\";\n  }catch(e){\n    if (msg) msg.textContent = e.message;\n  }\n}\n\nasync function saveNotice(){\n  try{\n    await apiPost(\"/api/fenix/admin/notice\", {\n      adminUsername:$(\"adminUser\").value.trim() || \"GokuuMods\",\n      adminSecret:$(\"adminSecret\").value.trim(),\n      message:$(\"noticeText\").value.trim()\n    });\n    $(\"noticeMsg\").textContent = \"Aviso salvo.\";\n  }catch(e){ $(\"noticeMsg\").textContent = e.message; }\n}\n\n\n\n// FENIX_ADMIN_AUTOCOMPLETE_CHANNELS_106\n(function(){\n  if (window.fenixAdminAutocompleteChannels106) return;\n  window.fenixAdminAutocompleteChannels106 = true;\n\n  const originalRenderSchedule106 = renderSchedule;\n\n  function fenixCleanChannelName106(value){\n    return String(value || \"\")\n      .trim()\n      .replace(/^https?:\\/\\/kick\\.com\\//i, \"\")\n      .replace(/^kick\\.com\\//i, \"\")\n      .replace(/^@/, \"\")\n      .trim();\n  }\n\n  function fenixCollectChannelNames106(schedule){\n    const map = {};\n\n    function add(value){\n      const clean = fenixCleanChannelName106(value);\n      if (!clean) return;\n      if (/^Tela [123] canal$/i.test(clean)) return;\n      map[clean.toLowerCase()] = clean;\n    }\n\n    add($(\"adminUser\") && $(\"adminUser\").value);\n    add(\"GokuuMods\");\n\n    (Array.isArray(schedule) ? schedule : []).forEach(function(slot){\n      add(slot.screen1Name);\n      add(slot.screen2Name);\n      add(slot.screen3Name);\n    });\n\n    return Object.keys(map).sort().map(function(key){ return map[key]; });\n  }\n\n  function fenixApplyAutocomplete106(schedule){\n    let datalist = document.getElementById(\"fenixChannelSuggestions\");\n\n    if (!datalist) {\n      datalist = document.createElement(\"datalist\");\n      datalist.id = \"fenixChannelSuggestions\";\n      document.body.appendChild(datalist);\n    }\n\n    const names = fenixCollectChannelNames106(schedule);\n    datalist.innerHTML = names.map(function(name){\n      return '<option value=\"' + escapeHtml(name) + '\"></option>';\n    }).join(\"\");\n\n    document.querySelectorAll(\"#scheduleRows input[data-screen]\").forEach(function(input){\n      input.setAttribute(\"list\", \"fenixChannelSuggestions\");\n      input.setAttribute(\"autocomplete\", \"off\");\n      input.title = \"Digite parte do nick e escolha uma sugestao\";\n    });\n  }\n\n  renderSchedule = function(schedule){\n    originalRenderSchedule106(schedule);\n    fenixApplyAutocomplete106(schedule);\n  };\n})();\n\n\n// FENIX_ADMIN_GRADE_SEARCH_106\n(function(){\n  if (window.fenixAdminGradeSearch106) return;\n  window.fenixAdminGradeSearch106 = true;\n\n  let fenixLastSchedule106 = [];\n  const originalRenderScheduleSearch106 = renderSchedule;\n\n  function cleanSearch106(value){\n    return String(value || \"\").trim().toLowerCase();\n  }\n\n  function formatDate106(value){\n    const v = String(value || \"\");\n    if (!/^\\d{4}-\\d{2}-\\d{2}$/.test(v)) return v || \"-\";\n    const parts = v.split(\"-\");\n    return parts[2] + \"/\" + parts[1] + \"/\" + parts[0];\n  }\n\n  function getScreens106(slot){\n    return [\n      { tela: \"Tela 1\", nome: slot.screen1Name || \"\", url: slot.screen1Url || \"\" },\n      { tela: \"Tela 2\", nome: slot.screen2Name || \"\", url: slot.screen2Url || \"\" },\n      { tela: \"Tela 3\", nome: slot.screen3Name || \"\", url: slot.screen3Url || \"\" }\n    ];\n  }\n\n  function ensureSearchBox106(){\n    if (document.getElementById(\"fenixGradeSearchBox106\")) return;\n\n    const rows = document.getElementById(\"scheduleRows\");\n    if (!rows || !rows.parentElement) return;\n\n    const box = document.createElement(\"div\");\n    box.id = \"fenixGradeSearchBox106\";\n    box.style.border = \"1px solid rgba(245,178,42,.45)\";\n    box.style.background = \"rgba(245,178,42,.08)\";\n    box.style.borderRadius = \"14px\";\n    box.style.padding = \"14px\";\n    box.style.margin = \"14px 0\";\n\n    box.innerHTML =\n      '<h2 style=\"margin:0 0 10px;color:#f5b22a\">Busca rápida na grade</h2>' +\n      '<div class=\"muted\" style=\"margin-bottom:10px\">Digite parte do nick para achar todos os horários onde ele está na grade.</div>' +\n      '<input id=\"fenixGradeSearchInput106\" placeholder=\"Ex: Gok, Neto, Rafa...\" style=\"margin-bottom:10px\" />' +\n      '<div id=\"fenixGradeSearchResult106\" class=\"muted\">Digite um nome para pesquisar.</div>';\n\n    rows.parentElement.insertBefore(box, rows);\n\n    const input = document.getElementById(\"fenixGradeSearchInput106\");\n    if (input) {\n      input.addEventListener(\"input\", renderSearchResult106);\n    }\n  }\n\n  function renderSearchResult106(){\n    const input = document.getElementById(\"fenixGradeSearchInput106\");\n    const result = document.getElementById(\"fenixGradeSearchResult106\");\n\n    if (!input || !result) return;\n\n    const query = cleanSearch106(input.value);\n\n    if (!query) {\n      result.className = \"muted\";\n      result.innerHTML = \"Digite um nome para pesquisar.\";\n      return;\n    }\n\n    const found = [];\n\n    (Array.isArray(fenixLastSchedule106) ? fenixLastSchedule106 : []).forEach(function(slot){\n      getScreens106(slot).forEach(function(screen){\n        const nome = String(screen.nome || \"\").trim();\n        if (!nome) return;\n\n        if (cleanSearch106(nome).includes(query)) {\n          found.push({\n            slotDate: slot.slotDate || \"\",\n            slotHour: slot.slotHour || \"\",\n            tela: screen.tela,\n            nome: nome,\n            url: screen.url || \"\"\n          });\n        }\n      });\n    });\n\n    if (!found.length) {\n      result.className = \"msg\";\n      result.innerHTML = \"Nenhum horário encontrado para: \" + escapeHtml(input.value);\n      return;\n    }\n\n    found.sort(function(a,b){\n      return String(a.slotDate + a.slotHour + a.tela).localeCompare(String(b.slotDate + b.slotHour + b.tela));\n    });\n\n    result.className = \"\";\n    result.innerHTML =\n      '<table><thead><tr>' +\n      '<th>Data</th><th>Horário</th><th>Tela</th><th>Canal</th><th>Link</th>' +\n      '</tr></thead><tbody>' +\n      found.map(function(item){\n        const link = item.url\n          ? '<a href=\"' + escapeHtml(item.url) + '\" target=\"_blank\" style=\"color:#00ff6a;font-weight:900\">Abrir</a>'\n          : '<span class=\"muted\">-</span>';\n\n        return '<tr>' +\n          '<td>' + escapeHtml(formatDate106(item.slotDate)) + '</td>' +\n          '<td><b>' + escapeHtml(item.slotHour || \"-\") + '</b></td>' +\n          '<td>' + escapeHtml(item.tela) + '</td>' +\n          '<td><b>' + escapeHtml(item.nome) + '</b></td>' +\n          '<td>' + link + '</td>' +\n        '</tr>';\n      }).join(\"\") +\n      '</tbody></table>';\n  }\n\n  renderSchedule = function(schedule){\n    fenixLastSchedule106 = Array.isArray(schedule) ? schedule : [];\n    originalRenderScheduleSearch106(schedule);\n    ensureSearchBox106();\n    renderSearchResult106();\n  };\n})();\n    \n// FENIX_ADMIN_USER_SEARCH_RESTORE_109\n(function(){\n  if (window.fenixAdminUserSearchRestore109) return;\n  window.fenixAdminUserSearchRestore109 = true;\n\n  let fenixUsersCache109 = [];\n\n  function norm109(value){\n    return String(value || '').trim().toLowerCase();\n  }\n\n  function match109(user, query){\n    if (!query) return true;\n    return norm109(user.username).includes(query) || norm109(user.kickUsername || user.kickName).includes(query);\n  }\n\n  function addSearch109(targetId, inputId, placeholder){\n    const target = document.getElementById(targetId);\n    if (!target || document.getElementById(inputId)) return;\n\n    const wrap = document.createElement('div');\n    wrap.style.margin = '12px 0';\n    wrap.innerHTML =\n      '<input id=\"' + inputId + '\" placeholder=\"' + placeholder + '\" ' +\n      'style=\"width:100%;border:1px solid rgba(245,178,42,.55);border-radius:10px;background:#080b12;color:#fff;padding:11px 12px;font-weight:900\" />';\n\n    target.parentElement.insertBefore(wrap, target);\n\n    const input = document.getElementById(inputId);\n    if (input) input.addEventListener('input', renderUsers109);\n  }\n\n  function ensureSearch109(){\n    addSearch109('activeUsers', 'fenixSearchActiveUsers109', 'Pesquisar usuario ou Kick no farm ativo...');\n    addSearch109('rankingUsers', 'fenixSearchRankingUsers109', 'Pesquisar usuario ou Kick no ranking...');\n  }\n\n  function renderUsers109(){\n    ensureSearch109();\n\n    const qActive = norm109((document.getElementById('fenixSearchActiveUsers109') || {}).value);\n    const qRanking = norm109((document.getElementById('fenixSearchRankingUsers109') || {}).value);\n\n    const active = fenixUsersCache109\n      .filter(function(u){ return u.online || u.farmActive || u.farmOk; })\n      .filter(function(u){ return match109(u, qActive); });\n\n    const ranking = fenixUsersCache109\n      .slice()\n      .sort(function(a,b){\n        return Number(b.weeklyPoints||0)-Number(a.weeklyPoints||0);\n      })\n      .filter(function(u){ return match109(u, qRanking); });\n\n    const activeBox = document.getElementById('activeUsers');\n    const rankingBox = document.getElementById('rankingUsers');\n\n    if (activeBox) activeBox.innerHTML = userTable(active, 'active');\n    if (rankingBox) rankingBox.innerHTML = userTable(ranking, 'ranking');\n  }\n\n  // FENIX_ADMIN_FARM_SUMMARY_119\nfunction ensureFarmSummary119(){\n  const activeBox = document.getElementById('activeUsers');\n  const card = activeBox && activeBox.closest('.card');\n  if (!card) return;\n\n  let summary = document.getElementById('fenixFarmSummary119');\n  if (!summary) {\n    summary = document.createElement('div');\n    summary.id = 'fenixFarmSummary119';\n    summary.style.margin = '10px 0 12px';\n    summary.style.display = 'flex';\n    summary.style.flexWrap = 'wrap';\n    summary.style.gap = '8px';\n\n    const button = card.querySelector('button[onclick=\"loadUsers()\"]');\n    if (button) button.insertAdjacentElement('afterend', summary);\n  }\n\n  document.querySelectorAll('.grid2 button[onclick=\"loadUsers()\"]').forEach(function(button){\n    button.textContent = '\u21bb';\n    button.title = 'Atualizar listas';\n    button.setAttribute('aria-label', 'Atualizar listas');\n    button.style.width = '42px';\n    button.style.height = '42px';\n    button.style.padding = '0';\n    button.style.borderRadius = '50%';\n    button.style.fontSize = '24px';\n    button.style.lineHeight = '38px';\n  });\n}\n\nfunction setFarmRefreshState119(loading){\n  document.querySelectorAll('.grid2 button[onclick=\"loadUsers()\"]').forEach(function(button){\n    button.disabled = Boolean(loading);\n    button.style.opacity = loading ? '0.55' : '1';\n  });\n}\n\nfunction updateFarmSummary119(users){\n  ensureFarmSummary119();\n  const list = Array.isArray(users) ? users : [];\n  const total = list.length;\n  const ok = list.filter(function(user){ return Boolean(user.farmOk); }).length;\n  const off = total - ok;\n  const summary = document.getElementById('fenixFarmSummary119');\n\n  if (summary) {\n    summary.innerHTML =\n      '<span class=\"pill warn\">Total: ' + total + '</span>' +\n      '<span class=\"pill ok\">Farm OK: ' + ok + '</span>' +\n      '<span class=\"pill bad\">Farm OFF: ' + off + '</span>';\n  }\n\n  setFarmRefreshState119(false);\n}\nloadUsers = async function(){\n    try{\n      ensureFarmSummary119();\n      setFarmRefreshState119(true);\n      ensureSearch109();\n\n      const data = await apiGet('/api/fenix/admin/online-users');\n      fenixUsersCache109 = Array.isArray(data.users) ? data.users : [];\n\n      renderUsers109();\n      updateFarmSummary119(fenixUsersCache109);\n\n      $('loginMsg').textContent = 'Usuarios carregados.';\n    }catch(e){\n      setFarmRefreshState119(false);\n      $('loginMsg').textContent = e.message;\n    }\n  };\n})();\n\n\n// FENIX_ADMIN_WEEKLY_EXTRA_PANEL_FINAL\n(function(){\n  if (window.fenixAdminWeeklyExtraPanelFinal) return;\n  window.fenixAdminWeeklyExtraPanelFinal = true;\n\n  function ensureWeeklyExtraCardFinal(){\n    if (document.getElementById(\"fenixWeeklyExtraPanelFinal\")) return;\n\n    const main = document.querySelector(\"main\");\n    if (!main) return;\n\n    const section = document.createElement(\"section\");\n    section.className = \"card\";\n    section.id = \"fenixWeeklyExtraPanelFinal\";\n    section.innerHTML =\n      '<h2>Histórico semanal e aba extra</h2>' +\n      '<div class=\"muted\">Semana válida: domingo 00:00 até sábado 23:59. Pontuação 24/7.</div>' +\n      '<br />' +\n      '<div class=\"grid2\">' +\n        '<div>' +\n          '<h2 style=\"font-size:18px\">Aba extra escondida</h2>' +\n          '<label><input id=\"fenixExtraEnabledFinal\" type=\"checkbox\" style=\"width:auto;margin-right:8px\" /> Ativar aba extra</label>' +\n          '<br />' +\n          '<label>Canal da aba extra<input id=\"fenixExtraNameFinal\" placeholder=\"Ex: gokuumods\" /></label>' +\n          '<br />' +\n          '<button class=\"gold\" onclick=\"saveFenixExtraTargetFinal()\">Salvar aba extra</button>' +\n          '<div class=\"msg\" id=\"fenixExtraMsgFinal\"></div>' +\n        '</div>' +\n        '<div>' +\n          '<h2 style=\"font-size:18px\">Semana atual</h2>' +\n          '<div id=\"fenixWeeklyCurrentFinal\" class=\"muted\">Carregando...</div>' +\n        '</div>' +\n      '</div>' +\n      '<br />' +\n      '<button onclick=\"loadFenixWeeklyExtraPanelFinal()\">Atualizar histórico semanal</button>' +\n      '<div id=\"fenixWeeklyHistoryFinal\" style=\"margin-top:12px\"></div>';\n\n    const notice = document.getElementById(\"noticeText\");\n    const noticeCard = notice ? notice.closest(\".card\") : null;\n\n    if (noticeCard && noticeCard.parentElement) {\n      noticeCard.parentElement.insertBefore(section, noticeCard);\n    } else {\n      main.appendChild(section);\n    }\n  }\n\n  function renderWeeklyUsersFinal(users){\n    if (!users || !users.length) return '<p class=\"muted\">Nenhum usuário na semana atual.</p>';\n\n    return '<table><thead><tr><th>#</th><th>Usuário</th><th>Kick</th><th>Pontos</th><th>%</th><th>Status</th></tr></thead><tbody>' +\n      users.map(function(u, i){\n        return '<tr>' +\n          '<td>' + (i + 1) + '</td>' +\n          '<td><b>' + escapeHtml(u.username || '-') + '</b></td>' +\n          '<td>' + escapeHtml(u.kickUsername || '-') + '</td>' +\n          '<td>' + Number(u.points || 0) + '</td>' +\n          '<td>' + Number(u.percent || 0) + '%</td>' +\n          '<td>' + (u.approved ? '<span class=\"pill ok\">LIBERADO</span>' : '<span class=\"pill bad\">NÃO LIBERADO</span>') + '</td>' +\n        '</tr>';\n      }).join(\"\") +\n    '</tbody></table>';\n  }\n\n  function renderHistoryFinal(history){\n    if (!history || !history.length) return '<p class=\"muted\">Nenhuma semana fechada ainda.</p>';\n\n    return history.slice(0, 8).map(function(week){\n      const users = Array.isArray(week.users) ? week.users : [];\n      return '<div style=\"border:1px solid rgba(255,255,255,.1);border-radius:14px;padding:12px;margin:12px 0\">' +\n        '<h2 style=\"font-size:17px;margin-bottom:8px\">Semana ' + escapeHtml(week.weekStart || '-') + ' até ' + escapeHtml(week.weekEnd || '-') + '</h2>' +\n        '<div class=\"muted\">Fechada em: ' + escapeHtml(week.closedAt || '-') + ' · Meta: ' + Number(week.goal || 2592) + ' · Mínimo: ' + Number(week.minimum || 1815) + '</div>' +\n        '<br />' +\n        renderWeeklyUsersFinal(users) +\n      '</div>';\n    }).join(\"\");\n  }\n\n  window.loadFenixWeeklyExtraPanelFinal = async function(){\n    ensureWeeklyExtraCardFinal();\n\n    try {\n      const weekly = await apiGet(\"/api/fenix/admin/weekly-history\");\n      const extra = await apiGet(\"/api/fenix/admin/extra-target\");\n\n      const current = weekly.currentWeek || {};\n      const users = Array.isArray(weekly.users) ? weekly.users : [];\n      const history = Array.isArray(weekly.history) ? weekly.history : [];\n      const target = extra.extraTarget || {};\n\n      const enabled = document.getElementById(\"fenixExtraEnabledFinal\");\n      const name = document.getElementById(\"fenixExtraNameFinal\");\n\n      if (enabled) enabled.checked = Boolean(target.enabled);\n      if (name) name.value = target.name || \"\";\n\n      const currentBox = document.getElementById(\"fenixWeeklyCurrentFinal\");\n      if (currentBox) {\n        currentBox.innerHTML =\n          '<b>Atual:</b> ' + escapeHtml(current.weekStart || '-') + ' até ' + escapeHtml(current.weekEnd || '-') +\n          '<br /><b>Status:</b> ' + escapeHtml(current.message || '') +\n          '<br /><br />' + renderWeeklyUsersFinal(users);\n      }\n\n      const historyBox = document.getElementById(\"fenixWeeklyHistoryFinal\");\n      if (historyBox) historyBox.innerHTML = renderHistoryFinal(history);\n    } catch (e) {\n      const box = document.getElementById(\"fenixWeeklyHistoryFinal\");\n      if (box) box.innerHTML = '<div class=\"msg\">' + escapeHtml(e.message || e) + '</div>';\n    }\n  };\n\n  window.saveFenixExtraTargetFinal = async function(){\n    const enabled = Boolean((document.getElementById(\"fenixExtraEnabledFinal\") || {}).checked);\n    const name = String((document.getElementById(\"fenixExtraNameFinal\") || {}).value || \"\").trim();\n    const msg = document.getElementById(\"fenixExtraMsgFinal\");\n\n    if (msg) msg.textContent = \"Salvando...\";\n\n    try {\n      const data = await apiPost(\"/api/fenix/admin/extra-target\", {\n        adminUsername: $(\"adminUser\").value.trim() || \"GokuuMods\",\n        adminSecret: $(\"adminSecret\").value.trim(),\n        enabled: enabled,\n        name: name,\n        url: buildKickUrl(name)\n      });\n\n      if (msg) msg.textContent = data.message || \"Salvo.\";\n      await loadFenixExtraTargetOnlyFast111();\n    } catch (e) {\n      if (msg) msg.textContent = e.message || String(e);\n    }\n  };\n\n  const originalSaveLoginWeeklyExtraFinal = saveLogin;\n  saveLogin = function(){\n    const result = originalSaveLoginWeeklyExtraFinal.apply(this, arguments);\n    // FENIX_ADMIN_WEEKLY_FAST_LOAD_DISABLED_113\n    return result;\n  };\n\n  ensureWeeklyExtraCardFinal();\n\n  if (document.getElementById(\"adminSecret\") && document.getElementById(\"adminSecret\").value) {\n    // FENIX_ADMIN_WEEKLY_FAST_LOAD_DISABLED_113\n  }\n\n  // FENIX_ADMIN_WEEKLY_INTERVAL_DISABLED_113\n})();\n\n// FENIX_ADMIN_WEEKLY_FAST_LOAD_111\nwindow.loadFenixExtraTargetOnlyFast111 = async function(){\n  try {\n    const extra = await apiGet(\"/api/fenix/admin/extra-target\");\n    const target = extra.extraTarget || {};\n\n    const enabled = document.getElementById(\"fenixExtraEnabledFinal\");\n    const name = document.getElementById(\"fenixExtraNameFinal\");\n    const currentBox = document.getElementById(\"fenixWeeklyCurrentFinal\");\n    const historyBox = document.getElementById(\"fenixWeeklyHistoryFinal\");\n\n    if (enabled) enabled.checked = Boolean(target.enabled);\n    if (name) name.value = target.name || \"\";\n\n    if (currentBox) {\n      currentBox.innerHTML =\n        '<b>Aba extra:</b> ' + (target.enabled ? '<span class=\"pill ok\">ATIVADA</span>' : '<span class=\"pill bad\">DESATIVADA</span>') +\n        '<br /><b>Canal:</b> ' + escapeHtml(target.name || '-') +\n        '<br /><br /><span class=\"muted\">Histórico semanal só carrega quando clicar em Atualizar histórico semanal.</span>';\n    }\n\n    if (historyBox && !historyBox.innerHTML.trim()) {\n      historyBox.innerHTML = '<p class=\"muted\">Clique em Atualizar histórico semanal para carregar os dados da semana.</p>';\n    }\n  } catch (e) {\n    const currentBox = document.getElementById(\"fenixWeeklyCurrentFinal\");\n    if (currentBox) currentBox.innerHTML = '<div class=\"msg\">' + escapeHtml(e.message || e) + '</div>';\n  }\n};\n\n\n// FENIX_ADMIN_EXTRA_TABS_107\n(function(){\n  const extraNumbers107 = [4, 5, 6];\n\n  function extraStatusText107(status){\n    const labels = {\n      disabled: \"DESATIVADA\",\n      closed: \"FECHADA\",\n      loading: \"CARREGANDO\",\n      loaded: \"CARREGADA\",\n      playing: \"REPRODUZINDO\",\n      paused: \"PAUSADA\",\n      stalled: \"TRAVADA\",\n      offline: \"OFFLINE\",\n      error: \"ERRO\"\n    };\n    return labels[String(status || \"\").toLowerCase()] || \"SEM SINAL\";\n  }\n\n  function extraStatusClass107(status){\n    const value = String(status || \"\").toLowerCase();\n    if (value === \"playing\") return \"pill ok\";\n    if (value === \"loading\" || value === \"loaded\" || value === \"paused\") return \"pill warn\";\n    return \"pill bad\";\n  }\n\n  function ensureExtraTabsPanel107(){\n    const section = document.getElementById(\"fenixWeeklyExtraPanelFinal\");\n    if (!section) return false;\n\n    const title = section.querySelector(\"h2\");\n    if (title) title.textContent = \"Histórico semanal e abas extras\";\n\n    const grid = section.querySelector(\".grid2\");\n    const oldColumn = grid && grid.firstElementChild;\n\n    if (oldColumn && !document.getElementById(\"fenixExtraTabsControls107\")) {\n      oldColumn.innerHTML =\n        '<div id=\"fenixExtraTabsControls107\">' +\n          '<h2 style=\"font-size:18px\">Abas extras ocultas</h2>' +\n          '<div class=\"muted\">As abas 4, 5 e 6 são independentes e nunca geram pontos.</div>' +\n          extraNumbers107.map(function(number){\n            return '<div style=\"border:1px solid rgba(245,178,42,.35);border-radius:12px;padding:12px;margin-top:12px\">' +\n              '<h2 style=\"font-size:16px;margin-bottom:10px\">Aba extra ' + number + '</h2>' +\n              '<label><input id=\"fenixExtraEnabled107_' + number + '\" type=\"checkbox\" style=\"width:auto;margin-right:8px\" /> Ativar aba ' + number + '</label>' +\n              '<br />' +\n              '<label>Canal<input id=\"fenixExtraName107_' + number + '\" placeholder=\"Ex: gokuumods\" /></label>' +\n              '<br />' +\n              '<button class=\"gold\" onclick=\"saveFenixExtraTarget107(' + number + ')\">Salvar aba ' + number + '</button>' +\n              '<div class=\"msg\" id=\"fenixExtraMsg107_' + number + '\"></div>' +\n            '</div>';\n          }).join(\"\") +\n        '</div>';\n    }\n\n    if (!document.getElementById(\"fenixExtraTabsStatus107\")) {\n      const statusWrap = document.createElement(\"div\");\n      statusWrap.id = \"fenixExtraTabsStatus107\";\n      statusWrap.style.marginTop = \"18px\";\n      statusWrap.innerHTML =\n        '<h2 style=\"font-size:18px\">Confirmação real das abas extras</h2>' +\n        '<div class=\"muted\">Mostra se a página, a live e o player estão realmente funcionando em cada PC.</div>' +\n        '<br />' +\n        '<button onclick=\"loadFenixExtraTabsStatus107()\">Atualizar status das abas</button>' +\n        '<div class=\"msg\" id=\"fenixExtraTabsStatusMsg107\"></div>' +\n        '<div id=\"fenixExtraTabsStatusTable107\" style=\"margin-top:12px\">' +\n          '<p class=\"muted\">Clique em Atualizar status das abas.</p>' +\n        '</div>';\n\n      const historyButton = Array.from(section.querySelectorAll(\"button\")).find(function(button){\n        return String(button.textContent || \"\").includes(\"Atualizar histórico semanal\");\n      });\n\n      if (historyButton) {\n        historyButton.insertAdjacentElement(\"beforebegin\", statusWrap);\n      } else {\n        section.appendChild(statusWrap);\n      }\n    }\n\n    return true;\n  }\n\n  function fillExtraTargets107(targets){\n    extraNumbers107.forEach(function(number){\n      const target = (Array.isArray(targets) ? targets : []).find(function(item){\n        return Number(item.number) === number;\n      }) || {};\n\n      const enabled = document.getElementById(\"fenixExtraEnabled107_\" + number);\n      const name = document.getElementById(\"fenixExtraName107_\" + number);\n      const msg = document.getElementById(\"fenixExtraMsg107_\" + number);\n\n      if (enabled) enabled.checked = Boolean(target.enabled);\n      if (name) name.value = target.name || \"\";\n      if (msg) {\n        msg.textContent = target.enabled\n          ? \"ATIVADA · Canal: \" + (target.name || \"-\")\n          : \"DESATIVADA · Canal: \" + (target.name || \"-\");\n      }\n    });\n  }\n\n  window.loadFenixExtraTargets107 = async function(){\n    ensureExtraTabsPanel107();\n\n    try {\n      const data = await apiGet(\"/api/fenix/admin/extra-targets\");\n      fillExtraTargets107(data.extraTargets || []);\n      return true;\n    } catch (error) {\n      const msg = document.getElementById(\"fenixExtraMsg107_4\");\n      if (msg) msg.textContent = error.message || String(error);\n      return false;\n    }\n  };\n\n  window.saveFenixExtraTarget107 = async function(number){\n    const enabled = Boolean((document.getElementById(\"fenixExtraEnabled107_\" + number) || {}).checked);\n    const name = String((document.getElementById(\"fenixExtraName107_\" + number) || {}).value || \"\").trim();\n    const msg = document.getElementById(\"fenixExtraMsg107_\" + number);\n\n    if (msg) msg.textContent = \"Salvando...\";\n\n    try {\n      const data = await apiPost(\"/api/fenix/admin/extra-targets/\" + number, {\n        adminUsername: $(\"adminUser\").value.trim() || \"GokuuMods\",\n        adminSecret: $(\"adminSecret\").value.trim(),\n        enabled: enabled,\n        name: name,\n        url: buildKickUrl(name)\n      });\n\n      if (msg) msg.textContent = data.message || \"Salvo.\";\n      fillExtraTargets107(data.extraTargets || []);\n    } catch (error) {\n      if (msg) msg.textContent = error.message || String(error);\n    }\n  };\n\n  window.loadFenixExtraTabsStatus107 = async function(){\n    ensureExtraTabsPanel107();\n\n    const msg = document.getElementById(\"fenixExtraTabsStatusMsg107\");\n    const table = document.getElementById(\"fenixExtraTabsStatusTable107\");\n\n    if (msg) msg.textContent = \"Carregando status...\";\n    if (table) table.innerHTML = \"\";\n\n    try {\n      const data = await apiGet(\"/api/fenix/admin/online-users\");\n      const users = Array.isArray(data.users) ? data.users : [];\n\n      if (!users.length) {\n        if (table) table.innerHTML = '<p class=\"muted\">Nenhum usuário encontrado.</p>';\n        if (msg) msg.textContent = \"Nenhum usuário.\";\n        return;\n      }\n\n      const rows = [];\n\n      users.forEach(function(user){\n        const tabs = Array.isArray(user.extraTabs) ? user.extraTabs : [];\n\n        extraNumbers107.forEach(function(number){\n          const tab = tabs.find(function(item){ return Number(item.number) === number; }) || {};\n          const device = String(user.deviceId || \"-\");\n          const heartbeat = user.extraTabsUpdatedAt\n            ? new Date(user.extraTabsUpdatedAt).toLocaleString(\"pt-BR\")\n            : \"Sem heartbeat\";\n\n          rows.push(\n            '<tr>' +\n              '<td><b>' + escapeHtml(user.username || \"-\") + '</b></td>' +\n              '<td>' + escapeHtml(user.appVersion || \"Versão não informada\") + '</td>' +\n              '<td title=\"' + escapeHtml(device) + '\">' + escapeHtml(device === \"-\" ? device : device.slice(0, 22)) + '</td>' +\n              '<td><b>Aba ' + number + '</b></td>' +\n              '<td>' + escapeHtml(tab.name || \"-\") + '</td>' +\n              '<td><span class=\"' + extraStatusClass107(tab.status) + '\">' + extraStatusText107(tab.status) + '</span></td>' +\n              '<td>' + (tab.playerFound ? \"SIM\" : \"NÃO\") + '</td>' +\n              '<td>' + (tab.playing ? \"SIM\" : \"NÃO\") + '</td>' +\n              '<td>' + escapeHtml(tab.detail || tab.error || \"-\") + '</td>' +\n              '<td>' + escapeHtml(heartbeat) + '</td>' +\n            '</tr>'\n          );\n        });\n      });\n\n      if (table) {\n        table.innerHTML =\n          '<table><thead><tr>' +\n            '<th>Usuário</th><th>Versão</th><th>PC</th><th>Aba</th><th>Canal</th>' +\n            '<th>Status</th><th>Player</th><th>Reproduzindo</th><th>Detalhe</th><th>Heartbeat</th>' +\n          '</tr></thead><tbody>' + rows.join(\"\") + '</tbody></table>';\n      }\n\n      if (msg) msg.textContent = \"Status atualizado agora.\";\n    } catch (error) {\n      if (msg) msg.textContent = error.message || String(error);\n      if (table) table.innerHTML = '<div class=\"msg\">' + escapeHtml(error.message || error) + '</div>';\n    }\n  };\n\n  window.loadFenixExtraTargetOnlyFast111 = async function(){\n    ensureExtraTabsPanel107();\n    await loadFenixExtraTargets107();\n\n    const currentBox = document.getElementById(\"fenixWeeklyCurrentFinal\");\n    const historyBox = document.getElementById(\"fenixWeeklyHistoryFinal\");\n\n    if (currentBox) {\n      currentBox.innerHTML =\n        '<span class=\"muted\">Clique em Atualizar histórico semanal para carregar a semana atual.</span>';\n    }\n\n    if (historyBox && !historyBox.innerHTML.trim()) {\n      historyBox.innerHTML =\n        '<p class=\"muted\">Clique em Atualizar histórico semanal para carregar os dados da semana.</p>';\n    }\n  };\n\n  ensureExtraTabsPanel107();\n})();\n$(\"slotDate\").value = today();\n$(\"adminUser\").value = localStorage.getItem(\"fenixAdminUser\") || \"GokuuMods\";\n$(\"adminSecret\").value = localStorage.getItem(\"fenixAdminSecret\") || \"\";\n\nif($(\"adminSecret\").value){\n  $(\"topStatus\").textContent = \"Admin conectado\";\n  // FENIX_ADMIN_NO_AUTO_LOAD_113\n  // Use os botoes manuais para carregar usuarios, ranking ou grade.\n\n  // FENIX_ADMIN_AUTO_LOAD_EXTRA_ONLY_117\n  // Carrega apenas o estado salvo da aba extra, sem puxar historico/ranking/grade.\n  if (typeof loadFenixExtraTargetOnlyFast111 === \"function\") {\n    setTimeout(loadFenixExtraTargetOnlyFast111, 0);\n  }\n}\n\n// FENIX_ADMIN_COMPACT_STATUS_107_FINAL\n(function(){\n  let fenixStatusUsers107 = [];\n  let fenixStatusFilter107 = \"all\";\n  const FENIX_LATEST_VERSION_STATUS_107 = \"1.0.7\";\n\n  function cleanVersion107(value){\n    return String(value || \"\").trim().replace(/^v/i, \"\");\n  }\n\n  function isLatestVersion107(value){\n    return cleanVersion107(value) === FENIX_LATEST_VERSION_STATUS_107;\n  }\n\n  function statusTextCompact107(status){\n    const labels = {\n      disabled: \"DESATIVADA\",\n      closed: \"FECHADA\",\n      loading: \"CARREGANDO\",\n      loaded: \"CARREGADA\",\n      playing: \"REPRODUZINDO\",\n      paused: \"PAUSADA\",\n      stalled: \"TRAVADA\",\n      offline: \"OFFLINE\",\n      error: \"ERRO\"\n    };\n    return labels[String(status || \"\").toLowerCase()] || \"SEM SINAL\";\n  }\n\n  function statusClassCompact107(status, playing){\n    const value = String(status || \"\").toLowerCase();\n    if (value === \"playing\" && playing) return \"pill ok\";\n    if (value === \"loading\" || value === \"loaded\" || value === \"paused\") return \"pill warn\";\n    return \"pill bad\";\n  }\n\n  function isTabActive107(tab){\n    if (!tab) return false;\n    if (tab.enabled === false) return false;\n    if (String(tab.status || \"\").toLowerCase() === \"disabled\") return false;\n    return Boolean(tab.enabled || tab.name || tab.url);\n  }\n\n  function tabOk107(tab){\n    return Boolean(\n      tab &&\n      tab.playing &&\n      String(tab.status || \"\").toLowerCase() === \"playing\"\n    );\n  }\n\n  function userOk107(item){\n    return item.activeTabs.length > 0 && item.activeTabs.every(tabOk107);\n  }\n\n  function userProblem107(item){\n    return item.activeTabs.length > 0 && !userOk107(item);\n  }\n\n  function matchesCompact107(item){\n    if (fenixStatusFilter107 === \"ok\") return userOk107(item);\n    if (fenixStatusFilter107 === \"problem\") return userProblem107(item);\n    if (fenixStatusFilter107 === \"updated\") return isLatestVersion107(item.version);\n    return true;\n  }\n\n  function escKey107(value){\n    return encodeURIComponent(String(value || \"\"));\n  }\n\n  window.fenixSetExtraStatusFilter107 = function(filter){\n    fenixStatusFilter107 = filter || \"all\";\n    fenixRenderExtraStatusCompact107();\n  };\n\n  window.fenixToggleExtraUser107 = function(key){\n    const row = document.getElementById(\"fenixExtraDetail107_\" + key);\n    if (!row) return;\n    row.style.display = row.style.display === \"none\" ? \"table-row\" : \"none\";\n  };\n\n  window.fenixRenderExtraStatusCompact107 = function(){\n    const table = document.getElementById(\"fenixExtraTabsStatusTable107\");\n    if (!table) return;\n\n    const allUsers = Array.isArray(fenixStatusUsers107) ? fenixStatusUsers107 : [];\n    const usersWithExtras = allUsers.filter(function(item){ return item.activeTabs.length > 0; });\n    const filtered = usersWithExtras.filter(matchesCompact107);\n\n    const totalUsers = allUsers.length;\n    const updated = allUsers.filter(function(item){ return isLatestVersion107(item.version); }).length;\n    const ok = usersWithExtras.filter(userOk107).length;\n    const problem = usersWithExtras.filter(userProblem107).length;\n\n    const summary =\n      '<div class=\"fenixStatusSummary107\">' +\n        '<span class=\"pill warn\">Total usuarios: ' + totalUsers + '</span>' +\n        '<span class=\"pill ok\">Atualizados ' + FENIX_LATEST_VERSION_STATUS_107 + ': ' + updated + '</span>' +\n        '<span class=\"pill warn\">Com extras ativas: ' + usersWithExtras.length + '</span>' +\n        '<span class=\"pill ok\">Tudo OK: ' + ok + '</span>' +\n        '<span class=\"pill bad\">Com problema: ' + problem + '</span>' +\n        '<span class=\"pill warn\">Mostrando: ' + filtered.length + '</span>' +\n      '</div>';\n\n    const actions =\n      '<div class=\"fenixCompactActions107\">' +\n        '<button onclick=\"fenixSetExtraStatusFilter107(\\'all\\')\">Todos com extras</button>' +\n        '<button onclick=\"fenixSetExtraStatusFilter107(\\'ok\\')\">Tudo OK</button>' +\n        '<button onclick=\"fenixSetExtraStatusFilter107(\\'problem\\')\">Com problema</button>' +\n        '<button onclick=\"fenixSetExtraStatusFilter107(\\'updated\\')\">Atualizados ' + FENIX_LATEST_VERSION_STATUS_107 + '</button>' +\n      '</div>';\n\n    if (!filtered.length) {\n      table.innerHTML = summary + actions + '<p class=\"muted\">Nenhum usuario neste filtro.</p>';\n      return;\n    }\n\n    table.innerHTML =\n      summary + actions +\n      '<div class=\"fenixStatusBox107\"><table><thead><tr>' +\n        '<th>Usuario</th><th>Versao</th><th>PC</th><th>Abas ativas</th><th>Status</th><th>Ação</th>' +\n      '</tr></thead><tbody>' +\n      filtered.map(function(item){\n        const key = escKey107(item.key);\n        const okUser = userOk107(item);\n        const status = okUser\n          ? '<span class=\"pill ok\">OK</span>'\n          : '<span class=\"pill bad\">PROBLEMA</span>';\n\n        const tabsText = item.activeTabs.map(function(tab){\n          const good = tabOk107(tab);\n          return '<span class=\"' + (good ? 'pill ok' : 'pill warn') + '\" style=\"margin:2px\">' +\n            'Aba ' + Number(tab.number) + ' ' + (good ? 'OK' : statusTextCompact107(tab.status)) +\n          '</span>';\n        }).join(' ');\n\n        const details =\n          '<tr id=\"fenixExtraDetail107_' + key + '\" style=\"display:none\">' +\n            '<td colspan=\"6\" style=\"background:rgba(255,255,255,.03)\">' +\n              '<div style=\"display:grid;gap:8px\">' +\n                item.activeTabs.map(function(tab){\n                  return '<div style=\"border:1px solid rgba(255,255,255,.09);border-radius:12px;padding:10px\">' +\n                    '<b style=\"color:#f5b22a\">Aba ' + Number(tab.number) + '</b>' +\n                    '<br />Canal: <b>' + escapeHtml(tab.name || '-') + '</b>' +\n                    '<br />Status: <span class=\"' + statusClassCompact107(tab.status, tab.playing) + '\">' + statusTextCompact107(tab.status) + '</span>' +\n                    '<br />Player: ' + (tab.playerFound ? 'SIM' : 'NAO') +\n                    ' · Reproduzindo: ' + (tab.playing ? 'SIM' : 'NAO') +\n                    '<br /><span class=\"muted\">' + escapeHtml(tab.detail || tab.error || '-') + '</span>' +\n                  '</div>';\n                }).join('') +\n                '<div class=\"muted\">Ultimo sinal das extras: ' + escapeHtml(item.heartbeat || '-') + '</div>' +\n              '</div>' +\n            '</td>' +\n          '</tr>';\n\n        return '<tr>' +\n          '<td><b>' + escapeHtml(item.username || \"-\") + '</b></td>' +\n          '<td>' + escapeHtml(item.version || \"Versao nao informada\") + '</td>' +\n          '<td title=\"' + escapeHtml(item.device || \"-\") + '\">' + escapeHtml(item.shortDevice || \"-\") + '</td>' +\n          '<td>' + tabsText + '</td>' +\n          '<td>' + status + '</td>' +\n          '<td><button class=\"gold\" onclick=\"fenixToggleExtraUser107(\\'' + key + '\\')\">Ver detalhes</button></td>' +\n        '</tr>' + details;\n      }).join(\"\") +\n      '</tbody></table></div>';\n  };\n\n  window.loadFenixExtraTabsStatus107 = async function(){\n    const msg = document.getElementById(\"fenixExtraTabsStatusMsg107\");\n    const table = document.getElementById(\"fenixExtraTabsStatusTable107\");\n\n    if (msg) msg.textContent = \"Carregando status...\";\n    if (table) table.innerHTML = \"\";\n\n    try {\n      const data = await apiGet(\"/api/fenix/admin/online-users\");\n      const users = Array.isArray(data.users) ? data.users : [];\n\n      fenixStatusUsers107 = users.map(function(user){\n        const tabs = Array.isArray(user.extraTabs) ? user.extraTabs : [];\n        const device = String(user.deviceId || \"-\");\n        const heartbeat = user.extraTabsUpdatedAt\n          ? new Date(user.extraTabsUpdatedAt).toLocaleString(\"pt-BR\")\n          : \"Sem heartbeat\";\n\n        const normalizedTabs = tabs.map(function(tab){\n          return {\n            number: Number(tab.number || 0),\n            enabled: tab.enabled,\n            name: tab.name || \"-\",\n            url: tab.url || \"\",\n            status: tab.status || \"closed\",\n            playerFound: Boolean(tab.playerFound),\n            playing: Boolean(tab.playing),\n            detail: tab.detail || tab.error || \"Sem informacao do app.\",\n            error: tab.error || \"\"\n          };\n        }).filter(isTabActive107);\n\n        normalizedTabs.sort(function(a,b){ return Number(a.number) - Number(b.number); });\n\n        return {\n          key: String(user.username || \"-\") + \"|\" + device,\n          username: user.username || \"-\",\n          version: user.appVersion || \"Versao nao informada\",\n          device: device,\n          shortDevice: device === \"-\" ? \"-\" : device.slice(0, 22),\n          heartbeat: heartbeat,\n          activeTabs: normalizedTabs\n        };\n      });\n\n      fenixStatusFilter107 = \"all\";\n      fenixRenderExtraStatusCompact107();\n\n      if (msg) msg.textContent = \"Status atualizado agora.\";\n    } catch (error) {\n      if (msg) msg.textContent = error.message || String(error);\n      if (table) table.innerHTML = '<div class=\"msg\">' + escapeHtml(error.message || error) + '</div>';\n    }\n  };\n})();\n\n// FENIX_ADMIN_USER_PROFILE_JS_120\n(function(){\n  if (window.fenixAdminUserProfile120) return;\n  window.fenixAdminUserProfile120 = true;\n\n  let currentProfileUser120 = null;\n\n  function profileText120(value){\n    if (value === true) return \"SIM\";\n    if (value === false) return \"NAO\";\n    return escapeHtml(value || \"-\");\n  }\n\n  function setProfileMsg120(text){\n    const msg = document.getElementById(\"fenixProfileMsg120\");\n    if (msg) msg.textContent = text || \"\";\n  }\n\n  function ensureProfileModal120(){\n    let wrap = document.getElementById(\"fenixUserProfileModal120\");\n    if (wrap) return wrap;\n\n    wrap = document.createElement(\"div\");\n    wrap.id = \"fenixUserProfileModal120\";\n    wrap.className = \"fenixModalBackdrop120\";\n    wrap.innerHTML =\n      '<div class=\"fenixModal120\">' +\n        '<div class=\"fenixModalHead120\">' +\n          '<div>' +\n            '<h2 id=\"fenixProfileTitle120\" style=\"margin:0;color:#00ff6a\">Perfil do usuario</h2>' +\n            '<div class=\"muted\">Alteracoes feitas aqui mudam a conta real no servidor.</div>' +\n          '</div>' +\n          '<button class=\"danger\" onclick=\"closeFenixUserProfile120()\">Fechar</button>' +\n        '</div>' +\n        '<div id=\"fenixProfileMsg120\" class=\"msg\"></div>' +\n        '<div id=\"fenixProfileBody120\"></div>' +\n      '</div>';\n\n    document.body.appendChild(wrap);\n\n    wrap.addEventListener(\"click\", function(event){\n      if (event.target === wrap) closeFenixUserProfile120();\n    });\n\n    return wrap;\n  }\n\n  function renderProfile120(user){\n    currentProfileUser120 = user || {};\n\n    const body = document.getElementById(\"fenixProfileBody120\");\n    const title = document.getElementById(\"fenixProfileTitle120\");\n\n    if (title) title.textContent = \"Perfil: \" + (user.username || \"-\");\n    if (!body) return;\n\n    const status = user.deleted\n      ? '<span class=\"pill bad\">DESATIVADA</span>'\n      : user.blocked\n        ? '<span class=\"pill bad\">BLOQUEADA</span>'\n        : '<span class=\"pill ok\">ATIVA</span>';\n\n    body.innerHTML =\n      '<div class=\"fenixProfileGrid120\">' +\n        '<div class=\"fenixProfileItem120\"><b>Usuario</b>' + profileText120(user.username) + '</div>' +\n        '<div class=\"fenixProfileItem120\"><b>Status</b>' + status + '</div>' +\n        '<div class=\"fenixProfileItem120\"><b>Email</b>' + profileText120(user.email) + '</div>' +\n        '<div class=\"fenixProfileItem120\"><b>Senha</b>PROTEGIDA / HASH</div>' +\n        '<div class=\"fenixProfileItem120\"><b>Kick</b>' + profileText120(user.kickUsername) + '</div>' +\n        '<div class=\"fenixProfileItem120\"><b>Kick vinculada</b>' + profileText120(user.kickConnected) + '</div>' +\n        '<div class=\"fenixProfileItem120\"><b>Pontos semana</b>' + Number(user.weeklyPoints || 0) + '</div>' +\n        '<div class=\"fenixProfileItem120\"><b>Pontos totais</b>' + Number(user.points || 0) + '</div>' +\n        '<div class=\"fenixProfileItem120\"><b>Minutos semana</b>' + Number(user.weeklyMinutes || 0) + '</div>' +\n        '<div class=\"fenixProfileItem120\"><b>Minutos totais</b>' + Number(user.totalMinutes || 0) + '</div>' +\n        '<div class=\"fenixProfileItem120\"><b>Versao app</b>' + profileText120(user.appVersion) + '</div>' +\n        '<div class=\"fenixProfileItem120\"><b>PC / Device</b>' + profileText120(user.deviceId) + '</div>' +\n        '<div class=\"fenixProfileItem120\"><b>Criada em</b>' + profileText120(user.createdAt) + '</div>' +\n        '<div class=\"fenixProfileItem120\"><b>Ultimo login</b>' + profileText120(user.lastLoginAt) + '</div>' +\n        '<div class=\"fenixProfileItem120\"><b>Ultimo sinal</b>' + profileText120(user.lastSeenAt) + '</div>' +\n        '<div class=\"fenixProfileItem120\"><b>Atualizada em</b>' + profileText120(user.updatedAt) + '</div>' +\n      '</div>' +\n\n      '<div class=\"fenixActionsGrid120\">' +\n        '<div class=\"card\" style=\"padding:12px\">' +\n          '<h2 style=\"font-size:16px\">Resetar senha</h2>' +\n          '<input id=\"fenixProfileNewPassword120\" placeholder=\"Nova senha\" />' +\n          '<br /><br /><button class=\"gold\" onclick=\"resetFenixProfilePassword120()\">Resetar senha</button>' +\n        '</div>' +\n\n        '<div class=\"card\" style=\"padding:12px\">' +\n          '<h2 style=\"font-size:16px\">Ajustar pontos</h2>' +\n          '<input id=\"fenixProfileWeeklyDelta120\" type=\"number\" placeholder=\"Semana: 100 ou -100\" />' +\n          '<input id=\"fenixProfileTotalDelta120\" type=\"number\" placeholder=\"Total: 100 ou -100\" />' +\n          '<input id=\"fenixProfilePointsReason120\" placeholder=\"Motivo\" />' +\n          '<br /><br /><button class=\"gold\" onclick=\"adjustFenixProfilePoints120()\">Aplicar pontos</button>' +\n        '</div>' +\n\n        '<div class=\"card\" style=\"padding:12px\">' +\n          '<h2 style=\"font-size:16px\">Bloqueio</h2>' +\n          '<input id=\"fenixProfileBlockReason120\" placeholder=\"Motivo\" />' +\n          '<br /><br />' +\n          (user.blocked\n            ? '<button class=\"gold\" onclick=\"setFenixProfileBlock120(false)\">Desbloquear conta</button>'\n            : '<button class=\"danger\" onclick=\"setFenixProfileBlock120(true)\">Bloquear conta</button>') +\n        '</div>' +\n\n        '<div class=\"card\" style=\"padding:12px\">' +\n          '<h2 style=\"font-size:16px\">Excluir / desativar</h2>' +\n          '<div class=\"muted\">Para confirmar, digite exatamente: <b>' + escapeHtml(user.username || \"\") + '</b></div>' +\n          '<input id=\"fenixProfileDeleteConfirm120\" placeholder=\"Digite o nick exato\" />' +\n          '<input id=\"fenixProfileDeleteReason120\" placeholder=\"Motivo\" />' +\n          '<br /><br />' +\n          '<button class=\"danger\" onclick=\"deleteFenixProfileUser120(false)\">Desativar conta</button> ' +\n          '<button class=\"danger\" onclick=\"deleteFenixProfileUser120(true)\">Excluir definitivo</button>' +\n        '</div>' +\n      '</div>';\n  }\n\n  window.closeFenixUserProfile120 = function(){\n    const wrap = document.getElementById(\"fenixUserProfileModal120\");\n    if (wrap) wrap.style.display = \"none\";\n  };\n\n  window.openFenixUserProfile120 = async function(username){\n    const wrap = ensureProfileModal120();\n    const body = document.getElementById(\"fenixProfileBody120\");\n\n    wrap.style.display = \"flex\";\n    if (body) body.innerHTML = \"\";\n    setProfileMsg120(\"Carregando perfil...\");\n\n    try {\n      const data = await apiGet(\"/api/fenix/admin/user/\" + encodeURIComponent(username));\n      renderProfile120(data.user || {});\n      setProfileMsg120(\"Perfil carregado.\");\n    } catch (error) {\n      setProfileMsg120(error.message || String(error));\n    }\n  };\n\n  async function reloadCurrentProfile120(message){\n    if (!currentProfileUser120 || !currentProfileUser120.username) return;\n\n    const data = await apiGet(\"/api/fenix/admin/user/\" + encodeURIComponent(currentProfileUser120.username));\n    renderProfile120(data.user || currentProfileUser120);\n    setProfileMsg120(message || \"Atualizado.\");\n\n    if (typeof loadUsers === \"function\") {\n      await loadUsers();\n    }\n  }\n\n  window.resetFenixProfilePassword120 = async function(){\n    if (!currentProfileUser120 || !currentProfileUser120.username) return;\n\n    const input = document.getElementById(\"fenixProfileNewPassword120\");\n    const newPassword = String(input && input.value || \"\").trim();\n\n    if (newPassword.length < 3) {\n      setProfileMsg120(\"Nova senha precisa ter pelo menos 3 caracteres.\");\n      return;\n    }\n\n    await apiPost(\"/api/fenix/admin/user-password/reset\", {\n      adminUsername: $(\"adminUser\").value.trim() || \"GokuuMods\",\n      adminSecret: $(\"adminSecret\").value.trim(),\n      username: currentProfileUser120.username,\n      newPassword: newPassword\n    });\n\n    if (input) input.value = \"\";\n    await reloadCurrentProfile120(\"Senha resetada. Usuario deve entrar novamente.\");\n  };\n\n  window.adjustFenixProfilePoints120 = async function(){\n    if (!currentProfileUser120 || !currentProfileUser120.username) return;\n\n    const weeklyDelta = Number((document.getElementById(\"fenixProfileWeeklyDelta120\") || {}).value || 0);\n    const totalDelta = Number((document.getElementById(\"fenixProfileTotalDelta120\") || {}).value || 0);\n    const reason = String((document.getElementById(\"fenixProfilePointsReason120\") || {}).value || \"\").trim();\n\n    await apiPost(\"/api/fenix/admin/user/points\", {\n      adminUsername: $(\"adminUser\").value.trim() || \"GokuuMods\",\n      adminSecret: $(\"adminSecret\").value.trim(),\n      username: currentProfileUser120.username,\n      weeklyDelta: weeklyDelta,\n      totalDelta: totalDelta,\n      reason: reason\n    });\n\n    await reloadCurrentProfile120(\"Pontos atualizados.\");\n  };\n\n  window.setFenixProfileBlock120 = async function(blocked){\n    if (!currentProfileUser120 || !currentProfileUser120.username) return;\n\n    const reason = String((document.getElementById(\"fenixProfileBlockReason120\") || {}).value || \"\").trim();\n\n    await apiPost(\"/api/fenix/admin/user/block\", {\n      adminUsername: $(\"adminUser\").value.trim() || \"GokuuMods\",\n      adminSecret: $(\"adminSecret\").value.trim(),\n      username: currentProfileUser120.username,\n      blocked: Boolean(blocked),\n      reason: reason\n    });\n\n    await reloadCurrentProfile120(blocked ? \"Conta bloqueada.\" : \"Conta desbloqueada.\");\n  };\n\n  window.deleteFenixProfileUser120 = async function(permanent){\n    if (!currentProfileUser120 || !currentProfileUser120.username) return;\n\n    const confirmUsername = String((document.getElementById(\"fenixProfileDeleteConfirm120\") || {}).value || \"\").trim();\n    const reason = String((document.getElementById(\"fenixProfileDeleteReason120\") || {}).value || \"\").trim();\n\n    const text = permanent\n      ? \"Tem certeza que deseja EXCLUIR DEFINITIVO?\"\n      : \"Tem certeza que deseja DESATIVAR esta conta?\";\n\n    if (!confirm(text)) return;\n\n    const data = await apiPost(\"/api/fenix/admin/user/delete\", {\n      adminUsername: $(\"adminUser\").value.trim() || \"GokuuMods\",\n      adminSecret: $(\"adminSecret\").value.trim(),\n      username: currentProfileUser120.username,\n      confirmUsername: confirmUsername,\n      permanent: Boolean(permanent),\n      reason: reason\n    });\n\n    setProfileMsg120(data.message || \"Conta alterada.\");\n\n    if (permanent) {\n      closeFenixUserProfile120();\n      if (typeof loadUsers === \"function\") await loadUsers();\n      return;\n    }\n\n    await reloadCurrentProfile120(data.message || \"Conta desativada.\");\n  };\n})();\n\n\n\n\n// FENIX_ADMIN_PROFILE_PASSWORD_MSG_127\n(function(){\n  function msg127(text){\n    const box = document.getElementById(\"fenixProfileMsg120\");\n    if (box) {\n      box.textContent = text || \"\";\n      box.scrollIntoView({ behavior: \"smooth\", block: \"nearest\" });\n    }\n  }\n\n  window.resetFenixProfilePassword120 = async function(){\n    try {\n      if (!currentProfileUser120 || !currentProfileUser120.username) {\n        msg127(\"Usuario do perfil nao encontrado. Feche e abra o perfil novamente.\");\n        return;\n      }\n\n      const input = document.getElementById(\"fenixProfileNewPassword120\");\n      const newPassword = String(input && input.value || \"\").trim();\n\n      if (newPassword.length < 3) {\n        msg127(\"Nova senha precisa ter pelo menos 3 caracteres.\");\n        if (input) input.focus();\n        return;\n      }\n\n      msg127(\"Resetando senha...\");\n\n      const data = await apiPost(\"/api/fenix/admin/user-password/reset\", {\n        adminUsername: $(\"adminUser\").value.trim() || \"GokuuMods\",\n        adminSecret: $(\"adminSecret\").value.trim(),\n        username: currentProfileUser120.username,\n        newPassword: newPassword\n      });\n\n      if (input) input.value = \"\";\n\n      msg127(data.message || \"Senha resetada com sucesso. Usuario deve entrar novamente.\");\n\n      if (typeof loadUsers === \"function\") {\n        await loadUsers();\n      }\n    } catch (error) {\n      msg127(error.message || String(error));\n    }\n  };\n})();\n// FENIX_ADMIN_DELETE_MODAL_FIX_125\n(function(){\n  function msg125(text){\n    const box = document.getElementById(\"fenixProfileMsg120\");\n    if (box) {\n      box.textContent = text || \"\";\n      box.scrollIntoView({ behavior: \"smooth\", block: \"nearest\" });\n    }\n  }\n\n  function currentUsername125(){\n    const title = document.getElementById(\"fenixProfileTitle120\");\n    return String(title && title.textContent || \"\")\n      .replace(/^Perfil:\\s*/i, \"\")\n      .trim();\n  }\n\n  window.deleteFenixProfileUser120 = async function(permanent){\n    const username = currentUsername125();\n    const confirmInput = document.getElementById(\"fenixProfileDeleteConfirm120\");\n    const reasonInput = document.getElementById(\"fenixProfileDeleteReason120\");\n\n    const confirmUsername = String(confirmInput && confirmInput.value || \"\").trim();\n    const reason = String(reasonInput && reasonInput.value || \"\").trim();\n\n    if (!username || username === \"-\") {\n      msg125(\"Usuario do perfil nao encontrado. Feche e abra o perfil novamente.\");\n      return;\n    }\n\n    if (confirmUsername.toLowerCase() !== username.toLowerCase()) {\n      msg125(\"Confirmacao invalida. Digite exatamente: \" + username);\n      if (confirmInput) confirmInput.focus();\n      return;\n    }\n\n    const text = permanent\n      ? \"Tem certeza que deseja EXCLUIR DEFINITIVO esta conta?\"\n      : \"Tem certeza que deseja DESATIVAR esta conta?\";\n\n    if (!confirm(text)) return;\n\n    msg125(permanent ? \"Excluindo conta...\" : \"Desativando conta...\");\n\n    try {\n      const data = await apiPost(\"/api/fenix/admin/user/delete\", {\n        adminUsername: $(\"adminUser\").value.trim() || \"GokuuMods\",\n        adminSecret: $(\"adminSecret\").value.trim(),\n        username: username,\n        confirmUsername: confirmUsername,\n        permanent: Boolean(permanent),\n        reason: reason\n      });\n\n      msg125(data.message || \"Conta alterada.\");\n\n      if (typeof loadUsers === \"function\") {\n        await loadUsers();\n      }\n\n      if (permanent) {\n        if (typeof closeFenixUserProfile120 === \"function\") {\n          closeFenixUserProfile120();\n        }\n        return;\n      }\n\n      if (typeof openFenixUserProfile120 === \"function\") {\n        await openFenixUserProfile120(username);\n      }\n    } catch (error) {\n      msg125(error.message || String(error));\n    }\n  };\n})();\n// FENIX_ADMIN_AUTO_REFRESH_30S_FINAL\n// FENIX_ADMIN_AUTO_REFRESH_DISABLED_113\n\n</script>\n</body>\n</html>");
});

// FENIX_FORM_GRADE_SORTEIO_FINAL
const FENIX_FORM_DAYS = [
  { key: 'domingo', label: 'Domingo' },
  { key: 'segunda', label: 'Segunda' },
  { key: 'terca', label: 'Terça' },
  { key: 'quarta', label: 'Quarta' },
  { key: 'quinta', label: 'Quinta' },
  { key: 'sexta', label: 'Sexta' },
  { key: 'sabado', label: 'Sábado' }
];

const FENIX_DRAW_DAYS = ['domingo', 'segunda', 'terca', 'quarta', 'quinta', 'sexta', 'sabado'];

function fenixText(value) {
  return String(value || '').trim();
}

function fenixTextKey(value) {
  return String(value || '')
    .normalize('NFD')
    .replace(/[\u0300-\u036f]/g, '')
    .toLowerCase()
    .trim();
}

function fenixNormalizeKickNick(value) {
  let nick = fenixText(value);

  nick = nick
    .replace(/^https?:\/\/kick\.com\//i, '')
    .replace(/^kick\.com\//i, '')
    .replace(/^@/, '')
    .split(/[/?#]/)[0]
    .trim();

  return nick;
}

function fenixKickUrlFromNick(nick) {
  const clean = fenixNormalizeKickNick(nick);
  return clean ? 'https://kick.com/' + clean.toLowerCase() : '';
}

function fenixFindColumn(headers, variants) {
  const normalized = headers.map((item) => fenixTextKey(item));

  for (const variant of variants) {
    const key = fenixTextKey(variant);
    const exact = normalized.findIndex((header) => header === key);

    if (exact >= 0) return exact;
  }

  for (const variant of variants) {
    const key = fenixTextKey(variant);
    const partial = normalized.findIndex((header) => header.includes(key));

    if (partial >= 0) return partial;
  }

  return -1;
}

function fenixCell(cols, index) {
  if (index < 0 || index >= cols.length) return '';
  return fenixText(cols[index]);
}

function fenixParseHours(value) {
  const result = [];
  const text = fenixText(value);

  if (!text) return result;

  const regex = /(\d{1,2})\s*:?\s*00\s*(?:as|às|a|-|até)\s*(\d{1,2})\s*:?\s*00/gi;
  let match;

  while ((match = regex.exec(text)) !== null) {
    const hour = Number(match[1]);

    if (Number.isInteger(hour) && hour >= 0 && hour <= 23 && !result.includes(hour)) {
      result.push(hour);
    }
  }

  return result.sort((a, b) => a - b);
}

function fenixFormatHour(hour) {
  return String(hour).padStart(2, '0') + ':00';
}

function fenixParseApplicantsFromPaste(pastedText) {
  const raw = String(pastedText || '').trim();

  if (!raw) return [];

  const lines = raw
    .split(/\r?\n/)
    .map((line) => line.trimEnd())
    .filter(Boolean);

  if (lines.length < 2) return [];

  const delimiter = lines[0].includes('\t') ? '\t' : ';';
  const headers = lines[0].split(delimiter).map(fenixText);

  const idxName = fenixFindColumn(headers, ['Qual seu nome?', 'Nome', 'Nome da pessoa']);
  const idxNick = fenixFindColumn(headers, ['Qual seu nick na Kick?', 'Nick', 'Nick Kick', 'Nome do Canal']);
  const idxLink = fenixFindColumn(headers, ['Qual o link do seu canal na Kick?', 'Link do canal', 'Canal na Kick']);
  const idxWhats = fenixFindColumn(headers, ['Qual seu WhatsApp?', 'WhatsApp', 'Whats']);
  const idxEmail = fenixFindColumn(headers, ['Qual seu e-mail?', 'email']);
  const idxIndicado = fenixFindColumn(headers, ['Quem te indicou', 'indicado']);
  const idxBaixou = fenixFindColumn(headers, ['Você já baixou', 'baixou']);
  const idxObs = fenixFindColumn(headers, ['Observação final', 'observacao', 'observação']);

  const dayIndexes = {
    domingo: fenixFindColumn(headers, ['[DOMINGO]', 'DOMINGO']),
    segunda: fenixFindColumn(headers, ['[SEGUNDA]', 'SEGUNDA']),
    terca: fenixFindColumn(headers, ['[TERÇA]', '[TERCA]', 'TERÇA', 'TERCA']),
    quarta: fenixFindColumn(headers, ['[QUARTA]', 'QUARTA']),
    quinta: fenixFindColumn(headers, ['[QUINTA]', 'QUINTA']),
    sexta: fenixFindColumn(headers, ['[SEXTA]', 'SEXTA']),
    sabado: fenixFindColumn(headers, ['[SÁBADO]', '[SABADO]', 'SÁBADO', 'SABADO'])
  };

  const byNick = new Map();

  for (const line of lines.slice(1)) {
    const cols = line.split(delimiter);

    const name = fenixCell(cols, idxName);
    const nickFromNick = fenixNormalizeKickNick(fenixCell(cols, idxNick));
    const nickFromLink = fenixNormalizeKickNick(fenixCell(cols, idxLink));
    const nick = nickFromNick || nickFromLink;

    if (!nick) continue;

    const key = nick.toLowerCase();

    const availability = {};

    for (const day of FENIX_FORM_DAYS) {
      const hours = fenixParseHours(fenixCell(cols, dayIndexes[day.key]));
      availability[day.key] = hours;
    }

    const applicant = {
      id: 'form-' + key,
      name,
      nick,
      slug: nick.toLowerCase(),
      url: fenixKickUrlFromNick(nick),
      whatsapp: fenixCell(cols, idxWhats),
      email: fenixCell(cols, idxEmail),
      referredBy: fenixCell(cols, idxIndicado),
      appDownloaded: fenixCell(cols, idxBaixou),
      observation: fenixCell(cols, idxObs),
      availability,
      ignored: false,
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString()
    };

    if (byNick.has(key)) {
      const previous = byNick.get(key);

      for (const day of FENIX_FORM_DAYS) {
        const merged = Array.from(new Set([
          ...(previous.availability?.[day.key] || []),
          ...(applicant.availability?.[day.key] || [])
        ])).sort((a, b) => a - b);

        previous.availability[day.key] = merged;
      }

      previous.name = applicant.name || previous.name;
      previous.whatsapp = applicant.whatsapp || previous.whatsapp;
      previous.email = applicant.email || previous.email;
      previous.referredBy = applicant.referredBy || previous.referredBy;
      previous.appDownloaded = applicant.appDownloaded || previous.appDownloaded;
      previous.observation = applicant.observation || previous.observation;
      previous.updatedAt = new Date().toISOString();
    } else {
      byNick.set(key, applicant);
    }
  }

  return Array.from(byNick.values());
}

function fenixRandomSort(items) {
  return items
    .map((item) => ({ item, random: Math.random() }))
    .sort((a, b) => a.random - b.random)
    .map((entry) => entry.item);
}

function fenixPickVacantHours(vacancyPerDay) {
  const count = Math.max(0, Math.min(24, Number(vacancyPerDay || 0)));
  const hours = fenixRandomSort(Array.from({ length: 24 }, (_, index) => index));
  return new Set(hours.slice(0, count));
}


function fenixSaveFormApplicantsFinal(applicants) {
  const data = readFenixData();
  data.formApplicants = Array.isArray(applicants) ? applicants : [];
  fs.writeFileSync(FENIX_DATA_FILE, JSON.stringify(data, null, 2), "utf8");
  return data.formApplicants;
}

function fenixReadFormApplicantsFinal() {
  const data = readFenixData();
  return Array.isArray(data.formApplicants) ? data.formApplicants : [];
}

function fenixGenerateGradeDraw(applicants, options = {}) {
  const vacancyPerDay = Math.max(0, Math.min(24, Number(options.vacancyPerDay || 0)));
  const requestedMinimum = Number(options.minimumPerApplicant || 4);
  const minimumPerApplicant = requestedMinimum === 6 ? 6 : 4;
  const screensPerHour = 3;
  const usage = {};
  const usageByDay = {};
  const rows = [];

  const activeApplicants = applicants
    .filter((item) => item && !item.ignored && item.nick)
    .map((item) => ({
      ...item,
      slug: fenixNormalizeKickNick(item.slug || item.nick).toLowerCase(),
      url: item.url || fenixKickUrlFromNick(item.nick)
    }));

  const applicantsBySlug = new Map();

  for (const applicant of activeApplicants) {
    usage[applicant.slug] = 0;
    usageByDay[applicant.slug] = {};
    applicantsBySlug.set(applicant.slug, applicant);
  }

  const vacantByDay = {};

  for (const dayKey of FENIX_DRAW_DAYS) {
    const hoursByDemand = Array.from({ length: 24 }, (_, hour) => {
      const demand = activeApplicants.filter((applicant) => {
        const available = Array.isArray(applicant.availability?.[dayKey])
          ? applicant.availability[dayKey]
          : [];

        return available.includes(hour);
      }).length;

      return {
        hour,
        demand,
        random: Math.random()
      };
    });

    hoursByDemand.sort((a, b) => {
      if (a.demand !== b.demand) return a.demand - b.demand;
      return a.random - b.random;
    });

    vacantByDay[dayKey] = new Set(
      hoursByDemand.slice(0, vacancyPerDay).map((item) => item.hour)
    );
  }

  const eligibleHours = {};

  for (const applicant of activeApplicants) {
    eligibleHours[applicant.slug] = FENIX_DRAW_DAYS.reduce((total, dayKey) => {
      const available = Array.isArray(applicant.availability?.[dayKey])
        ? applicant.availability[dayKey]
        : [];

      return total + available.filter((hour) => !vacantByDay[dayKey].has(hour)).length;
    }, 0);
  }

  function applicantScreen(applicant, screen) {
    return {
      screen,
      status: 'OK',
      name: applicant.name,
      nick: applicant.nick,
      slug: applicant.slug,
      url: applicant.url,
      whatsapp: applicant.whatsapp
    };
  }

  function applicantUrgency(applicant) {
    const currentUsage = Number(usage[applicant.slug] || 0);
    const missing = Math.max(0, minimumPerApplicant - currentUsage);
    const remainingOpportunities = Math.max(
      0,
      Number(eligibleHours[applicant.slug] || 0) - currentUsage
    );

    return remainingOpportunities - missing;
  }

  for (const dayKey of FENIX_DRAW_DAYS) {
    const vacantHours = vacantByDay[dayKey];

    for (let hour = 0; hour < 24; hour += 1) {
      const row = {
        id: dayKey + '-' + String(hour).padStart(2, '0'),
        day: dayKey,
        dayLabel: (FENIX_FORM_DAYS.find((day) => day.key === dayKey) || {}).label || dayKey,
        hour,
        hourLabel: fenixFormatHour(hour),
        manualVacancy: vacantHours.has(hour),
        screens: []
      };

      if (row.manualVacancy) {
        for (let screen = 1; screen <= screensPerHour; screen += 1) {
          row.screens.push({
            screen,
            status: 'VAGO',
            nick: '',
            url: ''
          });
        }

        rows.push(row);
        continue;
      }

      const picked = new Set();

      for (let screen = 1; screen <= screensPerHour; screen += 1) {
        const candidates = activeApplicants.filter((applicant) => {
          const available = Array.isArray(applicant.availability?.[dayKey])
            ? applicant.availability[dayKey]
            : [];

          return available.includes(hour) && !picked.has(applicant.slug);
        });

        candidates.sort((a, b) => {
          const aBelow = Number(usage[a.slug] || 0) < minimumPerApplicant;
          const bBelow = Number(usage[b.slug] || 0) < minimumPerApplicant;

          if (aBelow !== bBelow) return aBelow ? -1 : 1;

          const urgencyDifference = applicantUrgency(a) - applicantUrgency(b);
          if (urgencyDifference !== 0) return urgencyDifference;

          const usageDifference = Number(usage[a.slug] || 0) - Number(usage[b.slug] || 0);
          if (usageDifference !== 0) return usageDifference;

          const aDay = Number(usageByDay[a.slug]?.[dayKey] || 0);
          const bDay = Number(usageByDay[b.slug]?.[dayKey] || 0);

          if (aDay !== bDay) return aDay - bDay;

          return Math.random() - 0.5;
        });

        const selected = candidates[0];

        if (!selected) {
          row.screens.push({
            screen,
            status: 'SEM_CANDIDATO',
            nick: '',
            url: ''
          });
          continue;
        }

        picked.add(selected.slug);
        usage[selected.slug] = Number(usage[selected.slug] || 0) + 1;
        usageByDay[selected.slug][dayKey] =
          Number(usageByDay[selected.slug][dayKey] || 0) + 1;

        row.screens.push(applicantScreen(selected, screen));
      }

      rows.push(row);
    }
  }

  let repaired = true;
  let repairPasses = 0;
  const maxRepairPasses = Math.max(1, activeApplicants.length * minimumPerApplicant * 2);

  while (repaired && repairPasses < maxRepairPasses) {
    repaired = false;
    repairPasses += 1;

    const belowTarget = activeApplicants
      .filter((applicant) => Number(usage[applicant.slug] || 0) < minimumPerApplicant)
      .sort((a, b) => applicantUrgency(a) - applicantUrgency(b));

    for (const applicant of belowTarget) {
      const candidateRows = rows
        .filter((row) => {
          if (row.manualVacancy) return false;

          const available = Array.isArray(applicant.availability?.[row.day])
            ? applicant.availability[row.day]
            : [];

          if (!available.includes(row.hour)) return false;

          const alreadyInRow = row.screens.some((screen) => screen.slug === applicant.slug);
          if (alreadyInRow) return false;

          return row.screens.some((screen) => {
            if (screen.status !== 'OK') return true;
            return Number(usage[screen.slug] || 0) > minimumPerApplicant;
          });
        })
        .sort((a, b) => {
          const aHasOpen = a.screens.some((screen) => screen.status !== 'OK');
          const bHasOpen = b.screens.some((screen) => screen.status !== 'OK');

          if (aHasOpen !== bHasOpen) return aHasOpen ? -1 : 1;
          return Math.random() - 0.5;
        });

      const targetRow = candidateRows[0];
      if (!targetRow) continue;

      let targetScreen = targetRow.screens.find((screen) => screen.status !== 'OK');

      if (!targetScreen) {
        targetScreen = targetRow.screens
          .filter((screen) => Number(usage[screen.slug] || 0) > minimumPerApplicant)
          .sort((a, b) => Number(usage[b.slug] || 0) - Number(usage[a.slug] || 0))[0];
      }

      if (!targetScreen) continue;

      if (targetScreen.status === 'OK' && targetScreen.slug) {
        usage[targetScreen.slug] = Math.max(0, Number(usage[targetScreen.slug] || 0) - 1);
        usageByDay[targetScreen.slug][targetRow.day] = Math.max(
          0,
          Number(usageByDay[targetScreen.slug]?.[targetRow.day] || 0) - 1
        );
      }

      const replacement = applicantScreen(applicant, targetScreen.screen);
      Object.keys(targetScreen).forEach((key) => delete targetScreen[key]);
      Object.assign(targetScreen, replacement);

      usage[applicant.slug] = Number(usage[applicant.slug] || 0) + 1;
      usageByDay[applicant.slug][targetRow.day] =
        Number(usageByDay[applicant.slug]?.[targetRow.day] || 0) + 1;

      repaired = true;
    }
  }

  const totalAvailableScreens =
    rows.filter((row) => !row.manualVacancy).length * screensPerHour;
  const requiredScreens = activeApplicants.length * minimumPerApplicant;
  const capacityPossible = requiredScreens <= totalAvailableScreens;

  const belowMinimum = activeApplicants
    .filter((applicant) => Number(usage[applicant.slug] || 0) < minimumPerApplicant)
    .map((applicant) => {
      const assigned = Number(usage[applicant.slug] || 0);
      const available = Number(eligibleHours[applicant.slug] || 0);

      let reason = 'Conflito de horarios na distribuicao';

      if (available < minimumPerApplicant) {
        reason = 'Disponibilidade informada insuficiente';
      } else if (!capacityPossible) {
        reason = 'Capacidade semanal insuficiente';
      }

      return {
        nick: applicant.nick,
        slug: applicant.slug,
        assigned,
        missing: minimumPerApplicant - assigned,
        available,
        reason
      };
    })
    .sort((a, b) => {
      if (a.assigned !== b.assigned) return a.assigned - b.assigned;
      return String(a.nick || '').localeCompare(String(b.nick || ''));
    });

  return {
    id: 'draw-' + Date.now(),
    createdAt: new Date().toISOString(),
    vacancyPerDay,
    minimumPerApplicant,
    screensPerHour,
    rows,
    summary: {
      applicants: activeApplicants.length,
      totalRows: rows.length,
      totalVacantHours: rows.filter((row) => row.manualVacancy).length,
      totalAvailableScreens,
      requiredScreens,
      capacityPossible,
      metMinimum: activeApplicants.length - belowMinimum.length,
      belowMinimum,
      totalOpenScreens: rows.reduce((sum, row) => {
        return sum + row.screens.filter((screen) => screen.status !== 'OK').length;
      }, 0),
      usage
    }
  };
}

app.get('/admin/grade-sorteio', (req, res) => {
  res.type('html').send(`
<!doctype html>
<html lang="pt-BR">
<head>
  <meta charset="utf-8">
  <title>Fenix Lurk - Sorteio de Grade</title>
  <style>
    body { margin: 0; background: #090909; color: #f5f5f5; font-family: Arial, sans-serif; }
    header { padding: 22px; border-bottom: 1px solid #3a2a08; background: linear-gradient(135deg, #080808, #1b1304); }
    h1 { margin: 0; color: #f3c451; }
    main { padding: 20px; display: grid; gap: 18px; }
    section { background: #111; border: 1px solid #30240a; border-radius: 14px; padding: 16px; }
    textarea, input, select { width: 100%; box-sizing: border-box; background: #070707; color: #fff; border: 1px solid #3d300f; border-radius: 10px; padding: 10px; }
    textarea { min-height: 180px; }
    button { background: #d6a82d; color: #090909; border: none; padding: 10px 14px; border-radius: 10px; font-weight: 800; cursor: pointer; margin: 4px; }
    button.secondary { background: #222; color: #f3c451; border: 1px solid #4a390f; }
    .grid { display: grid; grid-template-columns: repeat(4, 1fr); gap: 10px; }
    .card { background: #080808; border: 1px solid #2d230d; border-radius: 12px; padding: 12px; }
    .muted { color: #aaa; font-size: 12px; }
    table { width: 100%; border-collapse: collapse; font-size: 13px; }
    th, td { border-bottom: 1px solid #222; padding: 8px; text-align: left; vertical-align: top; }
    th { color: #f3c451; background: #0c0c0c; position: sticky; top: 0; }
    .ok { color: #55ff99; font-weight: 800; }
    .vago { color: #ffcc55; font-weight: 800; }
    .bad { color: #ff7777; font-weight: 800; }
  </style>
</head>
<body>
  <header>
    <h1>Fenix Lurk - Sorteio de Grade</h1>
    <div class="muted">Importe os formulários, veja os inscritos e gere a grade respeitando os horários marcados.</div>
  </header>

  <main>
    <section>
      <h2>1. Importar formulário</h2>
      <p class="muted">Copie da planilha do Google Forms incluindo o cabeçalho e cole aqui.</p>
      <form method="POST" action="/admin/grade-sorteio/importar">
        <label>Senha Admin:</label>
        <input id="adminSecretBox" name="adminSecret" type="password" placeholder="Digite a senha admin da Railway">
        <br><br>
        <textarea id="pasteBox" name="text" placeholder="Cole aqui as respostas da planilha..."></textarea>
        <button type="submit">Importar inscritos</button>
        <button id="btnLoadApplicants" class="secondary" type="button">Atualizar lista</button>
      </form>
      <div id="importMsg" class="muted"></div>
    </section>

    <section>
      <h2>2. Inscritos importados</h2>
      <div id="applicantsBox" class="grid"></div>
    </section>

    <section>
      <h2>3. Gerar sorteio da semana</h2>
      <label>Horários vagos por dia para preencher manual no grupo:</label>
      <input id="vacancyPerDay" type="number" min="0" max="24" value="3">
      <br><br>
      <label>Meta minima garantida por pessoa:</label>
      <select id="minimumPerApplicant">
        <option value="4">4 vezes por semana</option>
        <option value="6">6 vezes por semana</option>
      </select>
      <br><br>
      <button id="btnGenerateDraw" type="button">Gerar grade por sorteio</button>
      <button id="btnLoadDraw" class="secondary" type="button">Ver último sorteio</button>
      <div id="drawMsg" class="muted"></div>
    </section>

    <section>
      <h2>4. Grade sorteada</h2>
      <div class="muted">Essa grade é rascunho. Ainda não altera a grade ativa do app.</div>
      <br>
      <div id="drawBox"></div>
    </section>
  </main>

<script>
  const API = "";
  let adminSecret = localStorage.getItem("fenixAdminSecret") || "";

  function getSecret() {
    const input = document.getElementById("adminSecretBox");
    const typed = input ? String(input.value || "").trim() : "";

    if (typed) {
      adminSecret = typed;
      localStorage.setItem("fenixAdminSecret", adminSecret);
      return adminSecret;
    }

    if (adminSecret && input) {
      input.value = adminSecret;
    }

    return adminSecret;
  }

  async function api(path, options) {
    const res = await fetch(API + path, {
      ...(options || {}),
      headers: {
        "Content-Type": "application/json",
        "x-fenix-admin": "GokuuMods",
        "x-fenix-admin-secret": getSecret(),
        ...((options && options.headers) || {})
      }
    });

    const data = await res.json().catch(() => ({}));

    if (!res.ok || data.ok === false) {
      throw new Error(data.message || data.error || "Erro na API");
    }

    return data;
  }

  function dayText(av) {
    const names = {
      domingo: "Dom",
      segunda: "Seg",
      terca: "Ter",
      quarta: "Qua",
      quinta: "Qui",
      sexta: "Sex",
      sabado: "Sáb"
    };

    return Object.keys(names).map((key) => {
      const hours = av && Array.isArray(av[key]) ? av[key] : [];
      if (!hours.length) return "";
      return names[key] + ": " + hours.map((h) => String(h).padStart(2, "0") + "h").join(", ");
    }).filter(Boolean).join(" | ");
  }

  async function importApplicants() {
    const text = document.getElementById("pasteBox").value;

    document.getElementById("importMsg").textContent = "Importando...";

    try {
      const data = await api("/api/fenix/admin/form-applicants/import", {
        method: "POST",
        body: JSON.stringify({ text })
      });

      document.getElementById("importMsg").textContent = "Importados/atualizados: " + data.imported;
      await loadApplicants();
    } catch (error) {
      document.getElementById("importMsg").textContent = "Erro: " + error.message;
    }
  }

  async function loadApplicants() {
    const box = document.getElementById("applicantsBox");
    box.innerHTML = "Carregando...";

    try {
      const data = await api("/api/fenix/admin/form-applicants", { method: "GET" });

      box.innerHTML = "";

      data.applicants.forEach((item) => {
        const div = document.createElement("div");
        div.className = "card";
        div.innerHTML =
          "<b>" + (item.nick || "") + "</b><br>" +
          "<span class='muted'>" + (item.name || "") + "</span><br>" +
          "<span>Whats: " + (item.whatsapp || "-") + "</span><br>" +
          "<span class='muted'>" + dayText(item.availability || {}) + "</span>";

        box.appendChild(div);
      });
    } catch (error) {
      box.innerHTML = "Erro: " + error.message;
    }
  }

  async function generateDraw() {
    const vacancyPerDay = Number(document.getElementById("vacancyPerDay").value || 0);
    const minimumPerApplicant = Number(document.getElementById("minimumPerApplicant").value || 4);

    document.getElementById("drawMsg").textContent = "Gerando sorteio...";

    try {
      const data = await api("/api/fenix/admin/grade-draw/generate", {
        method: "POST",
        body: JSON.stringify({ vacancyPerDay, minimumPerApplicant })
      });

      document.getElementById("drawMsg").textContent =
        "Sorteio gerado. Inscritos: " + data.draw.summary.applicants +
        " | Vagos por dia: " + data.draw.vacancyPerDay +
        " | Meta: " + data.draw.minimumPerApplicant + "x" +
        " | Abaixo: " + data.draw.summary.belowMinimum.length;

      renderDraw(data.draw);
    } catch (error) {
      document.getElementById("drawMsg").textContent = "Erro: " + error.message;
    }
  }

  async function loadDraw() {
    try {
      const data = await api("/api/fenix/admin/grade-draw", { method: "GET" });
      renderDraw(data.draw);
    } catch (error) {
      document.getElementById("drawBox").innerHTML = "Erro: " + error.message;
    }
  }

  function copyVacancy(day, hour) {
    const msg =
      "🔥 VAGA ABERTA NA GRADE FENIX 🔥\n\n" +
      "Horário: " + day + " às " + hour + "\n" +
      "Vagas disponíveis na grade.\n\n" +
      "Quem estiver em live nesse horário, marca ✅ aqui no grupo.";

    navigator.clipboard.writeText(msg);
    alert("Mensagem copiada.");
  }

  function renderDraw(draw) {
    const box = document.getElementById("drawBox");

    if (!draw || !Array.isArray(draw.rows)) {
      box.innerHTML = "Nenhum sorteio gerado ainda.";
      return;
    }

    const summary = draw.summary || {};
    const below = Array.isArray(summary.belowMinimum) ? summary.belowMinimum : [];
    const capacityClass = summary.capacityPossible ? "ok" : "bad";
    const capacityText = summary.capacityPossible
      ? "Capacidade suficiente para a meta escolhida."
      : "ATENCAO: capacidade semanal insuficiente para garantir a meta a todos.";

    let html =
      '<div class="card" style="margin-bottom:14px">' +
        '<h3 style="margin-top:0;color:#f3c451">Resumo da garantia</h3>' +
        '<div><b>Meta:</b> ' + Number(draw.minimumPerApplicant || 4) + 'x por pessoa</div>' +
        '<div><b>Atingiram:</b> ' + Number(summary.metMinimum || 0) + ' de ' + Number(summary.applicants || 0) + '</div>' +
        '<div><b>Vagas automáticas disponíveis:</b> ' + Number(summary.totalAvailableScreens || 0) + '</div>' +
        '<div><b>Vagas necessárias:</b> ' + Number(summary.requiredScreens || 0) + '</div>' +
        '<div class="' + capacityClass + '" style="margin-top:8px">' + capacityText + '</div>' +
      '</div>';

    if (below.length) {
      html +=
        '<div class="card" style="margin-bottom:14px;border-color:#713333">' +
          '<h3 style="margin-top:0;color:#ff7777">Pessoas abaixo da meta</h3>' +
          '<table><thead><tr><th>Canal</th><th>Recebeu</th><th>Faltam</th><th>Disponibilidade</th><th>Motivo</th></tr></thead><tbody>' +
          below.map((item) => {
            return '<tr>' +
              '<td><b>' + String(item.nick || '-') + '</b></td>' +
              '<td>' + Number(item.assigned || 0) + '</td>' +
              '<td>' + Number(item.missing || 0) + '</td>' +
              '<td>' + Number(item.available || 0) + ' horários</td>' +
              '<td class="bad">' + String(item.reason || '-') + '</td>' +
            '</tr>';
          }).join('') +
          '</tbody></table>' +
        '</div>';
    } else {
      html += '<div class="card ok" style="margin-bottom:14px">Todos atingiram a meta escolhida.</div>';
    }

    html += "<table><thead><tr><th>Dia</th><th>Hora</th><th>Tela 1</th><th>Tela 2</th><th>Tela 3</th><th>Ação</th></tr></thead><tbody>";

    draw.rows.forEach((row) => {
      const screens = row.screens || [];

      function screenText(index) {
        const s = screens[index] || {};
        if (s.status === "OK") return "<span class='ok'>" + s.nick + "</span>";
        if (s.status === "VAGO") return "<span class='vago'>VAGO</span>";
        return "<span class='bad'>PREENCHER MANUAL</span>";
      }

      const action = row.manualVacancy
        ? "<button onclick=\"copyVacancy('" + row.dayLabel + "','" + row.hourLabel + "')\">Copiar vaga</button>"
        : "";

      html += "<tr>" +
        "<td>" + row.dayLabel + "</td>" +
        "<td>" + row.hourLabel + "</td>" +
        "<td>" + screenText(0) + "</td>" +
        "<td>" + screenText(1) + "</td>" +
        "<td>" + screenText(2) + "</td>" +
        "<td>" + action + "</td>" +
        "</tr>";
    });

    html += "</tbody></table>";
    box.innerHTML = html;
  }

  document.addEventListener("DOMContentLoaded", () => {
    const input = document.getElementById("adminSecretBox");
    if (input && adminSecret) input.value = adminSecret;

    const btnImport = document.getElementById("btnImportApplicants");
    const btnLoadApplicants = document.getElementById("btnLoadApplicants");
    const btnGenerate = document.getElementById("btnGenerateDraw");
    const btnLoadDraw = document.getElementById("btnLoadDraw");

    if (btnImport) btnImport.addEventListener("click", importApplicants);
    if (btnLoadApplicants) btnLoadApplicants.addEventListener("click", loadApplicants);
    if (btnGenerate) btnGenerate.addEventListener("click", generateDraw);
    if (btnLoadDraw) btnLoadDraw.addEventListener("click", loadDraw);

    loadApplicants();
    loadDraw();
  });
</script>
</body>
</html>
  `);
});


// FENIX_GRADE_SORTEIO_FORM_POST_FINAL
app.use(express.urlencoded({ limit: '25mb', extended: true }));

app.post('/admin/grade-sorteio/importar', (req, res, next) => {
  req.headers['x-fenix-admin'] = 'GokuuMods';
  req.headers['x-fenix-admin-secret'] = String(req.body?.adminSecret || '').trim();
  next();
}, requireFenixAdmin, (req, res) => {
  try {
    const pasted = String(req.body?.text || '');
    const parsed = fenixParseApplicantsFromPaste(pasted);

    if (!parsed.length) {
      return res.type('html').send(`
        <body style="background:#090909;color:white;font-family:Arial;padding:30px">
          <h1 style="color:#f3c451">Erro ao importar</h1>
          <p>Nenhum inscrito encontrado.</p>
          <p>Copie a planilha incluindo a linha do cabeçalho.</p>
          <a style="color:#f3c451" href="/admin/grade-sorteio">Voltar</a>
        </body>
      `);
    }

    const data = readFenixData();

    data.formApplicants = Array.isArray(data.formApplicants) ? data.formApplicants : [];

    const current = new Map();

    for (const applicant of data.formApplicants) {
      const key = fenixNormalizeKickNick(applicant.slug || applicant.nick).toLowerCase();
      if (key) current.set(key, applicant);
    }

    for (const applicant of parsed) {
      const key = applicant.slug;

      if (current.has(key)) {
        const existing = current.get(key);
        Object.assign(existing, {
          ...existing,
          ...applicant,
          ignored: Boolean(existing.ignored),
          updatedAt: new Date().toISOString()
        });
      } else {
        data.formApplicants.push(applicant);
        current.set(key, applicant);
      }
    }

    fenixSaveFormApplicantsFinal(data.formApplicants);

    return res.type('html').send(`
      <body style="background:#090909;color:white;font-family:Arial;padding:30px">
        <h1 style="color:#f3c451">Importado com sucesso ✅</h1>
        <p>Inscritos importados/atualizados: <b>${parsed.length}</b></p>
        <p>Total salvo no Admin: <b>${data.formApplicants.length}</b></p>
        <a style="color:#f3c451;font-size:18px" href="/admin/grade-sorteio">Voltar para o sorteio da grade</a>
      </body>
    `);
  } catch (error) {
    return res.type('html').send(`
      <body style="background:#090909;color:white;font-family:Arial;padding:30px">
        <h1 style="color:#ff7777">Erro</h1>
        <pre>${String(error.stack || error.message || error)}</pre>
        <a style="color:#f3c451" href="/admin/grade-sorteio">Voltar</a>
      </body>
    `);
  }
});



// FENIX_FORM_APPLICANTS_SEPARATE_FILE_FINAL
function fenixFormApplicantsBaseDirFinal() {
  const file = String(FENIX_DATA_FILE || "./fenix-data.json");
  const normalized = file.replace(/\\/g, "/");
  const index = normalized.lastIndexOf("/");
  return index >= 0 ? normalized.slice(0, index) : ".";
}

function fenixFormApplicantsFileFinal() {
  return fenixFormApplicantsBaseDirFinal() + "/fenix-form-applicants.json";
}

function fenixGradeDrawFileFinal() {
  return fenixFormApplicantsBaseDirFinal() + "/fenix-grade-draw.json";
}

function fenixReadFormApplicantsFileFinal() {
  try {
    const file = fenixFormApplicantsFileFinal();

    if (!fs.existsSync(file)) return [];

    const parsed = JSON.parse(fs.readFileSync(file, "utf8"));

    return Array.isArray(parsed) ? parsed : [];
  } catch (error) {
    console.error("Erro lendo inscritos do formulario:", error);
    return [];
  }
}

function fenixSaveFormApplicantsFileFinal(applicants) {
  const file = fenixFormApplicantsFileFinal();
  const list = Array.isArray(applicants) ? applicants : [];

  fs.mkdirSync(fenixFormApplicantsBaseDirFinal(), { recursive: true });
  fs.writeFileSync(file, JSON.stringify(list, null, 2), "utf8");

  return list;
}

function fenixReadGradeDrawFileFinal() {
  try {
    const file = fenixGradeDrawFileFinal();

    if (!fs.existsSync(file)) return null;

    return JSON.parse(fs.readFileSync(file, "utf8"));
  } catch (error) {
    console.error("Erro lendo sorteio da grade:", error);
    return null;
  }
}

function fenixSaveGradeDrawFileFinal(draw) {
  const file = fenixGradeDrawFileFinal();

  fs.mkdirSync(fenixFormApplicantsBaseDirFinal(), { recursive: true });
  fs.writeFileSync(file, JSON.stringify(draw || null, null, 2), "utf8");

  return draw;
}

app.get('/api/fenix/admin/form-applicants', requireFenixAdmin, (req, res) => {
  const applicants = fenixReadFormApplicantsFileFinal();

  res.json({
    ok: true,
    total: applicants.length,
    applicants: applicants
      .slice()
      .sort((a, b) => String(a.nick || '').localeCompare(String(b.nick || '')))
  });
});

app.post('/api/fenix/admin/form-applicants/import', requireFenixAdmin, (req, res) => {
  const pasted = String(req.body?.text || '');
  const parsed = fenixParseApplicantsFromPaste(pasted);

  if (!parsed.length) {
    return res.status(400).json({
      ok: false,
      message: 'Nenhum inscrito encontrado. Cole a planilha com o cabeçalho.'
    });
  }

  const currentList = fenixReadFormApplicantsFileFinal();
  const current = new Map();

  for (const applicant of currentList) {
    const key = fenixNormalizeKickNick(applicant.slug || applicant.nick).toLowerCase();
    if (key) current.set(key, applicant);
  }

  for (const applicant of parsed) {
    const key = applicant.slug;

    if (current.has(key)) {
      const existing = current.get(key);
      Object.assign(existing, {
        ...existing,
        ...applicant,
        ignored: Boolean(existing.ignored),
        updatedAt: new Date().toISOString()
      });
    } else {
      currentList.push(applicant);
      current.set(key, applicant);
    }
  }

  const saved = fenixSaveFormApplicantsFileFinal(currentList);

  res.json({
    ok: true,
    imported: parsed.length,
    total: saved.length,
    applicants: saved
  });
});

app.post('/api/fenix/admin/grade-draw/generate', requireFenixAdmin, (req, res) => {
  const applicants = fenixReadFormApplicantsFileFinal();

  const vacancyPerDay = Number(req.body?.vacancyPerDay || 0);
  const minimumPerApplicant = Number(req.body?.minimumPerApplicant || 4);
  const draw = fenixGenerateGradeDraw(applicants, { vacancyPerDay, minimumPerApplicant });

  fenixSaveGradeDrawFileFinal(draw);

  res.json({
    ok: true,
    draw
  });
});

app.get('/api/fenix/admin/grade-draw', requireFenixAdmin, (req, res) => {
  res.json({
    ok: true,
    draw: fenixReadGradeDrawFileFinal()
  });
});


app.get('/api/fenix/admin/form-applicants', requireFenixAdmin, (req, res) => {
  const data = readFenixData();

  const applicants = fenixReadFormApplicantsFinal();

  res.json({
    ok: true,
    applicants: applicants
      .slice()
      .sort((a, b) => String(a.nick || '').localeCompare(String(b.nick || '')))
  });
});

app.post('/api/fenix/admin/form-applicants/import', requireFenixAdmin, (req, res) => {
  const pasted = String(req.body?.text || '');
  const parsed = fenixParseApplicantsFromPaste(pasted);

  if (!parsed.length) {
    return res.status(400).json({
      ok: false,
      message: 'Nenhum inscrito encontrado. Cole a planilha com o cabeçalho.'
    });
  }

  const data = readFenixData();

  data.formApplicants = Array.isArray(data.formApplicants) ? data.formApplicants : [];

  const current = new Map();

  for (const applicant of data.formApplicants) {
    const key = fenixNormalizeKickNick(applicant.slug || applicant.nick).toLowerCase();
    if (key) current.set(key, applicant);
  }

  for (const applicant of parsed) {
    const key = applicant.slug;

    if (current.has(key)) {
      const existing = current.get(key);
      Object.assign(existing, {
        ...existing,
        ...applicant,
        ignored: Boolean(existing.ignored),
        updatedAt: new Date().toISOString()
      });
    } else {
      data.formApplicants.push(applicant);
      current.set(key, applicant);
    }
  }

  fenixSaveFormApplicantsFinal(data.formApplicants);

  res.json({
    ok: true,
    imported: parsed.length,
    total: data.formApplicants.length,
    applicants: data.formApplicants
  });
});

app.post('/api/fenix/admin/grade-draw/generate', requireFenixAdmin, (req, res) => {
  const data = readFenixData();

  data.formApplicants = Array.isArray(data.formApplicants) ? data.formApplicants : [];

  const vacancyPerDay = Number(req.body?.vacancyPerDay || 0);
  const minimumPerApplicant = Number(req.body?.minimumPerApplicant || 4);
  const draw = fenixGenerateGradeDraw(data.formApplicants, { vacancyPerDay, minimumPerApplicant });

  data.gradeDraw = draw;

  writeFenixData(data);

  res.json({
    ok: true,
    draw
  });
});

app.get('/api/fenix/admin/grade-draw', requireFenixAdmin, (req, res) => {
  const data = readFenixData();

  res.json({
    ok: true,
    draw: data.gradeDraw || null
  });
});

// FENIX_GRADE_SORTEIO_SIMPLES_FINAL
function fenixHtmlEscape(value) {
  return String(value || '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

function fenixAvailabilityTextSimple(availability) {
  const days = [
    ['segunda', 'Seg'],
    ['terca', 'Ter'],
    ['quarta', 'Qua'],
    ['quinta', 'Qui'],
    ['sexta', 'Sex'],
    ['sabado', 'Sáb']
  ];

  return days.map(([key, label]) => {
    const hours = Array.isArray(availability?.[key]) ? availability[key] : [];
    if (!hours.length) return '';
    return label + ': ' + hours.map((h) => String(h).padStart(2, '0') + 'h').join(', ');
  }).filter(Boolean).join(' | ');
}

function fenixRenderGradeSorteioSimplesPage({ applicants = [], draw = null, message = '' } = {}) {
  // FENIX_APPLICANTS_COMPACT_LIST_119
  function applicantAvailabilityGroups119(availability) {
    const labels = { segunda: 'Segunda', terca: 'Terca', quarta: 'Quarta', quinta: 'Quinta', sexta: 'Sexta', sabado: 'Sabado' };
    const source = availability && typeof availability === 'object' ? availability : {};

    return ['segunda', 'terca', 'quarta', 'quinta', 'sexta', 'sabado'].map((key) => {
      const hours = Array.isArray(source[key]) ? source[key] : [];
      const cleanHours = hours
        .map((hour) => String(hour).replace(/\D/g, ''))
        .filter(Boolean)
        .map((hour) => String(hour).padStart(2, '0') + 'h');

      return { key, label: labels[key], hours: cleanHours, count: cleanHours.length };
    });
  }

  function applicantAvailabilityCount119(availability) {
    return applicantAvailabilityGroups119(availability).reduce((total, day) => total + day.count, 0);
  }

  function applicantAvailabilityDetails119(availability) {
    const groups = applicantAvailabilityGroups119(availability);

    if (!groups.some((day) => day.count > 0)) {
      return '<div class="muted">Nenhum horario marcado.</div>';
    }

    return '<div class="applicant-hours">' + groups.map((day) => {
      const content = day.count ? day.hours.join(', ') : '-';
      return '<div><b>' + fenixHtmlEscape(day.label) + ':</b> ' + fenixHtmlEscape(content) + '</div>';
    }).join('') + '</div>';
  }

  const applicantRows = applicants.map((item, index) => {
    const totalHours = applicantAvailabilityCount119(item.availability);
    const searchText = [
      item.name,
      item.nick,
      item.whatsapp,
      fenixAvailabilityTextSimple(item.availability)
    ].join(' ').toLowerCase();

    return '<tr class="applicant-row" data-search="' + fenixHtmlEscape(searchText) + '">' +
      '<td>' + (index + 1) + '</td>' +
      '<td>' + fenixHtmlEscape(item.name) + '</td>' +
      '<td><b>' + fenixHtmlEscape(item.nick) + '</b></td>' +
      '<td>' + fenixHtmlEscape(item.whatsapp) + '</td>' +
      '<td><b>' + totalHours + '</b></td>' +
      '<td><details><summary>Ver horarios</summary>' + applicantAvailabilityDetails119(item.availability) + '</details></td>' +
    '</tr>';
  }).join('');

  const drawRows = draw && Array.isArray(draw.rows) ? draw.rows.map((row) => {
    const screens = row.screens || [];

    function screen(index) {
      const s = screens[index] || {};
      if (s.status === 'OK') return '<span class="ok">' + fenixHtmlEscape(s.nick) + '</span>';
      if (s.status === 'VAGO') return '<span class="vago">VAGO</span>';
      return '<span class="bad">PREENCHER MANUAL</span>';
    }

    return `
      <tr>
        <td>${fenixHtmlEscape(row.dayLabel)}</td>
        <td>${fenixHtmlEscape(row.hourLabel)}</td>
        <td>${screen(0)}</td>
        <td>${screen(1)}</td>
        <td>${screen(2)}</td>
      </tr>
    `;
  }).join('') : '';

  return `
<!doctype html>
<html lang="pt-BR">
<head>
  <meta charset="utf-8">
  <title>Fenix Lurk - Sorteio Simples</title>
  <style>
    body { margin:0; background:#090909; color:#fff; font-family:Arial,sans-serif; }
    header { padding:24px; background:linear-gradient(135deg,#080808,#1b1304); border-bottom:1px solid #3a2a08; }
    h1 { margin:0; color:#f3c451; }
    main { padding:18px; display:grid; gap:16px; }
    section { background:#111; border:1px solid #30240a; border-radius:14px; padding:16px; }
    input, textarea, select { width:100%; box-sizing:border-box; background:#050505; color:#fff; border:1px solid #49370e; border-radius:10px; padding:10px; }
    textarea { min-height:170px; }
    button { background:#d6a82d; color:#090909; border:0; border-radius:10px; padding:11px 15px; font-weight:900; cursor:pointer; margin-top:10px; }
    table { width:100%; border-collapse:collapse; font-size:13px; margin-top:12px; }
    th,td { border-bottom:1px solid #252525; padding:8px; vertical-align:top; text-align:left; }
    th { color:#f3c451; background:#0b0b0b; }
    .msg { color:#55ff99; font-weight:900; }
    .muted { color:#aaa; font-size:12px; }
    .ok { color:#55ff99; font-weight:900; }
    .vago { color:#ffcc55; font-weight:900; }
    .bad { color:#ff7777; font-weight:900; }
  </style>
</head>
<body>
<header>
  <h1>Fenix Lurk - Sorteio de Grade Simples</h1>
  <div class="muted">Página sem JavaScript. Aqui os botões funcionam direto pelo backend.</div>
</header>

<main>
  ${message ? '<section><div class="msg">' + fenixHtmlEscape(message) + '</div></section>' : ''}

  <section>
    <h2>1. Importar formulário</h2>
    <form method="POST" action="/admin/grade-sorteio-simples/importar">
      <label>Senha Admin:</label>
      <input name="adminSecret" type="password" placeholder="Digite a senha admin da Railway" required>
      <br><br>
      <label>Planilha copiada:</label>
      <textarea name="text" placeholder="Cole aqui cabeçalho + respostas do Google Forms"></textarea>
      <button type="submit">Importar inscritos</button>
    </form>
  </section>

  <section>
    <h2>2. Importar grade pronta do Excel</h2>
    <div class="muted">
      Cole aqui a grade que vem do Excel. Ela vira rascunho e depois voce usa o botao "Aplicar essa grade no app".
    </div>
    <form method="POST" action="/admin/grade-sorteio-simples/importar-excel">
      <label>Senha Admin:</label>
      <input name="adminSecret" type="password" placeholder="Digite a senha admin da Railway" required>
      <br><br>

      <label>Importar:</label>
      <select name="importScope">
        <option value="semana">Semana toda</option>
        <option value="segunda">Apenas Segunda</option>
        <option value="terca">Apenas Terca</option>
        <option value="quarta">Apenas Quarta</option>
        <option value="quinta">Apenas Quinta</option>
        <option value="sexta">Apenas Sexta</option>
        <option value="sabado">Apenas Sabado</option>
      </select>
      <br><br>

      <label>Grade copiada do Excel:</label>
      <textarea name="excelText" placeholder="Cole aqui a grade do Excel com Horarios, Segunda, Terca, Quarta, Quinta, Sexta e Sabado"></textarea>

      <button type="submit">Importar grade do Excel</button>
    </form>
  </section>

  <section>
    <h2>3. Ver inscritos salvos</h2>
    <form method="POST" action="/admin/grade-sorteio-simples/ver">
      <label>Senha Admin:</label>
      <input name="adminSecret" type="password" placeholder="Digite a senha admin da Railway" required>
      <button type="submit">Ver inscritos</button>
    </form>

    <h3>Total: ${applicants.length}</h3>

    <div style="display:grid;grid-template-columns:1fr auto;gap:10px;align-items:end;margin:12px 0">
      <label>Pesquisar inscrito:
        <input id="applicantSearch119" type="text" placeholder="Nome, Kick ou WhatsApp">
      </label>
      <button type="button" onclick="fenixClearApplicantSearch119()">Limpar busca</button>
    </div>

    <div class="muted" id="applicantSearchInfo119">Mostrando ${applicants.length} inscritos.</div>

    <table id="applicantsTable119">
      <thead>
        <tr>
          <th>#</th>
          <th>Nome</th>
          <th>Nick Kick</th>
          <th>WhatsApp</th>
          <th>Total horarios</th>
          <th>Acoes</th>
        </tr>
      </thead>
      <tbody>
        ${applicantRows || '<tr><td colspan="6">Nenhum inscrito carregado ainda.</td></tr>'}
      </tbody>
    </table>

    <style>
      #applicantsTable119 td,
      #applicantsTable119 th { vertical-align: top; }
      #applicantsTable119 details { border: 1px solid rgba(245,178,42,.35); border-radius: 10px; padding: 7px 10px; background: rgba(245,178,42,.06); }
      #applicantsTable119 summary { cursor: pointer; color: #f5b22a; font-weight: 900; }
      .applicant-hours { display: grid; grid-template-columns: repeat(2, minmax(180px, 1fr)); gap: 6px 12px; margin-top: 8px; line-height: 1.45; }
      @media(max-width:900px) { .applicant-hours { grid-template-columns: 1fr; } }
    </style>

    <script>
      function fenixApplyApplicantSearch119(){
        const input = document.getElementById('applicantSearch119');
        const info = document.getElementById('applicantSearchInfo119');
        const rows = Array.from(document.querySelectorAll('#applicantsTable119 .applicant-row'));
        const query = String((input && input.value) || '').trim().toLowerCase();
        let visible = 0;

        rows.forEach(function(row){
          const text = String(row.getAttribute('data-search') || '').toLowerCase();
          const show = !query || text.includes(query);
          row.style.display = show ? '' : 'none';
          if (show) visible++;
        });

        if (info) info.textContent = 'Mostrando ' + visible + ' de ' + rows.length + ' inscritos.';
      }

      function fenixClearApplicantSearch119(){
        const input = document.getElementById('applicantSearch119');
        if (input) input.value = '';
        fenixApplyApplicantSearch119();
      }

      document.addEventListener('DOMContentLoaded', function(){
        const input = document.getElementById('applicantSearch119');
        if (input) input.addEventListener('input', fenixApplyApplicantSearch119);
        fenixApplyApplicantSearch119();
      });
    </script>
  </section>

  <section>
    <h2>3. Limpar inscritos</h2>
    <div class="muted">Use isso quando quiser apagar todos e importar a planilha completa atualizada.</div>
    <form method="POST" action="/admin/grade-sorteio-melhorado/limpar-inscritos">
      <label>Senha Admin:</label>
      <input name="adminSecret" type="password" placeholder="Digite a senha admin da Railway" required>
      <br><br>
      <label>Confirmação:</label>
      <input name="confirmText" placeholder="Digite APAGAR para confirmar" required>
      <button type="submit">Limpar todos os inscritos</button>
    </form>
  </section>

  <section>
    <h2>4. Gerar sorteio</h2>
    <form method="POST" action="/admin/grade-sorteio-simples/gerar">
      <label>Senha Admin:</label>
      <input name="adminSecret" type="password" placeholder="Digite a senha admin da Railway" required>
      <br><br>
      <label>Quantidade de horários vagos aleatórios por dia:</label>
      <input name="vacancyPerDay" type="number" min="0" max="24" value="0">
      <div class="muted">Use 0 se você quiser escolher os horários vagos manualmente.</div>
      <br><br>

      <label>Horários que você quer deixar VAGO:</label>
      <input name="manualVacantHours" placeholder="Exemplo: 12, 18, 23">
      <div class="muted">Digite só as horas. Exemplo: 12, 18, 23. Se preencher aqui, o sistema deixa exatamente esses horários vagos.</div>
      <br><br>

      <label>Horários fixos por pessoa na semana:</label>
      <input name="maxWeekly" type="number" min="1" max="200" value="4">
      <br><br>

      <label>Máximo por pessoa no dia:</label>
      <input name="maxDaily" type="number" min="1" max="24" value="2">
      <br><br>

      <label>Evitar repetir pessoa em horário seguido:</label>
      <select name="avoidConsecutive">
        <option value="sim">Sim</option>
        <option value="nao">Não</option>
      </select>

      <button type="submit">Gerar grade por sorteio</button>
    </form>
  </section>

  <section>
    <h2>4. Resumo rápido da grade</h2>
    <div class="muted">Use esse resumo para conferir se a grade ficou boa antes de aplicar no app.</div>
    ${(() => {
      const summary = fenixDrawVisualSummaryFinal(draw);
      return `
        <table>
          <thead>
            <tr>
              <th>Tipo</th>
              <th>Total</th>
            </tr>
          </thead>
          <tbody>
            <tr>
              <td><span class="ok">Preenchidas pelo sorteio</span></td>
              <td>${summary.filled}</td>
            </tr>
            <tr>
              <td><span class="vago">VAGO</span> - reservado por você</td>
              <td>${summary.reservedVacant}</td>
            </tr>
            <tr>
              <td><span class="bad">PREENCHER MANUAL</span> - faltou pessoa no sorteio</td>
              <td>${summary.manualFill}</td>
            </tr>
            <tr>
              <td>Total de telas</td>
              <td>${summary.totalScreens}</td>
            </tr>
            <tr>
              <td>Pessoas com 0 sorteios</td>
              <td>${summary.zeroApplicants.length ? summary.zeroApplicants.join(", ") : "Nenhuma"}</td>
            </tr>
          </tbody>
        </table>
      `;
    })()}
  </section>

  <section>
    <h2>5. Aplicar sorteio na grade real</h2>
    <div class="muted">
      Só clique aqui quando o resumo estiver correto. VAGO e PREENCHER MANUAL entram vazios na grade real.
    </div>

    <form method="POST" action="/admin/grade-sorteio-simples/aplicar">
      <label>Senha Admin:</label>
      <input name="adminSecret" type="password" placeholder="Digite a senha admin da Railway" required>
      <br><br>

      <label>Semana de destino:</label>
      <select name="weekMode">
        <option value="next">Próxima semana</option>
        <option value="current">Semana atual</option>
        <option value="manual">Escolher data manual</option>
      </select>
      <br><br>

      <label>Data manual de início:</label>
      <input name="manualStartDate" type="date">
      <div class="muted">Use apenas se escolher "Escolher data manual". Se aplicar apenas um dia, essa será a data exata usada. Se aplicar semana toda, escolha uma segunda-feira.</div>
      <br><br>

      <label>Aplicar:</label>
      <select name="applyScope">
        <option value="semana">Semana toda</option>
        <option value="segunda">Apenas Segunda</option>
        <option value="terca">Apenas Terça</option>
        <option value="quarta">Apenas Quarta</option>
        <option value="quinta">Apenas Quinta</option>
        <option value="sexta">Apenas Sexta</option>
        <option value="sabado">Apenas Sábado</option>
      </select>
      <br><br>

      <label>Confirmação:</label>
      <input name="confirmText" placeholder="Digite APLICAR para confirmar" required>

      <button type="submit">Aplicar essa grade no app</button>
    </form>
  </section>

  <section>
    <h2>6. Grade sorteada</h2>
    <div class="muted">Rascunho. Ainda não altera a grade ativa do app.</div>
    <table>
      <thead>
        <tr>
          <th>Dia</th>
          <th>Hora</th>
          <th>Tela 1</th>
          <th>Tela 2</th>
          <th>Tela 3</th>
        </tr>
      </thead>
      <tbody>
        ${drawRows || '<tr><td colspan="5">Nenhum sorteio carregado ainda.</td></tr>'}
      </tbody>
    </table>
  </section>
</main>
</body>
</html>
  `;
}

function fenixSimpleAdminAuth(req, res, next) {
  req.headers['x-fenix-admin'] = 'GokuuMods';
  req.headers['x-fenix-admin-secret'] = String(req.body?.adminSecret || req.query?.adminSecret || '').trim();
  return requireFenixAdmin(req, res, next);
}

app.get('/admin/grade-sorteio-simples', (req, res) => {
  res.type('html').send(fenixRenderGradeSorteioSimplesPage());
});

app.post('/admin/grade-sorteio-simples/ver', fenixSimpleAdminAuth, (req, res) => {
  const applicants = fenixReadFormApplicantsFileFinal();
  const draw = fenixReadGradeDrawFileFinal();

  res.type('html').send(fenixRenderGradeSorteioSimplesPage({
    applicants,
    draw,
    message: 'Inscritos carregados: ' + applicants.length
  }));
});


app.post('/admin/grade-sorteio-simples/importar', fenixSimpleAdminAuth, (req, res) => {
  try {
    const pasted = String(req.body && req.body.text ? req.body.text : '');

    if (!pasted.trim()) {
      return res.type('html').send(fenixRenderGradeSorteioSimplesPage({
        message: 'Erro: o campo da planilha veio vazio. Cole cabeçalho + respostas.'
      }));
    }

    const parsed = fenixParseApplicantsFromPaste(pasted);

    if (!parsed.length) {
      return res.type('html').send(fenixRenderGradeSorteioSimplesPage({
        message: 'Erro: nenhum inscrito encontrado. Cole a planilha com cabeçalho.'
      }));
    }

    const currentList = fenixReadFormApplicantsFileFinal();
    const current = new Map();

    for (const applicant of currentList) {
      const key = fenixNormalizeKickNick(applicant.slug || applicant.nick).toLowerCase();
      if (key) current.set(key, applicant);
    }

    for (const applicant of parsed) {
      const key = applicant.slug;

      if (current.has(key)) {
        const existing = current.get(key);
        Object.assign(existing, {
          ...existing,
          ...applicant,
          ignored: Boolean(existing.ignored),
          updatedAt: new Date().toISOString()
        });
      } else {
        currentList.push(applicant);
        current.set(key, applicant);
      }
    }

    const saved = fenixSaveFormApplicantsFileFinal(currentList);

    return res.type('html').send(fenixRenderGradeSorteioSimplesPage({
      applicants: saved,
      draw: fenixReadGradeDrawFileFinal(),
      message: 'Importado com sucesso. Total salvo: ' + saved.length
    }));
  } catch (error) {
    console.error('ERRO IMPORTAR GRADE SORTEIO SIMPLES:', error);

    return res.type('html').send(`
<!doctype html>
<html lang="pt-BR">
<head>
  <meta charset="utf-8">
  <title>Erro importação</title>
</head>
<body style="background:#090909;color:white;font-family:Arial;padding:30px">
  <h1 style="color:#ff7777">Erro ao importar</h1>
  <p>O backend encontrou um erro. Detalhe:</p>
  <pre style="white-space:pre-wrap;background:#111;border:1px solid #333;padding:15px;border-radius:10px;color:#ffb3b3">${String(error && (error.stack || error.message) || error)}</pre>
  <a href="/admin/grade-sorteio-simples" style="color:#f3c451;font-size:18px">Voltar</a>
</body>
</html>
    `);
  }
});


app.post('/admin/grade-sorteio-simples/gerar', fenixSimpleAdminAuth, (req, res) => {
  const applicants = fenixReadFormApplicantsFileFinal();

  const draw = fenixGenerateGradeDrawAdminChooseVagosFinal(applicants, {
    vacancyPerDay: Number(req.body?.vacancyPerDay || 0),
    manualVacantHours: req.body?.manualVacantHours || "",
    maxWeekly: Number(req.body?.maxWeekly || 8),
    maxDaily: Number(req.body?.maxDaily || 2),
    avoidConsecutive: req.body?.avoidConsecutive || "sim"
  });

  fenixSaveGradeDrawFileFinal(draw);

  res.type('html').send(fenixRenderGradeSorteioSimplesPage({
    applicants,
    draw,
    message: 'Sorteio gerado. Inscritos: ' + applicants.length + ' | Vagos: ' + draw.summary.totalVacantHours + ' | Meta semanal: ' + draw.maxWeekly + ' | Max dia: ' + draw.maxDaily + fenixFixedTargetMessageFinal(draw)
  }));
});


// FENIX_IMPORTAR_GRADE_EXCEL_PRONTA_FINAL
function fenixExcelDayMapFinal() {
  return [
    { key: 'segunda', label: 'Segunda' },
    { key: 'terca', label: 'Terça' },
    { key: 'quarta', label: 'Quarta' },
    { key: 'quinta', label: 'Quinta' },
    { key: 'sexta', label: 'Sexta' },
    { key: 'sabado', label: 'Sábado' }
  ];
}

function fenixNormalizeExcelDayFinal(value) {
  const text = String(value || '')
    .normalize('NFD')
    .replace(/[\u0300-\u036f]/g, '')
    .trim()
    .toLowerCase();

  const map = {
    segunda: 'segunda',
    seg: 'segunda',
    terca: 'terca',
    ter: 'terca',
    quarta: 'quarta',
    qua: 'quarta',
    quinta: 'quinta',
    qui: 'quinta',
    sexta: 'sexta',
    sex: 'sexta',
    sabado: 'sabado',
    sab: 'sabado'
  };

  return map[text] || '';
}

function fenixNormalizeExcelHourFinal(value) {
  const text = String(value || '').trim();
  const match = text.match(/(\d{1,2})\s*:\s*00/);

  if (!match) return '';

  const hour = Math.max(0, Math.min(23, Number(match[1] || 0)));
  return String(hour).padStart(2, '0') + ':00';
}

function fenixScreenFromExcelNameFinal(value) {
  const nick = String(value || '').trim();

  if (!nick) {
    return { status: 'MANUAL', nick: '' };
  }

  const upper = nick.toUpperCase();

  if (upper === 'VAGO') {
    return { status: 'VAGO', nick: '' };
  }

  if (upper === 'PREENCHER MANUAL') {
    return { status: 'MANUAL', nick: '' };
  }

  return {
    status: 'OK',
    nick,
    slug: fenixNormalizeKickNick(nick)
  };
}

function fenixBuildExcelDrawFinal(rows, sourceLabel) {
  const dayLabelMap = {};
  for (const day of fenixExcelDayMapFinal()) {
    dayLabelMap[day.key] = day.label;
  }

  rows.sort((a, b) => {
    const da = fenixDayOffsetFromKeyFinal(a.day);
    const db = fenixDayOffsetFromKeyFinal(b.day);
    if (da !== db) return da - db;
    return String(a.hourLabel || '').localeCompare(String(b.hourLabel || ''));
  });

  let ok = 0;
  let vago = 0;
  let manual = 0;

  for (const row of rows) {
    row.dayLabel = dayLabelMap[row.day] || row.day;
    for (const screen of row.screens || []) {
      if (screen.status === 'OK') ok += 1;
      else if (screen.status === 'VAGO') vago += 1;
      else manual += 1;
    }
  }

  return {
    id: 'excel-' + Date.now(),
    mode: 'excel',
    source: sourceLabel || 'grade-excel',
    createdAt: new Date().toISOString(),
    maxWeekly: 0,
    maxDaily: 0,
    summary: {
      applicants: 0,
      filled: ok,
      totalVacantHours: vago,
      manualFill: manual,
      totalRows: rows.length
    },
    rows
  };
}

function fenixParseExcelReadyScheduleFinal(text, importScope) {
  const pasted = String(text || '').replace(/\r/g, '').trim();

  if (!pasted) return [];

  const scope = String(importScope || 'semana').toLowerCase();
  const days = fenixExcelDayMapFinal();
  const rows = [];
  const seen = new Set();

  function allowDay(dayKey) {
    return scope === 'semana' || dayKey === scope;
  }

  function addRow(dayKey, hourLabel, screen1, screen2, screen3) {
    if (!dayKey || !allowDay(dayKey) || !/^\d{2}:00$/.test(hourLabel)) return;

    const key = dayKey + '|' + hourLabel;

    if (seen.has(key)) return;
    seen.add(key);

    rows.push({
      day: dayKey,
      dayLabel: '',
      hourLabel,
      screens: [
        fenixScreenFromExcelNameFinal(screen1),
        fenixScreenFromExcelNameFinal(screen2),
        fenixScreenFromExcelNameFinal(screen3)
      ]
    });
  }

  for (const rawLine of pasted.split('\n')) {
    const line = String(rawLine || '').trim();
    if (!line) continue;

    const cols = rawLine.split('\t').map((item) => String(item || '').trim());
    const dayKey = fenixNormalizeExcelDayFinal(cols[0]);
    const hourLabel = fenixNormalizeExcelHourFinal(cols[1]);

    if (dayKey && hourLabel && cols.length >= 5) {
      addRow(dayKey, hourLabel, cols[2], cols[3], cols[4]);
      continue;
    }

    const firstHour = fenixNormalizeExcelHourFinal(cols[0]);

    if (firstHour && cols.length >= 19) {
      for (let dayIndex = 0; dayIndex < days.length; dayIndex += 1) {
        const day = days[dayIndex];
        const start = 1 + dayIndex * 3;

        addRow(day.key, firstHour, cols[start], cols[start + 1], cols[start + 2]);
      }
    }
  }

  return rows;
}

app.post('/admin/grade-sorteio-simples/importar-excel', fenixSimpleAdminAuth, (req, res) => {
  try {
    const applicants = fenixReadFormApplicantsFileFinal();
    const pasted = String(req.body?.excelText || '');
    const importScope = String(req.body?.importScope || 'semana').toLowerCase();

    const rows = fenixParseExcelReadyScheduleFinal(pasted, importScope);

    if (!rows.length) {
      return res.type('html').send(fenixRenderGradeSorteioSimplesPage({
        applicants,
        draw: fenixReadGradeDrawFileFinal(),
        message: 'Erro: nenhuma linha da grade foi encontrada. Cole a grade do Excel com Horarios + Tela 1, Tela 2 e Tela 3.'
      }));
    }

    const draw = fenixBuildExcelDrawFinal(rows, 'grade-excel-' + importScope);
    fenixSaveGradeDrawFileFinal(draw);

    return res.type('html').send(fenixRenderGradeSorteioSimplesPage({
      applicants,
      draw,
      message: 'Grade do Excel importada como rascunho. Linhas: ' + rows.length + ' | Escopo: ' + importScope + '. Agora confira e clique em Aplicar essa grade no app.'
    }));
  } catch (error) {
    console.error('ERRO IMPORTAR GRADE EXCEL:', error);

    return res.type('html').send(fenixRenderGradeSorteioSimplesPage({
      applicants: fenixReadFormApplicantsFileFinal(),
      draw: fenixReadGradeDrawFileFinal(),
      message: 'Erro ao importar grade do Excel: ' + String(error.message || error)
    }));
  }
});


// FENIX_GRADE_SORTEIO_MELHORIAS_FINAL
function fenixParseManualVacantHoursFinal(value) {
  const text = String(value || '').trim();

  if (!text) return [];

  return Array.from(new Set(
    text
      .split(/[,. ;\n\r\t]+/g)
      .map((item) => item.replace(/h/gi, '').replace(':00', '').trim())
      .filter(Boolean)
      .map((item) => Number(item))
      .filter((hour) => Number.isInteger(hour) && hour >= 0 && hour <= 23)
  )).sort((a, b) => a - b);
}

function fenixDrawDaysFromOptionFinal(dayOption) {
  const option = String(dayOption || 'semana').toLowerCase();

  if (FENIX_DRAW_DAYS.includes(option)) {
    return [option];
  }

  return FENIX_DRAW_DAYS.slice();
}


function fenixGenerateGradeDrawImprovedFinal(applicants, options = {}) {
  const screensPerHour = 3;
  const dayOption = String(options.dayOption || 'semana').toLowerCase();
  const daysToDraw = fenixDrawDaysFromOptionFinal(dayOption);
  const vacancyPerDay = Math.max(0, Math.min(24, Number(options.vacancyPerDay || 0)));
  const manualVacantHours = fenixParseManualVacantHoursFinal(options.manualVacantHours);

  // Regra pensada para 50+ usuários:
  // Semana cheia tem 432 telas. Com 50 pessoas, média fica perto de 7/8 por pessoa.
  const maxWeekly = Math.max(1, Number(options.maxWeekly || 8));
  const maxDaily = Math.max(1, Number(options.maxDaily || 2));
  const avoidConsecutive = String(options.avoidConsecutive || 'sim').toLowerCase() !== 'nao';

  const usage = {};
  const usageByDay = {};
  const lastHourByDay = {};
  const rows = [];

  const activeApplicants = applicants
    .filter((item) => item && !item.ignored && item.nick)
    .map((item) => ({
      ...item,
      slug: fenixNormalizeKickNick(item.slug || item.nick).toLowerCase(),
      url: item.url || fenixKickUrlFromNick(item.nick)
    }));

  for (const applicant of activeApplicants) {
    usage[applicant.slug] = 0;
    usageByDay[applicant.slug] = {};
  }

  for (const dayKey of daysToDraw) {
    const randomVacants = manualVacantHours.length ? new Set() : fenixPickVacantHours(vacancyPerDay);
    const manualVacants = new Set(manualVacantHours);

    lastHourByDay[dayKey] = new Set();

    for (let hour = 0; hour < 24; hour += 1) {
      const isVacant = manualVacants.has(hour) || randomVacants.has(hour);

      const row = {
        id: dayKey + '-' + String(hour).padStart(2, '0'),
        day: dayKey,
        dayLabel: (FENIX_FORM_DAYS.find((day) => day.key === dayKey) || {}).label || dayKey,
        hour,
        hourLabel: fenixFormatHour(hour),
        manualVacancy: isVacant,
        screens: []
      };

      if (isVacant) {
        for (let screen = 1; screen <= screensPerHour; screen += 1) {
          row.screens.push({
            screen,
            status: 'VAGO',
            nick: '',
            url: ''
          });
        }

        rows.push(row);
        lastHourByDay[dayKey] = new Set();
        continue;
      }

      const picked = new Set();

      for (let screen = 1; screen <= screensPerHour; screen += 1) {
        let candidates = activeApplicants.filter((applicant) => {
          const available = Array.isArray(applicant.availability?.[dayKey])
            ? applicant.availability[dayKey]
            : [];

          const weekCount = usage[applicant.slug] || 0;
          const dayCount = usageByDay[applicant.slug]?.[dayKey] || 0;

          return available.includes(hour)
            && !picked.has(applicant.slug)
            && weekCount < maxWeekly
            && dayCount < maxDaily;
        });

        if (avoidConsecutive) {
          const notLastHour = candidates.filter((applicant) => {
            return !lastHourByDay[dayKey]?.has(applicant.slug);
          });

          if (notLastHour.length > 0) {
            candidates = notLastHour;
          }
        }

        candidates.sort((a, b) => {
          const aUsage = usage[a.slug] || 0;
          const bUsage = usage[b.slug] || 0;

          if (aUsage !== bUsage) return aUsage - bUsage;

          const aDay = usageByDay[a.slug]?.[dayKey] || 0;
          const bDay = usageByDay[b.slug]?.[dayKey] || 0;

          if (aDay !== bDay) return aDay - bDay;

          const aOptions = Object.values(a.availability || {}).reduce((sum, hours) => {
            return sum + (Array.isArray(hours) ? hours.length : 0);
          }, 0);

          const bOptions = Object.values(b.availability || {}).reduce((sum, hours) => {
            return sum + (Array.isArray(hours) ? hours.length : 0);
          }, 0);

          if (aOptions !== bOptions) return aOptions - bOptions;

          return Math.random() - 0.5;
        });

        const selected = candidates[0];

        if (!selected) {
          row.screens.push({
            screen,
            status: 'VAGO_MANUAL',
            nick: '',
            url: ''
          });
          continue;
        }

        picked.add(selected.slug);
        usage[selected.slug] = (usage[selected.slug] || 0) + 1;
        usageByDay[selected.slug][dayKey] = (usageByDay[selected.slug][dayKey] || 0) + 1;

        row.screens.push({
          screen,
          status: 'OK',
          name: selected.name,
          nick: selected.nick,
          slug: selected.slug,
          url: selected.url,
          whatsapp: selected.whatsapp
        });
      }

      rows.push(row);
      lastHourByDay[dayKey] = new Set(row.screens.filter((s) => s.status === 'OK').map((s) => s.slug));
    }
  }

  const zeroApplicants = activeApplicants
    .filter((applicant) => (usage[applicant.slug] || 0) === 0)
    .map((applicant) => applicant.slug);

  return {
    id: 'draw-' + Date.now(),
    createdAt: new Date().toISOString(),
    dayOption,
    daysToDraw,
    vacancyPerDay,
    manualVacantHours,
    maxWeekly,
    maxDaily,
    avoidConsecutive,
    ruleMode: '50_USERS_READY',
    screensPerHour,
    rows,
    summary: {
      applicants: activeApplicants.length,
      totalRows: rows.length,
      totalVacantHours: rows.filter((row) => row.manualVacancy).length,
      totalOpenScreens: rows.reduce((sum, row) => {
        return sum + row.screens.filter((screen) => screen.status !== 'OK').length;
      }, 0),
      zeroApplicants,
      usage
    }
  };
}

// FENIX_RESTORE_GRADE_MELHORADO_REDIRECT
app.get('/admin/grade-sorteio-melhorado', (req, res) => {
  res.redirect('/admin/grade-sorteio-simples');
});

// FENIX_FIX_LIMPAR_INSCRITOS_ALIAS_FINAL
app.post('/admin/grade-sorteio-melhorado/limpar-inscritos', (req, res, next) => {
  req.headers['x-fenix-admin'] = 'GokuuMods';
  req.headers['x-fenix-admin-secret'] = String(req.body?.adminSecret || '').trim();
  next();
}, requireFenixAdmin, (req, res) => {
  const confirmText = String(req.body?.confirmText || '').trim().toUpperCase();

  if (confirmText !== 'APAGAR') {
    return res.type('html').send(fenixRenderGradeSorteioSimplesPage({
      applicants: fenixReadFormApplicantsFileFinal(),
      draw: fenixReadGradeDrawFileFinal(),
      message: 'Para limpar todos os inscritos, digite APAGAR no campo de confirmação.'
    }));
  }

  fenixSaveFormApplicantsFileFinal([]);

  return res.type('html').send(fenixRenderGradeSorteioSimplesPage({
    applicants: [],
    draw: fenixReadGradeDrawFileFinal(),
    message: 'Todos os inscritos foram apagados. Agora importe a planilha completa novamente.'
  }));
});

// FENIX_SIMPLE_DRAW_ADMIN_CHOOSE_VAGOS_FINAL
function fenixGenerateGradeDrawAdminChooseVagosOldFinal(applicants, options = {}) {
  const screensPerHour = 3;
  const vacancyPerDay = Math.max(0, Math.min(24, Number(options.vacancyPerDay || 0)));
  const manualVacantHours = fenixParseManualVacantHoursFinal(options.manualVacantHours || "");
  const maxWeekly = Math.max(1, Number(options.maxWeekly || 8));
  const maxDaily = Math.max(1, Number(options.maxDaily || 2));
  const avoidConsecutive = String(options.avoidConsecutive || "sim").toLowerCase() !== "nao";

  const usage = {};
  const usageByDay = {};
  const lastHourByDay = {};
  const rows = [];

  const activeApplicants = applicants
    .filter((item) => item && !item.ignored && item.nick)
    .map((item) => ({
      ...item,
      slug: fenixNormalizeKickNick(item.slug || item.nick).toLowerCase(),
      url: item.url || fenixKickUrlFromNick(item.nick)
    }));

  for (const applicant of activeApplicants) {
    usage[applicant.slug] = 0;
    usageByDay[applicant.slug] = {};
  }

  for (const dayKey of FENIX_DRAW_DAYS) {
    const randomVacants = manualVacantHours.length ? new Set() : fenixPickVacantHours(vacancyPerDay);
    const manualVacants = new Set(manualVacantHours);

    lastHourByDay[dayKey] = new Set();

    for (let hour = 0; hour < 24; hour += 1) {
      const isVacant = manualVacants.has(hour) || randomVacants.has(hour);

      const row = {
        id: dayKey + "-" + String(hour).padStart(2, "0"),
        day: dayKey,
        dayLabel: (FENIX_FORM_DAYS.find((day) => day.key === dayKey) || {}).label || dayKey,
        hour,
        hourLabel: fenixFormatHour(hour),
        manualVacancy: isVacant,
        screens: []
      };

      if (isVacant) {
        for (let screen = 1; screen <= screensPerHour; screen += 1) {
          row.screens.push({
            screen,
            status: "VAGO",
            nick: "",
            url: ""
          });
        }

        rows.push(row);
        lastHourByDay[dayKey] = new Set();
        continue;
      }

      const picked = new Set();

      for (let screen = 1; screen <= screensPerHour; screen += 1) {
        let candidates = activeApplicants.filter((applicant) => {
          const available = Array.isArray(applicant.availability?.[dayKey])
            ? applicant.availability[dayKey]
            : [];

          const weekCount = usage[applicant.slug] || 0;
          const dayCount = usageByDay[applicant.slug]?.[dayKey] || 0;

          return available.includes(hour)
            && !picked.has(applicant.slug)
            && weekCount < maxWeekly
            && dayCount < maxDaily;
        });

        if (avoidConsecutive) {
          const notLastHour = candidates.filter((applicant) => {
            return !lastHourByDay[dayKey]?.has(applicant.slug);
          });

          if (notLastHour.length > 0) {
            candidates = notLastHour;
          }
        }

        candidates.sort((a, b) => {
          const aUsage = usage[a.slug] || 0;
          const bUsage = usage[b.slug] || 0;

          if (aUsage !== bUsage) return aUsage - bUsage;

          const aDay = usageByDay[a.slug]?.[dayKey] || 0;
          const bDay = usageByDay[b.slug]?.[dayKey] || 0;

          if (aDay !== bDay) return aDay - bDay;

          return Math.random() - 0.5;
        });

        const selected = candidates[0];

        if (!selected) {
          row.screens.push({
            screen,
            status: "VAGO_MANUAL",
            nick: "",
            url: ""
          });
          continue;
        }

        picked.add(selected.slug);
        usage[selected.slug] = (usage[selected.slug] || 0) + 1;
        usageByDay[selected.slug][dayKey] = (usageByDay[selected.slug][dayKey] || 0) + 1;

        row.screens.push({
          screen,
          status: "OK",
          name: selected.name,
          nick: selected.nick,
          slug: selected.slug,
          url: selected.url,
          whatsapp: selected.whatsapp
        });
      }

      rows.push(row);
      lastHourByDay[dayKey] = new Set(row.screens.filter((s) => s.status === "OK").map((s) => s.slug));
    }
  }

  const zeroApplicants = activeApplicants
    .filter((applicant) => (usage[applicant.slug] || 0) === 0)
    .map((applicant) => applicant.slug);

  return {
    id: "draw-" + Date.now(),
    createdAt: new Date().toISOString(),
    vacancyPerDay,
    manualVacantHours,
    maxWeekly,
    maxDaily,
    avoidConsecutive,
    screensPerHour,
    rows,
    summary: {
      applicants: activeApplicants.length,
      totalRows: rows.length,
      totalVacantHours: rows.filter((row) => row.manualVacancy).length,
      totalOpenScreens: rows.reduce((sum, row) => {
        return sum + row.screens.filter((screen) => screen.status !== "OK").length;
      }, 0),
      zeroApplicants,
      usage
    }
  };
}

// FENIX_SIMPLE_DRAW_RESUMO_VISUAL_FINAL
function fenixDrawVisualSummaryFinal(draw) {
  const rows = draw && Array.isArray(draw.rows) ? draw.rows : [];

  let filled = 0;
  let reservedVacant = 0;
  let manualFill = 0;

  for (const row of rows) {
    for (const screen of row.screens || []) {
      if (screen.status === 'OK') filled += 1;
      else if (screen.status === 'VAGO') reservedVacant += 1;
      else manualFill += 1;
    }
  }

  const zeroApplicants = draw?.summary?.zeroApplicants || [];

  return {
    filled,
    reservedVacant,
    manualFill,
    zeroApplicants,
    totalScreens: filled + reservedVacant + manualFill
  };
}


// FENIX_META_FIXA_SEMANAL_OVERRIDE_FINAL
function fenixFixedTargetMessageFinal(draw) {
  const below = Array.isArray(draw?.summary?.belowTarget) ? draw.summary.belowTarget : [];

  if (!below.length) {
    return ' | Todos bateram a meta semanal.';
  }

  return ' | Abaixo da meta: ' + below.map((item) => item.nick + ' ' + item.count + '/' + item.target).join(', ');
}

function fenixGenerateGradeDrawAdminChooseVagosFinal(applicants, options = {}) {
  const screensPerHour = 3;
  const dayOption = String(options.dayOption || 'semana').toLowerCase();
  const daysToDraw = fenixDrawDaysFromOptionFinal(dayOption);
  const vacancyPerDay = Math.max(0, Math.min(24, Number(options.vacancyPerDay || 0)));
  const manualVacantHours = fenixParseManualVacantHoursFinal(options.manualVacantHours);

  const targetWeekly = Math.max(1, Number(options.maxWeekly || 4));
  const maxDaily = Math.max(1, Number(options.maxDaily || 2));
  const avoidConsecutive = String(options.avoidConsecutive || 'sim').toLowerCase() !== 'nao';

  const usage = {};
  const usageByDay = {};
  const lastHourByDay = {};
  const rows = [];

  const activeApplicants = applicants
    .filter((item) => item && !item.ignored && item.nick)
    .map((item) => ({
      ...item,
      slug: fenixNormalizeKickNick(item.slug || item.nick).toLowerCase(),
      url: item.url || fenixKickUrlFromNick(item.nick)
    }));

  for (const applicant of activeApplicants) {
    usage[applicant.slug] = 0;
    usageByDay[applicant.slug] = {};
  }

  for (const dayKey of daysToDraw) {
    const randomVacants = manualVacantHours.length ? new Set() : fenixPickVacantHours(vacancyPerDay);
    const manualVacants = new Set(manualVacantHours);

    lastHourByDay[dayKey] = new Set();

    for (let hour = 0; hour < 24; hour += 1) {
      const isVacant = manualVacants.has(hour) || randomVacants.has(hour);

      const row = {
        id: dayKey + '-' + String(hour).padStart(2, '0'),
        day: dayKey,
        dayLabel: (FENIX_FORM_DAYS.find((day) => day.key === dayKey) || {}).label || dayKey,
        hour,
        hourLabel: fenixFormatHour(hour),
        manualVacancy: isVacant,
        screens: []
      };

      if (isVacant) {
        for (let screen = 1; screen <= screensPerHour; screen += 1) {
          row.screens.push({
            screen,
            status: 'VAGO',
            nick: '',
            url: ''
          });
        }

        rows.push(row);
        lastHourByDay[dayKey] = new Set();
        continue;
      }

      const picked = new Set();

      for (let screen = 1; screen <= screensPerHour; screen += 1) {
        let candidates = activeApplicants.filter((applicant) => {
          const available = Array.isArray(applicant.availability?.[dayKey])
            ? applicant.availability[dayKey]
            : [];

          const weekCount = usage[applicant.slug] || 0;
          const dayCount = usageByDay[applicant.slug]?.[dayKey] || 0;

          return available.includes(hour)
            && !picked.has(applicant.slug)
            && weekCount < targetWeekly
            && dayCount < maxDaily;
        });

        if (avoidConsecutive) {
          const notLastHour = candidates.filter((applicant) => {
            return !lastHourByDay[dayKey]?.has(applicant.slug);
          });

          if (notLastHour.length > 0) {
            candidates = notLastHour;
          }
        }

        candidates.sort((a, b) => {
          const aUsage = usage[a.slug] || 0;
          const bUsage = usage[b.slug] || 0;

          if (aUsage !== bUsage) return aUsage - bUsage;

          const aDay = usageByDay[a.slug]?.[dayKey] || 0;
          const bDay = usageByDay[b.slug]?.[dayKey] || 0;

          if (aDay !== bDay) return aDay - bDay;

          const aOptions = Object.values(a.availability || {}).reduce((sum, hours) => {
            return sum + (Array.isArray(hours) ? hours.length : 0);
          }, 0);

          const bOptions = Object.values(b.availability || {}).reduce((sum, hours) => {
            return sum + (Array.isArray(hours) ? hours.length : 0);
          }, 0);

          if (aOptions !== bOptions) return aOptions - bOptions;

          return Math.random() - 0.5;
        });

        const selected = candidates[0];

        if (!selected) {
          row.screens.push({
            screen,
            status: 'VAGO_MANUAL',
            nick: '',
            url: ''
          });
          continue;
        }

        picked.add(selected.slug);
        usage[selected.slug] = (usage[selected.slug] || 0) + 1;
        usageByDay[selected.slug][dayKey] = (usageByDay[selected.slug][dayKey] || 0) + 1;

        row.screens.push({
          screen,
          status: 'OK',
          name: selected.name,
          nick: selected.nick,
          slug: selected.slug,
          url: selected.url,
          whatsapp: selected.whatsapp
        });
      }

      rows.push(row);
      lastHourByDay[dayKey] = new Set(row.screens.filter((screen) => screen.status === 'OK').map((screen) => screen.slug));
    }
  }

  const belowTarget = activeApplicants
    .map((applicant) => ({
      slug: applicant.slug,
      nick: applicant.nick,
      count: usage[applicant.slug] || 0,
      target: targetWeekly
    }))
    .filter((item) => item.count < item.target)
    .sort((a, b) => {
      if (a.count !== b.count) return a.count - b.count;
      return String(a.nick).localeCompare(String(b.nick));
    });

  const zeroApplicants = activeApplicants
    .filter((applicant) => (usage[applicant.slug] || 0) === 0)
    .map((applicant) => applicant.slug);

  // FENIX_GRADE_DRAW_ORDER_MONDAY_FIRST_128
  const fenixDrawDayOrder128 = {
    segunda: 0,
    terca: 1,
    quarta: 2,
    quinta: 3,
    sexta: 4,
    sabado: 5,
    domingo: 6
  };

  function fenixDrawDayIndex128(value) {
    const key = String(value || '')
      .trim()
      .toLowerCase()
      .normalize('NFD')
      .replace(/[\u0300-\u036f]/g, '');

    return Object.prototype.hasOwnProperty.call(fenixDrawDayOrder128, key)
      ? fenixDrawDayOrder128[key]
      : 99;
  }

  rows.sort((a, b) => {
    const dayDiff = fenixDrawDayIndex128(a.day) - fenixDrawDayIndex128(b.day);
    if (dayDiff !== 0) return dayDiff;
    return String(a.hourLabel || '').localeCompare(String(b.hourLabel || ''));
  });

  const totalVacantHours = rows.filter((row) => row.manualVacancy).length;

  return {
    id: 'draw-' + Date.now(),
    createdAt: new Date().toISOString(),
    dayOption,
    daysToDraw,
    vacancyPerDay,
    manualVacantHours,
    maxWeekly: targetWeekly,
    maxDaily,
    avoidConsecutive,
    usage,
    usageByDay,
    rows,
    summary: {
      applicants: activeApplicants.length,
      totalVacantHours,
      zeroApplicants,
      belowTarget
    }
  };
}


// FENIX_APLICAR_SORTEIO_GRADE_REAL_FINAL
function fenixDateOnlyFinal(date) {
  const year = date.getFullYear();
  const month = String(date.getMonth() + 1).padStart(2, '0');
  const day = String(date.getDate()).padStart(2, '0');
  return year + '-' + month + '-' + day;
}

function fenixMondayOfWeekFinal(baseDate = new Date()) {
  const date = new Date(baseDate.getFullYear(), baseDate.getMonth(), baseDate.getDate(), 12, 0, 0);
  const day = date.getDay();
  const diff = day === 0 ? -6 : 1 - day;
  date.setDate(date.getDate() + diff);
  return date;
}

function fenixAddDaysFinal(date, amount) {
  const next = new Date(date.getFullYear(), date.getMonth(), date.getDate(), 12, 0, 0);
  next.setDate(next.getDate() + amount);
  return next;
}

function fenixWeekStartFromApplyModeFinal(mode, manualStartDate) {
  const selected = String(mode || 'next').toLowerCase();

  if (selected === 'manual' && /^\d{4}-\d{2}-\d{2}$/.test(String(manualStartDate || ''))) {
    return new Date(String(manualStartDate) + 'T12:00:00');
  }

  const currentMonday = fenixMondayOfWeekFinal(new Date());

  if (selected === 'current') {
    return currentMonday;
  }

  return fenixAddDaysFinal(currentMonday, 7);
}

function fenixDayOffsetFromKeyFinal(dayKey) {
  const normalized = String(dayKey || '')
    .trim()
    .toLowerCase()
    .normalize('NFD')
    .replace(/[\u0300-\u036f]/g, '');

  const map = {
    segunda: 0,
    terca: 1,
    quarta: 2,
    quinta: 3,
    sexta: 4,
    sabado: 5,
    domingo: 6
  };

  return Object.prototype.hasOwnProperty.call(map, normalized) ? map[normalized] : null;
}

function fenixScreenToScheduleFinal(screen) {
  if (!screen || screen.status !== 'OK' || !screen.nick) {
    return {
      name: '',
      url: '',
      maintenance: true
    };
  }

  const nick = String(screen.nick || '').trim();

  return {
    name: nick,
    url: fenixKickUrlFromNick(nick),
    maintenance: false
  };
}

function fenixApplyDrawToRealScheduleFinal(draw, options = {}) {
  if (!draw || !Array.isArray(draw.rows) || !draw.rows.length) {
    throw new Error('Nenhum sorteio encontrado para aplicar.');
  }

  const confirmText = String(options.confirmText || '').trim().toUpperCase();

  if (confirmText !== 'APLICAR') {
    throw new Error('Digite APLICAR para confirmar.');
  }

  const applyScope = String(options.applyScope || 'semana').toLowerCase();
  const weekStart = fenixWeekStartFromApplyModeFinal(options.weekMode, options.manualStartDate);
  const data = readFenixData();

  data.schedule = Array.isArray(data.schedule) ? data.schedule : [];

  let saved = 0;
  const affectedDates = new Set();

  const rowsToApply = draw.rows.filter((row) => {
    if (!row || !row.day) return false;
    if (applyScope === 'semana') return true;
    return String(row.day).toLowerCase() === applyScope;
  });

  for (const row of rowsToApply) {
    const offset = fenixDayOffsetFromKeyFinal(row.day);
    if (offset === null) continue;

    let slotDate = fenixDateOnlyFinal(fenixAddDaysFinal(weekStart, offset));

    if (
      String(options.weekMode || '').toLowerCase() === 'manual' &&
      applyScope !== 'semana' &&
      /^\d{4}-\d{2}-\d{2}$/.test(String(options.manualStartDate || ''))
    ) {
      slotDate = String(options.manualStartDate);
    }
    const slotHour = String(row.hourLabel || '').trim();

    if (!/^\d{2}:00$/.test(slotHour)) continue;

    affectedDates.add(slotDate);

    let slot = data.schedule.find((item) => item.slotDate === slotDate && item.slotHour === slotHour);

    if (!slot) {
      slot = {
        id: crypto.randomUUID(),
        slotDate,
        slotHour,
        active: true,
        createdAt: new Date().toISOString()
      };

      data.schedule.push(slot);
    }

    const screens = Array.isArray(row.screens) ? row.screens : [];
    const s1 = fenixScreenToScheduleFinal(screens[0]);
    const s2 = fenixScreenToScheduleFinal(screens[1]);
    const s3 = fenixScreenToScheduleFinal(screens[2]);

    slot.screen1Name = s1.name;
    slot.screen1Url = s1.url;
    slot.screen1Maintenance = s1.maintenance;

    slot.screen2Name = s2.name;
    slot.screen2Url = s2.url;
    slot.screen2Maintenance = s2.maintenance;

    slot.screen3Name = s3.name;
    slot.screen3Url = s3.url;
    slot.screen3Maintenance = s3.maintenance;

    slot.active = true;
    slot.updatedAt = new Date().toISOString();
    slot.source = 'grade-sorteio';
    slot.drawId = draw.id || '';

    saved += 1;
  }

  writeFenixData(data);

  return {
    saved,
    weekStart: fenixDateOnlyFinal(weekStart),
    affectedDates: Array.from(affectedDates).sort(),
    applyScope
  };
}

app.post('/admin/grade-sorteio-simples/aplicar', fenixSimpleAdminAuth, (req, res) => {
  try {
    const applicants = fenixReadFormApplicantsFileFinal();
    const draw = fenixReadGradeDrawFileFinal();

    const result = fenixApplyDrawToRealScheduleFinal(draw, {
      weekMode: req.body?.weekMode || 'next',
      manualStartDate: req.body?.manualStartDate || '',
      applyScope: req.body?.applyScope || 'semana',
      confirmText: req.body?.confirmText || ''
    });

    return res.type('html').send(fenixRenderGradeSorteioSimplesPage({
      applicants,
      draw,
      message: 'Grade aplicada no app. Horários salvos: ' + result.saved + ' | Início: ' + result.weekStart + ' | Escopo: ' + result.applyScope
    }));
  } catch (error) {
    return res.type('html').send(fenixRenderGradeSorteioSimplesPage({
      applicants: fenixReadFormApplicantsFileFinal(),
      draw: fenixReadGradeDrawFileFinal(),
      message: 'Erro ao aplicar: ' + String(error.message || error)
    }));
  }
});


// FENIX_WEEKLY_HISTORY_AND_EXTRA_TARGET_ROUTES_FINAL
app.get('/api/fenix/admin/weekly-history', requireFenixAdmin, (req, res) => {
  const data = readFenixData();
  const weeklyControl = ensureFenixWeeklyControlFinal(data);
  const currentGoal = Number(weeklyControl.info?.goal || FENIX_WEEKLY_GOAL_POINTS_FINAL);
  const currentMinimum = Number(weeklyControl.info?.minimum || FENIX_WEEKLY_MINIMUM_POINTS_FINAL);

  if (weeklyControl.changed) {
    writeFenixData(data);
  }

  const users = data.users
    .map((user) => {
      const weeklyPoints = Number(user.weeklyPoints || 0);
      const percent = fenixWeeklyPercentFinal(weeklyPoints, currentGoal);

      return {
        id: user.id,
        username: user.username,
        kickUsername: user.kickUsername || user.kickName || '',
        points: weeklyPoints,
        minutes: Number(user.weeklyMinutes || 0),
        percent,
        approved: weeklyPoints >= currentMinimum
      };
    })
    .sort((a, b) => Number(b.points || 0) - Number(a.points || 0));

  res.json({
    ok: true,
    currentWeek: weeklyControl.info,
    users,
    history: Array.isArray(data.weeklyHistory) ? data.weeklyHistory : []
  });
});

app.get('/api/fenix/admin/extra-target', requireFenixAdmin, (req, res) => {
  const data = readFenixData();

  res.json({
    ok: true,
    extraTarget: fenixGetExtraTargetFinal(data),
    extraTargets: fenixGetExtraTargetsFinal(data)
  });
});

app.post('/api/fenix/admin/extra-target', requireFenixAdmin, (req, res) => {
  const data = readFenixData();
  const updatedBy = String(
    req.body?.adminUsername ||
    req.headers['x-fenix-admin'] ||
    FENIX_ADMIN_USER
  );

  const target = fenixSetExtraTargetFinal(data, 4, req.body, updatedBy);
  writeFenixData(data);

  res.json({
    ok: true,
    message: target.enabled ? 'Aba extra 4 ativada.' : 'Aba extra 4 desativada.',
    extraTarget: target,
    extraTargets: fenixGetExtraTargetsFinal(data)
  });
});

app.get('/api/fenix/admin/extra-targets', requireFenixAdmin, (req, res) => {
  const data = readFenixData();

  res.json({
    ok: true,
    extraTargets: fenixGetExtraTargetsFinal(data)
  });
});

app.post('/api/fenix/admin/extra-targets/:number', requireFenixAdmin, (req, res) => {
  const number = Number(req.params.number);

  if (!FENIX_EXTRA_TAB_NUMBERS_FINAL.includes(number)) {
    return res.status(400).json({
      ok: false,
      message: 'Aba extra deve ser 4, 5 ou 6.'
    });
  }

  const data = readFenixData();
  const updatedBy = String(
    req.body?.adminUsername ||
    req.headers['x-fenix-admin'] ||
    FENIX_ADMIN_USER
  );

  const target = fenixSetExtraTargetFinal(data, number, req.body, updatedBy);
  writeFenixData(data);

  return res.json({
    ok: true,
    message: target.enabled
      ? 'Aba extra ' + number + ' ativada.'
      : 'Aba extra ' + number + ' desativada.',
    extraTarget: target,
    extraTargets: fenixGetExtraTargetsFinal(data)
  });
});

app.get('/api/fenix/app/extra-target', (req, res) => {
  const data = readFenixData();

  res.json({
    ok: true,
    extraTarget: fenixGetExtraTargetFinal(data)
  });
});

app.get('/api/fenix/app/extra-targets', (req, res) => {
  const data = readFenixData();

  res.json({
    ok: true,
    extraTargets: fenixGetExtraTargetsFinal(data)
  });
});

// FENIX_ADMIN_DIAGNOSTICS_129
function fenixCountCollection129(value) {
  if (Array.isArray(value)) return value.length;
  if (value && typeof value === 'object') return Object.keys(value).length;
  return 0;
}

function fenixBytesToMb129(bytes) {
  return Math.round((Number(bytes || 0) / 1024 / 1024) * 100) / 100;
}

// FENIX_ADMIN_DIAGNOSTICS_SIZES_130
function fenixJsonSizeMb130(value) {
  try {
    return fenixBytesToMb129(Buffer.byteLength(JSON.stringify(value || null), 'utf8'));
  } catch (error) {
    return 0;
  }
}

function fenixTopUsersBySize130(users) {
  const list = Array.isArray(users) ? users : [];

  return list
    .map((user) => ({
      username: user.username || user.name || '-',
      kickUsername: user.kickUsername || user.kickName || '-',
      sizeMb: fenixJsonSizeMb130(user),
      sessions: Array.isArray(user.sessions) ? user.sessions.length : 0,
      cycles: Array.isArray(user.cycles) ? user.cycles.length : 0,
      history: Array.isArray(user.history) ? user.history.length : 0,
      heartbeats: Array.isArray(user.heartbeats) ? user.heartbeats.length : 0
    }))
    .sort((a, b) => b.sizeMb - a.sizeMb)
    .slice(0, 15);
}

// FENIX_ADMIN_TOP_LEVEL_KEYS_131
function fenixTopLevelSizes131(data) {
  if (!data || typeof data !== 'object') return [];

  return Object.keys(data)
    .map((key) => {
      const value = data[key];

      return {
        key,
        type: Array.isArray(value) ? 'array' : typeof value,
        count: fenixCountCollection129(value),
        sizeMb: fenixJsonSizeMb130(value)
      };
    })
    .sort((a, b) => b.sizeMb - a.sizeMb);
}

function fenixBackupsInfo129() {
  try {
    fs.mkdirSync(FENIX_BACKUP_DIR, { recursive: true });

    const files = fs.readdirSync(FENIX_BACKUP_DIR)
      .filter((name) => name.startsWith('fenix-data-') && name.endsWith('.json'))
      .sort();

    let totalBytes = 0;

    const items = files.map((name) => {
      const file = path.join(FENIX_BACKUP_DIR, name);
      const stat = fs.statSync(file);
      totalBytes += stat.size;

      return {
        name,
        sizeMb: fenixBytesToMb129(stat.size),
        modifiedAt: stat.mtime.toISOString()
      };
    });

    return {
      count: items.length,
      maxConfigured: FENIX_MAX_BACKUPS,
      totalSizeMb: fenixBytesToMb129(totalBytes),
      oldest: items[0] || null,
      newest: items[items.length - 1] || null
    };
  } catch (error) {
    return {
      count: 0,
      maxConfigured: FENIX_MAX_BACKUPS,
      totalSizeMb: 0,
      error: error.message || String(error)
    };
  }
}

app.get('/api/fenix/admin/diagnostics', requireFenixAdmin, (req, res) => {
  try {
    let data = {};
    let dataSizeBytes = 0;

    if (fs.existsSync(FENIX_DATA_FILE)) {
      const raw = fs.readFileSync(FENIX_DATA_FILE, 'utf8');
      dataSizeBytes = Buffer.byteLength(raw, 'utf8');
      data = JSON.parse(raw);
    }

    const memory = process.memoryUsage();

    return res.json({
      ok: true,
      now: new Date().toISOString(),
      uptimeSeconds: Math.round(process.uptime()),
      dataFile: {
        path: FENIX_DATA_FILE,
        sizeMb: fenixBytesToMb129(dataSizeBytes)
      },
      backups: fenixBackupsInfo129(),
      counts: {
        users: fenixCountCollection129(data.users),
        sessions: fenixCountCollection129(data.sessions),
        schedule: fenixCountCollection129(data.schedule),
        weeklyHistory: fenixCountCollection129(data.weeklyHistory),
        drawApplicants: fenixCountCollection129(data.drawApplicants),
        draws: fenixCountCollection129(data.draws),
        extraTargets: fenixCountCollection129(data.extraTargets)
      },
      sizesMb: {
        users: fenixJsonSizeMb130(data.users),
        sessions: fenixJsonSizeMb130(data.sessions),
        schedule: fenixJsonSizeMb130(data.schedule),
        weeklyHistory: fenixJsonSizeMb130(data.weeklyHistory),
        drawApplicants: fenixJsonSizeMb130(data.drawApplicants),
        draws: fenixJsonSizeMb130(data.draws),
        extraTargets: fenixJsonSizeMb130(data.extraTargets)
      },
      largestUsers: fenixTopUsersBySize130(data.users),
      topLevelSizes: fenixTopLevelSizes131(data),
      memory: {
        rssMb: fenixBytesToMb129(memory.rss),
        heapUsedMb: fenixBytesToMb129(memory.heapUsed),
        heapTotalMb: fenixBytesToMb129(memory.heapTotal),
        externalMb: fenixBytesToMb129(memory.external)
      }
    });
  } catch (error) {
    return res.status(500).json({
      ok: false,
      message: error.message || String(error)
    });
  }
});

app.post('/api/fenix/admin/maintenance/cleanup-backups', requireFenixAdmin, (req, res) => {
  try {
    fs.mkdirSync(FENIX_BACKUP_DIR, { recursive: true });

    const keep = Math.max(5, Math.min(200, Number(req.body?.keep || req.query?.keep || 30)));

    const files = fs.readdirSync(FENIX_BACKUP_DIR)
      .filter((name) => name.startsWith('fenix-data-') && name.endsWith('.json'))
      .sort();

    const before = files.length;
    const removed = [];

    while (files.length > keep) {
      const oldFile = files.shift();
      fs.unlinkSync(path.join(FENIX_BACKUP_DIR, oldFile));
      removed.push(oldFile);
    }

    return res.json({
      ok: true,
      message: 'Limpeza de backups concluida.',
      before,
      after: files.length,
      keep,
      removedCount: removed.length,
      removedPreview: removed.slice(0, 20),
      backups: fenixBackupsInfo129()
    });
  } catch (error) {
    return res.status(500).json({
      ok: false,
      message: error.message || String(error)
    });
  }
});

// FENIX_ADMIN_CYCLES_CLEANUP_132
function fenixCycleDate132(cycle) {
  if (!cycle || typeof cycle !== 'object') return null;

  const candidates = [
    cycle.createdAt,
    cycle.completedAt,
    cycle.updatedAt,
    cycle.at,
    cycle.date,
    cycle.timestamp,
    cycle.finishedAt
  ];

  for (const value of candidates) {
    if (!value) continue;

    const date = new Date(value);
    if (!Number.isNaN(date.getTime())) return date;
  }

  return null;
}

app.post('/api/fenix/admin/maintenance/cleanup-cycles', requireFenixAdmin, (req, res) => {
  try {
    const keepDays = Math.max(1, Math.min(60, Number(req.body?.keepDays || req.query?.keepDays || 7)));
    const dryRun = String(req.body?.dryRun ?? req.query?.dryRun ?? 'true').toLowerCase() !== 'false';

    if (!fs.existsSync(FENIX_DATA_FILE)) {
      return res.status(404).json({
        ok: false,
        message: 'Arquivo de dados Fenix nao encontrado.'
      });
    }

    const raw = fs.readFileSync(FENIX_DATA_FILE, 'utf8');
    const data = JSON.parse(raw);
    const cycles = Array.isArray(data.cycles) ? data.cycles : [];

    const now = Date.now();
    const cutoff = now - keepDays * 24 * 60 * 60 * 1000;

    let withoutDate = 0;
    let kept = 0;
    let removed = 0;

    const nextCycles = cycles.filter((cycle) => {
      const date = fenixCycleDate132(cycle);

      if (!date) {
        withoutDate += 1;
        kept += 1;
        return true;
      }

      if (date.getTime() >= cutoff) {
        kept += 1;
        return true;
      }

      removed += 1;
      return false;
    });

    const beforeSizeMb = fenixJsonSizeMb130(cycles);
    const afterSizeMb = fenixJsonSizeMb130(nextCycles);

    if (!dryRun) {
      createFenixDataBackup('before-cleanup-cycles', true);

      data.cycles = nextCycles;

      const tempFile = `${FENIX_DATA_FILE}.tmp-${process.pid}-${Date.now()}`;
      fs.writeFileSync(tempFile, JSON.stringify(data, null, 2), 'utf8');
      JSON.parse(fs.readFileSync(tempFile, 'utf8'));
      fs.renameSync(tempFile, FENIX_DATA_FILE);

      FENIX_DATA_MEMORY_CACHE = normalizeFenixDataShape(data);
    }

    return res.json({
      ok: true,
      dryRun,
      keepDays,
      cutoff: new Date(cutoff).toISOString(),
      before: cycles.length,
      after: nextCycles.length,
      removed,
      kept,
      withoutDate,
      beforeSizeMb,
      afterSizeMb,
      savedSizeMb: Math.round((beforeSizeMb - afterSizeMb) * 100) / 100,
      message: dryRun
        ? 'Previa concluida. Nenhum cycle foi apagado.'
        : 'Limpeza de cycles concluida.'
    });
  } catch (error) {
    return res.status(500).json({
      ok: false,
      message: error.message || String(error)
    });
  }
});
app.listen(PORT, () => {
  console.log(`${APP_NAME} online na porta ${PORT}`);
  console.log(`URL local: http://localhost:${PORT}`);
});
























