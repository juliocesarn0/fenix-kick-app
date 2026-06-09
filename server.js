import 'dotenv/config';
import crypto from 'crypto';
import fs from 'fs';
import express from 'express';
import session from 'express-session';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = process.env.PORT || 3000;
const APP_NAME = process.env.APP_NAME || 'Fenix';
const APP_URL = (process.env.APP_URL || `http://localhost:${PORT}`).replace(/\/$/, '');
const KICK_CLIENT_ID = process.env.KICK_CLIENT_ID || '';
const KICK_CLIENT_SECRET = process.env.KICK_CLIENT_SECRET || '';
const KICK_REDIRECT_URI = process.env.KICK_REDIRECT_URI || `${APP_URL}/auth/kick/callback`;
const KICK_SCOPES = process.env.KICK_SCOPES || 'user:read channel:read';

const KICK_ID_URL = 'https://id.kick.com';
const KICK_API_URL = 'https://api.kick.com/public/v1';

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.set('trust proxy', 1);
app.use(
  session({
    name: 'fenix.sid',
    secret: process.env.SESSION_SECRET || 'fenix-dev-secret-change-me',
    resave: false,
    saveUninitialized: true,
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

app.get('/health', (req, res) => {
  res.json({ ok: true, app: APP_NAME, time: new Date().toISOString() });
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
const FENIX_DATA_DIR = path.join(__dirname, 'backend', 'data');
const FENIX_DATA_FILE = path.join(FENIX_DATA_DIR, 'fenix-data.json');

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
    kickLocks: []
  };
}

function readFenixData() {
  try {
    if (!fs.existsSync(FENIX_DATA_FILE)) {
      const initial = createDefaultFenixData();
      fs.writeFileSync(FENIX_DATA_FILE, JSON.stringify(initial, null, 2), 'utf8');
      return initial;
    }

    const parsed = JSON.parse(fs.readFileSync(FENIX_DATA_FILE, 'utf8'));
    return {
      users: Array.isArray(parsed.users) ? parsed.users : [],
      sessions: Array.isArray(parsed.sessions) ? parsed.sessions : [],
      schedule: Array.isArray(parsed.schedule) ? parsed.schedule : [],
      notices: Array.isArray(parsed.notices) ? parsed.notices : [],
      cycles: Array.isArray(parsed.cycles) ? parsed.cycles : [],
      deviceLocks: Array.isArray(parsed.deviceLocks) ? parsed.deviceLocks : [],
      kickLocks: Array.isArray(parsed.kickLocks) ? parsed.kickLocks : []
    };
  } catch (error) {
    console.error('Erro lendo fenix-data.json:', error);
    return createDefaultFenixData();
  }
}

function writeFenixData(data) {
  fs.writeFileSync(FENIX_DATA_FILE, JSON.stringify(data, null, 2), 'utf8');
}

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

function publicFenixUser(user) {
  return {
    username: user.username,
    role: user.role,
    isAdmin: user.role === 'ADMIN',
    points: Number(user.points || 0),
    weeklyPoints: Number(user.weeklyPoints || 0),
    totalMinutes: Number(user.totalMinutes || 0),
    weeklyMinutes: Number(user.weeklyMinutes || 0),
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

app.post('/api/fenix/app/heartbeat', (req, res) => {
  const sessionId = String(req.body?.sessionId || '').trim();
  const kickLoggedIn = Boolean(req.body?.kickLoggedIn);
  const tabsKickLoggedIn = Boolean(req.body?.tabsKickLoggedIn);

  const data = readFenixData();
  const now = new Date().toISOString();

  const session = data.sessions.find((item) => item.sessionId === sessionId && item.active !== false);

  if (!session) {
    return res.status(401).json({ ok: false, message: 'Sessao Fenix invalida.' });
  }

  const user = data.users.find((item) => item.id === session.userId);

  if (!user) {
    return res.status(404).json({ ok: false, message: 'Usuario Fenix nao encontrado.' });
  }

  session.lastSeenAt = now;
  session.kickLoggedIn = kickLoggedIn;

  user.isOnline = true;
  user.lastSeenAt = now;
  user.kickLoggedIn = kickLoggedIn;
  user.updatedAt = now;

  writeFenixData(data);

  res.json({
    ok: true,
    user: {
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
  const data = readFenixData();
  const session = data.sessions.find((item) => {
    return item.id === sessionId || item.sessionId === sessionId;
  });

  if (!session) {
    return res.status(401).json({ ok: false, message: 'Sessao invalida.' });
  }

  const user = data.users.find((item) => item.id === session.userId);

  if (!user) {
    return res.status(404).json({ ok: false, message: 'Usuario nao encontrado.' });
  }

  user.isOnline = true;
  user.lastSeenAt = new Date().toISOString();

  writeFenixData(data);

  res.json({
    ok: true,
    user: publicFenixUser(user)
  });
});




// FENIX_RESET_ACCESS_FINAL
app.post('/api/fenix/auth/reset-access', (req, res) => {
  const sessionId = String(req.body?.sessionId || '').trim();
  const username = String(req.body?.username || req.body?.userName || '').trim();

  if (!sessionId && !username) {
    return res.status(400).json({
      ok: false,
      message: 'Sessao ou usuario Fenix nao informado.'
    });
  }

  const data = readFenixData();

  data.sessions = Array.isArray(data.sessions) ? data.sessions : [];
  data.users = Array.isArray(data.users) ? data.users : [];

  const session = sessionId
    ? data.sessions.find((item) => item.id === sessionId || item.sessionId === sessionId)
    : null;

  const user = data.users.find((item) => {
    return (
      (session && (item.id === session.userId || item.username === session.username)) ||
      (username && String(item.username || '').toLowerCase() === username.toLowerCase())
    );
  });

  if (user) {
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
  }

  if (sessionId) {
    data.sessions = data.sessions.filter((item) => {
      return item.id !== sessionId && item.sessionId !== sessionId;
    });
  }

  writeFenixData(data);

  return res.json({
    ok: true,
    message: 'Acesso Fenix e Kick resetado. Vincule a Kick novamente.',
    resetUser: user ? user.username : username || ''
  });
});

app.get('/api/fenix/app/current-schedule', (req, res) => {
  const data = readFenixData();

  const slot = getCurrentFenixSlot(data);
  const notice = [...data.notices].reverse().find((item) => item.active !== false) || null;

  res.json({
    ok: true,
    slot,
    slots: fenixSlotToDesktopSlots(slot),
    notice
  });
});

app.get('/api/fenix-desktop-slots', (req, res) => {
  const data = readFenixData();

  const slot = getCurrentFenixSlot(data);

  res.json({
    ok: true,
    slots: fenixSlotToDesktopSlots(slot)
  });
});

app.post('/api/fenix/app/complete-cycle', (req, res) => {
  const sessionId = String(req.body?.sessionId || '').trim();
  const cycleKey = String(req.body?.cycleKey || '').trim();
  const kickLoggedIn = Boolean(req.body?.kickLoggedIn);
  const tabsKickLoggedIn = Boolean(req.body?.tabsKickLoggedIn);

  if (!sessionId || !cycleKey) {
    return res.status(400).json({ ok: false, message: 'sessionId e cycleKey sao obrigatorios.' });
  }

  const data = readFenixData();
  const session = data.sessions.find((item) => item.sessionId === sessionId && item.active !== false);

  if (!session) {
    return res.status(401).json({ ok: false, message: 'Sessao Fenix invalida.' });
  }

  const user = data.users.find((item) => item.id === session.userId);

  if (!user) {
    return res.status(404).json({ ok: false, message: 'Usuario Fenix nao encontrado.' });
  }

  if (!kickLoggedIn && !session.kickLoggedIn && !user.kickLoggedIn) {
    return res.status(403).json({
      ok: false,
      paid: false,
      message: 'Kick nao logada nas telas. Pontos nao contabilizados.'
    });
  }

  const alreadyPaid = data.cycles.find((item) => item.userId === user.id && item.cycleKey === cycleKey);

  if (alreadyPaid) {
    return res.json({
      ok: true,
      paid: false,
      duplicated: true,
      points: 0,
      user
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
  const points = activeScreens;

  const now = new Date().toISOString();

  const cycle = {
    id: crypto.randomUUID(),
    userId: user.id,
    username: user.username,
    sessionId,
    cycleKey,
    points,
    minutes: 10,
    activeScreens,
    slotDate: slot.slotDate,
    slotHour: slot.slotHour,
    createdAt: now
  };

  data.cycles.push(cycle);

  user.points += points;
  user.weeklyPoints += points;
  user.totalMinutes += 10;
  user.weeklyMinutes += 10;
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
    user: {
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

app.get('/api/fenix/admin/online-users', requireFenixAdmin, (req, res) => {
  const data = readFenixData();
  const limitDate = Date.now() - 1000 * 60 * 2;

  const users = data.users.map((user) => {
    const lastSeen = user.lastSeenAt ? new Date(user.lastSeenAt).getTime() : 0;

    return {
      username: user.username,
      role: user.role,
      isOnline: user.isOnline && lastSeen >= limitDate,
      kickLoggedIn: user.kickLoggedIn,
      kickConnected: Boolean(user.kickConnected),
      kickUsername: user.kickUsername || '',
      points: user.points,
      weeklyPoints: user.weeklyPoints,
      totalMinutes: user.totalMinutes,
      weeklyMinutes: user.weeklyMinutes,
      lastSeenAt: user.lastSeenAt
    };
  });

  res.json({ ok: true, users });
});


// FENIX_ADMIN_RESET_USER_POINTS_API
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

app.get('/api/fenix/admin/schedule', requireFenixAdmin, (req, res) => {
  const data = readFenixData();
  res.json({ ok: true, schedule: data.schedule });
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



app.post('/api/fenix/admin/schedule/bulk', requireFenixAdmin, (req, res) => {
  const data = readFenixData();

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
app.get('/admin', (req, res) => {
  res.setHeader('Content-Type', 'text/html; charset=utf-8');
  res.end("<!doctype html>\n<html lang=\"pt-BR\">\n<head>\n  <meta charset=\"utf-8\" />\n  <meta name=\"viewport\" content=\"width=device-width,initial-scale=1\" />\n  <title>Fenix Lurk Admin</title>\n  <style>\n    *{box-sizing:border-box}\n    body{margin:0;font-family:Arial,Helvetica,sans-serif;background:#05070d;color:#fff}\n    header{padding:18px 24px;border-bottom:1px solid rgba(0,255,106,.25);background:#07110c;display:flex;justify-content:space-between;align-items:center;gap:14px}\n    h1{margin:0;color:#00ff6a;font-size:22px}\n    h2{margin:0 0 14px;color:#f5b22a}\n    main{padding:20px;display:grid;gap:16px}\n    .card{border:1px solid rgba(0,255,106,.25);background:rgba(10,15,25,.96);border-radius:16px;padding:16px}\n    .login{display:grid;grid-template-columns:1fr 1fr auto auto;gap:10px;align-items:end}\n    label{display:grid;gap:6px;color:#b8c6d8;font-size:12px;font-weight:900;text-transform:uppercase}\n    input,textarea{width:100%;border:1px solid rgba(255,255,255,.16);border-radius:10px;background:#080b12;color:#fff;padding:11px 12px;font-weight:800}\n    button{border:1px solid rgba(0,255,106,.65);border-radius:10px;background:rgba(0,255,106,.14);color:#fff;padding:11px 14px;cursor:pointer;font-weight:900}\n    button:hover{background:rgba(0,255,106,.25)}\n    .danger{border-color:rgba(255,70,70,.65);background:rgba(255,70,70,.12)}\n    .gold{border-color:rgba(245,178,42,.7);background:rgba(245,178,42,.13)}\n    .grid2{display:grid;grid-template-columns:1fr 1fr;gap:16px}\n    table{width:100%;border-collapse:collapse;font-size:13px}\n    th,td{padding:10px 8px;border-bottom:1px solid rgba(255,255,255,.08);text-align:left}\n    th{color:#00ff6a;background:rgba(0,255,106,.06)}\n    .pill{padding:4px 8px;border-radius:999px;font-size:11px;font-weight:900;display:inline-block}\n    .ok{color:#00ff6a;border:1px solid rgba(0,255,106,.5);background:rgba(0,255,106,.12)}\n    .bad{color:#ff5252;border:1px solid rgba(255,82,82,.5);background:rgba(255,82,82,.12)}\n    .muted{color:#9ba8ba}\n    .row24{display:grid;grid-template-columns:80px 1fr 1fr 1fr auto;gap:8px;margin-bottom:8px;align-items:center}\n    .row24 b{color:#f5b22a}\n    .msg{color:#f5b22a;font-weight:900;margin-top:10px;min-height:20px}\n    @media(max-width:900px){.login,.grid2,.row24{grid-template-columns:1fr}header{display:block}}\n  </style>\n</head>\n<body>\n  <header>\n    <div>\n      <h1>Fenix Lurk Admin</h1>\n      <div style=\"color:#f5b22a;font-weight:800;font-size:13px\">Painel externo · atualiza sem trocar o app dos usuarios</div>\n    </div>\n    <div id=\"topStatus\" style=\"color:#f5b22a;font-weight:900\">Desconectado</div>\n  </header>\n\n  <main>\n    <section class=\"card\">\n      <div class=\"login\">\n        <label>Usuario Admin<input id=\"adminUser\" value=\"GokuuMods\" /></label>\n        <label>Senha Admin<input id=\"adminSecret\" type=\"password\" placeholder=\"senha da Railway\" /></label>\n        <button onclick=\"saveLogin()\">Entrar / Salvar</button>\n        <button class=\"danger\" onclick=\"logout()\">Sair</button>\n      </div>\n      <div class=\"msg\" id=\"loginMsg\">Digite a senha admin para liberar o painel.</div>\n    </section>\n\n    <section class=\"grid2\">\n      <div class=\"card\">\n        <h2>Farm ativo agora</h2>\n        <button onclick=\"loadUsers()\">Atualizar usuarios</button>\n        <div id=\"activeUsers\"></div>\n      </div>\n      <div class=\"card\">\n        <h2>Ranking de pontos da semana</h2>\n        <button onclick=\"loadUsers()\">Atualizar ranking</button>\n        <div id=\"rankingUsers\"></div>\n      </div>\n    </section>\n\n    <section class=\"card\">\n      <h2>Grade de lives por horario</h2>\n      <div class=\"muted\">Vazio = app abre kick.com. Com canal = app abre a live agendada.</div>\n      <br />\n      <label>Data<input id=\"slotDate\" type=\"date\" /></label>\n      <br />\n      <button onclick=\"loadSchedule()\">Carregar grade</button>\n      <button class=\"gold\" onclick=\"saveAllVisible()\">Salvar grade inteira</button>\n      <div class=\"msg\" id=\"scheduleMsg\"></div>\n      <div id=\"scheduleRows\"></div>\n    </section>\n\n    <section class=\"card\">\n      <h2>Aviso para o app</h2>\n      <textarea id=\"noticeText\" rows=\"3\" placeholder=\"Digite o aviso que aparece para os usuarios...\"></textarea>\n      <br /><br />\n      <button onclick=\"saveNotice()\">Salvar aviso</button>\n      <div class=\"msg\" id=\"noticeMsg\"></div>\n    </section>\n  </main>\n\n<script>\nconst API = location.origin;\nconst hours = Array.from({length:24}, (_,i)=>String(i).padStart(2,\"0\")+\":00\");\nfunction $(id){return document.getElementById(id)}\nfunction today(){return new Date().toISOString().slice(0,10)}\nfunction escapeHtml(v){return String(v).replace(/[&<>\"']/g, m => ({'&':'&amp;','<':'&lt;','>':'&gt;','\"':'&quot;',\"'\":'&#039;'}[m]))}\nfunction adminHeaders(){\n  return {\n    \"Content-Type\":\"application/json\",\n    \"x-fenix-admin\": $(\"adminUser\").value.trim() || \"GokuuMods\",\n    \"x-fenix-admin-secret\": $(\"adminSecret\").value.trim()\n  };\n}\nfunction buildKickUrl(name){\n  const clean = String(name || \"\").trim().replace(/^https?:\\/\\/kick\\.com\\//i,\"\").replace(/^kick\\.com\\//i,\"\").replace(/^@/,\"\");\n  return clean ? \"https://kick.com/\" + clean : \"\";\n}\nfunction saveLogin(){\n  localStorage.setItem(\"fenixAdminUser\", $(\"adminUser\").value.trim() || \"GokuuMods\");\n  localStorage.setItem(\"fenixAdminSecret\", $(\"adminSecret\").value.trim());\n  $(\"topStatus\").textContent = \"Admin conectado\";\n  $(\"loginMsg\").textContent = \"Login salvo neste navegador.\";\n  loadUsers();\n  loadSchedule();\n}\nfunction logout(){\n  localStorage.removeItem(\"fenixAdminSecret\");\n  $(\"adminSecret\").value = \"\";\n  $(\"topStatus\").textContent = \"Desconectado\";\n  $(\"loginMsg\").textContent = \"Senha removida.\";\n}\nasync function apiGet(url){\n  const res = await fetch(API + url, { headers: adminHeaders(), cache:\"no-store\" });\n  const data = await res.json();\n  if(!res.ok || data.ok === false) throw new Error(data.message || \"Erro API\");\n  return data;\n}\nasync function apiPost(url, body){\n  const res = await fetch(API + url, {method:\"POST\",headers:adminHeaders(),body:JSON.stringify(body)});\n  const data = await res.json();\n  if(!res.ok || data.ok === false) throw new Error(data.message || \"Erro API\");\n  return data;\n}\nfunction userTable(users, mode){\n  if(!users.length) return '<p class=\"muted\">Nenhum usuario encontrado.</p>';\n  return '<table><thead><tr><th>#</th><th>Usuario</th><th>Kick</th><th>Semana</th><th>Total</th><th>Status</th></tr></thead><tbody>' +\n    users.map((u,i)=>{\n      const weekly = Number(u.weeklyPoints || 0);\n      const total = Number(u.points || 0);\n      const approved = weekly >= 210;\n      const online = Boolean(u.online || u.farmActive);\n      const status = mode === \"active\"\n        ? (online ? '<span class=\"pill ok\">Farm ativo</span>' : '<span class=\"pill bad\">Offline</span>')\n        : (approved ? '<span class=\"pill ok\">Aprovado 70%</span>' : '<span class=\"pill bad\">Pendente</span>');\n      return '<tr><td>'+(i+1)+'</td><td><b>'+escapeHtml(u.username || \"-\")+'</b></td><td>'+escapeHtml(u.kickUsername || u.kickName || \"-\")+'</td><td>'+weekly+' pts</td><td>'+total+' pts</td><td>'+status+'</td></tr>';\n    }).join(\"\") + '</tbody></table>';\n}\nasync function loadUsers(){\n  try{\n    const data = await apiGet(\"/api/fenix/admin/online-users\");\n    const users = Array.isArray(data.users) ? data.users : [];\n    const active = users.filter(u => u.online || u.farmActive);\n    const ranking = users.slice().sort((a,b)=>Number(b.weeklyPoints||0)-Number(a.weeklyPoints||0) || Number(b.points||0)-Number(a.points||0));\n    $(\"activeUsers\").innerHTML = userTable(active, \"active\");\n    $(\"rankingUsers\").innerHTML = userTable(ranking, \"ranking\");\n    $(\"loginMsg\").textContent = \"Usuarios carregados.\";\n  }catch(e){ $(\"loginMsg\").textContent = e.message; }\n}\nfunction renderSchedule(schedule){\n  const date = $(\"slotDate\").value || today();\n  $(\"scheduleRows\").innerHTML = hours.map(hour => {\n    const slot = schedule.find(s => s.slotDate === date && s.slotHour === hour) || {};\n    return '<div class=\"row24\" data-hour=\"'+hour+'\"><b>'+hour+'</b>' +\n      '<input data-screen=\"1\" placeholder=\"Tela 1 canal\" value=\"'+escapeHtml(slot.screen1Name || \"\")+'\" />' +\n      '<input data-screen=\"2\" placeholder=\"Tela 2 canal\" value=\"'+escapeHtml(slot.screen2Name || \"\")+'\" />' +\n      '<input data-screen=\"3\" placeholder=\"Tela 3 canal\" value=\"'+escapeHtml(slot.screen3Name || \"\")+'\" />' +\n      '<button onclick=\"saveHour(\\''+hour+'\\')\">Salvar</button></div>';\n  }).join(\"\");\n}\nasync function loadSchedule(){\n  try{\n    const data = await apiGet(\"/api/fenix/admin/schedule\");\n    renderSchedule(Array.isArray(data.schedule) ? data.schedule : []);\n    $(\"scheduleMsg\").textContent = \"Grade carregada.\";\n  }catch(e){ $(\"scheduleMsg\").textContent = e.message; }\n}\nasync function saveHour(hour){\n  const row = document.querySelector('.row24[data-hour=\"'+hour+'\"]');\n  const date = $(\"slotDate\").value || today();\n  const s1 = row.querySelector('[data-screen=\"1\"]').value.trim();\n  const s2 = row.querySelector('[data-screen=\"2\"]').value.trim();\n  const s3 = row.querySelector('[data-screen=\"3\"]').value.trim();\n  try{\n    await apiPost(\"/api/fenix/admin/schedule\", {\n      adminUsername:$(\"adminUser\").value.trim() || \"GokuuMods\",\n      adminSecret:$(\"adminSecret\").value.trim(),\n      slotDate:date,\n      slotHour:hour,\n      screen1Name:s1, screen1Url:buildKickUrl(s1), screen1Maintenance:!s1,\n      screen2Name:s2, screen2Url:buildKickUrl(s2), screen2Maintenance:!s2,\n      screen3Name:s3, screen3Url:buildKickUrl(s3), screen3Maintenance:!s3\n    });\n    $(\"scheduleMsg\").textContent = \"Horario \" + hour + \" salvo.\";\n  }catch(e){ $(\"scheduleMsg\").textContent = e.message; }\n}\nasync function saveAllVisible(){\n  for(const hour of hours){ await saveHour(hour); }\n  $(\"scheduleMsg\").textContent = \"Grade inteira salva.\";\n}\nasync function saveNotice(){\n  try{\n    await apiPost(\"/api/fenix/admin/notice\", {\n      adminUsername:$(\"adminUser\").value.trim() || \"GokuuMods\",\n      adminSecret:$(\"adminSecret\").value.trim(),\n      message:$(\"noticeText\").value.trim()\n    });\n    $(\"noticeMsg\").textContent = \"Aviso salvo.\";\n  }catch(e){ $(\"noticeMsg\").textContent = e.message; }\n}\n$(\"slotDate\").value = today();\n$(\"adminUser\").value = localStorage.getItem(\"fenixAdminUser\") || \"GokuuMods\";\n$(\"adminSecret\").value = localStorage.getItem(\"fenixAdminSecret\") || \"\";\nif($(\"adminSecret\").value){\n  $(\"topStatus\").textContent = \"Admin conectado\";\n  loadUsers();\n  loadSchedule();\n}\n</script>\n</body>\n</html>");
});

app.listen(PORT, () => {
  console.log(`${APP_NAME} online na porta ${PORT}`);
  console.log(`URL local: http://localhost:${PORT}`);
});












