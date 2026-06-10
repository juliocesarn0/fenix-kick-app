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

// FENIX_URLENCODED_LIMIT_FINAL
app.use(express.urlencoded({ limit: '50mb', extended: true }));
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
const FENIX_DATA_DIR = process.env.FENIX_DATA_DIR || (fs.existsSync('/data') ? '/data' : path.join(__dirname, 'backend', 'data'));
const FENIX_DATA_FILE = path.join(FENIX_DATA_DIR, 'fenix-data.json');
console.log('Fenix data file:', FENIX_DATA_FILE);

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


// FENIX_ADMIN_ONLINE_USERS_LAST_CYCLE_FINAL


// FENIX_APP_FAST_HEARTBEAT_FINAL
app.post('/api/fenix/app/heartbeat', (req, res) => {
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
  const farmOk = Boolean(kickConnected && tabsLoggedIn);

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

  if (existingIndex >= 0) {
    data.farmHeartbeats[existingIndex] = {
      ...data.farmHeartbeats[existingIndex],
      ...heartbeat
    };
  } else {
    data.farmHeartbeats.push(heartbeat);
  }

  writeFenixData(data);

  return res.json({
    ok: true,
    heartbeat
  });
});

// FENIX_ADMIN_ONLINE_USERS_FAST_HEARTBEAT_FINAL
app.get('/api/fenix/admin/online-users', requireFenixAdmin, (req, res) => {
  const data = readFenixData();

  data.users = Array.isArray(data.users) ? data.users : [];
  data.cycles = Array.isArray(data.cycles) ? data.cycles : [];
  data.farmHeartbeats = Array.isArray(data.farmHeartbeats) ? data.farmHeartbeats : [];

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

    return data.farmHeartbeats.find((item) => {
      return item.userId === user.id ||
        String(item.username || '').toLowerCase() === username;
    }) || null;
  }

  function findLastCycleForUser(user) {
    const username = String(user.username || '').toLowerCase();

    const cycles = data.cycles.filter((cycle) => {
      const cycleUser =
        cycle.username ||
        cycle.userName ||
        cycle.farmerUserName ||
        cycle.fenixUsername ||
        cycle.name ||
        '';

      return cycle.userId === user.id ||
        String(cycleUser || '').toLowerCase() === username;
    });

    if (!cycles.length) return null;

    return cycles.slice().sort((a, b) => {
      const at = getTimeMs(a.completedAt || a.createdAt || a.updatedAt || a.finishedAt);
      const bt = getTimeMs(b.completedAt || b.createdAt || b.updatedAt || b.finishedAt);
      return bt - at;
    })[0];
  }

  const users = data.users.map((user) => {
    const heartbeat = findHeartbeat(user);
    const lastCycle = findLastCycleForUser(user);

    const userSession = data.sessions.find((session) => {
      return session.userId === user.id ||
        String(session.username || '').toLowerCase() === String(user.username || '').toLowerCase();
    }) || null;

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

    const farmOk = Boolean(kickConnected && ((appOnline && tabsLoggedIn) || cycleActive));

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
      kickUsername: user.kickUsername || user.kickName || heartbeat?.kickUsername || '',
      points: Number(user.points || 0),
      weeklyPoints: Number(user.weeklyPoints || 0),
      totalMinutes: Number(user.totalMinutes || 0),
      weeklyMinutes: Number(user.weeklyMinutes || 0),
      kickConnected,
      kickLoggedIn: kickConnected,
      tabsLoggedIn,
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
  res.end("<!doctype html>\n<html lang=\"pt-BR\">\n<head>\n  <meta charset=\"utf-8\" />\n  <meta name=\"viewport\" content=\"width=device-width,initial-scale=1\" />\n  <title>Fenix Lurk Admin</title>\n  <style>\n    *{box-sizing:border-box}\n    body{margin:0;font-family:Arial,Helvetica,sans-serif;background:#05070d;color:#fff}\n    header{padding:18px 24px;border-bottom:1px solid rgba(0,255,106,.25);background:#07110c;display:flex;justify-content:space-between;align-items:center;gap:14px}\n    h1{margin:0;color:#00ff6a;font-size:22px}\n    h2{margin:0 0 14px;color:#f5b22a}\n    main{padding:20px;display:grid;gap:16px}\n    .card{border:1px solid rgba(0,255,106,.25);background:rgba(10,15,25,.96);border-radius:16px;padding:16px}\n    .login{display:grid;grid-template-columns:1fr 1fr auto auto;gap:10px;align-items:end}\n    label{display:grid;gap:6px;color:#b8c6d8;font-size:12px;font-weight:900;text-transform:uppercase}\n    input,textarea{width:100%;border:1px solid rgba(255,255,255,.16);border-radius:10px;background:#080b12;color:#fff;padding:11px 12px;font-weight:800}\n    button{border:1px solid rgba(0,255,106,.65);border-radius:10px;background:rgba(0,255,106,.14);color:#fff;padding:11px 14px;cursor:pointer;font-weight:900}\n    button:hover{background:rgba(0,255,106,.25)}\n    .danger{border-color:rgba(255,70,70,.65);background:rgba(255,70,70,.12)}\n    .gold{border-color:rgba(245,178,42,.7);background:rgba(245,178,42,.13)}\n    .grid2{display:grid;grid-template-columns:1fr 1fr;gap:16px}\n    table{width:100%;border-collapse:collapse;font-size:13px}\n    th,td{padding:10px 8px;border-bottom:1px solid rgba(255,255,255,.08);text-align:left}\n    th{color:#00ff6a;background:rgba(0,255,106,.06)}\n    .pill{padding:4px 8px;border-radius:999px;font-size:11px;font-weight:900;display:inline-block}\n    .ok{color:#00ff6a;border:1px solid rgba(0,255,106,.5);background:rgba(0,255,106,.12)}\n    .bad{color:#ff5252;border:1px solid rgba(255,82,82,.5);background:rgba(255,82,82,.12)}\n    .warn{color:#f5b22a;border:1px solid rgba(245,178,42,.5);background:rgba(245,178,42,.12)}\n    .muted{color:#9ba8ba}\n    .row24{display:grid;grid-template-columns:80px 1fr 1fr 1fr auto;gap:8px;margin-bottom:8px;align-items:center}\n    .row24 b{color:#f5b22a}\n    .msg{color:#f5b22a;font-weight:900;margin-top:10px;min-height:20px}\n    @media(max-width:900px){.login,.grid2,.row24{grid-template-columns:1fr}header{display:block}}\n  </style>\n</head>\n<body>\n  <header>\n    <div>\n      <h1>Fenix Lurk Admin</h1>\n      <div style=\"color:#f5b22a;font-weight:800;font-size:13px\">Painel externo · atualiza sem trocar o app dos usuarios</div>\n    </div>\n    <div id=\"topStatus\" style=\"color:#f5b22a;font-weight:900\">Desconectado</div>\n  </header>\n\n  <main>\n    <section class=\"card\">\n      <div class=\"login\">\n        <label>Usuario Admin<input id=\"adminUser\" value=\"GokuuMods\" /></label>\n        <label>Senha Admin<input id=\"adminSecret\" type=\"password\" placeholder=\"senha da Railway\" /></label>\n        <button onclick=\"saveLogin()\">Entrar / Salvar</button>\n        <button class=\"danger\" onclick=\"logout()\">Sair</button>\n      </div>\n      <div class=\"msg\" id=\"loginMsg\">Digite a senha admin para liberar o painel.</div>\n    </section>\n\n    <section class=\"grid2\">\n      <div class=\"card\">\n        <h2>Farm ativo agora</h2>\n        <button onclick=\"loadUsers()\">Atualizar usuarios</button>\n        <div id=\"activeUsers\"></div>\n      </div>\n      <div class=\"card\">\n        <h2>Ranking de pontos da semana</h2>\n        <button onclick=\"loadUsers()\">Atualizar ranking</button>\n        <div id=\"rankingUsers\"></div>\n      </div>\n    </section>\n\n    <section class=\"card\">\n      <h2>Grade de lives por horario</h2>\n      <div class=\"muted\">Vazio = app abre kick.com. Com canal = app abre a live agendada.</div>\n      <br />\n      <label>Data<input id=\"slotDate\" type=\"date\" /></label>\n      <br />\n      <button onclick=\"loadSchedule()\">Carregar grade</button>\n      <button class=\"gold\" onclick=\"saveAllVisible()\">Salvar grade inteira</button>\n      <div class=\"msg\" id=\"scheduleMsg\"></div>\n      <div id=\"scheduleRows\"></div>\n    </section>\n\n    <section class=\"card\">\n      <h2>Aviso para o app</h2>\n      <textarea id=\"noticeText\" rows=\"3\" placeholder=\"Digite o aviso que aparece para os usuarios...\"></textarea>\n      <br /><br />\n      <button onclick=\"saveNotice()\">Salvar aviso</button>\n      <div class=\"msg\" id=\"noticeMsg\"></div>\n    </section>\n  </main>\n\n<script>\nconst API = location.origin;\nconst hours = Array.from({length:24}, (_,i)=>String(i).padStart(2,\"0\")+\":00\");\n\nfunction $(id){return document.getElementById(id)}\nfunction today(){return new Date().toISOString().slice(0,10)}\nfunction escapeHtml(v){\n  return String(v || \"\").replace(/[&<>\"']/g, function(m){\n    return {\"&\":\"&amp;\",\"<\":\"&lt;\",\">\":\"&gt;\",'\"':\"&quot;\",\"'\":\"&#039;\"}[m];\n  });\n}\nfunction adminHeaders(){\n  return {\n    \"Content-Type\":\"application/json\",\n    \"x-fenix-admin\": $(\"adminUser\").value.trim() || \"GokuuMods\",\n    \"x-fenix-admin-secret\": $(\"adminSecret\").value.trim()\n  };\n}\nfunction buildKickUrl(name){\n  const clean = String(name || \"\").trim().replace(/^https?:\\/\\/kick\\.com\\//i,\"\").replace(/^kick\\.com\\//i,\"\").replace(/^@/,\"\");\n  return clean ? \"https://kick.com/\" + clean : \"\";\n}\nfunction saveLogin(){\n  localStorage.setItem(\"fenixAdminUser\", $(\"adminUser\").value.trim() || \"GokuuMods\");\n  localStorage.setItem(\"fenixAdminSecret\", $(\"adminSecret\").value.trim());\n  $(\"topStatus\").textContent = \"Admin conectado\";\n  $(\"loginMsg\").textContent = \"Login salvo neste navegador.\";\n  loadUsers();\n  loadSchedule();\n}\nfunction logout(){\n  localStorage.removeItem(\"fenixAdminSecret\");\n  $(\"adminSecret\").value = \"\";\n  $(\"topStatus\").textContent = \"Desconectado\";\n  $(\"loginMsg\").textContent = \"Senha removida.\";\n}\nasync function apiGet(url){\n  const res = await fetch(API + url, { headers: adminHeaders(), cache:\"no-store\" });\n  const data = await res.json();\n  if(!res.ok || data.ok === false) throw new Error(data.message || \"Erro API\");\n  return data;\n}\nasync function apiPost(url, body){\n  const res = await fetch(API + url, {method:\"POST\",headers:adminHeaders(),body:JSON.stringify(body)});\n  const data = await res.json();\n  if(!res.ok || data.ok === false) throw new Error(data.message || \"Erro API\");\n  return data;\n}\nfunction farmPill(user){\n  if (user.farmOk) return '<span class=\"pill ok\">Farm OK</span>';\n  if (user.farmStatus === \"Atenção\" || user.farmStatus === \"Atencao\") return '<span class=\"pill warn\">Atenção</span>';\n  if (user.online || user.farmActive) return '<span class=\"pill warn\">Incompleto</span>';\n  return '<span class=\"pill bad\">Offline</span>';\n}\nfunction kickPill(user){\n  return (user.kickConnected || user.kickLoggedIn)\n    ? '<span class=\"pill ok\">Sim</span>'\n    : '<span class=\"pill bad\">Nao</span>';\n}\nfunction userTable(users, mode){\n  if(!users.length) return '<p class=\"muted\">Nenhum usuario encontrado.</p>';\n\n  return '<table><thead><tr>' +\n    '<th>#</th><th>Usuario</th><th>Kick</th><th>Farm</th><th>Kick vinculada</th><th>Ultimo ciclo</th><th>Semana</th><th>Total</th><th>Status</th>' +\n    '</tr></thead><tbody>' +\n    users.map(function(u,i){\n      const weekly = Number(u.weeklyPoints || 0);\n      const total = Number(u.points || 0);\n      const approved = weekly >= 1815;\n      const rankingStatus = approved ? '<span class=\"pill ok\">Aprovado 70%</span>' : '<span class=\"pill bad\">Pendente</span>';\n      const status = mode === \"ranking\" ? rankingStatus : farmPill(u);\n\n      return '<tr>' +\n        '<td>'+(i+1)+'</td>' +\n        '<td><b>'+escapeHtml(u.username || \"-\")+'</b></td>' +\n        '<td>'+escapeHtml(u.kickUsername || u.kickName || \"-\")+'</td>' +\n        '<td>'+farmPill(u)+'</td>' +\n        '<td>'+kickPill(u)+'</td>' +\n        '<td>'+escapeHtml(u.lastCycleText || \"Nunca\")+'</td>' +\n        '<td>'+weekly+' pts</td>' +\n        '<td>'+total+' pts</td>' +\n        '<td>'+status+'</td>' +\n      '</tr>';\n    }).join(\"\") + '</tbody></table>';\n}\nasync function loadUsers(){\n  try{\n    const data = await apiGet(\"/api/fenix/admin/online-users\");\n    const users = Array.isArray(data.users) ? data.users : [];\n    const active = users.filter(function(u){ return u.online || u.farmActive || u.farmOk; });\n    const ranking = users.slice().sort(function(a,b){\n      return Number(b.weeklyPoints||0)-Number(a.weeklyPoints||0) || Number(b.points||0)-Number(a.points||0);\n    });\n\n    $(\"activeUsers\").innerHTML = userTable(active, \"active\");\n    $(\"rankingUsers\").innerHTML = userTable(ranking, \"ranking\");\n    $(\"loginMsg\").textContent = \"Usuarios carregados.\";\n  }catch(e){ $(\"loginMsg\").textContent = e.message; }\n}\nfunction renderSchedule(schedule){\n  const date = $(\"slotDate\").value || today();\n  $(\"scheduleRows\").innerHTML = hours.map(function(hour){\n    const slot = schedule.find(function(s){ return s.slotDate === date && s.slotHour === hour; }) || {};\n    return '<div class=\"row24\" data-hour=\"'+hour+'\"><b>'+hour+'</b>' +\n      '<input data-screen=\"1\" placeholder=\"Tela 1 canal\" value=\"'+escapeHtml(slot.screen1Name || \"\")+'\" />' +\n      '<input data-screen=\"2\" placeholder=\"Tela 2 canal\" value=\"'+escapeHtml(slot.screen2Name || \"\")+'\" />' +\n      '<input data-screen=\"3\" placeholder=\"Tela 3 canal\" value=\"'+escapeHtml(slot.screen3Name || \"\")+'\" />' +\n      '<button onclick=\"saveHour(\\''+hour+'\\')\">Salvar</button></div>';\n  }).join(\"\");\n}\nasync function loadSchedule(){\n  try{\n    const data = await apiGet(\"/api/fenix/admin/schedule\");\n    renderSchedule(Array.isArray(data.schedule) ? data.schedule : []);\n    $(\"scheduleMsg\").textContent = \"Grade carregada.\";\n  }catch(e){ $(\"scheduleMsg\").textContent = e.message; }\n}\nasync function saveHour(hour){\n  const row = document.querySelector('.row24[data-hour=\"'+hour+'\"]');\n  const date = $(\"slotDate\").value || today();\n  const s1 = row.querySelector('[data-screen=\"1\"]').value.trim();\n  const s2 = row.querySelector('[data-screen=\"2\"]').value.trim();\n  const s3 = row.querySelector('[data-screen=\"3\"]').value.trim();\n\n  try{\n    await apiPost(\"/api/fenix/admin/schedule\", {\n      adminUsername:$(\"adminUser\").value.trim() || \"GokuuMods\",\n      adminSecret:$(\"adminSecret\").value.trim(),\n      slotDate:date,\n      slotHour:hour,\n      screen1Name:s1, screen1Url:buildKickUrl(s1), screen1Maintenance:!s1,\n      screen2Name:s2, screen2Url:buildKickUrl(s2), screen2Maintenance:!s2,\n      screen3Name:s3, screen3Url:buildKickUrl(s3), screen3Maintenance:!s3\n    });\n    $(\"scheduleMsg\").textContent = \"Horario \" + hour + \" salvo.\";\n  }catch(e){ $(\"scheduleMsg\").textContent = e.message; }\n}\nasync function saveAllVisible(){\n  for(const hour of hours){ await saveHour(hour); }\n  $(\"scheduleMsg\").textContent = \"Grade inteira salva.\";\n}\nasync function saveNotice(){\n  try{\n    await apiPost(\"/api/fenix/admin/notice\", {\n      adminUsername:$(\"adminUser\").value.trim() || \"GokuuMods\",\n      adminSecret:$(\"adminSecret\").value.trim(),\n      message:$(\"noticeText\").value.trim()\n    });\n    $(\"noticeMsg\").textContent = \"Aviso salvo.\";\n  }catch(e){ $(\"noticeMsg\").textContent = e.message; }\n}\n\n$(\"slotDate\").value = today();\n$(\"adminUser\").value = localStorage.getItem(\"fenixAdminUser\") || \"GokuuMods\";\n$(\"adminSecret\").value = localStorage.getItem(\"fenixAdminSecret\") || \"\";\n\nif($(\"adminSecret\").value){\n  $(\"topStatus\").textContent = \"Admin conectado\";\n  loadUsers();\n  loadSchedule();\n}\n\n// FENIX_ADMIN_AUTO_REFRESH_30S_FINAL\nsetInterval(function(){\n  var input = document.getElementById('adminSecret');\n  if(input && input.value){\n    loadUsers();\n  }\n}, 30000);\n\n</script>\n</body>\n</html>");
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

const FENIX_DRAW_DAYS = ['segunda', 'terca', 'quarta', 'quinta', 'sexta', 'sabado'];

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

  for (const applicant of activeApplicants) {
    usage[applicant.slug] = 0;
    usageByDay[applicant.slug] = {};
  }

  for (const dayKey of FENIX_DRAW_DAYS) {
    const vacantHours = fenixPickVacantHours(vacancyPerDay);

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
            status: 'SEM_CANDIDATO',
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
    }
  }

  return {
    id: 'draw-' + Date.now(),
    createdAt: new Date().toISOString(),
    vacancyPerDay,
    screensPerHour,
    rows,
    summary: {
      applicants: activeApplicants.length,
      totalRows: rows.length,
      totalVacantHours: rows.filter((row) => row.manualVacancy).length,
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
    textarea, input { width: 100%; box-sizing: border-box; background: #070707; color: #fff; border: 1px solid #3d300f; border-radius: 10px; padding: 10px; }
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

    document.getElementById("drawMsg").textContent = "Gerando sorteio...";

    try {
      const data = await api("/api/fenix/admin/grade-draw/generate", {
        method: "POST",
        body: JSON.stringify({ vacancyPerDay })
      });

      document.getElementById("drawMsg").textContent =
        "Sorteio gerado. Inscritos: " + data.draw.summary.applicants +
        " | Vagos por dia: " + data.draw.vacancyPerDay;

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

    let html = "<table><thead><tr><th>Dia</th><th>Hora</th><th>Tela 1</th><th>Tela 2</th><th>Tela 3</th><th>Ação</th></tr></thead><tbody>";

    draw.rows.forEach((row) => {
      const screens = row.screens || [];

      function screenText(index) {
        const s = screens[index] || {};
        if (s.status === "OK") return "<span class='ok'>" + s.nick + "</span>";
        if (s.status === "VAGO") return "<span class='vago'>VAGO</span>";
        return "<span class='bad'>VAGO MANUAL</span>";
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
  const draw = fenixGenerateGradeDraw(applicants, { vacancyPerDay });

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
  const draw = fenixGenerateGradeDraw(data.formApplicants, { vacancyPerDay });

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
  const applicantRows = applicants.map((item) => {
    return `
      <tr>
        <td>${fenixHtmlEscape(item.name)}</td>
        <td><b>${fenixHtmlEscape(item.nick)}</b></td>
        <td>${fenixHtmlEscape(item.whatsapp)}</td>
        <td>${fenixHtmlEscape(fenixAvailabilityTextSimple(item.availability))}</td>
      </tr>
    `;
  }).join('');

  const drawRows = draw && Array.isArray(draw.rows) ? draw.rows.map((row) => {
    const screens = row.screens || [];

    function screen(index) {
      const s = screens[index] || {};
      if (s.status === 'OK') return '<span class="ok">' + fenixHtmlEscape(s.nick) + '</span>';
      if (s.status === 'VAGO') return '<span class="vago">VAGO</span>';
      return '<span class="bad">VAGO MANUAL</span>';
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
    input, textarea { width:100%; box-sizing:border-box; background:#050505; color:#fff; border:1px solid #49370e; border-radius:10px; padding:10px; }
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
    <h2>2. Ver inscritos salvos</h2>
    <form method="POST" action="/admin/grade-sorteio-simples/ver">
      <label>Senha Admin:</label>
      <input name="adminSecret" type="password" placeholder="Digite a senha admin da Railway" required>
      <button type="submit">Ver inscritos</button>
    </form>

    <h3>Total: ${applicants.length}</h3>
    <table>
      <thead>
        <tr>
          <th>Nome</th>
          <th>Nick Kick</th>
          <th>WhatsApp</th>
          <th>Horários marcados</th>
        </tr>
      </thead>
      <tbody>
        ${applicantRows || '<tr><td colspan="4">Nenhum inscrito carregado ainda.</td></tr>'}
      </tbody>
    </table>
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
      <label>Horários vagos por dia:</label>
      <input name="vacancyPerDay" type="number" min="0" max="24" value="3">
      <button type="submit">Gerar grade por sorteio</button>
    </form>
  </section>

  <section>
    <h2>4. Grade sorteada</h2>
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
  const vacancyPerDay = Number(req.body?.vacancyPerDay || 0);
  const draw = fenixGenerateGradeDraw(applicants, { vacancyPerDay });

  fenixSaveGradeDrawFileFinal(draw);

  res.type('html').send(fenixRenderGradeSorteioSimplesPage({
    applicants,
    draw,
    message: 'Sorteio gerado. Inscritos: ' + applicants.length + ' | Vagos por dia: ' + vacancyPerDay
  }));
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

app.listen(PORT, () => {
  console.log(`${APP_NAME} online na porta ${PORT}`);
  console.log(`URL local: http://localhost:${PORT}`);
});















