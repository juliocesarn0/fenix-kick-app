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
    cycles: []
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
      cycles: Array.isArray(parsed.cycles) ? parsed.cycles : []
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

function requireFenixAdmin(req, res, next) {
  const adminUsername =
    req.headers['x-fenix-admin'] ||
    req.body?.adminUsername ||
    req.query?.adminUsername ||
    '';

  const adminSecret =
    req.headers['x-fenix-admin-secret'] ||
    req.body?.adminSecret ||
    req.query?.adminSecret ||
    '';

  if (String(adminUsername).trim().toLowerCase() !== FENIX_ADMIN_USER.toLowerCase()) {
    return res.status(403).json({
      ok: false,
      message: 'Painel Admin liberado somente para GokuuMods.'
    });
  }

  if (!FENIX_ADMIN_SECRET || String(adminSecret) !== String(FENIX_ADMIN_SECRET)) {
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
      kickLoggedIn: user.kickLoggedIn
    }
  });
});

app.post('/api/fenix/app/heartbeat', (req, res) => {
  const sessionId = String(req.body?.sessionId || '').trim();
  const kickLoggedIn = Boolean(req.body?.kickLoggedIn);

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
      kickLoggedIn: user.kickLoggedIn
    }
  });
});

app.get('/api/fenix/app/current-schedule', (req, res) => {
  const data = readFenixData();
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
  const notice = data.notices.find((item) => item.active !== false) || null;

  res.json({
    ok: true,
    slot,
    slots: fenixSlotToDesktopSlots(slot),
    notice
  });
});

app.get('/api/fenix-desktop-slots', (req, res) => {
  const data = readFenixData();
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

  res.json({
    ok: true,
    slots: fenixSlotToDesktopSlots(slot)
  });
});

app.post('/api/fenix/app/complete-cycle', (req, res) => {
  const sessionId = String(req.body?.sessionId || '').trim();
  const cycleKey = String(req.body?.cycleKey || '').trim();
  const kickLoggedIn = Boolean(req.body?.kickLoggedIn);

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
      kickLoggedIn: user.kickLoggedIn
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


app.listen(PORT, () => {
  console.log(`${APP_NAME} online na porta ${PORT}`);
  console.log(`URL local: http://localhost:${PORT}`);
});




