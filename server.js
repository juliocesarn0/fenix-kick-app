import 'dotenv/config';
import crypto from 'crypto';
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

app.listen(PORT, () => {
  console.log(`${APP_NAME} online na porta ${PORT}`);
  console.log(`URL local: http://localhost:${PORT}`);
});
