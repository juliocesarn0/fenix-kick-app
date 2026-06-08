# Fenix Kick App

Base propria em Node.js + Express, pronta para Railway.

## O que tem

- Tela Fenix com visual preto/laranja.
- Login OAuth Kick com PKCE.
- Dashboard.
- Consulta do proprio canal conectado.
- Consulta de canal por slug.
- Lista de livestreams publicas.
- Endpoint de health check.
- Configuracao por variaveis de ambiente.

## Rodar local

```powershell
cd "C:\Users\User\Desktop\fenix-kick-app"
npm install
copy .env.example .env
npm run dev
```

Depois edite o `.env` com seus dados da Kick.

## Variaveis da Railway

```env
APP_NAME=Fenix
APP_URL=https://SEU-DOMINIO.up.railway.app
SESSION_SECRET=troque-por-uma-chave-grande
KICK_CLIENT_ID=seu_client_id
KICK_CLIENT_SECRET=seu_client_secret
KICK_REDIRECT_URI=https://SEU-DOMINIO.up.railway.app/auth/kick/callback
KICK_SCOPES=user:read channel:read
```

Na Kick Developer, cadastre o mesmo Redirect URI:

```text
https://SEU-DOMINIO.up.railway.app/auth/kick/callback
```

## Rotas

- `/` tela inicial.
- `/dashboard.html` painel.
- `/health` teste.
- `/auth/kick` login Kick.
- `/auth/kick/callback` callback OAuth.
- `/api/me` dados do canal conectado.
- `/api/channel/:slug` consulta canal.
- `/api/livestreams` lista lives.
- `/api/livestreams/stats` total publico.
