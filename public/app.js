const els = {
  loginStatus: document.getElementById('loginStatus'),
  kickUser: document.getElementById('kickUser'),
  kickSlug: document.getElementById('kickSlug'),
  liveStatus: document.getElementById('liveStatus'),
  viewerCount: document.getElementById('viewerCount'),
  totalLive: document.getElementById('totalLive'),
  refreshBtn: document.getElementById('refreshBtn'),
  logoutBtn: document.getElementById('logoutBtn'),
  slugInput: document.getElementById('slugInput'),
  searchBtn: document.getElementById('searchBtn'),
  channelResult: document.getElementById('channelResult'),
  loadLivesBtn: document.getElementById('loadLivesBtn'),
  livesList: document.getElementById('livesList')
};

function safe(value, fallback = '---') {
  return value === undefined || value === null || value === '' ? fallback : value;
}

function renderChannel(box, channel) {
  if (!channel) {
    box.innerHTML = 'Canal nao encontrado.';
    return;
  }

  const stream = channel.stream || {};
  box.innerHTML = `
    <strong>${safe(channel.slug || channel.broadcaster_user_id)}</strong><br>
    <span class="muted">Titulo: ${safe(channel.stream_title)}</span><br>
    <span class="muted">Categoria: ${safe(channel.category?.name)}</span><br>
    <span class="muted">Live: ${stream.is_live ? 'AO VIVO' : 'Offline'}</span><br>
    <span class="muted">Viewers: ${safe(stream.viewer_count, 0)}</span>
  `;
}

async function loadMe() {
  try {
    const res = await fetch('/api/me');
    const data = await res.json();

    if (!res.ok) {
      els.loginStatus.textContent = 'Nao conectado';
      els.kickUser.textContent = 'Nao conectado';
      els.kickSlug.textContent = 'Entre com sua conta Kick.';
      return;
    }

    const user = data.user;
    const stream = user?.stream || {};
    els.loginStatus.textContent = 'Kick conectado';
    els.kickUser.textContent = safe(user?.slug || user?.broadcaster_user_id);
    els.kickSlug.textContent = user?.slug ? `kick.com/${user.slug}` : 'Conta conectada';
    els.liveStatus.textContent = stream.is_live ? 'AO VIVO' : 'Offline';
    els.viewerCount.textContent = `Viewers: ${safe(stream.viewer_count, 0)}`;
  } catch (e) {
    els.loginStatus.textContent = 'Erro ao verificar';
  }
}

async function loadStats() {
  try {
    const res = await fetch('/api/livestreams/stats');
    const data = await res.json();
    els.totalLive.textContent = safe(data.stats?.total_count, '---');
  } catch {
    els.totalLive.textContent = '---';
  }
}

async function searchChannel() {
  const slug = els.slugInput.value.trim().replace(/^https?:\/\/kick\.com\//i, '').replace(/^kick\.com\//i, '');
  if (!slug) {
    els.channelResult.textContent = 'Digite um slug primeiro.';
    return;
  }

  els.channelResult.textContent = 'Buscando...';
  try {
    const res = await fetch(`/api/channel/${encodeURIComponent(slug)}`);
    const data = await res.json();
    if (!res.ok) throw new Error(data.message || 'Erro na busca.');
    renderChannel(els.channelResult, data.channel);
  } catch (e) {
    els.channelResult.textContent = e.message;
  }
}

async function loadLives() {
  els.livesList.textContent = 'Carregando...';
  try {
    const res = await fetch('/api/livestreams?limit=15&sort=viewer_count');
    const data = await res.json();
    if (!res.ok) throw new Error(data.message || 'Erro ao carregar lives.');

    const lives = data.livestreams || [];
    if (!lives.length) {
      els.livesList.textContent = 'Nenhuma live retornada.';
      return;
    }

    els.livesList.innerHTML = lives.map((live) => `
      <div class="live-item">
        <div>
          <strong>${safe(live.slug)}</strong><br>
          <span class="muted">${safe(live.stream_title)}</span><br>
          <span class="muted">${safe(live.category?.name)} · ${safe(live.language)}</span>
        </div>
        <span class="badge">${safe(live.viewer_count, 0)}</span>
      </div>
    `).join('');
  } catch (e) {
    els.livesList.textContent = e.message;
  }
}

els.refreshBtn.addEventListener('click', () => { loadMe(); loadStats(); });
els.searchBtn.addEventListener('click', searchChannel);
els.slugInput.addEventListener('keydown', (e) => { if (e.key === 'Enter') searchChannel(); });
els.loadLivesBtn.addEventListener('click', loadLives);
els.logoutBtn.addEventListener('click', async () => {
  await fetch('/auth/logout', { method: 'POST' });
  location.href = '/';
});

loadMe();
loadStats();
