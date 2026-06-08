const CONFIG = {
  adminApi: "https://fenix-kick-app-production.up.railway.app",
  fallbackProfile: "gokuumods",
  refreshSeconds: 60,
  quality: "160p",
  slots: [
    {
      id: 1,
      title: "Tela 1",
      channel: "gokuumods",
      url: "https://kick.com/gokuumods",
      active: true
    },
    {
      id: 2,
      title: "Tela 2",
      channel: "",
      url: "",
      active: false
    },
    {
      id: 3,
      title: "Tela 3",
      channel: "",
      url: "",
      active: false
    }
  ]
};

let muted = true;
let currentSlots = CONFIG.slots;

const $ = (id) => document.getElementById(id);

function log(message) {
  const list = $("logList");
  const item = document.createElement("div");
  item.className = "log-item";
  item.innerHTML = `<span>${new Date().toLocaleTimeString("pt-BR")}</span><p>${message}</p>`;
  list.prepend(item);
}

function normalizeUrl(channelOrUrl) {
  const value = String(channelOrUrl || "").trim();

  if (!value) return "";

  if (value.startsWith("http://") || value.startsWith("https://")) {
    return value;
  }

  return `https://kick.com/${value.replace(/^@/, "")}`;
}

function setMaintenance(slotNumber, enabled, text = "Aguardando canal agendado") {
  const maint = $(`maint${slotNumber}`);
  const view = $(`view${slotNumber}`);

  maint.style.display = enabled ? "grid" : "none";
  view.style.display = enabled ? "none" : "flex";

  const span = maint.querySelector("span");
  if (span) span.textContent = text;
}

function setSlot(slot) {
  const number = slot.id;
  const view = $(`view${number}`);
  const label = $(`slot${number}Label`);
  const status = $(`slot${number}Status`);
  const quality = $(`slot${number}Quality`);

  const url = normalizeUrl(slot.url || slot.channel);

  label.textContent = slot.channel ? `kick.com/${slot.channel}` : "Aguardando live";
  quality.textContent = CONFIG.quality;

  if (!slot.active || !url) {
    setMaintenance(number, true, "Aguardando canal agendado");
    status.textContent = "Manutenção";
    view.removeAttribute("src");
    return;
  }

  setMaintenance(number, false);
  status.textContent = "Carregando";
  view.src = url;

  view.addEventListener("did-finish-load", () => {
    status.textContent = "Online";
    trySetLowQuality(view);
    if (muted) view.setAudioMuted(true);
  });

  view.addEventListener("did-fail-load", () => {
    status.textContent = "Erro ao carregar";
    setMaintenance(number, true, "Erro ao carregar a live");
  });

  log(`Tela ${number} carregando ${url}`);
}

function loadSlots(slots) {
  currentSlots = slots;
  slots.forEach(setSlot);
}

async function tryLoadAdminSlots() {
  try {
    const res = await fetch(`${CONFIG.adminApi}/api/fenix-desktop-slots`, {
      cache: "no-store"
    });

    if (!res.ok) throw new Error("Sem rota admin ainda");

    const data = await res.json();
    if (!Array.isArray(data.slots)) throw new Error("Resposta invalida");

    loadSlots(data.slots);
    log("Grade carregada pelo painel admin.");
  } catch {
    loadSlots(CONFIG.slots);
    log("Usando grade local do app. A rota do painel admin ainda nao existe.");
  }
}

function refreshScreens() {
  currentSlots.forEach((slot) => {
    const view = $(`view${slot.id}`);
    if (slot.active && view.src) {
      view.reload();
      log(`Tela ${slot.id} atualizada.`);
    }
  });
}

function openExternalSlot(slotNumber) {
  const slot = currentSlots.find((item) => item.id === slotNumber);
  const url = normalizeUrl(slot?.url || slot?.channel);

  if (url) {
    window.open(url, "_blank");
  }
}

function muteAll() {
  muted = !muted;

  [1, 2, 3].forEach((number) => {
    const view = $(`view${number}`);
    if (view) view.setAudioMuted(muted);
  });

  $("muteAllBtn").textContent = muted ? "Ativar Som" : "Silenciar Tudo";
  log(muted ? "Todas as telas silenciadas." : "Som ativado nas telas.");
}

function trySetLowQuality(view) {
  const code = `
    (() => {
      const delay = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

      async function click160p() {
        try {
          await delay(2500);

          const video = document.querySelector("video");
          if (video) {
            video.muted = true;
            video.volume = 0;
          }

          const buttons = Array.from(document.querySelectorAll("button, div, span"));
          const gear = buttons.find((el) => {
            const label = (el.getAttribute("aria-label") || el.title || el.textContent || "").toLowerCase();
            return label.includes("settings") || label.includes("quality") || label.includes("qualidade");
          });

          if (gear) gear.click();

          await delay(700);

          const options = Array.from(document.querySelectorAll("button, div, span"));
          const option160 = options.find((el) => String(el.textContent || "").includes("160p"));
          if (option160) option160.click();
        } catch {}
      }

      click160p();
    })();
  `;

  try {
    view.executeJavaScript(code, true);
  } catch {}
}

function updateClock() {
  const now = new Date();
  const hour = String(now.getHours()).padStart(2, "0");
  const min = String(now.getMinutes()).padStart(2, "0");
  $("clockTimer").textContent = `${hour}:${min}`;
}

function applyLayout(layout) {
  const grid = $("viewerGrid");
  grid.className = `viewer-grid ${layout}`;

  document.querySelectorAll(".layout-btn").forEach((btn) => {
    btn.classList.toggle("active", btn.dataset.layout === layout);
  });

  log(`Layout alterado para ${layout}.`);
}

function clearCookies() {
  localStorage.clear();
  log("Cookies/sessao local limpos. Para limpar login da Kick, feche e abra o app.");
}

function setupEvents() {
  $("refreshScreensBtn").addEventListener("click", refreshScreens);
  $("muteAllBtn").addEventListener("click", muteAll);
  $("exitBtn").addEventListener("click", () => window.close());
  $("clearCookiesBtn").addEventListener("click", clearCookies);
  $("clearLogBtn").addEventListener("click", () => $("logList").innerHTML = "");

  document.querySelectorAll(".layout-btn").forEach((btn) => {
    btn.addEventListener("click", () => applyLayout(btn.dataset.layout));
  });

  document.querySelectorAll("[data-refresh]").forEach((btn) => {
    btn.addEventListener("click", () => {
      const number = Number(btn.dataset.refresh);
      const view = $(`view${number}`);
      if (view?.src) view.reload();
      log(`Tela ${number} atualizada manualmente.`);
    });
  });

  document.querySelectorAll("[data-open]").forEach((btn) => {
    btn.addEventListener("click", () => openExternalSlot(Number(btn.dataset.open)));
  });
}

document.addEventListener("DOMContentLoaded", () => {
  $("profileName").textContent = CONFIG.fallbackProfile;
  $("coinValue").textContent = "0";
  $("hoursMeta").textContent = "0h / 100h";
  $("hoursBar").style.width = "0%";

  setupEvents();
  updateClock();
  setInterval(updateClock, 1000);

  tryLoadAdminSlots();
  setInterval(tryLoadAdminSlots, CONFIG.refreshSeconds * 1000);

  $("muteAllBtn").textContent = "Ativar Som";
  log("Fenix Lurk iniciado.");
});
