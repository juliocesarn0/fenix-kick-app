const CONFIG = {
  adminApi: "https://fenix-kick-app-production.up.railway.app",
  refreshSeconds: 60,
  cycleSeconds: 10 * 60,
  quality: "160p",
  defaultSlots: [
    { id: 1, title: "Tela 1", channel: "", url: "", active: false, maintenance: true },
    { id: 2, title: "Tela 2", channel: "", url: "", active: false, maintenance: true },
    { id: 3, title: "Tela 3", channel: "", url: "", active: false, maintenance: true }
  ]
};

let muted = true;
let currentSlots = CONFIG.defaultSlots;
let fenixSession = null;
let kickLoggedIn = false;
let cycleLeft = CONFIG.cycleSeconds;
let cycleTimer = null;
let heartbeatTimer = null;

const $ = (id) => document.getElementById(id);

function log(message) {
  const list = $("logList");
  if (!list) return;

  const item = document.createElement("div");
  item.className = "log-item";
  item.innerHTML = "<span>" + new Date().toLocaleTimeString("pt-BR") + "</span><p>" + message + "</p>";
  list.prepend(item);
}

function normalizeUrl(channelOrUrl) {
  const value = String(channelOrUrl || "").trim();

  if (!value) return "";

  if (value.startsWith("http://") || value.startsWith("https://")) {
    return value;
  }

  return "https://kick.com/" + value.replace(/^@/, "");
}

function formatMinutes(minutes) {
  const hours = Math.floor(Number(minutes || 0) / 60);
  const mins = Number(minutes || 0) % 60;

  if (hours <= 0) return mins + "min";

  return hours + "h" + (mins ? " " + mins + "min" : "");
}

function setKickStatus(isLogged) {
  kickLoggedIn = Boolean(isLogged);

  const dot = $("kickDot");
  const text = $("kickStatusText");

  if (dot) {
    dot.classList.toggle("ok", kickLoggedIn);
    dot.classList.toggle("danger", !kickLoggedIn);
  }

  if (text) {
    text.textContent = kickLoggedIn ? "KICK LOGADA" : "KICK NAO LOGADA";
    text.classList.toggle("kick-ok", kickLoggedIn);
    text.classList.toggle("kick-blocked", !kickLoggedIn);
  }

  if (fenixSession) {
    localStorage.setItem("fenixKickLoggedIn", kickLoggedIn ? "1" : "0");
  }
}

function renderUser(user) {
  if (!user) return;

  $("profileName").textContent = user.username || "usuario";
  $("coinValue").textContent = String(user.points || 0);

  const hoursText = formatMinutes(user.weeklyMinutes || 0) + " / 100h";
  $("hoursMeta").textContent = hoursText;

  const percent = Math.max(0, Math.min(100, (Number(user.weeklyMinutes || 0) / (100 * 60)) * 100));
  $("hoursBar").style.width = percent + "%";

  setKickStatus(Boolean(user.kickLoggedIn));
}

async function loginOrRegister() {
  const username = $("loginUsername").value.trim();
  const password = $("loginPassword").value;
  const message = $("loginMessage");

  message.textContent = "";

  if (!username || username.length < 3) {
    message.textContent = "Digite um username com pelo menos 3 caracteres.";
    return;
  }

  if (!password || password.length < 3) {
    message.textContent = "Digite uma senha com pelo menos 3 caracteres.";
    return;
  }

  try {
    $("loginButton").disabled = true;
    $("loginButton").textContent = "Entrando...";

    let deviceId = localStorage.getItem("fenixDeviceId");
    if (!deviceId) {
      deviceId = crypto.randomUUID();
      localStorage.setItem("fenixDeviceId", deviceId);
    }

    const res = await fetch(CONFIG.adminApi + "/api/fenix/auth/register-or-login", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        username,
        password,
        deviceId,
        appVersion: "1.0.0"
      })
    });

    const data = await res.json();

    if (!res.ok || !data.ok) {
      throw new Error(data.message || "Erro ao entrar.");
    }

    fenixSession = {
      sessionId: data.sessionId,
      user: data.user
    };

    localStorage.setItem("fenixSession", JSON.stringify(fenixSession));

    $("loginGate").classList.add("hidden");
    $("mainApp").classList.remove("hidden");

    renderUser(data.user);
    await tryLoadAdminSlots();
    startHeartbeat();
    startCycleTimer();

    log(data.created ? "Conta Fenix criada." : "Login Fenix realizado.");
  } catch (error) {
    message.textContent = error.message || String(error);
  } finally {
    $("loginButton").disabled = false;
    $("loginButton").textContent = "Entrar / Criar Conta";
  }
}

function restoreSession() {
  try {
    const saved = JSON.parse(localStorage.getItem("fenixSession") || "null");
    if (!saved?.sessionId || !saved?.user?.username) return false;

    fenixSession = saved;

    $("loginGate").classList.add("hidden");
    $("mainApp").classList.remove("hidden");

    renderUser(saved.user);
    setKickStatus(localStorage.getItem("fenixKickLoggedIn") === "1");

    return true;
  } catch {
    return false;
  }
}

function setMaintenance(slotNumber, enabled, text = "Aguardando canal agendado") {
  const maint = $("maint" + slotNumber);
  const view = $("view" + slotNumber);

  maint.style.display = enabled ? "grid" : "none";
  view.style.display = enabled ? "none" : "flex";

  const span = maint.querySelector("span");
  if (span) span.textContent = text;
}

function setSlot(slot) {
  const number = slot.id;
  const view = $("view" + number);
  const label = $("slot" + number + "Label");
  const status = $("slot" + number + "Status");
  const quality = $("slot" + number + "Quality");

  const url = normalizeUrl(slot.url || slot.channel);

  label.textContent = slot.channel ? "kick.com/" + slot.channel : "Aguardando live";
  quality.textContent = CONFIG.quality;

  if (!slot.active || !url || slot.maintenance) {
    setMaintenance(number, true, "Aguardando canal agendado");
    status.textContent = "Manutenção";
    view.removeAttribute("src");
    return;
  }

  setMaintenance(number, false);
  status.textContent = "Carregando";

  if (view.getAttribute("src") !== url) {
    view.setAttribute("src", url);
  }

  view.addEventListener("did-finish-load", () => {
    status.textContent = "Online";
    trySetLowQuality(view);
    if (muted) view.setAudioMuted(true);
  }, { once: true });

  view.addEventListener("did-fail-load", () => {
    status.textContent = "Erro ao carregar";
    setMaintenance(number, true, "Erro ao carregar a live");
  }, { once: true });

  log("Tela " + number + " carregando " + url);
}

function loadSlots(slots) {
  currentSlots = Array.isArray(slots) ? slots : CONFIG.defaultSlots;
  currentSlots.forEach(setSlot);
}

async function tryLoadAdminSlots() {
  try {
    const res = await fetch(CONFIG.adminApi + "/api/fenix-desktop-slots", {
      cache: "no-store"
    });

    if (!res.ok) throw new Error("Sem grade admin");

    const data = await res.json();
    if (!Array.isArray(data.slots)) throw new Error("Resposta invalida");

    loadSlots(data.slots);
    log("Grade carregada pelo painel admin.");
  } catch {
    loadSlots(CONFIG.defaultSlots);
    log("Erro ao carregar grade admin. Telas em manutenção.");
  }
}

async function detectKickLoginFromViews() {
  let foundLogged = false;

  for (const number of [1, 2, 3]) {
    const view = $("view" + number);

    if (!view || !view.getAttribute("src")) continue;

    try {
      const result = await view.executeJavaScript(`
        (function () {
          var text = document.body ? document.body.innerText.toLowerCase() : "";
          var hasLoginText = text.includes("log in") || text.includes("sign up") || text.includes("entrar") || text.includes("cadastre");
          var hasUserButtons = !!document.querySelector('a[href*="/settings"], a[href*="/dashboard"], button[aria-label*="profile"], button[aria-label*="Profile"]');
          return hasUserButtons || !hasLoginText;
        })();
      `, true);

      if (result) {
        foundLogged = true;
        break;
      }
    } catch {}
  }

  setKickStatus(foundLogged);
  await sendHeartbeat();

  if (foundLogged) {
    log("Kick logada confirmada nas telas. Pontos liberados.");
  } else {
    log("Kick ainda nao confirmada. Pontos bloqueados.");
  }

  return foundLogged;
}

async function refreshScreens() {
  await tryLoadAdminSlots();

  currentSlots.forEach((slot) => {
    const view = $("view" + slot.id);
    if (slot.active && view?.getAttribute("src")) {
      view.reload();
      log("Tela " + slot.id + " atualizada.");
    }
  });

  setTimeout(() => {
    detectKickLoginFromViews();
  }, 3500);
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
    const view = $("view" + number);
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

function updateCycleText() {
  const min = String(Math.floor(cycleLeft / 60)).padStart(2, "0");
  const sec = String(cycleLeft % 60).padStart(2, "0");

  $("clockTimer").textContent = min + ":" + sec;

  const info = $("cycleInfo");
  if (info) {
    info.textContent = kickLoggedIn
      ? "Ciclo: " + min + ":" + sec + " · pontos liberados"
      : "Ciclo: " + min + ":" + sec + " · Kick nao logada";
  }
}

function getCycleKey() {
  const now = new Date();
  const rounded = new Date(now);
  rounded.setMinutes(Math.floor(now.getMinutes() / 10) * 10, 0, 0);

  return rounded.toISOString();
}

async function completeCycle() {
  if (!fenixSession?.sessionId) return;

  if (!kickLoggedIn) {
    log("Ciclo finalizado sem pontos: Kick nao logada.");
    return;
  }

  try {
    const res = await fetch(CONFIG.adminApi + "/api/fenix/app/complete-cycle", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        sessionId: fenixSession.sessionId,
        cycleKey: getCycleKey(),
        kickLoggedIn
      })
    });

    const data = await res.json();

    if (!res.ok || !data.ok) {
      throw new Error(data.message || "Erro ao contabilizar ciclo.");
    }

    if (data.paid) {
      fenixSession.user = data.user;
      localStorage.setItem("fenixSession", JSON.stringify(fenixSession));
      renderUser(data.user);
      log("Ciclo pago: +" + data.points + " pontos.");
    } else if (data.duplicated) {
      log("Ciclo ja contabilizado.");
    }
  } catch (error) {
    log("Erro no ciclo: " + (error.message || String(error)));
  }
}

function startCycleTimer() {
  if (cycleTimer) clearInterval(cycleTimer);

  cycleLeft = CONFIG.cycleSeconds;
  updateCycleText();

  cycleTimer = setInterval(async () => {
    cycleLeft -= 1;

    if (cycleLeft <= 0) {
      await completeCycle();
      await refreshScreens();
      cycleLeft = CONFIG.cycleSeconds;
    }

    updateCycleText();
  }, 1000);
}

async function sendHeartbeat() {
  if (!fenixSession?.sessionId) return;

  try {
    const res = await fetch(CONFIG.adminApi + "/api/fenix/app/heartbeat", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        sessionId: fenixSession.sessionId,
        kickLoggedIn
      })
    });

    const data = await res.json();

    if (res.ok && data.ok) {
      fenixSession.user = data.user;
      localStorage.setItem("fenixSession", JSON.stringify(fenixSession));
      renderUser(data.user);
    }
  } catch {}
}

function startHeartbeat() {
  if (heartbeatTimer) clearInterval(heartbeatTimer);

  sendHeartbeat();
  heartbeatTimer = setInterval(sendHeartbeat, 30000);
}

function applyLayout(layout) {
  const grid = $("viewerGrid");
  grid.className = "viewer-grid " + layout;

  document.querySelectorAll(".layout-btn").forEach((btn) => {
    btn.classList.toggle("active", btn.dataset.layout === layout);
  });

  log("Layout alterado para " + layout + ".");
}

function clearCookies() {
  localStorage.clear();
  setKickStatus(false);
  log("Cookies/sessao local limpos. Feche e abra o app para entrar novamente.");
}

function setupEvents() {
  $("loginButton").addEventListener("click", loginOrRegister);
  $("loginUsername").addEventListener("keydown", (event) => {
    if (event.key === "Enter") $("loginPassword").focus();
  });
  $("loginPassword").addEventListener("keydown", (event) => {
    if (event.key === "Enter") loginOrRegister();
  });

  $("refreshScreensBtn").addEventListener("click", refreshScreens);
  $("muteAllBtn").addEventListener("click", muteAll);
  $("qualityBtn").addEventListener("click", () => {
    [1, 2, 3].forEach((number) => {
      const view = $("view" + number);
      if (view?.getAttribute("src")) trySetLowQuality(view);
    });
    log("Tentando aplicar 160p nas telas.");
  });
  $("exitBtn").addEventListener("click", () => window.close());
  $("clearCookiesBtn").addEventListener("click", clearCookies);
  $("clearLogBtn").addEventListener("click", () => $("logList").innerHTML = "");

  document.querySelectorAll(".layout-btn").forEach((btn) => {
    btn.addEventListener("click", () => applyLayout(btn.dataset.layout));
  });

  document.querySelectorAll("[data-refresh]").forEach((btn) => {
    btn.addEventListener("click", () => {
      const number = Number(btn.dataset.refresh);
      const view = $("view" + number);
      if (view?.getAttribute("src")) view.reload();
      log("Tela " + number + " atualizada manualmente.");
    });
  });

  document.querySelectorAll("[data-open]").forEach((btn) => {
    btn.addEventListener("click", () => openExternalSlot(Number(btn.dataset.open)));
  });
}

document.addEventListener("DOMContentLoaded", async () => {
  $("coinValue").textContent = "0";
  $("hoursMeta").textContent = "0h / 100h";
  $("hoursBar").style.width = "0%";

  setupEvents();

  if (restoreSession()) {
    await tryLoadAdminSlots();
    startHeartbeat();
    startCycleTimer();
    log("Sessao Fenix restaurada.");
  }

  $("muteAllBtn").textContent = "Ativar Som";
  setKickStatus(localStorage.getItem("fenixKickLoggedIn") === "1");
  log("Fenix Lurk iniciado.");
});


// PAINEL_ADMIN_FENIX_JS
function isFenixAdmin() {
  return String(fenixSession?.user?.username || "").toLowerCase() === "gokuumods";
}

function setCurrentAdminDateHour() {
  const now = new Date();
  const dateInput = $("adminSlotDate");
  const hourInput = $("adminSlotHour");

  if (dateInput && !dateInput.value) {
    dateInput.value = now.toISOString().slice(0, 10);
  }

  if (hourInput) {
    hourInput.value = String(now.getHours()).padStart(2, "0") + ":00";
  }
}

async function openAdminPanel() {
  if (!isFenixAdmin()) {
    log("Painel Admin bloqueado. Somente GokuuMods.");
    return;
  }

  $("adminModal").classList.remove("hidden");
  setCurrentAdminDateHour();
  await loadAdminUsers();
}

function closeAdminPanel() {
  $("adminModal").classList.add("hidden");
}

async function loadAdminUsers() {
  const box = $("adminUsersList");
  if (!box) return;

  box.innerHTML = "Carregando...";

  try {
    const res = await fetch(CONFIG.adminApi + "/api/fenix/admin/online-users", {
      headers: { "x-fenix-admin": "GokuuMods" },
      cache: "no-store"
    });

    const data = await res.json();

    if (!res.ok || !data.ok) {
      throw new Error(data.message || "Erro ao carregar usuarios.");
    }

    if (!data.users.length) {
      box.innerHTML = "Nenhum usuario encontrado.";
      return;
    }

    box.innerHTML = data.users.map((user) => {
      const status = user.isOnline ? "ONLINE" : "OFFLINE";
      const statusClass = user.isOnline ? "online" : "offline";
      const kick = user.kickLoggedIn ? "Kick logada" : "Kick nao logada";

      return '<div class="admin-user-item">' +
        '<strong>' + user.username + '</strong>' +
        '<span class="' + statusClass + '">' + status + '</span>' +
        '<span>' + kick + '</span>' +
        '<span>Pontos: ' + Number(user.points || 0) + '</span>' +
        '<span>Minutos semanais: ' + Number(user.weeklyMinutes || 0) + '</span>' +
        '</div>';
    }).join("");
  } catch (error) {
    box.innerHTML = "Erro: " + (error.message || String(error));
  }
}

async function saveAdminSchedule() {
  const body = {
    adminUsername: "GokuuMods",
    slotDate: $("adminSlotDate").value,
    slotHour: $("adminSlotHour").value,

    screen1Name: $("adminScreen1Name").value.trim(),
    screen1Url: $("adminScreen1Url").value.trim(),
    screen1Maintenance: $("adminScreen1Maintenance").checked,

    screen2Name: $("adminScreen2Name").value.trim(),
    screen2Url: $("adminScreen2Url").value.trim(),
    screen2Maintenance: $("adminScreen2Maintenance").checked,

    screen3Name: $("adminScreen3Name").value.trim(),
    screen3Url: $("adminScreen3Url").value.trim(),
    screen3Maintenance: $("adminScreen3Maintenance").checked,

    active: true
  };

  try {
    const res = await fetch(CONFIG.adminApi + "/api/fenix/admin/schedule", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "x-fenix-admin": "GokuuMods"
      },
      body: JSON.stringify(body)
    });

    const data = await res.json();

    if (!res.ok || !data.ok) {
      throw new Error(data.message || "Erro ao salvar grade.");
    }

    log("Grade Admin salva para " + body.slotDate + " " + body.slotHour + ".");
    await tryLoadAdminSlots();
  } catch (error) {
    log("Erro ao salvar grade: " + (error.message || String(error)));
  }
}

async function saveAdminNotice() {
  const message = $("adminNoticeText").value.trim();

  if (!message) {
    log("Digite um aviso antes de salvar.");
    return;
  }

  try {
    const res = await fetch(CONFIG.adminApi + "/api/fenix/admin/notice", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "x-fenix-admin": "GokuuMods"
      },
      body: JSON.stringify({
        adminUsername: "GokuuMods",
        message
      })
    });

    const data = await res.json();

    if (!res.ok || !data.ok) {
      throw new Error(data.message || "Erro ao salvar aviso.");
    }

    $("warningBar").textContent = message;
    $("noticeText").textContent = message;
    $("noticeCount").textContent = "1";
    log("Aviso geral salvo.");
  } catch (error) {
    log("Erro ao salvar aviso: " + (error.message || String(error)));
  }
}

const oldRenderUserForAdmin = renderUser;
renderUser = function (user) {
  oldRenderUserForAdmin(user);

  const adminBtn = $("adminPanelBtn");
  if (adminBtn) {
    adminBtn.classList.toggle("hidden", !isFenixAdmin());
  }
};

setTimeout(() => {
  if ($("adminPanelBtn")) $("adminPanelBtn").addEventListener("click", openAdminPanel);
  if ($("closeAdminBtn")) $("closeAdminBtn").addEventListener("click", closeAdminPanel);
  if ($("saveAdminScheduleBtn")) $("saveAdminScheduleBtn").addEventListener("click", saveAdminSchedule);
  if ($("saveAdminNoticeBtn")) $("saveAdminNoticeBtn").addEventListener("click", saveAdminNotice);
}, 500);
// FIM_PAINEL_ADMIN_FENIX_JS




// FENIX_ADMIN_SOMENTE_NOME_CANAL
function fenixBuildKickUrlFromChannel(channel) {
  const value = String(channel || "").trim();

  if (!value) return "";

  if (value.startsWith("http://") || value.startsWith("https://")) {
    return value;
  }

  return "https://kick.com/" + value.replace(/^@/, "");
}

saveAdminSchedule = async function () {
  const screen1Name = $("adminScreen1Name").value.trim();
  const screen2Name = $("adminScreen2Name").value.trim();
  const screen3Name = $("adminScreen3Name").value.trim();

  const screen1Maintenance = $("adminScreen1Maintenance").checked || !screen1Name;
  const screen2Maintenance = $("adminScreen2Maintenance").checked || !screen2Name;
  const screen3Maintenance = $("adminScreen3Maintenance").checked || !screen3Name;

  const body = {
    adminUsername: "GokuuMods",
    slotDate: $("adminSlotDate").value,
    slotHour: $("adminSlotHour").value,

    screen1Name,
    screen1Url: screen1Maintenance ? "" : fenixBuildKickUrlFromChannel(screen1Name),
    screen1Maintenance,

    screen2Name,
    screen2Url: screen2Maintenance ? "" : fenixBuildKickUrlFromChannel(screen2Name),
    screen2Maintenance,

    screen3Name,
    screen3Url: screen3Maintenance ? "" : fenixBuildKickUrlFromChannel(screen3Name),
    screen3Maintenance,

    active: true
  };

  try {
    const res = await fetch(CONFIG.adminApi + "/api/fenix/admin/schedule", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "x-fenix-admin": "GokuuMods"
      },
      body: JSON.stringify(body)
    });

    const data = await res.json();

    if (!res.ok || !data.ok) {
      throw new Error(data.message || "Erro ao salvar grade.");
    }

    log("Grade Admin salva para " + body.slotDate + " " + body.slotHour + ".");
    await tryLoadAdminSlots();
    await loadAdminUsers();
  } catch (error) {
    log("Erro ao salvar grade: " + (error.message || String(error)));
  }
};



// FENIX_GRADE_RAPIDA_ADMIN_JS
function setBulkDefaultDate() {
  const now = new Date();
  const input = $("bulkStartDate");

  if (input && !input.value) {
    input.value = now.toISOString().slice(0, 10);
  }
}

function fillBulkExample() {
  const box = $("bulkScheduleText");

  if (!box) return;

  box.value =
    "08:00 gokuumods canal2 canal3\n" +
    "09:00 canal4 canal5 -\n" +
    "10:00 - canal6 canal7\n" +
    "11:00 canal8 - -\n" +
    "12:00 gokuumods canal2 canal3\n" +
    "13:00 canal4 canal5 canal6\n" +
    "14:00 canal7 - canal8\n" +
    "15:00 gokuumods canal2 -\n" +
    "16:00 canal3 canal4 canal5\n" +
    "17:00 canal6 canal7 canal8\n" +
    "18:00 gokuumods canal2 canal3\n" +
    "19:00 canal4 canal5 canal6\n" +
    "20:00 canal7 canal8 -\n" +
    "21:00 gokuumods canal2 canal3\n" +
    "22:00 canal4 - -\n" +
    "23:00 - - -";

  log("Exemplo de grade rápida preenchido.");
}

function parseBulkScheduleText() {
  const text = String($("bulkScheduleText")?.value || "");
  const lines = text.split(/\r?\n/);
  const rows = [];

  for (const rawLine of lines) {
    const line = rawLine.trim();

    if (!line || line.startsWith("#")) continue;

    const parts = line.split(/\s+/);
    const hourRaw = String(parts[0] || "").trim();

    if (!/^\d{1,2}:00$/.test(hourRaw)) {
      throw new Error("Horario invalido na linha: " + line);
    }

    const hour = hourRaw.padStart(5, "0");

    rows.push({
      slotHour: hour,
      screen1Name: parts[1] || "-",
      screen2Name: parts[2] || "-",
      screen3Name: parts[3] || "-"
    });
  }

  return rows;
}

async function saveBulkSchedule() {
  try {
    const startDate = $("bulkStartDate").value;
    const days = Number($("bulkDays").value || 1);
    const rows = parseBulkScheduleText();

    if (!startDate) {
      throw new Error("Escolha a data inicial.");
    }

    if (!rows.length) {
      throw new Error("Preencha pelo menos uma linha da grade.");
    }

    const res = await fetch(CONFIG.adminApi + "/api/fenix/admin/schedule/bulk", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "x-fenix-admin": "GokuuMods"
      },
      body: JSON.stringify({
        adminUsername: "GokuuMods",
        startDate,
        days,
        rows
      })
    });

    const data = await res.json();

    if (!res.ok || !data.ok) {
      throw new Error(data.message || "Erro ao salvar grade rápida.");
    }

    log("Grade rápida salva: " + data.saved + " horários em " + data.days + " dia(s).");
    await tryLoadAdminSlots();
    await loadAdminUsers();
  } catch (error) {
    log("Erro na grade rápida: " + (error.message || String(error)));
  }
}

setTimeout(() => {
  setBulkDefaultDate();

  if ($("fillBulkExampleBtn")) {
    $("fillBulkExampleBtn").addEventListener("click", fillBulkExample);
  }

  if ($("saveBulkScheduleBtn")) {
    $("saveBulkScheduleBtn").addEventListener("click", saveBulkSchedule);
  }
}, 700);
// FIM_FENIX_GRADE_RAPIDA_ADMIN_JS








// FENIX_GRADE_VISUAL_FACIL_JS
function fenixTodayLocalDate() {
  const now = new Date();
  const year = now.getFullYear();
  const month = String(now.getMonth() + 1).padStart(2, "0");
  const day = String(now.getDate()).padStart(2, "0");
  return year + "-" + month + "-" + day;
}

function fenixAddDaysLocal(dateText, amount) {
  const date = new Date(dateText + "T12:00:00");
  date.setDate(date.getDate() + amount);

  const year = date.getFullYear();
  const month = String(date.getMonth() + 1).padStart(2, "0");
  const day = String(date.getDate()).padStart(2, "0");

  return year + "-" + month + "-" + day;
}

function fenixChannelToUrl(channel) {
  const value = String(channel || "").trim();

  if (!value) return "";

  if (value.startsWith("http://") || value.startsWith("https://")) {
    return value;
  }

  return "https://kick.com/" + value.replace(/^@/, "");
}

function buildEasyGradePanel() {
  const section = document.querySelector(".admin-bulk-section");

  if (!section || section.dataset.easyBuilt === "1") return;

  section.dataset.easyBuilt = "1";

  const hours = Array.from({ length: 24 }, function (_, index) {
    return String(index).padStart(2, "0") + ":00";
  });

  let rowsHtml = "";

  hours.forEach(function (hour) {
    rowsHtml +=
      '<div class="easy-grade-row" data-hour="' + hour + '">' +
        '<div class="easy-grade-hour">' + hour + '</div>' +
        '<input data-hour="' + hour + '" data-screen="1" placeholder="canal ou vazio" />' +
        '<input data-hour="' + hour + '" data-screen="2" placeholder="canal ou vazio" />' +
        '<input data-hour="' + hour + '" data-screen="3" placeholder="canal ou vazio" />' +
      '</div>';
  });

  section.innerHTML =
    '<h3>Grade Fácil do Dia</h3>' +
    '<div class="easy-grade-wrap">' +
      '<div class="easy-grade-top">' +
        '<div class="admin-form-row">' +
          '<label>Data da grade</label>' +
          '<input id="easyGradeDate" type="date" />' +
        '</div>' +
        '<div class="admin-form-row">' +
          '<label>Repetir por</label>' +
          '<select id="easyGradeDays">' +
            '<option value="1">1 dia</option>' +
            '<option value="2">2 dias</option>' +
            '<option value="3">3 dias</option>' +
            '<option value="4">4 dias</option>' +
            '<option value="5">5 dias</option>' +
            '<option value="6">6 dias</option>' +
            '<option value="7">7 dias</option>' +
          '</select>' +
        '</div>' +
      '</div>' +
      '<div class="easy-grade-help">' +
        'Preencha só o <b>nome do canal</b>. Exemplo: <b>gokuumods</b>. Campo vazio vira <b>manutenção</b>.' +
      '</div>' +
      '<div class="easy-grade-table" id="easyGradeTable">' +
        '<div class="easy-grade-row head">' +
          '<div>Hora</div><div>Tela 1</div><div>Tela 2</div><div>Tela 3</div>' +
        '</div>' +
        rowsHtml +
      '</div>' +
      '<div class="easy-grade-actions">' +
        '<button id="easyFillSameBtn" type="button">Preencher Tela 1 com gokuumods</button>' +
        '<button id="easyClearBtn" type="button">Limpar grade</button>' +
        '<button id="easySaveDayBtn" class="primary" type="button">Salvar Grade</button>' +
      '</div>' +
    '</div>';

  const dateInput = document.getElementById("easyGradeDate");
  if (dateInput) dateInput.value = fenixTodayLocalDate();

  document.getElementById("easyFillSameBtn").addEventListener("click", fillEasyGridWithGokuuMods);
  document.getElementById("easyClearBtn").addEventListener("click", clearEasyGrid);
  document.getElementById("easySaveDayBtn").addEventListener("click", saveEasyGrid);
}

function fillEasyGridWithGokuuMods() {
  document.querySelectorAll('#easyGradeTable input[data-screen="1"]').forEach(function (input) {
    input.value = "gokuumods";
  });

  log("Tela 1 preenchida em todos os horários com gokuumods.");
}

function clearEasyGrid() {
  document.querySelectorAll("#easyGradeTable input").forEach(function (input) {
    input.value = "";
  });

  log("Grade fácil limpa.");
}

async function saveOneEasySlot(slotDate, slotHour, screen1Name, screen2Name, screen3Name) {
  const body = {
    adminUsername: "GokuuMods",
    slotDate: slotDate,
    slotHour: slotHour,

    screen1Name: screen1Name,
    screen1Url: fenixChannelToUrl(screen1Name),
    screen1Maintenance: !screen1Name,

    screen2Name: screen2Name,
    screen2Url: fenixChannelToUrl(screen2Name),
    screen2Maintenance: !screen2Name,

    screen3Name: screen3Name,
    screen3Url: fenixChannelToUrl(screen3Name),
    screen3Maintenance: !screen3Name,

    active: true
  };

  const res = await fetch(CONFIG.adminApi + "/api/fenix/admin/schedule", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "x-fenix-admin": "GokuuMods"
    },
    body: JSON.stringify(body)
  });

  const data = await res.json();

  if (!res.ok || !data.ok) {
    throw new Error(data.message || "Erro ao salvar " + slotDate + " " + slotHour);
  }

  return data;
}

async function saveEasyGrid() {
  try {
    const startDate = document.getElementById("easyGradeDate").value || fenixTodayLocalDate();
    const days = Math.max(1, Math.min(7, Number(document.getElementById("easyGradeDays").value || 1)));
    const rows = Array.from(document.querySelectorAll(".easy-grade-row[data-hour]"));

    let saved = 0;

    for (let dayIndex = 0; dayIndex < days; dayIndex++) {
      const slotDate = fenixAddDaysLocal(startDate, dayIndex);

      for (const row of rows) {
        const slotHour = row.dataset.hour;

        const screen1Name = String(row.querySelector('input[data-screen="1"]').value || "").trim();
        const screen2Name = String(row.querySelector('input[data-screen="2"]').value || "").trim();
        const screen3Name = String(row.querySelector('input[data-screen="3"]').value || "").trim();

        await saveOneEasySlot(slotDate, slotHour, screen1Name, screen2Name, screen3Name);
        saved++;
      }
    }

    log("Grade fácil salva: " + saved + " horários atualizados.");
    await tryLoadAdminSlots();
    await loadAdminUsers();
  } catch (error) {
    log("Erro ao salvar grade fácil: " + (error.message || String(error)));
  }
}

const oldOpenAdminPanelEasyGrade = openAdminPanel;
openAdminPanel = async function () {
  await oldOpenAdminPanelEasyGrade();
  buildEasyGradePanel();
};
// FIM_FENIX_GRADE_VISUAL_FACIL_JS
