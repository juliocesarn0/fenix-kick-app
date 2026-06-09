const CONFIG = {
  adminApi: "https://fenix-kick-app-production.up.railway.app",
  fallbackProfile: "GokuuMods",
  refreshSeconds: 60,
  cycleSeconds: 600,
  quality: "160p",
  weeklyGoal: 300,
  weeklyMinimum: 210
};

let fenixSession = null;
let kickLoggedIn = false;
let currentSlots = [];
let cycleLeft = CONFIG.cycleSeconds;
let cycleTimer = null;
let kickPopupAlreadyShown = false;

const $ = (id) => document.getElementById(id);

function normalizeUsername(name) {
  return String(name || "").trim();
}

function normalizeChannel(value) {
  return String(value || "").trim().replace(/^@/, "");
}

function buildKickUrl(channelOrUrl) {
  const value = String(channelOrUrl || "").trim();

  if (!value) return "";

  if (value.startsWith("http://") || value.startsWith("https://")) {
    return value;
  }

  return "https://kick.com/" + value.replace(/^@/, "");
}

function showLoginGate(show) {
  $("loginGate").classList.toggle("show", show);

  const appEl = document.querySelector(".app");

  if (appEl) {
    appEl.style.display = show ? "none" : "grid";
  }

  [1, 2, 3].forEach((number) => {
    const view = $("view" + number);

    if (view) {
      view.style.pointerEvents = show ? "none" : "auto";
      view.style.visibility = show ? "hidden" : "visible";
    }
  });

  if (show) {
    setTimeout(() => {
      if (window.fenixDesktop && typeof window.fenixDesktop.focusLogin === "function") {
        window.fenixDesktop.focusLogin();
      }

      const username = $("loginUsername");

      if (username) {
        username.focus();
        username.click();
      }
    }, 300);
  }
}

function setWarning(message) {
  $("warningBar").textContent = message;
}

function updateKickStatus(logged) {
  kickLoggedIn = Boolean(logged);

  $("kickDot").classList.toggle("ok", kickLoggedIn);
  $("kickDot").classList.toggle("bad", !kickLoggedIn);
  $("kickStatus").textContent = kickLoggedIn ? "KICK LOGADA" : "KICK NAO LOGADA";
  $("kickStatus").classList.toggle("ok", kickLoggedIn);
}

function showKickPopup() {
  if (kickPopupAlreadyShown) return;

  kickPopupAlreadyShown = true;
  $("kickPopup").classList.add("show");
}

function hideKickPopup() {
  $("kickPopup").classList.remove("show");
}

function updateUserUi(user) {
  if (!user) return;

  $("profileName").textContent = user.username || CONFIG.fallbackProfile;
  $("totalPoints").textContent = Number(user.points || 0);

  const weeklyPoints = Number(user.weeklyPoints || 0);
  const percent = Math.min(100, Math.floor((weeklyPoints / CONFIG.weeklyGoal) * 100));
  const missing = Math.max(0, CONFIG.weeklyMinimum - weeklyPoints);

  $("weeklyPoints").textContent = weeklyPoints;
  $("weeklyGoal").textContent = CONFIG.weeklyGoal;
  $("weeklyPercent").textContent = percent + "%";
  $("weeklyMissing").textContent = missing;
  $("weeklyBar").style.width = percent + "%";

  if (weeklyPoints >= CONFIG.weeklyMinimum) {
    $("weeklyStatus").textContent = "LIBERADO";
    $("weeklyText").textContent = "Voce bateu 70% e pode entrar na proxima grade.";
  } else {
    $("weeklyStatus").textContent = "NAO LIBERADO";
    $("weeklyText").textContent = "Continue farmando para liberar a proxima grade.";
  }
}

async function loginFenix() {
  const username = normalizeUsername($("loginUsername").value);
  const password = String($("loginPassword").value || "");

  $("loginError").textContent = "";

  if (!username || !password) {
    $("loginError").textContent = "Preencha usuario e senha.";
    return;
  }

  try {
    const res = await fetch(CONFIG.adminApi + "/api/fenix/auth/register-or-login", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username, password })
    });

    const data = await res.json();

    if (!res.ok || data.ok === false) {
      throw new Error(data.message || data.error || "Erro ao entrar.");
    }

    fenixSession = {
      sessionId: data.sessionId,
      user: data.user
    };

    localStorage.setItem("fenixSession", JSON.stringify(fenixSession));

    updateUserUi(data.user);
    showLoginGate(false);
    setWarning("LOGIN KICK OBRIGATORIO: Clique dentro da Tela 1, faca login na sua conta Kick e depois clique em Atualizar Telas.");

    await loadSchedule();
  } catch (error) {
    $("loginError").textContent = error.message || String(error);
  }
}

function restoreSession() {
  try {
    const raw = localStorage.getItem("fenixSession");
    if (!raw) return false;

    fenixSession = JSON.parse(raw);

    if (!fenixSession?.sessionId || !fenixSession?.user) {
      return false;
    }

    updateUserUi(fenixSession.user);
    showLoginGate(false);
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

  const url = buildKickUrl(slot.url || slot.channel || slot.screenName || "");

  label.textContent = slot.channel ? "kick.com/" + slot.channel : "Aguardando live";

  if (!slot.active || !url) {
    setMaintenance(number, true, "Aguardando canal agendado");
    status.textContent = "Manutenção";
    view.removeAttribute("src");
    return;
  }

  setMaintenance(number, false);

  const currentUrl = view.getAttribute("src") || "";
  const changedUrl = currentUrl !== url;

  if (changedUrl) {
    status.textContent = "Carregando";
    view.src = url;
  } else if (status.textContent === "Manutenção" || status.textContent === "Carregando") {
    status.textContent = "Online";
  }

  muteWebview(view);

  view.addEventListener("did-finish-load", () => {
    status.textContent = "Online";
    muteWebview(view);

    if (number === 1) {
      setTimeout(checkKickLoggedFromView1, 1200);
    }
  });

  view.addEventListener("dom-ready", () => {
    muteWebview(view);

    if (number === 1) {
      setTimeout(checkKickLoggedFromView1, 1200);
    }
  });
}

async function loadSchedule() {
  try {
    const res = await fetch(CONFIG.adminApi + "/api/fenix/app/current-schedule", {
      cache: "no-store"
    });

    const data = await res.json();

    if (!res.ok || data.ok === false) {
      throw new Error("Erro ao carregar grade.");
    }

    currentSlots = Array.isArray(data.slots) ? data.slots : [];

    currentSlots.forEach(setSlot);

    if (data.notice?.message) {
      $("noticeText").textContent = "Nenhum aviso geral ainda.";
      $("noticeCount").textContent = "0";
      setWarning(data.notice.message);
    } else {
      $("noticeText").textContent = "Nenhum aviso geral ainda.";
      $("noticeCount").textContent = "0";
    }
  } catch {
    currentSlots = [
      { id: 1, title: "Tela 1", channel: "", url: "", active: false },
      { id: 2, title: "Tela 2", channel: "", url: "", active: false },
      { id: 3, title: "Tela 3", channel: "", url: "", active: false }
    ];

    currentSlots.forEach(setSlot);
  }
}

async function refreshScreens() {
  await loadSchedule();

  [1, 2, 3].forEach((number) => {
    const view = $("view" + number);
    if (view && view.getAttribute("src")) {
      try {
        view.reload();
        muteWebview(view);
      } catch {}
    }
  });

  setWarning(kickLoggedIn ? "Telas atualizadas. Pontos liberados." : "Telas atualizadas. Se ja logou na Kick, aguarde carregar.");
}

function openExternalSlot(slotNumber) {
  const slot = currentSlots.find((item) => item.id === slotNumber);
  const url = buildKickUrl(slot?.url || slot?.channel);

  if (url) {
    window.open(url, "_blank");
  }
}

function muteWebview(view) {
  try {
    if (view && typeof view.setAudioMuted === "function") {
      view.setAudioMuted(true);
    }
  } catch {}
}

function muteAllWebviews() {
  [1, 2, 3].forEach((number) => muteWebview($("view" + number)));
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function clickWebview(view, x, y) {
  try {
    view.focus();
    view.sendInputEvent({ type: "mouseDown", x, y, button: "left", clickCount: 1 });
    view.sendInputEvent({ type: "mouseUp", x, y, button: "left", clickCount: 1 });
  } catch {}
}

async function setLowQualityOnView(view, number) {
  if (!view || !view.getAttribute("src")) return;

  const rect = view.getBoundingClientRect();
  const width = Math.max(1, Math.floor(rect.width));
  const height = Math.max(1, Math.floor(rect.height));

  setWarning("Modo Leve: Tela " + number + " iniciada.");

  clickWebview(view, Math.floor(width * 0.50), Math.floor(height * 0.34));
  await sleep(1300);

  clickWebview(view, Math.max(20, width - 36), 88);
  await sleep(1200);

  clickWebview(view, 32, Math.max(20, height - 24));
  await sleep(800);

  muteWebview(view);
  setWarning("Modo Leve: Tela " + number + " finalizada.");
}

async function applyModoLeve() {
  setWarning("Modo Leve iniciado. Nao mexa no mouse por alguns segundos.");

  for (const number of [1, 2, 3]) {
    await setLowQualityOnView($("view" + number), number);
    await sleep(6500);
  }

  setWarning("Modo Leve finalizado.");
}

async function checkKickLoggedFromView1() {
  const view = $("view1");

  if (!view || !view.getAttribute("src")) return;

  try {
    const logged = await view.executeJavaScript(`
      (() => {
        const text = document.body ? document.body.innerText.toLowerCase() : "";
        const hasLoginText = text.includes("log in") || text.includes("login") || text.includes("entrar");
        const hasProfile =
          document.querySelector('a[href*="/settings"]') ||
          document.querySelector('a[href*="/profile"]') ||
          document.querySelector('button[aria-label*="profile" i]') ||
          document.querySelector('button[aria-label*="perfil" i]') ||
          document.querySelector('img[src*="user"]') ||
          document.querySelector('img[alt*="avatar" i]');
        return Boolean(hasProfile || !hasLoginText);
      })();
    `, true);

    if (logged) {
      updateKickStatus(true);
      showKickPopup();
      setWarning("Kick logada detectada. Clique em Atualizar Telas para aplicar nas 3 telas.");
    }
  } catch {}
}

async function completeCycle() {
  if (!fenixSession?.sessionId || !kickLoggedIn) return;

  const cycleKey = `${fenixSession.sessionId}-${new Date().toISOString().slice(0, 16)}`;

  try {
    const res = await fetch(CONFIG.adminApi + "/api/fenix/app/complete-cycle", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        sessionId: fenixSession.sessionId,
        cycleKey,
        kickLoggedIn: true
      })
    });

    const data = await res.json();

    if (data.user) {
      fenixSession.user = data.user;
      localStorage.setItem("fenixSession", JSON.stringify(fenixSession));
      updateUserUi(data.user);
    }
  } catch {}
}

function updateCycleTimer() {
  const minutes = String(Math.floor(cycleLeft / 60)).padStart(2, "0");
  const seconds = String(cycleLeft % 60).padStart(2, "0");

  $("cycleTimer").textContent = `${minutes}:${seconds}`;

  cycleLeft -= 1;

  if (cycleLeft < 0) {
    cycleLeft = CONFIG.cycleSeconds;
    completeCycle();
    refreshScreens();
  }
}

function clearLogin() {
  const ok = confirm("Resetar login da Fenix e Kick neste app?");
  if (!ok) return;

  localStorage.clear();
  sessionStorage.clear();

  fenixSession = null;
  kickLoggedIn = false;
  kickPopupAlreadyShown = false;

  if (window.fenixDesktop && typeof window.fenixDesktop.resetLogin === "function") {
    window.fenixDesktop.resetLogin();
    return;
  }

  window.location.reload();
}

function createAdminPanel() {
  if (!fenixSession?.user?.isAdmin && String(fenixSession?.user?.username || "").toLowerCase() !== "gokuumods") {
    alert("Painel Admin liberado somente para GokuuMods.");
    return;
  }

  let modal = $("adminModal");

  if (modal) {
    modal.classList.add("show");
    return;
  }

  modal = document.createElement("div");
  modal.id = "adminModal";
  modal.className = "fenix-admin-modal";

  const hours = Array.from({ length: 24 }, (_, h) => String(h).padStart(2, "0") + ":00");

  modal.innerHTML = `
    <div class="fenix-admin-box">
      <div class="fenix-admin-head">
        <div>
          <strong>Central Admin Fenix</strong>
          <span>Grade das lives por horario</span>
        </div>
        <div>
          <button id="adminUseNow">Usar hora atual</button>
          <button id="adminClose">Fechar</button>
        </div>
      </div>

      <div class="fenix-admin-now">
        <label>Data<input id="adminDate" type="date" /></label>
        <label>Hora<input id="adminHour" type="time" step="3600" /></label>
        <label>Senha Admin<input id="adminSecretInput" type="password" placeholder="senha da Railway" /></label>
        <label>Tela 1<input id="adminNow1" placeholder="gokuumods" /></label>
        <label>Tela 2<input id="adminNow2" placeholder="vazio = manutencao" /></label>
        <label>Tela 3<input id="adminNow3" placeholder="vazio = manutencao" /></label>
        <button id="adminSaveNow">Salvar horario</button>
      </div>

      <div class="fenix-admin-table">
        <div class="fenix-admin-row-head">
          <div>Hora</div><div>Tela 1</div><div>Tela 2</div><div>Tela 3</div><div>Ação</div>
        </div>
        ${hours.map((hour) => `
          <div class="fenix-admin-row" data-hour="${hour}">
            <button class="fenix-admin-hour" data-select-hour="${hour}">${hour}</button>
            <input data-screen="1" placeholder="canal tela 1" />
            <input data-screen="2" placeholder="canal tela 2" />
            <input data-screen="3" placeholder="canal tela 3" />
            <button data-save-hour="${hour}">Salvar</button>
          </div>
        `).join("")}
      </div>

      <div class="fenix-admin-bottom">
        <button id="adminSaveDay">Salvar dia inteiro</button>
        <button id="adminRefresh">Atualizar Telas</button>
        <div id="adminMsg">Painel pronto.</div>
      </div>
    </div>
  `;

  document.body.appendChild(modal);

  const today = new Date();
  const ymd = today.toISOString().slice(0, 10);
  const currentHour = String(today.getHours()).padStart(2, "0") + ":00";

  $("adminDate").value = ymd;
  $("adminHour").value = currentHour;

  function getRow(hour) {
    return modal.querySelector(`.fenix-admin-row[data-hour="${hour}"]`);
  }

  function selectHour(hour) {
    $("adminHour").value = hour;

    modal.querySelectorAll(".fenix-admin-row").forEach((row) => {
      row.classList.toggle("active", row.dataset.hour === hour);
    });

    const row = getRow(hour);

    if (!row) return;

    $("adminNow1").value = row.querySelector('input[data-screen="1"]').value;
    $("adminNow2").value = row.querySelector('input[data-screen="2"]').value;
    $("adminNow3").value = row.querySelector('input[data-screen="3"]').value;

    row.scrollIntoView({ block: "center" });
  }

  function syncNowToRow() {
    const hour = $("adminHour").value || currentHour;
    const row = getRow(hour);

    if (!row) return;

    row.querySelector('input[data-screen="1"]').value = $("adminNow1").value.trim();
    row.querySelector('input[data-screen="2"]').value = $("adminNow2").value.trim();
    row.querySelector('input[data-screen="3"]').value = $("adminNow3").value.trim();
  }

  async function saveHour(hour) {
    syncNowToRow();

    const row = getRow(hour);
    const slotDate = $("adminDate").value || ymd;

    const s1 = normalizeChannel(row.querySelector('input[data-screen="1"]').value);
    const s2 = normalizeChannel(row.querySelector('input[data-screen="2"]').value);
    const s3 = normalizeChannel(row.querySelector('input[data-screen="3"]').value);

    fenixAdminSecret = document.getElementById("adminSecretInput")?.value?.trim() || "";

    if (!fenixAdminSecret) {
      throw new Error("Digite a senha admin antes de salvar.");
    }

    const payload = {
      adminUsername: "GokuuMods",
      adminSecret: fenixAdminSecret,
      slotDate,
      slotHour: hour,
      screen1Name: s1,
      screen1Url: buildKickUrl(s1),
      screen1Maintenance: !s1,
      screen2Name: s2,
      screen2Url: buildKickUrl(s2),
      screen2Maintenance: !s2,
      screen3Name: s3,
      screen3Url: buildKickUrl(s3),
      screen3Maintenance: !s3
    };

    $("adminMsg").textContent = "Salvando " + hour + "...";

    const res = await fetch(CONFIG.adminApi + "/api/fenix/admin/schedule", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "x-fenix-admin": "GokuuMods",
        "x-fenix-admin-secret": fenixAdminSecret
      },
      body: JSON.stringify(payload)
    });

    const data = await res.json().catch(() => ({}));

    if (!res.ok || data.ok === false) {
      throw new Error(data.message || data.error || "Erro ao salvar " + hour);
    }

    $("adminMsg").textContent = "Horario " + hour + " salvo.";
  }

  $("adminClose").addEventListener("click", () => modal.classList.remove("show"));
  $("adminUseNow").addEventListener("click", () => selectHour(currentHour));
  $("adminSaveNow").addEventListener("click", async () => {
    try {
      await saveHour($("adminHour").value || currentHour);
    } catch (error) {
      $("adminMsg").textContent = error.message || String(error);
    }
  });

  $("adminRefresh").addEventListener("click", refreshScreens);

  $("adminSaveDay").addEventListener("click", async () => {
    const rows = Array.from(modal.querySelectorAll(".fenix-admin-row"));
    const filled = rows.filter((row) => {
      return Array.from(row.querySelectorAll("input")).some((input) => input.value.trim());
    });

    let ok = 0;
    let fail = 0;

    for (const row of filled) {
      try {
        await saveHour(row.dataset.hour);
        ok++;
      } catch {
        fail++;
      }
    }

    $("adminMsg").textContent = fail ? `Salvou ${ok}, falhou ${fail}.` : `Dia salvo: ${ok} horarios.`;
  });

  modal.querySelectorAll("[data-select-hour]").forEach((btn) => {
    btn.addEventListener("click", () => selectHour(btn.dataset.selectHour));
  });

  modal.querySelectorAll("[data-save-hour]").forEach((btn) => {
    btn.addEventListener("click", async () => {
      try {
        await saveHour(btn.dataset.saveHour);
      } catch (error) {
        $("adminMsg").textContent = error.message || String(error);
      }
    });
  });

  selectHour(currentHour);
  modal.classList.add("show");
}

function setupEvents() {
  $("loginBtn").addEventListener("click", loginFenix);
  $("refreshScreensBtn").addEventListener("click", refreshScreens);
  $("popupRefreshBtn").addEventListener("click", async () => {
    hideKickPopup();
    await refreshScreens();
  });
  $("qualityBtn").addEventListener("click", applyModoLeve);
  $("exitBtn").addEventListener("click", () => window.close());
  $("resetLoginBtn").addEventListener("click", clearLogin);
  $("adminBtn").addEventListener("click", createAdminPanel);

  document.querySelectorAll("[data-refresh]").forEach((btn) => {
    btn.addEventListener("click", () => {
      const number = Number(btn.dataset.refresh);
      const view = $("view" + number);
      if (view?.src) {
        view.reload();
        muteWebview(view);
      }
    });
  });

  document.querySelectorAll("[data-open]").forEach((btn) => {
    btn.addEventListener("click", () => openExternalSlot(Number(btn.dataset.open)));
  });
}

document.addEventListener("DOMContentLoaded", async () => {
  setupEvents();
  updateKickStatus(false);

  const restored = restoreSession();

  if (!restored) {
    showLoginGate(true);
  } else {
    await loadSchedule();
  }

  updateCycleTimer();
  cycleTimer = setInterval(updateCycleTimer, 1000);

  setInterval(loadSchedule, CONFIG.refreshSeconds * 1000);
  setInterval(muteAllWebviews, 5000);
});












