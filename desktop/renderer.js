const CONFIG = {
  // FENIX_LOCAL_API_OVERRIDE_105
  adminApi: localStorage.getItem("fenixApiOverride") || "https://fenix-kick-app-production.up.railway.app",
  fallbackProfile: "GokuuMods",
  refreshSeconds: 60,
  cycleSeconds: 600,
  quality: "160p",
  weeklyGoal: 2592,
  weeklyMinimum: 1815
};

let fenixSession = null;
let kickLoggedIn = false;
let kickTabsLoggedIn = false;
let currentSlots = [];
let cycleLeft = CONFIG.cycleSeconds;
let cycleTimer = null;
let kickPopupAlreadyShown = false;

const $ = (id) => document.getElementById(id);


function getFenixDeviceId() {
  let id = localStorage.getItem("fenixDeviceId");

  if (!id) {
    id = "fenix-device-" + Math.random().toString(16).slice(2) + "-" + Date.now();
    localStorage.setItem("fenixDeviceId", id);
  }

  return id;
}

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

function sanitizeFenixText(message) {
  return String(message || "")
    .replaceAll("COMEÃ‡AR", "COMECAR")
    .replaceAll("COMEÃ‡", "COMEC")
    .replaceAll("Ã‡", "C")
    .replaceAll("Ã§", "c")
    .replaceAll("Ã¡", "a")
    .replaceAll("Ã©", "e")
    .replaceAll("Ã­", "i")
    .replaceAll("Ã³", "o")
    .replaceAll("Ãº", "u")
    .replaceAll("Ã£", "a")
    .replaceAll("Ãµ", "o")
    .replaceAll("Ã", "A");
}

function setWarning(message) {
  $("warningBar").textContent = sanitizeFenixText(message);
}


function updateKickTabsStatus(logged) {
  kickTabsLoggedIn = Boolean(logged);

  let dot = document.getElementById("kickTabsDot");
  let label = document.getElementById("kickTabsStatus");

  if (!dot || !label) {
    const leftTop = document.querySelector(".left-top");

    if (!leftTop) return;

    dot = document.createElement("div");
    dot.id = "kickTabsDot";
    dot.className = "dot bad";

    label = document.createElement("span");
    label.id = "kickTabsStatus";
    label.textContent = "ABAS NAO LOGADAS";
    label.style.color = "#ff4a4a";

    leftTop.appendChild(dot);
    leftTop.appendChild(label);
  }

  dot.classList.toggle("ok", kickTabsLoggedIn);
  dot.classList.toggle("bad", !kickTabsLoggedIn);

  label.textContent = kickTabsLoggedIn ? "ABAS LOGADAS" : "ABAS NAO LOGADAS";
  label.style.color = kickTabsLoggedIn ? "#38ff74" : "#ff4a4a";
}

async function checkOneKickTabLogged(view) {
  if (!view || !view.getAttribute("src")) return false;

  try {
    return await view.executeJavaScript(`
      (async () => {
        async function apiUserLogged(url) {
          try {
            const response = await fetch(url, {
              credentials: "include",
              cache: "no-store"
            });

            if (!response.ok) return false;

            const data = await response.json().catch(() => null);
            if (!data || typeof data !== "object") return false;

            const user = data.user || data.data || data;

            return Boolean(
              user &&
              (
                user.id ||
                user.username ||
                user.slug ||
                user.email
              )
            );
          } catch {
            return false;
          }
        }

        const apiV2 = await apiUserLogged("/api/v2/user");
        if (apiV2) return true;

        const apiV1 = await apiUserLogged("/api/v1/user");
        if (apiV1) return true;

        const storageKeys = [];
        const storageValues = [];

        try {
          for (let i = 0; i < localStorage.length; i++) {
            const key = String(localStorage.key(i) || "").toLowerCase();
            const value = String(localStorage.getItem(localStorage.key(i)) || "").toLowerCase();

            storageKeys.push(key);
            storageValues.push(value);
          }
        } catch {}

        try {
          for (let i = 0; i < sessionStorage.length; i++) {
            const key = String(sessionStorage.key(i) || "").toLowerCase();
            const value = String(sessionStorage.getItem(sessionStorage.key(i)) || "").toLowerCase();

            storageKeys.push(key);
            storageValues.push(value);
          }
        } catch {}

        const hasAuthStorage = storageKeys.concat(storageValues).some((item) => {
          return (
            item.includes("access_token") ||
            item.includes("auth_token") ||
            item.includes("bearer") ||
            item.includes("kick_session") ||
            item.includes("user_session")
          );
        });

        if (hasAuthStorage) return true;

        const bodyText = document.body ? document.body.innerText.toLowerCase() : "";

        const hasLoginText =
          bodyText.includes("log in") ||
          bodyText.includes("login") ||
          bodyText.includes("sign up") ||
          bodyText.includes("entrar") ||
          bodyText.includes("criar conta");

        if (hasLoginText) return false;

        const candidates = Array.from(document.querySelectorAll("img, button, a, div"));

        const hasRealTopAvatar = candidates.some((el) => {
          const rect = el.getBoundingClientRect();
          const html = String(el.outerHTML || "").toLowerCase();
          const tag = String(el.tagName || "").toLowerCase();
          const src = String(el.getAttribute("src") || "").toLowerCase();
          const alt = String(el.getAttribute("alt") || "").toLowerCase();
          const style = window.getComputedStyle(el);
          const bg = String(style.backgroundImage || "").toLowerCase();

          const inTopRight =
            rect &&
            rect.width >= 20 &&
            rect.height >= 20 &&
            rect.width <= 130 &&
            rect.height <= 130 &&
            rect.top >= 5 &&
            rect.top <= 190 &&
            rect.right >= (window.innerWidth - 210);

          if (!inTopRight) return false;

          const hasImage = tag === "img" || html.includes("<img") || bg.includes("url(");
          const isKickLogo = src.includes("kick-logo") || alt.includes("kick") || html.includes("kick-logo");
          const isSvgOnly = html.includes("<svg") && !html.includes("<img") && !bg.includes("url(");

          return hasImage && !isKickLogo && !isSvgOnly;
        });

        return Boolean(hasRealTopAvatar);
      })();
    `, true);
  } catch {
    return false;
  }
}

async function checkKickTabsLoggedIn() {
  const view1 = $("view1");
  const logged = await checkOneKickTabLogged(view1);

  updateKickTabsStatus(logged);

  if (logged) {
    setWarning("Kick conectada ao Fenix e login detectado dentro das abas.");
  } else {
    setWarning("LOGIN KICK OBRIGATORIO: entre na Kick dentro da Tela 1 para liberar os pontos.");
  }

  return logged;
}
function updateKickStatus(logged) {
  kickLoggedIn = Boolean(logged);

  $("kickDot").classList.toggle("ok", kickLoggedIn);
  $("kickDot").classList.toggle("bad", !kickLoggedIn);
  $("kickStatus").textContent = kickLoggedIn ? "KICK VINCULADA" : "KICK NAO VINCULADA";
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


function updateAdminButtonVisibility(user) {
  const adminBtn = $("adminBtn");

  if (!adminBtn) return;

  const username = String(user?.username || "").toLowerCase();
  const isAdmin = Boolean(user?.isAdmin) || username === "gokuumods";

  adminBtn.style.display = isAdmin ? "block" : "none";
}
function updateUserUi(user) {
  if (!user) return;

  updateAdminButtonVisibility(user);

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
    $("weeklyText").textContent = "Voce bateu 70% da semana e pode entrar na proxima grade.";
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
      body: JSON.stringify({ username, password, deviceId: getFenixDeviceId() })
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
    const fallbackUrl = "https://kick.com/";

    label.textContent = "kick.com";
    setMaintenance(number, false);
    status.textContent = "Login Kick";

    const currentUrl = view.getAttribute("src") || "";

    if (currentUrl !== fallbackUrl) {
      view.src = fallbackUrl;
    }

    muteWebview(view);

    if (number === 1) {
      setTimeout(checkKickLoggedFromView1, 1200);
    }

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

  if (!view || !view.getAttribute("src")) {
    kickPopupAlreadyShown = false;
    hideKickPopup();
    updateKickStatus(Boolean(fenixSession?.user?.kickConnected || fenixSession?.user?.kickLoggedIn));
    return;
  }

  try {
    const logged = await view.executeJavaScript(`
      (() => {
        const imgs = Array.from(document.querySelectorAll("img"));

        const hasTopRightAvatar = imgs.some((img) => {
          const rect = img.getBoundingClientRect();
          const src = String(img.src || "").toLowerCase();
          const alt = String(img.alt || "").toLowerCase();

          const visible =
            rect.width >= 24 &&
            rect.height >= 24 &&
            rect.width <= 90 &&
            rect.height <= 90;

          const topRight =
            rect.top >= 20 &&
            rect.top <= 120 &&
            rect.right >= (window.innerWidth - 130);

          const notKickLogo =
            !src.includes("kick") &&
            !alt.includes("kick") &&
            !src.includes("logo");

          return visible && topRight && notKickLogo;
        });

        return Boolean(hasTopRightAvatar);
      })();
    `, true);

    if (logged) {
      updateKickStatus(true);
      showKickPopup();
      setWarning("Kick vinculada detectada. Clique em Atualizar Telas para aplicar nas 3 telas.");
    } else {
      kickPopupAlreadyShown = false;
      hideKickPopup();
      updateKickStatus(Boolean(fenixSession?.user?.kickConnected || fenixSession?.user?.kickLoggedIn));
      setWarning("LOGIN KICK OBRIGATORIO: entre na Kick dentro da Tela 1 e depois clique em Atualizar Telas.");
    }
  } catch {
    kickPopupAlreadyShown = false;
    hideKickPopup();
    updateKickStatus(Boolean(fenixSession?.user?.kickConnected || fenixSession?.user?.kickLoggedIn));
    setWarning("LOGIN KICK OBRIGATORIO: entre na Kick dentro da Tela 1 e depois clique em Atualizar Telas.");
  }
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
        kickLoggedIn: kickTabsLoggedIn,
        tabsKickLoggedIn: kickTabsLoggedIn
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

async function clearLogin() {
  const ok = confirm("Resetar acesso completo? Isso vai limpar Fenix, Kick vinculada e login da Kick nas abas.");
  if (!ok) return;

  const deviceId = typeof getFenixDeviceId === "function"
    ? getFenixDeviceId()
    : localStorage.getItem("fenixDeviceId");

  const sessionId = fenixSession?.sessionId || "";

  try {
    if (sessionId) {
      await fetch(CONFIG.adminApi + "/api/fenix/auth/reset-access", {
        method: "POST",
        headers: {
          "Content-Type": "application/json"
        },
        body: JSON.stringify({ sessionId })
      });
    }
  } catch (error) {
    console.error("Erro ao resetar acesso no backend:", error);
  }

  try {
    if (window.fenixDesktop && typeof window.fenixDesktop.clearAllAccess === "function") {
      await window.fenixDesktop.clearAllAccess();
    }
  } catch (error) {
    console.error("Erro ao limpar sessoes Electron:", error);
  }

  try {
    for (const number of [1, 2, 3]) {
      const view = $("view" + number);

      if (view) {
        try {
          await view.executeJavaScript("localStorage.clear(); sessionStorage.clear();", true);
        } catch {}

        view.removeAttribute("src");
        view.src = "about:blank";
      }
    }
  } catch {}

  fenixSession = null;
  kickLoggedIn = false;
  kickTabsLoggedIn = false;

  localStorage.clear();
  sessionStorage.clear();

  if (deviceId) {
    localStorage.setItem("fenixDeviceId", deviceId);
  }

  updateKickStatus(false);
  updateKickTabsStatus(false);

  location.reload();
}


function renderAdminUsers(users) {
  const box = $("adminUsersList");

  if (!box) return;

  if (!Array.isArray(users) || users.length === 0) {
    box.innerHTML = '<div class="admin-user-empty">Nenhum usuario cadastrado ainda.</div>';
    return;
  }

  box.innerHTML = users.map((user) => {
    const username = user.username || user.userName || "Sem nome";
    const points = Number(user.points || 0);
    const weeklyPoints = Number(user.weeklyPoints || 0);
    const totalMinutes = Number(user.totalMinutes || 0);
    const weeklyMinutes = Number(user.weeklyMinutes || 0);
    const kickLogged = user.kickLoggedIn ? "Kick vinculada" : "Kick nao vinculada";
    const role = user.role || (user.isAdmin ? "ADMIN" : "USER");

    return `
      <div class="admin-user-row">
        <div>
          <strong>${username}</strong>
          <span>${role} • ${kickLogged}</span>
        </div>
        <div><small>Pontos</small><b>${points}</b></div>
        <div><small>Semana</small><b>${weeklyPoints}</b></div>
        <div><small>Min total</small><b>${totalMinutes}</b></div>
        <div><small>Min semana</small><b>${weeklyMinutes}</b></div>
      </div>
    `;
  }).join("");
}



function getAdminSecretValue() {
  const direct =
    $("adminSecret") ||
    $("adminPassword") ||
    $("adminPass") ||
    $("adminSecretInput") ||
    $("fenixAdminSecret") ||
    document.querySelector('input[type="password"]');

  if (direct && String(direct.value || "").trim()) {
    return String(direct.value || "").trim();
  }

  const labels = Array.from(document.querySelectorAll("label, div, span, strong, p"));
  const senhaLabel = labels.find((el) => {
    const text = String(el.innerText || el.textContent || "").toLowerCase();
    return text.includes("senha admin");
  });

  if (senhaLabel) {
    const parent = senhaLabel.parentElement;
    const input =
      parent?.querySelector("input") ||
      senhaLabel.nextElementSibling?.querySelector?.("input") ||
      senhaLabel.nextElementSibling;

    if (input && String(input.value || "").trim()) {
      return String(input.value || "").trim();
    }
  }

  const inputs = Array.from(document.querySelectorAll("input"));
  const possible = inputs.find((input) => {
    const type = String(input.type || "").toLowerCase();
    const placeholder = String(input.placeholder || "").toLowerCase();
    const id = String(input.id || "").toLowerCase();
    const name = String(input.name || "").toLowerCase();
    const value = String(input.value || "").trim();

    if (!value) return false;

    return (
      type === "password" ||
      placeholder.includes("senha") ||
      id.includes("secret") ||
      id.includes("senha") ||
      name.includes("secret") ||
      name.includes("senha")
    );
  });

  return possible ? String(possible.value || "").trim() : "";
}


async function loadAdminUsers() {
  const adminUsersList = $("adminUsersList");
  if (!adminUsersList) return;

  adminUsersList.innerHTML = '<div class="admin-empty">Carregando usuarios...</div>';

  try {
    const adminApiUrl = typeof API_URL !== "undefined" ? API_URL : "https://fenix-kick-app-production.up.railway.app";

    const response = await fetch(adminApiUrl + "/api/fenix/admin/online-users", {
      method: "GET",
      headers: {
        "x-fenix-admin": "GokuuMods"
      }
    });

    const data = await response.json();

    if (!response.ok || !data.ok) {
      adminUsersList.innerHTML = '<div class="admin-empty">' + (data.message || "Erro ao carregar usuarios.") + '</div>';
      return;
    }

    const users = Array.isArray(data.users) ? data.users : [];

    if (!users.length) {
      adminUsersList.innerHTML = '<div class="admin-empty">Nenhum usuario encontrado ainda.</div>';
      return;
    }

    const now = Date.now();

    const normalized = users.map((user) => {
      const points = Number(user.points || user.totalPoints || 0);
      const weeklyPoints = Number(user.weeklyPoints || user.weekPoints || user.pointsWeek || 0);
      const weeklyMinutes = Number(user.weeklyMinutes || user.minutesWeek || 0);
      const totalMinutes = Number(user.totalMinutes || user.minutes || 0);

      const lastCycleRaw =
        user.lastCycleAt ||
        user.lastFarmAt ||
        user.lastSeenAt ||
        user.updatedAt ||
        user.createdAt ||
        null;

      const lastCycleTime = lastCycleRaw ? new Date(lastCycleRaw).getTime() : 0;
      const diffMinutes = lastCycleTime ? Math.floor((now - lastCycleTime) / 60000) : 999999;

      const farmActive =
        Boolean(user.farmActive) ||
        Boolean(user.online) ||
        diffMinutes <= 15;

      return {
        username: user.username || user.userName || user.name || "Usuario",
        kickName: user.kickUsername || user.kickName || user.kick || "-",
        points,
        weeklyPoints,
        weeklyMinutes,
        totalMinutes,
        farmActive,
        diffMinutes,
        lastCycleRaw
      };
    });

    const activeUsers = normalized
      .filter((user) => user.farmActive)
      .sort((a, b) => b.weeklyPoints - a.weeklyPoints || b.points - a.points);

    const ranking = normalized
      .slice()
      .sort((a, b) => b.weeklyPoints - a.weeklyPoints || b.points - a.points);

    const renderLastCycle = (user) => {
      if (!user.lastCycleRaw) return "-";
      if (user.diffMinutes <= 0) return "agora";
      if (user.diffMinutes === 1) return "1 min atras";
      if (user.diffMinutes < 60) return user.diffMinutes + " min atras";
      return new Date(user.lastCycleRaw).toLocaleString("pt-BR");
    };

    const activeRows = activeUsers.length
      ? activeUsers.map((user, index) => {
          return [
            "<tr>",
            "<td>" + (index + 1) + "</td>",
            "<td><b>" + user.username + "</b></td>",
            "<td>" + user.kickName + "</td>",
            '<td><span class="admin-pill green">Farm ativo</span></td>',
            "<td>" + user.weeklyPoints + "</td>",
            "<td>" + user.points + "</td>",
            "<td>" + user.weeklyMinutes + " min</td>",
            "<td>" + renderLastCycle(user) + "</td>",
            "</tr>"
          ].join("");
        }).join("")
      : '<tr><td colspan="8" class="admin-empty-cell">Ninguem farmando agora.</td></tr>';

    const rankingRows = ranking.map((user, index) => {
      const approved = user.weeklyPoints >= 1815;
      const percent = Math.min(100, Math.floor((user.weeklyPoints / 2592) * 100));

      return [
        "<tr>",
        "<td>" + (index + 1) + "</td>",
        "<td><b>" + user.username + "</b></td>",
        "<td>" + user.kickName + "</td>",
        "<td>" + user.weeklyPoints + " pontos</td>",
        "<td>" + user.points + " pontos</td>",
        "<td>" + percent + "%</td>",
        '<td><span class="admin-pill ' + (approved ? "green" : "red") + '">' + (approved ? "Aprovado 70%" : "Pendente") + "</span></td>",
        "</tr>"
      ].join("");
    }).join("");

    adminUsersList.innerHTML = [
      '<div class="admin-users-grid">',
      '<div class="admin-table-card">',
      '<div class="admin-table-title"><span>Farm ativo agora</span><small>' + activeUsers.length + " online/farmando</small></div>",
      '<table class="admin-users-table">',
      '<thead><tr><th>#</th><th>Usuario</th><th>Kick</th><th>Status</th><th>Semana</th><th>Total</th><th>Min semana</th><th>Ultimo ciclo</th></tr></thead>',
      "<tbody>" + activeRows + "</tbody>",
      "</table>",
      "</div>",
      '<div class="admin-table-card">',
      '<div class="admin-table-title"><span>Ranking de pontos da semana</span><small>Meta 2592 pontos - minimo 70% = 1815</small></div>',
      '<table class="admin-users-table">',
      '<thead><tr><th>#</th><th>Usuario</th><th>Kick</th><th>Semana</th><th>Total</th><th>% Meta</th><th>Status</th></tr></thead>',
      "<tbody>" + rankingRows + "</tbody>",
      "</table>",
      "</div>",
      "</div>"
    ].join("");

    if (typeof setAdminMessage === "function") {
      setAdminMessage("Usuarios carregados.");
    }
  } catch (error) {
    console.error("Erro ao carregar usuarios admin:", error);
    adminUsersList.innerHTML = '<div class="admin-empty">Erro ao carregar usuarios: ' + (error.message || error) + '</div>';
  }
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

      <div class="fenix-admin-users">
        <div class="fenix-admin-users-head">
          <strong>Usuarios / Pontos</strong>
          <button id="adminLoadUsers">Atualizar usuarios</button>
        </div>
        <div id="adminUsersList" class="admin-users-list">
          <div class="admin-user-empty">Clique em Atualizar usuarios para carregar a tabela.</div>
        </div>
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
      throw new Error("Salvando horario...");
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

  $("adminLoadUsers").addEventListener("click", async () => {
    try {
      await loadAdminUsers();
    } catch (error) {
      $("adminMsg").textContent = error.message || String(error);
    }
  });

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



function clearInvalidFenixSession(message = "Sessao Fenix expirada. Entre novamente.") {
  localStorage.removeItem("fenixSession");
  sessionStorage.clear();

  fenixSession = null;
  kickLoggedIn = false;
  kickPopupAlreadyShown = false;

  hideKickPopup();
  updateKickStatus(false);
  showKickConnectGate(false);
  showLoginGate(true);

  const loginError = $("loginError");
  if (loginError) {
    loginError.textContent = message;
  }

  setTimeout(() => {
    const input = $("loginUsername");
    if (input) {
      input.focus();
      input.click();
    }
  }, 250);
}

async function refreshFenixMe() {
  if (!fenixSession?.sessionId) return;

  try {
    const res = await fetch(CONFIG.adminApi + "/api/fenix/app/me?sessionId=" + encodeURIComponent(fenixSession.sessionId), {
      cache: "no-store"
    });

    const data = await res.json().catch(() => ({}));

    if (res.status === 401 || res.status === 404 || data.message === "Sessao invalida.") {
      clearInvalidFenixSession("Sessao Fenix expirada. Entre novamente.");
      return;
    }

    if (res.ok && data.ok && data.user) {
      fenixSession.user = data.user;
      localStorage.setItem("fenixSession", JSON.stringify(fenixSession));
      updateUserUi(data.user);
      updateKickStatus(Boolean(data.user.kickConnected || data.user.kickLoggedIn));

      if (data.user.kickConnected) {
        setWarning("Kick conectada ao Fenix: " + (data.user.kickUsername || ""));
      }
    }
  } catch {}
}

async function connectKickOAuth() {
  if (!fenixSession?.sessionId) {
    clearInvalidFenixSession("Entre na conta Fenix primeiro.");
    return;
  }

  try {
    const res = await fetch(CONFIG.adminApi + "/api/fenix/kick/connect-url?sessionId=" + encodeURIComponent(fenixSession.sessionId), {
      cache: "no-store"
    });

    const data = await res.json().catch(() => ({}));

    if (res.status === 401 || res.status === 404 || data.message === "Sessao Fenix invalida.") {
      clearInvalidFenixSession("Sessao Fenix expirada. Entre novamente.");
      return;
    }

    if (!res.ok || !data.ok || !data.url) {
      throw new Error(data.message || "Nao foi possivel iniciar login Kick.");
    }

    if (window.fenixDesktop && typeof window.fenixDesktop.openExternal === "function") {
      await window.fenixDesktop.openExternal(data.url);
    } else {
      window.open(data.url, "_blank");
    }

    setWarning("Login Kick aberto. Depois de autorizar, volte ao Fenix Lurk e clique em Atualizar Telas.");

    setTimeout(refreshFenixMe, 4000);
    setTimeout(refreshFenixMe, 9000);
    setTimeout(refreshFenixMe, 15000);
  } catch (error) {
    alert(error.message || String(error));
  }
}

function setupEvents() {
  $("loginBtn").addEventListener("click", loginFenix);
  const connectKickBtn = $("connectKickBtn");
  if (connectKickBtn) {
    connectKickBtn.addEventListener("click", connectKickOAuth);
  }
  $("refreshScreensBtn").addEventListener("click", async () => {
    await refreshFenixMe();
    await refreshScreens();
    await checkKickTabsLoggedIn();
  });
  $("popupRefreshBtn").addEventListener("click", async () => {
    hideKickPopup();
    await refreshScreens();
    await checkKickTabsLoggedIn();
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
  updateKickTabsStatus(false);
  updateAdminButtonVisibility(null);
  updateKickStatus(Boolean(fenixSession?.user?.kickConnected || fenixSession?.user?.kickLoggedIn));

  const restored = restoreSession();

  if (!restored) {
    showLoginGate(true);
  } else {
    await loadSchedule();
  }

  updateCycleTimer();
  cycleTimer = setInterval(updateCycleTimer, 1000);

  setInterval(loadSchedule, CONFIG.cycleSeconds * 1000);

  // FENIX_BACKEND_KICK_STATUS_TIMER
  setInterval(refreshFenixMe, 15000);
  setInterval(muteAllWebviews, 5000);

  // FENIX_RECHECK_TABS_LOGIN_TIMER
  setInterval(checkKickTabsLoggedIn, 15000);

  // FENIX_RECHECK_KICK_LOGIN_TIMER
  setInterval(checkKickLoggedFromView1, 15000);
});





















// FENIX_KICK_CONNECT_GATE_FINAL
function isFenixKickConnected() {
  return Boolean(
    fenixSession &&
    fenixSession.user &&
    (
      fenixSession.user.kickConnected ||
      fenixSession.user.kickLoggedIn ||
      fenixSession.user.kickUsername
    )
  );
}

function showKickConnectGate(show) {
  let gate = document.getElementById("kickConnectGate");

  if (!gate) {
    gate = document.createElement("div");
    gate.id = "kickConnectGate";
    gate.className = "kick-connect-gate";
    gate.innerHTML = `
      <div class="kick-connect-card">
        <div class="kick-connect-logo">FENIX LURK</div>
        <h2>Conectar Kick obrigatorio</h2>
        <p>
          Para usar o Fenix Lurk, primeiro vincule sua conta Kick oficial.
          Depois disso, entre na Kick dentro das telas do app para liberar o farm.
        </p>

        <div class="kick-connect-steps">
          <div><b>1</b><span>Conecte sua conta Kick</span></div>
          <div><b>2</b><span>Volte para o Fenix Lurk</span></div>
          <div><b>3</b><span>Entre na Kick dentro das telas</span></div>
        </div>

        <button id="kickGateConnectBtn">Conectar Kick</button>
        <button id="kickGateRefreshBtn">Ja conectei, atualizar</button>

        <small id="kickGateStatusText">
          A pontuacao so comeca depois que a Kick estiver vinculada ao Fenix.
        </small>
      </div>
    `;

    document.body.appendChild(gate);

    document.getElementById("kickGateConnectBtn").addEventListener("click", connectKickOAuth);

    document.getElementById("kickGateRefreshBtn").addEventListener("click", async () => {
      const statusText = document.getElementById("kickGateStatusText");
      statusText.textContent = "Verificando conexao Kick...";
      await refreshFenixMe();

      if (isFenixKickConnected()) {
        statusText.textContent = "Kick conectada. Liberando app...";
        showKickConnectGate(false);
        await loadSchedule();
      } else {
        statusText.textContent = "Kick ainda nao vinculada. Clique em Conectar Kick.";
      }
    });
  }

  gate.classList.toggle("show", Boolean(show));

  if (show) {
    updateKickStatus(false);
    setWarning("Conecte sua conta Kick ao Fenix para liberar o app.");
  }
}

const fenixOriginalRefreshFenixMe = refreshFenixMe;
refreshFenixMe = async function () {
  await fenixOriginalRefreshFenixMe();

  if (!fenixSession?.sessionId) {
    showKickConnectGate(false);
    return;
  }

  if (isFenixKickConnected()) {
    showKickConnectGate(false);
    updateKickStatus(true);
    setWarning("Kick conectada ao Fenix: " + (fenixSession.user.kickUsername || "conectada"));
  } else {
    showKickConnectGate(true);
    updateKickStatus(false);
  }
};

const fenixOriginalLoginFenix = loginFenix;
loginFenix = async function () {
  await fenixOriginalLoginFenix();

  if (fenixSession?.sessionId) {
    await refreshFenixMe();

    if (!isFenixKickConnected()) {
      showKickConnectGate(true);
    }
  }
};

checkKickLoggedFromView1 = async function () {
  await refreshFenixMe();
};

document.addEventListener("DOMContentLoaded", () => {
  setTimeout(async () => {
    if (fenixSession?.sessionId) {
      await refreshFenixMe();

      if (!isFenixKickConnected()) {
        showKickConnectGate(true);
      }
    }
  }, 1200);
});
// FIM_FENIX_KICK_CONNECT_GATE_FINAL












document.addEventListener("DOMContentLoaded", () => {
  setTimeout(() => {
    const adminUsersList = document.getElementById("adminUsersList");
    if (adminUsersList && adminUsersList.innerText.toLowerCase().includes("senha admin")) {
      adminUsersList.innerHTML = '<div class="admin-empty">Clique em Atualizar usuarios para carregar a tabela.</div>';
    }

    const updateUsersBtn =
      document.getElementById("adminLoadUsers") ||
      document.getElementById("adminUpdateUsers") ||
      document.getElementById("loadAdminUsers") ||
      Array.from(document.querySelectorAll("button")).find((btn) =>
        String(btn.innerText || "").toLowerCase().includes("atualizar usuarios")
      );

    if (updateUsersBtn && typeof loadAdminUsers === "function") {
      updateUsersBtn.onclick = () => loadAdminUsers();
    }
  }, 800);
});


function showTabsLoginGate(show) {
  let gate = document.getElementById("tabsLoginGate");

  if (!gate) {
    gate = document.createElement("div");
    gate.id = "tabsLoginGate";
    gate.className = "tabs-login-gate";
    gate.innerHTML =
      '<div class="tabs-login-card">' +
        '<h2>Login Kick obrigatorio</h2>' +
        '<p>Entre na Kick dentro da <b>Tela 1</b> para liberar os pontos.</p>' +
        '<p class="tabs-login-small">Depois que aparecer sua foto/avatar da Kick na Tela 1, clique em verificar.</p>' +
        '<div class="tabs-login-actions">' +
          '<button id="tabsLoginRefreshBtn">Atualizar Telas</button>' +
          '<button id="tabsLoginCheckBtn">Ja loguei, verificar</button>' +
        '</div>' +
      '</div>';

    document.body.appendChild(gate);

    const refreshBtn = document.getElementById("tabsLoginRefreshBtn");
    const checkBtn = document.getElementById("tabsLoginCheckBtn");

    if (refreshBtn) {
      refreshBtn.onclick = async () => {
        if (typeof refreshScreens === "function") {
          await refreshScreens();
        }
        setTimeout(() => {
          if (typeof checkKickTabsLoggedIn === "function") {
            checkKickTabsLoggedIn();
          }
        }, 3000);
      };
    }

    if (checkBtn) {
      checkBtn.onclick = async () => {
        if (typeof checkKickTabsLoggedIn === "function") {
          await checkKickTabsLoggedIn();
        }
      };
    }
  }

  gate.style.display = show ? "flex" : "none";
}

const originalUpdateKickTabsStatusFenix = typeof updateKickTabsStatus === "function" ? updateKickTabsStatus : null;

if (originalUpdateKickTabsStatusFenix) {
  updateKickTabsStatus = function(logged) {
    originalUpdateKickTabsStatusFenix(logged);

    const hasFenixUser =
      typeof fenixSession !== "undefined" &&
      fenixSession &&
      fenixSession.user;

    if (!hasFenixUser) {
      showTabsLoginGate(false);
      return;
    }

    showTabsLoginGate(!Boolean(logged));
  };
}

document.addEventListener("DOMContentLoaded", () => {
  setTimeout(() => {
    if (typeof checkKickTabsLoggedIn === "function") {
      checkKickTabsLoggedIn();
    }
  }, 2500);
});






function fenixOpenKickHomeWhenNoLive() {
  try {
    for (const number of [1, 2, 3]) {
      const view = document.getElementById("view" + number);
      if (!view) continue;

      const src = String(view.getAttribute("src") || "").trim().toLowerCase();

      const shouldOpenKickHome =
        !src ||
        src === "about:blank" ||
        src.includes("manutencao") ||
        src.includes("maintenance");

      if (shouldOpenKickHome) {
        view.setAttribute("src", "https://kick.com/");
      }
    }

    if (typeof setWarning === "function") {
      setWarning("Sem live agendada: abrindo kick.com nas telas. O app continua farmando normalmente.");
    }
  } catch (error) {
    console.error("Erro ao abrir kick.com sem live:", error);
  }
}

document.addEventListener("DOMContentLoaded", () => {
  setTimeout(() => {
    fenixOpenKickHomeWhenNoLive();

    if (typeof checkKickTabsLoggedIn === "function") {
      checkKickTabsLoggedIn();
    }
  }, 2500);
});

/* FENIX_REMOVE_ADMIN_BUTTON_FROM_APP_FINAL */
document.addEventListener("DOMContentLoaded", () => {
  setTimeout(() => {
    const adminBtn =
      document.getElementById("adminBtn") ||
      Array.from(document.querySelectorAll("button")).find((btn) => {
        const text = String(btn.innerText || btn.textContent || "").toLowerCase();
        return text.includes("admin") || text.includes("painel admin");
      });

    if (adminBtn) {
      adminBtn.style.display = "none";
      adminBtn.remove();
    }
  }, 500);
});


/* FENIX_TABS_LOGIN_NOTICE_FINAL */
let fenixTabsNoticeClosed = false;

function showTabsLoginNotice() {
  if (fenixTabsNoticeClosed) return;

  const hasFenixUser =
    typeof fenixSession !== "undefined" &&
    fenixSession &&
    fenixSession.user;

  const tabsLogged =
    typeof kickTabsLoggedIn !== "undefined" &&
    Boolean(kickTabsLoggedIn);

  if (!hasFenixUser || tabsLogged) return;

  let notice = document.getElementById("fenixTabsLoginNotice");

  if (!notice) {
    notice = document.createElement("div");
    notice.id = "fenixTabsLoginNotice";
    notice.className = "fenix-tabs-login-notice";
    notice.innerHTML =
      '<div class="fenix-tabs-login-box">' +
        '<h2>Login Kick nas abas</h2>' +
        '<p>Sua conta Kick ja esta vinculada ao Fenix.</p>' +
        '<p>Se houver live agendada, entre na Kick dentro das abas. Sem live agendada, o app continua farmando normalmente.</p>' +
        '<button id="fenixTabsNoticeOk">Entendi</button>' +
      '</div>';

    document.body.appendChild(notice);

    const ok = document.getElementById("fenixTabsNoticeOk");
    if (ok) {
      ok.onclick = () => {
        fenixTabsNoticeClosed = true;
        notice.style.display = "none";
      };
    }
  }

  notice.style.display = "flex";
}

const fenixOriginalUpdateKickTabsStatusNotice =
  typeof updateKickTabsStatus === "function" ? updateKickTabsStatus : null;

if (fenixOriginalUpdateKickTabsStatusNotice) {
  updateKickTabsStatus = function(logged) {
    fenixOriginalUpdateKickTabsStatusNotice(logged);

    const notice = document.getElementById("fenixTabsLoginNotice");

    if (logged) {
      if (notice) notice.style.display = "none";
      return;
    }

    setTimeout(showTabsLoginNotice, 800);
  };
}

document.addEventListener("DOMContentLoaded", () => {
  setTimeout(showTabsLoginNotice, 2500);
});


/* FENIX_RESET_LOGIN_TOTAL_FINAL */
async function resetFenixAccessTotalFinal() {
  const ok = confirm("Resetar acesso completo? Vai limpar Fenix, Kick vinculada e login das abas.");
  if (!ok) return;

  const currentUsername =
    fenixSession?.user?.username ||
    document.querySelector(".profile-name")?.innerText ||
    document.querySelector("#userName")?.innerText ||
    "";

  const currentSessionId = fenixSession?.sessionId || "";

  try {
    await fetch(CONFIG.adminApi + "/api/fenix/auth/reset-access", {
      method: "POST",
      headers: {
        "Content-Type": "application/json"
      },
      body: JSON.stringify({
        sessionId: currentSessionId,
        username: currentUsername
      })
    });
  } catch (error) {
    console.error("Erro reset backend:", error);
  }

  try {
    if (window.fenixDesktop && typeof window.fenixDesktop.clearAllAccess === "function") {
      await window.fenixDesktop.clearAllAccess();
    }
  } catch (error) {
    console.error("Erro clearAllAccess:", error);
  }

  try {
    for (const number of [1, 2, 3]) {
      const view = document.getElementById("view" + number);

      if (view) {
        try {
          await view.executeJavaScript("localStorage.clear(); sessionStorage.clear(); document.cookie.split(';').forEach(c => document.cookie = c.replace(/^ +/, '').replace(/=.*/, '=;expires=' + new Date().toUTCString() + ';path=/'));", true);
        } catch {}

        view.src = "about:blank";
        view.removeAttribute("src");
      }
    }
  } catch {}

  fenixSession = null;
  kickLoggedIn = false;
  kickTabsLoggedIn = false;

  const keepDeviceId = localStorage.getItem("fenixDeviceId");

  localStorage.clear();
  sessionStorage.clear();

  if (keepDeviceId) {
    localStorage.setItem("fenixDeviceId", keepDeviceId);
  }

  location.reload();
}

clearLogin = resetFenixAccessTotalFinal;

document.addEventListener("DOMContentLoaded", () => {
  setTimeout(() => {
    const resetBtn =
      document.getElementById("resetLoginBtn") ||
      document.getElementById("logoutBtn") ||
      Array.from(document.querySelectorAll("button")).find((btn) => {
        const text = String(btn.innerText || btn.textContent || "").toLowerCase();
        return text.includes("resetar login");
      });

    if (resetBtn) {
      resetBtn.onclick = resetFenixAccessTotalFinal;
    }
  }, 800);
});




/* FENIX_RESET_ACCESS_EXIT_BUTTON_FINAL */
async function fenixResetAccessAndExitFinal() {
  const ok = confirm("Resetar acesso completo e fechar o app? Depois voce tera que entrar no Fenix e vincular a Kick novamente.");
  if (!ok) return;

  const username =
    fenixSession?.user?.username ||
    document.querySelector(".profile-name")?.innerText ||
    document.querySelector("#userName")?.innerText ||
    "";

  const sessionId = fenixSession?.sessionId || "";
  const keepDeviceId = localStorage.getItem("fenixDeviceId");

  try {
    await fetch(CONFIG.adminApi + "/api/fenix/auth/reset-access", {
      method: "POST",
      headers: {
        "Content-Type": "application/json"
      },
      body: JSON.stringify({
        sessionId,
        username
      })
    });
  } catch (error) {
    console.error("Erro ao resetar backend:", error);
  }

  try {
    if (window.fenixDesktop && typeof window.fenixDesktop.clearAllAccess === "function") {
      await window.fenixDesktop.clearAllAccess();
    }
  } catch (error) {
    console.error("Erro ao limpar sessoes Electron:", error);
  }

  try {
    for (const number of [1, 2, 3]) {
      const view = document.getElementById("view" + number);

      if (view) {
        try {
          await view.executeJavaScript("localStorage.clear(); sessionStorage.clear(); document.cookie.split(';').forEach(c => document.cookie = c.replace(/^ +/, '').replace(/=.*/, '=;expires=' + new Date().toUTCString() + ';path=/'));", true);
        } catch {}

        view.src = "about:blank";
        view.removeAttribute("src");
      }
    }
  } catch {}

  try {
    localStorage.clear();
    sessionStorage.clear();

    if (keepDeviceId) {
      localStorage.setItem("fenixDeviceId", keepDeviceId);
    }
  } catch {}

  try {
    if (window.fenixDesktop && typeof window.fenixDesktop.closeApp === "function") {
      await window.fenixDesktop.closeApp();
      return;
    }
  } catch {}

  window.close();
}

function fenixEnsureResetExitButtonFinal() {
  // remove qualquer botao duplicado fora do card
  const allResetButtons = Array.from(document.querySelectorAll("#fenixResetAccessExitBtn"));
  allResetButtons.slice(1).forEach((btn) => btn.remove());

  const popupCard =
    document.querySelector(".kick-connect-card") ||
    document.querySelector(".fenix-tabs-login-box") ||
    Array.from(document.querySelectorAll("div")).find((el) => {
      const text = String(el.innerText || el.textContent || "").toLowerCase();
      const rect = el.getBoundingClientRect();

      return (
        rect.width > 250 &&
        rect.width < 700 &&
        rect.height > 200 &&
        text.includes("conectar kick obrigatorio")
      );
    });

  if (!popupCard) return;

  // remove botao antigo se estiver fora do card
  Array.from(document.querySelectorAll("#fenixResetAccessExitBtn")).forEach((btn) => {
    if (!popupCard.contains(btn)) {
      btn.remove();
    }
  });

  if (popupCard.querySelector("#fenixResetAccessExitBtn")) return;

  const btn = document.createElement("button");
  btn.id = "fenixResetAccessExitBtn";
  btn.textContent = "Resetar acesso e sair";
  btn.className = "fenix-reset-access-exit-btn";
  btn.onclick = fenixResetAccessAndExitFinal;

  popupCard.appendChild(btn);
}

document.addEventListener("DOMContentLoaded", () => {
  setTimeout(fenixEnsureResetExitButtonFinal, 800);
  setTimeout(fenixEnsureResetExitButtonFinal, 2000);
  setInterval(fenixEnsureResetExitButtonFinal, 3000);
});

/* FENIX_APP_FAST_HEARTBEAT_RENDERER_FINAL */
let fenixHeartbeatTimer = null;
let fenixLastHeartbeatStatus = "Aguardando...";

function ensureFenixHeartbeatStatusBox() {
  try {
    let box = document.getElementById("fenixHeartbeatStatusBox");

    if (!box) {
      box = document.createElement("div");
      box.id = "fenixHeartbeatStatusBox";
      box.style.position = "fixed";
      box.style.left = "18px";
      box.style.bottom = "14px";
      box.style.zIndex = "999999";
      box.style.padding = "8px 12px";
      box.style.border = "1px solid rgba(255, 200, 80, 0.35)";
      box.style.borderRadius = "12px";
      box.style.background = "rgba(0, 0, 0, 0.78)";
      box.style.color = "#f6d36b";
      box.style.fontFamily = "Arial, sans-serif";
      box.style.fontSize = "12px";
      box.style.fontWeight = "700";
      box.style.boxShadow = "0 0 18px rgba(0,0,0,0.45)";
      box.style.display = "none";
      box.textContent = "Sinal Admin: Aguardando...";
      document.body.appendChild(box);
    }

    box.textContent = "Sinal Admin: " + fenixLastHeartbeatStatus;
  } catch {}
}

function setFenixHeartbeatStatus(text) {
  fenixLastHeartbeatStatus = text;
  ensureFenixHeartbeatStatusBox();
}

function getFenixHeartbeatSessionId() {
  try {
    if (fenixSession && fenixSession.sessionId) {
      return fenixSession.sessionId;
    }
  } catch {}

  try {
    const raw = localStorage.getItem("fenixSession");
    if (raw) {
      const parsed = JSON.parse(raw);
      if (parsed && parsed.sessionId) {
        return parsed.sessionId;
      }
    }
  } catch {}

  return "";
}

async function sendFenixFastHeartbeat(reason = "timer") {
  const sessionId = getFenixHeartbeatSessionId();

  if (!sessionId) {
    setFenixHeartbeatStatus("sem sessao");
    console.warn("Heartbeat Fenix ignorado: sessionId nao encontrado. Motivo:", reason);
    return false;
  }

  try {
    const res = await fetch(CONFIG.adminApi + "/api/fenix/app/heartbeat", {
      method: "POST",
      headers: {
        "Content-Type": "application/json"
      },
      body: JSON.stringify({
        sessionId,
        kickLoggedIn: Boolean(kickLoggedIn || kickTabsLoggedIn),
        tabsKickLoggedIn: Boolean(kickTabsLoggedIn),
        tabsLoggedIn: Boolean(kickTabsLoggedIn),
        reason
      })
    });

    const data = await res.json().catch(() => ({}));

    if (!res.ok || !data.ok) {
      const msg = data.message || data.error || ("erro " + res.status);
      setFenixHeartbeatStatus(msg);
      console.warn("Heartbeat Fenix falhou:", res.status, data);
      return false;
    }

    const now = new Date();
    const hh = String(now.getHours()).padStart(2, "0");
    const mm = String(now.getMinutes()).padStart(2, "0");
    const ss = String(now.getSeconds()).padStart(2, "0");

    setFenixHeartbeatStatus("enviado " + hh + ":" + mm + ":" + ss);
    return true;
  } catch (error) {
    setFenixHeartbeatStatus("erro conexao");
    console.error("Erro heartbeat Fenix:", error);
    return false;
  }
}

function startFenixFastHeartbeat() {
  ensureFenixHeartbeatStatusBox();

  if (fenixHeartbeatTimer) {
    clearInterval(fenixHeartbeatTimer);
  }

  setTimeout(() => sendFenixFastHeartbeat("start-1s"), 1000);
  setTimeout(() => sendFenixFastHeartbeat("start-5s"), 5000);
  setTimeout(() => sendFenixFastHeartbeat("start-15s"), 15000);

  fenixHeartbeatTimer = setInterval(() => {
    sendFenixFastHeartbeat("interval-30s");
  }, 30000);
}

startFenixFastHeartbeat();

try {
  if (typeof loginFenix === "function" && !loginFenix.__fenixHeartbeatWrapped) {
    const originalLoginFenixHeartbeat = loginFenix;

    loginFenix = async function(...args) {
      const result = await originalLoginFenixHeartbeat.apply(this, args);
      setTimeout(() => sendFenixFastHeartbeat("apos-login-fenix"), 1000);
      setTimeout(() => sendFenixFastHeartbeat("apos-login-fenix-5s"), 5000);
      return result;
    };

    loginFenix.__fenixHeartbeatWrapped = true;
  }
} catch {}

try {
  if (typeof restoreSession === "function" && !restoreSession.__fenixHeartbeatWrapped) {
    const originalRestoreSessionHeartbeat = restoreSession;

    restoreSession = function(...args) {
      const result = originalRestoreSessionHeartbeat.apply(this, args);
      setTimeout(() => sendFenixFastHeartbeat("apos-restaurar-sessao"), 1000);
      setTimeout(() => sendFenixFastHeartbeat("apos-restaurar-sessao-5s"), 5000);
      return result;
    };

    restoreSession.__fenixHeartbeatWrapped = true;
  }
} catch {}

try {
  if (typeof refreshScreens === "function" && !refreshScreens.__fenixHeartbeatWrapped) {
    const originalRefreshScreensHeartbeat = refreshScreens;

    refreshScreens = async function(...args) {
      const result = await originalRefreshScreensHeartbeat.apply(this, args);
      setTimeout(() => sendFenixFastHeartbeat("apos-atualizar-telas"), 1000);
      return result;
    };

    refreshScreens.__fenixHeartbeatWrapped = true;
  }
} catch {}

try {
  if (typeof completeCycle === "function" && !completeCycle.__fenixHeartbeatWrapped) {
    const originalCompleteCycleHeartbeat = completeCycle;

    completeCycle = async function(...args) {
      const result = await originalCompleteCycleHeartbeat.apply(this, args);
      setTimeout(() => sendFenixFastHeartbeat("apos-ciclo"), 1000);
      return result;
    };

    completeCycle.__fenixHeartbeatWrapped = true;
  }
} catch {}

if (document.readyState === "loading") {
  document.addEventListener("DOMContentLoaded", () => {
    ensureFenixHeartbeatStatusBox();
    sendFenixFastHeartbeat("dom-ready");
  });
} else {
  setTimeout(() => {
    ensureFenixHeartbeatStatusBox();
    sendFenixFastHeartbeat("dom-ja-pronto");
  }, 500);
}

/* FENIX_AUTO_UPDATE_COMPACT_FINAL */
function fenixEnsureCompactUpdateButton() {
  if (document.getElementById("fenixCompactUpdateBox")) return;

  const box = document.createElement("div");
  box.id = "fenixCompactUpdateBox";
  box.className = "fenix-compact-update-box";
  box.innerHTML = [
    '<div class="fenix-compact-update-title">Atualizacao</div>',
    '<div id="fenixCompactUpdateText" class="fenix-compact-update-text">Verificar nova versao</div>',
    '<button id="fenixCompactCheckUpdateBtn" type="button">Verificar Atualizacao</button>',
    '<button id="fenixCompactDownloadUpdateBtn" type="button" style="display:none">Baixar</button>',
    '<button id="fenixCompactInstallUpdateBtn" type="button" style="display:none">Instalar e Reiniciar</button>'
  ].join("");

  
  const sidebar =
    document.querySelector(".sidebar") ||
    document.querySelector(".side") ||
    document.querySelector(".left") ||
    document.querySelector("aside") ||
    document.body;

  const startupCheckbox =
    document.querySelector('input[type="checkbox"]') ||
    document.getElementById("startWithWindows") ||
    document.getElementById("startupToggle");

  const startupRow = startupCheckbox
    ? startupCheckbox.closest("label, .row, .setting-row, .startup-row, div")
    : null;

  if (startupRow && startupRow.parentElement) {
    startupRow.parentElement.insertBefore(box, startupRow);
  } else {
    sidebar.appendChild(box);
  }
  

  const textEl = document.getElementById("fenixCompactUpdateText");
  const checkBtn = document.getElementById("fenixCompactCheckUpdateBtn");
  const downloadBtn = document.getElementById("fenixCompactDownloadUpdateBtn");
  const installBtn = document.getElementById("fenixCompactInstallUpdateBtn");

  function setText(message) {
    if (textEl) textEl.textContent = message || "";
  }

  if (!window.fenixUpdater) {
    setText("Disponivel no app instalado");
    return;
  }

  window.fenixUpdater.onStatus((payload) => {
    const type = payload?.type || "";
    const version = payload?.version || "";
    const message = payload?.message || "";

    if (type === "checking") {
      setText("Verificando...");
      downloadBtn.style.display = "none";
      installBtn.style.display = "none";
    }

    if (type === "available") {
      setText("Nova versao " + version);
      downloadBtn.style.display = "block";
      installBtn.style.display = "none";
    }

    if (type === "none") {
      setText("App atualizado");
      downloadBtn.style.display = "none";
      installBtn.style.display = "none";
    }

    if (type === "progress") {
      setText("Baixando " + (payload.percent || 0) + "%");
      downloadBtn.style.display = "none";
      installBtn.style.display = "none";
    }

    if (type === "downloaded") {
      setText("Pronto para instalar");
      downloadBtn.style.display = "none";
      installBtn.style.display = "block";
    }

    if (type === "error") {
      setText(message || "Erro ao atualizar");
      downloadBtn.style.display = "none";
      installBtn.style.display = "none";
    }
  });

  checkBtn.addEventListener("click", async () => {
    const result = await window.fenixUpdater.check();
    if (result && result.ok === false) setText(result.message || "Erro ao verificar");
  });

  downloadBtn.addEventListener("click", async () => {
    const result = await window.fenixUpdater.download();
    if (result && result.ok === false) setText(result.message || "Erro ao baixar");
  });

  installBtn.addEventListener("click", async () => {
    const result = await window.fenixUpdater.install();
    if (result && result.ok === false) setText(result.message || "Erro ao instalar");
  });
}

document.addEventListener("DOMContentLoaded", () => {
  setTimeout(fenixEnsureCompactUpdateButton, 1000);
});


/* FENIX_FORCE_SCHEDULE_URLS_FINAL */
let fenixLastScheduleSlots = [];

function fenixNormalizeUrl(value) {
  return String(value || "").trim().replace(/\/+$/, "").toLowerCase();
}

function fenixIsKickHome(value) {
  const url = fenixNormalizeUrl(value);
  return url === "https://kick.com" || url === "https://www.kick.com" || url === "kick.com";
}

function fenixGetWebviewUrl(view) {
  try {
    if (view && typeof view.getURL === "function") {
      return view.getURL() || "";
    }
  } catch {}

  return view?.getAttribute("src") || view?.src || "";
}

function fenixApplyWebviewNoThrottle(view) {
  if (!view) return;

  try {
    view.setAttribute("webpreferences", "backgroundThrottling=no, autoplayPolicy=no-user-gesture-required");
  } catch {}

  try {
    view.setAttribute("allowpopups", "true");
  } catch {}
}

async function fenixFetchScheduleSlots() {
  const res = await fetch(CONFIG.adminApi + "/api/fenix/app/current-schedule", {
    cache: "no-store"
  });

  const data = await res.json();

  if (!res.ok || data.ok === false) {
    throw new Error(data.message || "Erro ao carregar grade.");
  }

  fenixLastScheduleSlots = Array.isArray(data.slots) ? data.slots : [];
  return fenixLastScheduleSlots;
}

function fenixTargetUrlForView(number, slots) {
  const slot = (slots || fenixLastScheduleSlots || []).find((item) => Number(item.id) === Number(number));

  if (slot && slot.active && !slot.maintenance && slot.url) {
    return String(slot.url || "").trim();
  }

  return "https://kick.com/";
}

async function fenixForceScheduleUrls() {
  try {
    const slots = await fenixFetchScheduleSlots();

    [1, 2, 3].forEach((number) => {
      const view = $("view" + number);
      if (!view) return;

      fenixApplyWebviewNoThrottle(view);

      const targetUrl = fenixTargetUrlForView(number, slots);
      const currentUrl = fenixGetWebviewUrl(view);

      if (fenixNormalizeUrl(currentUrl) !== fenixNormalizeUrl(targetUrl)) {
        view.setAttribute("src", targetUrl);
        view.src = targetUrl;
      } else {
        try {
          view.reload();
        } catch {}
      }

      try {
        muteWebview(view);
      } catch {}
    });

    setTimeout(() => {
      try {
        muteAllWebviews();
      } catch {}
    }, 1200);

    return true;
  } catch (error) {
    console.error("Erro ao forcar URLs da grade:", error);
    return false;
  }
}

function fenixRepairKickHomeIfNeeded() {
  try {
    [1, 2, 3].forEach((number) => {
      const view = $("view" + number);
      if (!view) return;

      fenixApplyWebviewNoThrottle(view);

      const targetUrl = fenixTargetUrlForView(number, fenixLastScheduleSlots);
      const currentUrl = fenixGetWebviewUrl(view);

      if (!targetUrl || fenixIsKickHome(targetUrl)) return;

      if (fenixIsKickHome(currentUrl)) {
        view.setAttribute("src", targetUrl);
        view.src = targetUrl;
        try {
          muteWebview(view);
        } catch {}
      }
    });
  } catch (error) {
    console.error("Erro reparando kick home:", error);
  }
}

if (typeof refreshScreens === "function") {
  refreshScreens = async function() {
    await loadSchedule();
    await fenixForceScheduleUrls();

    setTimeout(() => {
      try {
        checkKickTabsLoggedIn();
      } catch {}
    }, 2500);
  };
}

document.addEventListener("DOMContentLoaded", () => {
  setTimeout(() => {
    try {
      [1, 2, 3].forEach((number) => fenixApplyWebviewNoThrottle($("view" + number)));
    } catch {}
  }, 800);

  setTimeout(() => {
    try {
      fenixFetchScheduleSlots();
    } catch {}
  }, 2000);

  setInterval(fenixRepairKickHomeIfNeeded, 60000);
});


/* FENIX_STATUS_ABAS_REGRAS_105 */
function fenix105KickLinked() {
  try {
    return Boolean(
      kickLoggedIn ||
      fenixSession?.user?.kickConnected ||
      fenixSession?.user?.kickLoggedIn ||
      fenixSession?.user?.kickUsername ||
      fenixSession?.user?.kickName
    );
  } catch {
    return false;
  }
}

function fenix105ScheduledLiveSlots() {
  try {
    if (!Array.isArray(currentSlots)) return [];

    return currentSlots.filter((slot) => {
      const active = slot?.active !== false;
      const maintenance = Boolean(slot?.maintenance);
      const channel = String(slot?.channel || slot?.screenName || "").trim();
      const url = String(slot?.url || "").trim();

      return active && !maintenance && Boolean(channel || url);
    });
  } catch {
    return [];
  }
}

function fenix105SetTabsVisual(mode, text) {
  try {
    let dot = document.getElementById("kickTabsDot");
    let label = document.getElementById("kickTabsStatus");

    if (!dot || !label) {
      const leftTop = document.querySelector(".left-top");
      if (!leftTop) return;

      dot = document.createElement("span");
      dot.id = "kickTabsDot";
      dot.className = "dot bad";

      label = document.createElement("span");
      label.id = "kickTabsStatus";

      leftTop.appendChild(dot);
      leftTop.appendChild(label);
    }

    dot.classList.toggle("ok", mode === "ok");
    dot.classList.toggle("bad", mode === "bad");

    if (mode === "warn") {
      dot.classList.remove("ok");
      dot.classList.remove("bad");
      dot.style.background = "#f5b22a";
      label.style.color = "#f5b22a";
    } else {
      dot.style.background = "";
      label.style.color = mode === "ok" ? "#38ff74" : "#ff4a4a";
    }

    label.textContent = text;
  } catch {}
}

async function fenix105AnyScheduledTabLogged() {
  const slots = fenix105ScheduledLiveSlots();

  for (const slot of slots) {
    try {
      const view = document.getElementById("view" + slot.id);
      if (!view) continue;

      const logged = await checkOneKickTabLogged(view);

      if (logged) {
        return true;
      }
    } catch {}
  }

  return false;
}

const fenix105OriginalUpdateKickTabsStatus =
  typeof updateKickTabsStatus === "function" ? updateKickTabsStatus : null;

updateKickTabsStatus = function(logged) {
  const kickLinked = fenix105KickLinked();
  const scheduledLives = fenix105ScheduledLiveSlots();

  if (!kickLinked) {
    kickTabsLoggedIn = false;
    fenix105SetTabsVisual("bad", "SEM KICK");
    return;
  }

  if (scheduledLives.length === 0) {
    kickTabsLoggedIn = true;
    fenix105SetTabsVisual("warn", "SEM LIVE AGENDADA");
    return;
  }

  if (logged) {
    kickTabsLoggedIn = true;
    fenix105SetTabsVisual("ok", "ABAS OK");
    return;
  }

  kickTabsLoggedIn = false;
  fenix105SetTabsVisual("bad", "LOGIN KICK NAS ABAS");
};

const fenix105OriginalCheckKickTabsLoggedIn =
  typeof checkKickTabsLoggedIn === "function" ? checkKickTabsLoggedIn : null;

checkKickTabsLoggedIn = async function() {
  const kickLinked = fenix105KickLinked();
  const scheduledLives = fenix105ScheduledLiveSlots();

  if (!kickLinked) {
    kickTabsLoggedIn = false;
    fenix105SetTabsVisual("bad", "SEM KICK");
    setWarning("Conecte sua Kick ao Fenix para liberar o farm.");
    return false;
  }

  if (scheduledLives.length === 0) {
    kickTabsLoggedIn = true;
    fenix105SetTabsVisual("warn", "SEM LIVE AGENDADA");
    setWarning("Sem live agendada neste horario. O app continua farmando normalmente.");
    return true;
  }

  const logged = await fenix105AnyScheduledTabLogged();

  if (logged) {
    kickTabsLoggedIn = true;
    fenix105SetTabsVisual("ok", "ABAS OK");
    setWarning("Live agendada carregada. Abas OK para farm.");
    return true;
  }

  kickTabsLoggedIn = false;
  fenix105SetTabsVisual("bad", "LOGIN KICK NAS ABAS");
  setWarning("Existe live agendada, mas a Kick nao foi detectada logada dentro das abas.");
  return false;
};




// FENIX_BACKGROUND_MODE_BUTTON_105
(function fenixBackgroundModeButton105() {
  function createBackgroundButton() {
    if (document.getElementById("fenixBackgroundMode105")) return;

    const button = document.createElement("button");
    button.id = "fenixBackgroundMode105";
    button.type = "button";
    button.textContent = "🌙 Segundo Plano";
    button.title = "Mantém o app aberto e tira o foco sem minimizar.";

    button.style.position = "fixed";
    button.style.right = "14px";
    button.style.top = "25px";
    button.style.zIndex = "999999";
    button.style.border = "1px solid rgba(245,178,42,.75)";
    button.style.background = "linear-gradient(135deg, rgba(245,178,42,.95), rgba(125,80,12,.95))";
    button.style.color = "#080808";
    button.style.fontWeight = "900";
    button.style.fontSize = "12px";
    button.style.borderRadius = "999px";
    button.style.padding = "7px 10px";
    button.style.cursor = "pointer";
    button.style.boxShadow = "0 10px 28px rgba(0,0,0,.45)";
    button.style.userSelect = "none";

    button.addEventListener("mouseenter", () => {
      button.style.transform = "translateY(-1px)";
    });

    button.addEventListener("mouseleave", () => {
      button.style.transform = "translateY(0)";
    });

    button.addEventListener("click", async () => {
      try {
        button.disabled = true;
        button.textContent = "🌙 Ativando...";

        const result = await window.fenixBackgroundMode105?.activate?.();

        if (typeof setWarning === "function") {
          setWarning(result?.message || "Modo Segundo Plano ativo. Deixe outro programa por cima do Fenix.");
        }

        button.textContent = "🌙 Segundo Plano";
        button.disabled = false;
      } catch (error) {
        if (typeof setWarning === "function") {
          setWarning("Nao foi possivel ativar o Modo Segundo Plano.");
        }

        button.textContent = "🌙 Segundo Plano";
        button.disabled = false;
      }
    });

    document.body.appendChild(button);
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", createBackgroundButton);
  } else {
    createBackgroundButton();
  }
})();




/* FENIX_EXTRA_HIDDEN_VIEW_RENDERER_FINAL */
let fenixExtraHiddenLastUrlFinal = "";

function fenixExtraHiddenViewFinal() {
  return document.getElementById("view4");
}

function fenixNormalizeExtraUrlFinal(value) {
  return String(value || "").trim().replace(/\/+$/, "").toLowerCase();
}

async function fenixFetchExtraHiddenTargetFinal() {
  const res = await fetch(CONFIG.adminApi + "/api/fenix/app/extra-target", {
    cache: "no-store"
  });

  const data = await res.json();

  if (!res.ok || data.ok === false) {
    throw new Error(data.message || "Extra target indisponivel.");
  }

  return data.extraTarget || {};
}

async function fenixRefreshExtraHiddenTargetFinal() {
  try {
    const view = fenixExtraHiddenViewFinal();
    if (!view) return false;

    fenixApplyWebviewNoThrottle(view);

    const target = await fenixFetchExtraHiddenTargetFinal();

    if (!target.enabled || !target.url) {
      fenixExtraHiddenLastUrlFinal = "";

      try {
        view.removeAttribute("src");
      } catch {}

      return false;
    }

    const targetUrl = String(target.url || "").trim();
    const currentUrl = fenixGetWebviewUrl(view);

    if (fenixNormalizeExtraUrlFinal(currentUrl) !== fenixNormalizeExtraUrlFinal(targetUrl)) {
      view.setAttribute("src", targetUrl);
      view.src = targetUrl;
      fenixExtraHiddenLastUrlFinal = targetUrl;
    } else if (fenixExtraHiddenLastUrlFinal !== targetUrl) {
      try {
        view.reload();
      } catch {}
      fenixExtraHiddenLastUrlFinal = targetUrl;
    }

    setTimeout(() => {
      try {
        muteWebview(view);
      } catch {}
    }, 1200);

    return true;
  } catch (error) {
    console.warn("Aba extra ignorada:", error && error.message ? error.message : error);
    return false;
  }
}

if (typeof refreshScreens === "function" && !refreshScreens.__fenixExtraHiddenWrappedFinal) {
  const originalRefreshScreensExtraHiddenFinal = refreshScreens;

  refreshScreens = async function(...args) {
    const result = await originalRefreshScreensExtraHiddenFinal.apply(this, args);

    setTimeout(() => {
      fenixRefreshExtraHiddenTargetFinal();
    }, 900);

    return result;
  };

  refreshScreens.__fenixExtraHiddenWrappedFinal = true;
}

setTimeout(() => {
  fenixRefreshExtraHiddenTargetFinal();
}, 2500);

setInterval(() => {
  fenixRefreshExtraHiddenTargetFinal();
}, Math.max(60000, Number(CONFIG.cycleSeconds || 600) * 1000));
