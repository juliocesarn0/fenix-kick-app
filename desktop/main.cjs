const { autoUpdater } = require("electron-updater");
const { app, BrowserWindow, Menu, ipcMain, session, shell, powerSaveBlocker } = require("electron");
const path = require("path");
const fenixUserDataPath = path.join(app.getPath("appData"), "Fenix Lurk");

// FENIX_NO_BACKGROUND_THROTTLE_FINAL
app.commandLine.appendSwitch("disable-renderer-backgrounding");
app.commandLine.appendSwitch("disable-background-timer-throttling");
app.commandLine.appendSwitch("disable-backgrounding-occluded-windows");
app.commandLine.appendSwitch("autoplay-policy", "no-user-gesture-required");
app.commandLine.appendSwitch("disable-features", "CalculateNativeWinOcclusion,IntensiveWakeUpThrottling,BackForwardCache");
app.commandLine.appendSwitch("disable-hang-monitor");


app.setName("Fenix Lurk");
app.setPath("userData", fenixUserDataPath);


let mainWindow = null;

function createWindow() {
  mainWindow = new BrowserWindow({
    width: 1366,
    height: 820,
    minWidth: 1180,
    minHeight: 720,
    title: "Fenix Lurk",
    icon: path.join(__dirname, "assets", "icon.ico"),
    backgroundColor: "#07070a",
    show: false,
    autoHideMenuBar: true,
    webPreferences: {
      backgroundThrottling: false, preload: path.join(__dirname, "preload.cjs"),
      contextIsolation: true,
      nodeIntegration: false,
      webviewTag: true,
      partition: "persist:fenix-lurk-session"
    }
  });

  Menu.setApplicationMenu(null);

  fenixMainWindowForUpdate = mainWindow;
  mainWindow.loadFile(path.join(__dirname, "index.html"));

  // FENIX_MAXIMIZAR_JANELA
  mainWindow.once("ready-to-show", () => {
    mainWindow.maximize();
    mainWindow.show();
  });

  mainWindow.webContents.setWindowOpenHandler(({ url }) => {
    if (url.includes("kick.com") || url.includes("id.kick.com")) {
      return { action: "allow" };
    }

    shell.openExternal(url);
    return { action: "deny" };
  });

  mainWindow.on("closed", () => {
    mainWindow = null;
  });
}



// FENIX_AUTO_UPDATE_MAIN_FINAL
let fenixMainWindowForUpdate = null;

function sendFenixUpdateStatus(payload) {
  try {
    const target = fenixMainWindowForUpdate || BrowserWindow.getAllWindows()[0];
    if (target && !target.isDestroyed()) {
      target.webContents.send("fenix:update-status", payload);
    }
  } catch (error) {
    console.error("Erro enviando status update:", error);
  }
}

function setupFenixAutoUpdater() {
  try {
    autoUpdater.autoDownload = false;
    autoUpdater.allowPrerelease = false;
    autoUpdater.allowDowngrade = false;

    autoUpdater.on("checking-for-update", () => {
      sendFenixUpdateStatus({
        type: "checking",
        message: "Verificando atualizacao..."
      });
    });

    autoUpdater.on("update-available", (info) => {
      sendFenixUpdateStatus({
        type: "available",
        version: info?.version || "",
        message: "Atualizacao disponivel."
      });
    });

    autoUpdater.on("update-not-available", () => {
      sendFenixUpdateStatus({
        type: "none",
        message: "Voce ja esta usando a versao mais recente."
      });
    });

    autoUpdater.on("download-progress", (progress) => {
      sendFenixUpdateStatus({
        type: "progress",
        percent: Math.floor(progress?.percent || 0),
        message: "Baixando atualizacao..."
      });
    });

    autoUpdater.on("update-downloaded", () => {
      sendFenixUpdateStatus({
        type: "downloaded",
        message: "Atualizacao baixada. Reinicie para instalar."
      });
    });

    autoUpdater.on("error", (error) => {
      sendFenixUpdateStatus({
        type: "error",
        message: error?.message || "Erro ao verificar atualizacao."
      });
    });
  } catch (error) {
    console.error("Erro setup autoUpdater:", error);
  }
}

ipcMain.handle("fenix:update-check", async () => {
  try {
    if (!app.isPackaged) {
      return {
        ok: false,
        message: "Atualizacao automatica funciona apenas no app instalado."
      };
    }

    await autoUpdater.checkForUpdates();
    return {
      ok: true,
      message: "Verificacao iniciada."
    };
  } catch (error) {
    return {
      ok: false,
      message: error?.message || String(error)
    };
  }
});

ipcMain.handle("fenix:update-download", async () => {
  try {
    if (!app.isPackaged) {
      return {
        ok: false,
        message: "Download de atualizacao funciona apenas no app instalado."
      };
    }

    await autoUpdater.downloadUpdate();
    return {
      ok: true,
      message: "Download iniciado."
    };
  } catch (error) {
    return {
      ok: false,
      message: error?.message || String(error)
    };
  }
});

ipcMain.handle("fenix:update-install", async () => {
  try {
    autoUpdater.quitAndInstall(false, true);
    return {
      ok: true
    };
  } catch (error) {
    return {
      ok: false,
      message: error?.message || String(error)
    };
  }
});



// FENIX_POWER_SAVE_BLOCKER_FINAL
let fenixPowerSaveBlockerId = null;

function startFenixPowerSaveBlocker() {
  try {
    if (powerSaveBlocker && (fenixPowerSaveBlockerId === null || !powerSaveBlocker.isStarted(fenixPowerSaveBlockerId))) {
      fenixPowerSaveBlockerId = powerSaveBlocker.start("prevent-app-suspension");
      console.log("Fenix powerSaveBlocker ativo:", fenixPowerSaveBlockerId);
    }
  } catch (error) {
    console.error("Erro powerSaveBlocker:", error);
  }
}

app.whenReady().then(() => {
  startFenixPowerSaveBlocker();
  setupFenixAutoUpdater();
  app.setAppUserModelId("com.fenix.lurk");
  createWindow();

  app.on("activate", () => {
    if (BrowserWindow.getAllWindows().length === 0) createWindow();
  });
});

app.on("window-all-closed", () => {
  if (process.platform !== "darwin") app.quit();
});

ipcMain.handle("fenix:reset-login", async () => {
  try {
    await session.fromPartition("persist:fenix-kick-session").clearStorageData();
    await session.defaultSession.clearStorageData();
  } catch (error) {}

  app.relaunch();
  app.exit(0);
});

ipcMain.handle("fenix:focus-login", async () => {
  const win = BrowserWindow.getFocusedWindow() || BrowserWindow.getAllWindows()[0];

  if (win && !win.isDestroyed()) {
    win.minimize();

    setTimeout(() => {
      if (!win.isDestroyed()) {
        win.restore();
        win.focus();
      }
    }, 180);
  }

  return true;
});



ipcMain.handle("fenix:is-kick-logged-in", async () => {
  try {
    const cookies = await session.fromPartition("persist:fenix-kick-session").cookies.get({
      url: "https://kick.com"
    });

    const loggedIn = cookies.some((cookie) => {
      const name = String(cookie.name || "").toLowerCase();

      const looksAuth =
        name.includes("auth") ||
        name.includes("token") ||
        name.includes("remember") ||
        name.includes("jwt") ||
        name.includes("user");

      const looksPublic =
        name.includes("xsrf") ||
        name.includes("csrf") ||
        name.includes("guest") ||
        name.includes("anonymous") ||
        name.includes("visitor") ||
        name.includes("locale") ||
        name.includes("theme") ||
        name.includes("_ga") ||
        name.includes("_gid") ||
        name.includes("cf_") ||
        name.includes("__cf");

      return looksAuth && !looksPublic;
    });

    return { ok: true, loggedIn };
  } catch (error) {
    return { ok: false, loggedIn: false };
  }
});



ipcMain.handle("fenix:open-external", async (event, url) => {
  const safeUrl = String(url || "");

  if (safeUrl.startsWith("https://id.kick.com/") || safeUrl.startsWith("https://kick.com/")) {
    await shell.openExternal(safeUrl);
    return true;
  }

  return false;
});




// FENIX_CLEAR_ALL_ACCESS_IPC
ipcMain.handle("fenix:clear-all-access", async () => {
  const sessionsToClear = [
    session.defaultSession,
    session.fromPartition("persist:fenix-lurk-session"),
    session.fromPartition("persist:fenix-kick-session"),
    session.fromPartition("persist:kick"),
    session.fromPartition("persist:default")
  ];

  for (const ses of sessionsToClear) {
    try {
      await ses.clearStorageData({
        storages: [
          "cookies",
          "localstorage",
          "indexdb",
          "serviceworkers",
          "cachestorage",
          "shadercache"
        ]
      });
    } catch {}

    try {
      await ses.clearCache();
    } catch {}
  }

  return { ok: true };
});
