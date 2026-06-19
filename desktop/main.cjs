const { autoUpdater } = require("electron-updater");
const { app, BrowserWindow, Menu, ipcMain, session, shell, powerSaveBlocker, screen, dialog } = require("electron");
const path = require("path");
const { execFile } = require("child_process");
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

/* FENIX_VM_BLOCK_107 */
function detectFenixVirtualMachine107() {
  if (
    process.env.FENIX_TEST_USER_DATA_DIR &&
    process.env.FENIX_TEST_FORCE_VM === "1"
  ) {
    return Promise.resolve({
      detected: true,
      matches: ["SIMULACAO LOCAL DE VM"]
    });
  }

  if (process.platform !== "win32") {
    return Promise.resolve({ detected: false, matches: [] });
  }

  const command = [
    "$ErrorActionPreference = 'SilentlyContinue'",
    "$computer = Get-CimInstance Win32_ComputerSystem",
    "$product = Get-CimInstance Win32_ComputerSystemProduct",
    "$bios = Get-CimInstance Win32_BIOS",
    "[pscustomobject]@{",
    "Manufacturer = [string]$computer.Manufacturer",
    "Model = [string]$computer.Model",
    "ProductVendor = [string]$product.Vendor",
    "ProductName = [string]$product.Name",
    "ProductVersion = [string]$product.Version",
    "BiosManufacturer = [string]$bios.Manufacturer",
    "BiosVersion = [string]$bios.SMBIOSBIOSVersion",
    "} | ConvertTo-Json -Compress"
  ].join("; ");

  return new Promise((resolve) => {
    execFile(
      "powershell.exe",
      [
        "-NoProfile",
        "-NonInteractive",
        "-ExecutionPolicy",
        "Bypass",
        "-Command",
        command
      ],
      {
        windowsHide: true,
        timeout: 8000,
        maxBuffer: 1024 * 1024
      },
      (error, stdout) => {
        if (error || !String(stdout || "").trim()) {
          console.warn("Verificacao de VM indisponivel. Aplicativo liberado.");
          return resolve({ detected: false, matches: [] });
        }

        try {
          const info = JSON.parse(String(stdout).trim());
          const values = [
            info.Manufacturer,
            info.Model,
            info.ProductVendor,
            info.ProductName,
            info.ProductVersion,
            info.BiosManufacturer,
            info.BiosVersion
          ]
            .map((value) => String(value || "").trim())
            .filter(Boolean);

          const strongPattern =
            /virtualbox|innotek|vmware|virtual machine|qemu|kvm|xen|parallels|bochs|bhyve|amazon ec2|google compute engine|digitalocean|openstack|hvm domu|rhev|red hat virtualization|nutanix|proxmox|seabios/i;

          const matches = values.filter((value) => strongPattern.test(value));

          return resolve({
            detected: matches.length > 0,
            matches
          });
        } catch (error) {
          console.warn("Resposta invalida na verificacao de VM. Aplicativo liberado.");
          return resolve({ detected: false, matches: [] });
        }
      }
    );
  });
}

function applyFenixDisplayScale(targetWindow) {
  try {
    if (!targetWindow || targetWindow.isDestroyed()) return;

    const display = screen.getDisplayMatching(targetWindow.getBounds());
    const displayScale = Math.max(1, Number(display?.scaleFactor || 1));
    const zoomFactor = Math.max(0.5, Math.min(1, 1 / displayScale));

    targetWindow.webContents.setZoomFactor(zoomFactor);
  } catch (error) {
    console.error("Erro ajustando escala do Fenix:", error);
  }
}

function createWindow() {
  mainWindow = new BrowserWindow({
    width: 1366,
    height: 820,
    minWidth: 800,
    minHeight: 520,
    title: "Fenix Lurk",
    icon: path.join(__dirname, "assets", "icon.ico"),
    backgroundColor: "#07070a",
    show: false,
    autoHideMenuBar: true,
    webPreferences: {
      backgroundThrottling: false, preload: path.join(__dirname, "preload.cjs"),
      contextIsolation: true,
      nodeIntegration: false,
      webSecurity: true,
      webviewTag: true,
      partition: "persist:fenix-lurk-session"
    }
  });

  Menu.setApplicationMenu(null);

  fenixMainWindowForUpdate = mainWindow;
  mainWindow.loadFile(path.join(__dirname, "index.html"));

  mainWindow.webContents.on("did-finish-load", () => {
    applyFenixDisplayScale(mainWindow);
  });

  mainWindow.on("move", () => {
    applyFenixDisplayScale(mainWindow);
  });

// FENIX_BACKGROUND_MODE_105
  if (!global.fenixBackgroundMode105Registered) {
    global.fenixBackgroundMode105Registered = true;

    ipcMain.handle("fenix:background-mode-105", async () => {
      try {
        if (mainWindow && !mainWindow.isDestroyed()) {
          mainWindow.setAlwaysOnTop(false);
          mainWindow.showInactive();

          setTimeout(() => {
            try {
              if (mainWindow && !mainWindow.isDestroyed()) {
                mainWindow.blur();
              }
            } catch {}
          }, 120);
        }

        return {
          ok: true,
          message: "Modo Segundo Plano ativado. O app continua aberto para manter as lives rodando."
        };
      } catch (error) {
        return {
          ok: false,
          message: error?.message || "Erro ao ativar Modo Segundo Plano."
        };
      }
    });
  }

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

app.whenReady().then(async () => {
  const vmCheck107 = await detectFenixVirtualMachine107();

  if (vmCheck107.detected) {
    console.warn("Fenix bloqueado por maquina virtual:", vmCheck107.matches);

    dialog.showMessageBoxSync({
      type: "error",
      title: "Fenix bloqueado",
      message: "MAQUINA VIRTUAL DETECTADA",
      detail: "O Fenix Lurk e permitido somente em PC fisico. O aplicativo sera fechado sem abrir as lives.",
      buttons: ["Fechar"],
      defaultId: 0,
      noLink: true
    });

    app.quit();
    return;
  }
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
