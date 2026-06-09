const { app, BrowserWindow, Menu, ipcMain, session } = require("electron");
const path = require("path");
const fenixUserDataPath = path.join(app.getPath("appData"), "Fenix Lurk");

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
    webPreferences: { preload: path.join(__dirname, "preload.cjs"),
      contextIsolation: true,
      nodeIntegration: false,
      webviewTag: true,
      partition: "persist:fenix-lurk-session"
    }
  });

  Menu.setApplicationMenu(null);

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

app.whenReady().then(() => {
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


