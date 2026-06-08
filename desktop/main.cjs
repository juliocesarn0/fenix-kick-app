const { app, BrowserWindow, Menu, shell } = require("electron");

const FENIX_URL = "https://fenix-kick-app-production.up.railway.app";

let mainWindow = null;

function createWindow() {
  mainWindow = new BrowserWindow({
    width: 1280,
    height: 820,
    minWidth: 1100,
    minHeight: 720,
    title: "Fenix Lurk",
    backgroundColor: "#050505",
    autoHideMenuBar: true,
    webPreferences: {
      contextIsolation: true,
      nodeIntegration: false,
      partition: "persist:fenix-kick-session"
    }
  });

  Menu.setApplicationMenu(null);

  mainWindow.loadURL(FENIX_URL);

  mainWindow.webContents.setWindowOpenHandler(({ url }) => {
    if (
      url.startsWith("https://fenix-kick-app-production.up.railway.app") ||
      url.includes("kick.com") ||
      url.includes("id.kick.com")
    ) {
      return { action: "allow" };
    }

    shell.openExternal(url);
    return { action: "deny" };
  });

  mainWindow.webContents.on("did-fail-load", () => {
    const fallbackHtml = [
      "<!doctype html>",
      "<html>",
      "<head>",
      "<meta charset='utf-8'>",
      "<title>Fenix Desktop</title>",
      "</head>",
      "<body style='margin:0;background:#050505;color:white;font-family:Arial;display:flex;align-items:center;justify-content:center;height:100vh;'>",
      "<div style='max-width:520px;text-align:center;border:1px solid #ff7a00;border-radius:20px;padding:35px;background:#111;'>",
      "<div style='font-size:60px;margin-bottom:15px;'>F</div>",
      "<h1>Fenix Desktop</h1>",
      "<p>Nao foi possivel carregar o painel online.</p>",
      "<p style='color:#ffb36b;'>Confira sua internet ou se a Railway esta online.</p>",
      "</div>",
      "</body>",
      "</html>"
    ].join("");

    mainWindow.loadURL("data:text/html;charset=utf-8," + encodeURIComponent(fallbackHtml));
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
