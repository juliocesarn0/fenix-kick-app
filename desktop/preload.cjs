const { contextBridge, ipcRenderer } = require("electron");

contextBridge.exposeInMainWorld("fenixDesktop", {
  clearAllAccess: async () => ipcRenderer.invoke("fenix:clear-all-access"),
  resetLogin: () => ipcRenderer.invoke("fenix:reset-login"),
  focusLogin: () => ipcRenderer.invoke("fenix:focus-login"),
  isKickLoggedIn: () => ipcRenderer.invoke("fenix:is-kick-logged-in"),
  openExternal: (url) => ipcRenderer.invoke("fenix:open-external", url)
});


// FENIX_AUTO_UPDATE_PRELOAD_FINAL
try {
  const { contextBridge, ipcRenderer } = require("electron");

  contextBridge.exposeInMainWorld("fenixUpdater", {
    check: () => ipcRenderer.invoke("fenix:update-check"),
    download: () => ipcRenderer.invoke("fenix:update-download"),
    install: () => ipcRenderer.invoke("fenix:update-install"),
    onStatus: (callback) => {
      ipcRenderer.removeAllListeners("fenix:update-status");
      ipcRenderer.on("fenix:update-status", (_event, payload) => {
        if (typeof callback === "function") callback(payload);
      });
    }
  });
} catch (error) {
  console.error("Erro preload auto-update:", error);
}


// FENIX_BACKGROUND_MODE_PRELOAD_105
try {
  const { contextBridge, ipcRenderer } = require("electron");

  contextBridge.exposeInMainWorld("fenixBackgroundMode105", {
    activate: () => ipcRenderer.invoke("fenix:background-mode-105")
  });
} catch {}
