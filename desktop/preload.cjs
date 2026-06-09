const { contextBridge, ipcRenderer } = require("electron");

contextBridge.exposeInMainWorld("fenixDesktop", {
  clearAllAccess: async () => ipcRenderer.invoke("fenix:clear-all-access"),
  resetLogin: () => ipcRenderer.invoke("fenix:reset-login"),
  focusLogin: () => ipcRenderer.invoke("fenix:focus-login"),
  isKickLoggedIn: () => ipcRenderer.invoke("fenix:is-kick-logged-in"),
  openExternal: (url) => ipcRenderer.invoke("fenix:open-external", url)
});
