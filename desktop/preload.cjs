const { contextBridge, ipcRenderer } = require("electron");

contextBridge.exposeInMainWorld("fenixDesktop", {
  resetLogin: () => ipcRenderer.invoke("fenix:reset-login"),
  focusLogin: () => ipcRenderer.invoke("fenix:focus-login")
});
