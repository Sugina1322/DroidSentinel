const { contextBridge, ipcRenderer } = require("electron");

contextBridge.exposeInMainWorld("androidGuard", {
  getAdbVersion: () => ipcRenderer.invoke("adb:version"),
  scanDevice: () => ipcRenderer.invoke("device:scan"),
  scanPrivacy: () => ipcRenderer.invoke("privacy:scan"),
  setPackageEnabled: (payload) => ipcRenderer.invoke("package:set-enabled", payload),
  setAppOpMode: (payload) => ipcRenderer.invoke("appops:set-mode", payload),
  listHistory: () => ipcRenderer.invoke("history:list"),
  clearHistory: () => ipcRenderer.invoke("history:clear"),
  restoreHistory: (payload) => ipcRenderer.invoke("history:restore", payload),
  exportReport: () => ipcRenderer.invoke("report:export"),
  setPrivateDns: (payload) => ipcRenderer.invoke("dns:set", payload),
  uninstallUserApp: (payload) => ipcRenderer.invoke("app:uninstall-user", payload),
  getSettings: () => ipcRenderer.invoke("app:settings"),
  quitApp: () => ipcRenderer.invoke("app:quit")
});
