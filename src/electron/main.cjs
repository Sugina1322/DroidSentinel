const { app, BrowserWindow, ipcMain } = require("electron");
const { execFile } = require("node:child_process");
const fs = require("node:fs");
const path = require("node:path");
const { TELEMETRY_PACKAGES, TRACKING_SIGNALS, PERMISSION_AUDIT_OPS } = require("./telemetry-rules.cjs");
const { labelForPackage } = require("./app-labels.cjs");

const ADB_CANDIDATES = [
  path.join(process.resourcesPath || "", "tools", "platform-tools", "adb.exe"),
  path.join(process.cwd(), "tools", "platform-tools", "adb.exe"),
  "D:\\Downloads\\platform-tools-latest-windows\\platform-tools\\adb.exe",
  "adb"
];

let lastPrivacyScan = null;
let lastDnsState = null;
let currentDeviceSerial = null;

function historyPath() {
  return path.join(app.getPath("userData"), "action-history.json");
}

function readHistory() {
  try {
    return JSON.parse(fs.readFileSync(historyPath(), "utf8"));
  } catch {
    return [];
  }
}

function writeHistory(history) {
  fs.mkdirSync(app.getPath("userData"), { recursive: true });
  fs.writeFileSync(historyPath(), JSON.stringify(history, null, 2));
}

function recordHistory(entry) {
  const nextEntry = {
    id: `${Date.now()}-${Math.random().toString(16).slice(2)}`,
    createdAt: new Date().toISOString(),
    restored: false,
    deviceSerial: currentDeviceSerial || "unknown",
    ...entry
  };
  writeHistory([nextEntry, ...readHistory()].slice(0, 200));
  return nextEntry;
}

function historyForCurrentDevice() {
  const serial = currentDeviceSerial || "unknown";
  return readHistory().filter((entry) => (entry.deviceSerial || "unknown") === serial);
}

function htmlEscape(value) {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;");
}

function renderReportHtml(report) {
  const scan = report.scan;
  const rows = scan.permissionAudit
    .slice(0, 80)
    .map((appItem) => `
      <tr>
        <td>${htmlEscape(appItem.label || appItem.packageName)}</td>
        <td>${htmlEscape(appItem.packageName)}</td>
        <td>${htmlEscape(appItem.risk)}</td>
        <td>${htmlEscape(appItem.signals.map((signal) => signal.label).join(", "))}</td>
      </tr>
    `)
    .join("");
  const telemetryRows = scan.telemetryFindings
    .map((finding) => `
      <tr>
        <td>${htmlEscape(finding.name)}</td>
        <td>${htmlEscape(finding.packageName)}</td>
        <td>${htmlEscape(finding.risk)}</td>
        <td>${htmlEscape(finding.vendor)}</td>
      </tr>
    `)
    .join("");

  return `<!doctype html>
<html>
<head>
  <meta charset="utf-8" />
  <title>DroidSentinel Report</title>
  <style>
    body { font-family: Segoe UI, Arial, sans-serif; margin: 32px; color: #14212b; }
    h1, h2 { margin-bottom: 8px; }
    .muted { color: #607080; }
    .grid { display: grid; grid-template-columns: repeat(4, 1fr); gap: 12px; margin: 20px 0; }
    .card { border: 1px solid #dfe6ee; border-radius: 8px; padding: 14px; background: #f8fafc; }
    table { width: 100%; border-collapse: collapse; margin: 12px 0 28px; }
    th, td { border-bottom: 1px solid #dfe6ee; text-align: left; padding: 9px; vertical-align: top; }
    th { background: #f4f7fa; }
  </style>
</head>
<body>
  <h1>DroidSentinel Security Audit Report</h1>
  <p class="muted">Exported ${htmlEscape(report.exportedAt)}</p>
  <div class="grid">
    <div class="card"><strong>${scan.summary.packagesScanned}</strong><br />Packages audited</div>
    <div class="card"><strong>${scan.summary.telemetryFindings}</strong><br />Telemetry findings</div>
    <div class="card"><strong>${scan.summary.permissionApps}</strong><br />Apps to review</div>
    <div class="card"><strong>${htmlEscape(scan.privateDns.mode || "unknown")}</strong><br />Private DNS mode</div>
  </div>
  <h2>Telemetry Findings</h2>
  <table><thead><tr><th>Name</th><th>Package</th><th>Risk</th><th>Vendor</th></tr></thead><tbody>${telemetryRows || "<tr><td colspan='4'>No findings.</td></tr>"}</tbody></table>
  <h2>Permission Exposure</h2>
  <table><thead><tr><th>App</th><th>Package</th><th>Risk</th><th>Signals</th></tr></thead><tbody>${rows || "<tr><td colspan='4'>No permission exposure findings.</td></tr>"}</tbody></table>
</body>
</html>`;
}

function parseAppOpRestoreMode(value) {
  if (!value) return "default";
  if (/\bdeny\b/i.test(value)) return "deny";
  if (/\bignore\b/i.test(value)) return "ignore";
  if (/\bforeground\b/i.test(value)) return "foreground";
  if (/\ballow\b/i.test(value)) return "allow";
  return "default";
}

function isManageAppOpsBlocked(result) {
  return /MANAGE_APP_OPS_MODES|SecurityException/i.test(`${result.stderr}\n${result.error}\n${result.stdout}`);
}

function updateHistoryEntry(id, patch) {
  const history = readHistory();
  const nextHistory = history.map((entry) => entry.id === id ? { ...entry, ...patch } : entry);
  writeHistory(nextHistory);
}

function createWindow() {
  const win = new BrowserWindow({
    width: 1180,
    height: 760,
    minWidth: 980,
    minHeight: 640,
    title: "DroidSentinel",
    backgroundColor: "#f6f7f9",
    webPreferences: {
      preload: path.join(__dirname, "preload.cjs"),
      contextIsolation: true,
      nodeIntegration: false
    }
  });

  win.loadFile(path.join(__dirname, "../renderer/index.html"));
}

function getAdbPath() {
  const localAdb = ADB_CANDIDATES.find((candidate) => {
    return candidate === "adb" || fs.existsSync(candidate);
  });

  return localAdb || "adb";
}

function runAdb(args, timeout = 12000) {
  return new Promise((resolve) => {
    execFile(getAdbPath(), args, { timeout, windowsHide: true }, (error, stdout, stderr) => {
      resolve({
        ok: !error,
        stdout: stdout.trim(),
        stderr: stderr.trim(),
        error: error ? error.message : ""
      });
    });
  });
}

async function getProp(name) {
  const result = await runAdb(["shell", "getprop", name]);
  return result.ok ? result.stdout : "";
}

async function listPackages() {
  const result = await runAdb(["shell", "pm", "list", "packages"]);
  if (!result.ok) return [];

  return result.stdout
    .split(/\r?\n/)
    .map((line) => line.replace(/^package:/, "").trim())
    .filter(Boolean);
}

async function listPackagesByFlag(flag) {
  const result = await runAdb(["shell", "pm", "list", "packages", flag]);
  if (!result.ok) return [];

  return result.stdout
    .split(/\r?\n/)
    .map((line) => line.replace(/^package:/, "").trim())
    .filter(Boolean);
}

function parseComponentPackages(value) {
  if (!value || value === "null") return [];

  return [...new Set(
    value
      .split(":")
      .map((entry) => entry.split("/")[0].trim())
      .filter(Boolean)
  )];
}

function parseAppOpsPackages(value) {
  if (!value || value === "null") return [];

  const matches = value.matchAll(/(?:Package\s+)?([a-zA-Z0-9_]+(?:\.[a-zA-Z0-9_]+)+):/g);
  const colonPackages = [...matches].map((match) => match[1]);
  const linePackages = value
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter((line) => /^[a-zA-Z0-9_]+(?:\.[a-zA-Z0-9_]+)+$/.test(line));

  return [...new Set([...colonPackages, ...linePackages])];
}

async function scanTrackingSignals(packageSet, thirdPartySet) {
  const scans = await Promise.all(
    TRACKING_SIGNALS.map(async (signal) => {
      const result = await runAdb(signal.command);
      const packages = signal.id === "notification_listeners" || signal.id === "accessibility_services"
        ? parseComponentPackages(result.stdout)
        : parseAppOpsPackages(result.stdout);
      const allowedPackages = signal.id === "notification_listeners" || signal.id === "accessibility_services"
        ? packageSet
        : thirdPartySet;

      return {
        ...signal,
        ok: result.ok,
        packages: packages.filter((packageName) => allowedPackages.has(packageName)),
        raw: result.ok ? "" : result.stderr || result.error
      };
    })
  );

  return scans.filter((scan) => scan.packages.length || !scan.ok);
}

function riskLabel(score) {
  if (score >= 6) return "high";
  if (score >= 3) return "medium";
  return "low";
}

async function scanPermissionAudit(thirdPartySet) {
  const appMap = new Map();

  const addSignal = (packageName, signal) => {
    if (!thirdPartySet.has(packageName)) return;

    const existing = appMap.get(packageName) || {
      packageName,
      label: labelForPackage(packageName),
      score: 0,
      signals: []
    };

    if (!existing.signals.some((item) => item.id === signal.id)) {
      existing.score += signal.risk;
      existing.signals.push({
        id: signal.id,
        label: signal.label,
        op: signal.op,
        risk: signal.risk,
        summary: signal.summary
      });
    }

    appMap.set(packageName, existing);
  };

  await Promise.all(
    PERMISSION_AUDIT_OPS.map(async (signal) => {
      const result = await runAdb(["shell", "cmd", "appops", "query-op", signal.op, "allow"]);
      if (!result.ok) return;

      parseAppOpsPackages(result.stdout).forEach((packageName) => addSignal(packageName, signal));
    })
  );

  return [...appMap.values()]
    .map((app) => ({
      ...app,
      risk: riskLabel(app.score),
      signalCount: app.signals.length
    }))
    .sort((a, b) => b.score - a.score || a.packageName.localeCompare(b.packageName));
}

ipcMain.handle("adb:version", async () => {
  const result = await runAdb(["version"]);
  return {
    available: result.ok,
    version: result.stdout,
    error: result.error || result.stderr
  };
});

ipcMain.handle("device:scan", async () => {
  const adb = await runAdb(["devices"]);
  if (!adb.ok) {
    return {
      connected: false,
      error: adb.error || adb.stderr || "ADB is not available."
    };
  }

  const devices = adb.stdout
    .split(/\r?\n/)
    .slice(1)
    .map((line) => line.trim().split(/\s+/))
    .filter((parts) => parts.length >= 2);

  const authorized = devices.find((parts) => parts[1] === "device");
  const unauthorized = devices.find((parts) => parts[1] === "unauthorized");

  if (!authorized) {
    currentDeviceSerial = null;
    return {
      connected: false,
      unauthorized: Boolean(unauthorized),
      error: unauthorized
        ? "Phone detected, but USB debugging authorization is pending."
        : "No authorized Android device found."
    };
  }

  currentDeviceSerial = authorized[0];

  const [manufacturer, model, androidVersion, securityPatch] = await Promise.all([
    getProp("ro.product.manufacturer"),
    getProp("ro.product.model"),
    getProp("ro.build.version.release"),
    getProp("ro.build.version.security_patch")
  ]);

  return {
    connected: true,
    serial: authorized[0],
    manufacturer,
    model,
    androidVersion,
    securityPatch
  };
});

ipcMain.handle("privacy:scan", async () => {
  const [dnsMode, dnsHost, packages, thirdPartyPackages, disabledPackages] = await Promise.all([
    runAdb(["shell", "settings", "get", "global", "private_dns_mode"]),
    runAdb(["shell", "settings", "get", "global", "private_dns_specifier"]),
    listPackages(),
    listPackagesByFlag("-3"),
    listPackagesByFlag("-d")
  ]);

  const packageSet = new Set(packages);
  const thirdPartySet = new Set(thirdPartyPackages);
  const disabledSet = new Set(disabledPackages);
  const telemetryFindings = Object.entries(TELEMETRY_PACKAGES)
    .filter(([packageName]) => packageSet.has(packageName))
    .map(([packageName, details]) => ({
      packageName,
      label: labelForPackage(packageName),
      installedAs: thirdPartySet.has(packageName) ? "user app" : "system app",
      disabled: disabledSet.has(packageName),
      reversible: true,
      ...details
    }));

  const [trackingSignals, permissionAudit] = await Promise.all([
    scanTrackingSignals(packageSet, thirdPartySet),
    scanPermissionAudit(thirdPartySet)
  ]);

  lastPrivacyScan = {
    scannedAt: new Date().toISOString(),
    privateDns: {
      mode: dnsMode.ok ? dnsMode.stdout : "unknown",
      hostname: dnsHost.ok ? dnsHost.stdout : "",
      healthy: dnsMode.ok && dnsMode.stdout === "hostname" && Boolean(dnsHost.stdout)
    },
    summary: {
      packagesScanned: packages.length,
      thirdPartyPackages: thirdPartyPackages.length,
      systemPackages: Math.max(packages.length - thirdPartyPackages.length, 0),
      disabledPackages: disabledPackages.length,
      telemetryFindings: telemetryFindings.length,
      trackingSignals: trackingSignals.reduce((total, signal) => total + signal.packages.length, 0),
      permissionApps: permissionAudit.length
    },
    packagesScanned: packages.length,
    telemetryFindings,
    trackingSignals,
    permissionAudit,
    guidance: [
      {
        title: "Advertising ID",
        risk: "medium",
        summary: "Android does not expose a reliable ADB-only check for whether the advertising ID has been deleted or reset on every device.",
        recommendation: "Open Android Settings and review Privacy > Ads. Delete or reset the advertising ID if your Android version supports it."
      },
      {
        title: "Private DNS",
        risk: dnsMode.ok && dnsMode.stdout === "hostname" ? "low" : "medium",
        summary: "Private DNS can reduce exposure to known tracking, phishing, and telemetry domains when paired with a trustworthy provider.",
        recommendation: "Use a provider you trust, such as Quad9 or a personal NextDNS profile, if it matches your privacy goals."
      }
    ]
  };

  return lastPrivacyScan;
});

ipcMain.handle("package:set-enabled", async (_event, payload) => {
  const packageName = payload?.packageName;
  const enabled = Boolean(payload?.enabled);
  const actionMode = payload?.actionMode === "uninstall" ? "uninstall" : "disable";

  if (!packageName || !TELEMETRY_PACKAGES[packageName]) {
    return {
      ok: false,
      error: "This action is only available for known telemetry package findings."
    };
  }

  const args = enabled
    ? actionMode === "uninstall"
      ? ["shell", "cmd", "package", "install-existing", "--user", "0", packageName]
      : ["shell", "pm", "enable", packageName]
    : actionMode === "uninstall"
      ? ["shell", "pm", "uninstall", "--user", "0", packageName]
      : ["shell", "pm", "disable-user", "--user", "0", packageName];
  const result = await runAdb(args, 20000);
  let historyEntry = null;

  if (result.ok) {
    historyEntry = recordHistory({
      type: "package",
      title: `${enabled ? "Restored" : actionMode === "uninstall" ? "Uninstalled for user" : "Disabled"} ${TELEMETRY_PACKAGES[packageName].name}`,
      packageName,
      label: TELEMETRY_PACKAGES[packageName].name,
      actionMode,
      command: `adb ${args.join(" ")}`,
      restoreCommand: enabled
        ? actionMode === "uninstall"
          ? `adb shell pm uninstall --user 0 ${packageName}`
          : `adb shell pm disable-user --user 0 ${packageName}`
        : actionMode === "uninstall"
          ? `adb shell cmd package install-existing --user 0 ${packageName}`
          : `adb shell pm enable ${packageName}`,
      restoreArgs: enabled
        ? actionMode === "uninstall"
          ? ["shell", "pm", "uninstall", "--user", "0", packageName]
          : ["shell", "pm", "disable-user", "--user", "0", packageName]
        : actionMode === "uninstall"
          ? ["shell", "cmd", "package", "install-existing", "--user", "0", packageName]
          : ["shell", "pm", "enable", packageName]
    });
  }

  return {
    ok: result.ok,
    packageName,
    enabled,
    actionMode,
    command: `adb ${args.join(" ")}`,
    output: result.stdout,
    error: result.error || result.stderr,
    historyEntry
  };
});

ipcMain.handle("appops:set-mode", async (_event, payload) => {
  const packageName = payload?.packageName;
  const signalId = payload?.signalId;
  const mode = payload?.mode;
  const signal = PERMISSION_AUDIT_OPS.find((item) => item.id === signalId);

  if (!packageName || !signal || !["deny", "default"].includes(mode)) {
    return {
      ok: false,
      error: "Invalid permission action request."
    };
  }

  const thirdPartyPackages = await listPackagesByFlag("-3");
  if (!thirdPartyPackages.includes(packageName)) {
    return {
      ok: false,
      error: "Permission actions are only available for user-installed apps."
    };
  }

  const previous = await runAdb(["shell", "cmd", "appops", "get", "--user", "0", packageName, signal.op], 12000);
  const previousMode = previous.ok ? parseAppOpRestoreMode(previous.stdout) : "default";
  let args = ["shell", "cmd", "appops", "set", "--user", "0", packageName, signal.op, mode];
  let result = await runAdb(args, 20000);
  let method = "appops";
  let restoreArgs = ["shell", "cmd", "appops", "set", "--user", "0", packageName, signal.op, previousMode];
  let restoreCommand = `adb shell cmd appops set --user 0 ${packageName} ${signal.op} ${previousMode}`;

  if (!result.ok && mode === "deny" && signal.permission && isManageAppOpsBlocked(result)) {
    args = ["shell", "pm", "revoke", packageName, signal.permission];
    result = await runAdb(args, 20000);
    method = "pm-revoke";
    restoreArgs = ["shell", "pm", "grant", packageName, signal.permission];
    restoreCommand = `adb shell pm grant ${packageName} ${signal.permission}`;
  }

  let historyEntry = null;

  if (result.ok) {
    historyEntry = recordHistory({
      type: "permission",
      title: `${mode === "deny" ? "Denied" : "Reset"} ${signal.label} for ${labelForPackage(packageName)}`,
      packageName,
      label: labelForPackage(packageName),
      signalId,
      signalLabel: signal.label,
      previousMode,
      command: `adb ${args.join(" ")}`,
      method,
      restoreCommand,
      restoreArgs
    });
  }

  const blockedWithoutFallback = !result.ok && mode === "deny" && !signal.permission && isManageAppOpsBlocked(result);

  return {
    ok: result.ok,
    packageName,
    signalId,
    mode,
    label: signal.label,
    command: `adb ${args.join(" ")}`,
    output: result.stdout,
    error: blockedWithoutFallback
      ? `${signal.label} cannot be changed automatically on this device. Open Android Settings and change it manually.`
      : result.error || result.stderr,
    method,
    historyEntry
  };
});

ipcMain.handle("app:uninstall-user", async (_event, payload) => {
  const packageName = payload?.packageName;

  if (!packageName) {
    return { ok: false, error: "Missing package name." };
  }

  const thirdPartyPackages = await listPackagesByFlag("-3");
  if (!thirdPartyPackages.includes(packageName)) {
    return {
      ok: false,
      error: "App uninstall actions are only available for user-installed apps."
    };
  }

  const args = ["shell", "pm", "uninstall", "--user", "0", packageName];
  const result = await runAdb(args, 30000);
  let historyEntry = null;

  if (result.ok) {
    historyEntry = recordHistory({
      type: "app-uninstall",
      title: `Uninstalled ${labelForPackage(packageName)}`,
      packageName,
      label: labelForPackage(packageName),
      command: `adb ${args.join(" ")}`,
      restoreUnavailable: true,
      restoreCommand: "Manual reinstall required",
      restoreArgs: null
    });
  }

  return {
    ok: result.ok,
    packageName,
    command: `adb ${args.join(" ")}`,
    output: result.stdout,
    error: result.error || result.stderr,
    historyEntry
  };
});

ipcMain.handle("history:list", async () => {
  return historyForCurrentDevice();
});

ipcMain.handle("history:clear", async () => {
  const serial = currentDeviceSerial || "unknown";
  const history = readHistory();
  const scopedHistory = history.filter((entry) => (entry.deviceSerial || "unknown") === serial);
  const activeCount = scopedHistory.filter((entry) => !entry.restored).length;
  writeHistory(history.filter((entry) => (entry.deviceSerial || "unknown") !== serial));
  return { ok: true, activeCount };
});

ipcMain.handle("history:restore", async (_event, payload) => {
  const id = payload?.id;
  const entry = historyForCurrentDevice().find((item) => item.id === id);

  if (!entry) {
    return { ok: false, error: "History entry not found." };
  }

  if (entry.restored) {
    return { ok: false, error: "This action has already been restored." };
  }

  if (entry.restoreUnavailable || !entry.restoreArgs) {
    return { ok: false, error: "This action cannot be restored automatically. Reinstall the app manually." };
  }

  const restoreCommands = Array.isArray(entry.restoreCommands)
    ? entry.restoreCommands
    : [entry.restoreArgs];
  let failedResult = null;

  for (const args of restoreCommands) {
    const result = await runAdb(args, 20000);
    if (!result.ok) {
      failedResult = { args, result };
      break;
    }
  }

  if (!failedResult) {
    updateHistoryEntry(id, {
      restored: true,
      restoredAt: new Date().toISOString()
    });
  }

  return {
    ok: !failedResult,
    id,
    command: entry.restoreCommand,
    output: "",
    error: failedResult ? failedResult.result.error || failedResult.result.stderr : ""
  };
});

ipcMain.handle("report:export", async () => {
  if (!lastPrivacyScan) {
    return {
      ok: false,
      error: "Run a scan before exporting a report."
    };
  }

  const timestamp = new Date().toISOString().replaceAll(":", "-").replaceAll(".", "-");
  const jsonPath = path.join(app.getPath("documents"), `DroidSentinel-report-${timestamp}.json`);
  const htmlPath = path.join(app.getPath("documents"), `DroidSentinel-report-${timestamp}.html`);
  const report = {
    app: "DroidSentinel",
    exportedAt: new Date().toISOString(),
    scan: lastPrivacyScan,
    actionHistory: historyForCurrentDevice()
  };

  fs.writeFileSync(jsonPath, JSON.stringify(report, null, 2));
  fs.writeFileSync(htmlPath, renderReportHtml(report));

  return {
    ok: true,
    path: jsonPath,
    htmlPath
  };
});

ipcMain.handle("app:settings", async () => {
  return {
    adbPath: getAdbPath(),
    userDataPath: app.getPath("userData"),
    documentsPath: app.getPath("documents"),
    deviceSerial: currentDeviceSerial || "none",
    historyCount: historyForCurrentDevice().length
  };
});

ipcMain.handle("app:quit", async () => {
  app.quit();
});

ipcMain.handle("dns:set", async (_event, payload) => {
  const mode = payload?.mode;
  const hostname = String(payload?.hostname || "").trim();
  const restoreState = payload?.restoreState || lastPrivacyScan?.privateDns || lastDnsState;

  if (!["off", "opportunistic", "hostname"].includes(mode)) {
    return { ok: false, error: "Invalid Private DNS mode." };
  }

  if (mode === "hostname" && !/^[a-zA-Z0-9.-]{1,253}$/.test(hostname)) {
    return { ok: false, error: "Enter a valid DNS hostname." };
  }

  const commands = [];
  if (mode === "hostname") {
    commands.push(["shell", "settings", "put", "global", "private_dns_mode", "hostname"]);
    commands.push(["shell", "settings", "put", "global", "private_dns_specifier", hostname]);
  } else {
    commands.push(["shell", "settings", "put", "global", "private_dns_mode", mode]);
    commands.push(["shell", "settings", "delete", "global", "private_dns_specifier"]);
  }

  const results = [];
  for (const args of commands) {
    const result = await runAdb(args, 12000);
    results.push({ args, result });
    if (!result.ok) {
      return {
        ok: false,
        command: `adb ${args.join(" ")}`,
        error: result.error || result.stderr
      };
    }
  }

  lastDnsState = {
    mode,
    hostname: mode === "hostname" ? hostname : ""
  };

  const restoreMode = restoreState?.mode && restoreState.mode !== "null"
    ? restoreState.mode
    : "opportunistic";
  const restoreHostname = restoreState?.hostname && restoreState.hostname !== "null"
    ? restoreState.hostname
    : "";
  const restoreCommands = restoreMode === "hostname"
    ? [
        ["shell", "settings", "put", "global", "private_dns_mode", "hostname"],
        ["shell", "settings", "put", "global", "private_dns_specifier", restoreHostname]
      ]
    : [
        ["shell", "settings", "put", "global", "private_dns_mode", restoreMode],
        ["shell", "settings", "delete", "global", "private_dns_specifier"]
      ];

  recordHistory({
    type: "dns",
    title: mode === "hostname" ? `Set Private DNS to ${hostname}` : `Set Private DNS to ${mode}`,
    command: results.map(({ args }) => `adb ${args.join(" ")}`).join(" && "),
    restoreCommand: restoreCommands.map((args) => `adb ${args.join(" ")}`).join(" && "),
    restoreArgs: restoreCommands[0],
    restoreCommands
  });

  return {
    ok: true,
    mode,
    hostname,
    command: results.map(({ args }) => `adb ${args.join(" ")}`).join("\n")
  };
});

app.whenReady().then(createWindow);

app.on("window-all-closed", () => {
  if (process.platform !== "darwin") app.quit();
});

app.on("activate", () => {
  if (BrowserWindow.getAllWindows().length === 0) createWindow();
});
