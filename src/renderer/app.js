const scanButton = document.querySelector("#scanButton");
const enterAppButton = document.querySelector("#enterAppButton");
const landingScanButton = document.querySelector("#landingScanButton");
const landingPage = document.querySelector("#landingPage");
const landingStatus = document.querySelector("#landingStatus");
const exitButton = document.querySelector("#exitButton");
const exportButton = document.querySelector("#exportButton");
const viewEyebrow = document.querySelector("#viewEyebrow");
const viewTitle = document.querySelector("#viewTitle");
const adbBadge = document.querySelector("#adbBadge");
const adbText = document.querySelector("#adbText");
const deviceBadge = document.querySelector("#deviceBadge");
const deviceText = document.querySelector("#deviceText");
const dnsBadge = document.querySelector("#dnsBadge");
const dnsText = document.querySelector("#dnsText");
const dnsPageBadge = document.querySelector("#dnsPageBadge");
const dnsDetails = document.querySelector("#dnsDetails");
const dnsActionStatus = document.querySelector("#dnsActionStatus");
const customDns = document.querySelector("#customDns");
const customDnsButton = document.querySelector("#customDnsButton");
const revertDnsButton = document.querySelector("#revertDnsButton");
const scanMeta = document.querySelector("#scanMeta");
const auditStats = document.querySelector("#auditStats");
const overviewHighlights = document.querySelector("#overviewHighlights");
const findingsList = document.querySelector("#findingsList");
const actionStatus = document.querySelector("#actionStatus");
const signalsList = document.querySelector("#signalsList");
const appAuditBadge = document.querySelector("#appAuditBadge");
const appAuditList = document.querySelector("#appAuditList");
const appSearch = document.querySelector("#appSearch");
const appActionStatus = document.querySelector("#appActionStatus");
const historyBadge = document.querySelector("#historyBadge");
const historyStatus = document.querySelector("#historyStatus");
const historyList = document.querySelector("#historyList");
const clearHistoryButton = document.querySelector("#clearHistoryButton");
const settingsDetails = document.querySelector("#settingsDetails");
const settingsRefreshButton = document.querySelector("#settingsRefreshButton");
const settingsClearHistoryButton = document.querySelector("#settingsClearHistoryButton");
const troubleshootingPanel = document.querySelector("#troubleshootingPanel");
const packageActionModeInputs = document.querySelectorAll('input[name="packageActionMode"]');
const filterButtons = document.querySelectorAll(".filter");
const navItems = document.querySelectorAll(".nav-item");
const views = document.querySelectorAll(".view");
const dnsActionButtons = document.querySelectorAll(".dns-action");

const VIEW_COPY = {
  overview: {
    eyebrow: "Security audit",
    title: "Device exposure overview"
  },
  telemetry: {
    eyebrow: "Telemetry intelligence",
    title: "Advertising and OEM telemetry findings"
  },
  dns: {
    eyebrow: "Network hardening",
    title: "Private DNS protection"
  },
  apps: {
    eyebrow: "Permission exposure",
    title: "Sensitive app access audit"
  },
  history: {
    eyebrow: "Restore trail",
    title: "Action history and rollback"
  },
  settings: {
    eyebrow: "Local configuration",
    title: "DroidSentinel settings"
  }
};

let activeFilter = "all";
let lastFindings = [];
let lastPermissionAudit = [];
let lastDnsScanState = null;
let appSearchQuery = "";
let packageActionMode = "disable";
let actionInProgress = false;
let appActionInProgress = false;

function setBadge(element, text, tone) {
  element.textContent = text;
  element.className = `badge ${tone}`;
}

function riskTone(risk) {
  if (risk === "high") return "danger";
  if (risk === "medium") return "warning";
  if (risk === "low") return "success";
  return "neutral";
}

function escapeHtml(value) {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

function commandFor(finding) {
  if (finding.disabled) {
    return packageActionMode === "uninstall"
      ? `adb shell cmd package install-existing --user 0 ${finding.packageName}`
      : `adb shell pm enable ${finding.packageName}`;
  }
  if (packageActionMode === "uninstall") {
    return `adb shell pm uninstall --user 0 ${finding.packageName}`;
  }
  return finding.command || `adb shell pm disable-user --user 0 ${finding.packageName}`;
}

function setActionStatus(message, tone = "neutral") {
  actionStatus.textContent = message;
  actionStatus.className = `action-status ${tone}`;
}

function setAppActionStatus(message, tone = "neutral") {
  appActionStatus.textContent = message;
  appActionStatus.className = `action-status ${tone}`;
}

function setHistoryStatus(message, tone = "neutral") {
  historyStatus.textContent = message;
  historyStatus.className = `action-status ${tone}`;
}

function setDnsActionStatus(message, tone = "neutral") {
  dnsActionStatus.textContent = message;
  dnsActionStatus.className = `action-status ${tone}`;
}

function shortError(message) {
  if (!message) return "Action failed.";
  if (/MANAGE_APP_OPS_MODES|SecurityException/i.test(message)) {
    return "This device blocks automatic app-ops changes for that permission. Try changing it from Android app settings.";
  }
  return message.length > 240 ? `${message.slice(0, 240)}...` : message;
}

function renderStats(summary) {
  if (!summary) {
    auditStats.innerHTML = "";
    return;
  }

  auditStats.innerHTML = `
    <div><strong>${summary.packagesScanned}</strong><span>packages</span></div>
    <div><strong>${summary.systemPackages}</strong><span>system</span></div>
    <div><strong>${summary.thirdPartyPackages}</strong><span>user apps</span></div>
    <div><strong>${summary.telemetryFindings}</strong><span>telemetry hits</span></div>
    <div><strong>${summary.permissionApps}</strong><span>apps to review</span></div>
  `;
}

function renderOverviewHighlights(summary, privateDns) {
  if (!summary) {
    overviewHighlights.className = "empty-state";
    overviewHighlights.textContent = "No audit summary yet.";
    return;
  }

  overviewHighlights.className = "overview-highlights";
  const dnsTone = privateDns.healthy ? "success" : "warning";
  const dnsTextValue = privateDns.healthy
    ? `Private DNS is using ${privateDns.hostname}.`
    : `Private DNS needs review. Current mode: ${privateDns.mode || "unknown"}.`;

  overviewHighlights.innerHTML = `
    <article>
      <span class="badge ${summary.telemetryFindings ? "danger" : "success"}">${summary.telemetryFindings ? "Review" : "Clear"}</span>
      <div>
        <strong>Telemetry packages</strong>
        <p>${summary.telemetryFindings} known ad or telemetry package finding(s).</p>
      </div>
    </article>
    <article>
      <span class="badge ${summary.trackingSignals ? "warning" : "success"}">${summary.trackingSignals ? "Review" : "Clear"}</span>
      <div>
        <strong>Tracking access</strong>
        <p>${summary.permissionApps} user app(s) have tracking-sensitive permissions or app access.</p>
      </div>
    </article>
    <article>
      <span class="badge ${dnsTone}">${privateDns.healthy ? "Protected" : "Review"}</span>
      <div>
        <strong>Private DNS</strong>
        <p>${escapeHtml(dnsTextValue)}</p>
      </div>
    </article>
  `;
}

function renderDnsDetails(privateDns) {
  dnsDetails.className = "dns-simple";
  dnsDetails.innerHTML = `
    <dl>
      <div>
        <dt>Status</dt>
        <dd>${privateDns.healthy ? "Protected" : "Needs review"}</dd>
      </div>
      <div>
        <dt>Mode</dt>
        <dd>${escapeHtml(privateDns.mode || "unknown")}</dd>
      </div>
      <div>
        <dt>Hostname</dt>
        <dd>${escapeHtml(privateDns.hostname || "none")}</dd>
      </div>
    </dl>
    <div class="simple-note">
      For browser ad blocking, use a filtering provider like AdGuard DNS. Private DNS can reduce many web ads and trackers, but it will not block every in-app or video-platform ad.
    </div>
  `;
}

function renderFindings(findings) {
  lastFindings = findings;
  const visibleFindings = activeFilter === "all"
    ? findings
    : findings.filter((finding) => finding.risk === activeFilter);

  if (!visibleFindings.length) {
    findingsList.className = "empty-state";
    findingsList.textContent = findings.length
      ? "No findings match the selected filter."
      : "No known telemetry packages found in the current rules database.";
    return;
  }

  findingsList.className = "finding-list";
  findingsList.innerHTML = visibleFindings
    .map(
      (finding) => `
        <article class="finding risk-${escapeHtml(finding.risk)}">
          <div>
            <div class="finding-title">${escapeHtml(finding.name)}</div>
            <div class="finding-package">${escapeHtml(finding.label || finding.packageName)} | ${escapeHtml(finding.packageName)}</div>
            <p>${escapeHtml(finding.summary)}</p>
            <div class="recommendation">${escapeHtml(finding.recommendation)}</div>
            <code>${escapeHtml(commandFor(finding))}</code>
          </div>
          <div class="finding-side">
            <span class="badge ${riskTone(finding.risk)}">${finding.risk}</span>
            <span class="vendor">${escapeHtml(finding.vendor)}</span>
            <span class="vendor">${escapeHtml(finding.category)}</span>
            <span class="state">${finding.disabled ? "Disabled" : escapeHtml(finding.installedAs)}</span>
            <button
              class="action-button ${finding.disabled ? "secondary" : "danger-action"}"
              data-package="${escapeHtml(finding.packageName)}"
              data-enabled="${finding.disabled ? "true" : "false"}"
              ${actionInProgress ? "disabled" : ""}
            >
              ${finding.disabled ? "Restore" : packageActionMode === "uninstall" ? "Uninstall" : "Disable"}
            </button>
          </div>
        </article>
      `
    )
    .join("");
}

function renderSignals(signals) {
  if (!signals.length) {
    signalsList.className = "empty-state";
    signalsList.textContent = "No sensitive tracking access signals were found.";
    return;
  }

  signalsList.className = "signal-list";
  signalsList.innerHTML = signals
    .map((signal) => {
      const packages = signal.packages.length
        ? signal.packages.map((packageName) => `<span>${escapeHtml(packageName)}</span>`).join("")
        : `<span>${escapeHtml(signal.raw || "Scan unavailable on this Android version.")}</span>`;

      return `
        <article class="signal">
          <div class="signal-main">
            <div>
              <div class="finding-title">${escapeHtml(signal.title)}</div>
              <p>${escapeHtml(signal.summary)}</p>
            </div>
            <span class="badge ${riskTone(signal.risk)}">${escapeHtml(signal.risk)}</span>
          </div>
          <div class="package-chips">${packages}</div>
        </article>
      `;
    })
    .join("");
}

function renderPermissionAudit(apps) {
  lastPermissionAudit = apps;
  const query = appSearchQuery.trim().toLowerCase();
  const visibleApps = query
    ? apps.filter((app) => {
        const haystack = [
          app.label,
          app.packageName,
          ...app.signals.map((signal) => signal.label)
        ].join(" ").toLowerCase();
        return haystack.includes(query);
      })
    : apps;

  if (!apps.length) {
    setBadge(appAuditBadge, "Clear", "success");
    appAuditList.className = "empty-state";
    appAuditList.textContent = "No user-installed apps with tracked sensitive access were found.";
    return;
  }

  setBadge(
    appAuditBadge,
    query ? `${visibleApps.length}/${apps.length}` : `${apps.length} apps`,
    apps.some((app) => app.risk === "high") ? "danger" : "warning"
  );

  if (!visibleApps.length) {
    appAuditList.className = "empty-state";
    appAuditList.textContent = "No apps match your search.";
    return;
  }

  appAuditList.className = "app-audit-list";
  appAuditList.innerHTML = visibleApps
    .map((app) => {
      const chips = app.signals
        .map(
          (signal) => `
            <span class="permission-chip" title="${escapeHtml(signal.summary)}">
              ${escapeHtml(signal.label)}
              <button
                class="mini-action"
                data-package="${escapeHtml(app.packageName)}"
                data-signal="${escapeHtml(signal.id)}"
                data-label="${escapeHtml(signal.label)}"
                ${appActionInProgress ? "disabled" : ""}
              >
                Deny
              </button>
            </span>
          `
        )
        .join("");

      return `
        <article class="app-audit risk-${escapeHtml(app.risk)}">
          <div>
            <div class="finding-title">${escapeHtml(app.packageName)}</div>
            <div class="finding-package">${escapeHtml(app.packageName)}</div>
            <p>${escapeHtml(app.label || app.packageName)} | ${app.signalCount} sensitive signal(s), score ${app.score}</p>
            <div class="package-chips">${chips}</div>
          </div>
          <div class="app-audit-side">
            <span class="badge ${riskTone(app.risk)}">${escapeHtml(app.risk)}</span>
            <button class="action-button danger-action" data-uninstall-package="${escapeHtml(app.packageName)}" ${appActionInProgress ? "disabled" : ""}>
              Uninstall
            </button>
          </div>
        </article>
      `;
    })
    .join("");
}

async function renderHistory() {
  const history = await window.androidGuard.listHistory();
  const activeHistory = history.filter((entry) => !entry.restored);
  setBadge(historyBadge, `${activeHistory.length} active`, activeHistory.length ? "warning" : "success");

  if (!history.length) {
    historyList.className = "empty-state";
    historyList.textContent = "No actions recorded yet.";
    return;
  }

  historyList.className = "history-list";
  historyList.innerHTML = history
    .map((entry) => `
      <article class="history-item ${entry.restored ? "is-restored" : ""}">
        <div>
          <div class="finding-title">${escapeHtml(entry.title)}</div>
          <div class="finding-package">${escapeHtml(entry.packageName || "")}</div>
          <p>${new Date(entry.createdAt).toLocaleString()}</p>
          <code>${escapeHtml(entry.restoreCommand)}</code>
        </div>
        <div class="history-side">
          <span class="badge ${entry.restored ? "success" : "warning"}">${entry.restored ? "Restored" : "Active"}</span>
          <button class="action-button secondary" data-history-id="${escapeHtml(entry.id)}" ${entry.restored || entry.restoreUnavailable ? "disabled" : ""}>
            ${entry.restoreUnavailable ? "Manual" : "Restore"}
          </button>
        </div>
      </article>
    `)
    .join("");
}

function switchView(viewName) {
  const copy = VIEW_COPY[viewName] || VIEW_COPY.overview;
  viewEyebrow.textContent = copy.eyebrow;
  viewTitle.textContent = copy.title;

  navItems.forEach((item) => {
    item.classList.toggle("active", item.dataset.view === viewName);
  });

  views.forEach((view) => {
    view.classList.toggle("active", view.id === `view-${viewName}`);
  });
}

function enterApp(viewName = "overview") {
  document.body.classList.remove("landing-active");
  landingPage.hidden = true;
  switchView(viewName);
}

function renderNoDeviceTroubleshooting(show) {
  troubleshootingPanel.hidden = !show;
}

async function renderLandingStatus() {
  const adb = await window.androidGuard.getAdbVersion();
  if (!adb.available) {
    landingStatus.textContent = "Status: ADB runtime unavailable. Bundled platform-tools is required.";
    landingStatus.className = "landing-status danger";
    return;
  }

  const device = await window.androidGuard.scanDevice();
  if (device.connected) {
    landingStatus.textContent = `Status: Device ready - ${device.manufacturer} ${device.model}`;
    landingStatus.className = "landing-status success";
  } else if (device.unauthorized) {
    landingStatus.textContent = "Status: Phone detected. Accept the USB debugging prompt on Android.";
    landingStatus.className = "landing-status warning";
  } else {
    landingStatus.textContent = "Status: No authorized device detected.";
    landingStatus.className = "landing-status warning";
  }
}

async function runScan() {
  scanButton.disabled = true;
  scanButton.textContent = "Scanning...";
  scanButton.classList.add("is-loading");

  setBadge(adbBadge, "Checking", "neutral");
  setBadge(deviceBadge, "Checking", "neutral");
  setBadge(dnsBadge, "Waiting", "neutral");
  setBadge(dnsPageBadge, "Waiting", "neutral");
  setBadge(appAuditBadge, "Scanning", "neutral");
  auditStats.innerHTML = "";

  const adb = await window.androidGuard.getAdbVersion();
  if (!adb.available) {
    setBadge(adbBadge, "Missing", "danger");
    adbText.textContent = "ADB runtime was not found. DroidSentinel needs platform-tools to audit the device.";
    setBadge(deviceBadge, "Offline", "danger");
    deviceText.innerHTML = '<p class="muted">Security audit cannot run until ADB is available.</p>';
    renderNoDeviceTroubleshooting(true);
    scanButton.disabled = false;
    scanButton.textContent = "Scan device";
    scanButton.classList.remove("is-loading");
    return;
  }

  setBadge(adbBadge, "Ready", "success");
  adbText.textContent = adb.version.split(/\r?\n/)[0] || "ADB is available.";

  const device = await window.androidGuard.scanDevice();
  if (!device.connected) {
    setBadge(deviceBadge, device.unauthorized ? "Authorize" : "Offline", "warning");
    deviceText.innerHTML = `<p class="muted">${device.error}</p>`;
    renderNoDeviceTroubleshooting(true);
    scanButton.disabled = false;
    scanButton.textContent = "Scan device";
    scanButton.classList.remove("is-loading");
    return;
  }

  setBadge(deviceBadge, "Connected", "success");
  renderNoDeviceTroubleshooting(false);
  deviceText.innerHTML = `
    <dl>
      <div><dt>Device</dt><dd>${device.manufacturer} ${device.model}</dd></div>
      <div><dt>Android</dt><dd>${device.androidVersion}</dd></div>
      <div><dt>Security patch</dt><dd>${device.securityPatch || "Unknown"}</dd></div>
      <div><dt>Serial</dt><dd>${device.serial}</dd></div>
    </dl>
  `;

  const privacy = await window.androidGuard.scanPrivacy();
  lastDnsScanState = { ...privacy.privateDns };
  if (privacy.privateDns.healthy) {
    setBadge(dnsBadge, "Protected", "success");
    setBadge(dnsPageBadge, "Protected", "success");
    dnsText.textContent = `Hostname mode enabled: ${privacy.privateDns.hostname}`;
  } else {
    setBadge(dnsBadge, "Review", "warning");
    setBadge(dnsPageBadge, "Review", "warning");
    dnsText.textContent = `Mode: ${privacy.privateDns.mode || "unknown"}. Host: ${privacy.privateDns.hostname || "none"}.`;
  }

  scanMeta.textContent = `${privacy.summary.packagesScanned} packages audited with ${privacy.summary.telemetryFindings} known telemetry finding(s).`;
  renderStats(privacy.summary);
  renderOverviewHighlights(privacy.summary, privacy.privateDns);
  renderDnsDetails(privacy.privateDns);
  renderFindings(privacy.telemetryFindings);
  renderSignals(privacy.trackingSignals);
  renderPermissionAudit(privacy.permissionAudit);

  scanButton.disabled = false;
  scanButton.textContent = "Scan device";
  scanButton.classList.remove("is-loading");
}

async function handlePackageAction(button) {
  const packageName = button.dataset.package;
  const enabled = button.dataset.enabled === "true";
  const actionLabel = enabled ? "Restoring" : packageActionMode === "uninstall" ? "Uninstalling for current user" : "Disabling";
  const finding = lastFindings.find((item) => item.packageName === packageName);

  if (!finding) return;

  const impactWarning = finding.installedAs === "system app"
    ? "\n\nHigh impact warning: this is a system package. Disabling it can affect OEM features, account services, notifications, or diagnostics."
    : "";
  const uninstallWarning = packageActionMode === "uninstall" && !enabled
    ? "\n\nUninstall mode warning: this removes the package for the current Android user. It is usually reversible with install-existing, but OEM behavior can vary."
    : "";
  const confirmation = window.confirm(
    `${actionLabel} ${finding.name}\n\nPackage: ${packageName}${impactWarning}${uninstallWarning}\n\nCommand:\n${commandFor(finding)}\n\nContinue?`
  );

  if (!confirmation) return;

  actionInProgress = true;
  renderFindings(lastFindings);
  setActionStatus(`${actionLabel} ${packageName}...`, "neutral");

  const result = await window.androidGuard.setPackageEnabled({ packageName, enabled, actionMode: packageActionMode });

  if (result.ok) {
    setActionStatus(`${packageName} ${enabled ? "enabled" : "disabled"}. Rescanning device...`, "success");
    await runScan();
    await renderHistory();
    setActionStatus(`${packageName} ${enabled ? "enabled" : "disabled"} successfully.`, "success");
  } else {
    setActionStatus(shortError(result.error || `Failed to update ${packageName}.`), "danger");
  }

  actionInProgress = false;
  renderFindings(lastFindings);
}

async function handleAppOpAction(button) {
  const packageName = button.dataset.package;
  const signalId = button.dataset.signal;
  const label = button.dataset.label;
  const app = lastPermissionAudit.find((item) => item.packageName === packageName);
  const signal = app?.signals.find((item) => item.id === signalId);

  if (!app || !signal) return;

  const highImpact = ["contacts", "sms", "phone_state", "overlay"].includes(signalId)
    ? "\n\nHigh impact warning: denying this access may break sign-in, messaging, payments, calls, overlays, or account recovery flows."
    : "";
  const confirmation = window.confirm(
    `Deny ${label} for ${packageName}?\n\nThis uses Android app-ops and can break app features that depend on this access.${highImpact}\n\nCommand:\nadb shell cmd appops set --user 0 ${packageName} ${signal.op} deny\n\nContinue?`
  );

  if (!confirmation) return;

  appActionInProgress = true;
  renderPermissionAudit(lastPermissionAudit);
  setAppActionStatus(`Denying ${label} for ${packageName}...`, "neutral");

  const result = await window.androidGuard.setAppOpMode({
    packageName,
    signalId,
    mode: "deny"
  });

  if (result.ok) {
    setAppActionStatus(`${label} denied for ${packageName}. Rescanning device...`, "success");
    await runScan();
    await renderHistory();
    setAppActionStatus(`${label} denied for ${packageName}.`, "success");
  } else {
    setAppActionStatus(shortError(result.error || `Failed to update ${packageName}.`), "danger");
  }

  appActionInProgress = false;
  renderPermissionAudit(lastPermissionAudit);
}

async function handleAppUninstall(button) {
  const packageName = button.dataset.uninstallPackage;
  const app = lastPermissionAudit.find((item) => item.packageName === packageName);
  if (!app) return;

  const confirmation = window.confirm(
    `Uninstall ${app.label || packageName} for the current Android user?\n\nPackage: ${packageName}\n\nThis removes a user-installed app. DroidSentinel may not be able to restore it automatically; reinstall from the original source if needed.\n\nCommand:\nadb shell pm uninstall --user 0 ${packageName}\n\nContinue?`
  );
  if (!confirmation) return;

  appActionInProgress = true;
  renderPermissionAudit(lastPermissionAudit);
  setAppActionStatus(`Uninstalling ${packageName}...`, "neutral");

  const result = await window.androidGuard.uninstallUserApp({ packageName });

  if (result.ok) {
    setAppActionStatus(`${packageName} uninstalled. Rescanning device...`, "success");
    await runScan();
    await renderHistory();
    setAppActionStatus(`${packageName} uninstalled for current user.`, "success");
  } else {
    setAppActionStatus(shortError(result.error || `Failed to uninstall ${packageName}.`), "danger");
  }

  appActionInProgress = false;
  renderPermissionAudit(lastPermissionAudit);
}

async function handleHistoryRestore(button) {
  const id = button.dataset.historyId;
  const confirmation = window.confirm("Restore this recorded action?\n\nDroidSentinel will run the stored restore command.");
  if (!confirmation) return;

  setHistoryStatus("Restoring action...", "neutral");
  const result = await window.androidGuard.restoreHistory({ id });

  if (result.ok) {
    setHistoryStatus("Action restored. Rescanning device...", "success");
    await runScan();
    await renderHistory();
    setHistoryStatus("Action restored successfully.", "success");
  } else {
    setHistoryStatus(shortError(result.error || "Failed to restore action."), "danger");
  }
}

async function handleClearHistory() {
  const history = await window.androidGuard.listHistory();
  const activeCount = history.filter((entry) => !entry.restored).length;
  const confirmation = window.confirm(
    `Clear all DroidSentinel action history?\n\n${activeCount} active unrestored action(s) will lose their restore buttons. This does not undo changes already applied to the phone.`
  );
  if (!confirmation) return;

  const result = await window.androidGuard.clearHistory();
  if (result.ok) {
    setHistoryStatus("Action history cleared.", "success");
    await renderHistory();
  } else {
    setHistoryStatus(shortError(result.error || "Failed to clear action history."), "danger");
  }
}

async function handleExportReport() {
  exportButton.disabled = true;
  exportButton.textContent = "Exporting...";
  const result = await window.androidGuard.exportReport();
  exportButton.disabled = false;
  exportButton.textContent = "Export report";

  if (result.ok) {
    window.alert(`Reports exported:\nJSON: ${result.path}\nHTML: ${result.htmlPath}`);
  } else {
    window.alert(result.error || "Could not export report.");
  }
}

async function renderSettings() {
  const settings = await window.androidGuard.getSettings();
  settingsDetails.className = "settings-list";
  settingsDetails.innerHTML = `
    <dl>
      <div><dt>ADB runtime</dt><dd>${escapeHtml(settings.adbPath)}</dd></div>
      <div><dt>Current device</dt><dd>${escapeHtml(settings.deviceSerial)}</dd></div>
      <div><dt>User data</dt><dd>${escapeHtml(settings.userDataPath)}</dd></div>
      <div><dt>Reports folder</dt><dd>${escapeHtml(settings.documentsPath)}</dd></div>
      <div><dt>History entries</dt><dd>${settings.historyCount}</dd></div>
    </dl>
  `;
}

async function applyPrivateDns(mode, hostname = "", restoreState = lastDnsScanState) {
  const label = mode === "hostname" ? hostname : mode === "opportunistic" ? "Automatic" : "Off";
  const confirmation = window.confirm(
    `Set Private DNS to ${label}?\n\nChanging DNS may affect some Wi-Fi networks, captive portals, or work/school networks.`
  );
  if (!confirmation) return;

  setDnsActionStatus(`Setting Private DNS to ${label}...`, "neutral");
  const result = await window.androidGuard.setPrivateDns({ mode, hostname, restoreState });

  if (result.ok) {
    setDnsActionStatus("Private DNS updated. Rescanning device...", "success");
    await runScan();
    await renderHistory();
    setDnsActionStatus("Private DNS updated successfully.", "success");
  } else {
    setDnsActionStatus(shortError(result.error || "Failed to update Private DNS."), "danger");
  }
}

async function revertPrivateDns() {
  if (!lastDnsScanState) {
    setDnsActionStatus("Run a scan before reverting Private DNS.", "danger");
    return;
  }

  const mode = lastDnsScanState.mode && lastDnsScanState.mode !== "null"
    ? lastDnsScanState.mode
    : "opportunistic";
  const hostname = lastDnsScanState.hostname && lastDnsScanState.hostname !== "null"
    ? lastDnsScanState.hostname
    : "";

  await applyPrivateDns(mode, hostname, lastDnsScanState);
}

filterButtons.forEach((button) => {
  button.addEventListener("click", () => {
    activeFilter = button.dataset.filter;
    filterButtons.forEach((item) => item.classList.toggle("active", item === button));
    renderFindings(lastFindings);
  });
});

packageActionModeInputs.forEach((input) => {
  input.addEventListener("change", () => {
    packageActionMode = input.value;
    localStorage.setItem("packageActionMode", packageActionMode);
    renderFindings(lastFindings);
  });
});

appSearch.addEventListener("input", () => {
  appSearchQuery = appSearch.value;
  renderPermissionAudit(lastPermissionAudit);
});

navItems.forEach((item) => {
  item.addEventListener("click", () => {
    switchView(item.dataset.view);
    if (item.dataset.view === "settings") renderSettings();
  });
});

findingsList.addEventListener("click", (event) => {
  const button = event.target.closest(".action-button");
  if (!button || actionInProgress) return;
  handlePackageAction(button);
});

appAuditList.addEventListener("click", (event) => {
  const uninstallButton = event.target.closest("[data-uninstall-package]");
  if (uninstallButton || appActionInProgress) {
    if (uninstallButton && !appActionInProgress) handleAppUninstall(uninstallButton);
    return;
  }
  const button = event.target.closest(".mini-action");
  if (!button || appActionInProgress) return;
  handleAppOpAction(button);
});

historyList.addEventListener("click", (event) => {
  const button = event.target.closest("[data-history-id]");
  if (!button) return;
  handleHistoryRestore(button);
});

clearHistoryButton.addEventListener("click", handleClearHistory);
settingsClearHistoryButton.addEventListener("click", handleClearHistory);
settingsRefreshButton.addEventListener("click", renderSettings);
exportButton.addEventListener("click", handleExportReport);
exitButton.addEventListener("click", () => window.androidGuard.quitApp());
dnsActionButtons.forEach((button) => {
  button.addEventListener("click", () => {
    applyPrivateDns(button.dataset.mode, button.dataset.hostname || "");
  });
});
customDnsButton.addEventListener("click", () => {
  applyPrivateDns("hostname", customDns.value.trim());
});
revertDnsButton.addEventListener("click", revertPrivateDns);
scanButton.addEventListener("click", runScan);
enterAppButton.addEventListener("click", () => enterApp("overview"));
landingScanButton.addEventListener("click", () => {
  enterApp("overview");
  runScan();
});
renderHistory();
renderLandingStatus();
const savedPackageActionMode = localStorage.getItem("packageActionMode");
if (savedPackageActionMode === "disable" || savedPackageActionMode === "uninstall") {
  packageActionMode = savedPackageActionMode;
  packageActionModeInputs.forEach((input) => {
    input.checked = input.value === packageActionMode;
  });
}
runScan();
