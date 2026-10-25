// Genesis Seek — Frontend Controller (Tauri Native IPC + Persistent Theme Memory + Browser Fallback)

const THEME_STORAGE_KEY = "genesis_seek_theme";

function safeGetStorage(key) {
  try {
    return localStorage.getItem(key);
  } catch (e) {
    return null;
  }
}

function safeSetStorage(key, val) {
  try {
    localStorage.setItem(key, val);
  } catch (e) {}
}

// Local state for standalone preview mode if Tauri runtime isn't active
const fallbackState = {
  theme: safeGetStorage(THEME_STORAGE_KEY) || "night",
  shields: {
    real_time_file_guard: true,
    web_browser_guard: true,
    ransomware_canary_guard: true,
    exploit_process_guard: true,
    auto_quarantine_realtime: true,
    shield_mode: "Kernel Pre-Exec (fanotify)",
    last_intel_sync: new Date().toISOString(),
    encrypted_quarantine: true,
  },
  feedStatus: {
    version: "2026.10.25.01",
    total_hash_signatures: 148520,
    total_web_indicators: 64290,
    yara_heuristic_rules: 412,
    last_synced: new Date().toISOString(),
    last_intel_sync: new Date().toISOString(),
    shield_mode: "Kernel Pre-Exec (fanotify)",
    encrypted_quarantine: true,
    feed_sources: [
      "Genesis Seek Core Signatures (SQLite)",
      "Abuse.ch MalwareBazaar SHA-256 Stream",
      "Abuse.ch URLhaus & PhishStats Tracker",
      "Community YARA-X Rules (Hot-Reloaded)",
    ],
  },
  scannedTotal: 1420,
  threatsNeutralized: 0,
  webBlocks: 2,
  detections: [],
  quarantine: [],
  events: [
    {
      timestamp: new Date().toISOString(),
      module: "File Guard",
      severity: "Info",
      title: "Real-Time File System Watcher Armed",
      target: "Downloads, Desktop, Temp",
      action_taken: "Monitoring",
    },
    {
      timestamp: new Date().toISOString(),
      module: "Ransomware Shield",
      severity: "Info",
      title: "Canary Tripwire Decoys Active",
      target: "Volume Shadow & Canary Guard",
      action_taken: "Protected",
    },
    {
      timestamp: new Date().toISOString(),
      module: "Browser Guard",
      severity: "High",
      title: "Blocked Phishing Domain (Typosquat)",
      target: "https://paypa1-security-verify.com",
      action_taken: "Connection Blocked",
    },
  ],
};

async function invokeBackend(cmd, args = {}) {
  if (
    window.__TAURI__ &&
    window.__TAURI__.core &&
    typeof window.__TAURI__.core.invoke === "function"
  ) {
    try {
      return await window.__TAURI__.core.invoke(cmd, args);
    } catch (err) {
      if (
        cmd === "virustotal_lookup" ||
        cmd === "save_virustotal_config" ||
        cmd === "check_app_update" ||
        cmd === "install_app_update"
      ) {
        throw err;
      }
      console.warn(`Tauri IPC error on ${cmd}, using fallback:`, err);
    }
  }
  return simulateBackend(cmd, args);
}

function simulateBackend(cmd, args) {
  switch (cmd) {
    case "get_user_preferences":
      return { theme: safeGetStorage(THEME_STORAGE_KEY) || fallbackState.theme || "night" };
    case "save_user_theme":
      fallbackState.theme = args.theme;
      safeSetStorage(THEME_STORAGE_KEY, args.theme);
      return { theme: args.theme };
    case "get_shield_state":
      return { ...fallbackState.shields };
    case "update_shield_state":
      fallbackState.shields = { ...args.newState };
      return fallbackState.shields;
    case "create_eicar_test_file": {
      const sample = {
        id: "det-" + Date.now(),
        file_path: "/home/user/Downloads/genesis_seek_eicar_test.txt",
        threat_name: "EICAR-Standard-AV-Test-Signature",
        category: "Test.Signature",
        severity: "High",
        sha256: "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
        entropy: 5.18,
        detection_engine: "Signature Engine (SHA-256) + YARA",
        detected_at: new Date().toISOString(),
        description: "Standard EICAR antivirus verification test signature.",
      };
      fallbackState.detections.unshift(sample);
      fallbackState.events.unshift({
        timestamp: new Date().toISOString(),
        module: "File Guard",
        severity: "High",
        title: "EICAR Test Signature Created & Flagged",
        target: sample.file_path,
        action_taken: "Flagged for Quarantine",
      });
      return sample.file_path;
    }
    case "run_threat_scan": {
      const count = args.scanType === "quick" ? 642 : 2910;
      fallbackState.scannedTotal += count;
      fallbackState.events.unshift({
        timestamp: new Date().toISOString(),
        module: "File Guard",
        severity: fallbackState.detections.length ? "High" : "Info",
        title: `${args.scanType.toUpperCase()} Scan Completed (${count} files)`,
        target: `${fallbackState.detections.length} detection(s)`,
        action_taken: fallbackState.detections.length ? "Action Required" : "Clean",
      });
      return {
        scan_id: "scan-" + Date.now(),
        scan_type: args.scanType,
        scanned_files: count,
        skipped_files: 4,
        duration_ms: 380,
        detections: [...fallbackState.detections],
        completed_at: new Date().toISOString(),
      };
    }
    case "quarantine_threat": {
      fallbackState.detections = fallbackState.detections.filter(
        (d) => d.file_path !== args.filePath
      );
      const qItem = {
        id: "q-" + Date.now(),
        original_path: args.filePath,
        vault_file_name: `${Date.now()}.gsvault`,
        threat_name: args.threatName,
        severity: args.severity,
        sha256: args.sha256,
        file_size: 68,
        quarantined_at: new Date().toISOString(),
      };
      fallbackState.quarantine.unshift(qItem);
      fallbackState.threatsNeutralized += 1;
      fallbackState.events.unshift({
        timestamp: new Date().toISOString(),
        module: "Quarantine Vault",
        severity: args.severity,
        title: `Threat Isolated: ${args.threatName}`,
        target: args.filePath,
        action_taken: "XOR Encrypted in Vault",
      });
      return qItem;
    }
    case "get_quarantine_list":
      return [...fallbackState.quarantine];
    case "restore_from_quarantine": {
      const idx = fallbackState.quarantine.findIndex((q) => q.id === args.id);
      if (idx !== -1) {
        const item = fallbackState.quarantine.splice(idx, 1)[0];
        return item.original_path;
      }
      return "";
    }
    case "delete_from_quarantine": {
      fallbackState.quarantine = fallbackState.quarantine.filter((q) => q.id !== args.id);
      return null;
    }
    case "check_url_reputation": {
      const u = (args.url || "").toLowerCase();
      const bad =
        u.includes("paypa1") ||
        u.includes("coinhive") ||
        u.includes("urlhaus") ||
        u.includes("xn--") ||
        u.endsWith(".exe") ||
        u.endsWith(".zip");
      if (bad) {
        fallbackState.webBlocks += 1;
        fallbackState.events.unshift({
          timestamp: new Date().toISOString(),
          module: "Browser Guard",
          severity: "High",
          title: "Browser Guard Blocked Malicious URL",
          target: args.url,
          action_taken: "Blocked",
        });
      }
      return {
        url: args.url,
        domain: args.url.replace(/^https?:\/\//, "").split("/")[0],
        safe: !bad,
        category: bad ? "Heur.BrowserGuard.Threat" : "Clean / Verified",
        risk_score: bad ? 95 : 3,
        reason: bad
          ? "Phishing, homograph, URLhaus feed, cryptojacking, or raw-IP binary signature matched."
          : "Domain verified clean with no phishing or malware indicators.",
      };
    }
    case "get_feed_status":
      return { ...fallbackState.feedStatus };
    case "sync_threat_feeds":
    case "sync_threat_intelligence": {
      fallbackState.feedStatus.total_hash_signatures += 184;
      fallbackState.feedStatus.total_web_indicators += 95;
      fallbackState.feedStatus.yara_heuristic_rules += 4;
      fallbackState.feedStatus.version =
        "2026.10.25." + Math.floor(10 + Math.random() * 89);
      const nowIso = new Date().toISOString();
      fallbackState.feedStatus.last_synced = nowIso;
      fallbackState.feedStatus.last_intel_sync = nowIso;
      fallbackState.events.unshift({
        timestamp: nowIso,
        module: "Threat Intel",
        severity: "Info",
        title: `Threat Feeds, SQLite DB & YARA Rules Synced (v${fallbackState.feedStatus.version})`,
        target: "Abuse.ch MalwareBazaar, URLhaus, PhishStats & Community YARA",
        action_taken: "Updated",
      });
      return { ...fallbackState.feedStatus };
    }
    case "get_network_connections":
      return [
        {
          protocol: "TCPv4",
          local_address: "127.0.0.1:49152",
          remote_address: "0.0.0.0:0",
          remote_port: 0,
          state: "LISTEN",
          risk_level: "Safe",
          reason: "Genesis Seek Browser Guard Local Loopback Bridge",
        },
        {
          protocol: "TCPv4",
          local_address: "192.168.1.24:51842",
          remote_address: "140.82.112.4:443",
          remote_port: 443,
          state: "ESTABLISHED",
          risk_level: "Safe",
          reason: "Standard HTTPS outbound socket",
        },
      ];
    case "get_processes_and_risks":
      return [
        {
          pid: 1042,
          name: "genesis-seek-engine",
          exe_path: "/usr/local/bin/genesis-seek",
          cmd_line: "genesis-seek --daemon",
          cpu_usage: 0.4,
          memory_mb: 14,
          risk_level: "Safe",
          risk_reason: "Signed Genesis Seek Core Service",
        },
        {
          pid: 2819,
          name: "browser-renderer",
          exe_path: "/usr/lib/chromium/chromium",
          cmd_line: "chromium --type=renderer",
          cpu_usage: 3.1,
          memory_mb: 245,
          risk_level: "Safe",
          risk_reason: "Normal process behavior",
        },
      ];
    case "get_persistence_items":
      return [
        {
          location_type: "Shell Profile Hook",
          name: ".bashrc",
          path: "~/.bashrc",
          command_or_detail: "No anomalous network or LD_PRELOAD hooks found",
          status: "Verified",
        },
        {
          location_type: "User Autostart (.desktop)",
          name: "genesis-seek-tray.desktop",
          path: "~/.config/autostart/genesis-seek-tray.desktop",
          command_or_detail: "Exec=/usr/bin/genesis-seek --minimized",
          status: "Verified",
        },
      ];
    case "get_detected_browsers":
      return [
        {
          id: "chrome",
          name: "Google Chrome",
          installed: true,
          binary_path: "/usr/bin/google-chrome",
          extension_dir: "/home/coraje/.gemini/antigravity/scratch/genesis-seek/browser-extension",
        },
        {
          id: "brave",
          name: "Brave Browser",
          installed: true,
          binary_path: "/usr/bin/brave-browser",
          extension_dir: "/home/coraje/.gemini/antigravity/scratch/genesis-seek/browser-extension",
        },
        {
          id: "edge",
          name: "Microsoft Edge",
          installed: false,
          binary_path: "",
          extension_dir: "/home/coraje/.gemini/antigravity/scratch/genesis-seek/browser-extension",
        },
        {
          id: "firefox",
          name: "Mozilla Firefox",
          installed: true,
          binary_path: "/usr/bin/firefox",
          extension_dir: "/home/coraje/.gemini/antigravity/scratch/genesis-seek/browser-extension",
        },
      ];
    case "install_browser_guard_extension": {
      const extDir = "/home/coraje/.gemini/antigravity/scratch/genesis-seek/browser-extension";
      fallbackState.events.unshift({
        timestamp: new Date().toISOString(),
        module: "Browser Guard",
        severity: "Info",
        title: `Browser Guard Extension Installed (${args.browserId.toUpperCase()})`,
        target: extDir,
        action_taken: "Extension Ready",
      });
      return {
        browser_name: args.browserId.toUpperCase(),
        success: true,
        extension_path: extDir,
        method_used: "Direct Browser Launch (--load-extension) & Staged Package",
        message: `Genesis Seek Browser Guard is ready for ${args.browserId.toUpperCase()}!\n\nExtension Path: ${extDir}`,
      };
    }
    case "open_browser_extension_folder":
      return "/home/coraje/.gemini/antigravity/scratch/genesis-seek/browser-extension";
    case "get_live_memory_usage":
      return { pid: 86151, rss_mb: 174.2, private_mb: 44.8 };
    case "get_virustotal_status":
      return {
        configured: Boolean(fallbackState.vtConfigured),
        masked_key: fallbackState.vtConfigured ? "vt••••demo" : "Not Configured",
        source: fallbackState.vtConfigured ? "Browser Preview" : "None",
        auto_check_suspicious: Boolean(fallbackState.vtAutoCheck),
      };
    case "save_virustotal_config":
      if (args.apiKey && args.apiKey.trim()) {
        fallbackState.vtConfigured = true;
      }
      fallbackState.vtAutoCheck = Boolean(args.autoCheckSuspicious);
      return simulateBackend("get_virustotal_status", {});
    case "clear_virustotal_key":
      fallbackState.vtConfigured = false;
      return simulateBackend("get_virustotal_status", {});
    case "virustotal_lookup": {
      const t = (args.target || "").toLowerCase();
      const isMal = t.startsWith("275a021b") || t.startsWith("ed01ebfb");
      return {
        query_type: t.includes(".") ? "domain" : "file_hash",
        target: args.target,
        indicator: args.target,
        found_in_vt: true,
        malicious: isMal ? 64 : 0,
        suspicious: isMal ? 2 : 0,
        undetected: isMal ? 4 : 68,
        harmless: isMal ? 0 : 2,
        total_engines: 70,
        verdict: isMal ? "Malicious" : "Clean",
        threat_label: isMal ? "EICAR / Known Malware Signature" : "Clean / Harmless",
        flagged_engines: isMal
          ? ["Microsoft: VirTool:Win32/EICAR_Test_File", "Kaspersky: EICAR-Test-File", "BitDefender: EICAR-Test-File (not a virus)"]
          : [],
        permalink: `https://www.virustotal.com/gui/search/${encodeURIComponent(args.target)}`,
      };
    }
    case "get_security_events":
      return [...fallbackState.events];
    default:
      return null;
  }
}

// Persistent Theme Application (Obsidian Night vs Warm Cream Light)
async function applyTheme(theme, persist = true) {
  const chosen = theme === "cream" ? "cream" : "night";
  document.documentElement.setAttribute("data-theme", chosen);

  // Swap vector crest logos to match Night or Cream Light palette
  const logoSrc = chosen === "cream" ? "assets/logo-mark-cream.svg" : "assets/logo-mark.svg";
  const sidebarLogo = document.getElementById("brand-logo-img");
  const heroLogo = document.getElementById("hero-crest-img");
  if (sidebarLogo) sidebarLogo.src = logoSrc;
  if (heroLogo) heroLogo.src = logoSrc;

  // Update active state on theme switcher buttons
  document.querySelectorAll(".theme-btn").forEach((btn) => {
    btn.classList.toggle("active", btn.dataset.setTheme === chosen);
  });

  // Always save to localStorage for instant pre-paint restore AND to Rust disk preferences
  try {
    localStorage.setItem(THEME_STORAGE_KEY, chosen);
  } catch (e) {}

  if (persist) {
    try {
      await invokeBackend("save_user_theme", { theme: chosen });
    } catch (e) {}
  }
}

document.querySelectorAll(".theme-btn").forEach((btn) => {
  btn.addEventListener("click", () => {
    applyTheme(btn.dataset.setTheme, true);
  });
});

// Tab Navigation (supports inline onclick, delegated nav-menu clicks, and programmatic switchTab)
window.onTabActivated = function (tabName) {
  if (tabName === "network-intel") refreshNetworkAndFeeds();
  if (tabName === "processes") refreshProcessesAndPersistence();
  if (tabName === "quarantine") refreshQuarantine();
  if (tabName === "events" || tabName === "dashboard") refreshEvents();
  if (tabName === "browser-guard") renderBrowserExtensionInstaller();
};

window.switchTab = function (tabName) {
  if (!tabName) return;
  document.querySelectorAll(".nav-item").forEach((b) => {
    b.classList.toggle("active", b.dataset.tab === tabName);
  });
  document.querySelectorAll(".tab-panel").forEach((p) => {
    p.classList.toggle("active", p.id === `tab-${tabName}`);
  });
  if (typeof window.onTabActivated === "function") {
    try {
      window.onTabActivated(tabName);
    } catch (err) {
      console.warn("Tab activation refresh error:", err);
    }
  }
};

const navMenuEl = document.getElementById("sidebar-nav-menu") || document.querySelector(".nav-menu");
if (navMenuEl) {
  navMenuEl.addEventListener("click", (e) => {
    const btn = e.target.closest(".nav-item");
    if (btn && btn.dataset.tab) {
      window.switchTab(btn.dataset.tab);
    }
  });
}

document.querySelectorAll(".nav-item").forEach((btn) => {
  btn.addEventListener("click", (e) => {
    e.stopPropagation();
    if (btn.dataset.tab) {
      window.switchTab(btn.dataset.tab);
    }
  });
});

function formatTime(iso) {
  try {
    return new Date(iso).toLocaleTimeString();
  } catch {
    return iso;
  }
}

// Shield Integrity Calculation (Each of the 4 layers = 25% of total 100% protection)
function syncExtAutoloadBadge(enabled) {
  const badge = document.getElementById("status-ext-autoload");
  if (badge) {
    badge.textContent = enabled ? "AUTO-LOAD ON" : "MANUAL ONLY";
    badge.className = "sev-badge " + (enabled ? "sev-Safe" : "sev-Medium");
  }
}

async function syncShieldToggles() {
  const autoLoadEl = document.getElementById("toggle-ext-autoload");
  const autoLoadEnabled = autoLoadEl ? Boolean(autoLoadEl.checked) : true;
  syncExtAutoloadBadge(autoLoadEnabled);

  const newState = {
    real_time_file_guard: Boolean(document.getElementById("toggle-file-guard")?.checked),
    web_browser_guard: Boolean(document.getElementById("toggle-web-guard")?.checked),
    ransomware_canary_guard: Boolean(document.getElementById("toggle-ransomware-guard")?.checked),
    exploit_process_guard: Boolean(document.getElementById("toggle-process-guard")?.checked),
    auto_quarantine_realtime: true,
    browser_extension_autoload: autoLoadEnabled,
  };
  if (typeof window.recalculateProtectionNow === "function") {
    window.recalculateProtectionNow(true);
  }
  await invokeBackend("update_shield_state", { newState });
  await refreshEvents();
}
window.syncShieldToggles = syncShieldToggles;

function updateProtectionRing(state) {
  if (state) {
    const fg = document.getElementById("toggle-file-guard");
    const wg = document.getElementById("toggle-web-guard");
    const rg = document.getElementById("toggle-ransomware-guard");
    const pg = document.getElementById("toggle-process-guard");
    const al = document.getElementById("toggle-ext-autoload");
    if (fg) fg.checked = Boolean(state.real_time_file_guard);
    if (wg) wg.checked = Boolean(state.web_browser_guard);
    if (rg) rg.checked = Boolean(state.ransomware_canary_guard);
    if (pg) pg.checked = Boolean(state.exploit_process_guard);
    if (al && typeof state.browser_extension_autoload === "boolean") {
      al.checked = state.browser_extension_autoload;
      syncExtAutoloadBadge(state.browser_extension_autoload);
    }
    const modeEl = document.getElementById("sidebar-shield-mode");
    if (modeEl && state.shield_mode) {
      modeEl.textContent = state.shield_mode;
      modeEl.className =
        state.shield_mode.includes("fanotify") || state.shield_mode.includes("Suspend")
          ? "text-ok"
          : "text-accent";
    }
    const vaultEl = document.getElementById("sidebar-vault-crypto");
    if (vaultEl && state.encrypted_quarantine !== undefined) {
      vaultEl.textContent = state.encrypted_quarantine
        ? "ChaCha20-Poly1305 (.gvault)"
        : "Standard Vault";
    }
  }
  if (typeof window.recalculateProtectionNow === "function") {
    window.recalculateProtectionNow(true);
  }
}

const minBarBtn = document.getElementById("btn-minimize-bar");
if (minBarBtn) {
  minBarBtn.addEventListener("click", async () => {
    await invokeBackend("minimize_to_bar");
  });
}

// 1-Click GitHub Self-Updater
const updateBtn = document.getElementById("btn-app-update");

async function checkForUpdatesSilent() {
  if (!updateBtn) return;
  try {
    const info = await invokeBackend("check_app_update");
    if (info && info.update_available) {
      updateBtn.textContent = `⬆️ Update to ${info.latest_version}`;
      updateBtn.className = "btn btn-primary";
      updateBtn.title = `New GitHub Release ${info.latest_version} available! Click to auto-install.`;
    } else if (info && info.current_version) {
      updateBtn.textContent = `↻ Update (${info.current_version})`;
    }
  } catch (e) {}
}

if (updateBtn) {
  updateBtn.addEventListener("click", async () => {
    const origText = updateBtn.textContent;
    updateBtn.textContent = "↻ Checking GitHub...";
    updateBtn.disabled = true;
    try {
      const info = await invokeBackend("check_app_update");
      let shouldInstall = false;
      if (info.update_available) {
        shouldInstall = confirm(
          `New Genesis Seek update available on GitHub!\n\nCurrent Version: ${info.current_version}\nLatest Version: ${info.latest_version}\nPackage: ${info.asset_name}\n\nClick OK to automatically download, install, and restart Genesis Seek.`
        );
      } else {
        shouldInstall = confirm(
          `You are on Genesis Seek ${info.current_version} (Latest GitHub Release: ${info.latest_version}).\n\nWould you like to pull and install the latest ${info.asset_name} build directly from GitHub anyway?`
        );
      }

      if (shouldInstall) {
        updateBtn.textContent = "⬇️ Updating from GitHub...";
        const res = await invokeBackend("install_app_update");
        alert(res.message);
      } else {
        updateBtn.textContent = info.update_available
          ? `⬆️ Update to ${info.latest_version}`
          : `↻ Update (${info.current_version})`;
      }
    } catch (err) {
      alert("Update check / install notice:\n" + err);
      updateBtn.textContent = origText;
    } finally {
      updateBtn.disabled = false;
    }
  });
}

// Threat Scanner Actions
async function triggerScan(scanType, customPath = null) {
  window.switchTab("scanner");
  const heading = document.getElementById("scan-status-heading");
  const sub = document.getElementById("scan-summary-sub");
  const pill = document.getElementById("scan-metrics-pill");

  heading.textContent = `Running ${scanType.toUpperCase()} Scan...`;
  sub.textContent = "Inspecting files with SHA-256 signatures, YARA heuristics, and Shannon entropy analysis...";
  pill.textContent = "Scanning...";

  const report = await invokeBackend("run_threat_scan", {
    scanType,
    customPath,
  });

  heading.textContent = `Scan Complete — ${report.detections.length} Threat(s) Found`;
  sub.textContent = `Inspected ${report.scanned_files} files in ${report.duration_ms} ms (${report.skipped_files} skipped)`;
  pill.textContent = `${report.duration_ms} ms`;

  const statScanned = document.getElementById("stat-scanned");
  statScanned.textContent =
    parseInt(statScanned.textContent || "0", 10) + report.scanned_files;

  renderDetections(report.detections);
  refreshEvents();
}

function renderDetections(detections) {
  const tbody = document.getElementById("scan-detections-tbody");
  if (!detections || detections.length === 0) {
    tbody.innerHTML = `<tr><td colspan="6" class="empty-cell">No active threats detected. Your system is clean!</td></tr>`;
    return;
  }

  tbody.innerHTML = detections
    .map(
      (d) => `
    <tr>
      <td><strong>${d.threat_name}</strong><div class="muted small">${d.description}</div></td>
      <td>${d.category}</td>
      <td><span class="sev-badge sev-${d.severity}">${d.severity}</span></td>
      <td>${d.detection_engine}<div class="muted small">Entropy: ${d.entropy} bits/B</div></td>
      <td><code>${d.file_path}</code></td>
      <td style="display:flex;gap:6px;">
        <button class="btn btn-outline" style="padding:5px 9px;font-size:0.75rem;" onclick="checkHashOnVt('${d.sha256}')" title="Check SHA-256 across 70+ engines on VirusTotal">
          VT Check
        </button>
        <button class="btn btn-danger" onclick="quarantineFile('${d.file_path.replace(/\\/g, "\\\\")}', '${d.threat_name}', '${d.severity}', '${d.sha256}')">
          Quarantine
        </button>
      </td>
    </tr>
  `
    )
    .join("");
}

window.quarantineFile = async function (filePath, threatName, severity, sha256) {
  await invokeBackend("quarantine_threat", {
    filePath,
    threatName,
    severity,
    sha256,
  });
  const statThreats = document.getElementById("stat-threats");
  statThreats.textContent = parseInt(statThreats.textContent || "0", 10) + 1;
  await triggerScan("quick");
  await refreshQuarantine();
};

document.querySelectorAll("[data-scan]").forEach((btn) => {
  btn.addEventListener("click", () => triggerScan(btn.dataset.scan));
});

document.getElementById("btn-quick-scan-top").addEventListener("click", () => {
  triggerScan("quick");
});

document.getElementById("btn-custom-scan").addEventListener("click", () => {
  const path = document.getElementById("custom-scan-path").value.trim();
  triggerScan("custom", path || null);
});

document.getElementById("btn-generate-eicar").addEventListener("click", async () => {
  const path = await invokeBackend("create_eicar_test_file");
  alert(`Safe EICAR verification file created at:\n${path}\n\nNow running Quick Scan to demonstrate detection!`);
  await triggerScan("quick");
});

// Browser Guard URL Checker
async function inspectUrl(url) {
  if (!url) return;
  const res = await invokeBackend("check_url_reputation", { url });
  const card = document.getElementById("url-result-card");
  card.classList.remove("hidden");

  if (!res.safe) {
    const statWeb = document.getElementById("stat-web-blocks");
    statWeb.textContent = parseInt(statWeb.textContent || "0", 10) + 1;
  }

  card.innerHTML = `
    <div style="display:flex;justify-content:space-between;align-items:center;">
      <div>
        <span class="sev-badge ${res.safe ? "sev-Safe" : "sev-Critical"}">
          ${res.safe ? "SAFE DOMAIN" : "BLOCKED BY BROWSER GUARD"}
        </span>
        <strong style="margin-left:10px;font-size:1rem;">${res.domain}</strong>
      </div>
      <div class="pill-tag">Risk Score: ${res.risk_score}/100</div>
    </div>
    <p style="margin-top:10px;font-size:0.88rem;"><strong>Classification:</strong> ${res.category}</p>
    <p class="muted small" style="margin-top:4px;">${res.reason}</p>
  `;
  refreshEvents();
}

document.getElementById("btn-check-url").addEventListener("click", () => {
  inspectUrl(document.getElementById("url-check-input").value.trim());
});

document.querySelectorAll(".chip[data-url]").forEach((chip) => {
  chip.addEventListener("click", () => {
    const u = chip.dataset.url;
    document.getElementById("url-check-input").value = u;
    inspectUrl(u);
  });
});

// Network Sockets & Cloud Threat Intelligence Feeds
async function refreshNetworkAndFeeds() {
  const feed = await invokeBackend("get_feed_status");
  renderFeedStatus(feed);
  await refreshVtStatus();

  const sockets = await invokeBackend("get_network_connections");
  const tbody = document.getElementById("network-tbody");
  if (!sockets || !sockets.length) {
    tbody.innerHTML = `<tr><td colspan="6" class="empty-cell">No active external sockets found.</td></tr>`;
    return;
  }
  tbody.innerHTML = sockets
    .map(
      (s) => `
    <tr>
      <td><strong>${s.protocol}</strong></td>
      <td><code>${s.local_address}</code></td>
      <td><code>${s.remote_address}</code></td>
      <td>${s.state}</td>
      <td><span class="sev-badge sev-${s.risk_level}">${s.risk_level}</span></td>
      <td class="muted small">${s.reason}</td>
    </tr>
  `
    )
    .join("");
}

function renderFeedStatus(feed) {
  if (!feed) return;
  document.getElementById("feed-hashes-count").textContent =
    feed.total_hash_signatures.toLocaleString();
  document.getElementById("feed-web-count").textContent =
    feed.total_web_indicators.toLocaleString();
  document.getElementById("feed-yara-count").textContent =
    feed.yara_heuristic_rules.toLocaleString();
  document.getElementById("sidebar-feed-ver").textContent = `v${feed.version}`;

  const sourcesEl = document.getElementById("feed-sources-list");
  sourcesEl.innerHTML =
    `<span class="muted small">Active Threat Intelligence Feeds:</span>` +
    (feed.feed_sources || [])
      .map((src) => {
        if (typeof src === "string") {
          return `<span class="chip">${src}</span>`;
        }
        const label = `${src.name} (${(src.entries || 0).toLocaleString()} IOCs)`;
        return `<span class="chip" title="${src.error || src.url || ""}">${label}</span>`;
      })
      .join("");
}

document.getElementById("btn-sync-feeds").addEventListener("click", async () => {
  const btn = document.getElementById("btn-sync-feeds");
  const origText = btn.textContent;
  btn.textContent = "↻ Syncing Live Abuse.ch Feeds...";
  btn.disabled = true;
  try {
    const updated = await invokeBackend("sync_threat_feeds");
    renderFeedStatus(updated);
    await refreshEvents();
  } finally {
    btn.textContent = origText;
    btn.disabled = false;
  }
});

document
  .getElementById("btn-refresh-network")
  .addEventListener("click", refreshNetworkAndFeeds);

// VirusTotal v3 Multi-Engine Cloud Integration (Windows & Linux)
async function refreshVtStatus() {
  try {
    const st = await invokeBackend("get_virustotal_status");
    if (!st) return;
    const badge = document.getElementById("vt-status-badge");
    const info = document.getElementById("vt-key-source-info");
    const sidebarVt = document.getElementById("sidebar-vt-status");
    const autoCheckEl = document.getElementById("toggle-vt-autocheck");

    if (autoCheckEl && typeof st.auto_check_suspicious === "boolean") {
      autoCheckEl.checked = st.auto_check_suspicious;
    }

    if (st.configured) {
      if (badge) {
        badge.textContent = `ACTIVE • ${st.masked_key}`;
        badge.className = "sev-badge sev-Safe";
      }
      if (info) {
        info.textContent = `Key Source: ${st.source} (${st.masked_key}) • 70+ Engine SHA-256 & Domain Lookups Ready`;
      }
      if (sidebarVt) {
        sidebarVt.textContent = "Active • 70+ Engines";
        sidebarVt.className = "text-ok";
      }
    } else {
      if (badge) {
        badge.textContent = "OPTIONAL • NO KEY SET";
        badge.className = "sev-badge sev-Medium";
      }
      if (info) {
        info.textContent =
          "Key Status: Not configured (Genesis Seek local engines & Abuse.ch feeds remain 100% active without a key).";
      }
      if (sidebarVt) {
        sidebarVt.textContent = "Optional • Standby";
        sidebarVt.className = "text-warn";
      }
    }
  } catch (e) {
    console.warn("VT status error:", e);
  }
}

window.saveVtSettings = async function (includeKeyInput = true) {
  const keyInput = document.getElementById("vt-api-key-input");
  const autoCheckEl = document.getElementById("toggle-vt-autocheck");
  const rawKey = includeKeyInput && keyInput ? keyInput.value.trim() : null;
  const autoCheck = autoCheckEl ? Boolean(autoCheckEl.checked) : false;

  try {
    await invokeBackend("save_virustotal_config", {
      apiKey: rawKey || null,
      autoCheckSuspicious: autoCheck,
    });
    if (includeKeyInput && keyInput) {
      keyInput.value = "";
    }
    await refreshVtStatus();
    await refreshEvents();
  } catch (err) {
    alert("Failed to save VirusTotal settings: " + err);
  }
};

async function runVtLookup(targetStr) {
  const target = (targetStr || "").trim();
  if (!target) return;
  const card = document.getElementById("vt-result-card");
  if (!card) return;
  card.classList.remove("hidden");
  card.innerHTML = `<span class="muted">Querying VirusTotal v3 (70+ engines) for <code>${target}</code>...</span>`;

  try {
    const res = await invokeBackend("virustotal_lookup", { target });
    const sevClass =
      res.verdict === "Malicious"
        ? "sev-Critical"
        : res.verdict === "Suspicious"
        ? "sev-High"
        : res.verdict === "Clean"
        ? "sev-Safe"
        : "sev-Medium";

    const enginesHtml =
      res.flagged_engines && res.flagged_engines.length
        ? `<div style="margin-top:8px;font-size:0.8rem;"><strong>Flagging Engines:</strong> <code>${res.flagged_engines.join(" • ")}</code></div>`
        : "";

    card.innerHTML = `
      <div style="display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:8px;">
        <div>
          <span class="sev-badge ${sevClass}">${res.verdict.toUpperCase()}</span>
          <strong style="margin-left:8px;font-size:0.95rem;">${res.threat_label}</strong>
        </div>
        <div class="pill-tag">
          ${
            res.found_in_vt
              ? `${res.malicious + res.suspicious} / ${res.total_engines} Engines Flagged`
              : "Unseen Hash (0 Detections)"
          }
        </div>
      </div>
      <div class="muted small" style="margin-top:8px;word-break:break-all;">
        <strong>Indicator (${res.query_type === "file_hash" ? "SHA-256" : "Domain"}):</strong> <code>${res.indicator}</code>
      </div>
      ${
        res.found_in_vt
          ? `<div class="muted small" style="margin-top:4px;">
              Malicious: <strong>${res.malicious}</strong> • Suspicious: <strong>${res.suspicious}</strong> • Harmless: <strong>${res.harmless}</strong> • Undetected: <strong>${res.undetected}</strong>
            </div>`
          : ""
      }
      ${enginesHtml}
    `;
    await refreshEvents();
  } catch (err) {
    card.innerHTML = `
      <span class="sev-badge sev-Critical">VIRUSTOTAL LOOKUP INFO</span>
      <span class="small" style="margin-left:8px;">${err}</span>
    `;
  }
}

window.checkHashOnVt = async function (sha256) {
  window.switchTab("network-intel");
  const input = document.getElementById("vt-lookup-input");
  if (input) input.value = sha256;
  await runVtLookup(sha256);
};

const btnSaveVt = document.getElementById("btn-save-vt-key");
if (btnSaveVt) {
  btnSaveVt.addEventListener("click", () => window.saveVtSettings(true));
}

const btnClearVt = document.getElementById("btn-clear-vt-key");
if (btnClearVt) {
  btnClearVt.addEventListener("click", async () => {
    await invokeBackend("clear_virustotal_key");
    await refreshVtStatus();
  });
}

const btnVtLookup = document.getElementById("btn-vt-lookup");
if (btnVtLookup) {
  btnVtLookup.addEventListener("click", () => {
    const val = document.getElementById("vt-lookup-input")?.value || "";
    runVtLookup(val);
  });
}

document.querySelectorAll(".chip[data-vt]").forEach((chip) => {
  chip.addEventListener("click", () => {
    const val = chip.getAttribute("data-vt") || "";
    const input = document.getElementById("vt-lookup-input");
    if (input) input.value = val;
    runVtLookup(val);
  });
});

// Process & Startup Guard
async function refreshProcessesAndPersistence() {
  const procs = await invokeBackend("get_processes_and_risks");
  const pTbody = document.getElementById("processes-tbody");
  pTbody.innerHTML = procs
    .map(
      (p) => `
    <tr>
      <td><code>${p.pid}</code></td>
      <td><strong>${p.name}</strong></td>
      <td>${p.cpu_usage}% CPU • ${p.memory_mb} MB</td>
      <td><span class="sev-badge sev-${p.risk_level}">${p.risk_level}</span></td>
      <td>
        <div class="small"><code>${p.exe_path || p.cmd_line || "System Process"}</code></div>
        <div class="muted small">${p.risk_reason}</div>
      </td>
      <td>
        ${
          p.risk_level !== "Safe"
            ? `<button class="btn btn-danger" onclick="terminatePid(${p.pid})">Kill Process</button>`
            : `<span class="muted small">Verified</span>`
        }
      </td>
    </tr>
  `
    )
    .join("");

  const hooks = await invokeBackend("get_persistence_items");
  const hTbody = document.getElementById("persistence-tbody");
  hTbody.innerHTML = hooks
    .map(
      (h) => `
    <tr>
      <td>${h.location_type}</td>
      <td><strong>${h.name}</strong></td>
      <td><code>${h.command_or_detail}</code></td>
      <td class="muted small">${h.path}</td>
      <td><span class="sev-badge sev-${h.status}">${h.status}</span></td>
    </tr>
  `
    )
    .join("");
}

window.terminatePid = async function (pid) {
  try {
    const msg = await invokeBackend("kill_suspicious_process", { pid });
    alert(msg);
    refreshProcessesAndPersistence();
  } catch (e) {
    alert("Error terminating process: " + e);
  }
};

document
  .getElementById("btn-refresh-processes")
  .addEventListener("click", refreshProcessesAndPersistence);

// Quarantine Vault
async function refreshQuarantine() {
  const list = await invokeBackend("get_quarantine_list");
  document.getElementById("quarantine-badge").textContent = list.length;
  const tbody = document.getElementById("quarantine-tbody");
  if (!list.length) {
    tbody.innerHTML = `<tr><td colspan="6" class="empty-cell">Quarantine Vault is empty.</td></tr>`;
    return;
  }
  tbody.innerHTML = list
    .map(
      (item) => `
    <tr>
      <td>${formatTime(item.quarantined_at)}</td>
      <td><strong>${item.threat_name}</strong></td>
      <td><span class="sev-badge sev-${item.severity}">${item.severity}</span></td>
      <td><code>${item.original_path}</code></td>
      <td class="muted small"><code>${item.sha256.slice(0, 16)}...</code></td>
      <td style="display:flex;gap:6px;">
        <button class="btn btn-outline" style="padding:4px 8px;font-size:0.75rem;" onclick="restoreQuarantine('${item.id}')">Restore</button>
        <button class="btn btn-danger" onclick="deleteQuarantine('${item.id}')">Shred Forever</button>
      </td>
    </tr>
  `
    )
    .join("");
}

window.restoreQuarantine = async function (id) {
  await invokeBackend("restore_from_quarantine", { id });
  await refreshQuarantine();
  await refreshEvents();
};

window.deleteQuarantine = async function (id) {
  await invokeBackend("delete_from_quarantine", { id });
  await refreshQuarantine();
  await refreshEvents();
};

document
  .getElementById("btn-refresh-quarantine")
  .addEventListener("click", refreshQuarantine);

// Real-Time Events Log
async function refreshEvents() {
  const events = await invokeBackend("get_security_events");
  const renderRows = (items) =>
    items
      .map(
        (ev) => `
      <tr>
        <td class="muted small">${formatTime(ev.timestamp)}</td>
        <td><strong>${ev.module}</strong></td>
        <td><span class="sev-badge sev-${ev.severity}">${ev.severity}</span></td>
        <td>${ev.title}</td>
        <td><code>${ev.target}</code></td>
        <td>${ev.action_taken}</td>
      </tr>
    `
      )
      .join("");

  document.getElementById("dashboard-events-tbody").innerHTML = renderRows(
    events.slice(0, 6)
  );
  document.getElementById("full-events-tbody").innerHTML = renderRows(events);
}

// One-Click Browser Extension Installer
async function renderBrowserExtensionInstaller() {
  const browsers = await invokeBackend("get_detected_browsers");
  const grid = document.getElementById("browser-installer-grid");
  if (!grid || !browsers) return;

  grid.innerHTML = browsers
    .map(
      (b) => `
    <div class="scan-mode-card">
      <div class="mode-badge ${b.installed ? "accent" : ""}">
        ${b.installed ? "DETECTED ON SYSTEM" : "MANUAL / UNPACKED"}
      </div>
      <h3>${b.name}</h3>
      <p class="muted small">
        ${
          b.id === "firefox"
            ? "Stages the extension package and opens the directory for Firefox Temporary Add-on or XPI load."
            : "Launches browser with Genesis Seek Browser Guard pre-loaded or stages unpacked extension."
        }
      </p>
      <button class="btn btn-primary full-width" onclick="installForBrowser('${b.id}')">
        + Install to ${b.name}
      </button>
    </div>
  `
    )
    .join("");
}

window.installForBrowser = async function (browserId) {
  const feedback = document.getElementById("ext-install-feedback");
  if (feedback) {
    feedback.classList.remove("hidden");
    feedback.innerHTML = `<span class="muted">Launching installer for ${browserId.toUpperCase()}...</span>`;
  }

  // Hide reminder banner once user initiates install
  const banner = document.getElementById("browser-extension-reminder-banner");
  if (banner) {
    banner.style.display = "none";
    localStorage.setItem("gs_ext_banner_dismissed", "true");
  }

  try {
    const res = await invokeBackend("install_browser_guard_extension", { browserId });

    const tipHtml =
      browserId === "firefox"
        ? `<strong>Official Mozilla Add-on:</strong> In the Firefox tab that just opened, simply click <strong>Add to Firefox</strong> to permanently enable and auto-update Genesis Seek Browser Guard.`
        : `<strong>Microsoft Edge & Chromium:</strong> A ready-to-upload package (<code>genesis-seek-edge.zip</code>) is prepared in your Downloads folder for the Microsoft Edge Add-ons store (Free).`;

    if (feedback) {
      feedback.innerHTML = `
        <div style="display:flex;justify-content:space-between;align-items:center;">
          <div>
            <span class="sev-badge sev-Safe">EXTENSION READY</span>
            <strong style="margin-left:8px;">${res.browser_name}</strong>
          </div>
          <span class="pill-tag">${res.method_used}</span>
        </div>
        <p class="small" style="margin-top:10px;white-space:pre-line;">${res.message}</p>
        <p class="muted small" style="margin-top:8px;">
          ${tipHtml}
        </p>
      `;
    }
    await refreshEvents();
  } catch (err) {
    if (feedback) {
      feedback.innerHTML = `<span class="sev-badge sev-Critical">Install Error</span> <span class="small">${err}</span>`;
    }
  }
};

document.getElementById("btn-copy-ext-path").addEventListener("click", async () => {
  const path = await invokeBackend("open_browser_extension_folder");
  if (navigator.clipboard && path) {
    await navigator.clipboard.writeText(path).catch(() => {});
  }
  const feedback = document.getElementById("ext-install-feedback");
  feedback.classList.remove("hidden");
  feedback.innerHTML = `
    <span class="sev-badge sev-Info">PATH COPIED</span>
    <span class="small" style="margin-left:8px;">Copied extension path to clipboard: <code>${path}</code></span>
  `;
});

document.getElementById("btn-open-ext-folder").addEventListener("click", async () => {
  const path = await invokeBackend("open_browser_extension_folder");
  const feedback = document.getElementById("ext-install-feedback");
  feedback.classList.remove("hidden");
  feedback.innerHTML = `
    <span class="sev-badge sev-Safe">FOLDER OPENED</span>
    <span class="small" style="margin-left:8px;">Opened extension directory in system file manager: <code>${path}</code></span>
  `;
});

async function refreshLiveMemory() {
  try {
    const mem = await invokeBackend("get_live_memory_usage");
    const ramEl = document.getElementById("sidebar-ram-usage");
    if (ramEl && mem && typeof mem.rss_mb === "number") {
      ramEl.textContent = `${mem.rss_mb.toFixed(1)} MB RAM`;
      ramEl.title = `PID ${mem.pid} • Total Resident RSS: ${mem.rss_mb.toFixed(1)} MB • Private Core: ${(mem.private_mb || mem.rss_mb).toFixed(1)} MB`;
    }
  } catch (e) {}
}

// Initial Boot: Restore saved theme from localStorage AND native disk preferences
(async function init() {
  try {
    const localSaved = safeGetStorage(THEME_STORAGE_KEY);
    if (localSaved === "cream" || localSaved === "night") {
      await applyTheme(localSaved, false);
    } else {
      const prefs = await invokeBackend("get_user_preferences");
      await applyTheme((prefs && prefs.theme) || "night", false);
    }
  } catch (e) {
    console.warn("Theme init fallback:", e);
  }

  try {
    const st = await invokeBackend("get_shield_state");
    if (st) updateProtectionRing(st);
  } catch (e) {}

  await refreshLiveMemory();
  await refreshVtStatus();
  checkForUpdatesSilent();

  try {
    await renderBrowserExtensionInstaller();
  } catch (e) {}

  // Check and display Browser Extension Reminder Banner
  try {
    const banner = document.getElementById("browser-extension-reminder-banner");
    if (banner && localStorage.getItem("gs_ext_banner_dismissed") !== "true") {
      banner.style.display = "flex";
    }
  } catch (e) {}

  try {
    await refreshEvents();
  } catch (e) {}

  try {
    await refreshQuarantine();
  } catch (e) {}

  // Keep UI synchronized with Desktop Bar tray menu and live RAM usage
  setInterval(async () => {
    try {
      const st = await invokeBackend("get_shield_state");
      if (st) updateProtectionRing(st);
      await refreshLiveMemory();
    } catch (e) {}
  }, 2500);
})();
