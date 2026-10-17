// Genesis Seek — Frontend Controller (Tauri Native IPC + Persistent Theme Memory + Browser Fallback)

const isTauri = Boolean(window.__TAURI__ && window.__TAURI__.core && window.__TAURI__.core.invoke);
const THEME_STORAGE_KEY = "genesis_seek_theme";

// Local state for standalone preview mode if Tauri runtime isn't active
const fallbackState = {
  theme: localStorage.getItem(THEME_STORAGE_KEY) || "night",
  shields: {
    real_time_file_guard: true,
    web_browser_guard: true,
    ransomware_canary_guard: true,
    exploit_process_guard: true,
    auto_quarantine_realtime: true,
  },
  feedStatus: {
    version: "2026.10.16.01",
    total_hash_signatures: 148520,
    total_web_indicators: 64290,
    yara_heuristic_rules: 412,
    last_synced: new Date().toISOString(),
    feed_sources: [
      "Genesis Seek Core Signatures",
      "Abuse.ch MalwareBazaar SHA-256 Stream",
      "Abuse.ch URLhaus & Feodo C2 Tracker",
      "OpenPhish & Homograph Phishing Feed",
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
  if (isTauri) {
    return await window.__TAURI__.core.invoke(cmd, args);
  }
  return simulateBackend(cmd, args);
}

function simulateBackend(cmd, args) {
  switch (cmd) {
    case "get_user_preferences":
      return { theme: localStorage.getItem(THEME_STORAGE_KEY) || fallbackState.theme || "night" };
    case "save_user_theme":
      fallbackState.theme = args.theme;
      localStorage.setItem(THEME_STORAGE_KEY, args.theme);
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
    case "sync_threat_feeds": {
      fallbackState.feedStatus.total_hash_signatures += 184;
      fallbackState.feedStatus.total_web_indicators += 95;
      fallbackState.feedStatus.yara_heuristic_rules += 4;
      fallbackState.feedStatus.version =
        "2026.10.16." + Math.floor(10 + Math.random() * 89);
      fallbackState.feedStatus.last_synced = new Date().toISOString();
      fallbackState.events.unshift({
        timestamp: new Date().toISOString(),
        module: "Threat Intel",
        severity: "Info",
        title: `Threat Feeds Synced (v${fallbackState.feedStatus.version})`,
        target: "Abuse.ch MalwareBazaar, URLhaus & OpenPhish",
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

// Tab Navigation
document.querySelectorAll(".nav-item").forEach((btn) => {
  btn.addEventListener("click", () => {
    document.querySelectorAll(".nav-item").forEach((b) => b.classList.remove("active"));
    document.querySelectorAll(".tab-panel").forEach((p) => p.classList.remove("active"));
    btn.classList.add("active");
    const tabId = `tab-${btn.dataset.tab}`;
    const panel = document.getElementById(tabId);
    if (panel) panel.classList.add("active");

    if (btn.dataset.tab === "network-intel") refreshNetworkAndFeeds();
    if (btn.dataset.tab === "processes") refreshProcessesAndPersistence();
    if (btn.dataset.tab === "quarantine") refreshQuarantine();
    if (btn.dataset.tab === "events" || btn.dataset.tab === "dashboard") refreshEvents();
  });
});

function formatTime(iso) {
  try {
    return new Date(iso).toLocaleTimeString();
  } catch {
    return iso;
  }
}

// Shield Integrity Calculation
async function syncShieldToggles() {
  const newState = {
    real_time_file_guard: document.getElementById("toggle-file-guard").checked,
    web_browser_guard: document.getElementById("toggle-web-guard").checked,
    ransomware_canary_guard: document.getElementById("toggle-ransomware-guard").checked,
    exploit_process_guard: document.getElementById("toggle-process-guard").checked,
    auto_quarantine_realtime: true,
  };
  await invokeBackend("update_shield_state", { newState });
  updateProtectionRing(newState);
  refreshEvents();
}

function updateProtectionRing(state) {
  const enabledCount = [
    state.real_time_file_guard,
    state.web_browser_guard,
    state.ransomware_canary_guard,
    state.exploit_process_guard,
  ].filter(Boolean).length;

  const pct = enabledCount * 25;
  const scoreEl = document.getElementById("protection-score");
  const ringEl = document.getElementById("protection-ring");
  const statusText = document.getElementById("overall-status-text");
  const pulse = document.getElementById("overall-pulse");

  scoreEl.textContent = `${pct}%`;
  let color = "var(--accent-emerald)";
  if (pct < 100 && pct >= 50) color = "var(--accent-amber)";
  if (pct < 50) color = "var(--accent-danger)";

  scoreEl.style.color = color;
  ringEl.style.background = `conic-gradient(${color} 0% ${pct}%, var(--ring-track) ${pct}% 100%)`;
  pulse.style.background = color;

  statusText.textContent =
    pct === 100
      ? "All Real-Time Shields Active — Endpoint Protected"
      : `${4 - enabledCount} Protection Layer(s) Disabled — Reduced Defense`;
}

[
  "toggle-file-guard",
  "toggle-web-guard",
  "toggle-ransomware-guard",
  "toggle-process-guard",
].forEach((id) => {
  document.getElementById(id).addEventListener("change", syncShieldToggles);
});

// Threat Scanner Actions
async function triggerScan(scanType, customPath = null) {
  document.querySelector('[data-tab="scanner"]').click();
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
      <td>
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
  feedback.classList.remove("hidden");
  feedback.innerHTML = `<span class="muted">Installing & staging Genesis Seek Browser Guard for ${browserId.toUpperCase()}...</span>`;

  try {
    const res = await invokeBackend("install_browser_guard_extension", { browserId });
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
        <strong>Quick Manual Pinning Tip:</strong> In Chrome/Brave/Edge, open <code>chrome://extensions</code>, enable <em>Developer mode</em>, click <strong>Load unpacked</strong>, and select <code>${res.extension_path}</code>.
      </p>
    `;
    await refreshEvents();
  } catch (err) {
    feedback.innerHTML = `<span class="sev-badge sev-Critical">Install Error</span> <span class="small">${err}</span>`;
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

// Initial Boot: Restore saved theme from localStorage AND native disk preferences
(async function init() {
  const localSaved = localStorage.getItem(THEME_STORAGE_KEY);
  if (localSaved === "cream" || localSaved === "night") {
    await applyTheme(localSaved, false);
  } else {
    const prefs = await invokeBackend("get_user_preferences");
    await applyTheme((prefs && prefs.theme) || "night", false);
  }

  const st = await invokeBackend("get_shield_state");
  updateProtectionRing(st);
  await renderBrowserExtensionInstaller();
  await refreshEvents();
  await refreshQuarantine();
})();
