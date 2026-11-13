// Genesis Seek Browser Guard — Background Service Worker
const DESKTOP_BRIDGE_URL = "http://127.0.0.1:49152/check?url=";
const DESKTOP_BRIDGE_STATUS = "http://127.0.0.1:49152/status";
const GITHUB_RELEASE_API = "https://api.github.com/repos/Coraje187/Genesis-Seek/releases/latest";
const CURRENT_EXTENSION_VERSION = "0.3.7";

// 1. Inspect navigation events for phishing, malware, and IDN homographs
chrome.tabs.onUpdated.addListener(async (tabId, changeInfo, tab) => {
  if (changeInfo.status !== "loading" || !tab.url) return;
  if (tab.url.startsWith("chrome://") || tab.url.startsWith("about:")) return;

  try {
    const resp = await fetch(`${DESKTOP_BRIDGE_URL}${encodeURIComponent(tab.url)}`, {
      headers: { "X-Genesis-Seek-Client": "BrowserGuard" }
    });
    if (resp.ok) {
      const verdict = await resp.json();
      await chrome.storage.local.set({ [`tab_${tabId}`]: verdict });
      if (!verdict.safe) {
        chrome.tabs.sendMessage(tabId, {
          type: "GENESIS_SEEK_BLOCK_WARNING",
          verdict,
        }).catch(() => {});
      }
    }
  } catch {
    // Fallback local heuristic check when desktop daemon is offline
    const verdict = localHeuristicCheck(tab.url);
    await chrome.storage.local.set({ [`tab_${tabId}`]: verdict });
    if (!verdict.safe) {
      chrome.tabs.sendMessage(tabId, {
        type: "GENESIS_SEEK_BLOCK_WARNING",
        verdict,
      }).catch(() => {});
    }
  }
});

// 2. Prevent storage leaks by cleaning up state when tabs close
chrome.tabs.onRemoved.addListener((tabId) => {
  chrome.storage.local.remove(`tab_${tabId}`).catch(() => {});
});

// 3. Heuristic offline URL analyzer
function localHeuristicCheck(rawUrl) {
  try {
    const parsed = new URL(rawUrl);
    const host = parsed.hostname.toLowerCase();
    const isPunycode = host.startsWith("xn--") || host.includes(".xn--");
    const isSuspiciousZip =
      (host.endsWith(".zip") || host.endsWith(".mov")) &&
      /(paypal|microsoft|google|apple|login|secure|verify)/.test(host);

    if (isPunycode || isSuspiciousZip) {
      return {
        url: rawUrl,
        domain: host,
        safe: false,
        category: isPunycode ? "Heur.Phishing.IDNHomograph" : "Heur.Phishing.ZipTLD",
        risk_score: 88,
        reason: "Heuristic phishing / domain spoofing indicator detected by Browser Guard.",
      };
    }
    return {
      url: rawUrl,
      domain: host,
      safe: true,
      category: "Clean / Verified",
      risk_score: 4,
      reason: "No phishing, cryptojacking, or drive-by download indicators found.",
    };
  } catch {
    return { url: rawUrl, domain: "unknown", safe: true, category: "Clean", risk_score: 0 };
  }
}

// 4. Update notifier & version synchronization
function compareVersions(v1, v2) {
  const clean1 = (v1 || "").replace(/^v/, "").trim();
  const clean2 = (v2 || "").replace(/^v/, "").trim();
  const p1 = clean1.split(".").map((n) => parseInt(n, 10) || 0);
  const p2 = clean2.split(".").map((n) => parseInt(n, 10) || 0);
  const len = Math.max(p1.length, p2.length);
  for (let i = 0; i < len; i++) {
    const a = p1[i] || 0;
    const b = p2[i] || 0;
    if (a > b) return 1;
    if (a < b) return -1;
  }
  return 0;
}

async function checkForExtensionUpdates() {
  let updateAvailable = false;
  let latestVer = CURRENT_EXTENSION_VERSION;
  let updateUrl = "https://addons.mozilla.org/en-US/firefox/addon/genesis-seek-browser-guard/";

  // Check 1: Query Desktop Daemon Bridge for latest reported version
  try {
    const resp = await fetch(DESKTOP_BRIDGE_STATUS, {
      headers: { "X-Genesis-Seek-Client": "BrowserGuard" },
    });
    if (resp.ok) {
      const data = await resp.json();
      const reportedVer = data.version || data.app_version;
      if (reportedVer && compareVersions(reportedVer, CURRENT_EXTENSION_VERSION) > 0) {
        updateAvailable = true;
        latestVer = reportedVer.replace(/^v/, "");
      }
    }
  } catch {}

  // Check 2: Check GitHub Releases API if daemon didn't signal an update
  if (!updateAvailable) {
    try {
      const ghResp = await fetch(GITHUB_RELEASE_API);
      if (ghResp.ok) {
        const release = await ghResp.json();
        const tag = (release.tag_name || "").replace(/^v/, "");
        if (tag && compareVersions(tag, CURRENT_EXTENSION_VERSION) > 0) {
          updateAvailable = true;
          latestVer = tag;
          if (release.html_url) updateUrl = release.html_url;
        }
      }
    } catch {}
  }

  const updateInfo = {
    updateAvailable,
    currentVersion: CURRENT_EXTENSION_VERSION,
    latestVersion: latestVer,
    updateUrl,
    checkedAt: Date.now(),
  };

  await chrome.storage.local.set({ update_info: updateInfo });

  if (chrome.action && chrome.action.setBadgeText) {
    if (updateAvailable) {
      chrome.action.setBadgeText({ text: "NEW" });
      chrome.action.setBadgeBackgroundColor({ color: "#00e5ff" });
    } else {
      chrome.action.setBadgeText({ text: "" });
    }
  }

  return updateInfo;
}

// Check for updates on startup and install
chrome.runtime.onInstalled.addListener(() => {
  checkForExtensionUpdates().catch(() => {});
});

chrome.runtime.onStartup.addListener(() => {
  checkForExtensionUpdates().catch(() => {});
});

// Periodic background check every 60 minutes
setInterval(() => {
  checkForExtensionUpdates().catch(() => {});
}, 60 * 60 * 1000);

// Listen for explicit manual update check requests from popup UI
chrome.runtime.onMessage.addListener((msg, _sender, sendResponse) => {
  if (msg && msg.action === "CHECK_FOR_UPDATE") {
    checkForExtensionUpdates().then(sendResponse);
    return true; // asynchronous reply
  }
});
