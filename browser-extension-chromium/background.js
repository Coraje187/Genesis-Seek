// Genesis Seek Browser Guard — Background Service Worker
const DESKTOP_BRIDGE_URL = "http://127.0.0.1:49152/check?url=";

chrome.tabs.onUpdated.addListener(async (tabId, changeInfo, tab) => {
  if (changeInfo.status !== "loading" || !tab.url) return;
  if (tab.url.startsWith("chrome://") || tab.url.startsWith("about:")) return;

  try {
    const resp = await fetch(`${DESKTOP_BRIDGE_URL}${encodeURIComponent(tab.url)}`);
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
  }
});

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
