(async function () {
  const THEME_KEY = "genesis_seek_theme";
  const toggleBtn = document.getElementById("popup-theme-toggle");

  function setPopupTheme(theme) {
    const mode = theme === "cream" ? "cream" : "night";
    document.documentElement.setAttribute("data-theme", mode);
    toggleBtn.textContent = mode === "cream" ? "🌙 Night" : "☀️ Cream";
    try {
      localStorage.setItem(THEME_KEY, mode);
    } catch (e) {}
    if (chrome && chrome.storage && chrome.storage.local) {
      chrome.storage.local.set({ [THEME_KEY]: mode });
    }
  }

  // Restore saved theme from localStorage or chrome.storage.local
  const initialLocal = localStorage.getItem(THEME_KEY);
  if (initialLocal) {
    setPopupTheme(initialLocal);
  } else if (chrome && chrome.storage && chrome.storage.local) {
    const storedTheme = await chrome.storage.local.get(THEME_KEY);
    if (storedTheme[THEME_KEY]) setPopupTheme(storedTheme[THEME_KEY]);
  }

  toggleBtn.addEventListener("click", () => {
    const current = document.documentElement.getAttribute("data-theme") || "night";
    setPopupTheme(current === "night" ? "cream" : "night");
  });

  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  const domainEl = document.getElementById("current-domain");
  const badgeEl = document.getElementById("verdict-badge");
  const reasonEl = document.getElementById("verdict-reason");
  const bridgeEl = document.getElementById("bridge-status");

  if (tab && tab.url) {
    try {
      const u = new URL(tab.url);
      domainEl.textContent = u.hostname || tab.url;
    } catch {
      domainEl.textContent = tab.url;
    }

    const stored = await chrome.storage.local.get(`tab_${tab.id}`);
    const verdict = stored[`tab_${tab.id}`];
    if (verdict) {
      badgeEl.textContent = verdict.safe
        ? `SAFE (${verdict.category})`
        : `BLOCKED: ${verdict.category}`;
      badgeEl.className = `badge ${verdict.safe ? "safe" : "danger"}`;
      reasonEl.textContent = verdict.reason;
    }
  }

  try {
    const r = await fetch("http://127.0.0.1:49152/");
    if (r.ok) {
      bridgeEl.textContent = "Connected (127.0.0.1:49152)";
      bridgeEl.style.color = "var(--ok)";
    }
  } catch {
    bridgeEl.textContent = "Standalone Heuristics Mode";
  }
})();
