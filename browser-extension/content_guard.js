// Genesis Seek Browser Guard — Real-Time DOM & Credential Guard

(function () {
  // 1. Listen for block warnings from background service worker
  chrome.runtime.onMessage.addListener((msg) => {
    if (msg && msg.type === "GENESIS_SEEK_BLOCK_WARNING" && msg.verdict) {
      renderWarningBanner(msg.verdict);
    }
  });

  // 2. Inspect page for insecure password forms submitting over plain HTTP
  const forms = document.querySelectorAll("form");
  forms.forEach((form) => {
    const hasPassword = form.querySelector('input[type="password"]');
    const action = (form.getAttribute("action") || window.location.href).toLowerCase();
    if (hasPassword && action.startsWith("http://") && !action.includes("127.0.0.1") && !action.includes("localhost")) {
      renderWarningBanner({
        domain: window.location.hostname,
        category: "Heur.CredentialHarvest.InsecureForm",
        risk_score: 85,
        reason: "This page contains a password field that transmits credentials over unencrypted HTTP.",
      });
    }
  });

  function renderWarningBanner(verdict) {
    if (document.getElementById("genesis-seek-shield-banner")) return;
    const banner = document.createElement("div");
    banner.id = "genesis-seek-shield-banner";
    banner.style.cssText = [
      "position:fixed",
      "top:0",
      "left:0",
      "right:0",
      "z-index:2147483647",
      "background:linear-gradient(90deg, #991b1b, #dc2626)",
      "color:#fff",
      "padding:12px 20px",
      "font-family:system-ui, sans-serif",
      "font-size:14px",
      "display:flex",
      "justify-content:space-between",
      "align-items:center",
      "box-shadow:0 4px 16px rgba(0,0,0,0.45)",
    ].join(";");

    const contentDiv = document.createElement("div");

    const strongTitle = document.createElement("strong");
    strongTitle.textContent = "🛡️ GENESIS SEEK BROWSER GUARD ALERT: ";
    contentDiv.appendChild(strongTitle);

    const spanText = document.createElement("span");
    const categoryText = document.createTextNode((verdict.category || "Threat") + " detected on ");
    const uDomain = document.createElement("u");
    uDomain.textContent = verdict.domain || "unknown domain";
    const riskScore = typeof verdict.risk_score === "number" ? verdict.risk_score : 80;
    const detailsText = document.createTextNode(" (Risk: " + riskScore + "/100) — " + (verdict.reason || "Potentially malicious website."));

    spanText.appendChild(categoryText);
    spanText.appendChild(uDomain);
    spanText.appendChild(detailsText);
    contentDiv.appendChild(spanText);

    const dismissBtn = document.createElement("button");
    dismissBtn.id = "gs-dismiss-btn";
    dismissBtn.textContent = "Dismiss";
    dismissBtn.style.cssText = "background:#fff;color:#991b1b;border:none;padding:5px 12px;border-radius:5px;font-weight:700;cursor:pointer;";
    dismissBtn.addEventListener("click", () => banner.remove());

    banner.appendChild(contentDiv);
    banner.appendChild(dismissBtn);

    if (document.body) {
      document.body.prepend(banner);
    } else {
      document.documentElement.appendChild(banner);
    }
  }
})();
