use crate::process_guard;
use crate::quarantine;
use crate::scanner;
use crate::threat_intel_and_net;
use chrono::{DateTime, Utc};
use notify::{Config, Event, EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::fs;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::PathBuf;
use std::sync::Mutex;
use std::thread;
use std::time::{Duration, Instant};
use uuid::Uuid;

pub const BRIDGE_ADDR: &str = "127.0.0.1:49152";

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ShieldState {
    pub real_time_file_guard: bool,
    pub web_browser_guard: bool,
    pub ransomware_canary_guard: bool,
    pub exploit_process_guard: bool,
    pub auto_quarantine_realtime: bool,
}

impl Default for ShieldState {
    fn default() -> Self {
        Self {
            real_time_file_guard: true,
            web_browser_guard: true,
            ransomware_canary_guard: true,
            exploit_process_guard: true,
            auto_quarantine_realtime: true,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityEvent {
    pub id: String,
    pub module: String,
    pub severity: String,
    pub title: String,
    pub target: String,
    pub action_taken: String,
    pub timestamp: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UrlCheckResult {
    pub url: String,
    pub domain: String,
    pub safe: bool,
    pub category: String,
    pub risk_score: u8,
    pub reason: String,
}

/// Per-user settings directory (`~/.config/genesis-seek` / `%APPDATA%\genesis-seek`).
pub fn app_config_dir() -> PathBuf {
    let dir = dirs::config_dir()
        .unwrap_or_else(std::env::temp_dir)
        .join("genesis-seek");
    let _ = fs::create_dir_all(&dir);
    dir
}

fn shield_state_path() -> PathBuf {
    app_config_dir().join("shield_state.json")
}

/// Shield toggles are persisted so they survive restarts.
pub static SHIELD_STATE: Lazy<Mutex<ShieldState>> = Lazy::new(|| {
    let state = fs::read_to_string(shield_state_path())
        .ok()
        .and_then(|raw| serde_json::from_str::<ShieldState>(&raw).ok())
        .unwrap_or_default();
    Mutex::new(state)
});

pub fn current_shields() -> ShieldState {
    SHIELD_STATE.lock().map(|s| s.clone()).unwrap_or_default()
}

pub fn save_shield_state(state: &ShieldState) {
    if let Ok(mut s) = SHIELD_STATE.lock() {
        *s = state.clone();
    }
    if let Ok(json) = serde_json::to_string_pretty(state) {
        let _ = fs::write(shield_state_path(), json);
    }
}

pub static SECURITY_EVENTS: Lazy<Mutex<Vec<SecurityEvent>>> = Lazy::new(|| Mutex::new(Vec::new()));

pub fn log_security_event(module: &str, severity: &str, title: &str, target: &str, action_taken: &str) {
    if let Ok(mut events) = SECURITY_EVENTS.lock() {
        events.insert(
            0,
            SecurityEvent {
                id: Uuid::new_v4().to_string(),
                module: module.to_string(),
                severity: severity.to_string(),
                title: title.to_string(),
                target: target.to_string(),
                action_taken: action_taken.to_string(),
                timestamp: Utc::now(),
            },
        );
        events.truncate(200);
    }
}

const KNOWN_BAD_DOMAINS: [(&str, &str, &str); 7] = [
    ("coinhive.com", "Cryptojacking", "Browser cryptocurrency mining script host"),
    ("crypto-loot.com", "Cryptojacking", "Unauthorized WebAssembly miner host"),
    ("testsafebrowsing.appspot.com", "Malware/Phishing Test", "Standard Safe Browsing test threat domain"),
    ("malware.testing.google.test", "Malware Distribution", "Malware test distribution signature"),
    ("paypa1-security-verify.com", "Phishing.Spoof", "Credential harvesting typosquatting domain"),
    ("micros0ft-login-alert.net", "Phishing.Spoof", "Account takeover phishing domain"),
    ("steamcommunlty-trade.ru", "Phishing.Scam", "Lookalike domain targeting user credentials"),
];

pub fn builtin_bad_domain_count() -> usize {
    KNOWN_BAD_DOMAINS.len()
}

/// Extract the lowercase hostname from a URL or bare domain (strips scheme, userinfo, port, path).
fn extract_domain(raw_url: &str) -> String {
    let lower = raw_url.trim().to_lowercase();
    let without_scheme = lower.split_once("://").map(|(_, rest)| rest).unwrap_or(&lower);
    let authority = without_scheme
        .split(|c| c == '/' || c == '?' || c == '#')
        .next()
        .unwrap_or("");
    let host_port = authority.rsplit('@').next().unwrap_or(authority);
    host_port.split(':').next().unwrap_or("").trim_end_matches('.').to_string()
}

/// Evaluate a URL using the built-in blocklist, downloaded URLhaus feed and heuristics.
pub fn evaluate_url_safety(raw_url: &str) -> UrlCheckResult {
    let lower = raw_url.trim().to_lowercase();
    let domain = extract_domain(raw_url);
    let verdict = |safe: bool, category: &str, risk: u8, reason: &str| UrlCheckResult {
        url: raw_url.to_string(),
        domain: domain.clone(),
        safe,
        category: category.to_string(),
        risk_score: risk,
        reason: reason.to_string(),
    };

    for (bad, category, reason) in KNOWN_BAD_DOMAINS {
        if domain == bad || domain.ends_with(&format!(".{}", bad)) {
            return verdict(false, category, 96, reason);
        }
    }

    if threat_intel_and_net::is_feed_bad_domain(&domain) {
        return verdict(
            false,
            "ThreatFeed.URLhaus",
            98,
            "Host is listed in the abuse.ch URLhaus malware-distribution feed.",
        );
    }

    if domain.starts_with("xn--") || domain.contains(".xn--") {
        return verdict(
            false,
            "Heur.Phishing.IDNHomograph",
            82,
            "Punycode (IDN) internationalized domain often used in homograph spoofing attacks.",
        );
    }

    let high_risk_tlds = [".zip", ".mov", ".top", ".xyz", ".tk", ".gq", ".cf"];
    let impersonated_brands = ["paypal", "microsoft", "appleid", "google-security", "metamask", "coinbase", "bank"];
    if high_risk_tlds.iter().any(|tld| domain.ends_with(tld))
        && impersonated_brands.iter().any(|b| domain.contains(b))
    {
        return verdict(
            false,
            "Heur.Phishing.BrandImpersonation",
            91,
            "Brand keyword combined with high-risk TLD (.zip/.mov/.top/.xyz) indicative of phishing.",
        );
    }

    let is_ip_host = domain.split('.').count() == 4 && domain.split('.').all(|p| p.parse::<u8>().is_ok());
    let path_only = lower.split(|c| c == '?' || c == '#').next().unwrap_or(&lower);
    let exe_like = [".exe", ".scr", ".sh", ".bat", ".msi", ".ps1", ".hta"];
    if is_ip_host && exe_like.iter().any(|ext| path_only.ends_with(ext)) {
        return verdict(
            false,
            "Heur.DriveBy.DirectIPPayload",
            95,
            "Executable served directly from a raw IPv4 address without a domain identity.",
        );
    }

    verdict(true, "Clean / Verified", 4, "No phishing, malware, or cryptojacking indicators detected.")
}

/// Minimal percent-decoder for the bridge's `?url=` parameter (browser uses encodeURIComponent).
fn percent_decode(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'%' if i + 2 < bytes.len() + 0 && i + 2 <= bytes.len() - 1 => {
                let hex = std::str::from_utf8(&bytes[i + 1..i + 3]).unwrap_or("");
                match u8::from_str_radix(hex, 16) {
                    Ok(b) => {
                        out.push(b);
                        i += 3;
                    }
                    Err(_) => {
                        out.push(b'%');
                        i += 1;
                    }
                }
            }
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn is_auto_quarantine_severity(sev: &str) -> bool {
    sev == "Critical" || sev == "High"
}

/// Real-time file guard: watches Downloads, Desktop and Temp with OS-native notifications
/// (inotify / ReadDirectoryChangesW) and scans files as they are created or modified.
pub fn spawn_realtime_file_watcher() {
    thread::spawn(move || {
        let (tx, rx) = std::sync::mpsc::channel();
        let mut watcher = match RecommendedWatcher::new(tx, Config::default()) {
            Ok(w) => w,
            Err(e) => {
                log_security_event("File Guard", "High", "Real-Time File Guard failed to start", &e.to_string(), "Inactive");
                return;
            }
        };

        let mut watch_dirs: Vec<PathBuf> = Vec::new();
        if let Some(dl) = dirs::download_dir() {
            watch_dirs.push(dl);
        }
        if let Some(dt) = dirs::desktop_dir() {
            watch_dirs.push(dt);
        }
        watch_dirs.push(std::env::temp_dir());

        let mut watched = Vec::new();
        for dir in &watch_dirs {
            if dir.exists() && watcher.watch(dir, RecursiveMode::NonRecursive).is_ok() {
                watched.push(dir.to_string_lossy().to_string());
            }
        }
        log_security_event("File Guard", "Info", "Real-Time File System Guard Active", &watched.join(", "), "Monitoring");

        // Paths we already acted on, to avoid duplicate events from bursts of Modify notifications.
        let mut recently_handled: HashMap<PathBuf, Instant> = HashMap::new();

        for res in rx {
            let Ok(Event { kind: EventKind::Create(_) | EventKind::Modify(_), paths, .. }) = res else {
                continue;
            };
            let shields = current_shields();
            if !shields.real_time_file_guard {
                continue;
            }
            recently_handled.retain(|_, t| t.elapsed() < Duration::from_secs(5));

            for path in paths {
                if scanner::is_excluded_path(&path) || !path.is_file() || recently_handled.contains_key(&path) {
                    continue;
                }
                let Some(det) = scanner::scan_single_file(&path) else { continue };
                recently_handled.insert(path.clone(), Instant::now());

                let action = if shields.auto_quarantine_realtime && is_auto_quarantine_severity(&det.severity) {
                    match quarantine::quarantine_file(&det.file_path, &det.threat_name, &det.severity, &det.sha256) {
                        Ok(_) => "Auto-Quarantined".to_string(),
                        Err(e) => format!("Detected (quarantine failed: {})", e),
                    }
                } else {
                    "Detected — review in Threat Scanner".to_string()
                };

                log_security_event(
                    "File Guard",
                    &det.severity,
                    &format!("Real-Time Threat Intercepted: {}", det.threat_name),
                    &det.file_path,
                    &action,
                );
            }
        }
    });
}

const CANARY_FILES: [(&str, &str); 2] = [
    ("Q3_Financial_Report.xlsx", "GENESIS SEEK RANSOMWARE CANARY — DO NOT MODIFY.\nThis decoy file detects mass-encryption activity.\n"),
    ("Passwords_Backup.docx", "GENESIS SEEK RANSOMWARE CANARY — DO NOT MODIFY.\nThis decoy file detects mass-encryption activity.\n"),
];

fn canary_dir() -> PathBuf {
    dirs::document_dir()
        .or_else(dirs::home_dir)
        .unwrap_or_else(std::env::temp_dir)
        .join(".genesis-seek-canary")
}

fn write_canaries(dir: &PathBuf) {
    let _ = fs::create_dir_all(dir);
    for (name, content) in CANARY_FILES {
        let p = dir.join(name);
        if fs::read_to_string(&p).map(|c| c != content).unwrap_or(true) {
            let _ = fs::write(&p, content);
        }
    }
}

/// Ransomware canary: hidden decoy documents that no legitimate program should touch.
/// If one is modified, renamed or deleted, a Critical alert is raised and the decoy restored.
/// (Detection/alerting only — it does not stop the offending process.)
pub fn spawn_ransomware_canary() {
    thread::spawn(move || {
        let dir = canary_dir();
        write_canaries(&dir);

        let (tx, rx) = std::sync::mpsc::channel();
        let mut watcher = match RecommendedWatcher::new(tx, Config::default()) {
            Ok(w) => w,
            Err(_) => return,
        };
        if watcher.watch(&dir, RecursiveMode::NonRecursive).is_err() {
            return;
        }
        log_security_event("Ransomware Shield", "Info", "Ransomware Canary Decoys Armed", &dir.to_string_lossy(), "Monitoring");

        for res in rx {
            let Ok(event) = res else { continue };
            if matches!(event.kind, EventKind::Access(_)) || !current_shields().ransomware_canary_guard {
                continue;
            }
            // A decoy is "tripped" if it is missing or its contents changed.
            let tripped: Vec<&str> = CANARY_FILES
                .iter()
                .filter(|(name, content)| {
                    fs::read_to_string(dir.join(name)).map(|c| c != *content).unwrap_or(true)
                })
                .map(|(name, _)| *name)
                .collect();
            if tripped.is_empty() {
                continue; // our own rewrite or a harmless metadata change
            }
            log_security_event(
                "Ransomware Shield",
                "Critical",
                "Ransomware Canary Tripped — possible encryption activity",
                &format!("{} ({})", dir.display(), tripped.join(", ")),
                "Alerted & Decoys Restored",
            );
            write_canaries(&dir);
        }
    });
}

/// Background process monitor: every 15 s, flags newly seen Critical-risk processes
/// and automatically injects Browser Guard into newly launched Firefox sessions.
pub fn spawn_process_monitor() {
    thread::spawn(move || {
        use sysinfo::System;
        let mut sys = System::new();
        let mut alerted: HashSet<u32> = HashSet::new();
        let mut ff_injected: HashSet<u32> = HashSet::new();
        let self_pid = std::process::id();
        loop {
            let shields = current_shields();
            if shields.exploit_process_guard || shields.web_browser_guard {
                sys.refresh_processes();
                let mut alive = HashSet::new();
                for (pid, p) in sys.processes() {
                    let pid_u = pid.as_u32();
                    alive.insert(pid_u);
                    if pid_u == self_pid {
                        continue;
                    }
                    let pname = p.name();
                    if shields.web_browser_guard
                        && (pname == "firefox" || pname == "firefox-bin")
                        && !ff_injected.contains(&pid_u)
                    {
                        let staged = crate::extension_installer::setup_firefox_permanent_autoload();
                        if crate::extension_installer::try_firefox_marionette_install(&staged).is_ok() {
                            ff_injected.insert(pid_u);
                        }
                    }
                    if !shields.exploit_process_guard || alerted.contains(&pid_u) {
                        continue;
                    }
                    let exe = p.exe().map(|e| e.to_string_lossy().to_string()).unwrap_or_default();
                    let cmd = p.cmd().join(" ");
                    let (risk, reason) = process_guard::evaluate_process_risk(pname, &exe, &cmd);
                    if risk == "Critical" {
                        alerted.insert(pid_u);
                        log_security_event(
                            "Process Guard",
                            "Critical",
                            &format!("Suspicious process detected: {} (PID {})", pname, pid_u),
                            &reason,
                            "Alerted — review in Process Guard",
                        );
                    }
                }
                alerted.retain(|p| alive.contains(p));
                ff_injected.retain(|p| alive.contains(p));
            }
            thread::sleep(Duration::from_secs(15));
        }
    });
}

fn http_json(status: &str, body: &str) -> String {
    format!(
        "HTTP/1.1 {}\r\nContent-Type: application/json\r\nAccess-Control-Allow-Origin: *\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        status,
        body.len(),
        body
    )
}

/// Local HTTP bridge so the browser extension can query URL verdicts.
/// Bound to loopback only; it returns verdicts and never performs actions.
pub fn spawn_browser_guard_bridge() {
    thread::spawn(move || {
        let listener = match TcpListener::bind(BRIDGE_ADDR) {
            Ok(l) => {
                log_security_event("Browser Guard", "Info", &format!("Browser Guard Bridge Listening ({})", BRIDGE_ADDR), "Phishing, Malvertising & Cryptojacking Filter", "Active");
                l
            }
            Err(e) => {
                log_security_event("Browser Guard", "High", "Browser Guard Bridge failed to start", &format!("{}: {}", BRIDGE_ADDR, e), "Inactive");
                return;
            }
        };

        // Rate-limit "blocked" log entries so a page can't flood the event log.
        let mut last_logged: HashMap<String, Instant> = HashMap::new();

        for mut stream in listener.incoming().flatten() {
            let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
            let _ = stream.set_write_timeout(Some(Duration::from_secs(2)));
            let mut buf = [0u8; 8192];
            let Ok(n) = stream.read(&mut buf) else { continue };
            let req = String::from_utf8_lossy(&buf[..n]);
            let first_line = req.lines().next().unwrap_or("");

            if first_line.starts_with("OPTIONS ") {
                let resp = "HTTP/1.1 204 No Content\r\nAccess-Control-Allow-Origin: *\r\nAccess-Control-Allow-Methods: GET, OPTIONS\r\nAccess-Control-Allow-Headers: Content-Type\r\nConnection: close\r\n\r\n";
                let _ = stream.write_all(resp.as_bytes());
                continue;
            }

            let target = first_line.split_whitespace().nth(1).unwrap_or("/");
            let response = if target.starts_with("/install-firefox") {
                let manifest_path = dirs::download_dir()
                    .unwrap_or_else(|| PathBuf::from("/home/coraje/Downloads"))
                    .join("Genesis-Seek-Browser-Guard")
                    .join("manifest.json")
                    .to_string_lossy()
                    .to_string();
                let html = format!(
                    r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Genesis Seek — Firefox Extension Installer</title>
<style>
  body {{ background:#090d16; color:#f1f5f9; font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif; display:flex; justify-content:center; align-items:center; min-height:100vh; margin:0; padding:24px; }}
  .card {{ max-width:680px; width:100%; background:#101726; border:1px solid #1f2d47; border-radius:16px; padding:32px; box-shadow:0 16px 40px rgba(0,0,0,0.45); }}
  .badge {{ display:inline-block; background:rgba(16,185,129,0.15); color:#10b981; border:1px solid rgba(16,185,129,0.4); padding:4px 12px; border-radius:99px; font-size:0.78rem; font-weight:700; margin-bottom:12px; }}
  h1 {{ font-size:1.45rem; margin:0 0 10px 0; color:#00e5ff; }}
  .warn-box {{ background:rgba(16,185,129,0.12); border:1px solid rgba(16,185,129,0.4); border-radius:10px; padding:14px 16px; margin:16px 0; font-size:0.9rem; color:#a7f3d0; line-height:1.45; }}
  .step {{ background:#162035; border:1px solid #1f2d47; border-radius:12px; padding:16px; margin-top:14px; }}
  .step-title {{ font-weight:700; font-size:1rem; color:#ffffff; margin-bottom:8px; }}
  code {{ background:#090d16; color:#00e5ff; padding:6px 10px; border-radius:6px; display:block; margin:8px 0; font-size:0.9rem; word-break:break-all; border:1px solid #1f2d47; }}
  button {{ background:linear-gradient(135deg,#00c6ff,#0072ff); color:#fff; border:none; padding:10px 18px; border-radius:8px; font-weight:700; cursor:pointer; font-size:0.88rem; margin-top:6px; }}
  button:hover {{ filter:brightness(1.1); }}
  .copied {{ background:#10b981 !important; }}
</style>
</head>
<body>
  <div class="card">
    <span class="badge">🛡️ GENESIS SEEK BROWSER GUARD — AUTO-START ENABLED</span>
    <h1>Automatic Firefox Extension Loader</h1>
    <div class="warn-box">
      <strong>✓ Automatic Startup Installed!</strong><br>
      Genesis Seek has installed an automatic Firefox startup hook (<code>~/.local/bin/firefox</code> &amp; <code>~/.local/share/applications/firefox.desktop</code>). <strong>Every time you open Firefox from now on, Genesis Seek Browser Guard will load automatically in the background!</strong>
    </div>

    <div class="step">
      <div class="step-title">One-Time Setup for Your Currently Open Firefox Window:</div>
      <div style="font-size:0.88rem;color:#94a3b8;">If you don't want to restart Firefox right now, paste this into the address bar once:</div>
      <code id="dbg-url">about:debugging#/runtime/this-firefox</code>
      <button onclick="navigator.clipboard.writeText('about:debugging#/runtime/this-firefox'); this.textContent='✓ Copied! Paste into Firefox Address Bar (Ctrl+L, Ctrl+V)'; this.classList.add('copied');">
        📋 Copy: about:debugging#/runtime/this-firefox
      </button>
    </div>

    <div class="step">
      <div class="step-title">Then click "Load Temporary Add-on..." and select:</div>
      <code id="manifest-path">{manifest_path}</code>
      <button onclick="navigator.clipboard.writeText(document.getElementById('manifest-path').textContent); this.textContent='✓ Copied manifest.json Path!'; this.classList.add('copied');">
        📋 Copy manifest.json File Path
      </button>
    </div>
  </div>
</body>
</html>"#
                );
                format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    html.len(),
                    html
                )
            } else if let Some(encoded) = target.strip_prefix("/check?url=") {
                let url = percent_decode(encoded.split('&').next().unwrap_or(""));
                let result = if current_shields().web_browser_guard {
                    evaluate_url_safety(&url)
                } else {
                    UrlCheckResult {
                        domain: extract_domain(&url),
                        url: url.clone(),
                        safe: true,
                        category: "Browser Guard Disabled".to_string(),
                        risk_score: 0,
                        reason: "Web & Browser Guard is turned off in Genesis Seek.".to_string(),
                    }
                };
                if !result.safe {
                    let fresh = last_logged
                        .get(&result.domain)
                        .map(|t| t.elapsed() > Duration::from_secs(60))
                        .unwrap_or(true);
                    if fresh {
                        last_logged.insert(result.domain.clone(), Instant::now());
                        log_security_event("Browser Guard", "High", &format!("Browser Guard Blocked {}", result.category), &result.url, "Warning Shown");
                    }
                }
                http_json("200 OK", &serde_json::to_string(&result).unwrap_or_else(|_| "{}".to_string()))
            } else {
                http_json("200 OK", r#"{"service":"Genesis Seek Browser Guard Bridge","status":"active"}"#)
            };
            let _ = stream.write_all(response.as_bytes());
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_encoded_urls() {
        assert_eq!(
            percent_decode("https%3A%2F%2Fexample.com%2Fa%3Fb%3D1%26c%3D2"),
            "https://example.com/a?b=1&c=2"
        );
        assert_eq!(percent_decode("bad%zzinput%"), "bad%zzinput%");
    }

    #[test]
    fn extracts_domains() {
        assert_eq!(extract_domain("https://User@Sub.Example.com:8443/x?y"), "sub.example.com");
        assert_eq!(extract_domain("example.org"), "example.org");
    }

    #[test]
    fn flags_known_and_heuristic_threats() {
        assert!(!evaluate_url_safety("https://paypa1-security-verify.com/login").safe);
        assert!(!evaluate_url_safety("https://xn--80ak6aa92e.com").safe);
        assert!(!evaluate_url_safety("http://198.51.100.42/invoice.exe").safe);
        assert!(evaluate_url_safety("https://github.com").safe);
    }
}
