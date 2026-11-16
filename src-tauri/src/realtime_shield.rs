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
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};
use uuid::Uuid;

pub const BRIDGE_ADDR: &str = "127.0.0.1:49152";

#[cfg(target_os = "windows")]
const DEFAULT_SHIELD_MODE: &str = "Win32 Process Suspend";
#[cfg(not(target_os = "windows"))]
const DEFAULT_SHIELD_MODE: &str = "User-Space Watcher";

pub static ACTIVE_SHIELD_MODE: Lazy<Mutex<String>> =
    Lazy::new(|| Mutex::new(DEFAULT_SHIELD_MODE.to_string()));

pub fn get_active_shield_mode() -> String {
    ACTIVE_SHIELD_MODE
        .lock()
        .map(|s| s.clone())
        .unwrap_or_else(|_| DEFAULT_SHIELD_MODE.to_string())
}

pub fn set_active_shield_mode(mode: &str) {
    if let Ok(mut guard) = ACTIVE_SHIELD_MODE.lock() {
        *guard = mode.to_string();
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ShieldState {
    pub real_time_file_guard: bool,
    pub web_browser_guard: bool,
    pub ransomware_canary_guard: bool,
    pub exploit_process_guard: bool,
    pub auto_quarantine_realtime: bool,
    pub browser_extension_autoload: bool,
    pub shield_mode: String,
    pub last_intel_sync: Option<String>,
    pub encrypted_quarantine: bool,
}

impl Default for ShieldState {
    fn default() -> Self {
        Self {
            real_time_file_guard: true,
            web_browser_guard: true,
            ransomware_canary_guard: true,
            exploit_process_guard: true,
            auto_quarantine_realtime: true,
            browser_extension_autoload: true,
            shield_mode: DEFAULT_SHIELD_MODE.to_string(),
            last_intel_sync: None,
            encrypted_quarantine: true,
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
    let mut state = SHIELD_STATE.lock().map(|s| s.clone()).unwrap_or_default();
    state.shield_mode = get_active_shield_mode();
    state.last_intel_sync = threat_intel_and_net::last_synced_rfc3339();
    state.encrypted_quarantine = true;
    state
}

pub fn save_shield_state(state: &ShieldState) {
    let mut updated = state.clone();
    updated.shield_mode = get_active_shield_mode();
    updated.last_intel_sync = threat_intel_and_net::last_synced_rfc3339();
    updated.encrypted_quarantine = true;
    if let Ok(mut s) = SHIELD_STATE.lock() {
        *s = updated.clone();
    }
    if let Ok(json) = serde_json::to_string_pretty(&updated) {
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

/// Returns `true` for standard OS system binary directories that must never be pre-exec blocked
/// so essential tools like `sudo`, `systemd`, `dbus`, and `polkit` cannot be locked out.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub fn is_trusted_system_binary(path: &Path) -> bool {
    let norm = path.to_string_lossy().replace('\\', "/").to_ascii_lowercase();
    norm.starts_with("/usr/bin/")
        || norm.starts_with("/usr/sbin/")
        || norm.starts_with("/bin/")
        || norm.starts_with("/sbin/")
        || norm.starts_with("/usr/lib/systemd/")
        || norm.starts_with("/lib/systemd/")
        || norm.starts_with("/usr/libexec/")
        || norm.starts_with("/usr/lib/polkit")
        || norm.starts_with("c:/windows/system32/")
        || norm.starts_with("c:/windows/syswow64/")
}

/// Returns `true` for volatile/user-writable execution locations where binaries pose elevated pre-exec risk.
#[allow(dead_code)]
pub fn is_untrusted_exec_path(path: &Path) -> bool {
    if is_trusted_system_binary(path) {
        return false;
    }
    let norm = path.to_string_lossy().replace('\\', "/").to_ascii_lowercase();
    if norm.starts_with("/tmp/.mount_") {
        return false;
    }
    norm.starts_with("/tmp/")
        || norm.starts_with("/var/tmp/")
        || norm.starts_with("/dev/shm/")
        || norm.contains("/downloads/")
        || norm.contains("/appdata/local/temp/")
        || norm.contains("/.local/share/trash/")
}

#[cfg(target_os = "linux")]
fn is_self_or_child_pid(pid: i32, self_pid: i32) -> bool {
    if pid <= 0 || pid == self_pid {
        return true;
    }
    let mut cur = pid;
    for _ in 0..4 {
        let Ok(stat) = fs::read_to_string(format!("/proc/{}/stat", cur)) else {
            break;
        };
        let Some(rparen) = stat.rfind(')') else {
            break;
        };
        let Some(ppid) = stat[rparen + 1..]
            .split_whitespace()
            .nth(1)
            .and_then(|s| s.parse::<i32>().ok())
        else {
            break;
        };
        if ppid == self_pid {
            return true;
        }
        if ppid <= 1 || ppid == cur {
            break;
        }
        cur = ppid;
    }
    false
}

#[cfg(target_os = "linux")]
fn write_fanotify_verdict(
    fan_fd: libc::c_int,
    event_fd: libc::c_int,
    is_perm: bool,
    response: u32,
) {
    if is_perm {
        let resp = libc::fanotify_response {
            fd: event_fd,
            response,
        };
        unsafe {
            libc::write(
                fan_fd,
                &resp as *const _ as *const libc::c_void,
                std::mem::size_of::<libc::fanotify_response>(),
            );
        }
    }
    unsafe {
        libc::close(event_fd);
    }
}

/// Linux Tier 1 Kernel Pre-Execution Blocker (`fanotify` with `FAN_OPEN_EXEC_PERM | FAN_CLOSE_WRITE`).
/// Requires `CAP_SYS_ADMIN` (granted by `install.sh` via `setcap`) or root.
/// Uses self/child PID exclusion, trusted-system allowlisting, and a 250 ms fail-open watchdog timeout
/// so a slow scan can never deadlock desktop program launches.
#[cfg(target_os = "linux")]
fn try_spawn_linux_fanotify_shield() -> bool {
    use std::ffi::CString;
    let fan_fd = unsafe {
        libc::fanotify_init(
            libc::FAN_CLOEXEC | libc::FAN_CLASS_CONTENT,
            (libc::O_RDONLY | libc::O_LARGEFILE) as u32,
        )
    };
    if fan_fd < 0 {
        return false;
    }

    let mut targets: Vec<PathBuf> = vec![
        PathBuf::from("/home"),
        PathBuf::from("/tmp"),
        PathBuf::from("/var/tmp"),
        PathBuf::from("/dev/shm"),
    ];
    if let Some(dl) = dirs::download_dir() {
        targets.push(dl);
    }

    let mask: u64 = libc::FAN_OPEN_EXEC_PERM | libc::FAN_CLOSE_WRITE;
    let mut marked_mounts = Vec::new();

    for dir in targets {
        if !dir.exists() {
            continue;
        }
        if let Ok(c_path) = CString::new(dir.to_string_lossy().as_bytes()) {
            let rc = unsafe {
                libc::fanotify_mark(
                    fan_fd,
                    libc::FAN_MARK_ADD | libc::FAN_MARK_MOUNT,
                    mask,
                    libc::AT_FDCWD,
                    c_path.as_ptr(),
                )
            };
            if rc == 0 {
                marked_mounts.push(dir.to_string_lossy().to_string());
            }
        }
    }

    if marked_mounts.is_empty() {
        unsafe {
            libc::close(fan_fd);
        }
        return false;
    }

    set_active_shield_mode("Kernel Pre-Exec (fanotify)");
    log_security_event(
        "File Guard",
        "Info",
        "Kernel Pre-Execution Shield Active (fanotify Tier 1)",
        &marked_mounts.join(", "),
        "Instruction-Zero Blocking",
    );

    let self_pid = std::process::id() as i32;

    thread::spawn(move || {
        let mut buf = [0u8; 8192];
        loop {
            let n = unsafe { libc::read(fan_fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len()) };
            if n <= 0 {
                continue;
            }
            let mut offset: usize = 0;
            let meta_size = std::mem::size_of::<libc::fanotify_event_metadata>();
            let shields = current_shields();

            while offset + meta_size <= n as usize {
                let meta = unsafe {
                    *(buf.as_ptr().add(offset) as *const libc::fanotify_event_metadata)
                };
                if meta.event_len < meta_size as u32 {
                    break;
                }
                if meta.fd >= 0 {
                    let is_perm = (meta.mask & libc::FAN_OPEN_EXEC_PERM) != 0;
                    if !shields.real_time_file_guard || is_self_or_child_pid(meta.pid, self_pid) {
                        write_fanotify_verdict(fan_fd, meta.fd, is_perm, libc::FAN_ALLOW);
                    } else {
                        let proc_fd_link = format!("/proc/self/fd/{}", meta.fd);
                        let target_path = fs::read_link(&proc_fd_link)
                            .unwrap_or_else(|_| PathBuf::from(&proc_fd_link));

                        if scanner::is_excluded_path(&target_path)
                            || is_trusted_system_binary(&target_path)
                            || scanner::is_cached_clean(&target_path)
                        {
                            write_fanotify_verdict(fan_fd, meta.fd, is_perm, libc::FAN_ALLOW);
                        } else {
                            let scan_path = target_path.clone();
                            let (tx, rx) = std::sync::mpsc::channel();
                            thread::spawn(move || {
                                let _ = tx.send(scanner::scan_single_file_fast(&scan_path));
                            });
                            let det_opt = match rx.recv_timeout(Duration::from_millis(250)) {
                                Ok(res) => res,
                                Err(_) => None, // Watchdog fail-open to prevent OS execution stalls
                            };

                            if let Some(det) = det_opt {
                                write_fanotify_verdict(fan_fd, meta.fd, is_perm, libc::FAN_DENY);
                                let auto_q = shields.auto_quarantine_realtime;
                                thread::spawn(move || {
                                    let q_msg = if auto_q {
                                        match quarantine::quarantine_file(
                                            &det.file_path,
                                            &det.threat_name,
                                            &det.severity,
                                            &det.sha256,
                                        ) {
                                            Ok(_) => "Blocked at Instruction Zero & Quarantined (.gvault)".to_string(),
                                            Err(e) => format!("Blocked at Instruction Zero (quarantine err: {})", e),
                                        }
                                    } else {
                                        "Blocked at Instruction Zero (FAN_DENY)".to_string()
                                    };
                                    log_security_event(
                                        "File Guard",
                                        &det.severity,
                                        &format!("fanotify Pre-Exec Blocked: {}", det.threat_name),
                                        &det.file_path,
                                        &q_msg,
                                    );
                                    crate::tray_indicator::notify_tray_updated();
                                });
                            } else {
                                write_fanotify_verdict(fan_fd, meta.fd, is_perm, libc::FAN_ALLOW);
                            }
                        }
                    }
                }
                offset += meta.event_len as usize;
            }
        }
    });

    true
}

/// Real-time file guard:
/// - On Linux: attempts Tier 1 `fanotify` Kernel Pre-Execution Blocking (`FAN_OPEN_EXEC_PERM | FAN_CLOSE_WRITE`),
///   and gracefully falls back to Tier 2 (`notify` User-Space Watcher) on `EPERM` without crashing.
/// - On Windows: watches Downloads, Desktop, AppData\Roaming and Temp with `ReadDirectoryChangesW` alongside
///   `Win32 Process Suspend` (`NtSuspendProcess`) in `spawn_process_monitor()`.
pub fn spawn_realtime_file_watcher() {
    #[cfg(target_os = "linux")]
    {
        if try_spawn_linux_fanotify_shield() {
            return;
        }
        set_active_shield_mode("User-Space Watcher");
    }

    #[cfg(target_os = "windows")]
    {
        set_active_shield_mode("Win32 Process Suspend");
    }

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

        #[cfg(target_os = "windows")]
        {
            for letter in b'D'..=b'Z' {
                let drive_str = format!("{}:\\", letter as char);
                let p = PathBuf::from(&drive_str);
                if p.exists() {
                    watch_dirs.push(p);
                }
            }
        }
        #[cfg(target_os = "linux")]
        {
            for mount_root in &["/media", "/run/media", "/mnt"] {
                let p = PathBuf::from(mount_root);
                if p.exists() {
                    watch_dirs.push(p);
                }
            }
        }

        let mut watched = Vec::new();
        for dir in &watch_dirs {
            if dir.exists() && watcher.watch(dir, RecursiveMode::Recursive).is_ok() {
                watched.push(dir.to_string_lossy().to_string());
            }
        }
        log_security_event(
            "File Guard",
            "Info",
            &format!("Real-Time File System Guard Active ({})", get_active_shield_mode()),
            &watched.join(", "),
            "Monitoring",
        );

        // Paths and hashes we already acted on, to avoid duplicate events from bursts of Modify notifications.
        let mut recently_handled: HashMap<PathBuf, Instant> = HashMap::new();
        let mut alerted_hashes: HashSet<String> = HashSet::new();
        let mut system_watcher = SystemWatcherJournal::new();
        for dir in &watch_dirs {
            system_watcher.seed_directory(dir);
        }

        for res in rx {
            let Ok(Event { kind: EventKind::Create(_) | EventKind::Modify(_), paths, .. }) = res else {
                continue;
            };
            let shields = current_shields();
            recently_handled.retain(|_, t| t.elapsed() < Duration::from_secs(60));

            for path in paths {
                if scanner::is_excluded_path(&path) {
                    continue;
                }
                if shields.ransomware_canary_guard {
                    if let Some((restored_path, reason)) =
                        system_watcher.inspect_and_rollback_mutation(&path)
                    {
                        let neutralized =
                            process_guard::neutralize_suspicious_processes_on_canary_trip();
                        let action_msg = if neutralized.is_empty() {
                            format!(
                                "System Watcher: Automatically rolled back {}",
                                restored_path.display()
                            )
                        } else {
                            format!(
                                "System Watcher: Rolled back {} & stopped {}",
                                restored_path.display(),
                                neutralized.join(" | ")
                            )
                        };
                        log_security_event(
                            "System Watcher",
                            "Critical",
                            "Ransomware File Encryption Rolled Back",
                            &reason,
                            &action_msg,
                        );
                        crate::tray_indicator::notify_tray_updated();
                        continue;
                    }
                }
                if !shields.real_time_file_guard || !path.is_file() || recently_handled.contains_key(&path) {
                    continue;
                }
                let Some(det) = scanner::scan_single_file(&path) else { continue };
                recently_handled.insert(path.clone(), Instant::now());

                if quarantine::is_allowlisted(&det.sha256) {
                    continue;
                }

                let is_riskware = det.threat_name.contains("RiskWare") || det.category.contains("RiskWare");

                // RiskWare / Game Cracks / Non-destructive items: prompt once per SHA-256 with interactive alert
                if is_riskware || !shields.auto_quarantine_realtime || !is_auto_quarantine_severity(&det.severity) {
                    if alerted_hashes.insert(det.sha256.clone()) {
                        crate::threat_alert::trigger_threat_alert(&det);
                        log_security_event(
                            "File Guard",
                            &det.severity,
                            &format!("Real-Time Notice: {}", det.threat_name),
                            &det.file_path,
                            "Interactive Alert Triggered (Quarantine or Allow)",
                        );
                        crate::tray_indicator::notify_tray_updated();
                    }
                    continue;
                }

                let action = match quarantine::quarantine_file(&det.file_path, &det.threat_name, &det.severity, &det.sha256) {
                    Ok(_) => "Auto-Quarantined (.gvault)".to_string(),
                    Err(e) => {
                        if alerted_hashes.insert(det.sha256.clone()) {
                            crate::threat_alert::trigger_threat_alert(&det);
                        }
                        format!("Detected (quarantine failed: {})", e)
                    }
                };

                log_security_event(
                    "File Guard",
                    &det.severity,
                    &format!("Real-Time Threat Intercepted: {}", det.threat_name),
                    &det.file_path,
                    &action,
                );
                crate::tray_indicator::notify_tray_updated();
            }
        }
    });
}

const CANARY_FILES: [(&str, &str); 2] = [
    ("Q3_Financial_Report.xlsx", "GENESIS SEEK RANSOMWARE CANARY — DO NOT MODIFY.\nThis decoy file detects mass-encryption activity.\n"),
    ("Passwords_Backup.docx", "GENESIS SEEK RANSOMWARE CANARY — DO NOT MODIFY.\nThis decoy file detects mass-encryption activity.\n"),
];

const MAX_SHADOW_FILES: usize = 64;
const MAX_SHADOW_FILE_BYTES: u64 = 256 * 1024;

const RANSOMWARE_EXTENSIONS: &[&str] = &[
    "locked",
    "encrypted",
    "crypt",
    "crypted",
    "ryuk",
    "lockbit",
    "akira",
    "blackcat",
    "alphv",
    "conti",
    "wannacry",
    "wnry",
    "zepto",
    "cerber",
    "phobos",
    "hive",
];

const JOURNALED_DOC_EXTENSIONS: &[&str] = &[
    "txt", "md", "csv", "json", "docx", "xlsx", "pptx", "pdf", "rtf", "odt", "ods",
];

/// Kaspersky-style System Watcher pre-encryption shadow journal and automatic file rollback engine.
/// Keeps bounded in-memory snapshots of user documents so in-place high-entropy encryption or
/// `.locked`/`.encrypted` ransomware renames can be automatically reverted to their clean state.
pub struct SystemWatcherJournal {
    snapshots: HashMap<PathBuf, Vec<u8>>,
}

impl SystemWatcherJournal {
    pub fn new() -> Self {
        Self {
            snapshots: HashMap::with_capacity(MAX_SHADOW_FILES),
        }
    }

    fn is_journalable_doc_ext(ext: &str) -> bool {
        JOURNALED_DOC_EXTENSIONS
            .iter()
            .any(|e| ext.eq_ignore_ascii_case(e))
    }

    fn is_ransomware_ext(ext: &str) -> bool {
        RANSOMWARE_EXTENSIONS
            .iter()
            .any(|e| ext.eq_ignore_ascii_case(e))
    }

    /// Snapshot clean user documents in `dir` up to `MAX_SHADOW_FILES`.
    pub fn seed_directory(&mut self, dir: &Path) {
        let Ok(entries) = fs::read_dir(dir) else {
            return;
        };
        for entry in entries.flatten() {
            if self.snapshots.len() >= MAX_SHADOW_FILES {
                break;
            }
            let p = entry.path();
            let _ = self.try_snapshot_clean_file(&p);
        }
    }

    pub fn try_snapshot_clean_file(&mut self, path: &Path) -> bool {
        if !path.is_file() {
            return false;
        }
        let Some(ext) = path.extension().and_then(|e| e.to_str()) else {
            return false;
        };
        if !Self::is_journalable_doc_ext(ext) || Self::is_ransomware_ext(ext) {
            return false;
        }
        let Ok(meta) = fs::metadata(path) else {
            return false;
        };
        if meta.len() == 0 || meta.len() > MAX_SHADOW_FILE_BYTES {
            return false;
        }
        let Ok(bytes) = fs::read(path) else {
            return false;
        };
        if scanner::calculate_entropy(&bytes) >= 6.8 {
            return false;
        }
        if self.snapshots.len() < MAX_SHADOW_FILES || self.snapshots.contains_key(path) {
            self.snapshots.insert(path.to_path_buf(), bytes);
            return true;
        }
        false
    }

    /// Inspect a created or modified file event:
    /// - If `mutated_path` has a known ransomware extension (`report.txt.locked`) and the base path (`report.txt`)
    ///   is in the shadow journal, restores `report.txt` and removes the `.locked` ciphertext file.
    /// - If `mutated_path` is a journaled document whose content was overwritten with high-entropy ciphertext
    ///   ($H \ge 7.20$ on $\ge 64$ bytes while the baseline had $H < 6.5$), automatically writes the clean snapshot back.
    pub fn inspect_and_rollback_mutation(
        &mut self,
        mutated_path: &Path,
    ) -> Option<(PathBuf, String)> {
        let ext = mutated_path
            .extension()
            .and_then(|e| e.to_str())
            .unwrap_or("");

        // Case 1: Ransomware extension appended (e.g. "notes.txt.locked" or "budget.xlsx.lockbit")
        if Self::is_ransomware_ext(ext) {
            let orig_path = mutated_path.with_extension("");
            if let Some(clean_bytes) = self.snapshots.get(&orig_path).cloned() {
                let _ = fs::write(&orig_path, &clean_bytes);
                if mutated_path != orig_path {
                    let _ = fs::remove_file(mutated_path);
                }
                return Some((
                    orig_path.clone(),
                    format!(
                        "Ransomware extension (.{}) detected on {}; restored clean snapshot ({} bytes)",
                        ext,
                        orig_path.display(),
                        clean_bytes.len()
                    ),
                ));
            }
        }

        // Case 2: In-place overwrite of a tracked document with high-entropy ciphertext
        if let Some(clean_bytes) = self.snapshots.get(mutated_path).cloned() {
            if let Ok(current_bytes) = fs::read(mutated_path) {
                if current_bytes == clean_bytes {
                    return None;
                }
                let old_entropy = scanner::calculate_entropy(&clean_bytes);
                let new_entropy = scanner::calculate_entropy(&current_bytes);
                if current_bytes.len() >= 64 && old_entropy < 6.5 && new_entropy >= 7.20 {
                    let _ = fs::write(mutated_path, &clean_bytes);
                    return Some((
                        mutated_path.to_path_buf(),
                        format!(
                            "High-entropy overwrite ({:.2} -> {:.2} bits/byte) on {}; rolled back to clean snapshot ({} bytes)",
                            old_entropy,
                            new_entropy,
                            mutated_path.display(),
                            clean_bytes.len()
                        ),
                    ));
                }
                // Normal user edit (low/moderate entropy): update baseline snapshot
                if !current_bytes.is_empty()
                    && (current_bytes.len() as u64) <= MAX_SHADOW_FILE_BYTES
                    && new_entropy < 6.8
                {
                    self.snapshots
                        .insert(mutated_path.to_path_buf(), current_bytes);
                }
            }
            return None;
        }

        // Otherwise, if this is a newly created or modified clean document, add it to the journal
        let _ = self.try_snapshot_clean_file(mutated_path);
        None
    }
}

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
/// If one is modified, renamed or deleted, suspect volatile processes are terminated/quarantined,
/// a Critical alert is raised, and the decoy files are restored.
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
            let neutralized = process_guard::neutralize_suspicious_processes_on_canary_trip();
            let action_taken = if neutralized.is_empty() {
                "Alerted & Decoys Restored".to_string()
            } else {
                format!(
                    "Alerted, Decoys Restored & Stopped: {}",
                    neutralized.join(" | ")
                )
            };
            log_security_event(
                "Ransomware Shield",
                "Critical",
                "Ransomware Canary Tripped — possible encryption activity",
                &format!("{} ({})", dir.display(), tripped.join(", ")),
                &action_taken,
            );
            write_canaries(&dir);
        }
    });
}

/// Background process monitor:
/// - On Windows: performs instant thread suspension (`NtSuspendProcess` via `ntdll.dll`) on newly spawned
///   processes from high-risk paths (`Downloads`, `AppData\Local\Temp`, `AppData\Roaming`, `Public`),
///   scans the executable image with `scanner.rs`, resumes if clean, or terminates + quarantines if malicious.
/// - Across all platforms: flags Critical-risk processes and auto-injects Browser Guard into Firefox sessions.
pub fn spawn_process_monitor() {
    thread::spawn(move || {
        use sysinfo::System;
        let mut sys = System::new();
        let mut alerted: HashSet<u32> = HashSet::new();
        let mut inspected_pids: HashSet<u32> = HashSet::new();
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
                    let pname_lower = pname.to_lowercase();
                    if shields.web_browser_guard
                        && shields.browser_extension_autoload
                        && (pname_lower == "firefox" || pname_lower == "firefox-bin" || pname_lower == "firefox.exe")
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
                    let ancestors = process_guard::resolve_ancestor_names(&sys, p);

                    #[cfg(target_os = "windows")]
                    if !inspected_pids.contains(&pid_u) {
                        inspected_pids.insert(pid_u);
                        if let Some((threat_name, _reason, action_msg)) =
                            process_guard::intercept_and_scan_windows_process(
                                pid_u,
                                pname,
                                &exe,
                                &cmd,
                                &ancestors,
                            )
                        {
                            alerted.insert(pid_u);
                            log_security_event(
                                "Process Guard",
                                "Critical",
                                &format!("Win32 Process Suspended & Blocked: {} (PID {})", pname, pid_u),
                                &format!("{} — {}", threat_name, exe),
                                &action_msg,
                            );
                            crate::tray_indicator::notify_tray_updated();
                            continue;
                        }
                    }

                    let (mut risk, mut reason) = process_guard::evaluate_process_risk_with_ancestors(
                        pname,
                        &exe,
                        &cmd,
                        &ancestors,
                    );
                    if risk != "Critical" {
                        if let Some(mem_reason) =
                            process_guard::scan_process_memory_for_hollowing(pid_u, pname)
                        {
                            risk = "Critical".to_string();
                            reason = mem_reason;
                        }
                    }
                    if risk == "Critical" {
                        alerted.insert(pid_u);
                        log_security_event(
                            "Process Guard",
                            "Critical",
                            &format!("Suspicious process detected: {} (PID {})", pname, pid_u),
                            &reason,
                            "Alerted — review in Process Guard",
                        );
                        crate::tray_indicator::notify_tray_updated();
                    }
                }
                alerted.retain(|p| alive.contains(p));
                inspected_pids.retain(|p| alive.contains(p));
                ff_injected.retain(|p| alive.contains(p));
            }
            #[cfg(target_os = "windows")]
            thread::sleep(Duration::from_secs(2));
            #[cfg(not(target_os = "windows"))]
            thread::sleep(Duration::from_secs(10));
        }
    });
}

fn http_json(status: &str, body: &str, allow_cors: bool) -> String {
    let cors_header = if allow_cors {
        "Access-Control-Allow-Origin: *\r\n"
    } else {
        ""
    };
    format!(
        "HTTP/1.1 {}\r\nContent-Type: application/json\r\n{}Content-Length: {}\r\nConnection: close\r\n\r\n{}",
        status,
        cors_header,
        body.len(),
        body
    )
}

const MAX_BRIDGE_WORKERS: usize = 16;
const MAX_BRIDGE_URL_LEN: usize = 2048;
const MAX_LOGGED_DOMAINS: usize = 1024;

struct BridgeWorkerGuard(Arc<AtomicUsize>);

impl Drop for BridgeWorkerGuard {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}

fn header_value<'a>(req: &'a str, header_name: &str) -> Option<&'a str> {
    req.lines().find_map(|line| {
        let (name, val) = line.split_once(':')?;
        if name.trim().eq_ignore_ascii_case(header_name) {
            Some(val.trim())
        } else {
            None
        }
    })
}

fn is_valid_loopback_host(host: &str) -> bool {
    let lower = host.trim().to_ascii_lowercase();
    matches!(
        lower.as_str(),
        "127.0.0.1:49152" | "localhost:49152" | "127.0.0.1" | "localhost"
    )
}

fn extract_http_body(stream: &mut std::net::TcpStream, initial: &[u8]) -> Vec<u8> {
    let Some(pos) = initial.windows(4).position(|w| w == b"\r\n\r\n") else {
        return Vec::new();
    };
    let hdr_str = String::from_utf8_lossy(&initial[..pos]);
    let content_len = header_value(&hdr_str, "content-length")
        .and_then(|s| s.parse::<usize>().ok())
        .unwrap_or(0)
        .min(2 * 1024 * 1024);
    let already = &initial[pos + 4..];
    let mut body = Vec::with_capacity(content_len.max(already.len()));
    body.extend_from_slice(&already[..already.len().min(2 * 1024 * 1024)]);
    if content_len > body.len() {
        let remaining = content_len - body.len();
        let _ = stream.take(remaining as u64).read_to_end(&mut body);
    }
    body
}

fn handle_bridge_connection(
    mut stream: std::net::TcpStream,
    last_logged: Arc<Mutex<HashMap<String, Instant>>>,
) {
    let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
    let _ = stream.set_write_timeout(Some(Duration::from_secs(2)));
    let mut buf = [0u8; 8192];
    let Ok(n) = stream.read(&mut buf) else {
        return;
    };
    let req = String::from_utf8_lossy(&buf[..n]).to_string();
    let first_line = req.lines().next().unwrap_or("");

    if first_line.starts_with("OPTIONS ") {
        let resp = "HTTP/1.1 204 No Content\r\nAccess-Control-Allow-Origin: *\r\nAccess-Control-Allow-Methods: GET, POST, OPTIONS\r\nAccess-Control-Allow-Headers: Content-Type, X-Genesis-Seek-Client, X-Filename\r\nConnection: close\r\n\r\n";
        let _ = stream.write_all(resp.as_bytes());
        return;
    }

    if let Some(host) = header_value(&req, "host") {
        if !is_valid_loopback_host(host) {
            let resp = http_json(
                "403 Forbidden",
                r#"{"error":"Rejected non-loopback Host header (DNS-rebinding protection)"}"#,
                false,
            );
            let _ = stream.write_all(resp.as_bytes());
            return;
        }
    }

    let is_untrusted_web_origin = match header_value(&req, "origin") {
        Some(origin) => {
            let low = origin.to_ascii_lowercase();
            !low.starts_with("moz-extension://")
                && !low.starts_with("chrome-extension://")
                && !low.starts_with("http://127.0.0.1")
                && !low.starts_with("http://localhost")
        }
        None => false,
    };
    let is_cross_site = header_value(&req, "sec-fetch-site")
        .map(|v| v.eq_ignore_ascii_case("cross-site"))
        .unwrap_or(false);
    let restrict_sensitive_endpoint = is_untrusted_web_origin || is_cross_site;

    let target = first_line.split_whitespace().nth(1).unwrap_or("/");
    if target.starts_with("/genesis-seek-browser-guard.xpi") {
        if restrict_sensitive_endpoint {
            let resp = http_json(
                "403 Forbidden",
                r#"{"error":"Access denied: Firefox XPI endpoint cannot be loaded cross-site"}"#,
                false,
            );
            let _ = stream.write_all(resp.as_bytes());
            return;
        }
        match crate::extension_installer::build_valid_firefox_xpi_bytes() {
            Ok(xpi_bytes) => {
                let is_download = target.contains("download=1");
                let (ctype, disp) = if is_download {
                    (
                        "application/octet-stream",
                        "attachment; filename=\"Genesis-Seek-Browser-Guard-for-Firefox-v0.4.1.xpi\"",
                    )
                } else {
                    (
                        "application/x-xpinstall",
                        "inline; filename=\"Genesis-Seek-Browser-Guard-for-Firefox-v0.4.1.xpi\"",
                    )
                };
                let hdr = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: {}\r\nContent-Disposition: {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    ctype,
                    disp,
                    xpi_bytes.len()
                );
                let _ = stream.write_all(hdr.as_bytes());
                let _ = stream.write_all(&xpi_bytes);
                return;
            }
            Err(e) => {
                let resp = http_json(
                    "500 Internal Server Error",
                    &serde_json::json!({ "error": e }).to_string(),
                    false,
                );
                let _ = stream.write_all(resp.as_bytes());
                return;
            }
        }
    }

    let response = if target.starts_with("/install-firefox") {
        if restrict_sensitive_endpoint {
            http_json(
                "403 Forbidden",
                r#"{"error":"Access denied: Firefox installer page cannot be loaded cross-site"}"#,
                false,
            )
        } else {
            let staged_dir = dirs::download_dir()
                .or_else(dirs::home_dir)
                .unwrap_or_else(std::env::temp_dir)
                .join("Genesis-Seek-Browser-Guard");
            let manifest_path = staged_dir.join("manifest.json").to_string_lossy().to_string();
            let xpi_path = staged_dir
                .join("Genesis-Seek-Browser-Guard-for-Firefox-v0.4.1.xpi")
                .to_string_lossy()
                .to_string();
            let html = format!(
                r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Genesis Seek v0.4.1 — Firefox Extension Installer</title>
<style>
  body {{ background:#090d16; color:#f1f5f9; font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif; display:flex; justify-content:center; align-items:center; min-height:100vh; margin:0; padding:24px; }}
  .card {{ max-width:720px; width:100%; background:#101726; border:1px solid #1f2d47; border-radius:16px; padding:32px; box-shadow:0 16px 40px rgba(0,0,0,0.45); }}
  .badge {{ display:inline-block; background:rgba(16,185,129,0.15); color:#10b981; border:1px solid rgba(16,185,129,0.4); padding:4px 12px; border-radius:99px; font-size:0.78rem; font-weight:700; margin-bottom:12px; }}
  h1 {{ font-size:1.45rem; margin:0 0 10px 0; color:#00e5ff; }}
  .warn-box {{ background:rgba(16,185,129,0.12); border:1px solid rgba(16,185,129,0.4); border-radius:10px; padding:14px 16px; margin:16px 0; font-size:0.9rem; color:#a7f3d0; line-height:1.45; }}
  .info-box {{ background:rgba(0,229,255,0.08); border:1px solid rgba(0,229,255,0.3); border-radius:10px; padding:14px 16px; margin:14px 0; font-size:0.86rem; color:#cbd5e1; line-height:1.45; }}
  .step {{ background:#162035; border:1px solid #1f2d47; border-radius:12px; padding:16px; margin-top:14px; }}
  .step-title {{ font-weight:700; font-size:1rem; color:#ffffff; margin-bottom:8px; }}
  code {{ background:#090d16; color:#00e5ff; padding:6px 10px; border-radius:6px; display:block; margin:8px 0; font-size:0.88rem; word-break:break-all; border:1px solid #1f2d47; }}
  .btn-row {{ display:flex; flex-wrap:wrap; gap:10px; margin-top:10px; }}
  button, a.btn {{ display:inline-block; background:linear-gradient(135deg,#00c6ff,#0072ff); color:#fff; border:none; padding:10px 16px; border-radius:8px; font-weight:700; cursor:pointer; font-size:0.86rem; text-decoration:none; }}
  a.btn-sec {{ background:#1e293b; border:1px solid #334155; }}
  button:hover, a.btn:hover {{ filter:brightness(1.1); }}
  .copied {{ background:#10b981 !important; }}
</style>
</head>
<body>
  <div class="card">
    <span class="badge">🛡️ GENESIS SEEK BROWSER GUARD v0.4.1 — FIREFOX INSTALLER</span>
    <h1>Install Genesis Seek Browser Guard in Firefox</h1>
    <div class="warn-box">
      <strong>✓ Valid POSIX .XPI Package &amp; Profile Hooks Ready!</strong><br>
      Genesis Seek generated a BOM-free v0.4.1 XPI package and provisioned <code>extensions/browser-guard@genesisseek.io.xpi</code> + <code>user.js</code> across your Firefox profiles (Developer Edition, Nightly, ESR &amp; Linux builds activate it automatically on restart).
    </div>

    <div class="step">
      <div class="step-title">Option 1 — Direct .XPI Install / Download (Firefox Dev, Nightly, ESR &amp; Linux)</div>
      <div style="font-size:0.86rem;color:#94a3b8;">Click below to trigger Firefox's native add-on prompt or save the repaired <code>.xpi</code> file:</div>
      <div class="btn-row">
        <a class="btn" href="/genesis-seek-browser-guard.xpi">⚡ 1-Click Install .XPI in Firefox</a>
        <a class="btn btn-sec" href="/genesis-seek-browser-guard.xpi?download=1">💾 Download v0.4.1 .XPI File</a>
      </div>
      <code id="xpi-path">{xpi_path}</code>
      <button onclick="navigator.clipboard.writeText(document.getElementById('xpi-path').textContent); this.textContent='✓ Copied .XPI Path!'; this.classList.add('copied');">
        📋 Copy .XPI File Path
      </button>
    </div>

    <div class="info-box">
      <strong>Using Standard Consumer Firefox Release?</strong><br>
      Consumer Firefox Release enforces Mozilla AMO cryptographic signing for drag-and-drop <code>.xpi</code> files. Use Option 2 below (takes 5 seconds) to load the extension cleanly without modifying your Firefox build:
    </div>

    <div class="step">
      <div class="step-title">Option 2 — Works in All Firefox Versions (Temporary Add-on)</div>
      <div style="font-size:0.86rem;color:#94a3b8;">1. Paste this URL into your Firefox address bar and press Enter:</div>
      <code id="dbg-url">about:debugging#/runtime/this-firefox</code>
      <button onclick="navigator.clipboard.writeText('about:debugging#/runtime/this-firefox'); this.textContent='✓ Copied! Paste in Firefox Address Bar (Ctrl+L, Ctrl+V)'; this.classList.add('copied');">
        📋 Copy: about:debugging#/runtime/this-firefox
      </button>
      <div style="font-size:0.86rem;color:#94a3b8;margin-top:12px;">2. Click <strong>"Load Temporary Add-on..."</strong> and select <code>manifest.json</code> (or the <code>.xpi</code> file above):</div>
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
        }
    } else if let Some(encoded) = target.strip_prefix("/check?url=") {
        let raw_param = encoded.split('&').next().unwrap_or("");
        if raw_param.len() > MAX_BRIDGE_URL_LEN {
            http_json(
                "400 Bad Request",
                r#"{"error":"URL parameter exceeds 2048 character safety cap"}"#,
                true,
            )
        } else {
            let mut url = percent_decode(raw_param);
            if url.len() > MAX_BRIDGE_URL_LEN {
                url.truncate(MAX_BRIDGE_URL_LEN);
            }
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
                if let Ok(mut map) = last_logged.lock() {
                    if map.len() >= MAX_LOGGED_DOMAINS {
                        map.retain(|_, t| t.elapsed() < Duration::from_secs(60));
                        if map.len() >= MAX_LOGGED_DOMAINS {
                            map.clear();
                        }
                    }
                    let fresh = map
                        .get(&result.domain)
                        .map(|t| t.elapsed() > Duration::from_secs(60))
                        .unwrap_or(true);
                    if fresh {
                        map.insert(result.domain.clone(), Instant::now());
                        log_security_event(
                            "Browser Guard",
                            "High",
                            &format!("Browser Guard Blocked {}", result.category),
                            &result.url,
                            "Warning Shown",
                        );
                    }
                }
            }
            http_json(
                "200 OK",
                &serde_json::to_string(&result).unwrap_or_else(|_| "{}".to_string()),
                true,
            )
        }
    } else if target.starts_with("/gateway/scan-email") {
        let has_client_hdr = header_value(&req, "x-genesis-seek-client").is_some();
        if restrict_sensitive_endpoint || !has_client_hdr {
            http_json(
                "403 Forbidden",
                r#"{"error":"Access denied: Mail Gateway requires local client header (X-Genesis-Seek-Client) and non-cross-site origin"}"#,
                false,
            )
        } else if !threat_intel_and_net::is_http_gateway_enabled() {
            http_json(
                "403 Forbidden",
                r#"{"error":"Local HTTP Mail Gateway is opt-in and currently disabled. Enable it in Network & Threat Feeds."}"#,
                false,
            )
        } else {
            let body_bytes = extract_http_body(&mut stream, &buf[..n]);
            let report = scanner::inspect_raw_email_gateway("gateway://inbound.eml", &body_bytes, 0);
            if !report.safe {
                log_security_event(
                    "Mail Gateway",
                    &report.severity,
                    &format!(
                        "Mail Gateway Blocked {}: {}",
                        report.verdict,
                        report.threat_name.as_deref().unwrap_or("Heur.Mail.GatewayThreat")
                    ),
                    &format!("From: {} | Subject: {}", report.sender_from, report.subject),
                    &report.verdict,
                );
            }
            http_json(
                "200 OK",
                &serde_json::to_string(&report).unwrap_or_else(|_| "{}".to_string()),
                false,
            )
        }
    } else if target.starts_with("/gateway/scan-stream") {
        let has_client_hdr = header_value(&req, "x-genesis-seek-client").is_some();
        if restrict_sensitive_endpoint || !has_client_hdr {
            http_json(
                "403 Forbidden",
                r#"{"error":"Access denied: Stream Gateway requires local client header (X-Genesis-Seek-Client) and non-cross-site origin"}"#,
                false,
            )
        } else if !threat_intel_and_net::is_http_gateway_enabled() {
            http_json(
                "403 Forbidden",
                r#"{"error":"Local HTTP Stream Gateway is opt-in and currently disabled. Enable it in Network & Threat Feeds."}"#,
                false,
            )
        } else {
            let stream_name = header_value(&req, "x-filename").unwrap_or("gateway_stream.bin").to_string();
            let body_bytes = extract_http_body(&mut stream, &buf[..n]);
            let det = scanner::scan_raw_stream_gateway(&stream_name, &body_bytes);
            if let Some(ref d) = det {
                log_security_event(
                    "Network Gateway",
                    &d.severity,
                    &format!("Stream Gateway Blocked: {}", d.threat_name),
                    &stream_name,
                    "STREAM_REJECTED",
                );
            }
            let payload = serde_json::json!({
                "safe": det.is_none(),
                "verdict": if det.is_some() { "FOUND" } else { "OK" },
                "stream_name": stream_name,
                "bytes_scanned": body_bytes.len(),
                "detection": det,
            });
            http_json("200 OK", &payload.to_string(), false)
        }
    } else if target.starts_with("/sentinel-profile") {
        if restrict_sensitive_endpoint {
            http_json(
                "403 Forbidden",
                r#"{"error":"Access denied: sentinel profile restricted to local clients"}"#,
                false,
            )
        } else {
            http_json("200 OK", include_str!("../../sentinel_profile.json"), false)
        }
    } else if target.starts_with("/audit") {
        if restrict_sensitive_endpoint {
            http_json(
                "403 Forbidden",
                r#"{"error":"Access denied: system audit restricted to local clients"}"#,
                false,
            )
        } else {
            let report = crate::system_audit::run_system_audit();
            http_json(
                "200 OK",
                &serde_json::to_string(&report).unwrap_or_else(|_| "{}".to_string()),
                false,
            )
        }
    } else {
        http_json(
            "200 OK",
            r#"{"service":"Genesis Seek Browser, Mail & Stream Gateway Bridge","status":"active","version":"v0.4.1 Enterprise","app_version":"0.4.1","extension_version":"0.4.1","latest_extension_version":"0.4.1","mail_gateway":"active","stream_gateway":"active","protection_health":100}"#,
            true,
        )
    };
    let _ = stream.write_all(response.as_bytes());
}

/// Local HTTP bridge so the browser extension can query URL verdicts.
/// Bound to loopback only; enforces Host/Origin/Sec-Fetch-Site validation and a bounded worker pool.
pub fn spawn_browser_guard_bridge() {
    thread::spawn(move || {
        let listener = match TcpListener::bind(BRIDGE_ADDR) {
            Ok(l) => {
                log_security_event(
                    "Browser Guard",
                    "Info",
                    &format!("Browser Guard Bridge Listening ({})", BRIDGE_ADDR),
                    "Phishing, Malvertising & Cryptojacking Filter",
                    "Active",
                );
                l
            }
            Err(e) => {
                log_security_event(
                    "Browser Guard",
                    "High",
                    "Browser Guard Bridge failed to start",
                    &format!("{}: {}", BRIDGE_ADDR, e),
                    "Inactive",
                );
                return;
            }
        };

        let last_logged = Arc::new(Mutex::new(HashMap::<String, Instant>::new()));
        let active_workers = Arc::new(AtomicUsize::new(0));

        for mut stream in listener.incoming().flatten() {
            if active_workers.load(Ordering::Acquire) >= MAX_BRIDGE_WORKERS {
                let busy = http_json(
                    "503 Service Unavailable",
                    r#"{"error":"Browser Guard bridge worker pool busy"}"#,
                    true,
                );
                let _ = stream.write_all(busy.as_bytes());
                continue;
            }
            active_workers.fetch_add(1, Ordering::AcqRel);
            let worker_pool = Arc::clone(&active_workers);
            let logged_ref = Arc::clone(&last_logged);
            thread::spawn(move || {
                let _guard = BridgeWorkerGuard(worker_pool);
                handle_bridge_connection(stream, logged_ref);
            });
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

    #[test]
    fn validates_trusted_and_untrusted_exec_paths() {
        assert!(is_trusted_system_binary(Path::new("/usr/bin/sudo")));
        assert!(is_trusted_system_binary(Path::new("/bin/sh")));
        assert!(is_trusted_system_binary(Path::new("/usr/lib/systemd/systemd")));
        assert!(!is_untrusted_exec_path(Path::new("/usr/bin/sudo")));

        assert!(is_untrusted_exec_path(Path::new("/tmp/dropper.elf")));
        assert!(is_untrusted_exec_path(Path::new("/dev/shm/payload")));
        assert!(is_untrusted_exec_path(Path::new(r"C:\Users\alice\Downloads\evil.exe")));
        assert!(is_untrusted_exec_path(Path::new(r"C:\Users\alice\AppData\Local\Temp\stage.exe")));
        assert!(!is_untrusted_exec_path(Path::new("/tmp/.mount_GenesisSeek/usr/bin/app")));
    }

    #[test]
    fn system_watcher_journal_automatically_rolls_back_ransomware_encryption_and_renames() {
        let dir = std::env::temp_dir().join(format!("gs_syswatcher_{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let doc_path = dir.join("quarterly_budget.txt");
        let clean_content = b"Q3 Budget Forecast: Engineering=120000, Security=95000, Operations=80000.\nApproved by Finance.\n";
        std::fs::write(&doc_path, clean_content).unwrap();

        let mut journal = SystemWatcherJournal::new();
        journal.seed_directory(&dir);

        // 1. Benign user edit updates the baseline snapshot without triggering rollback
        let updated_clean = b"Q4 Budget Forecast: Engineering=135000, Security=110000, Operations=85000.\nApproved by Finance.\n";
        std::fs::write(&doc_path, updated_clean).unwrap();
        assert!(journal.inspect_and_rollback_mutation(&doc_path).is_none());
        assert_eq!(std::fs::read(&doc_path).unwrap(), updated_clean);

        // 2. In-place high-entropy encryption overwrite is automatically rolled back to updated_clean
        let ciphertext: Vec<u8> = (0..=255u8).collect();
        std::fs::write(&doc_path, &ciphertext).unwrap();
        let (restored, reason) = journal
            .inspect_and_rollback_mutation(&doc_path)
            .expect("High-entropy overwrite must trigger automatic rollback");
        assert_eq!(restored, doc_path);
        assert!(reason.contains("High-entropy overwrite"));
        assert_eq!(
            std::fs::read(&doc_path).unwrap(),
            updated_clean,
            "Document on disk must be restored to clean pre-encryption content"
        );

        // 3. Ransomware rename/append (.lockbit) restores original document and deletes .lockbit file
        let locked_path = dir.join("quarterly_budget.txt.lockbit");
        let _ = std::fs::remove_file(&doc_path);
        std::fs::write(&locked_path, &ciphertext).unwrap();
        let (restored2, reason2) = journal
            .inspect_and_rollback_mutation(&locked_path)
            .expect(".lockbit rename must trigger automatic rollback");
        assert_eq!(restored2, doc_path);
        assert!(reason2.contains(".lockbit"));
        assert!(!locked_path.exists(), "Ransomware .lockbit artifact must be removed");
        assert_eq!(std::fs::read(&doc_path).unwrap(), updated_clean);

        let _ = std::fs::remove_dir_all(&dir);
    }
}
