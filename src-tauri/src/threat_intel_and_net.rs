use crate::realtime_shield;
use crate::scanner;
use chrono::{DateTime, Utc};
use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::fs;
use std::path::PathBuf;
use std::sync::{Mutex, RwLock};
use std::time::Duration;

const URLHAUS_HOSTFILE: &str = "https://urlhaus.abuse.ch/downloads/hostfile/";
const BAZAAR_RECENT_SHA256: &str = "https://bazaar.abuse.ch/export/txt/sha256/recent/";
const PHISHSTATS_CSV_FEED: &str = "https://phishstats.info/phish_score.csv";
const COMMUNITY_YARA_FEED: &str =
    "https://raw.githubusercontent.com/Yara-Rules/rules/master/malware/MALW_Ransomware.yar";
const MAX_FEED_BYTES: u64 = 25 * 1024 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeedSourceStatus {
    pub name: String,
    pub url: String,
    pub ok: bool,
    pub entries: usize,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatFeedStatus {
    pub version: String,
    pub total_hash_signatures: usize,
    pub total_web_indicators: usize,
    pub yara_heuristic_rules: usize,
    pub last_synced: Option<DateTime<Utc>>,
    pub last_intel_sync: Option<String>,
    pub shield_mode: String,
    pub encrypted_quarantine: bool,
    pub feed_sources: Vec<FeedSourceStatus>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkConnectionItem {
    pub protocol: String,
    pub local_address: String,
    pub remote_address: String,
    pub remote_port: u16,
    pub state: String,
    pub risk_level: String, // "Safe", "Suspicious", "Critical"
    pub reason: String,
}

fn feeds_dir() -> PathBuf {
    let dir = realtime_shield::app_config_dir().join("feeds");
    let _ = fs::create_dir_all(&dir);
    dir
}

fn load_cached_set(file: &str) -> HashSet<String> {
    fs::read_to_string(feeds_dir().join(file))
        .map(|raw| raw.lines().map(|l| l.trim().to_string()).filter(|l| !l.is_empty()).collect())
        .unwrap_or_default()
}

/// Malicious hosts downloaded from abuse.ch URLhaus & PhishStats (cached on disk between runs).
pub static DYNAMIC_BAD_DOMAINS: Lazy<RwLock<HashSet<String>>> =
    Lazy::new(|| RwLock::new(load_cached_set("urlhaus_hosts.txt")));

/// Recent malware SHA-256 hashes downloaded from abuse.ch MalwareBazaar.
pub static DYNAMIC_HASHES: Lazy<RwLock<HashSet<String>>> =
    Lazy::new(|| RwLock::new(load_cached_set("bazaar_sha256.txt")));

static LAST_SOURCES: Lazy<Mutex<(Option<DateTime<Utc>>, Vec<FeedSourceStatus>)>> = Lazy::new(|| {
    let last = fs::read_to_string(feeds_dir().join("last_sync.txt"))
        .ok()
        .and_then(|s| DateTime::parse_from_rfc3339(s.trim()).ok())
        .map(|d| d.with_timezone(&Utc));
    Mutex::new((last, Vec::new()))
});

pub fn last_synced_rfc3339() -> Option<String> {
    LAST_SOURCES
        .lock()
        .ok()
        .and_then(|g| g.0.map(|d| d.to_rfc3339()))
}

pub fn is_known_malware_hash(sha256: &str) -> bool {
    DYNAMIC_HASHES.read().map(|s| s.contains(sha256)).unwrap_or(false)
}

pub fn is_feed_bad_domain(domain: &str) -> bool {
    DYNAMIC_BAD_DOMAINS.read().map(|s| s.contains(domain)).unwrap_or(false)
}

fn fetch_text(url: &str) -> Result<String, String> {
    if let Ok(client) = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(30))
        .user_agent("GenesisSeek/0.3 (+zero-telemetry-threat-feed)")
        .build()
    {
        if let Ok(resp) = client.get(url).send() {
            if resp.status().is_success() {
                if let Ok(text) = resp.text() {
                    if !text.is_empty() {
                        return Ok(text);
                    }
                }
            }
        }
    }

    let agent = ureq::AgentBuilder::new()
        .timeout(Duration::from_secs(30))
        .user_agent("GenesisSeek/0.3 (+zero-telemetry-threat-feed)")
        .build();
    let resp = agent.get(url).call().map_err(|e| e.to_string())?;
    let mut body = String::new();
    use std::io::Read;
    resp.into_reader()
        .take(MAX_FEED_BYTES)
        .read_to_string(&mut body)
        .map_err(|e| e.to_string())?;
    Ok(body)
}

fn parse_urlhaus_hosts(body: &str) -> HashSet<String> {
    body.lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .filter_map(|l| l.split_whitespace().nth(1))
        .map(|h| h.to_lowercase())
        .collect()
}

fn parse_phishstats_domains(body: &str) -> HashSet<String> {
    let mut out = HashSet::new();
    for line in body.lines().map(str::trim) {
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        // PhishStats CSV format: "date","score","url","ip"
        for field in line.split(',') {
            let unquoted = field.trim().trim_matches('"');
            if unquoted.starts_with("http://") || unquoted.starts_with("https://") {
                let dom = extract_domain_simple(unquoted);
                if !dom.is_empty() && dom.contains('.') {
                    out.insert(dom);
                }
            }
        }
    }
    out
}

fn parse_sha256_list(body: &str) -> HashSet<String> {
    body.lines()
        .map(str::trim)
        .filter(|l| l.len() == 64 && l.chars().all(|c| c.is_ascii_hexdigit()))
        .map(|l| l.to_lowercase())
        .collect()
}

fn sync_one(
    name: &str,
    url: &str,
    cache_file: &str,
    parse: fn(&str) -> HashSet<String>,
    target: &RwLock<HashSet<String>>,
) -> FeedSourceStatus {
    match fetch_text(url).map(|body| parse(&body)) {
        Ok(set) if !set.is_empty() => {
            let mut sorted: Vec<&String> = set.iter().collect();
            sorted.sort();
            let joined = sorted.iter().map(|s| s.as_str()).collect::<Vec<_>>().join("\n");
            let _ = fs::write(feeds_dir().join(cache_file), joined);
            let entries = set.len();
            if let Ok(mut t) = target.write() {
                *t = set;
            }
            FeedSourceStatus { name: name.into(), url: url.into(), ok: true, entries, error: None }
        }
        Ok(_) => FeedSourceStatus {
            name: name.into(),
            url: url.into(),
            ok: false,
            entries: target.read().map(|s| s.len()).unwrap_or(0),
            error: Some("Feed returned no entries; keeping cached copy".into()),
        },
        Err(e) => FeedSourceStatus {
            name: name.into(),
            url: url.into(),
            ok: false,
            entries: target.read().map(|s| s.len()).unwrap_or(0),
            error: Some(format!("{} (keeping cached copy)", e)),
        },
    }
}

/// Download Abuse.ch MalwareBazaar SHA-256 hashes (batch insert into SQLite `threat_hashes.db`),
/// Abuse.ch URLhaus & PhishStats malicious domains (syncing `browser-extension/rules.json`),
/// and community YARA rules (hot-reloading `ScannerEngine`).
/// Blocking — call from a background thread or `spawn_blocking`.
pub fn sync_threat_intelligence_feeds() -> ThreatFeedStatus {
    let mut sources = vec![
        sync_one(
            "abuse.ch URLhaus malicious hosts",
            URLHAUS_HOSTFILE,
            "urlhaus_hosts.txt",
            parse_urlhaus_hosts,
            &DYNAMIC_BAD_DOMAINS,
        ),
        sync_one(
            "abuse.ch MalwareBazaar recent SHA-256",
            BAZAAR_RECENT_SHA256,
            "bazaar_sha256.txt",
            parse_sha256_list,
            &DYNAMIC_HASHES,
        ),
    ];

    // 1. Batch-insert MalwareBazaar SHA-256 hashes into local SQLite `threat_hashes.db` for O(1) indexed queries
    if let Ok(hashes) = DYNAMIC_HASHES.read() {
        if !hashes.is_empty() {
            let batch: Vec<(String, String, String, String)> = hashes
                .iter()
                .map(|h| {
                    (
                        h.clone(),
                        "ThreatFeed.MalwareBazaar.SHA256".to_string(),
                        "ThreatFeed.Hash".to_string(),
                        "Critical".to_string(),
                    )
                })
                .collect();
            let _ = scanner::batch_insert_threat_hashes(&batch);
        }
    }

    // 2. Pull PhishStats active phishing URLs/domains and merge into DYNAMIC_BAD_DOMAINS
    match fetch_text(PHISHSTATS_CSV_FEED).map(|b| parse_phishstats_domains(&b)) {
        Ok(phish_set) if !phish_set.is_empty() => {
            let count = phish_set.len();
            if let Ok(mut doms) = DYNAMIC_BAD_DOMAINS.write() {
                doms.extend(phish_set);
            }
            sources.push(FeedSourceStatus {
                name: "PhishStats active phishing domains".into(),
                url: PHISHSTATS_CSV_FEED.into(),
                ok: true,
                entries: count,
                error: None,
            });
        }
        Ok(_) => sources.push(FeedSourceStatus {
            name: "PhishStats active phishing domains".into(),
            url: PHISHSTATS_CSV_FEED.into(),
            ok: false,
            entries: 0,
            error: Some("No new entries returned".into()),
        }),
        Err(e) => sources.push(FeedSourceStatus {
            name: "PhishStats active phishing domains".into(),
            url: PHISHSTATS_CSV_FEED.into(),
            ok: false,
            entries: 0,
            error: Some(format!("{} (keeping cached domains)", e)),
        }),
    }

    // 3. Dynamically compile top active malicious domains into Chromium/Firefox DeclarativeNetRequest `rules.json`
    if let Ok(doms) = DYNAMIC_BAD_DOMAINS.read() {
        let _ = crate::extension_installer::sync_dynamic_browser_rules(&doms);
    }

    // 4. Pull curated community YARA rules into `rules/community_threat_feed.yar` and hot-reload ScannerEngine
    let yara_target = scanner::rules_directory().join("community_threat_feed.yar");
    match fetch_text(COMMUNITY_YARA_FEED) {
        Ok(yara_body) if yara_body.contains("rule ") => {
            let _ = fs::write(&yara_target, &yara_body);
            let total_rules = scanner::reload_yara_rules();
            sources.push(FeedSourceStatus {
                name: "Community YARA Rules (Hot-Reloaded)".into(),
                url: COMMUNITY_YARA_FEED.into(),
                ok: true,
                entries: total_rules,
                error: None,
            });
        }
        Ok(_) => {
            let total_rules = scanner::reload_yara_rules();
            sources.push(FeedSourceStatus {
                name: "Community YARA Rules (Local Ruleset)".into(),
                url: COMMUNITY_YARA_FEED.into(),
                ok: true,
                entries: total_rules,
                error: None,
            });
        }
        Err(e) => {
            let total_rules = scanner::reload_yara_rules();
            sources.push(FeedSourceStatus {
                name: "Community YARA Rules (Cached)".into(),
                url: COMMUNITY_YARA_FEED.into(),
                ok: total_rules > 0,
                entries: total_rules,
                error: Some(format!("{} (using local rules/ directory)", e)),
            });
        }
    }

    let any_ok = sources.iter().any(|s| s.ok);
    if let Ok(mut last) = LAST_SOURCES.lock() {
        if any_ok {
            let now = Utc::now();
            last.0 = Some(now);
            let _ = fs::write(feeds_dir().join("last_sync.txt"), now.to_rfc3339());
        }
        last.1 = sources.clone();
    }

    let status = get_threat_feed_status();
    let failed: Vec<&str> = sources.iter().filter(|s| !s.ok).map(|s| s.name.as_str()).collect();
    realtime_shield::log_security_event(
        "Threat Intel",
        if failed.is_empty() { "Info" } else { "Medium" },
        &if failed.is_empty() {
            "Threat Feeds, SQLite DB & YARA Rules Synced".to_string()
        } else {
            format!("Threat Feed Sync Completed ({} partial)", failed.len())
        },
        &format!(
            "{} hashes • {} malicious hosts • {} YARA/heuristic rules",
            status.total_hash_signatures, status.total_web_indicators, status.yara_heuristic_rules
        ),
        if failed.is_empty() { "Updated" } else { "Partially Updated" },
    );
    status
}

/// Alias matching the enterprise upgrade specification `sync_threat_intelligence()`.
pub fn sync_threat_intelligence() -> ThreatFeedStatus {
    sync_threat_intelligence_feeds()
}

/// Background scheduler that syncs zero-telemetry community threat feeds on startup (if stale)
/// and every 6 hours thereafter.
pub fn spawn_threat_feed_scheduler() {
    std::thread::spawn(move || {
        // Hydrate SQLite DB with any cached MalwareBazaar hashes on startup
        if let Ok(hashes) = DYNAMIC_HASHES.read() {
            if !hashes.is_empty() && scanner::sqlite_hash_count() <= scanner::builtin_hash_count() {
                let batch: Vec<(String, String, String, String)> = hashes
                    .iter()
                    .map(|h| {
                        (
                            h.clone(),
                            "ThreatFeed.MalwareBazaar.SHA256".to_string(),
                            "ThreatFeed.Hash".to_string(),
                            "Critical".to_string(),
                        )
                    })
                    .collect();
                let _ = scanner::batch_insert_threat_hashes(&batch);
            }
        }
        if let Ok(doms) = DYNAMIC_BAD_DOMAINS.read() {
            if !doms.is_empty() {
                let _ = crate::extension_installer::sync_dynamic_browser_rules(&doms);
            }
        }

        // Initial background sync 20 seconds after launch if feeds haven't been synced in the last 6 hours
        std::thread::sleep(Duration::from_secs(20));
        let needs_initial_sync = LAST_SOURCES
            .lock()
            .ok()
            .and_then(|g| g.0)
            .map(|t| (Utc::now() - t).num_hours() >= 6)
            .unwrap_or(true);
        if needs_initial_sync {
            let _ = sync_threat_intelligence_feeds();
        }

        loop {
            std::thread::sleep(Duration::from_secs(6 * 3600));
            let _ = sync_threat_intelligence_feeds();
        }
    });
}

pub fn get_threat_feed_status() -> ThreatFeedStatus {
    let mem_hashes = DYNAMIC_HASHES.read().map(|s| s.len()).unwrap_or(0);
    let sqlite_hashes = scanner::sqlite_hash_count();
    let total_hashes = sqlite_hashes.max(scanner::builtin_hash_count() + mem_hashes);
    let hosts = DYNAMIC_BAD_DOMAINS.read().map(|s| s.len()).unwrap_or(0);
    let (last_synced, mut sources) = LAST_SOURCES
        .lock()
        .map(|g| g.clone())
        .unwrap_or((None, Vec::new()));

    if sources.is_empty() {
        sources = vec![
            FeedSourceStatus { name: "abuse.ch URLhaus malicious hosts".into(), url: URLHAUS_HOSTFILE.into(), ok: hosts > 0, entries: hosts, error: None },
            FeedSourceStatus { name: "abuse.ch MalwareBazaar recent SHA-256 (SQLite)".into(), url: BAZAAR_RECENT_SHA256.into(), ok: total_hashes > scanner::builtin_hash_count(), entries: total_hashes, error: None },
            FeedSourceStatus { name: "PhishStats active phishing domains".into(), url: PHISHSTATS_CSV_FEED.into(), ok: hosts > 0, entries: hosts, error: None },
            FeedSourceStatus { name: "YARA-X & Heuristic Pattern Engine (rules/)".into(), url: COMMUNITY_YARA_FEED.into(), ok: true, entries: scanner::heuristic_rule_count(), error: None },
        ];
    }

    ThreatFeedStatus {
        version: last_synced
            .map(|d| d.format("%Y.%m.%d-%H%M").to_string())
            .unwrap_or_else(|| "built-in + local SQLite".to_string()),
        total_hash_signatures: total_hashes,
        total_web_indicators: realtime_shield::builtin_bad_domain_count() + hosts,
        yara_heuristic_rules: scanner::heuristic_rule_count(),
        last_synced,
        last_intel_sync: last_synced.map(|d| d.to_rfc3339()),
        shield_mode: realtime_shield::get_active_shield_mode(),
        encrypted_quarantine: true,
        feed_sources: sources,
    }
}

/// Inspect active TCP sockets (Linux `/proc/net/tcp`, Windows `netstat -ano`) to flag
/// reverse-shell ports, Stratum mining pools, IRC C2 and Tor proxies.
pub fn inspect_active_network_connections() -> Vec<NetworkConnectionItem> {
    #[allow(unused_mut)]
    let mut list = Vec::new();

    #[cfg(target_os = "linux")]
    {
        if let Ok(content) = fs::read_to_string("/proc/net/tcp") {
            for line in content.lines().skip(1).take(120) {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() < 4 {
                    continue;
                }
                let (local_ip, local_port) = parse_proc_hex_ip_port(parts[1]);
                let (remote_ip, remote_port) = parse_proc_hex_ip_port(parts[2]);
                let state = match parts[3] {
                    "01" => "ESTABLISHED",
                    "02" => "SYN_SENT",
                    "06" => "TIME_WAIT",
                    "08" => "CLOSE_WAIT",
                    "0A" => "LISTEN",
                    _ => "OTHER",
                };
                let (risk_level, reason) = evaluate_port_risk(remote_port, &remote_ip);
                list.push(NetworkConnectionItem {
                    protocol: "TCPv4".to_string(),
                    local_address: format!("{}:{}", local_ip, local_port),
                    remote_address: format!("{}:{}", remote_ip, remote_port),
                    remote_port,
                    state: state.to_string(),
                    risk_level,
                    reason,
                });
            }
        }
    }

    #[cfg(target_os = "windows")]
    {
        use std::os::windows::process::CommandExt;
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        if let Ok(output) = std::process::Command::new("netstat")
            .args(["-ano", "-p", "TCP"])
            .creation_flags(CREATE_NO_WINDOW)
            .output()
        {
            let text = String::from_utf8_lossy(&output.stdout);
            for line in text.lines() {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() < 4 || !parts[0].eq_ignore_ascii_case("TCP") {
                    continue;
                }
                let remote = parts[2].to_string();
                let remote_port = remote
                    .rsplit(':')
                    .next()
                    .and_then(|p| p.parse::<u16>().ok())
                    .unwrap_or(0);
                let (risk_level, reason) = evaluate_port_risk(remote_port, &remote);
                list.push(NetworkConnectionItem {
                    protocol: "TCP".to_string(),
                    local_address: parts[1].to_string(),
                    remote_address: remote,
                    remote_port,
                    state: parts[3].to_string(),
                    risk_level,
                    reason,
                });
                if list.len() >= 120 {
                    break;
                }
            }
        }
    }

    // Risky sockets first.
    list.sort_by_key(|c| match c.risk_level.as_str() {
        "Critical" => 0,
        "Suspicious" => 1,
        _ => 2,
    });
    list
}

#[cfg(target_os = "linux")]
fn parse_proc_hex_ip_port(hex_addr: &str) -> (String, u16) {
    let mut split = hex_addr.split(':');
    let ip_hex = split.next().unwrap_or("00000000");
    let port_hex = split.next().unwrap_or("0000");
    let port = u16::from_str_radix(port_hex, 16).unwrap_or(0);
    if let Ok(num) = u32::from_str_radix(ip_hex, 16) {
        // /proc/net/tcp stores IPv4 in host (little-endian) byte order.
        let b = num.to_le_bytes();
        return (format!("{}.{}.{}.{}", b[0], b[1], b[2], b[3]), port);
    }
    ("0.0.0.0".to_string(), port)
}

fn evaluate_port_risk(port: u16, remote: &str) -> (String, String) {
    match port {
        4444 | 1337 | 31337 => (
            "Critical".to_string(),
            "Known Metasploit / reverse-shell default C2 port".to_string(),
        ),
        3333 | 14444 | 45700 => (
            "Suspicious".to_string(),
            "Common Stratum cryptocurrency mining pool port".to_string(),
        ),
        6667 | 6697 => (
            "Suspicious".to_string(),
            "IRC command & control communication port".to_string(),
        ),
        9050 | 9150 => (
            "Suspicious".to_string(),
            "Tor SOCKS proxy relay port".to_string(),
        ),
        0 => ("Safe".to_string(), "Listening socket".to_string()),
        _ => {
            if remote.starts_with("127.") || remote.starts_with("[::1]") {
                ("Safe".to_string(), "Localhost connection".to_string())
            } else {
                ("Safe".to_string(), "Standard outbound socket".to_string())
            }
        }
    }
}

// ============================================================================
// Optional VirusTotal v3 API Integration (Windows & Linux, Zero-Upload Hash/Domain Check)
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
struct VtDiskConfig {
    api_key: String,
    auto_check_suspicious: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VtConfigStatus {
    pub configured: bool,
    pub masked_key: String,
    pub source: String,
    pub auto_check_suspicious: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VtScanReport {
    pub query_type: String, // "file_hash" or "domain"
    pub target: String,
    pub indicator: String,  // SHA-256 or hostname
    pub found_in_vt: bool,
    pub malicious: u32,
    pub suspicious: u32,
    pub undetected: u32,
    pub harmless: u32,
    pub total_engines: u32,
    pub verdict: String, // "Clean", "Suspicious", "Malicious", "Not Found in VT"
    pub threat_label: String,
    pub flagged_engines: Vec<String>,
    pub permalink: String,
}

static VT_CACHE: Lazy<RwLock< std::collections::HashMap<String, VtScanReport> >> =
    Lazy::new(|| RwLock::new(std::collections::HashMap::new()));

fn vt_config_path() -> PathBuf {
    realtime_shield::app_config_dir().join("vt_config.json")
}

fn load_vt_disk_config() -> VtDiskConfig {
    fs::read_to_string(vt_config_path())
        .ok()
        .and_then(|raw| serde_json::from_str::<VtDiskConfig>(&raw).ok())
        .unwrap_or_default()
}

fn save_vt_disk_config(cfg: &VtDiskConfig) -> Result<(), String> {
    let path = vt_config_path();
    let json = serde_json::to_string_pretty(cfg).map_err(|e| e.to_string())?;
    fs::write(&path, json).map_err(|e| e.to_string())?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(&path, fs::Permissions::from_mode(0o600));
    }
    Ok(())
}

/// Resolve the active VirusTotal API key (Environment variable `VIRUSTOTAL_API_KEY` or local vault).
fn resolve_vt_key() -> Option<(String, &'static str, bool)> {
    let disk = load_vt_disk_config();
    if let Ok(env_key) = std::env::var("VIRUSTOTAL_API_KEY") {
        let trimmed = env_key.trim().to_string();
        if !trimmed.is_empty() {
            return Some((trimmed, "Environment (VIRUSTOTAL_API_KEY)", disk.auto_check_suspicious));
        }
    }
    let trimmed = disk.api_key.trim().to_string();
    if !trimmed.is_empty() {
        return Some((trimmed, "Local Vault (vt_config.json)", disk.auto_check_suspicious));
    }
    None
}

fn mask_key(key: &str) -> String {
    let chars: Vec<char> = key.chars().collect();
    if chars.len() <= 8 {
        "••••••••".to_string()
    } else {
        let prefix: String = chars[..4].iter().collect();
        let suffix: String = chars[chars.len() - 4..].iter().collect();
        format!("{}••••••••{}", prefix, suffix)
    }
}

pub fn get_vt_config_status() -> VtConfigStatus {
    let disk = load_vt_disk_config();
    if let Some((key, source, auto_check)) = resolve_vt_key() {
        VtConfigStatus {
            configured: true,
            masked_key: mask_key(&key),
            source: source.to_string(),
            auto_check_suspicious: auto_check,
        }
    } else {
        VtConfigStatus {
            configured: false,
            masked_key: "Not Configured".to_string(),
            source: "None".to_string(),
            auto_check_suspicious: disk.auto_check_suspicious,
        }
    }
}

pub fn update_vt_config(api_key: Option<String>, auto_check_suspicious: bool) -> Result<VtConfigStatus, String> {
    let mut cfg = load_vt_disk_config();
    if let Some(k) = api_key {
        let trimmed = k.trim();
        if !trimmed.is_empty() {
            cfg.api_key = trimmed.to_string();
        }
    }
    cfg.auto_check_suspicious = auto_check_suspicious;
    save_vt_disk_config(&cfg)?;
    let status = get_vt_config_status();
    realtime_shield::log_security_event(
        "VirusTotal Cloud",
        "Info",
        "VirusTotal v3 Configuration Updated",
        &format!("Source: {} • Auto-Check: {}", status.source, status.auto_check_suspicious),
        if status.configured { "API Key Active" } else { "Standby" },
    );
    Ok(status)
}

pub fn clear_vt_api_key() -> Result<VtConfigStatus, String> {
    let mut cfg = load_vt_disk_config();
    cfg.api_key.clear();
    save_vt_disk_config(&cfg)?;
    Ok(get_vt_config_status())
}

pub fn should_auto_check_vt() -> bool {
    resolve_vt_key().map(|(_, _, auto)| auto).unwrap_or(false)
}

/// Query VirusTotal v3 API for a SHA-256 hash or local file path (computes SHA-256 locally; never uploads file bytes).
pub fn vt_check_target(input: &str) -> Result<VtScanReport, String> {
    let (api_key, _, _) = resolve_vt_key().ok_or_else(|| {
        "No VirusTotal API key configured. Enter your free VirusTotal API key or set VIRUSTOTAL_API_KEY.".to_string()
    })?;

    let trimmed = input.trim();
    if trimmed.is_empty() {
        return Err("Please provide a file path, SHA-256 hash, or URL/domain.".to_string());
    }

    // 1. Determine if input is a 64-char hex SHA-256, an existing local file path, or a URL/domain.
    let is_sha256 = trimmed.len() == 64 && trimmed.chars().all(|c| c.is_ascii_hexdigit());
    let as_path = std::path::Path::new(trimmed);

    let (query_type, indicator, display_target) = if is_sha256 {
        ("file_hash".to_string(), trimmed.to_lowercase(), trimmed.to_lowercase())
    } else if as_path.exists() && as_path.is_file() {
        let sha = scanner::compute_file_sha256(as_path)
            .ok_or_else(|| format!("Failed to read and hash file: {}", trimmed))?;
        ("file_hash".to_string(), sha, trimmed.to_string())
    } else if trimmed.starts_with("http://")
        || trimmed.starts_with("https://")
        || (trimmed.contains('.') && !trimmed.contains('\\') && !trimmed.contains('/'))
    {
        let dom = extract_domain_simple(trimmed);
        if dom.is_empty() {
            return Err(format!("Could not extract valid domain from '{}'", trimmed));
        }
        ("domain".to_string(), dom, trimmed.to_string())
    } else {
        return Err(format!(
            "Target '{}' is neither a valid 64-character SHA-256 hash, an existing local file, nor a domain/URL.",
            trimmed
        ));
    };

    let cache_key = format!("{}:{}", query_type, indicator);
    if let Ok(cache) = VT_CACHE.read() {
        if let Some(cached) = cache.get(&cache_key) {
            return Ok(cached.clone());
        }
    }

    let endpoint = if query_type == "file_hash" {
        format!("https://www.virustotal.com/api/v3/files/{}", indicator)
    } else {
        format!("https://www.virustotal.com/api/v3/domains/{}", indicator)
    };

    let permalink = if query_type == "file_hash" {
        format!("https://www.virustotal.com/gui/file/{}", indicator)
    } else {
        format!("https://www.virustotal.com/gui/domain/{}", indicator)
    };

    let agent = ureq::AgentBuilder::new()
        .timeout(Duration::from_secs(20))
        .user_agent("GenesisSeek/0.2 (+virustotal-v3)")
        .build();

    let response = agent
        .get(&endpoint)
        .set("x-apikey", &api_key)
        .set("Accept", "application/json")
        .call();

    match response {
        Ok(resp) => {
            let body: serde_json::Value = serde_json::from_reader(resp.into_reader())
                .map_err(|e| format!("Failed to parse VirusTotal JSON response: {}", e))?;
            let attrs = &body["data"]["attributes"];
            let stats = &attrs["last_analysis_stats"];

            let malicious = stats["malicious"].as_u64().unwrap_or(0) as u32;
            let suspicious = stats["suspicious"].as_u64().unwrap_or(0) as u32;
            let undetected = stats["undetected"].as_u64().unwrap_or(0) as u32;
            let harmless = stats["harmless"].as_u64().unwrap_or(0) as u32;
            let total_engines = malicious + suspicious + undetected + harmless;

            let threat_label = attrs["popular_threat_classification"]["suggested_threat_label"]
                .as_str()
                .or_else(|| attrs["meaningful_name"].as_str())
                .unwrap_or(if malicious > 0 {
                    "Multi-Engine Malware Detection"
                } else {
                    "No Threat Label"
                })
                .to_string();

            let mut flagged_engines = Vec::new();
            if let Some(results) = attrs["last_analysis_results"].as_object() {
                for (engine_name, detail) in results {
                    let cat = detail["category"].as_str().unwrap_or("");
                    if cat == "malicious" || cat == "suspicious" {
                        let res_name = detail["result"].as_str().unwrap_or(cat);
                        flagged_engines.push(format!("{}: {}", engine_name, res_name));
                        if flagged_engines.len() >= 10 {
                            break;
                        }
                    }
                }
            }

            let verdict = if malicious >= 2 || (malicious == 1 && suspicious >= 1) {
                "Malicious"
            } else if malicious == 1 || suspicious >= 1 {
                "Suspicious"
            } else {
                "Clean"
            }
            .to_string();

            // Feed positive detections back into Genesis Seek's live in-memory & SQLite IOC sets!
            if verdict == "Malicious" {
                if query_type == "file_hash" {
                    if let Ok(mut set) = DYNAMIC_HASHES.write() {
                        set.insert(indicator.clone());
                    }
                    let _ = scanner::batch_insert_threat_hashes(&[(
                        indicator.clone(),
                        format!("VirusTotal.{}", threat_label),
                        "VirusTotal.Cloud".to_string(),
                        "Critical".to_string(),
                    )]);
                } else if let Ok(mut set) = DYNAMIC_BAD_DOMAINS.write() {
                    set.insert(indicator.clone());
                }
            }

            let report = VtScanReport {
                query_type: query_type.clone(),
                target: display_target.clone(),
                indicator: indicator.clone(),
                found_in_vt: true,
                malicious,
                suspicious,
                undetected,
                harmless,
                total_engines,
                verdict: verdict.clone(),
                threat_label: threat_label.clone(),
                flagged_engines,
                permalink,
            };

            if let Ok(mut cache) = VT_CACHE.write() {
                cache.insert(cache_key, report.clone());
            }

            realtime_shield::log_security_event(
                "VirusTotal Cloud",
                if verdict == "Malicious" {
                    "Critical"
                } else if verdict == "Suspicious" {
                    "Medium"
                } else {
                    "Info"
                },
                &format!(
                    "VirusTotal: {}/{} engines flagged ({})",
                    malicious + suspicious,
                    total_engines,
                    verdict
                ),
                &display_target,
                &threat_label,
            );

            Ok(report)
        }
        Err(ureq::Error::Status(404, _)) => {
            let report = VtScanReport {
                query_type,
                target: display_target.clone(),
                indicator,
                found_in_vt: false,
                malicious: 0,
                suspicious: 0,
                undetected: 0,
                harmless: 0,
                total_engines: 0,
                verdict: "Not Found in VT".to_string(),
                threat_label: "Hash/indicator not previously submitted to VirusTotal (Zero-upload privacy preserved)".to_string(),
                flagged_engines: Vec::new(),
                permalink,
            };
            if let Ok(mut cache) = VT_CACHE.write() {
                cache.insert(cache_key, report.clone());
            }
            Ok(report)
        }
        Err(ureq::Error::Status(401, _)) | Err(ureq::Error::Status(403, _)) => {
            Err("VirusTotal rejected the API key (HTTP 401/403). Please verify your VirusTotal API key.".to_string())
        }
        Err(ureq::Error::Status(429, _)) => {
            Err("VirusTotal rate limit reached (HTTP 429 — free tier allows 4 lookups/minute). Please wait a moment.".to_string())
        }
        Err(e) => Err(format!("VirusTotal request error: {}", e)),
    }
}

fn extract_domain_simple(raw_url: &str) -> String {
    let lower = raw_url.trim().to_lowercase();
    let without_scheme = lower.split_once("://").map(|(_, rest)| rest).unwrap_or(&lower);
    let authority = without_scheme
        .split(|c| c == '/' || c == '?' || c == '#')
        .next()
        .unwrap_or("");
    let host_port = authority.rsplit('@').next().unwrap_or(authority);
    host_port.split(':').next().unwrap_or("").trim_end_matches('.').to_string()
}

// ============================================================================
// 1-Click GitHub Release Self-Updater (Windows & Linux)
// ============================================================================

const GITHUB_LATEST_RELEASE_API: &str =
    "https://api.github.com/repos/Coraje187/Genesis-Seek/releases/latest";
const MAX_UPDATE_BYTES: u64 = 80 * 1024 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppUpdateInfo {
    pub current_version: String,
    pub latest_version: String,
    pub update_available: bool,
    pub asset_name: String,
    pub download_url: String,
    pub release_url: String,
    pub published_at: String,
    pub release_notes: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppUpdateInstallResult {
    pub success: bool,
    pub restarted: bool,
    pub installed_version: String,
    pub saved_path: String,
    pub message: String,
}

fn parse_version_tuple(ver: &str) -> (u32, u32, u32) {
    let clean = ver.trim().trim_start_matches(|c: char| !c.is_ascii_digit());
    let mut parts = clean.split('.').map(|p| {
        p.chars()
            .take_while(|c| c.is_ascii_digit())
            .collect::<String>()
            .parse::<u32>()
            .unwrap_or(0)
    });
    (
        parts.next().unwrap_or(0),
        parts.next().unwrap_or(0),
        parts.next().unwrap_or(0),
    )
}

/// Remove any leftover `.old` executable created by a previous Windows in-place update.
pub fn cleanup_old_update_backup() {
    if let Ok(exe) = std::env::current_exe() {
        let old_backup = exe.with_extension("exe.old");
        if old_backup.exists() {
            let _ = fs::remove_file(old_backup);
        }
    }
}

/// Check `Coraje187/Genesis-Seek` GitHub Releases for a newer version.
pub fn check_github_update() -> Result<AppUpdateInfo, String> {
    cleanup_old_update_backup();
    let current_version = format!("v{}", env!("CARGO_PKG_VERSION"));

    let agent = ureq::AgentBuilder::new()
        .timeout(Duration::from_secs(15))
        .user_agent("GenesisSeek-Updater/0.2 (+https://github.com/Coraje187/Genesis-Seek)")
        .build();

    let resp = agent
        .get(GITHUB_LATEST_RELEASE_API)
        .set("Accept", "application/vnd.github+json")
        .call()
        .map_err(|e| format!("Failed to reach GitHub Releases API: {}", e))?;

    let body: serde_json::Value = serde_json::from_reader(resp.into_reader())
        .map_err(|e| format!("Invalid GitHub release JSON: {}", e))?;

    let raw_tag = body["tag_name"].as_str().unwrap_or("v0.2.0").trim();
    let latest_version = if raw_tag.starts_with('v') {
        raw_tag.to_string()
    } else {
        format!("v{}", raw_tag)
    };

    let release_url = body["html_url"]
        .as_str()
        .unwrap_or("https://github.com/Coraje187/Genesis-Seek/releases/latest")
        .to_string();
    let published_at = body["published_at"].as_str().unwrap_or("").to_string();
    let release_notes = body["body"]
        .as_str()
        .unwrap_or("Latest security engine and threat intelligence update.")
        .to_string();

    let cur_tuple = parse_version_tuple(&current_version);
    let lat_tuple = parse_version_tuple(&latest_version);
    let update_available = lat_tuple > cur_tuple;

    // Select best asset for current OS
    let mut asset_name = String::new();
    let mut download_url = String::new();

    if let Some(assets) = body["assets"].as_array() {
        #[cfg(target_os = "windows")]
        {
            // Prefer standalone genesis-seek.exe for instant in-place self-replacement
            for a in assets {
                let name = a["name"].as_str().unwrap_or("");
                let url = a["browser_download_url"].as_str().unwrap_or("");
                if name.eq_ignore_ascii_case("genesis-seek.exe") {
                    asset_name = name.to_string();
                    download_url = url.to_string();
                    break;
                }
            }
            if download_url.is_empty() {
                for a in assets {
                    let name = a["name"].as_str().unwrap_or("");
                    let url = a["browser_download_url"].as_str().unwrap_or("");
                    if name.ends_with(".exe") || (name.contains("windows") && name.ends_with(".zip")) {
                        asset_name = name.to_string();
                        download_url = url.to_string();
                        break;
                    }
                }
            }
        }

        #[cfg(not(target_os = "windows"))]
        {
            for a in assets {
                let name = a["name"].as_str().unwrap_or("");
                let url = a["browser_download_url"].as_str().unwrap_or("");
                if name.ends_with(".AppImage") || name == "genesis-seek" {
                    asset_name = name.to_string();
                    download_url = url.to_string();
                    break;
                }
            }
            if download_url.is_empty() {
                for a in assets {
                    let name = a["name"].as_str().unwrap_or("");
                    let url = a["browser_download_url"].as_str().unwrap_or("");
                    if name.ends_with(".deb") || (name.contains("linux") && name.ends_with(".tar.gz")) {
                        asset_name = name.to_string();
                        download_url = url.to_string();
                        break;
                    }
                }
            }
        }
    }

    if download_url.is_empty() {
        #[cfg(target_os = "windows")]
        {
            asset_name = "genesis-seek.exe".to_string();
            download_url =
                "https://github.com/Coraje187/Genesis-Seek/releases/latest/download/genesis-seek.exe"
                    .to_string();
        }
        #[cfg(not(target_os = "windows"))]
        {
            asset_name = "GitHub Release Page".to_string();
            download_url = release_url.clone();
        }
    }

    Ok(AppUpdateInfo {
        current_version,
        latest_version,
        update_available,
        asset_name,
        download_url,
        release_url,
        published_at,
        release_notes,
    })
}

/// Download the latest release binary from GitHub and apply the self-update on Windows or Linux.
pub fn install_github_update() -> Result<AppUpdateInstallResult, String> {
    let info = check_github_update()?;

    let agent = ureq::AgentBuilder::new()
        .timeout(Duration::from_secs(90))
        .user_agent("GenesisSeek-Updater/0.2 (+https://github.com/Coraje187/Genesis-Seek)")
        .build();

    #[cfg(target_os = "windows")]
    {
        if !info.download_url.ends_with(".exe") {
            let _ = std::process::Command::new("cmd")
                .args(["/c", "start", &info.release_url])
                .spawn();
            return Ok(AppUpdateInstallResult {
                success: true,
                restarted: false,
                installed_version: info.latest_version,
                saved_path: info.release_url,
                message: "Opened GitHub Release page in your browser to download the latest package."
                    .to_string(),
            });
        }

        let resp = agent
            .get(&info.download_url)
            .call()
            .map_err(|e| format!("Failed to download update from GitHub: {}", e))?;

        let mut bytes = Vec::new();
        use std::io::Read;
        resp.into_reader()
            .take(MAX_UPDATE_BYTES)
            .read_to_end(&mut bytes)
            .map_err(|e| format!("Error reading update stream: {}", e))?;

        if bytes.len() < 1024 * 100 || !bytes.starts_with(b"MZ") {
            return Err("Downloaded file is not a valid Windows PE executable.".to_string());
        }

        let current_exe = std::env::current_exe()
            .map_err(|e| format!("Cannot resolve current executable path: {}", e))?;
        let old_backup = current_exe.with_extension("exe.old");
        let _ = fs::remove_file(&old_backup);

        // Windows allows renaming a running .exe and writing the new .exe in its place!
        if fs::rename(&current_exe, &old_backup).is_ok() {
            if let Err(e) = fs::write(&current_exe, &bytes) {
                // Roll back rename if writing failed
                let _ = fs::rename(&old_backup, &current_exe);
                return Err(format!("Failed to write new executable: {}", e));
            }

            realtime_shield::log_security_event(
                "System Updater",
                "Info",
                &format!("Updated Genesis Seek to {}", info.latest_version),
                &current_exe.to_string_lossy(),
                "Restarting into new build",
            );

            // Spawn the newly written executable and exit current process after 600ms
            let exe_clone = current_exe.clone();
            std::thread::spawn(move || {
                std::thread::sleep(Duration::from_millis(600));
                let _ = std::process::Command::new(&exe_clone).spawn();
                std::process::exit(0);
            });

            return Ok(AppUpdateInstallResult {
                success: true,
                restarted: true,
                installed_version: info.latest_version.clone(),
                saved_path: current_exe.to_string_lossy().to_string(),
                message: format!(
                    "Genesis Seek {} downloaded and installed in-place! Restarting application now...",
                    info.latest_version
                ),
            });
        }

        // Fallback if running from a protected directory: stage in Downloads and launch
        let dl_target = dirs::download_dir()
            .unwrap_or_else(std::env::temp_dir)
            .join("genesis-seek-latest.exe");
        fs::write(&dl_target, &bytes)
            .map_err(|e| format!("Failed to save update to Downloads: {}", e))?;

        let _ = std::process::Command::new(&dl_target).spawn();
        return Ok(AppUpdateInstallResult {
            success: true,
            restarted: true,
            installed_version: info.latest_version.clone(),
            saved_path: dl_target.to_string_lossy().to_string(),
            message: format!(
                "Downloaded Genesis Seek {} to {} and launched the updated version!",
                info.latest_version,
                dl_target.display()
            ),
        });
    }

    #[cfg(not(target_os = "windows"))]
    {
        if info.download_url.ends_with(".AppImage") || info.asset_name == "genesis-seek" {
            let resp = agent
                .get(&info.download_url)
                .call()
                .map_err(|e| format!("Failed to download Linux update from GitHub: {}", e))?;

            let mut bytes = Vec::new();
            use std::io::Read;
            resp.into_reader()
                .take(MAX_UPDATE_BYTES)
                .read_to_end(&mut bytes)
                .map_err(|e| format!("Error reading Linux update stream: {}", e))?;

            if bytes.len() < 1024 * 100 || !bytes.starts_with(b"\x7fELF") {
                return Err("Downloaded file is not a valid Linux ELF/AppImage binary.".to_string());
            }

            let target_bin = std::env::var_os("APPIMAGE")
                .map(PathBuf::from)
                .or_else(|| std::env::current_exe().ok())
                .ok_or_else(|| "Cannot determine current Linux binary path".to_string())?;

            let staged = target_bin.with_extension("new");
            if fs::write(&staged, &bytes).is_ok() {
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    let _ = fs::set_permissions(&staged, fs::Permissions::from_mode(0o755));
                }
                if fs::rename(&staged, &target_bin).is_ok() {
                    let bin_clone = target_bin.clone();
                    std::thread::spawn(move || {
                        std::thread::sleep(Duration::from_millis(600));
                        let _ = std::process::Command::new(&bin_clone).spawn();
                        std::process::exit(0);
                    });

                    return Ok(AppUpdateInstallResult {
                        success: true,
                        restarted: true,
                        installed_version: info.latest_version.clone(),
                        saved_path: target_bin.to_string_lossy().to_string(),
                        message: format!(
                            "Genesis Seek {} installed! Restarting application now...",
                            info.latest_version
                        ),
                    });
                }
            }
        }

        let _ = std::process::Command::new("xdg-open")
            .arg(&info.release_url)
            .spawn();
        Ok(AppUpdateInstallResult {
            success: true,
            restarted: false,
            installed_version: info.latest_version,
            saved_path: info.release_url,
            message: "Opened GitHub Release page in your browser to download the Linux package."
                .to_string(),
        })
    }
}
