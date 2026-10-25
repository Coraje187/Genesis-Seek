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

/// Malicious hosts downloaded from abuse.ch URLhaus (cached on disk between runs).
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

pub fn is_known_malware_hash(sha256: &str) -> bool {
    DYNAMIC_HASHES.read().map(|s| s.contains(sha256)).unwrap_or(false)
}

pub fn is_feed_bad_domain(domain: &str) -> bool {
    DYNAMIC_BAD_DOMAINS.read().map(|s| s.contains(domain)).unwrap_or(false)
}

fn fetch_text(url: &str) -> Result<String, String> {
    let agent = ureq::AgentBuilder::new()
        .timeout(Duration::from_secs(30))
        .user_agent("GenesisSeek/0.1 (+threat-feed-sync)")
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

/// Download the abuse.ch feeds, replace the in-memory indicator sets and cache them on disk.
/// Blocking — call from a background thread.
pub fn sync_threat_intelligence_feeds() -> ThreatFeedStatus {
    let sources = vec![
        sync_one("abuse.ch URLhaus malicious hosts", URLHAUS_HOSTFILE, "urlhaus_hosts.txt", parse_urlhaus_hosts, &DYNAMIC_BAD_DOMAINS),
        sync_one("abuse.ch MalwareBazaar recent SHA-256", BAZAAR_RECENT_SHA256, "bazaar_sha256.txt", parse_sha256_list, &DYNAMIC_HASHES),
    ];

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
            "Threat Feeds Synced".to_string()
        } else {
            format!("Threat Feed Sync Incomplete ({} failed)", failed.len())
        },
        &format!(
            "{} hashes • {} malicious hosts",
            status.total_hash_signatures, status.total_web_indicators
        ),
        if failed.is_empty() { "Updated" } else { "Partially Updated" },
    );
    status
}

pub fn get_threat_feed_status() -> ThreatFeedStatus {
    let hashes = DYNAMIC_HASHES.read().map(|s| s.len()).unwrap_or(0);
    let hosts = DYNAMIC_BAD_DOMAINS.read().map(|s| s.len()).unwrap_or(0);
    let (last_synced, mut sources) = LAST_SOURCES
        .lock()
        .map(|g| g.clone())
        .unwrap_or((None, Vec::new()));

    if sources.is_empty() {
        sources = vec![
            FeedSourceStatus { name: "abuse.ch URLhaus malicious hosts".into(), url: URLHAUS_HOSTFILE.into(), ok: hosts > 0, entries: hosts, error: None },
            FeedSourceStatus { name: "abuse.ch MalwareBazaar recent SHA-256".into(), url: BAZAAR_RECENT_SHA256.into(), ok: hashes > 0, entries: hashes, error: None },
        ];
    }

    ThreatFeedStatus {
        version: last_synced
            .map(|d| d.format("%Y.%m.%d-%H%M").to_string())
            .unwrap_or_else(|| "built-in only".to_string()),
        total_hash_signatures: scanner::builtin_hash_count() + hashes,
        total_web_indicators: realtime_shield::builtin_bad_domain_count() + hosts,
        yara_heuristic_rules: scanner::heuristic_rule_count(),
        last_synced,
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

            // Feed positive detections back into Genesis Seek's live in-memory IOC sets!
            if verdict == "Malicious" {
                if query_type == "file_hash" {
                    if let Ok(mut set) = DYNAMIC_HASHES.write() {
                        set.insert(indicator.clone());
                    }
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
