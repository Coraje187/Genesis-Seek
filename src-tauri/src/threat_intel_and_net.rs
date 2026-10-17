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
