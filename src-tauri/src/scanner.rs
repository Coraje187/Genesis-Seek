use crate::quarantine;
use crate::realtime_shield;
use crate::threat_intel_and_net;
use chrono::{DateTime, Utc};
use lru::LruCache;
use once_cell::sync::Lazy;
use regex::Regex;
use rusqlite::{params, Connection};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs::{self, File};
use std::io::Read;
use std::num::NonZeroUsize;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, RwLock};
use uuid::Uuid;
use walkdir::WalkDir;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatDetection {
    pub id: String,
    pub file_path: String,
    pub threat_name: String,
    pub category: String,
    pub severity: String, // "Critical", "High", "Medium"
    pub sha256: String,
    pub entropy: f64,
    pub detection_engine: String,
    pub detected_at: DateTime<Utc>,
    pub description: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanReport {
    pub scan_id: String,
    pub scan_type: String,
    pub scanned_files: usize,
    pub skipped_files: usize,
    pub duration_ms: u128,
    pub detections: Vec<ThreatDetection>,
    pub completed_at: DateTime<Utc>,
}

/// Verdict cached in the in-memory LRU cache keyed by `(device_id, inode_or_file_index, mtime_secs, file_size)`.
#[derive(Debug, Clone)]
pub enum ScanVerdict {
    Clean,
    Malicious(ThreatDetection),
}

type VerdictCacheKey = (u64, u64, i64, u64);

/// Compiled pure-Rust YARA rule loaded from built-in definitions or `.yar` files in `rules/`.
#[derive(Debug, Clone)]
pub struct CompiledYaraRule {
    pub name: String,
    pub category: String,
    pub severity: String,
    pub description: String,
    pub pattern: Regex,
}

/// Thread-safe enterprise scanner engine holding compiled YARA rules and SQLite database path.
pub struct ScannerEngine {
    pub yara_rules: Vec<CompiledYaraRule>,
    pub rules_dir: PathBuf,
    pub db_path: PathBuf,
}

/// Max file size inspected (keeps scans fast and memory low).
const MAX_FILE_BYTES: u64 = 64 * 1024 * 1024;
/// Bytes of file content kept for heuristic/YARA/entropy analysis.
const CONTENT_WINDOW: usize = 2 * 1024 * 1024;

/// Default YARA rules materialized into `rules/genesis_core_rules.yar`.
const DEFAULT_CORE_YARA_FILE: &str = r#"
rule YARA_ReverseShell_NetworkPipe {
    meta:
        category = "Backdoor.Shell"
        severity = "Critical"
        description = "Interactive reverse shell command sequence capable of granting remote unauthorized control."
    strings:
        $re = /(bash\s+-i\s+>&\s*\/dev\/tcp\/|nc(at)?\s+-e\s+\/bin\/(ba)?sh|Invoke-PowerShellTcp|socat\s+TCP4?.*EXEC:)/i
    condition:
        any of them
}

rule YARA_PowerShell_ObfuscatedDropper {
    meta:
        category = "Trojan.Dropper"
        severity = "Critical"
        description = "Obfuscated or fileless PowerShell execution pattern commonly used by staging droppers."
    strings:
        $re = /(powershell.*\s-(e|enc|encodedcommand)\s+[A-Za-z0-9+\/=]{24,}|IEX\s*\(\s*New-Object\s+Net\.WebClient\)\.DownloadString|FromBase64String.*Invoke-Expression)/i
    condition:
        any of them
}

rule YARA_Ransomware_ShadowCopyWipe {
    meta:
        category = "Ransomware.Behavior"
        severity = "Critical"
        description = "Attempts to inhibit system recovery by deleting Volume Shadow Copies or backup catalogs."
    strings:
        $re = /(vssadmin(\.exe)?\s+delete\s+shadows|wmic(\.exe)?\s+shadowcopy\s+delete|wbadmin\s+delete\s+catalog|bcdedit.*recoveryenabled\s+no)/i
    condition:
        any of them
}

rule YARA_CryptoMiner_StratumPool {
    meta:
        category = "Riskware.CryptoMiner"
        severity = "High"
        description = "Unauthorized cryptocurrency mining pool protocol or configuration signature."
    strings:
        $re = /(stratum\+(tcp|ssl):\/\/|donate-level.*xmrig|pool\.minexmr\.com|nanopool\.org)/i
    condition:
        any of them
}

rule YARA_Linux_StealthPreload_Rootkit {
    meta:
        category = "Rootkit.Linux"
        severity = "Critical"
        description = "Linux shared-library hijacking via ld.so.preload or a preload library in a volatile directory."
    strings:
        $re = /(>>?\s*\/etc\/ld\.so\.preload|LD_PRELOAD\s*=\s*\/(tmp|dev\/shm|var\/tmp)\/)/i
    condition:
        any of them
}

rule YARA_CredentialStealer_BrowserDB {
    meta:
        category = "Spyware.Infostealer"
        severity = "Critical"
        description = "Targets browser credential databases and master decryption keys (Infostealer behavior)."
    strings:
        $re = /(Login Data.{0,400}Local State.{0,400}CryptUnprotectData|cookies\.sqlite.{0,400}key4\.db.{0,400}logins\.json)/is
    condition:
        any of them
}

rule YARA_Python_ObfuscatedExec {
    meta:
        category = "Trojan.PythonDropper"
        severity = "High"
        description = "Obfuscated Python exec/marshal/base64 stage-loader payload."
    strings:
        $re = /(exec\s*\(\s*__import__\s*\(\s*['"]base64['"]\s*\)\.b64decode|marshal\.loads\s*\(\s*zlib\.decompress)/i
    condition:
        any of them
}
"#;

/// The EICAR test string is assembled at runtime from two halves so the literal never
/// appears in our source or compiled binary.
pub fn eicar_test_string() -> String {
    [
        r"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-",
        "STANDARD-ANTIVIRUS-TEST-FILE!$H+H*",
    ]
    .concat()
}

static KNOWN_HASHES: Lazy<HashMap<&'static str, (&'static str, &'static str, &'static str)>> =
    Lazy::new(|| {
        let mut m = HashMap::new();
        m.insert(
            "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
            ("EICAR-Standard-AV-Test-Signature", "Test.Signature", "High"),
        );
        m.insert(
            "ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa",
            ("Ransom.WannaCry.Gen", "Ransomware", "Critical"),
        );
        m
    });

/// Global LRU Verdict Cache keyed by `(device_id, inode_or_file_index, mtime_secs, file_size)`.
static VERDICT_CACHE: Lazy<Mutex<LruCache<VerdictCacheKey, ScanVerdict>>> = Lazy::new(|| {
    Mutex::new(LruCache::new(NonZeroUsize::new(16_384).unwrap()))
});

/// Global thread-safe `Arc<RwLock<ScannerEngine>>` initialized on startup.
pub static SCANNER_ENGINE: Lazy<Arc<RwLock<ScannerEngine>>> = Lazy::new(|| {
    let rules_dir = rules_directory();
    let db_path = sqlite_db_path();
    init_sqlite_db(&db_path);
    ensure_default_yara_files(&rules_dir);
    let yara_rules = load_yara_rules_from_dir(&rules_dir);
    Arc::new(RwLock::new(ScannerEngine {
        yara_rules,
        rules_dir,
        db_path,
    }))
});

pub fn rules_directory() -> PathBuf {
    let dir = realtime_shield::app_config_dir().join("rules");
    let _ = fs::create_dir_all(&dir);
    dir
}

pub fn sqlite_db_path() -> PathBuf {
    realtime_shield::app_config_dir().join("threat_hashes.db")
}

fn init_sqlite_db(db_path: &Path) {
    if let Ok(conn) = Connection::open(db_path) {
        let _ = conn.execute_batch(
            "PRAGMA journal_mode = WAL;
             PRAGMA synchronous = NORMAL;
             CREATE TABLE IF NOT EXISTS threat_hashes (
                 sha256 TEXT PRIMARY KEY,
                 threat_name TEXT NOT NULL,
                 category TEXT NOT NULL,
                 severity TEXT NOT NULL,
                 updated_at TEXT NOT NULL
             ) WITHOUT ROWID;",
        );
        let now = Utc::now().to_rfc3339();
        for (&sha, &(name, cat, sev)) in KNOWN_HASHES.iter() {
            let _ = conn.execute(
                "INSERT OR IGNORE INTO threat_hashes (sha256, threat_name, category, severity, updated_at)
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                params![sha, name, cat, sev, now],
            );
        }
    }
}

/// Fast $O(1)$ PRIMARY KEY lookup in local SQLite `threat_hashes.db`.
pub fn lookup_sqlite_hash(sha256: &str) -> Option<(String, String, String)> {
    let db_path = sqlite_db_path();
    let conn = Connection::open(db_path).ok()?;
    let mut stmt = conn
        .prepare_cached(
            "SELECT threat_name, category, severity FROM threat_hashes WHERE sha256 = ?1 LIMIT 1",
        )
        .ok()?;
    stmt.query_row(params![sha256], |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, String>(2)?,
        ))
    })
    .ok()
}

/// Batch-insert SHA-256 malware signatures into `threat_hashes.db` inside a single transaction.
pub fn batch_insert_threat_hashes(entries: &[(String, String, String, String)]) -> usize {
    let db_path = sqlite_db_path();
    let Ok(mut conn) = Connection::open(&db_path) else {
        return 0;
    };
    init_sqlite_db(&db_path);
    let Ok(tx) = conn.transaction() else {
        return 0;
    };
    let now = Utc::now().to_rfc3339();
    let mut inserted = 0usize;
    {
        if let Ok(mut stmt) = tx.prepare(
            "INSERT OR REPLACE INTO threat_hashes (sha256, threat_name, category, severity, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5)",
        ) {
            for (sha, name, cat, sev) in entries {
                if stmt.execute(params![sha, name, cat, sev, now]).is_ok() {
                    inserted += 1;
                }
            }
        }
    }
    let _ = tx.commit();
    inserted
}

pub fn sqlite_hash_count() -> usize {
    let db_path = sqlite_db_path();
    if let Ok(conn) = Connection::open(db_path) {
        if let Ok(count) = conn.query_row("SELECT COUNT(*) FROM threat_hashes", [], |r| r.get::<_, i64>(0)) {
            return count.max(0) as usize;
        }
    }
    KNOWN_HASHES.len()
}

fn ensure_default_yara_files(rules_dir: &Path) {
    let core_file = rules_dir.join("genesis_core_rules.yar");
    if !core_file.exists() {
        let _ = fs::write(core_file, DEFAULT_CORE_YARA_FILE.trim());
    }

    // Copy bundled .yar rule files from relative rules folders
    for rel in &["rules", "../rules", "../../rules"] {
        let rel_p = PathBuf::from(rel);
        if rel_p.is_dir() {
            if let Ok(entries) = fs::read_dir(rel_p) {
                for entry in entries.flatten() {
                    let p = entry.path();
                    let ext = p.extension().and_then(|e| e.to_str()).unwrap_or("");
                    if ext.eq_ignore_ascii_case("yar") || ext.eq_ignore_ascii_case("yara") {
                        let dest = rules_dir.join(entry.file_name());
                        if !dest.exists() {
                            let _ = fs::copy(&p, &dest);
                        }
                    }
                }
            }
        }
    }
}

/// Parse `.yar` / `.yara` rule files from `rules/` into `CompiledYaraRule` patterns.
pub fn load_yara_rules_from_dir(rules_dir: &Path) -> Vec<CompiledYaraRule> {
    let mut rules = Vec::new();
    let mut raw_sources = vec![DEFAULT_CORE_YARA_FILE.to_string()];

    if let Ok(entries) = fs::read_dir(rules_dir) {
        for entry in entries.flatten() {
            let p = entry.path();
            let ext = p.extension().and_then(|e| e.to_str()).unwrap_or("");
            if (ext.eq_ignore_ascii_case("yar") || ext.eq_ignore_ascii_case("yara"))
                && p.file_name().and_then(|n| n.to_str()) != Some("genesis_core_rules.yar")
            {
                if let Ok(text) = fs::read_to_string(&p) {
                    raw_sources.push(text);
                }
            }
        }
    }

    let block_re = Regex::new(r"(?s)rule\s+([A-Za-z0-9_]+)\s*\{(.*?)\}").unwrap();
    let meta_cat_re = Regex::new(r#"category\s*=\s*"([^"]+)""#).unwrap();
    let meta_sev_re = Regex::new(r#"severity\s*=\s*"([^"]+)""#).unwrap();
    let meta_desc_re = Regex::new(r#"description\s*=\s*"([^"]+)""#).unwrap();
    let regex_str_re = Regex::new(r"\$[A-Za-z0-9_]+\s*=\s*/(.*?)/([is]*)").unwrap();
    let literal_str_re = Regex::new(r#"\$[A-Za-z0-9_]+\s*=\s*"([^"]{4,})"\s*(nocase)?"#).unwrap();

    for src in &raw_sources {
        for cap in block_re.captures_iter(src) {
            let name = cap[1].to_string();
            let body = &cap[2];
            let category = meta_cat_re
                .captures(body)
                .map(|c| c[1].to_string())
                .unwrap_or_else(|| "YARA.Heuristic".to_string());
            let severity = meta_sev_re
                .captures(body)
                .map(|c| c[1].to_string())
                .unwrap_or_else(|| "High".to_string());
            let description = meta_desc_re
                .captures(body)
                .map(|c| c[1].to_string())
                .unwrap_or_else(|| format!("Matched YARA rule {}", name));

            let mut sub_patterns = Vec::new();
            for rcap in regex_str_re.captures_iter(body) {
                let pat = &rcap[1];
                let flags = &rcap[2];
                let prefix = if flags.contains('i') && flags.contains('s') {
                    "(?is)"
                } else if flags.contains('s') {
                    "(?s)"
                } else {
                    "(?i)"
                };
                sub_patterns.push(format!("{}(?:{})", prefix, pat));
            }
            for lcap in literal_str_re.captures_iter(body) {
                let lit = regex::escape(&lcap[1]);
                sub_patterns.push(format!("(?i)(?:{})", lit));
            }

            if !sub_patterns.is_empty() {
                let combined = sub_patterns.join("|");
                if let Ok(compiled) = Regex::new(&combined) {
                    if !rules.iter().any(|r: &CompiledYaraRule| r.name == name) {
                        rules.push(CompiledYaraRule {
                            name,
                            category,
                            severity,
                            description,
                            pattern: compiled,
                        });
                    }
                }
            }
        }
    }

    rules
}

/// Hot-reload `.yar` files from `rules/` into the global `SCANNER_ENGINE` and clear the LRU cache.
pub fn reload_yara_rules() -> usize {
    let dir = rules_directory();
    ensure_default_yara_files(&dir);
    let loaded = load_yara_rules_from_dir(&dir);
    let count = loaded.len();
    if let Ok(mut eng) = SCANNER_ENGINE.write() {
        eng.yara_rules = loaded;
    }
    if let Ok(mut cache) = VERDICT_CACHE.lock() {
        cache.clear();
    }
    count
}

pub fn builtin_hash_count() -> usize {
    sqlite_hash_count().max(KNOWN_HASHES.len())
}

pub fn heuristic_rule_count() -> usize {
    let yara_len = SCANNER_ENGINE
        .read()
        .map(|e| e.yara_rules.len())
        .unwrap_or(7);
    // +4 for EICAR, double-extension, disguised ELF/PE magic header, and UPX/entropy analyzer
    yara_len + 4
}

static DOUBLE_EXT_REGEX: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)\.(pdf|doc|docx|xls|xlsx|jpg|jpeg|png|txt|mp4|zip)\.(exe|scr|bat|cmd|vbs|ps1|js|hta|com|pif)$").unwrap()
});

/// Compute the 4-tuple cache key `(device_id, inode_or_file_index, mtime_secs, file_size)` for $O(1)$ LRU lookups.
fn file_cache_key(path: &Path, metadata: &fs::Metadata) -> VerdictCacheKey {
    let file_size = metadata.len();
    let mtime_secs = metadata
        .modified()
        .ok()
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);

    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        return (metadata.dev(), metadata.ino(), mtime_secs, file_size);
    }

    #[cfg(not(unix))]
    {
        // Fast 64-bit FNV-1a path hash + creation time on Windows
        let created_ticks = metadata
            .created()
            .ok()
            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0);
        let mut hash: u64 = 0xcbf29ce484222325;
        for b in path.to_string_lossy().as_bytes() {
            hash ^= b.to_ascii_lowercase() as u64;
            hash = hash.wrapping_mul(0x100000001b3);
        }
        (created_ticks, hash, mtime_secs, file_size)
    }
}

/// Explicitly record a `Clean` verdict in the LRU cache for a verified executable path.
pub fn cache_clean_verdict(path: &Path) {
    if let Ok(meta) = fs::metadata(path) {
        let key = file_cache_key(path, &meta);
        if let Ok(mut cache) = VERDICT_CACHE.lock() {
            cache.put(key, ScanVerdict::Clean);
        }
    }
}

/// Check if a file is already verified `Clean` in the LRU Verdict Cache.
pub fn is_cached_clean(path: &Path) -> bool {
    let Ok(meta) = fs::metadata(path) else {
        return false;
    };
    let key = file_cache_key(path, &meta);
    if let Ok(mut cache) = VERDICT_CACHE.lock() {
        return matches!(cache.get(&key), Some(ScanVerdict::Clean));
    }
    false
}

/// Detect non-executable document/media extensions hiding raw PE (`MZ`) or Linux (`\x7fELF`) binaries.
fn is_disguised_executable_header(path: &Path, head: &[u8]) -> Option<&'static str> {
    let ext = path
        .extension()
        .map(|e| e.to_string_lossy().to_lowercase())
        .unwrap_or_default();
    let is_doc_or_media = matches!(
        ext.as_str(),
        "txt" | "pdf" | "jpg" | "jpeg" | "png" | "gif" | "svg" | "doc" | "docx" | "xls" | "xlsx" | "mp3" | "mp4" | "csv"
    );
    if !is_doc_or_media {
        return None;
    }
    if head.starts_with(b"MZ") {
        Some("Windows PE (MZ) executable disguised with document/media extension")
    } else if head.starts_with(b"\x7fELF") {
        Some("Linux ELF binary disguised with document/media extension")
    } else {
        None
    }
}

fn is_content_scannable(path: &Path, head: &[u8]) -> bool {
    if head.starts_with(b"#!") || head.starts_with(b"MZ") || head.starts_with(b"\x7fELF") {
        return true;
    }
    let ext = path
        .extension()
        .map(|e| e.to_string_lossy().to_lowercase())
        .unwrap_or_default();
    matches!(
        ext.as_str(),
        "sh" | "bash" | "zsh" | "ps1" | "psm1" | "bat" | "cmd" | "vbs" | "vbe" | "js" | "jse"
            | "hta" | "wsf" | "py" | "pl" | "desktop" | "service" | "exe" | "dll" | "scr"
            | "com" | "so" | "appimage" | "elf" | "bin"
    )
}

/// Calculate Shannon entropy (0.0 to 8.0 bits per byte) of a byte slice.
pub fn calculate_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut counts = [0usize; 256];
    for &b in data {
        counts[b as usize] += 1;
    }
    let len = data.len() as f64;
    let mut entropy = 0.0;
    for &count in &counts {
        if count > 0 {
            let p = (count as f64) / len;
            entropy -= p * p.log2();
        }
    }
    (entropy * 100.0).round() / 100.0
}

fn hash_and_sample(path: &Path) -> Option<(String, Vec<u8>)> {
    let mut file = File::open(path).ok()?;
    let mut hasher = Sha256::new();
    let mut head = Vec::with_capacity(64 * 1024);
    let mut chunk = vec![0u8; 64 * 1024];
    loop {
        let n = file.read(&mut chunk).ok()?;
        if n == 0 {
            break;
        }
        hasher.update(&chunk[..n]);
        if head.len() < CONTENT_WINDOW {
            let take = std::cmp::min(n, CONTENT_WINDOW - head.len());
            head.extend_from_slice(&chunk[..take]);
        }
    }
    Some((hex::encode(hasher.finalize()), head))
}

/// Compute the full-file SHA-256 hash without uploading or retaining file contents.
pub fn compute_file_sha256(path: &Path) -> Option<String> {
    hash_and_sample(path).map(|(sha, _)| sha)
}

fn detection(
    path: &str,
    sha256: &str,
    entropy: f64,
    name: &str,
    category: &str,
    severity: &str,
    engine: &str,
    description: String,
) -> ThreatDetection {
    ThreatDetection {
        id: Uuid::new_v4().to_string(),
        file_path: path.to_string(),
        threat_name: name.to_string(),
        category: category.to_string(),
        severity: severity.to_string(),
        sha256: sha256.to_string(),
        entropy,
        detection_engine: engine.to_string(),
        detected_at: Utc::now(),
        description,
    }
}

/// Inspect a single file using the LRU Verdict Cache, SQLite SHA-256 DB, YARA rules, and entropy analysis.
pub fn scan_single_file(path: &Path) -> Option<ThreatDetection> {
    if is_excluded_path(path) {
        return None;
    }
    let metadata = fs::metadata(path).ok()?;
    if !metadata.is_file() || metadata.len() == 0 || metadata.len() > MAX_FILE_BYTES {
        return None;
    }

    let cache_key = file_cache_key(path, &metadata);
    if let Ok(mut cache) = VERDICT_CACHE.lock() {
        if let Some(verdict) = cache.get(&cache_key) {
            return match verdict {
                ScanVerdict::Clean => None,
                ScanVerdict::Malicious(det) => {
                    if quarantine::is_allowlisted(&det.sha256) {
                        None
                    } else {
                        Some(det.clone())
                    }
                }
            };
        }
    }

    let file_name = path.file_name()?.to_string_lossy().to_string();
    let full_path = path.to_string_lossy().to_string();

    let (sha256_hex, buffer) = hash_and_sample(path)?;

    if quarantine::is_allowlisted(&sha256_hex) {
        if let Ok(mut cache) = VERDICT_CACHE.lock() {
            cache.put(cache_key, ScanVerdict::Clean);
        }
        return None;
    }

    let entropy = calculate_entropy(&buffer);

    let store_and_return = |det: Option<ThreatDetection>| -> Option<ThreatDetection> {
        if let Ok(mut cache) = VERDICT_CACHE.lock() {
            match &det {
                Some(d) => {
                    cache.put(cache_key, ScanVerdict::Malicious(d.clone()));
                }
                None => {
                    cache.put(cache_key, ScanVerdict::Clean);
                }
            }
        }
        det
    };

    // Layer 1: Fast SHA-256 lookup (built-in map + indexed SQLite `threat_hashes.db` + MalwareBazaar feed).
    if let Some(&(name, category, severity)) = KNOWN_HASHES.get(sha256_hex.as_str()) {
        return store_and_return(Some(detection(
            &full_path,
            &sha256_hex,
            entropy,
            name,
            category,
            severity,
            "Signature Engine (SHA-256)",
            "Exact cryptographic hash match against core threat database.".to_string(),
        )));
    }
    if let Some((name, category, severity)) = lookup_sqlite_hash(&sha256_hex) {
        return store_and_return(Some(detection(
            &full_path,
            &sha256_hex,
            entropy,
            &name,
            &category,
            &severity,
            "SQLite Threat DB (O(1) SHA-256)",
            "SHA-256 matched indexed local threat_hashes.db signature.".to_string(),
        )));
    }
    if threat_intel_and_net::is_known_malware_hash(&sha256_hex) {
        return store_and_return(Some(detection(
            &full_path,
            &sha256_hex,
            entropy,
            "ThreatFeed.MalwareBazaar.Sample",
            "Malware",
            "Critical",
            "Signature Engine (MalwareBazaar feed)",
            "SHA-256 matches a recent malware sample published by abuse.ch MalwareBazaar.".to_string(),
        )));
    }

    // Layer 2: EICAR test file.
    if buffer.starts_with(eicar_test_string().as_bytes()) {
        return store_and_return(Some(detection(
            &full_path,
            &sha256_hex,
            entropy,
            "EICAR-Standard-AV-Test-Signature",
            "Test.Signature",
            "High",
            "Signature Engine (EICAR)",
            "Standard EICAR antivirus verification test file (harmless).".to_string(),
        )));
    }

    // Layer 3: Double-extension masquerading & disguised ELF/PE magic header detection.
    if DOUBLE_EXT_REGEX.is_match(&file_name) {
        return store_and_return(Some(detection(
            &full_path,
            &sha256_hex,
            entropy,
            "Heur.Masquerade.DoubleExtension",
            "Trojan.Masquerade",
            "High",
            "Heuristic File Anomaly",
            format!("Executable disguised with deceptive double file extension ({}).", file_name),
        )));
    }
    if let Some(reason) = is_disguised_executable_header(path, &buffer) {
        return store_and_return(Some(detection(
            &full_path,
            &sha256_hex,
            entropy,
            "Heur.Masquerade.DisguisedMagicHeader",
            "Trojan.Masquerade",
            "Critical",
            "Magic Header Inspector (ELF/PE)",
            format!("{} ({}).", reason, file_name),
        )));
    }

    if !is_content_scannable(path, &buffer) {
        return store_and_return(None);
    }

    // Layer 4: Compiled YARA-X / Pure-Rust YARA rules engine (`SCANNER_ENGINE`).
    let content_lossy = String::from_utf8_lossy(&buffer);
    if let Ok(engine) = SCANNER_ENGINE.read() {
        for rule in &engine.yara_rules {
            if rule.pattern.is_match(&content_lossy) {
                return store_and_return(Some(detection(
                    &full_path,
                    &sha256_hex,
                    entropy,
                    &rule.name,
                    &rule.category,
                    &rule.severity,
                    "YARA-X Behavioral Engine",
                    rule.description.clone(),
                )));
            }
        }
    }

    // Layer 5: UPX-packed, high-entropy PE/ELF binaries.
    let is_pe = buffer.starts_with(b"MZ");
    let is_elf = buffer.starts_with(b"\x7fELF");
    if (is_pe || is_elf) && entropy > 7.45 && content_lossy.contains("UPX!") {
        return store_and_return(Some(detection(
            &full_path,
            &sha256_hex,
            entropy,
            "Heur.Packed.SuspiciousBinary",
            "Suspicious.Packer",
            "Medium",
            "Entropy & Packer Analyzer",
            format!("Packed executable binary with abnormally high Shannon entropy ({} bits/byte).", entropy),
        )));
    }

    // Layer 6: Optional VirusTotal v3 SHA-256 cloud verification for high-entropy binaries.
    if (is_pe || is_elf) && entropy > 7.15 && threat_intel_and_net::should_auto_check_vt() {
        if let Ok(vt) = threat_intel_and_net::vt_check_target(&sha256_hex) {
            if vt.verdict == "Malicious" || vt.verdict == "Suspicious" {
                let sev = if vt.verdict == "Malicious" { "Critical" } else { "High" };
                return store_and_return(Some(detection(
                    &full_path,
                    &sha256_hex,
                    entropy,
                    &format!("VirusTotal.{}", vt.threat_label.replace(' ', ".")),
                    "Cloud.MultiEngine",
                    sev,
                    &format!("VirusTotal v3 ({}/{} engines)", vt.malicious + vt.suspicious, vt.total_engines),
                    format!(
                        "Flagged by {}/{} antivirus engines on VirusTotal ({}).",
                        vt.malicious + vt.suspicious,
                        vt.total_engines,
                        vt.flagged_engines.into_iter().take(4).collect::<Vec<_>>().join(", ")
                    ),
                )));
            }
        }
    }

    store_and_return(None)
}

/// Paths the scanner must never inspect (our own vault, canary decoys, and SQLite DB).
pub fn is_excluded_path(path: &Path) -> bool {
    let s = path.to_string_lossy();
    if s.contains(".genesis_seek_quarantine")
        || s.contains(".genesis-seek-canary")
        || s.ends_with("threat_hashes.db")
        || s.ends_with("threat_hashes.db-wal")
        || s.ends_with("threat_hashes.db-shm")
        || s.contains(".mount_Genes")
        || s.contains(".mount_genesis")
        || s.contains("/.mount_")
        || s.contains("genesis-seek") && (s.contains("/rules/") || s.contains("\\rules\\"))
    {
        return true;
    }

    if let Ok(cur) = std::env::current_exe() {
        if path == cur || path.canonicalize().ok() == cur.canonicalize().ok() {
            return true;
        }
    }
    false
}

fn get_scan_targets(scan_type: &str) -> Vec<PathBuf> {
    let mut targets = Vec::new();
    if let Some(dl) = dirs::download_dir() {
        targets.push(dl);
    }
    if let Some(desktop) = dirs::desktop_dir() {
        targets.push(desktop);
    }
    targets.push(std::env::temp_dir());

    if scan_type == "threat" || scan_type == "full" {
        if let Some(config) = dirs::config_dir() {
            targets.push(config);
        }
        if let Some(data_local) = dirs::data_local_dir() {
            targets.push(data_local);
        }
        #[cfg(target_os = "windows")]
        {
            if scan_type == "full" {
                for letter in b'D'..=b'Z' {
                    let p = PathBuf::from(format!("{}:\\", letter as char));
                    if p.exists() {
                        targets.push(p);
                    }
                }
            }
        }
        #[cfg(target_os = "linux")]
        {
            targets.push(PathBuf::from("/dev/shm"));
            targets.push(PathBuf::from("/var/tmp"));
            if scan_type == "full" {
                for mount_root in &["/media", "/run/media", "/mnt"] {
                    let p = PathBuf::from(mount_root);
                    if p.exists() {
                        targets.push(p);
                    }
                }
            }
        }
    }

    targets.retain(|p| p.exists());
    targets.dedup();
    targets
}

pub fn execute_scan(
    scan_type: &str,
    custom_path: Option<String>,
    max_files: usize,
) -> Result<ScanReport, String> {
    let start = std::time::Instant::now();
    // Ensure global ScannerEngine is initialized and its rules/DB paths are ready
    if let Ok(eng) = SCANNER_ENGINE.read() {
        let _ = (&eng.rules_dir, &eng.db_path);
    }

    let targets = match custom_path.filter(|p| !p.trim().is_empty()) {
        Some(custom) => {
            let p = PathBuf::from(custom.trim());
            if !p.exists() {
                return Err(format!("Path does not exist: {}", p.display()));
            }
            vec![p]
        }
        None => get_scan_targets(scan_type),
    };

    let mut scanned_files = 0usize;
    let mut skipped_files = 0usize;
    let mut detections = Vec::new();

    'targets: for target in targets {
        for entry in WalkDir::new(&target).max_depth(5).follow_links(false) {
            if scanned_files >= max_files {
                break 'targets;
            }
            match entry {
                Ok(e) if e.file_type().is_file() => {
                    let path = e.path();
                    if is_excluded_path(path) {
                        skipped_files += 1;
                        continue;
                    }
                    scanned_files += 1;
                    if let Some(d) = scan_single_file(path) {
                        detections.push(d);
                    }
                }
                Ok(_) => {}
                Err(_) => skipped_files += 1,
            }
        }
    }

    Ok(ScanReport {
        scan_id: Uuid::new_v4().to_string(),
        scan_type: scan_type.to_string(),
        scanned_files,
        skipped_files,
        duration_ms: start.elapsed().as_millis(),
        detections,
        completed_at: Utc::now(),
    })
}
