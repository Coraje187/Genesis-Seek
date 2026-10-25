use crate::quarantine;
use crate::threat_intel_and_net;
use chrono::{DateTime, Utc};
use once_cell::sync::Lazy;
use regex::Regex;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs::{self, File};
use std::io::Read;
use std::path::{Path, PathBuf};
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

struct HeuristicRule {
    name: &'static str,
    category: &'static str,
    severity: &'static str,
    pattern: Regex,
    description: &'static str,
}

/// Max file size inspected (keeps scans fast and memory low).
const MAX_FILE_BYTES: u64 = 64 * 1024 * 1024;
/// Bytes of file content kept for heuristic/entropy analysis.
const CONTENT_WINDOW: usize = 2 * 1024 * 1024;

/// The EICAR test string is assembled at runtime from two halves so the literal never
/// appears in our source or compiled binary (otherwise Genesis Seek — and other AVs —
/// would flag Genesis Seek itself).
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
        // SHA-256 of the 68-byte EICAR test file.
        m.insert(
            "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
            ("EICAR-Standard-AV-Test-Signature", "Test.Signature", "High"),
        );
        // Widely published WannaCry ransomware sample.
        m.insert(
            "ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa",
            ("Ransom.WannaCry.Gen", "Ransomware", "Critical"),
        );
        m
    });

pub fn builtin_hash_count() -> usize {
    KNOWN_HASHES.len()
}

static HEURISTIC_RULES: Lazy<Vec<HeuristicRule>> = Lazy::new(|| {
    vec![
        HeuristicRule {
            name: "Heur.ReverseShell.NetworkPipe",
            category: "Backdoor.Shell",
            severity: "Critical",
            pattern: Regex::new(r"(?i)(bash\s+-i\s+>&\s*/dev/tcp/|nc(at)?\s+-e\s+/bin/(ba)?sh|Invoke-PowerShellTcp|socat\s+TCP4?.*EXEC:)").unwrap(),
            description: "Interactive reverse shell command sequence capable of granting remote unauthorized control.",
        },
        HeuristicRule {
            name: "Heur.PowerShell.ObfuscatedDropper",
            category: "Trojan.Dropper",
            severity: "Critical",
            pattern: Regex::new(r"(?i)(powershell.*\s-(e|enc|encodedcommand)\s+[A-Za-z0-9+/=]{24,}|IEX\s*\(\s*New-Object\s+Net\.WebClient\)\.DownloadString|FromBase64String.*Invoke-Expression)").unwrap(),
            description: "Obfuscated or fileless PowerShell execution pattern commonly used by staging droppers.",
        },
        HeuristicRule {
            name: "Heur.Ransomware.ShadowCopyWipe",
            category: "Ransomware.Behavior",
            severity: "Critical",
            pattern: Regex::new(r"(?i)(vssadmin(\.exe)?\s+delete\s+shadows|wmic(\.exe)?\s+shadowcopy\s+delete|wbadmin\s+delete\s+catalog|bcdedit.*recoveryenabled\s+no)").unwrap(),
            description: "Attempts to inhibit system recovery by deleting Volume Shadow Copies or backup catalogs.",
        },
        HeuristicRule {
            name: "Heur.CryptoMiner.StratumPool",
            category: "Riskware.CryptoMiner",
            severity: "High",
            pattern: Regex::new(r"(?i)(stratum\+(tcp|ssl)://|donate-level.*xmrig|pool\.minexmr\.com|nanopool\.org)").unwrap(),
            description: "Unauthorized cryptocurrency mining pool protocol or configuration signature.",
        },
        HeuristicRule {
            name: "Heur.Linux.StealthPreload",
            category: "Rootkit.Linux",
            severity: "Critical",
            pattern: Regex::new(r"(?i)(>>?\s*/etc/ld\.so\.preload|LD_PRELOAD\s*=\s*/(tmp|dev/shm|var/tmp)/)").unwrap(),
            description: "Linux shared-library hijacking via ld.so.preload or a preload library in a volatile directory.",
        },
        HeuristicRule {
            name: "Heur.CredentialStealer.BrowserDB",
            category: "Spyware.Infostealer",
            severity: "Critical",
            pattern: Regex::new(r"(?is)(Login Data.{0,400}Local State.{0,400}CryptUnprotectData|cookies\.sqlite.{0,400}key4\.db.{0,400}logins\.json)").unwrap(),
            description: "Targets browser credential databases and master decryption keys (Infostealer behavior).",
        },
    ]
});

pub fn heuristic_rule_count() -> usize {
    // +1 for the EICAR test-file rule, +1 double-extension, +1 packer/entropy.
    HEURISTIC_RULES.len() + 3
}

static DOUBLE_EXT_REGEX: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)\.(pdf|doc|docx|xls|xlsx|jpg|jpeg|png|txt|mp4|zip)\.(exe|scr|bat|cmd|vbs|ps1|js|hta|com|pif)$").unwrap()
});

/// Content heuristics only run on scripts/executables. Running them on documents
/// (README, HTML, PDFs, security articles) causes false positives that the real-time
/// guard would then auto-quarantine.
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

/// Read a file once: SHA-256 over the WHOLE file, keeping the first CONTENT_WINDOW bytes
/// for heuristic analysis.
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

/// Inspect a single file using multi-layered signature, heuristic, and entropy analysis.
pub fn scan_single_file(path: &Path) -> Option<ThreatDetection> {
    let metadata = fs::metadata(path).ok()?;
    if !metadata.is_file() || metadata.len() == 0 || metadata.len() > MAX_FILE_BYTES {
        return None;
    }

    let file_name = path.file_name()?.to_string_lossy().to_string();
    let full_path = path.to_string_lossy().to_string();

    let (sha256_hex, buffer) = hash_and_sample(path)?;

    // User restored this exact file before — treat as a confirmed false positive.
    if quarantine::is_allowlisted(&sha256_hex) {
        return None;
    }

    let entropy = calculate_entropy(&buffer);

    // Layer 1: exact SHA-256 lookup (built-in + downloaded MalwareBazaar feed).
    if let Some(&(name, category, severity)) = KNOWN_HASHES.get(sha256_hex.as_str()) {
        return Some(detection(
            &full_path, &sha256_hex, entropy, name, category, severity,
            "Signature Engine (SHA-256)",
            "Exact cryptographic hash match against known threat database.".to_string(),
        ));
    }
    if threat_intel_and_net::is_known_malware_hash(&sha256_hex) {
        return Some(detection(
            &full_path, &sha256_hex, entropy, "ThreatFeed.MalwareBazaar.Sample", "Malware", "Critical",
            "Signature Engine (MalwareBazaar feed)",
            "SHA-256 matches a recent malware sample published by abuse.ch MalwareBazaar.".to_string(),
        ));
    }

    // Layer 2: EICAR test file (per spec the string must be at the start of the file).
    if buffer.starts_with(eicar_test_string().as_bytes()) {
        return Some(detection(
            &full_path, &sha256_hex, entropy, "EICAR-Standard-AV-Test-Signature", "Test.Signature", "High",
            "Signature Engine (EICAR)",
            "Standard EICAR antivirus verification test file (harmless).".to_string(),
        ));
    }

    // Layer 3: double-extension masquerading.
    if DOUBLE_EXT_REGEX.is_match(&file_name) {
        return Some(detection(
            &full_path, &sha256_hex, entropy, "Heur.Masquerade.DoubleExtension", "Trojan.Masquerade", "High",
            "Heuristic File Anomaly",
            format!("Executable disguised with deceptive double file extension ({}).", file_name),
        ));
    }

    if !is_content_scannable(path, &buffer) {
        return None;
    }

    // Layer 4: behavioral content heuristics (scripts and executables only).
    let content_lossy = String::from_utf8_lossy(&buffer);
    for rule in HEURISTIC_RULES.iter() {
        if rule.pattern.is_match(&content_lossy) {
            return Some(detection(
                &full_path, &sha256_hex, entropy, rule.name, rule.category, rule.severity,
                "Behavioral Heuristic",
                rule.description.to_string(),
            ));
        }
    }

    // Layer 5: UPX-packed, high-entropy PE/ELF binaries. Medium severity: many legitimate
    // tools are UPX-packed, so these are flagged but never auto-quarantined.
    let is_pe = buffer.starts_with(b"MZ");
    let is_elf = buffer.starts_with(b"\x7fELF");
    if (is_pe || is_elf) && entropy > 7.45 && content_lossy.contains("UPX!") {
        return Some(detection(
            &full_path, &sha256_hex, entropy, "Heur.Packed.SuspiciousBinary", "Suspicious.Packer", "Medium",
            "Entropy & Packer Analyzer",
            format!("Packed executable binary with abnormally high Shannon entropy ({} bits/byte).", entropy),
        ));
    }

    // Layer 6: Optional VirusTotal v3 SHA-256 cloud verification for high-entropy binaries
    // when the user has configured a VirusTotal API key and enabled automatic cloud hash checks.
    if (is_pe || is_elf) && entropy > 7.15 && threat_intel_and_net::should_auto_check_vt() {
        if let Ok(vt) = threat_intel_and_net::vt_check_target(&sha256_hex) {
            if vt.verdict == "Malicious" || vt.verdict == "Suspicious" {
                let sev = if vt.verdict == "Malicious" { "Critical" } else { "High" };
                return Some(detection(
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
                ));
            }
        }
    }

    None
}

/// Paths the scanner must never inspect (our own vault and canary decoys).
pub fn is_excluded_path(path: &Path) -> bool {
    let s = path.to_string_lossy();
    s.contains(".genesis_seek_quarantine") || s.contains(".genesis-seek-canary")
}

/// Determine directories for Quick / Deep scans across Windows and Linux.
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
        #[cfg(target_os = "linux")]
        {
            targets.push(PathBuf::from("/dev/shm"));
            targets.push(PathBuf::from("/var/tmp"));
        }
    }

    targets.retain(|p| p.exists());
    targets.dedup();
    targets
}

/// Run a directory scan with a depth and file limit to keep resource usage low.
pub fn execute_scan(
    scan_type: &str,
    custom_path: Option<String>,
    max_files: usize,
) -> Result<ScanReport, String> {
    let start = std::time::Instant::now();

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
