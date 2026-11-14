use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Key, Nonce,
};
use chrono::{DateTime, Utc};
use once_cell::sync::Lazy;
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use uuid::Uuid;

/// Legacy XOR key retained strictly for backward-compatible restoration of pre-v0.3 `.gsvault` items.
const LEGACY_XOR_KEY: &[u8] = b"GENESIS_SEEK_VAULT_KEY_2026_SAFE";

fn default_true() -> bool {
    true
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuarantinedItem {
    pub id: String,
    pub original_path: String,
    pub vault_file_name: String,
    pub threat_name: String,
    pub severity: String,
    pub sha256: String,
    pub file_size: u64,
    pub quarantined_at: DateTime<Utc>,
    #[serde(default)]
    pub nonce: String,
    #[serde(default = "default_true")]
    pub encrypted_quarantine: bool,
}

pub fn get_quarantine_dir() -> PathBuf {
    let base = dirs::data_local_dir().unwrap_or_else(std::env::temp_dir);
    let vault = base.join(".genesis_seek_quarantine");
    if !vault.exists() {
        let _ = fs::create_dir_all(&vault);
    }
    vault
}

fn get_manifest_path() -> PathBuf {
    get_quarantine_dir().join("quarantine_manifest.json")
}

fn get_allowlist_path() -> PathBuf {
    get_quarantine_dir().join("allowlist.json")
}

fn get_vault_key_path() -> PathBuf {
    get_quarantine_dir().join("vault.key")
}

/// Load or generate a persistent 256-bit (32-byte) ChaCha20-Poly1305 vault key.
fn load_or_create_vault_key() -> Result<[u8; 32], String> {
    let key_path = get_vault_key_path();
    if key_path.exists() {
        if let Ok(hex_str) = fs::read_to_string(&key_path) {
            if let Ok(decoded) = hex::decode(hex_str.trim()) {
                if decoded.len() == 32 {
                    let mut arr = [0u8; 32];
                    arr.copy_from_slice(&decoded);
                    return Ok(arr);
                }
            }
        }
    }

    let mut key_bytes = [0u8; 32];
    OsRng.fill_bytes(&mut key_bytes);
    let encoded = hex::encode(key_bytes);
    fs::write(&key_path, encoded).map_err(|e| format!("Failed to persist vault key: {}", e))?;
    restrict_vault_permissions(&key_path);
    Ok(key_bytes)
}

/// SHA-256 hashes the user has explicitly restored (false positives). Scans and the
/// real-time guard skip these so a restored file isn't immediately re-quarantined.
static ALLOWLIST: Lazy<Mutex<HashSet<String>>> = Lazy::new(|| {
    let set = fs::read_to_string(get_allowlist_path())
        .ok()
        .and_then(|raw| serde_json::from_str::<HashSet<String>>(&raw).ok())
        .unwrap_or_default();
    Mutex::new(set)
});

pub fn is_allowlisted(sha256: &str) -> bool {
    ALLOWLIST
        .lock()
        .map(|set| set.contains(sha256))
        .unwrap_or(false)
}

pub fn add_to_allowlist(sha256: &str) {
    if let Ok(mut set) = ALLOWLIST.lock() {
        set.insert(sha256.to_string());
        if let Ok(json) = serde_json::to_string_pretty(&*set) {
            let _ = fs::write(get_allowlist_path(), json);
        }
    }
}

pub fn list_quarantined_items() -> Vec<QuarantinedItem> {
    let manifest = get_manifest_path();
    if !manifest.exists() {
        return Vec::new();
    }
    let data = fs::read_to_string(manifest).unwrap_or_default();
    serde_json::from_str(&data).unwrap_or_default()
}

fn save_manifest(items: &[QuarantinedItem]) -> Result<(), String> {
    let manifest = get_manifest_path();
    let json = serde_json::to_string_pretty(items).map_err(|e| e.to_string())?;
    fs::write(manifest, json).map_err(|e| e.to_string())
}

fn legacy_xor_transform(data: &mut [u8]) {
    for (i, byte) in data.iter_mut().enumerate() {
        *byte ^= LEGACY_XOR_KEY[i % LEGACY_XOR_KEY.len()];
    }
}

/// Immediately strip execution bits from a malicious file before reading/isolating it.
#[cfg(unix)]
fn strip_execute_permissions(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    // Strip all execute bits while retaining owner read/write so we can read & zero-fill before unlink
    let _ = fs::set_permissions(path, fs::Permissions::from_mode(0o600));
}

#[cfg(not(unix))]
fn strip_execute_permissions(_path: &Path) {}

/// Lock down vault files (`chmod 000` / `0600` non-executable on Linux, read-only on Windows).
#[cfg(unix)]
fn restrict_vault_permissions(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    let _ = fs::set_permissions(path, fs::Permissions::from_mode(0o600));
}

#[cfg(not(unix))]
fn restrict_vault_permissions(path: &Path) {
    if let Ok(meta) = fs::metadata(path) {
        let mut perms = meta.permissions();
        perms.set_readonly(true);
        let _ = fs::set_permissions(path, perms);
    }
}

#[cfg(not(unix))]
fn clear_readonly(path: &Path) {
    if let Ok(meta) = fs::metadata(path) {
        let mut perms = meta.permissions();
        if perms.readonly() {
            perms.set_readonly(false);
            let _ = fs::set_permissions(path, perms);
        }
    }
}

#[cfg(unix)]
fn clear_readonly(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    let _ = fs::set_permissions(path, fs::Permissions::from_mode(0o600));
}

fn norm_path(s: &str) -> String {
    let mut n = s.replace('\\', "/").to_ascii_lowercase();
    if let Some(rest) = n.strip_prefix("//?/") {
        n = rest.to_string();
    }
    n
}

/// True when `norm` equals `root` or is located strictly beneath it (path-segment aware).
fn under(norm: &str, root: &str) -> bool {
    let root = root.trim_end_matches('/');
    !root.is_empty() && (norm == root || norm.starts_with(&format!("{}/", root)))
}

/// Genesis Seek's own per-user data/vault directories (never the install dir as a whole, because users
/// frequently run the portable `.exe` straight from `Downloads`).
fn own_data_roots() -> Vec<String> {
    [dirs::data_local_dir(), dirs::data_dir(), dirs::config_dir()]
        .into_iter()
        .flatten()
        .map(|base| norm_path(&base.join("genesis-seek").to_string_lossy()))
        .collect()
}

/// Strict, anchored (never substring) protection of OS-core trees. Folders that merely *contain* words like
/// `windows`, `genesis-seek` or `downloads` somewhere in their name are NOT protected.
fn is_lexically_protected(norm: &str) -> bool {
    if norm.is_empty() || norm.split('/').any(|seg| seg == "..") {
        return true;
    }
    if own_data_roots().iter().any(|r| under(norm, r)) {
        return true;
    }

    // Windows: drive-anchored OS trees (`<drive>:/windows`, `<drive>:/program files*`), except `\Windows\Temp`.
    let bytes = norm.as_bytes();
    if bytes.len() >= 2 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':' {
        let rel = &norm[2..];
        if under(rel, "/windows/temp") {
            return false;
        }
        if under(rel, "/windows")
            || under(rel, "/program files")
            || under(rel, "/program files (x86)")
            || under(rel, "/programdata/microsoft/windows defender")
        {
            return true;
        }
    }
    // Windows: environment-resolved roots for non-default install drives / relocated SystemRoot.
    for var in ["SystemRoot", "windir", "ProgramFiles", "ProgramFiles(x86)", "ProgramW6432"] {
        if let Some(val) = std::env::var_os(var) {
            let root = norm_path(&val.to_string_lossy());
            if under(norm, &root) && !under(norm, &format!("{}/temp", root.trim_end_matches('/'))) {
                return true;
            }
        }
    }

    // POSIX: volatile drop zones are explicitly quarantine-able.
    if under(norm, "/dev/shm") || under(norm, "/tmp") || under(norm, "/var/tmp") {
        return false;
    }
    // POSIX: anchored OS-core trees.
    [
        "/bin", "/sbin", "/usr/bin", "/usr/sbin", "/usr/lib", "/usr/lib64", "/usr/libexec", "/lib",
        "/lib64", "/etc", "/boot", "/proc", "/sys", "/dev",
    ]
    .iter()
    .any(|root| under(norm, root))
}

/// Check whether `path` points to a protected OS/system binary or installed system directory
/// that must NEVER be stripped of permissions or moved into the quarantine vault.
pub fn is_protected_system_path(path: &Path) -> bool {
    if path
        .components()
        .any(|c| matches!(c, std::path::Component::ParentDir))
    {
        return true;
    }
    let cur_exe = std::env::current_exe().ok();
    if cur_exe.as_deref() == Some(path) {
        return true;
    }

    if is_lexically_protected(&norm_path(&path.to_string_lossy())) {
        return true;
    }

    // Resolve symlinks/junctions: a link in a drop zone pointing into an OS tree is protected.
    if let Ok(canon) = fs::canonicalize(path) {
        if cur_exe.as_deref() == Some(canon.as_path()) {
            return true;
        }
        if is_lexically_protected(&norm_path(&canon.to_string_lossy())) {
            return true;
        }
    }

    false
}

/// Encrypt and isolate a malicious file into the Genesis Seek ChaCha20-Poly1305 Quarantine Vault (`.gvault`).
pub fn quarantine_file(
    file_path: &str,
    threat_name: &str,
    severity: &str,
    sha256: &str,
) -> Result<QuarantinedItem, String> {
    let src = Path::new(file_path);
    if is_protected_system_path(src) {
        return Err(format!(
            "Refusing to quarantine protected OS/system binary: {}",
            file_path
        ));
    }
    let sym_meta = fs::symlink_metadata(src)
        .map_err(|_| format!("File no longer exists at {}", file_path))?;
    if sym_meta.file_type().is_symlink() {
        return Err(format!(
            "Refusing to follow or quarantine symbolic link: {}",
            file_path
        ));
    }

    // 1. Immediately strip execute permissions on the target regular file
    strip_execute_permissions(src);

    // 2. Read raw file stream and encrypt with ChaCha20-Poly1305 AEAD
    let raw_bytes = fs::read(src).map_err(|e| format!("Failed to read file: {}", e))?;
    let file_size = raw_bytes.len() as u64;

    let key_bytes = load_or_create_vault_key()?;
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&key_bytes));
    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, raw_bytes.as_ref())
        .map_err(|e| format!("ChaCha20-Poly1305 encryption failed: {}", e))?;

    let id = Uuid::new_v4().to_string();
    let vault_file_name = format!("{}.gvault", id);
    let dest = get_quarantine_dir().join(&vault_file_name);

    fs::write(&dest, &ciphertext).map_err(|e| format!("Failed to write encrypted vault file: {}", e))?;
    restrict_vault_permissions(&dest);

    // 3. Overwrite original file bytes with zeros and unlink safely
    clear_readonly(src);
    if file_size > 0 && file_size <= 32 * 1024 * 1024 {
        let zeros = vec![0u8; file_size as usize];
        let _ = fs::write(src, &zeros);
    }

    if let Err(e) = fs::remove_file(src) {
        clear_readonly(&dest);
        let _ = fs::remove_file(&dest);
        return Err(format!("Failed to remove original file: {}", e));
    }

    let item = QuarantinedItem {
        id,
        original_path: file_path.to_string(),
        vault_file_name,
        threat_name: threat_name.to_string(),
        severity: severity.to_string(),
        sha256: sha256.to_string(),
        file_size,
        quarantined_at: Utc::now(),
        nonce: hex::encode(nonce_bytes),
        encrypted_quarantine: true,
    };

    let mut items = list_quarantined_items();
    items.insert(0, item.clone());
    save_manifest(&items)?;

    Ok(item)
}

/// Decrypt and restore a quarantined file back to its original path and allowlist its SHA-256 hash.
pub fn restore_quarantined_file(id: &str) -> Result<String, String> {
    let mut items = list_quarantined_items();
    let idx = items
        .iter()
        .position(|x| x.id == id)
        .ok_or_else(|| "Quarantined item not found".to_string())?;

    let item = items[idx].clone();
    let vault_path = get_quarantine_dir().join(&item.vault_file_name);
    if !vault_path.exists() {
        return Err("Vault payload file is missing".to_string());
    }

    clear_readonly(&vault_path);
    let vault_bytes = fs::read(&vault_path).map_err(|e| e.to_string())?;

    let plaintext = if item.vault_file_name.ends_with(".gvault") && !item.nonce.is_empty() {
        let key_bytes = load_or_create_vault_key()?;
        let cipher = ChaCha20Poly1305::new(Key::from_slice(&key_bytes));
        let nonce_raw = hex::decode(&item.nonce).map_err(|e| format!("Invalid nonce hex: {}", e))?;
        if nonce_raw.len() != 12 {
            return Err("Corrupted 96-bit nonce in quarantine manifest".to_string());
        }
        let nonce = Nonce::from_slice(&nonce_raw);
        cipher
            .decrypt(nonce, vault_bytes.as_ref())
            .map_err(|e| format!("ChaCha20-Poly1305 authentication/decryption failed: {}", e))?
    } else {
        let mut legacy = vault_bytes;
        legacy_xor_transform(&mut legacy);
        legacy
    };

    // Allowlist BEFORE writing so the real-time watcher ignores the restored file.
    add_to_allowlist(&item.sha256);

    if let Some(parent) = Path::new(&item.original_path).parent() {
        let _ = fs::create_dir_all(parent);
    }
    fs::write(&item.original_path, &plaintext).map_err(|e| e.to_string())?;
    let _ = fs::remove_file(&vault_path);

    items.remove(idx);
    save_manifest(&items)?;

    Ok(item.original_path)
}

/// Zero-fill and permanently shred a quarantined file from the vault.
pub fn delete_quarantined_file(id: &str) -> Result<(), String> {
    let mut items = list_quarantined_items();
    let idx = items
        .iter()
        .position(|x| x.id == id)
        .ok_or_else(|| "Quarantined item not found".to_string())?;

    let item = items.remove(idx);
    let vault_path = get_quarantine_dir().join(&item.vault_file_name);
    if vault_path.exists() {
        clear_readonly(&vault_path);
        if let Ok(meta) = fs::metadata(&vault_path) {
            let len = std::cmp::min(meta.len() as usize, 32 * 1024 * 1024);
            let zeros = vec![0u8; len];
            let _ = fs::write(&vault_path, &zeros);
        }
        let _ = fs::remove_file(&vault_path);
    }
    save_manifest(&items)?;
    Ok(())
}

#[cfg(test)]
mod quarantine_tests {
    use super::{is_protected_system_path, quarantine_file};
    use std::path::Path;

    #[test]
    fn refuses_to_quarantine_protected_system_binaries() {
        assert!(is_protected_system_path(Path::new(
            r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
        )));
        assert!(is_protected_system_path(Path::new(
            r"C:\Windows\SysWOW64\cmd.exe"
        )));
        assert!(is_protected_system_path(Path::new(
            r"C:\Program Files\LibreOffice\program\soffice.bin"
        )));
        assert!(is_protected_system_path(Path::new(
            r"C:\Windows\Microsoft.NET\Framework64\v4.0.30319\MSBuild.exe"
        )));
        assert!(is_protected_system_path(Path::new(
            r"C:\Users\Alice\Downloads\..\..\Windows\System32\cmd.exe"
        )));
        assert!(is_protected_system_path(Path::new("/usr/bin/bash")));
        assert!(is_protected_system_path(Path::new("/lib/x86_64-linux-gnu/libc.so.6")));
        assert!(is_protected_system_path(Path::new("/etc/cron.d/backdoor")));

        // Anchoring: folders that merely CONTAIN protected-looking words must NOT be protected
        assert!(!is_protected_system_path(Path::new(
            r"C:\Users\Public\windows\evil.exe"
        )));
        assert!(!is_protected_system_path(Path::new(
            r"C:\Users\Alice\Desktop\genesis-seek\dropper.exe"
        )));
        assert!(!is_protected_system_path(Path::new(
            r"C:\Users\Alice\Downloads\Program Files\setup.exe"
        )));
        assert!(!is_protected_system_path(Path::new("/home/alice/opt/miner")));
        assert!(!is_protected_system_path(Path::new("/home/alice/usr/bin/x")));
        assert!(!is_protected_system_path(Path::new("/opt/vendor/dropper.elf")));
        assert!(!is_protected_system_path(Path::new("/usr/local/bin/implant")));

        // Protected roots must win even when the path also contains drop-zone words
        assert!(is_protected_system_path(Path::new(
            r"C:\Windows\System32\Downloads\x.exe"
        )));
        assert!(is_protected_system_path(Path::new(
            r"C:\Windows\System32\config\systemprofile\AppData\Local\Temp\x.exe"
        )));
        assert!(is_protected_system_path(Path::new("/usr/lib/foo/downloads/bar")));

        assert!(!is_protected_system_path(Path::new(
            r"C:\Users\Alice\Downloads\invoice_dropper.exe"
        )));
        assert!(!is_protected_system_path(Path::new(
            r"C:\Users\Alice\AppData\Local\Temp\stage.exe"
        )));
        assert!(!is_protected_system_path(Path::new(
            r"C:\Windows\Temp\dropper.exe"
        )));
        assert!(!is_protected_system_path(Path::new("/tmp/miner.elf")));
        assert!(!is_protected_system_path(Path::new("/dev/shm/payload.bin")));

        let err = quarantine_file(
            r"C:\Windows\System32\cmd.exe",
            "Test.Behavioral",
            "Critical",
            "00",
        );
        assert!(err.is_err());
        assert!(err.unwrap_err().contains("Refusing to quarantine protected OS/system binary"));
    }

    #[test]
    fn refuses_symlinks_and_never_touches_link_targets() {
        let dir = std::env::temp_dir().join(format!("gs_q_link_{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let victim = dir.join("victim.bin");
        std::fs::write(&victim, b"data").unwrap();
        let link = dir.join("drop_link.bin");

        #[cfg(unix)]
        let linked = std::os::unix::fs::symlink(&victim, &link).is_ok();
        #[cfg(windows)]
        let linked = std::os::windows::fs::symlink_file(&victim, &link).is_ok();
        #[cfg(not(any(unix, windows)))]
        let linked = false;

        if linked {
            let err = quarantine_file(&link.to_string_lossy(), "Test.Link", "High", "00")
                .expect_err("symlink must be refused");
            assert!(err.contains("symbolic link"), "unexpected error: {}", err);
            assert_eq!(std::fs::read(&victim).unwrap(), b"data");
        } else {
            eprintln!("symlink creation unavailable (no privilege); skipping link assertions");
        }

        // A link pointing into an OS tree is treated as protected via canonicalization
        #[cfg(unix)]
        {
            let os_link = dir.join("sudo_link");
            if std::os::unix::fs::symlink("/usr/bin/env", &os_link).is_ok() {
                assert!(is_protected_system_path(&os_link));
            }
        }
        #[cfg(windows)]
        {
            let os_link = dir.join("cmd_link.exe");
            let cmd = std::path::PathBuf::from(
                std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".into()),
            )
            .join("System32")
            .join("cmd.exe");
            if std::os::windows::fs::symlink_file(&cmd, &os_link).is_ok() {
                assert!(is_protected_system_path(&os_link));
            }
        }

        let _ = std::fs::remove_dir_all(&dir);
    }
}
