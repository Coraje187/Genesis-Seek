use chrono::{DateTime, Utc};
use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use uuid::Uuid;

/// Payload bytes are XOR-obfuscated so the stored sample can't be executed or re-detected
/// by other scanners. This is obfuscation, not cryptographic encryption.
const QUARANTINE_XOR_KEY: &[u8] = b"GENESIS_SEEK_VAULT_KEY_2026_SAFE";

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

fn add_to_allowlist(sha256: &str) {
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

fn xor_transform(data: &mut [u8]) {
    for (i, byte) in data.iter_mut().enumerate() {
        *byte ^= QUARANTINE_XOR_KEY[i % QUARANTINE_XOR_KEY.len()];
    }
}

#[cfg(unix)]
fn restrict_permissions(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    let _ = fs::set_permissions(path, fs::Permissions::from_mode(0o600));
}

#[cfg(not(unix))]
fn restrict_permissions(_path: &Path) {}

/// Neutralize and move a suspicious file into the Genesis Seek Quarantine Vault.
pub fn quarantine_file(
    file_path: &str,
    threat_name: &str,
    severity: &str,
    sha256: &str,
) -> Result<QuarantinedItem, String> {
    let src = Path::new(file_path);
    if !src.exists() {
        return Err(format!("File no longer exists at {}", file_path));
    }

    let mut raw_bytes = fs::read(src).map_err(|e| format!("Failed to read file: {}", e))?;
    let file_size = raw_bytes.len() as u64;

    xor_transform(&mut raw_bytes);

    let id = Uuid::new_v4().to_string();
    let vault_file_name = format!("{}.gsvault", id);
    let dest = get_quarantine_dir().join(&vault_file_name);

    fs::write(&dest, &raw_bytes).map_err(|e| format!("Failed to write vault file: {}", e))?;
    restrict_permissions(&dest);

    if let Err(e) = fs::remove_file(src) {
        // Don't leave an orphaned vault copy if the original couldn't be removed.
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
    };

    let mut items = list_quarantined_items();
    items.insert(0, item.clone());
    save_manifest(&items)?;

    Ok(item)
}

/// Restore a quarantined file back to its original path and allowlist its hash.
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

    let mut bytes = fs::read(&vault_path).map_err(|e| e.to_string())?;
    xor_transform(&mut bytes);

    // Allowlist BEFORE writing so the real-time watcher ignores the restored file.
    add_to_allowlist(&item.sha256);

    if let Some(parent) = Path::new(&item.original_path).parent() {
        let _ = fs::create_dir_all(parent);
    }
    fs::write(&item.original_path, &bytes).map_err(|e| e.to_string())?;
    let _ = fs::remove_file(&vault_path);

    items.remove(idx);
    save_manifest(&items)?;

    Ok(item.original_path)
}

/// Overwrite and delete a quarantined file from the vault.
pub fn delete_quarantined_file(id: &str) -> Result<(), String> {
    let mut items = list_quarantined_items();
    let idx = items
        .iter()
        .position(|x| x.id == id)
        .ok_or_else(|| "Quarantined item not found".to_string())?;

    let item = items.remove(idx);
    let vault_path = get_quarantine_dir().join(&item.vault_file_name);
    if vault_path.exists() {
        // Zero-fill before unlinking. Note: on SSDs/copy-on-write filesystems this
        // does not guarantee the old blocks are physically erased.
        if let Ok(meta) = fs::metadata(&vault_path) {
            let zeros = vec![0u8; meta.len() as usize];
            let _ = fs::write(&vault_path, &zeros);
        }
        let _ = fs::remove_file(&vault_path);
    }
    save_manifest(&items)?;
    Ok(())
}
