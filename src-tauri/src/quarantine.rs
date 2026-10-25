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

/// Encrypt and isolate a malicious file into the Genesis Seek ChaCha20-Poly1305 Quarantine Vault (`.gvault`).
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

    // 1. Immediately strip execute permissions on the target file
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
