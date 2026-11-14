use crate::realtime_shield;
use serde::{Deserialize, Serialize};
use std::fs;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::thread;
use std::time::Duration;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectedBrowser {
    pub id: String,       // "chrome", "brave", "edge", "chromium", "firefox"
    pub name: String,     // "Google Chrome", "Brave Browser", etc.
    pub installed: bool,
    pub binary_path: String,
    pub extension_dir: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExtensionInstallResult {
    pub browser_name: String,
    pub success: bool,
    pub extension_path: String,
    pub method_used: String,
    pub message: String,
}

const EMBEDDED_BG_JS: &str = include_str!("../../browser-extension/background.js");
const EMBEDDED_CONTENT_JS: &str = include_str!("../../browser-extension/content_guard.js");
const EMBEDDED_POPUP_HTML: &str = include_str!("../../browser-extension/popup.html");
const EMBEDDED_POPUP_JS: &str = include_str!("../../browser-extension/popup.js");
const EMBEDDED_THEME_INIT_JS: &str = include_str!("../../browser-extension/theme-init.js");
const EMBEDDED_ICON_SVG: &str = include_str!("../../browser-extension/icon.svg");
const EMBEDDED_RULES_JSON: &str = include_str!("../../browser-extension/rules.json");
const EMBEDDED_ICON_16: &[u8] = include_bytes!("../../browser-extension/icons/icon-16.png");
const EMBEDDED_ICON_32: &[u8] = include_bytes!("../../browser-extension/icons/icon-32.png");
const EMBEDDED_ICON_48: &[u8] = include_bytes!("../../browser-extension/icons/icon-48.png");
const EMBEDDED_ICON_128: &[u8] = include_bytes!("../../browser-extension/icons/icon-128.png");

const FIREFOX_MANIFEST_JSON: &str = r#"{
  "manifest_version": 3,
  "name": "Genesis Seek Browser Guard",
  "version": "0.3.8",
  "description": "Real-time phishing, IDN homograph, cryptojacking, and drive-by malware blocker synced with Genesis Seek Endpoint Defense.",
  "permissions": [
    "tabs",
    "storage",
    "declarativeNetRequest"
  ],
  "host_permissions": [
    "<all_urls>",
    "http://127.0.0.1:49152/*"
  ],
  "background": {
    "scripts": ["background.js"]
  },
  "browser_specific_settings": {
    "gecko": {
      "id": "browser-guard@genesisseek.io",
      "strict_min_version": "115.0"
    }
  },
  "content_scripts": [
    {
      "matches": ["<all_urls>"],
      "js": ["content_guard.js"],
      "run_at": "document_idle"
    }
  ],
  "declarative_net_request": {
    "rule_resources": [
      {
        "id": "genesis_seek_blocklist",
        "enabled": true,
        "path": "rules.json"
      }
    ]
  },
  "icons": {
    "16": "icons/icon-16.png",
    "32": "icons/icon-32.png",
    "48": "icons/icon-48.png",
    "128": "icons/icon-128.png"
  },
  "action": {
    "default_title": "Genesis Seek Browser Guard",
    "default_popup": "popup.html",
    "default_icon": {
      "16": "icons/icon-16.png",
      "32": "icons/icon-32.png"
    }
  }
}
"#;

const CHROMIUM_MANIFEST_JSON: &str = r#"{
  "manifest_version": 3,
  "name": "Genesis Seek Browser Guard",
  "version": "0.3.8",
  "description": "Real-time phishing, IDN homograph, cryptojacking, and drive-by malware blocker synced with Genesis Seek Endpoint Defense.",
  "permissions": [
    "tabs",
    "storage",
    "declarativeNetRequest"
  ],
  "host_permissions": [
    "<all_urls>",
    "http://127.0.0.1:49152/*"
  ],
  "background": {
    "service_worker": "background.js"
  },
  "content_scripts": [
    {
      "matches": ["<all_urls>"],
      "js": ["content_guard.js"],
      "run_at": "document_idle"
    }
  ],
  "declarative_net_request": {
    "rule_resources": [
      {
        "id": "genesis_seek_blocklist",
        "enabled": true,
        "path": "rules.json"
      }
    ]
  },
  "icons": {
    "16": "icons/icon-16.png",
    "32": "icons/icon-32.png",
    "48": "icons/icon-48.png",
    "128": "icons/icon-128.png"
  },
  "action": {
    "default_title": "Genesis Seek Browser Guard",
    "default_popup": "popup.html",
    "default_icon": {
      "16": "icons/icon-16.png",
      "32": "icons/icon-32.png"
    }
  }
}
"#;

/// Return the latest dynamically synced `rules.json` bytes from `candidates` if valid,
/// falling back to `EMBEDDED_RULES_JSON`. Freshness (`mtime`) wins; size breaks exact timestamp ties.
fn select_best_rules_json_bytes(candidates: &[PathBuf]) -> Vec<u8> {
    let mut best: Option<(std::time::SystemTime, usize, Vec<u8>)> = None;
    for path in candidates {
        if let Ok(bytes) = fs::read(path) {
            let slice = bytes.strip_prefix(&[0xEF, 0xBB, 0xBF]).unwrap_or(&bytes);
            let is_valid = serde_json::from_slice::<serde_json::Value>(slice)
                .map(|v| v.as_array().map(|a| !a.is_empty()).unwrap_or(false))
                .unwrap_or(false);
            if is_valid {
                let mtime = fs::metadata(path)
                    .and_then(|m| m.modified())
                    .unwrap_or(std::time::SystemTime::UNIX_EPOCH);
                let len = slice.len();
                let replace = match &best {
                    None => true,
                    Some((prev_mtime, prev_len, _)) => (mtime, len) > (*prev_mtime, *prev_len),
                };
                if replace {
                    best = Some((mtime, len, slice.to_vec()));
                }
            }
        }
    }

    best.map(|(_, _, b)| b)
        .unwrap_or_else(|| EMBEDDED_RULES_JSON.as_bytes().to_vec())
}

/// Return the latest dynamically synced `rules.json` bytes from disk if valid, falling back to `EMBEDDED_RULES_JSON`.
fn current_rules_json_bytes() -> Vec<u8> {
    let mut candidates = vec![resolve_extension_dir().join("rules.json")];
    if let Some(dl) = dirs::download_dir() {
        candidates.push(dl.join("Genesis-Seek-Browser-Guard").join("rules.json"));
    }
    if let Some(local_data) = dirs::data_local_dir() {
        candidates.push(
            local_data
                .join("genesis-seek")
                .join("browser-extension")
                .join("rules.json"),
        );
    }
    select_best_rules_json_bytes(&candidates)
}

/// Build a valid Firefox `.xpi` (PKZIP archive) in memory with POSIX forward-slash paths,
/// zero directory entries, and BOM-free UTF-8 `manifest.json`.
pub fn build_valid_firefox_xpi_bytes() -> Result<Vec<u8>, String> {
    use flate2::{write::DeflateEncoder, Compression, Crc};

    let rules_bytes = current_rules_json_bytes();
    let entries: [(&str, &[u8]); 12] = [
        ("manifest.json", FIREFOX_MANIFEST_JSON.as_bytes()),
        ("background.js", EMBEDDED_BG_JS.as_bytes()),
        ("content_guard.js", EMBEDDED_CONTENT_JS.as_bytes()),
        ("popup.html", EMBEDDED_POPUP_HTML.as_bytes()),
        ("popup.js", EMBEDDED_POPUP_JS.as_bytes()),
        ("theme-init.js", EMBEDDED_THEME_INIT_JS.as_bytes()),
        ("icon.svg", EMBEDDED_ICON_SVG.as_bytes()),
        ("rules.json", &rules_bytes),
        ("icons/icon-16.png", EMBEDDED_ICON_16),
        ("icons/icon-32.png", EMBEDDED_ICON_32),
        ("icons/icon-48.png", EMBEDDED_ICON_48),
        ("icons/icon-128.png", EMBEDDED_ICON_128),
    ];

    let mut out = Vec::with_capacity(64 * 1024);
    let mut cd = Vec::with_capacity(2048);

    for &(name, raw) in &entries {
        let mut crc = Crc::new();
        crc.update(raw);
        let crc32 = crc.sum();

        let mut encoder = DeflateEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(raw).map_err(|e| e.to_string())?;
        let comp = encoder.finish().map_err(|e| e.to_string())?;

        let local_header_offset = out.len() as u32;
        let name_bytes = name.as_bytes();
        let name_len = name_bytes.len() as u16;
        let comp_len = comp.len() as u32;
        let uncomp_len = raw.len() as u32;

        // Local File Header
        out.extend_from_slice(b"PK\x03\x04");
        out.extend_from_slice(&20u16.to_le_bytes()); // version needed
        out.extend_from_slice(&0u16.to_le_bytes()); // general purpose flags
        out.extend_from_slice(&8u16.to_le_bytes()); // compression method: Deflate (8)
        out.extend_from_slice(&0u16.to_le_bytes()); // mod time
        out.extend_from_slice(&0x5421u16.to_le_bytes()); // mod date
        out.extend_from_slice(&crc32.to_le_bytes());
        out.extend_from_slice(&comp_len.to_le_bytes());
        out.extend_from_slice(&uncomp_len.to_le_bytes());
        out.extend_from_slice(&name_len.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes()); // extra len
        out.extend_from_slice(name_bytes);
        out.extend_from_slice(&comp);

        // Central Directory Header
        cd.extend_from_slice(b"PK\x01\x02");
        cd.extend_from_slice(&0x0314u16.to_le_bytes()); // version made by: Unix
        cd.extend_from_slice(&20u16.to_le_bytes()); // version needed
        cd.extend_from_slice(&0u16.to_le_bytes()); // flags
        cd.extend_from_slice(&8u16.to_le_bytes()); // method: Deflate
        cd.extend_from_slice(&0u16.to_le_bytes()); // mod time
        cd.extend_from_slice(&0x5421u16.to_le_bytes()); // mod date
        cd.extend_from_slice(&crc32.to_le_bytes());
        cd.extend_from_slice(&comp_len.to_le_bytes());
        cd.extend_from_slice(&uncomp_len.to_le_bytes());
        cd.extend_from_slice(&name_len.to_le_bytes());
        cd.extend_from_slice(&0u16.to_le_bytes()); // extra len
        cd.extend_from_slice(&0u16.to_le_bytes()); // comment len
        cd.extend_from_slice(&0u16.to_le_bytes()); // disk number
        cd.extend_from_slice(&0u16.to_le_bytes()); // internal attrs
        cd.extend_from_slice(&(0o100644u32 << 16).to_le_bytes()); // Unix rw-r--r-- regular file
        cd.extend_from_slice(&local_header_offset.to_le_bytes());
        cd.extend_from_slice(name_bytes);
    }

    let cd_offset = out.len() as u32;
    let cd_size = cd.len() as u32;
    let entry_count = entries.len() as u16;
    out.extend_from_slice(&cd);

    // End of Central Directory Record
    out.extend_from_slice(b"PK\x05\x06");
    out.extend_from_slice(&0u16.to_le_bytes()); // disk number
    out.extend_from_slice(&0u16.to_le_bytes()); // cd start disk
    out.extend_from_slice(&entry_count.to_le_bytes());
    out.extend_from_slice(&entry_count.to_le_bytes());
    out.extend_from_slice(&cd_size.to_le_bytes());
    out.extend_from_slice(&cd_offset.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes()); // comment len

    Ok(out)
}

/// Ensure all embedded extension files, icons, and (for Firefox) a valid `.xpi` archive are materialized in `target_dir`.
fn materialize_embedded_extension(target_dir: &Path, is_firefox: bool) {
    let icons_dir = target_dir.join("icons");
    let _ = fs::create_dir_all(&icons_dir);
    let rules_bytes = current_rules_json_bytes();
    let _ = fs::write(target_dir.join("background.js"), EMBEDDED_BG_JS);
    let _ = fs::write(target_dir.join("content_guard.js"), EMBEDDED_CONTENT_JS);
    let _ = fs::write(target_dir.join("popup.html"), EMBEDDED_POPUP_HTML);
    let _ = fs::write(target_dir.join("popup.js"), EMBEDDED_POPUP_JS);
    let _ = fs::write(target_dir.join("theme-init.js"), EMBEDDED_THEME_INIT_JS);
    let _ = fs::write(target_dir.join("icon.svg"), EMBEDDED_ICON_SVG);
    let _ = fs::write(target_dir.join("rules.json"), &rules_bytes);
    let _ = fs::write(icons_dir.join("icon-16.png"), EMBEDDED_ICON_16);
    let _ = fs::write(icons_dir.join("icon-32.png"), EMBEDDED_ICON_32);
    let _ = fs::write(icons_dir.join("icon-48.png"), EMBEDDED_ICON_48);
    let _ = fs::write(icons_dir.join("icon-128.png"), EMBEDDED_ICON_128);
    write_browser_manifest(target_dir, is_firefox);
    if is_firefox {
        if let Ok(xpi_bytes) = build_valid_firefox_xpi_bytes() {
            let _ = fs::write(
                target_dir.join("Genesis-Seek-Browser-Guard-for-Firefox-v0.3.8.xpi"),
                &xpi_bytes,
            );
            let _ = fs::write(target_dir.join("browser-guard@genesisseek.io.xpi"), &xpi_bytes);
        }
    }
}

/// Locate or materialize the `browser-extension/` directory on any Windows or Linux PC.
pub fn resolve_extension_dir() -> PathBuf {
    if let Ok(cwd) = std::env::current_dir() {
        let candidate1 = cwd.join("browser-extension");
        if candidate1.exists() {
            return candidate1;
        }
        if let Some(parent) = cwd.parent() {
            let candidate2 = parent.join("browser-extension");
            if candidate2.exists() {
                return candidate2;
            }
        }
    }
    let fallback = dirs::data_local_dir()
        .or_else(dirs::home_dir)
        .unwrap_or_else(std::env::temp_dir)
        .join("genesis-seek")
        .join("browser-extension");
    if !fallback.join("background.js").exists() {
        materialize_embedded_extension(&fallback, true);
    }
    fallback
}

/// Recursively copy a directory (including `icons/` subdirectory) so staged unpacked extensions
/// never fail due to missing `icons/icon-16.png` etc.
fn copy_dir_recursive(src: &Path, dst: &Path) -> std::io::Result<()> {
    fs::create_dir_all(dst)?;
    for entry in fs::read_dir(src)? {
        let entry = entry?;
        let file_type = entry.file_type()?;
        let dest_path = dst.join(entry.file_name());
        if file_type.is_dir() {
            copy_dir_recursive(&entry.path(), &dest_path)?;
        } else {
            fs::copy(entry.path(), dest_path)?;
        }
    }
    Ok(())
}

/// Write a browser-tailored `manifest.json` so neither Firefox (which prefers `background.scripts` + `gecko`)
/// nor Chromium/Chrome/Brave/Edge (which require `background.service_worker` only in MV3) rejects the manifest.
fn write_browser_manifest(target_dir: &Path, is_firefox: bool) {
    let manifest_json = if is_firefox {
        FIREFOX_MANIFEST_JSON
    } else {
        CHROMIUM_MANIFEST_JSON
    };

    let _ = fs::write(target_dir.join("manifest.json"), manifest_json);
}

/// Read a length-prefixed JSON packet (`<len>:<json>`) from Firefox Marionette socket.
fn marionette_read_packet(stream: &mut TcpStream) -> Result<String, String> {
    let mut len_buf = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        stream.read_exact(&mut byte).map_err(|e| e.to_string())?;
        if byte[0] == b':' {
            break;
        }
        len_buf.push(byte[0]);
        if len_buf.len() > 16 {
            return Err("Invalid Marionette packet header".to_string());
        }
    }
    let len_str = String::from_utf8_lossy(&len_buf);
    let len: usize = len_str.parse().map_err(|e: std::num::ParseIntError| e.to_string())?;
    let mut payload = vec![0u8; len];
    stream.read_exact(&mut payload).map_err(|e| e.to_string())?;
    Ok(String::from_utf8_lossy(&payload).to_string())
}

fn marionette_send_packet(stream: &mut TcpStream, json_payload: &str) -> Result<(), String> {
    let formatted = format!("{}:{}", json_payload.len(), json_payload);
    stream.write_all(formatted.as_bytes()).map_err(|e| e.to_string())?;
    stream.flush().map_err(|e| e.to_string())
}

/// Attempt to install the extension automatically into Firefox via Marionette (`127.0.0.1:2828`).
pub fn try_firefox_marionette_install(ext_path: &str) -> Result<String, String> {
    let addr: SocketAddr = "127.0.0.1:2828".parse().unwrap();
    let mut stream = TcpStream::connect_timeout(&addr, Duration::from_millis(900))
        .map_err(|e| e.to_string())?;
    let _ = stream.set_read_timeout(Some(Duration::from_secs(4)));
    let _ = stream.set_write_timeout(Some(Duration::from_secs(4)));

    // 1. Read greeting
    let _greeting = marionette_read_packet(&mut stream)?;

    // 2. WebDriver:NewSession
    marionette_send_packet(&mut stream, r#"[0,1,"WebDriver:NewSession",{}]"#)?;
    let _session = marionette_read_packet(&mut stream)?;

    // 3. Addon:Install
    let escaped_path = ext_path.replace('\\', "\\\\").replace('"', "\\\"");
    let install_cmd = format!(
        r#"[0,2,"Addon:Install",{{"path":"{}","temporary":true}}]"#,
        escaped_path
    );
    marionette_send_packet(&mut stream, &install_cmd)?;
    let install_resp = marionette_read_packet(&mut stream)?;

    // 4. WebDriver:DeleteSession (disconnect cleanly so browser remains normal)
    let _ = marionette_send_packet(&mut stream, r#"[0,3,"WebDriver:DeleteSession",{}]"#);
    let _ = marionette_read_packet(&mut stream);

    if install_resp.contains("browser-guard@genesisseek.io") || install_resp.contains(r#""value""#) {
        Ok(install_resp)
    } else {
        Err(format!("Marionette response: {}", install_resp))
    }
}

/// Pure-Rust CLI helper (`genesis-seek --inject-firefox`) that waits up to 15 seconds for
/// Firefox's local port 2828 and injects the staged extension without requiring Python on Windows or Linux.
pub fn inject_firefox_cli_loop() {
    let staged = staged_firefox_extension_path();
    for _ in 0..30 {
        if try_firefox_marionette_install(&staged).is_ok() {
            return;
        }
        thread::sleep(Duration::from_millis(500));
    }
}

/// Stage the Firefox extension into `<Downloads>/Genesis-Seek-Browser-Guard` on any OS.
pub fn staged_firefox_extension_path() -> String {
    let ext_path = resolve_extension_dir();
    let staged_dir = dirs::download_dir()
        .or_else(dirs::data_local_dir)
        .or_else(dirs::home_dir)
        .unwrap_or_else(std::env::temp_dir)
        .join("Genesis-Seek-Browser-Guard");
    materialize_embedded_extension(&staged_dir, true);
    if ext_path.exists() && ext_path != staged_dir {
        let _ = copy_dir_recursive(&ext_path, &staged_dir);
        write_browser_manifest(&staged_dir, true);
    }
    staged_dir.to_string_lossy().to_string()
}

fn collect_profiles_in_root(root: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = fs::read_dir(root) else {
        return;
    };
    for entry in entries.flatten() {
        let p = entry.path();
        if !p.is_dir() {
            continue;
        }
        let is_profile = p.join("prefs.js").exists()
            || p.join("times.json").exists()
            || p
                .file_name()
                .and_then(|n| n.to_str())
                .map(|s| s.contains(".default"))
                .unwrap_or(false);
        if is_profile {
            out.push(p);
        }
    }
}

/// Discover Firefox profile directories across Windows and Linux (native, Flatpak, Snap).
fn get_firefox_profile_dirs() -> Vec<PathBuf> {
    let mut profiles = Vec::new();
    #[cfg(target_os = "windows")]
    if let Some(appdata) = dirs::config_dir() {
        collect_profiles_in_root(
            &appdata.join("Mozilla").join("Firefox").join("Profiles"),
            &mut profiles,
        );
    }
    #[cfg(target_os = "linux")]
    if let Some(home) = dirs::home_dir() {
        collect_profiles_in_root(&home.join(".mozilla").join("firefox"), &mut profiles);
        collect_profiles_in_root(
            &home
                .join(".var")
                .join("app")
                .join("org.mozilla.firefox")
                .join(".mozilla")
                .join("firefox"),
            &mut profiles,
        );
        collect_profiles_in_root(
            &home
                .join("snap")
                .join("firefox")
                .join("common")
                .join(".mozilla")
                .join("firefox"),
            &mut profiles,
        );
    }
    profiles
}

const GENESIS_BLOCK_BEGIN: &str = "// >>> Genesis Seek Browser Guard Auto-Loader BEGIN >>>";
const GENESIS_BLOCK_END: &str = "// <<< Genesis Seek Browser Guard Auto-Loader END <<<";

const LEGACY_GENESIS_PREF_MARKERS: &[&str] = &[
    "user_pref(\"xpinstall.signatures.required\"",
    "user_pref(\"extensions.langpacks.signatures.required\"",
    "user_pref(\"extensions.autoDisableScopes\"",
    "user_pref(\"extensions.enabledScopes\"",
    "user_pref(\"browser.newtabpage.activity-stream.testing.shouldInitializeFeeds\"",
    "user_pref(\"browser.newtabpage.enabled\"",
];

fn format_firefox_prefs_block(eol: &str) -> String {
    format!(
        "{eol}{GENESIS_BLOCK_BEGIN}{eol}\
         user_pref(\"xpinstall.signatures.required\", false);{eol}\
         user_pref(\"extensions.langpacks.signatures.required\", false);{eol}\
         {GENESIS_BLOCK_END}{eol}"
    )
}

/// Strip only Genesis Seek's managed preference block from an existing Firefox `user.js`
/// while preserving CRLF/LF line endings and any user-authored `xpinstall.signatures.required` outside our block.
fn strip_genesis_seek_firefox_prefs(existing: &str) -> String {
    let eol = if existing.contains("\r\n") { "\r\n" } else { "\n" };
    let mut kept = Vec::new();
    let mut in_marked_block = false;
    let mut in_legacy_block = false;

    for line in existing.lines() {
        let trimmed = line.trim();
        if trimmed == GENESIS_BLOCK_BEGIN {
            in_marked_block = true;
            continue;
        }
        if in_marked_block {
            if trimmed == GENESIS_BLOCK_END {
                in_marked_block = false;
            }
            continue;
        }
        if trimmed.starts_with("// Genesis Seek Browser Guard Auto-Loader") {
            in_legacy_block = true;
            continue;
        }
        if in_legacy_block {
            if LEGACY_GENESIS_PREF_MARKERS
                .iter()
                .any(|m| trimmed.starts_with(m))
            {
                continue;
            }
            in_legacy_block = false;
        }
        kept.push(line);
    }

    let mut joined = kept.join(eol);
    if !joined.is_empty() && !joined.ends_with(eol) {
        joined.push_str(eol);
    }
    joined
}

/// Deploy `extensions/browser-guard@genesisseek.io.xpi` into a single Firefox profile directory and
/// optionally write opt-in unsigned extension preferences (`xpinstall.signatures.required=false`) to `user.js`.
pub fn provision_firefox_profile_dir(profile: &Path, xpi_bytes: &[u8], allow_unsigned_pref: bool) -> bool {
    let ext_dir = profile.join("extensions");
    let wrote_xpi = fs::create_dir_all(&ext_dir).is_ok()
        && fs::write(ext_dir.join("browser-guard@genesisseek.io.xpi"), xpi_bytes).is_ok();

    let user_js = profile.join("user.js");
    if user_js.exists() || allow_unsigned_pref {
        let existing = fs::read_to_string(&user_js).unwrap_or_default();
        let eol = if existing.contains("\r\n") {
            "\r\n"
        } else if existing.is_empty() && cfg!(target_os = "windows") {
            "\r\n"
        } else {
            "\n"
        };
        let cleaned = strip_genesis_seek_firefox_prefs(&existing);
        let desired = if allow_unsigned_pref {
            format!(
                "{}{}",
                cleaned.trim_end_matches(['\r', '\n']),
                format_firefox_prefs_block(eol)
            )
        } else {
            cleaned
        };
        if desired != existing {
            let _ = fs::write(&user_js, desired);
        }
    }

    wrote_xpi
}

/// Remove `extensions/browser-guard@genesisseek.io.xpi` and strip Genesis Seek entries from `user.js`.
pub fn unprovision_firefox_profile_dir(profile: &Path) {
    let _ = fs::remove_file(
        profile
            .join("extensions")
            .join("browser-guard@genesisseek.io.xpi"),
    );
    let user_js = profile.join("user.js");
    if user_js.exists() {
        let existing = fs::read_to_string(&user_js).unwrap_or_default();
        let cleaned = strip_genesis_seek_firefox_prefs(&existing);
        if cleaned != existing {
            let _ = fs::write(&user_js, cleaned);
        }
    }
}

/// Provision `extensions/browser-guard@genesisseek.io.xpi` (and optional `user.js` preferences when
/// `allow_unsigned_pref` is true) across all discovered Firefox profiles. Returns the count of provisioned profiles.
pub fn provision_firefox_profiles_with_xpi(xpi_bytes: &[u8], allow_unsigned_pref: bool) -> usize {
    let mut updated = 0usize;
    for profile in get_firefox_profile_dirs() {
        if provision_firefox_profile_dir(&profile, xpi_bytes, allow_unsigned_pref) {
            updated += 1;
        }
    }
    updated
}

/// Enable or disable automatic browser startup loading across both Linux and Windows.
pub fn set_browser_autoload_enabled(enabled: bool) -> String {
    let staged_str = staged_firefox_extension_path();

    #[cfg(target_os = "linux")]
    {
        if let Some(home) = dirs::home_dir() {
            let local_bin = home.join(".local/bin");
            let py_helper = local_bin.join("genesis-seek-ff-autoload.py");
            let ff_wrapper = local_bin.join("firefox");
            let desktop_override = home.join(".local/share/applications/firefox.desktop");
            // Clean up any old wrappers that forced --marionette automation mode
            let _ = fs::remove_file(&py_helper);
            let _ = fs::remove_file(&ff_wrapper);
            let _ = fs::remove_file(&desktop_override);
        }
    }

    if enabled {
        if let Ok(xpi_bytes) = build_valid_firefox_xpi_bytes() {
            let _ = provision_firefox_profiles_with_xpi(&xpi_bytes, true);
        }
    } else {
        for profile in get_firefox_profile_dirs() {
            unprovision_firefox_profile_dir(&profile);
        }
    }

    #[cfg(target_os = "windows")]
    {
        let exe_path = std::env::current_exe()
            .unwrap_or_else(|_| PathBuf::from("genesis-seek"))
            .to_string_lossy()
            .to_string();
        let local_app = dirs::data_local_dir()
            .unwrap_or_else(std::env::temp_dir)
            .join("genesis-seek");
        let _ = fs::create_dir_all(&local_app);
        let cmd_wrapper = local_app.join("firefox-autoload.cmd");
        let start_menu_cmd = dirs::config_dir()
            .map(|d| d.join(r"Microsoft\Windows\Start Menu\Programs\Firefox (Genesis Seek Protected).cmd"));

        if !enabled {
            let _ = fs::remove_file(&cmd_wrapper);
            if let Some(sm) = start_menu_cmd {
                let _ = fs::remove_file(sm);
            }
            return staged_str;
        }

        // Create Windows launcher script that invokes `genesis-seek.exe --inject-firefox` + `firefox.exe --marionette`
        let batch_script = format!(
            "@echo off\r\nstart \"\" /B \"{}\" --inject-firefox\r\nstart \"\" \"C:\\Program Files\\Mozilla Firefox\\firefox.exe\" --marionette %*\r\n",
            exe_path
        );
        let _ = fs::write(&cmd_wrapper, &batch_script);
        if let Some(sm) = start_menu_cmd {
            let _ = fs::write(sm, &batch_script);
        }
    }

    staged_str
}

/// Ensure the staged Firefox extension exists and configure permanent auto-load if enabled in ShieldState.
pub fn setup_firefox_permanent_autoload() -> String {
    let enabled = realtime_shield::current_shields().browser_extension_autoload;
    set_browser_autoload_enabled(enabled)
}

/// Detect installed web browsers across Linux and Windows.
pub fn detect_installed_browsers() -> Vec<DetectedBrowser> {
    let ext_dir = resolve_extension_dir().to_string_lossy().to_string();

    let candidates = [
        (
            "firefox",
            "Mozilla Firefox",
            vec![
                "/usr/bin/firefox",
                "/snap/bin/firefox",
                r"C:\Program Files\Mozilla Firefox\firefox.exe",
            ],
        ),
        (
            "chrome",
            "Google Chrome",
            vec![
                "/usr/bin/google-chrome",
                "/usr/bin/google-chrome-stable",
                r"C:\Program Files\Google\Chrome\Application\chrome.exe",
                r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe",
            ],
        ),
        (
            "brave",
            "Brave Browser",
            vec![
                "/usr/bin/brave-browser",
                "/usr/bin/brave",
                "/snap/bin/brave",
                r"C:\Program Files\BraveSoftware\Brave-Browser\Application\brave.exe",
            ],
        ),
        (
            "edge",
            "Microsoft Edge",
            vec![
                "/usr/bin/microsoft-edge",
                "/usr/bin/microsoft-edge-stable",
                r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
                r"C:\Program Files\Microsoft\Edge\Application\msedge.exe",
            ],
        ),
        (
            "chromium",
            "Chromium",
            vec![
                "/usr/bin/chromium",
                "/usr/bin/chromium-browser",
                "/snap/bin/chromium",
            ],
        ),
    ];

    let mut results = Vec::new();
    for (id, name, paths) in candidates {
        let found = paths
            .iter()
            .find(|p| Path::new(p).exists())
            .map(|s| s.to_string())
            .unwrap_or_default();

        results.push(DetectedBrowser {
            id: id.to_string(),
            name: name.to_string(),
            installed: !found.is_empty(),
            binary_path: found,
            extension_dir: ext_dir.clone(),
        });
    }

    results
}

/// Install or launch the Genesis Seek Browser Guard extension into the chosen browser.
pub fn install_extension_for_browser(browser_id: &str) -> Result<ExtensionInstallResult, String> {
    let ext_path = resolve_extension_dir();
    let ext_path_str = ext_path.to_string_lossy().to_string();

    if !ext_path.exists() {
        return Err(format!(
            "Browser extension folder not found at {}",
            ext_path_str
        ));
    }

    let is_firefox = browser_id == "firefox";

    // Stage browser-tailored copies into separate Downloads subfolders so the source `browser-extension/`
    // Firefox manifest is never overwritten when installing Chromium browsers.
    let staged_dir = if is_firefox {
        PathBuf::from(staged_firefox_extension_path())
    } else {
        let base_dir = dirs::download_dir()
            .or_else(dirs::data_local_dir)
            .or_else(dirs::home_dir)
            .unwrap_or_else(std::env::temp_dir);
        let dir = base_dir.join("Genesis-Seek-Browser-Guard-Chromium");
        materialize_embedded_extension(&dir, false);
        if copy_dir_recursive(&ext_path, &dir).is_ok() {
            write_browser_manifest(&dir, false);
        }
        dir
    };
    let staged_path_str = staged_dir.to_string_lossy().to_string();

    let browsers = detect_installed_browsers();
    let target = browsers
        .iter()
        .find(|b| b.id == browser_id)
        .cloned()
        .unwrap_or(DetectedBrowser {
            id: browser_id.to_string(),
            name: browser_id.to_uppercase(),
            installed: false,
            binary_path: String::new(),
            extension_dir: ext_path_str.clone(),
        });

    // 1. Chromium-based browsers (Chrome, Brave, Edge, Chromium): launch with `--load-extension=<staged_chromium_path>`
    if target.installed && !target.binary_path.is_empty() && !is_firefox {
        let load_arg = format!("--load-extension={}", staged_path_str);
        if Command::new(&target.binary_path)
            .arg(&load_arg)
            .arg("chrome://extensions")
            .spawn()
            .is_ok()
        {
            realtime_shield::log_security_event(
                "Browser Guard",
                "Info",
                &format!("Installed Browser Guard into {}", target.name),
                &staged_path_str,
                "Extension Loaded",
            );

            return Ok(ExtensionInstallResult {
                browser_name: target.name,
                success: true,
                extension_path: staged_path_str,
                method_used: "Direct Browser Launch (--load-extension)".to_string(),
                message: "Browser launched with Genesis Seek Browser Guard pre-loaded!".to_string(),
            });
        }
    }

    // 2. Mozilla Firefox:
    //    Stage unpacked files + valid v0.3.8 `.xpi`, provision Firefox profile `extensions/*.xpi` (and opt-in
    //    `user.js` only if autoload is enabled), attempt live Marionette injection, and open the local Guided Installer.
    if is_firefox {
        let xpi_path = staged_dir
            .join("Genesis-Seek-Browser-Guard-for-Firefox-v0.3.8.xpi")
            .to_string_lossy()
            .to_string();
        let allow_unsigned = realtime_shield::current_shields().browser_extension_autoload;
        let mut profiles_updated = 0usize;
        if let Ok(xpi_bytes) = build_valid_firefox_xpi_bytes() {
            profiles_updated = provision_firefox_profiles_with_xpi(&xpi_bytes, allow_unsigned);
        }

        if try_firefox_marionette_install(&staged_path_str).is_ok() {
            realtime_shield::log_security_event(
                "Browser Guard",
                "Info",
                "Injected Browser Guard v0.3.8 into Active Firefox",
                &staged_path_str,
                "Extension Loaded via Marionette",
            );

            return Ok(ExtensionInstallResult {
                browser_name: "Mozilla Firefox".to_string(),
                success: true,
                extension_path: xpi_path,
                method_used: "Marionette Live Injection + XPI Staged".to_string(),
                message: format!(
                    "Genesis Seek Browser Guard v0.3.8 was injected into your active Firefox session and staged to {} ({} Firefox profile(s) provisioned).",
                    staged_path_str, profiles_updated
                ),
            });
        }

        let installer_url = "http://127.0.0.1:49152/install-firefox";
        if target.installed && !target.binary_path.is_empty() {
            let _ = Command::new(&target.binary_path).arg(installer_url).spawn();
        } else {
            #[cfg(target_os = "windows")]
            let _ = Command::new("cmd").args(["/c", "start", installer_url]).spawn();
            #[cfg(not(target_os = "windows"))]
            let _ = Command::new("xdg-open").arg(installer_url).spawn();
        }

        realtime_shield::log_security_event(
            "Browser Guard",
            "Info",
            "Staged Firefox XPI v0.3.8 & Opened Guided Installer",
            &xpi_path,
            &format!("Provisioned {} Firefox profile(s)", profiles_updated),
        );

        return Ok(ExtensionInstallResult {
            browser_name: "Mozilla Firefox".to_string(),
            success: true,
            extension_path: xpi_path.clone(),
            method_used: "Valid .XPI Staged + Local Guided Installer".to_string(),
            message: format!(
                "Valid v0.3.8 .XPI package generated at:\n{}\n({} Firefox profile(s) provisioned).\nFollow the opened Guided Installer tab to install or load via about:debugging!",
                xpi_path, profiles_updated
            ),
        });
    }

    #[cfg(target_os = "linux")]
    {
        let _ = Command::new("xdg-open").arg(&staged_path_str).spawn();
    }
    #[cfg(target_os = "windows")]
    {
        let _ = Command::new("explorer.exe").arg(&staged_path_str).spawn();
    }

    Ok(ExtensionInstallResult {
        browser_name: target.name.clone(),
        success: true,
        extension_path: staged_path_str.clone(),
        method_used: "Staged Extension Package".to_string(),
        message: format!(
            "Extension staged (with all icons and manifest) at:\n{}",
            staged_path_str
        ),
    })
}

/// Open the unpacked browser extension folder in the native OS file manager.
pub fn open_extension_directory() -> Result<String, String> {
    let ext_path = resolve_extension_dir();
    let mut target_dir = ext_path.clone();
    if let Some(dl) = dirs::download_dir() {
        let staged = dl.join("Genesis-Seek-Browser-Guard");
        if copy_dir_recursive(&ext_path, &staged).is_ok() {
            target_dir = staged;
        }
    }
    let ext_path_str = target_dir.to_string_lossy().to_string();

    #[cfg(target_os = "linux")]
    {
        let _ = Command::new("xdg-open").arg(&ext_path_str).spawn();
    }
    #[cfg(target_os = "windows")]
    {
        let _ = Command::new("explorer.exe").arg(&ext_path_str).spawn();
    }

    Ok(ext_path_str)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct DeclarativeNetAction {
    #[serde(rename = "type")]
    action_type: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct DeclarativeNetCondition {
    #[serde(rename = "urlFilter")]
    url_filter: String,
    #[serde(rename = "resourceTypes")]
    resource_types: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct DeclarativeNetRule {
    id: usize,
    priority: u8,
    action: DeclarativeNetAction,
    condition: DeclarativeNetCondition,
}

/// Compile the built-in blocklist and top active malicious domains from URLhaus/PhishStats
/// into MV3 `DeclarativeNetRequest` format (`rules.json`) across `browser-extension/rules.json`
/// and staged Firefox/Chromium extension directories.
pub fn sync_dynamic_browser_rules(domains: &std::collections::HashSet<String>) -> usize {
    let base_domains = [
        ("coinhive.com", vec!["script", "xmlhttprequest", "sub_frame", "main_frame"]),
        ("crypto-loot.com", vec!["script", "xmlhttprequest", "sub_frame", "main_frame"]),
        ("paypa1-security-verify.com", vec!["main_frame", "sub_frame", "xmlhttprequest"]),
        ("micros0ft-login-alert.net", vec!["main_frame", "sub_frame", "xmlhttprequest"]),
        ("steamcommunlty-trade.ru", vec!["main_frame", "sub_frame", "xmlhttprequest"]),
    ];

    let mut rules: Vec<DeclarativeNetRule> = Vec::with_capacity(512);
    let mut seen = std::collections::HashSet::new();
    let mut id_counter: usize = 1;

    for (dom, rtypes) in base_domains {
        seen.insert(dom.to_string());
        rules.push(DeclarativeNetRule {
            id: id_counter,
            priority: 1,
            action: DeclarativeNetAction {
                action_type: "block".to_string(),
            },
            condition: DeclarativeNetCondition {
                url_filter: format!("||{}^", dom),
                resource_types: rtypes.into_iter().map(String::from).collect(),
            },
        });
        id_counter += 1;
    }

    let mut sorted_feed: Vec<&String> = domains
        .iter()
        .filter(|d| {
            let s = d.trim();
            !s.is_empty()
                && s.contains('.')
                && s != "localhost"
                && s != "127.0.0.1"
                && s != "0.0.0.0"
                && s.len() <= 120
                && s.chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-')
        })
        .collect();
    sorted_feed.sort();

    // Include up to 500 top active malicious domains so rules.json stays fast and well within MV3 static ruleset limits
    for dom in sorted_feed.into_iter().take(500) {
        if !seen.insert(dom.clone()) {
            continue;
        }
        rules.push(DeclarativeNetRule {
            id: id_counter,
            priority: 1,
            action: DeclarativeNetAction {
                action_type: "block".to_string(),
            },
            condition: DeclarativeNetCondition {
                url_filter: format!("||{}^", dom),
                resource_types: vec![
                    "main_frame".to_string(),
                    "sub_frame".to_string(),
                    "script".to_string(),
                    "xmlhttprequest".to_string(),
                ],
            },
        });
        id_counter += 1;
    }

    if let Ok(json) = serde_json::to_string_pretty(&rules) {
        let ext_dir = resolve_extension_dir();
        if ext_dir.exists() {
            let _ = fs::write(ext_dir.join("rules.json"), &json);
        }
        if let Some(dl) = dirs::download_dir() {
            let staged_ff = dl.join("Genesis-Seek-Browser-Guard");
            if staged_ff.exists() {
                let _ = fs::write(staged_ff.join("rules.json"), &json);
                if let Ok(xpi_bytes) = build_valid_firefox_xpi_bytes() {
                    let _ = fs::write(
                        staged_ff.join("Genesis-Seek-Browser-Guard-for-Firefox-v0.3.8.xpi"),
                        &xpi_bytes,
                    );
                    let _ = fs::write(staged_ff.join("browser-guard@genesisseek.io.xpi"), &xpi_bytes);
                }
            }
            let staged_cr = dl.join("Genesis-Seek-Browser-Guard-Chromium");
            if staged_cr.exists() {
                let _ = fs::write(staged_cr.join("rules.json"), &json);
            }
        }
        if let Some(local_data) = dirs::data_local_dir() {
            let fallback = local_data.join("genesis-seek").join("browser-extension");
            if fallback.exists() {
                let _ = fs::write(fallback.join("rules.json"), &json);
            }
        }
    }

    rules.len()
}

#[cfg(test)]
mod extension_tests {
    use super::build_valid_firefox_xpi_bytes;
    use flate2::read::DeflateDecoder;
    use std::io::Read;

    fn le_u16(b: &[u8], off: usize) -> u16 {
        u16::from_le_bytes([b[off], b[off + 1]])
    }

    fn le_u32(b: &[u8], off: usize) -> u32 {
        u32::from_le_bytes([b[off], b[off + 1], b[off + 2], b[off + 3]])
    }

    #[test]
    fn builds_valid_posix_firefox_xpi_without_bom() {
        let xpi = build_valid_firefox_xpi_bytes().expect("XPI builder should succeed");
        assert!(xpi.starts_with(b"PK\x03\x04"), "Must start with local PKZIP magic");

        // Locate EOCD record at tail
        let eocd_off = xpi
            .windows(4)
            .rposition(|w| w == b"PK\x05\x06")
            .expect("Must contain EOCD record");
        let cd_count = le_u16(&xpi, eocd_off + 10) as usize;
        let cd_size = le_u32(&xpi, eocd_off + 12) as usize;
        let cd_off = le_u32(&xpi, eocd_off + 16) as usize;
        assert_eq!(cd_count, 12, "Expected 12 XPI entries");
        assert!(cd_off + cd_size <= eocd_off);

        let mut names = Vec::new();
        let mut manifest_bytes = None;
        let mut cur = cd_off;
        for _ in 0..cd_count {
            assert_eq!(&xpi[cur..cur + 4], b"PK\x01\x02");
            let method = le_u16(&xpi, cur + 10);
            let comp_size = le_u32(&xpi, cur + 20) as usize;
            let fn_len = le_u16(&xpi, cur + 28) as usize;
            let ex_len = le_u16(&xpi, cur + 30) as usize;
            let cm_len = le_u16(&xpi, cur + 32) as usize;
            let local_off = le_u32(&xpi, cur + 42) as usize;

            let name = std::str::from_utf8(&xpi[cur + 46..cur + 46 + fn_len])
                .expect("Entry name must be UTF-8")
                .to_string();
            assert!(!name.contains('\\'), "Entry name '{}' must use POSIX '/' slashes only", name);
            assert!(!name.ends_with('/'), "Directory entries should not be present: '{}'", name);
            names.push(name.clone());

            if name == "manifest.json" {
                assert_eq!(method, 8);
                let l_fn = le_u16(&xpi, local_off + 26) as usize;
                let l_ex = le_u16(&xpi, local_off + 28) as usize;
                let data_start = local_off + 30 + l_fn + l_ex;
                let comp = &xpi[data_start..data_start + comp_size];
                let mut dec = DeflateDecoder::new(comp);
                let mut raw = Vec::new();
                dec.read_to_end(&mut raw).expect("Deflate decode should succeed");
                manifest_bytes = Some(raw);
            }

            cur += 46 + fn_len + ex_len + cm_len;
        }

        assert!(names.contains(&"manifest.json".to_string()));
        assert!(names.contains(&"icons/icon-16.png".to_string()));

        let manifest = manifest_bytes.expect("manifest.json must exist in XPI");
        assert!(
            !manifest.starts_with(&[0xEF, 0xBB, 0xBF]),
            "manifest.json must NOT contain UTF-8 BOM"
        );
        let parsed: serde_json::Value =
            serde_json::from_slice(&manifest).expect("manifest.json must be valid JSON");
        assert_eq!(parsed["version"], "0.3.8");
        assert_eq!(
            parsed["browser_specific_settings"]["gecko"]["id"],
            "browser-guard@genesisseek.io"
        );
    }

    #[test]
    fn profile_provisioning_respects_opt_in_and_cleans_up_user_js() {
        let tmp_prof = std::env::temp_dir().join(format!("gs_ff_prof_{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&tmp_prof).unwrap();
        let user_js_path = tmp_prof.join("user.js");
        // Write CRLF user.js with an existing user-owned preference
        std::fs::write(
            &user_js_path,
            "user_pref(\"browser.startup.homepage\", \"https://example.com\");\r\n",
        )
        .unwrap();

        let xpi = build_valid_firefox_xpi_bytes().unwrap();

        // 1. Opt-out: XPI is staged, CRLF preserved, user.js signature pref is NOT added
        assert!(super::provision_firefox_profile_dir(&tmp_prof, &xpi, false));
        assert!(tmp_prof.join("extensions").join("browser-guard@genesisseek.io.xpi").exists());
        let u1 = std::fs::read_to_string(&user_js_path).unwrap();
        assert!(u1.contains("browser.startup.homepage"));
        assert!(u1.contains("\r\n"));
        assert!(!u1.contains("xpinstall.signatures.required"));
        assert!(!u1.contains("autoDisableScopes"));

        // 2. Opt-in: xpinstall.signatures.required added inside marker block, scope overrides NEVER added
        assert!(super::provision_firefox_profile_dir(&tmp_prof, &xpi, true));
        let u2 = std::fs::read_to_string(&user_js_path).unwrap();
        assert!(u2.contains(super::GENESIS_BLOCK_BEGIN));
        assert!(u2.contains("user_pref(\"xpinstall.signatures.required\", false);"));
        assert!(u2.contains(super::GENESIS_BLOCK_END));
        assert!(!u2.contains("extensions.autoDisableScopes"));
        assert!(!u2.contains("extensions.enabledScopes"));

        // 3. Unprovision: removes XPI and strips Genesis Seek block while keeping unrelated user_prefs and CRLF
        super::unprovision_firefox_profile_dir(&tmp_prof);
        assert!(!tmp_prof.join("extensions").join("browser-guard@genesisseek.io.xpi").exists());
        let u3 = std::fs::read_to_string(&user_js_path).unwrap();
        assert!(u3.contains("browser.startup.homepage"));
        assert!(u3.contains("\r\n"));
        assert!(!u3.contains("xpinstall.signatures.required"));

        // 4. User-authored prefs outside Genesis Seek block (including xpinstall.signatures.required
        // and extensions.autoDisableScopes) are preserved, while legacy v0.3.7 header blocks are stripped
        let legacy_plus_user = concat!(
            "// Custom developer settings\r\n",
            "user_pref(\"xpinstall.signatures.required\", false);\r\n",
            "user_pref(\"extensions.autoDisableScopes\", 0);\r\n",
            "// Genesis Seek Browser Guard Auto-Loader Preferences\r\n",
            "user_pref(\"xpinstall.signatures.required\", false);\r\n",
            "user_pref(\"extensions.autoDisableScopes\", 0);\r\n",
            "user_pref(\"extensions.enabledScopes\", 15);\r\n",
            "user_pref(\"browser.startup.homepage\", \"https://kept.example\");\r\n"
        );
        std::fs::write(&user_js_path, legacy_plus_user).unwrap();
        assert!(super::provision_firefox_profile_dir(&tmp_prof, &xpi, false));
        let u4 = std::fs::read_to_string(&user_js_path).unwrap();
        assert!(
            u4.contains("user_pref(\"xpinstall.signatures.required\", false);"),
            "User-authored xpinstall.signatures.required outside Genesis Seek block must be preserved"
        );
        assert!(
            u4.contains("user_pref(\"extensions.autoDisableScopes\", 0);"),
            "User-authored extensions.autoDisableScopes outside Genesis Seek block must be preserved"
        );
        assert!(
            !u4.contains("extensions.enabledScopes"),
            "Legacy Genesis Seek block line extensions.enabledScopes must be stripped"
        );
        assert!(u4.contains("https://kept.example"));

        // 5. Freshness priority: newer valid rules.json beats older larger rules.json
        let older_large = tmp_prof.join("older_rules.json");
        let newer_small = tmp_prof.join("newer_rules.json");
        let large_payload =
            b"[{\"id\":1,\"priority\":1,\"action\":{\"type\":\"block\"},\"condition\":{\"urlFilter\":\"||old1.test^\"}},{\"id\":2,\"priority\":1,\"action\":{\"type\":\"block\"},\"condition\":{\"urlFilter\":\"||old2.test^\"}}]";
        let small_payload =
            b"[{\"id\":1,\"priority\":1,\"action\":{\"type\":\"block\"},\"condition\":{\"urlFilter\":\"||fresh.test^\"}}]";
        std::fs::write(&older_large, large_payload).unwrap();
        std::thread::sleep(std::time::Duration::from_millis(50));
        std::fs::write(&newer_small, small_payload).unwrap();
        let chosen = super::select_best_rules_json_bytes(&[older_large.clone(), newer_small.clone()]);
        assert_eq!(chosen, small_payload);

        let _ = std::fs::remove_dir_all(&tmp_prof);
    }
}
