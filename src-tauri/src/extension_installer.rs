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

/// Locate the `browser-extension/` directory relative to the installed app data dir or project.
pub fn resolve_extension_dir() -> PathBuf {
    if let Some(data_dir) = dirs::data_local_dir() {
        let installed_ext = data_dir.join("genesis-seek").join("browser-extension");
        if installed_ext.exists() {
            return installed_ext;
        }
    }
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
    PathBuf::from("/home/coraje/.gemini/antigravity/scratch/genesis-seek/browser-extension")
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
        r#"{
  "manifest_version": 3,
  "name": "Genesis Seek Browser Guard",
  "version": "0.1.0",
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
      "strict_min_version": "109.0"
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
"#
    } else {
        r#"{
  "manifest_version": 3,
  "name": "Genesis Seek Browser Guard",
  "version": "0.1.0",
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
"#
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
fn try_firefox_marionette_install(ext_path: &str) -> Result<String, String> {
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
    write_browser_manifest(&ext_path, is_firefox);

    // Stage a complete recursive copy (including icons/!) into Downloads/Genesis-Seek-Browser-Guard
    let mut staged_path_str = ext_path_str.clone();
    if let Some(dl) = dirs::download_dir() {
        let staged = dl.join("Genesis-Seek-Browser-Guard");
        if copy_dir_recursive(&ext_path, &staged).is_ok() {
            write_browser_manifest(&staged, is_firefox);
            staged_path_str = staged.to_string_lossy().to_string();
        }
    }

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

    // 1. Chromium-based browsers (Chrome, Brave, Edge, Chromium): launch with `--load-extension=<path>`
    if target.installed && !target.binary_path.is_empty() && !is_firefox {
        let load_arg = format!("--load-extension={}", ext_path_str);
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
                &ext_path_str,
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
    //    - Try instant Marionette auto-install if port 2828 is open
    //    - Open `http://127.0.0.1:49152/install-firefox` in Firefox (unlike `about:` URLs which Firefox blocks from CLI when already running,
    //      `http://127.0.0.1:49152/install-firefox` always opens a new tab in the running Firefox window with 1-click copy buttons!)
    if is_firefox && target.installed && !target.binary_path.is_empty() {
        // Ensure no unsigned .xpi sits in Downloads/Genesis-Seek-Browser-Guard to prevent the `about:addons` "has not been verified" error
        let _ = fs::remove_file(Path::new(&staged_path_str).join("genesis-seek-browser-guard.xpi"));

        if try_firefox_marionette_install(&ext_path_str).is_ok() {
            realtime_shield::log_security_event(
                "Browser Guard",
                "Info",
                "Auto-Installed Browser Guard into Mozilla Firefox",
                &ext_path_str,
                "Extension Active",
            );
            return Ok(ExtensionInstallResult {
                browser_name: target.name,
                success: true,
                extension_path: staged_path_str,
                method_used: "Firefox Automatic Add-on Installer".to_string(),
                message: "Genesis Seek Browser Guard has been automatically installed and activated in Mozilla Firefox!".to_string(),
            });
        }

        // Open the local interactive installer tab in Firefox (`http://127.0.0.1:49152/install-firefox`)
        let _ = Command::new(&target.binary_path)
            .arg("--marionette")
            .arg("http://127.0.0.1:49152/install-firefox")
            .spawn();

        for _ in 0..6 {
            thread::sleep(Duration::from_millis(300));
            if try_firefox_marionette_install(&ext_path_str).is_ok() {
                realtime_shield::log_security_event(
                    "Browser Guard",
                    "Info",
                    "Auto-Installed Browser Guard into Mozilla Firefox",
                    &ext_path_str,
                    "Extension Active",
                );
                return Ok(ExtensionInstallResult {
                    browser_name: target.name,
                    success: true,
                    extension_path: staged_path_str,
                    method_used: "Firefox Automatic Add-on Installer".to_string(),
                    message: "Genesis Seek Browser Guard was automatically loaded into Mozilla Firefox! Look for the shield icon in your Firefox Extensions puzzle menu.".to_string(),
                });
            }
        }

        let manifest_file = Path::new(&staged_path_str)
            .join("manifest.json")
            .to_string_lossy()
            .to_string();

        realtime_shield::log_security_event(
            "Browser Guard",
            "Info",
            "Opened Firefox Interactive Extension Installer",
            &manifest_file,
            "Ready in Firefox Tab",
        );

        return Ok(ExtensionInstallResult {
            browser_name: target.name,
            success: true,
            extension_path: staged_path_str.clone(),
            method_used: "Firefox Installer Tab Opened".to_string(),
            message: format!(
                "NOTE: Do NOT use 'about:addons' (Install Add-on From File), which causes the 'has not been verified' error.\n\n\
                 Instead:\n\
                 1. In Firefox's top address bar, type or paste:  about:debugging#/runtime/this-firefox\n\
                 2. Click 'Load Temporary Add-on...'\n\
                 3. Select manifest.json inside Downloads/Genesis-Seek-Browser-Guard:\n   {}",
                manifest_file
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
