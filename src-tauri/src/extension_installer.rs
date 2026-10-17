use crate::realtime_shield;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

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

/// Detect installed web browsers across Linux and Windows.
pub fn detect_installed_browsers() -> Vec<DetectedBrowser> {
    let ext_dir = resolve_extension_dir().to_string_lossy().to_string();

    let candidates = [
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
        (
            "firefox",
            "Mozilla Firefox",
            vec![
                "/usr/bin/firefox",
                "/snap/bin/firefox",
                r"C:\Program Files\Mozilla Firefox\firefox.exe",
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

    // Also stage a copy into the user's Downloads/Genesis-Seek-Browser-Guard folder for easy access
    if let Some(dl) = dirs::download_dir() {
        let staged = dl.join("Genesis-Seek-Browser-Guard");
        let _ = fs::create_dir_all(&staged);
        if let Ok(entries) = fs::read_dir(&ext_path) {
            for entry in entries.flatten() {
                if entry.path().is_file() {
                    let dest = staged.join(entry.file_name());
                    let _ = fs::copy(entry.path(), dest);
                }
            }
        }
    }

    // If the browser is installed and is Chromium-based (Chrome, Brave, Edge, Chromium),
    // launch it with `--load-extension=<path>` so the extension is loaded immediately!
    if target.installed && !target.binary_path.is_empty() && browser_id != "firefox" {
        let load_arg = format!("--load-extension={}", ext_path_str);
        let spawn_res = Command::new(&target.binary_path)
            .arg(&load_arg)
            .arg("chrome://extensions")
            .spawn();

        if spawn_res.is_ok() {
            realtime_shield::log_security_event(
                "Browser Guard",
                "Info",
                &format!("Installed Browser Guard into {}", target.name),
                &ext_path_str,
                "Extension Loaded",
            );

            return Ok(ExtensionInstallResult {
                browser_name: target.name.clone(),
                success: true,
                extension_path: ext_path_str,
                method_used: "Direct Browser Launch (--load-extension)".to_string(),
                message: format!(
                    "{} was launched with Genesis Seek Browser Guard pre-loaded! You can also pin it from the extensions toolbar.",
                    target.name
                ),
            });
        }
    }

    // For Firefox or if launching the browser in the sandbox wasn't possible, open the extension directory
    // and provide one-click instructions.
    #[cfg(target_os = "linux")]
    {
        let _ = Command::new("xdg-open").arg(&ext_path_str).spawn();
    }
    #[cfg(target_os = "windows")]
    {
        let _ = Command::new("explorer.exe").arg(&ext_path_str).spawn();
    }

    realtime_shield::log_security_event(
        "Browser Guard",
        "Info",
        &format!("Prepared Browser Guard Package for {}", target.name),
        &ext_path_str,
        "Ready to Enable",
    );

    Ok(ExtensionInstallResult {
        browser_name: target.name.clone(),
        success: true,
        extension_path: ext_path_str.clone(),
        method_used: "Staged Extension Package & Folder Opened".to_string(),
        message: format!(
            "Extension staged at:\n{}\n\nAlso copied to your Downloads/Genesis-Seek-Browser-Guard folder for instant installation in {}.",
            ext_path_str, target.name
        ),
    })
}

/// Open the unpacked browser extension folder in the native OS file manager (Windows Explorer / Linux File Manager).
pub fn open_extension_directory() -> Result<String, String> {
    let ext_path = resolve_extension_dir();
    let ext_path_str = ext_path.to_string_lossy().to_string();

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
