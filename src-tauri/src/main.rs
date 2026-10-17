#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod extension_installer;
mod process_guard;
mod quarantine;
mod realtime_shield;
mod scanner;
mod threat_intel_and_net;

use extension_installer::{DetectedBrowser, ExtensionInstallResult};
use process_guard::{PersistenceEntry, ProcessRiskItem};
use quarantine::QuarantinedItem;
use realtime_shield::{SecurityEvent, ShieldState, UrlCheckResult, SECURITY_EVENTS};
use scanner::ScanReport;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;
use threat_intel_and_net::{NetworkConnectionItem, ThreatFeedStatus};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserPreferences {
    pub theme: String, // "night" or "cream"
}

impl Default for UserPreferences {
    fn default() -> Self {
        Self {
            theme: "night".to_string(),
        }
    }
}

fn get_preferences_file() -> PathBuf {
    realtime_shield::app_config_dir().join("user_preferences.json")
}

#[tauri::command]
fn get_user_preferences() -> UserPreferences {
    let path = get_preferences_file();
    if path.exists() {
        if let Ok(raw) = fs::read_to_string(path) {
            if let Ok(prefs) = serde_json::from_str::<UserPreferences>(&raw) {
                return prefs;
            }
        }
    }
    UserPreferences::default()
}

#[tauri::command]
fn save_user_theme(theme: String) -> Result<UserPreferences, String> {
    let normalized = if theme == "cream" { "cream" } else { "night" }.to_string();
    let prefs = UserPreferences { theme: normalized };
    let json = serde_json::to_string_pretty(&prefs).map_err(|e| e.to_string())?;
    fs::write(get_preferences_file(), json).map_err(|e| e.to_string())?;
    Ok(prefs)
}

#[tauri::command]
fn get_shield_state() -> ShieldState {
    realtime_shield::current_shields()
}

#[tauri::command]
fn update_shield_state(new_state: ShieldState) -> ShieldState {
    realtime_shield::save_shield_state(&new_state);
    realtime_shield::log_security_event(
        "System",
        "Info",
        "Real-Time Protection Policy Updated",
        "All Endpoint Shields",
        "Synchronized",
    );
    new_state
}

#[tauri::command]
async fn run_threat_scan(scan_type: String, custom_path: Option<String>) -> Result<ScanReport, String> {
    let max_files = match scan_type.as_str() {
        "quick" => 2500,
        "threat" => 8000,
        _ => 15000,
    };

    let st = scan_type.clone();
    let report = tauri::async_runtime::spawn_blocking(move || {
        scanner::execute_scan(&st, custom_path, max_files)
    })
    .await
    .map_err(|e| e.to_string())??;

    realtime_shield::log_security_event(
        "File Guard",
        if report.detections.is_empty() {
            "Info"
        } else {
            "High"
        },
        &format!(
            "{} Scan Completed ({} files inspected)",
            scan_type.to_uppercase(),
            report.scanned_files
        ),
        &format!("{} threat(s) detected", report.detections.len()),
        if report.detections.is_empty() {
            "System Clean"
        } else {
            "Action Required"
        },
    );

    Ok(report)
}

#[tauri::command]
fn create_eicar_test_file() -> Result<String, String> {
    let target_dir = dirs::download_dir().unwrap_or_else(std::env::temp_dir);
    let test_file = target_dir.join("genesis_seek_eicar_test.txt");
    let eicar_str = scanner::eicar_test_string();
    fs::write(&test_file, eicar_str).map_err(|e| e.to_string())?;
    let path_str = test_file.to_string_lossy().to_string();

    realtime_shield::log_security_event(
        "File Guard",
        "Medium",
        "Safe EICAR Verification File Created",
        &path_str,
        "Ready for Scan / Real-Time Intercept",
    );

    Ok(path_str)
}

#[tauri::command]
fn quarantine_threat(
    file_path: String,
    threat_name: String,
    severity: String,
    sha256: String,
) -> Result<QuarantinedItem, String> {
    let item = quarantine::quarantine_file(&file_path, &threat_name, &severity, &sha256)?;
    realtime_shield::log_security_event(
        "Quarantine Vault",
        &severity,
        &format!("Threat Isolated: {}", threat_name),
        &file_path,
        "Obfuscated in Vault",
    );
    Ok(item)
}

#[tauri::command]
fn get_quarantine_list() -> Vec<QuarantinedItem> {
    quarantine::list_quarantined_items()
}

#[tauri::command]
fn restore_from_quarantine(id: String) -> Result<String, String> {
    let path = quarantine::restore_quarantined_file(&id)?;
    realtime_shield::log_security_event(
        "Quarantine Vault",
        "Info",
        "File Restored & Allowlisted",
        &path,
        "Restored",
    );
    Ok(path)
}

#[tauri::command]
fn delete_from_quarantine(id: String) -> Result<(), String> {
    quarantine::delete_quarantined_file(&id)?;
    realtime_shield::log_security_event(
        "Quarantine Vault",
        "Info",
        "Threat Permanently Shredded",
        &id,
        "Zero-Filled & Deleted",
    );
    Ok(())
}

#[tauri::command]
async fn get_processes_and_risks() -> Result<Vec<ProcessRiskItem>, String> {
    tauri::async_runtime::spawn_blocking(process_guard::inspect_running_processes)
        .await
        .map_err(|e| e.to_string())
}

#[tauri::command]
fn kill_suspicious_process(pid: u32) -> Result<String, String> {
    let msg = process_guard::terminate_process(pid)?;
    realtime_shield::log_security_event(
        "Process Guard",
        "High",
        "Process Terminated by User",
        &format!("PID {}", pid),
        "Terminated",
    );
    Ok(msg)
}

#[tauri::command]
fn get_persistence_items() -> Vec<PersistenceEntry> {
    process_guard::inspect_persistence_hooks()
}

#[tauri::command]
fn check_url_reputation(url: String) -> UrlCheckResult {
    let res = realtime_shield::evaluate_url_safety(&url);
    if !res.safe {
        realtime_shield::log_security_event(
            "Browser Guard",
            "High",
            &format!("Blocked {}: {}", res.category, res.domain),
            &res.url,
            "Blocked",
        );
    }
    res
}

#[tauri::command]
fn get_security_events() -> Vec<SecurityEvent> {
    SECURITY_EVENTS
        .lock()
        .map(|e| e.clone())
        .unwrap_or_default()
}

#[tauri::command]
fn get_feed_status() -> ThreatFeedStatus {
    threat_intel_and_net::get_threat_feed_status()
}

#[tauri::command]
async fn sync_threat_feeds() -> Result<ThreatFeedStatus, String> {
    tauri::async_runtime::spawn_blocking(threat_intel_and_net::sync_threat_intelligence_feeds)
        .await
        .map_err(|e| e.to_string())
}

#[tauri::command]
fn get_network_connections() -> Vec<NetworkConnectionItem> {
    threat_intel_and_net::inspect_active_network_connections()
}

#[tauri::command]
fn get_detected_browsers() -> Vec<DetectedBrowser> {
    extension_installer::detect_installed_browsers()
}

#[tauri::command]
fn install_browser_guard_extension(browser_id: String) -> Result<ExtensionInstallResult, String> {
    extension_installer::install_extension_for_browser(&browser_id)
}

#[tauri::command]
fn open_browser_extension_folder() -> Result<String, String> {
    extension_installer::open_extension_directory()
}

fn main() {
    #[cfg(target_os = "linux")]
    {
        if std::env::var_os("WEBKIT_DISABLE_DMABUF_RENDERER").is_none() {
            std::env::set_var("WEBKIT_DISABLE_DMABUF_RENDERER", "1");
        }
        if std::env::var_os("WEBKIT_DISABLE_COMPOSITING_MODE").is_none() {
            std::env::set_var("WEBKIT_DISABLE_COMPOSITING_MODE", "1");
        }
    }

    realtime_shield::spawn_realtime_file_watcher();
    realtime_shield::spawn_ransomware_canary();
    realtime_shield::spawn_process_monitor();
    realtime_shield::spawn_browser_guard_bridge();

    tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![
            get_user_preferences,
            save_user_theme,
            get_shield_state,
            update_shield_state,
            run_threat_scan,
            create_eicar_test_file,
            quarantine_threat,
            get_quarantine_list,
            restore_from_quarantine,
            delete_from_quarantine,
            get_processes_and_risks,
            kill_suspicious_process,
            get_persistence_items,
            check_url_reputation,
            get_security_events,
            get_feed_status,
            sync_threat_feeds,
            get_network_connections,
            get_detected_browsers,
            install_browser_guard_extension,
            open_browser_extension_folder,
        ])
        .run(tauri::generate_context!())
        .expect("error while running Genesis Seek application");
}
