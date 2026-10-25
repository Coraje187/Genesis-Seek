#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod extension_installer;
mod process_guard;
mod quarantine;
mod realtime_shield;
mod scanner;
mod threat_intel_and_net;
mod tray_indicator;

use extension_installer::{DetectedBrowser, ExtensionInstallResult};
use process_guard::{PersistenceEntry, ProcessRiskItem};
use quarantine::QuarantinedItem;
use realtime_shield::{SecurityEvent, ShieldState, UrlCheckResult, SECURITY_EVENTS};
use scanner::ScanReport;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;
use tauri::Manager;
use threat_intel_and_net::{
    AppUpdateInfo, AppUpdateInstallResult, NetworkConnectionItem, ThreatFeedStatus, VtConfigStatus,
    VtScanReport,
};

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
    let _ = extension_installer::set_browser_autoload_enabled(new_state.browser_extension_autoload);
    tray_indicator::notify_tray_updated();

    let enabled_count = [
        new_state.real_time_file_guard,
        new_state.web_browser_guard,
        new_state.ransomware_canary_guard,
        new_state.exploit_process_guard,
    ]
    .iter()
    .filter(|&&b| b)
    .count();
    let pct = enabled_count * 25;

    realtime_shield::log_security_event(
        "System",
        if pct == 100 {
            "Info"
        } else if pct >= 50 {
            "Medium"
        } else {
            "High"
        },
        &format!("Protection Level Now {}% ({}/4 Shields Active)", pct, enabled_count),
        "Endpoint & Browser Shields",
        if pct == 100 {
            "100% Protected"
        } else {
            "Reduced Protection"
        },
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
fn get_virustotal_status() -> VtConfigStatus {
    threat_intel_and_net::get_vt_config_status()
}

#[tauri::command]
fn save_virustotal_config(
    api_key: Option<String>,
    auto_check_suspicious: bool,
) -> Result<VtConfigStatus, String> {
    threat_intel_and_net::update_vt_config(api_key, auto_check_suspicious)
}

#[tauri::command]
fn clear_virustotal_key() -> Result<VtConfigStatus, String> {
    threat_intel_and_net::clear_vt_api_key()
}

#[tauri::command]
async fn virustotal_lookup(target: String) -> Result<VtScanReport, String> {
    tauri::async_runtime::spawn_blocking(move || threat_intel_and_net::vt_check_target(&target))
        .await
        .map_err(|e| e.to_string())?
}

#[tauri::command]
async fn check_app_update() -> Result<AppUpdateInfo, String> {
    tauri::async_runtime::spawn_blocking(threat_intel_and_net::check_github_update)
        .await
        .map_err(|e| e.to_string())?
}

#[tauri::command]
async fn install_app_update() -> Result<AppUpdateInstallResult, String> {
    tauri::async_runtime::spawn_blocking(threat_intel_and_net::install_github_update)
        .await
        .map_err(|e| e.to_string())?
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryTelemetry {
    pub pid: u32,
    pub rss_mb: f64,
    pub private_mb: f64,
}

#[tauri::command]
fn get_live_memory_usage() -> MemoryTelemetry {
    let pid = std::process::id();

    #[cfg(target_os = "linux")]
    {
        let mut rss_kb: u64 = 0;
        if let Ok(status) = fs::read_to_string("/proc/self/status") {
            for line in status.lines() {
                if let Some(rest) = line.strip_prefix("VmRSS:") {
                    if let Some(num_str) = rest.split_whitespace().next() {
                        rss_kb = num_str.parse::<u64>().unwrap_or(0);
                    }
                    break;
                }
            }
        }

        let mut priv_kb: u64 = 0;
        if let Ok(rollup) = fs::read_to_string("/proc/self/smaps_rollup") {
            for line in rollup.lines() {
                if line.starts_with("Private_Clean:") || line.starts_with("Private_Dirty:") {
                    if let Some(num_str) = line.split_whitespace().nth(1) {
                        priv_kb += num_str.parse::<u64>().unwrap_or(0);
                    }
                }
            }
        }

        let rss_mb = ((rss_kb as f64 / 1024.0) * 10.0).round() / 10.0;
        let private_mb = if priv_kb > 0 {
            ((priv_kb as f64 / 1024.0) * 10.0).round() / 10.0
        } else {
            rss_mb
        };

        return MemoryTelemetry {
            pid,
            rss_mb,
            private_mb,
        };
    }

    #[cfg(not(target_os = "linux"))]
    {
        use sysinfo::{Pid, System};
        let mut sys = System::new();
        let sys_pid = Pid::from_u32(pid);
        sys.refresh_process(sys_pid);
        let bytes = sys.process(sys_pid).map(|p| p.memory()).unwrap_or(0);
        let rss_mb = ((bytes as f64 / (1024.0 * 1024.0)) * 10.0).round() / 10.0;
        MemoryTelemetry {
            pid,
            rss_mb,
            private_mb: rss_mb,
        }
    }
}

#[tauri::command]
fn minimize_to_bar(app: tauri::AppHandle) -> Result<(), String> {
    if let Some(win) = app.get_webview_window("main") {
        let _ = win.hide();
    }
    Ok(())
}

fn main() {
    if std::env::args().any(|a| a == "--inject-firefox") {
        extension_installer::inject_firefox_cli_loop();
        return;
    }

    #[cfg(target_os = "linux")]
    {
        if std::env::var_os("WEBKIT_DISABLE_DMABUF_RENDERER").is_none() {
            std::env::set_var("WEBKIT_DISABLE_DMABUF_RENDERER", "1");
        }
        if std::env::var_os("WEBKIT_DISABLE_COMPOSITING_MODE").is_none() {
            std::env::set_var("WEBKIT_DISABLE_COMPOSITING_MODE", "1");
        }
    }

    let _ = extension_installer::setup_firefox_permanent_autoload();
    realtime_shield::spawn_realtime_file_watcher();
    realtime_shield::spawn_ransomware_canary();
    realtime_shield::spawn_process_monitor();
    realtime_shield::spawn_browser_guard_bridge();

    tauri::Builder::default()
        .setup(|app| {
            tray_indicator::register_desktop_bar_indicator(app.handle().clone());
            Ok(())
        })
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
            get_virustotal_status,
            save_virustotal_config,
            clear_virustotal_key,
            virustotal_lookup,
            check_app_update,
            install_app_update,
            get_detected_browsers,
            install_browser_guard_extension,
            open_browser_extension_folder,
            minimize_to_bar,
            get_live_memory_usage,
        ])
        .run(tauri::generate_context!())
        .expect("error while running Genesis Seek application");
}
