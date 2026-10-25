use crate::quarantine;
use crate::realtime_shield;
use crate::scanner::{self, ThreatDetection};
use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};
use std::path::Path;
use std::sync::Mutex;
use tauri::{AppHandle, Emitter, Manager};

static ALERT_APP: Lazy<Mutex<Option<AppHandle>>> = Lazy::new(|| Mutex::new(None));
static PENDING_ALERT: Lazy<Mutex<Option<ThreatAlertData>>> = Lazy::new(|| Mutex::new(None));

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatAlertData {
    pub file_path: String,
    pub file_name: String,
    pub threat_name: String,
    pub category: String,
    pub severity: String,
    pub sha256: String,
    pub description: String,
}

pub fn set_alert_app_handle(app: AppHandle) {
    if let Ok(mut g) = ALERT_APP.lock() {
        *g = Some(app);
    }
}

/// Trigger an interactive, non-intrusive alert popup with options to "Quarantine" or "Allow & Leave".
pub fn trigger_threat_alert(det: &ThreatDetection) {
    let p = Path::new(&det.file_path);
    let fname = p
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_else(|| det.file_path.clone());

    let desc = if det.threat_name.contains("RiskWare") || det.category.contains("RiskWare") {
        "Game repack, patcher, or DRM-bypass signatures detected. If you trust this source and know it is safe, choose Allow & Leave."
    } else {
        &det.description
    };

    let alert_data = ThreatAlertData {
        file_path: det.file_path.clone(),
        file_name: fname,
        threat_name: det.threat_name.clone(),
        category: det.category.clone(),
        severity: det.severity.clone(),
        sha256: det.sha256.clone(),
        description: desc.to_string(),
    };

    if let Ok(mut pending) = PENDING_ALERT.lock() {
        *pending = Some(alert_data.clone());
    }

    if let Ok(g) = ALERT_APP.lock() {
        if let Some(app) = g.as_ref() {
            // 1. Emit to main window if open
            let _ = app.emit("threat-alert-data", &alert_data);

            // 2. Display dedicated floating alert window
            if let Some(alert_win) = app.get_webview_window("alert-window") {
                if let Ok(Some(mon)) = alert_win.current_monitor() {
                    let size = mon.size();
                    let scale = mon.scale_factor();
                    let x = (size.width as f64 / scale) - 500.0;
                    let y = (size.height as f64 / scale) - 300.0;
                    let _ = alert_win.set_position(tauri::Position::Logical(tauri::LogicalPosition::new(x, y)));
                }
                let _ = alert_win.emit("threat-alert-data", &alert_data);
                let _ = alert_win.show();
                let _ = alert_win.set_focus();
            }
        }
    }
}

#[tauri::command]
pub fn get_pending_threat_alert() -> Option<ThreatAlertData> {
    if let Ok(pending) = PENDING_ALERT.lock() {
        pending.clone()
    } else {
        None
    }
}

#[tauri::command]
pub fn allowlist_and_trust_threat(file_path: String, sha256: String) -> Result<String, String> {
    let p = Path::new(&file_path);
    if !sha256.is_empty() {
        quarantine::add_to_allowlist(&sha256);
    } else if let Some(calc_sha) = scanner::compute_file_sha256(p) {
        quarantine::add_to_allowlist(&calc_sha);
    }

    scanner::cache_clean_verdict(p);

    realtime_shield::log_security_event(
        "User Trust",
        "Safe",
        "File Allowed & Trusted by User",
        &file_path,
        "Retained untouched on disk",
    );

    crate::tray_indicator::notify_tray_updated();
    dismiss_threat_alert()?;

    Ok(format!("Allowed and trusted {}", file_path))
}

#[tauri::command]
pub fn quarantine_threat_file(
    file_path: String,
    threat_name: String,
    severity: String,
    sha256: String,
) -> Result<String, String> {
    let result = quarantine::quarantine_file(&file_path, &threat_name, &severity, &sha256)?;

    realtime_shield::log_security_event(
        "Interactive Quarantine",
        &severity,
        &format!("Threat Quarantined by User: {}", threat_name),
        &file_path,
        "Encrypted & moved to .gvault",
    );

    crate::tray_indicator::notify_tray_updated();
    dismiss_threat_alert()?;

    Ok(format!("Successfully quarantined item ID {}", result.id))
}

#[tauri::command]
pub fn dismiss_threat_alert() -> Result<(), String> {
    if let Ok(g) = ALERT_APP.lock() {
        if let Some(app) = g.as_ref() {
            if let Some(alert_win) = app.get_webview_window("alert-window") {
                let _ = alert_win.hide();
            }
        }
    }
    Ok(())
}
