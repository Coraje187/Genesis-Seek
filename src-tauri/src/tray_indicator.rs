use crate::realtime_shield;
use once_cell::sync::Lazy;
use std::sync::Mutex;
use tauri::menu::{Menu, MenuItem};
use tauri::tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent};
use tauri::AppHandle;
use tauri::Manager;

static APP_HANDLE: Lazy<Mutex<Option<AppHandle>>> = Lazy::new(|| Mutex::new(None));

pub fn register_desktop_bar_indicator(app: AppHandle) {
    init_app_tray(&app);
    if let Ok(mut guard) = APP_HANDLE.lock() {
        *guard = Some(app);
    }
}

fn init_app_tray(app: &AppHandle) {
    let show_item = MenuItem::with_id(app, "show", "Open Genesis Seek Dashboard", true, None::<&str>).ok();
    let scan_item = MenuItem::with_id(app, "scan", "Run Quick Scan", true, None::<&str>).ok();
    let quit_item = MenuItem::with_id(app, "quit", "Quit Genesis Seek", true, None::<&str>).ok();

    let menu_builder = Menu::default(app).ok();
    if let Some(ref m) = menu_builder {
        if let Some(ref s) = show_item {
            let _ = m.append(s);
        }
        if let Some(ref sc) = scan_item {
            let _ = m.append(sc);
        }
        if let Some(ref q) = quit_item {
            let _ = m.append(q);
        }
    }

    let icon = app.default_window_icon().cloned();

    let mut builder = TrayIconBuilder::with_id("genesis-seek-tray")
        .tooltip("Genesis Seek — 100% Protected (Real-Time Shield Active)")
        .show_menu_on_left_click(false);

    if let Some(ic) = icon {
        builder = builder.icon(ic);
    }

    if let Some(ref m) = menu_builder {
        builder = builder.menu(m);
    }

    let _ = builder
        .on_menu_event(|app, event| match event.id.as_ref() {
            "show" => {
                if let Some(win) = app.get_webview_window("main") {
                    let _ = win.show();
                    let _ = win.unminimize();
                    let _ = win.set_focus();
                }
            }
            "scan" => {
                if let Some(win) = app.get_webview_window("main") {
                    let _ = win.show();
                    let _ = win.unminimize();
                    let _ = win.set_focus();
                    let _ = win.eval("window.switchTab('scanner'); triggerScan('quick');");
                }
            }
            "quit" => {
                std::process::exit(0);
            }
            _ => {}
        })
        .on_tray_icon_event(|tray, event| {
            if let TrayIconEvent::Click {
                button: MouseButton::Left,
                button_state: MouseButtonState::Up,
                ..
            } = event
            {
                let app = tray.app_handle();
                if let Some(win) = app.get_webview_window("main") {
                    if win.is_visible().unwrap_or(false) {
                        let _ = win.hide();
                    } else {
                        let _ = win.show();
                        let _ = win.unminimize();
                        let _ = win.set_focus();
                    }
                }
            }
        })
        .build(app);
}

pub fn notify_tray_updated() {
    if let Ok(guard) = APP_HANDLE.lock() {
        if let Some(app) = guard.as_ref() {
            if let Some(tray) = app.tray_by_id("genesis-seek-tray") {
                let state = realtime_shield::current_shields();
                let active_count = [
                    state.real_time_file_guard,
                    state.web_browser_guard,
                    state.ransomware_canary_guard,
                    state.exploit_process_guard,
                ]
                .iter()
                .filter(|&&b| b)
                .count();
                let pct = (active_count as u8) * 25;
                let tooltip = format!(
                    "Genesis Seek — {}% Protected ({}/4 Shields Active)",
                    pct, active_count
                );
                let _ = tray.set_tooltip(Some(tooltip));
            }
        }
    }
}
