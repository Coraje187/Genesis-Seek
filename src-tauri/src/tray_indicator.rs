#[cfg(target_os = "linux")]
use crate::realtime_shield::{self, ShieldState};
use once_cell::sync::Lazy;
use std::sync::Mutex;
use tauri::AppHandle;
#[cfg(target_os = "linux")]
use tauri::Manager;

static APP_HANDLE: Lazy<Mutex<Option<AppHandle>>> = Lazy::new(|| Mutex::new(None));

#[cfg(target_os = "linux")]
mod linux_sni {
    use super::*;
    use glib::variant::{FromVariant, ToVariant};
    use glib::{Variant, VariantDict, VariantTy};

    static DBUS_CONN: Lazy<Mutex<Option<gio::DBusConnection>>> = Lazy::new(|| Mutex::new(None));

    const SNI_XML: &str = r#"
    <node>
      <interface name="org.kde.StatusNotifierItem">
        <property name="Category" type="s" access="read"/>
        <property name="Id" type="s" access="read"/>
        <property name="Title" type="s" access="read"/>
        <property name="Status" type="s" access="read"/>
        <property name="WindowId" type="i" access="read"/>
        <property name="IconName" type="s" access="read"/>
        <property name="IconThemePath" type="s" access="read"/>
        <property name="IconPixmap" type="a(iiay)" access="read"/>
        <property name="OverlayIconName" type="s" access="read"/>
        <property name="OverlayIconPixmap" type="a(iiay)" access="read"/>
        <property name="AttentionIconName" type="s" access="read"/>
        <property name="AttentionIconPixmap" type="a(iiay)" access="read"/>
        <property name="ToolTip" type="(sa(iiay)ss)" access="read"/>
        <property name="ItemIsMenu" type="b" access="read"/>
        <property name="Menu" type="o" access="read"/>
        <method name="Activate">
          <arg name="x" type="i" direction="in"/>
          <arg name="y" type="i" direction="in"/>
        </method>
        <method name="SecondaryActivate">
          <arg name="x" type="i" direction="in"/>
          <arg name="y" type="i" direction="in"/>
        </method>
        <method name="ContextMenu">
          <arg name="x" type="i" direction="in"/>
          <arg name="y" type="i" direction="in"/>
        </method>
        <method name="Scroll">
          <arg name="delta" type="i" direction="in"/>
          <arg name="orientation" type="s" direction="in"/>
        </method>
        <signal name="NewTitle"/>
        <signal name="NewIcon"/>
        <signal name="NewAttentionIcon"/>
        <signal name="NewOverlayIcon"/>
        <signal name="NewToolTip"/>
        <signal name="NewStatus">
          <arg name="status" type="s"/>
        </signal>
      </interface>
    </node>
    "#;

    const DBUSMENU_XML: &str = r#"
    <node>
      <interface name="com.canonical.dbusmenu">
        <property name="Version" type="u" access="read"/>
        <property name="TextDirection" type="s" access="read"/>
        <property name="Status" type="s" access="read"/>
        <property name="IconThemePath" type="as" access="read"/>
        <method name="GetLayout">
          <arg name="parentId" type="i" direction="in"/>
          <arg name="recursionDepth" type="i" direction="in"/>
          <arg name="propertyNames" type="as" direction="in"/>
          <arg name="revision" type="u" direction="out"/>
          <arg name="layout" type="(ia{sv}av)" direction="out"/>
        </method>
        <method name="GetGroupProperties">
          <arg name="ids" type="ai" direction="in"/>
          <arg name="propertyNames" type="as" direction="in"/>
          <arg name="properties" type="a(ia{sv})" direction="out"/>
        </method>
        <method name="GetProperty">
          <arg name="id" type="i" direction="in"/>
          <arg name="name" type="s" direction="in"/>
          <arg name="value" type="v" direction="out"/>
        </method>
        <method name="Event">
          <arg name="id" type="i" direction="in"/>
          <arg name="eventId" type="s" direction="in"/>
          <arg name="data" type="v" direction="in"/>
          <arg name="timestamp" type="u" direction="in"/>
        </method>
        <method name="EventGroup">
          <arg name="events" type="a(isvu)" direction="in"/>
          <arg name="idErrors" type="ai" direction="out"/>
        </method>
        <method name="AboutToShow">
          <arg name="id" type="i" direction="in"/>
          <arg name="needUpdate" type="b" direction="out"/>
        </method>
        <method name="AboutToShowGroup">
          <arg name="ids" type="ai" direction="in"/>
          <arg name="updatesNeeded" type="ai" direction="out"/>
          <arg name="idErrors" type="ai" direction="out"/>
        </method>
        <signal name="LayoutUpdated">
          <arg name="revision" type="u"/>
          <arg name="parent" type="i"/>
        </signal>
      </interface>
    </node>
    "#;

    fn shield_summary(state: &ShieldState) -> (u8, usize, String, String) {
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
        let title = format!("Genesis Seek — {}% Protected ({}/4 Shields)", pct, active_count);
        let subtitle = if pct == 100 {
            "All Real-Time Endpoint & Browser Shields Active".to_string()
        } else if pct == 0 {
            "WARNING: All Real-Time Protection Layers Disabled!".to_string()
        } else {
            format!(
                "{} Protection Layer(s) Disabled — Click to review shields",
                4 - active_count
            )
        };
        (pct, active_count, title, subtitle)
    }

    const NIGHT_SHIELD_ARGB: &[u8; 4096] = include_bytes!("night_shield_32x32.argb");
    const CREAM_SHIELD_ARGB: &[u8; 4096] = include_bytes!("cream_shield_32x32.argb");

    /// Uses the authentic transparent Genesis Seek shield emblem for the system tray:
    /// - 100%: Pure transparent silver shield with cyan/emerald crystal core
    /// - 50..=75%: Transparent shield with subtle amber warning badge dot
    /// - 0..=25%: Transparent shield with subtle red danger badge dot
    fn build_shield_icon_pixmap(pct: u8) -> Variant {
        let size: i32 = 32;
        let mut bytes = NIGHT_SHIELD_ARGB.to_vec();

        if pct < 100 {
            let (r_badge, g_badge, b_badge) = if pct >= 50 {
                (0xf5u8, 0x9eu8, 0x0bu8) // Amber warning
            } else {
                (0xefu8, 0x44u8, 0x44u8) // Red danger
            };
            // Overlay small 7x7 circular status badge in bottom-right corner
            for by in 23..30 {
                for bx in 23..30 {
                    let dx = (bx as f32) - 26.5;
                    let dy = (by as f32) - 26.5;
                    let dist = (dx * dx + dy * dy).sqrt();
                    let idx = ((by * 32 + bx) * 4) as usize;
                    if dist <= 3.2 {
                        if dist <= 2.2 {
                            bytes[idx] = 0xff;
                            bytes[idx + 1] = r_badge;
                            bytes[idx + 2] = g_badge;
                            bytes[idx + 3] = b_badge;
                        } else {
                            bytes[idx] = 0xff;
                            bytes[idx + 1] = 0x0f;
                            bytes[idx + 2] = 0x17;
                            bytes[idx + 3] = 0x2a;
                        }
                    }
                }
            }
        }

        let row = Variant::tuple_from_iter([
            size.to_variant(),
            size.to_variant(),
            Variant::array_from_fixed_array(&bytes),
        ]);
        Variant::array_from_iter::<(i32, i32, Vec<u8>)>([row])
    }

    fn empty_pixmap() -> Variant {
        let empty: [Variant; 0] = [];
        Variant::array_from_iter::<(i32, i32, Vec<u8>)>(empty)
    }

    fn get_sni_property(prop: &str) -> Option<Variant> {
        let state = realtime_shield::current_shields();
        let (pct, _count, title, subtitle) = shield_summary(&state);
        match prop {
            "Category" => Some("ApplicationStatus".to_variant()),
            "Id" => Some("genesis-seek".to_variant()),
            "Title" => Some(title.to_variant()),
            "Status" => Some("Active".to_variant()),
            "WindowId" => Some(0i32.to_variant()),
            "IconName" => Some("".to_variant()), // Force bar to use our live color-coded IconPixmap!
            "IconThemePath" => Some("".to_variant()),
            "IconPixmap" => Some(build_shield_icon_pixmap(pct)),
            "OverlayIconName" => Some("".to_variant()),
            "OverlayIconPixmap" => Some(empty_pixmap()),
            "AttentionIconName" => Some("".to_variant()),
            "AttentionIconPixmap" => Some(build_shield_icon_pixmap(pct)),
            "ToolTip" => {
                let pixmap = build_shield_icon_pixmap(pct);
                Some(Variant::tuple_from_iter([
                    "".to_variant(),
                    pixmap,
                    title.to_variant(),
                    subtitle.to_variant(),
                ]))
            }
            "ItemIsMenu" => Some(false.to_variant()),
            "Menu" => Some(glib::variant::ObjectPath::try_from("/MenuBar").unwrap().to_variant()),
            _ => None,
        }
    }

    fn build_dbusmenu_layout() -> Variant {
        let state = realtime_shield::current_shields();
        let (pct, active_count, _title, _subtitle) = shield_summary(&state);

        let make_item = |id: i32, label: &str, enabled: bool| -> Variant {
            let dict = VariantDict::new(None);
            dict.insert("label", label);
            dict.insert("enabled", enabled);
            dict.insert("visible", true);
            let empty_children: [Variant; 0] = [];
            Variant::tuple_from_iter([
                id.to_variant(),
                dict.end(),
                Variant::array_from_iter::<Variant>(empty_children),
            ])
            .to_variant()
        };

        let status_label = format!("🛡️ Protection: {}% ({}/4 Shields Active)", pct, active_count);
        let children = [
            make_item(1, &status_label, false),
            make_item(2, "Open Genesis Seek Dashboard", true),
            make_item(3, "Enable All Shields (Restore 100%)", true),
            make_item(4, "Quit Genesis Seek", true),
        ];

        let root_dict = VariantDict::new(None);
        root_dict.insert("children-display", "submenu");
        let layout = Variant::tuple_from_iter([
            0i32.to_variant(),
            root_dict.end(),
            Variant::array_from_iter::<Variant>(children),
        ]);
        Variant::tuple_from_iter([1u32.to_variant(), layout])
    }

    fn focus_main_window() {
        if let Ok(guard) = APP_HANDLE.lock() {
            if let Some(app) = guard.as_ref() {
                if let Some(win) = app.get_webview_window("main") {
                    let _ = win.show();
                    let _ = win.unminimize();
                    let _ = win.set_focus();
                }
            }
        }
    }

    pub fn init_linux_tray() {
        let conn = match gio::bus_get_sync(gio::BusType::Session, gio::Cancellable::NONE) {
            Ok(c) => c,
            Err(e) => {
                eprintln!("Failed to connect to session D-Bus for tray indicator: {}", e);
                return;
            }
        };

        let sni_node = match gio::DBusNodeInfo::for_xml(SNI_XML) {
            Ok(n) => n,
            Err(e) => {
                eprintln!("Failed to parse SNI XML: {}", e);
                return;
            }
        };
        let sni_iface = sni_node.lookup_interface("org.kde.StatusNotifierItem").unwrap();

        let _ = conn.register_object(
            "/StatusNotifierItem",
            &sni_iface,
            |_conn, _sender, _path, _iface, method, _params, invocation| {
                match method {
                    "Activate" | "SecondaryActivate" | "ContextMenu" => {
                        focus_main_window();
                        invocation.return_value(None);
                    }
                    "Scroll" => {
                        invocation.return_value(None);
                    }
                    _ => {
                        invocation.return_value(None);
                    }
                }
            },
            |_conn, _sender, _path, _iface, prop| {
                get_sni_property(prop).unwrap_or_else(|| "".to_variant())
            },
            |_conn, _sender, _path, _iface, _prop, _val| false,
        );

        let menu_node = match gio::DBusNodeInfo::for_xml(DBUSMENU_XML) {
            Ok(n) => n,
            Err(_) => return,
        };
        let menu_iface = menu_node.lookup_interface("com.canonical.dbusmenu").unwrap();

        let _ = conn.register_object(
            "/MenuBar",
            &menu_iface,
            |_conn, _sender, _path, _iface, method, params, invocation| {
                match method {
                    "GetLayout" => {
                        invocation.return_value(Some(&build_dbusmenu_layout()));
                    }
                    "GetGroupProperties" => {
                        let empty: [Variant; 0] = [];
                        let arr = Variant::array_from_iter::<(i32, std::collections::HashMap<String, Variant>)>(empty);
                        invocation.return_value(Some(&Variant::tuple_from_iter([arr])));
                    }
                    "GetProperty" => {
                        invocation.return_value(Some(&Variant::tuple_from_iter(["".to_variant().to_variant()])));
                    }
                    "Event" => {
                        if let Some(id_var) = params.try_child_value(0) {
                            if let Some(id) = i32::from_variant(&id_var) {
                                match id {
                                    1 | 2 => focus_main_window(),
                                    3 => {
                                        let full = ShieldState::default();
                                        realtime_shield::save_shield_state(&full);
                                        notify_tray_updated();
                                        focus_main_window();
                                    }
                                    4 => {
                                        std::process::exit(0);
                                    }
                                    _ => {}
                                }
                            }
                        }
                        invocation.return_value(None);
                    }
                    "EventGroup" => {
                        let empty: [i32; 0] = [];
                        invocation.return_value(Some(&Variant::tuple_from_iter([empty.to_variant()])));
                    }
                    "AboutToShow" => {
                        invocation.return_value(Some(&Variant::tuple_from_iter([false.to_variant()])));
                    }
                    "AboutToShowGroup" => {
                        let empty: [i32; 0] = [];
                        invocation.return_value(Some(&Variant::tuple_from_iter([
                            empty.to_variant(),
                            empty.to_variant(),
                        ])));
                    }
                    _ => {
                        invocation.return_value(None);
                    }
                }
            },
            |_conn, _sender, _path, _iface, prop| match prop {
                "Version" => 3u32.to_variant(),
                "TextDirection" => "ltr".to_variant(),
                "Status" => "normal".to_variant(),
                "IconThemePath" => {
                    let empty: [&str; 0] = [];
                    empty.to_variant()
                }
                _ => "".to_variant(),
            },
            |_conn, _sender, _path, _iface, _prop, _val| false,
        );

        let service_name = format!("org.freedesktop.StatusNotifierItem-{}-1", std::process::id());
        let conn_clone = conn.clone();
        let service_clone = service_name.clone();

        gio::bus_own_name_on_connection(
            &conn,
            &service_name,
            gio::BusNameOwnerFlags::NONE,
            move |c, name| {
                let _ = c.call_sync(
                    Some("org.kde.StatusNotifierWatcher"),
                    "/StatusNotifierWatcher",
                    "org.kde.StatusNotifierWatcher",
                    "RegisterStatusNotifierItem",
                    Some(&(name,).to_variant()),
                    None::<&VariantTy>,
                    gio::DBusCallFlags::NONE,
                    2000,
                    gio::Cancellable::NONE,
                );
            },
            |_c, _name| {},
        );

        // Also register directly with unique bus name fallback in case watcher prefers object path
        let _ = conn_clone.call_sync(
            Some("org.kde.StatusNotifierWatcher"),
            "/StatusNotifierWatcher",
            "org.kde.StatusNotifierWatcher",
            "RegisterStatusNotifierItem",
            Some(&(service_clone.as_str(),).to_variant()),
            None::<&VariantTy>,
            gio::DBusCallFlags::NONE,
            2000,
            gio::Cancellable::NONE,
        );

        if let Ok(mut g) = DBUS_CONN.lock() {
            *g = Some(conn);
        }
    }

    pub fn emit_sni_updates() {
        if let Ok(guard) = DBUS_CONN.lock() {
            if let Some(conn) = guard.as_ref() {
                let _ = conn.emit_signal(
                    None::<&str>,
                    "/StatusNotifierItem",
                    "org.kde.StatusNotifierItem",
                    "NewIcon",
                    None,
                );
                let _ = conn.emit_signal(
                    None::<&str>,
                    "/StatusNotifierItem",
                    "org.kde.StatusNotifierItem",
                    "NewTitle",
                    None,
                );
                let _ = conn.emit_signal(
                    None::<&str>,
                    "/StatusNotifierItem",
                    "org.kde.StatusNotifierItem",
                    "NewToolTip",
                    None,
                );
                let _ = conn.emit_signal(
                    None::<&str>,
                    "/StatusNotifierItem",
                    "org.kde.StatusNotifierItem",
                    "NewStatus",
                    Some(&("Active",).to_variant()),
                );
                let _ = conn.emit_signal(
                    None::<&str>,
                    "/MenuBar",
                    "com.canonical.dbusmenu",
                    "LayoutUpdated",
                    Some(&(2u32, 0i32).to_variant()),
                );
            }
        }
    }
}


#[cfg(not(target_os = "linux"))]
fn init_windows_tray(app: &AppHandle) {
    use tauri::menu::{Menu, MenuItem};
    use tauri::tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent};

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

pub fn register_desktop_bar_indicator(app: AppHandle) {
    if let Ok(mut guard) = APP_HANDLE.lock() {
        *guard = Some(app.clone());
    }
    #[cfg(target_os = "linux")]
    {
        linux_sni::init_linux_tray();
    }
    #[cfg(not(target_os = "linux"))]
    {
        init_windows_tray(&app);
    }
}

pub fn notify_tray_updated() {
    #[cfg(target_os = "linux")]
    {
        linux_sni::emit_sni_updates();
    }
    #[cfg(not(target_os = "linux"))]
    {
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
}
