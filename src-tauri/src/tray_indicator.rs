use crate::realtime_shield::{self, ShieldState};
use once_cell::sync::Lazy;
use std::sync::Mutex;
use tauri::{AppHandle, Manager};

static APP_HANDLE: Lazy<Mutex<Option<AppHandle>>> = Lazy::new(|| Mutex::new(None));

#[cfg(target_os = "linux")]
mod linux_sni {
    use super::*;
    use gio::prelude::*;
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

    /// Generates a 32x32 ARGB32 shield icon pixmap dynamically colored by protection percentage:
    /// - 100%: Emerald / Cyan (#10b981 / #00e5ff)
    /// - 50..=75%: Amber Warning (#f59e0b)
    /// - 0..=25%: Red Danger (#ef4444)
    fn build_shield_icon_pixmap(pct: u8) -> Variant {
        let size: i32 = 32;
        let mut bytes = Vec::with_capacity((size * size * 4) as usize);

        let (r_main, g_main, b_main, r_border, g_border, b_border) = if pct == 100 {
            (0x10u8, 0xb9u8, 0x81u8, 0x00u8, 0xe5u8, 0xffu8) // Emerald + Cyan border
        } else if pct >= 50 {
            (0xf5u8, 0x9eu8, 0x0bu8, 0xfbu8, 0xbfu8, 0x24u8) // Amber warning
        } else {
            (0xefu8, 0x44u8, 0x44u8, 0xf8u8, 0x71u8, 0x71u8) // Red danger
        };

        for y in 0..size {
            for x in 0..size {
                let fx = (x as f32) - 15.5;
                let fy = (y as f32) - 15.5;

                // Shield silhouette math
                let top_ok = y >= 3 && y <= 29;
                let half_width = if y < 14 {
                    11.5
                } else {
                    11.5 * (1.0 - ((y - 14) as f32 / 16.0).powf(1.35))
                };
                let inside_outer = top_ok && fx.abs() <= half_width;
                let inside_inner = y >= 5
                    && y <= 27
                    && fx.abs() <= (half_width - 2.2).max(0.0);

                // Inner emblem (check or exclamation)
                let is_symbol = if pct == 100 {
                    // Checkmark
                    let seg1 = (x >= 10 && x <= 14) && (y - (x + 4)).abs() <= 1;
                    let seg2 = (x >= 14 && x <= 22) && (y - (32 - x)).abs() <= 1;
                    seg1 || seg2
                } else {
                    // Exclamation mark (!)
                    let bar = fx.abs() <= 1.3 && y >= 9 && y <= 18;
                    let dot = fx.abs() <= 1.3 && y >= 21 && y <= 23;
                    bar || dot
                };

                if is_symbol && inside_inner {
                    // Crisp white symbol
                    bytes.extend_from_slice(&[0xff, 0xff, 0xff, 0xff]);
                } else if inside_inner {
                    // Deep obsidian interior blended with status color
                    bytes.extend_from_slice(&[
                        0xf2,
                        (r_main as u16 / 2 + 12) as u8,
                        (g_main as u16 / 2 + 18) as u8,
                        (b_main as u16 / 2 + 28) as u8,
                    ]);
                } else if inside_outer {
                    // Glowing shield border
                    bytes.extend_from_slice(&[0xff, r_border, g_border, b_border]);
                } else {
                    let _ = fy;
                    bytes.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
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

pub fn register_desktop_bar_indicator(app: AppHandle) {
    if let Ok(mut guard) = APP_HANDLE.lock() {
        *guard = Some(app);
    }
    #[cfg(target_os = "linux")]
    {
        linux_sni::init_linux_tray();
    }
}

pub fn notify_tray_updated() {
    #[cfg(target_os = "linux")]
    {
        linux_sni::emit_sni_updates();
    }
}
