use crate::quarantine;
use crate::scanner;
use crate::tray_indicator;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};
use sysinfo::{Pid, System};

#[cfg(target_os = "windows")]
use windows_sys::Win32::{
    Foundation::{CloseHandle, HANDLE},
    System::Threading::{
        OpenProcess, TerminateProcess, PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_SUSPEND_RESUME,
        PROCESS_TERMINATE,
    },
};

#[cfg(target_os = "windows")]
#[link(name = "ntdll")]
extern "system" {
    fn NtSuspendProcess(ProcessHandle: HANDLE) -> i32;
    fn NtResumeProcess(ProcessHandle: HANDLE) -> i32;
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessRiskItem {
    pub pid: u32,
    pub name: String,
    pub exe_path: String,
    pub cmd_line: String,
    pub cpu_usage: f32,
    pub memory_mb: u64,
    pub risk_level: String, // "Safe", "Suspicious", "Critical"
    pub risk_reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PersistenceEntry {
    pub location_type: String,
    pub name: String,
    pub path: String,
    pub command_or_detail: String,
    pub status: String, // "Verified", "Suspicious"
}

/// Check if an executable path on Windows resides in a high-risk user/temp drop zone
/// (`Downloads`, `AppData\Local\Temp`, `AppData\Roaming`, `Users\Public`).
#[cfg(target_os = "windows")]
pub fn is_high_risk_windows_exec_path(exe_path: &str) -> bool {
    if exe_path.is_empty() {
        return false;
    }
    let lower = exe_path.to_lowercase();
    if lower.contains("genesis-seek") || lower.contains("\\windows\\system32\\") {
        return false;
    }
    lower.contains("\\downloads\\")
        || lower.contains("\\appdata\\local\\temp\\")
        || lower.contains("\\appdata\\roaming\\")
        || lower.contains("\\users\\public\\")
}

/// Windows Pre-Execution / Startup Interception:
/// Immediately suspends all threads of a newly spawned process from a high-risk path via `NtSuspendProcess`,
/// scans its executable image with `scanner.rs`, and either resumes (`NtResumeProcess` + LRU cache) if clean
/// or terminates (`TerminateProcess`) and quarantines (`quarantine.rs`) if malicious.
#[cfg(target_os = "windows")]
pub fn intercept_and_scan_windows_process(
    pid: u32,
    pname: &str,
    exe_path: &str,
    cmd_line: &str,
) -> Option<(String, String, String)> {
    let path_obj = Path::new(exe_path);
    if !exe_path.is_empty() && scanner::is_cached_clean(path_obj) {
        let (risk, _) = evaluate_process_risk(pname, exe_path, cmd_line);
        if risk != "Critical" {
            return None;
        }
    }

    let high_risk_path = is_high_risk_windows_exec_path(exe_path);
    let (behav_risk, behav_reason) = evaluate_process_risk(pname, exe_path, cmd_line);

    if !high_risk_path && behav_risk != "Critical" {
        return None;
    }

    unsafe {
        let handle = OpenProcess(
            PROCESS_SUSPEND_RESUME | PROCESS_TERMINATE | PROCESS_QUERY_LIMITED_INFORMATION,
            0,
            pid,
        );

        let mut suspended = false;
        if handle != 0 {
            let status = NtSuspendProcess(handle);
            suspended = status >= 0;
        }

        // Scan the frozen executable image on disk
        let file_detection = if !exe_path.is_empty() && path_obj.exists() {
            scanner::scan_single_file(path_obj)
        } else {
            None
        };

        let is_malicious = file_detection.is_some() || behav_risk == "Critical";

        if is_malicious {
            let (threat_name, reason, sha256) = match file_detection {
                Some(det) => (det.threat_name, det.description, det.sha256),
                None => (
                    "Heur.Win32.VolatileProcessExec".to_string(),
                    behav_reason,
                    scanner::compute_file_sha256(path_obj).unwrap_or_default(),
                ),
            };

            let mut action = if suspended {
                "Suspended via NtSuspendProcess"
            } else {
                "Intercepted"
            }
            .to_string();

            if handle != 0 {
                if TerminateProcess(handle, 1) != 0 {
                    action = "Frozen & Terminated (NtSuspendProcess + TerminateProcess)".to_string();
                }
                CloseHandle(handle);
            }

            if !exe_path.is_empty() && path_obj.exists() {
                if quarantine::quarantine_file(exe_path, &threat_name, "Critical", &sha256).is_ok() {
                    action.push_str(" • Quarantined (.gvault)");
                }
            }

            tray_indicator::notify_tray_updated();
            return Some((threat_name, reason, action));
        } else {
            if handle != 0 {
                if suspended {
                    let _ = NtResumeProcess(handle);
                }
                CloseHandle(handle);
            }
            if !exe_path.is_empty() && path_obj.exists() {
                scanner::cache_clean_verdict(path_obj);
            }
            None
        }
    }
}

pub fn inspect_running_processes() -> Vec<ProcessRiskItem> {
    let mut sys = System::new_all();
    std::thread::sleep(sysinfo::MINIMUM_CPU_UPDATE_INTERVAL);
    sys.refresh_processes();

    let self_pid = std::process::id();
    let mut results = Vec::new();

    for (pid, process) in sys.processes() {
        if pid.as_u32() == self_pid {
            continue;
        }
        let name = process.name().to_string();
        let exe_path = process
            .exe()
            .map(|p| p.to_string_lossy().to_string())
            .unwrap_or_default();
        let cmd_line = process.cmd().join(" ");
        let memory_mb = process.memory() / (1024 * 1024);
        let cpu_usage = process.cpu_usage();

        let (risk_level, risk_reason) = evaluate_process_risk(&name, &exe_path, &cmd_line);

        if risk_level != "Safe" || memory_mb > 35 || cpu_usage > 2.0 {
            results.push(ProcessRiskItem {
                pid: pid.as_u32(),
                name,
                exe_path,
                cmd_line,
                cpu_usage: (cpu_usage * 10.0).round() / 10.0,
                memory_mb,
                risk_level,
                risk_reason,
            });
        }
    }

    results.sort_by(|a, b| {
        let rank = |lvl: &str| match lvl {
            "Critical" => 0,
            "Suspicious" => 1,
            _ => 2,
        };
        rank(&a.risk_level)
            .cmp(&rank(&b.risk_level))
            .then_with(|| b.memory_mb.cmp(&a.memory_mb))
    });

    results.truncate(80);
    results
}

pub fn evaluate_process_risk(name: &str, exe_path: &str, cmd_line: &str) -> (String, String) {
    let lower_exe = exe_path.to_lowercase();
    let lower_cmd = cmd_line.to_lowercase();
    let lower_name = name.to_lowercase();

    let is_appimage_mount = lower_exe.starts_with("/tmp/.mount_");

    // Check 1: Execution from volatile memory or temp directories
    if !is_appimage_mount
        && (lower_exe.starts_with("/dev/shm/")
            || lower_exe.starts_with("/tmp/")
            || lower_exe.starts_with("/var/tmp/")
            || lower_exe.contains("\\appdata\\local\\temp\\"))
    {
        return (
            "Critical".to_string(),
            "Binary executing directly from temporary/volatile memory directory".to_string(),
        );
    }

    // Check 2: Suspicious command line payloads
    if lower_cmd.contains("-encodedcommand")
        || lower_cmd.contains("/dev/tcp/")
        || lower_cmd.contains("stratum+tcp")
        || lower_cmd.contains("xmrig")
        || lower_cmd.contains("nc -e /bin/")
    {
        return (
            "Critical".to_string(),
            "Command-line contains obfuscated payload, reverse shell, or miner arguments".to_string(),
        );
    }

    // Check 3: Windows svchost / lsass masquerading outside System32
    if (lower_name == "svchost.exe" || lower_name == "lsass.exe" || lower_name == "csrss.exe")
        && !lower_exe.is_empty()
        && !lower_exe.contains("\\windows\\system32")
    {
        return (
            "Critical".to_string(),
            "System process name masquerading outside Windows\\System32".to_string(),
        );
    }

    // Check 4: Execution from Downloads directory
    if lower_exe.contains("/downloads/") || lower_exe.contains("\\downloads\\") {
        return (
            "Suspicious".to_string(),
            "Executable running directly from user Downloads folder".to_string(),
        );
    }

    ("Safe".to_string(), "Normal process behavior".to_string())
}

pub fn terminate_process(pid_num: u32) -> Result<String, String> {
    let mut sys = System::new_all();
    sys.refresh_all();
    let pid = Pid::from_u32(pid_num);
    if let Some(process) = sys.process(pid) {
        let name = process.name().to_string();
        if process.kill() {
            Ok(format!("Terminated process {} (PID {})", name, pid_num))
        } else {
            Err(format!(
                "OS denied permission to terminate {} (PID {})",
                name, pid_num
            ))
        }
    } else {
        Err(format!("Process PID {} not found", pid_num))
    }
}

/// Inspect cross-platform startup and persistence hooks (Linux & Windows).
pub fn inspect_persistence_hooks() -> Vec<PersistenceEntry> {
    let mut hooks = Vec::new();

    if let Some(config_dir) = dirs::config_dir() {
        let autostart = config_dir.join("autostart");
        if autostart.exists() {
            if let Ok(entries) = fs::read_dir(&autostart) {
                for entry in entries.flatten() {
                    let path = entry.path();
                    if path.is_file() {
                        let content = fs::read_to_string(&path).unwrap_or_default();
                        let exec_line = content
                            .lines()
                            .find(|l| l.starts_with("Exec="))
                            .unwrap_or("Exec=(unspecified)")
                            .to_string();
                        let status = if exec_line.contains("/tmp/")
                            || exec_line.contains("curl ")
                            || exec_line.contains("wget ")
                            || exec_line.contains("base64")
                        {
                            "Suspicious"
                        } else {
                            "Verified"
                        };
                        hooks.push(PersistenceEntry {
                            location_type: "User Autostart (.desktop)".to_string(),
                            name: entry.file_name().to_string_lossy().to_string(),
                            path: path.to_string_lossy().to_string(),
                            command_or_detail: exec_line,
                            status: status.to_string(),
                        });
                    }
                }
            }
        }

        let systemd_user = config_dir.join("systemd").join("user");
        if systemd_user.exists() {
            if let Ok(entries) = fs::read_dir(&systemd_user) {
                for entry in entries.flatten() {
                    let path = entry.path();
                    if path.is_file() {
                        let content = fs::read_to_string(&path).unwrap_or_default();
                        let exec_line = content
                            .lines()
                            .find(|l| l.trim().starts_with("ExecStart="))
                            .unwrap_or("Unit Configuration")
                            .trim()
                            .to_string();
                        hooks.push(PersistenceEntry {
                            location_type: "Systemd User Service".to_string(),
                            name: entry.file_name().to_string_lossy().to_string(),
                            path: path.to_string_lossy().to_string(),
                            command_or_detail: exec_line,
                            status: "Verified".to_string(),
                        });
                    }
                }
            }
        }
    }

    if let Some(data_roaming) = dirs::data_dir() {
        let win_startup: PathBuf = data_roaming
            .join("Microsoft")
            .join("Windows")
            .join("Start Menu")
            .join("Programs")
            .join("Startup");
        if win_startup.exists() {
            if let Ok(entries) = fs::read_dir(&win_startup) {
                for entry in entries.flatten() {
                    let p = entry.path();
                    hooks.push(PersistenceEntry {
                        location_type: "Windows Startup Folder".to_string(),
                        name: entry.file_name().to_string_lossy().to_string(),
                        path: p.to_string_lossy().to_string(),
                        command_or_detail: "Startup Shortcut / Binary".to_string(),
                        status: "Verified".to_string(),
                    });
                }
            }
        }
    }

    if let Some(home) = dirs::home_dir() {
        let bashrc = home.join(".bashrc");
        if bashrc.exists() {
            let content = fs::read_to_string(&bashrc).unwrap_or_default();
            let suspicious_lines: Vec<&str> = content
                .lines()
                .filter(|l| {
                    let t = l.trim();
                    !t.starts_with('#')
                        && (t.contains("/dev/tcp/")
                            || t.contains("LD_PRELOAD")
                            || t.contains("curl ")
                            || t.contains("nc -e"))
                })
                .collect();
            let status = if suspicious_lines.is_empty() {
                "Verified"
            } else {
                "Suspicious"
            };
            hooks.push(PersistenceEntry {
                location_type: "Shell Profile Hook".to_string(),
                name: ".bashrc".to_string(),
                path: bashrc.to_string_lossy().to_string(),
                command_or_detail: if suspicious_lines.is_empty() {
                    "No anomalous network or preload hooks found".to_string()
                } else {
                    suspicious_lines.join("; ")
                },
                status: status.to_string(),
            });
        }
    }

    hooks
}
