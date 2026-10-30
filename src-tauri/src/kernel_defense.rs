use crate::realtime_shield;
use serde::{Deserialize, Serialize};
use std::fs;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LinuxKernelAudit {
    pub is_linux: bool,
    pub kernel_release: String,
    pub mptcp_supported: bool,
    pub mptcp_enabled: bool,
    pub vulnerability_status: String,
    pub severity: String,
    pub advisory_title: String,
    pub advisory_details: String,
    pub mitigation_command: String,
    pub can_mitigate: bool,
}

pub fn audit_linux_kernel_mptcp() -> LinuxKernelAudit {
    #[cfg(target_os = "linux")]
    {
        let kernel_release = fs::read_to_string("/proc/sys/kernel/osrelease")
            .map(|s| s.trim().to_string())
            .unwrap_or_else(|_| "Unknown Linux Kernel".to_string());

        let mptcp_path = "/proc/sys/net/mptcp/enabled";
        if let Ok(content) = fs::read_to_string(mptcp_path) {
            let enabled = content.trim() == "1";
            if enabled {
                LinuxKernelAudit {
                    is_linux: true,
                    kernel_release,
                    mptcp_supported: true,
                    mptcp_enabled: true,
                    vulnerability_status: "Vulnerable (CVE-2026-98432 Zero-Click Vector Open)".into(),
                    severity: "Critical".into(),
                    advisory_title: "Critical Linux Kernel TCP/MPTCP Exploit (CVE-2026-98432)".into(),
                    advisory_details: "Multipath TCP is enabled (net.mptcp.enabled = 1). An unauthenticated remote attacker can exploit a race condition in MPTCP suboptions to achieve remote root code execution over TCP. Immediate mitigation: Disable MPTCP.".into(),
                    mitigation_command: "sysctl -w net.mptcp.enabled=0".into(),
                    can_mitigate: true,
                }
            } else {
                LinuxKernelAudit {
                    is_linux: true,
                    kernel_release,
                    mptcp_supported: true,
                    mptcp_enabled: false,
                    vulnerability_status: "Hardened & Protected (MPTCP Disabled)".into(),
                    severity: "Safe".into(),
                    advisory_title: "Linux Kernel Hardened: MPTCP Network Vector Neutralized".into(),
                    advisory_details: "Multipath TCP is disabled (net.mptcp.enabled = 0). The zero-click network attack vector for CVE-2026-98432 is neutralized. Keep your package manager updated to the latest distro kernel release.".into(),
                    mitigation_command: "Protected".into(),
                    can_mitigate: true,
                }
            }
        } else {
            LinuxKernelAudit {
                is_linux: true,
                kernel_release,
                mptcp_supported: false,
                mptcp_enabled: false,
                vulnerability_status: "Protected (MPTCP Stack Absent / Not Loaded)".into(),
                severity: "Safe".into(),
                advisory_title: "Linux Kernel: MPTCP Not Active".into(),
                advisory_details: "Multipath TCP (/proc/sys/net/mptcp/enabled) is not loaded or not built into this kernel. Your system is not vulnerable to MPTCP remote option injection.".into(),
                mitigation_command: "N/A".into(),
                can_mitigate: false,
            }
        }
    }

    #[cfg(not(target_os = "linux"))]
    {
        LinuxKernelAudit {
            is_linux: false,
            kernel_release: "Windows NT Subsystem".into(),
            mptcp_supported: false,
            mptcp_enabled: false,
            vulnerability_status: "Not Applicable (Windows)".into(),
            severity: "Safe".into(),
            advisory_title: "Windows NT Kernel — Linux CVE-2026-98432 Not Applicable".into(),
            advisory_details: "This vulnerability exclusively targets the Linux kernel MPTCP networking stack. Windows TCP/IP is unaffected.".into(),
            mitigation_command: "N/A".into(),
            can_mitigate: false,
        }
    }
}

pub fn harden_linux_kernel_mptcp(disable_mptcp: bool) -> Result<LinuxKernelAudit, String> {
    #[cfg(target_os = "linux")]
    {
        let target_val = if disable_mptcp { "0" } else { "1" };
        let mptcp_path = "/proc/sys/net/mptcp/enabled";

        // 1. Attempt writing directly to procfs (works if running with cap_net_admin / root)
        let direct_write = fs::write(mptcp_path, target_val);

        if direct_write.is_err() {
            // 2. Fall back to sysctl via pkexec or sudo
            let sysctl_arg = format!("net.mptcp.enabled={}", target_val);
            let mut cmd = if std::path::Path::new("/usr/bin/pkexec").exists() {
                let mut c = std::process::Command::new("/usr/bin/pkexec");
                c.args(["sysctl", "-w", &sysctl_arg]);
                c
            } else {
                let mut c = std::process::Command::new("sudo");
                c.args(["sysctl", "-w", &sysctl_arg]);
                c
            };

            let output = cmd.output().map_err(|e| format!("Failed to invoke sysctl: {}", e))?;
            if !output.status.success() {
                let stderr = String::from_utf8_lossy(&output.stderr);
                return Err(format!("Could not apply sysctl hardening: {}", stderr));
            }
        }

        // 3. Persist into /etc/sysctl.d/99-genesis-seek-mptcp.conf if possible
        if disable_mptcp {
            let conf_content = "# Hardened by Genesis Seek for CVE-2026-98432\nnet.mptcp.enabled = 0\n";
            let conf_path = "/etc/sysctl.d/99-genesis-seek-mptcp.conf";
            if fs::write(conf_path, conf_content).is_err() {
                // If unprivileged, attempt via pkexec tee
                if std::path::Path::new("/usr/bin/pkexec").exists() {
                    let mut tee = std::process::Command::new("/usr/bin/pkexec");
                    tee.args(["tee", conf_path]);
                    tee.stdin(std::process::Stdio::piped());
                    if let Ok(mut child) = tee.spawn() {
                        if let Some(mut stdin) = child.stdin.take() {
                            use std::io::Write;
                            let _ = stdin.write_all(conf_content.as_bytes());
                        }
                        let _ = child.wait();
                    }
                }
            }
        }

        // 4. Log security event
        realtime_shield::log_security_event(
            "Kernel Defense",
            if disable_mptcp { "Safe" } else { "High" },
            if disable_mptcp {
                "Linux Kernel Hardened: MPTCP Vector Neutralized"
            } else {
                "Linux Kernel Hardening Reverted: MPTCP Re-Enabled"
            },
            &format!("net.mptcp.enabled={}", target_val),
            if disable_mptcp {
                "Mitigated (CVE-2026-98432 Blocked)"
            } else {
                "Exposed"
            },
        );

        Ok(audit_linux_kernel_mptcp())
    }

    #[cfg(not(target_os = "linux"))]
    {
        Ok(audit_linux_kernel_mptcp())
    }
}
