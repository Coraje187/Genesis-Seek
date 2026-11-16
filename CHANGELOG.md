# 🛡️ Genesis Seek Enterprise — Official Changelog & Release History

> **Backward-Compatibility & Stability Policy:**
> All `v0.3.x` → `v0.4.x` releases of **Genesis Seek Enterprise** are **100% backward-compatible drop-in upgrades**. Local SQLite threat databases (`threat_hashes.db`), ChaCha20-Poly1305 quarantine vaults (`.gvault` / `quarantine_index.json`), SHA-256 allowlists (`allowlist.json`), custom YARA rules (`rules/*.yar`), and the loopback Browser Guard bridge (`127.0.0.1:49152`) require **zero manual migration** when upgrading.

---

## [v0.4.1 Enterprise] — 2026-11-16
### Lynis-Grade System Posture Audit, SUID Rootkit Scanner & 1-Click Auto-Hardening

#### 🚀 New Features
- **Host Security Posture Audit Engine (`src-tauri/src/system_audit.rs`)**:
  - Audits 18+ critical OS configuration controls and computes a real-time **Hardening Index (0–100)**.
  - **Kernel & Memory Hardening:** Inspects ASLR (`kernel.randomize_va_space`), `kptr_restrict`, `dmesg_restrict`, `unprivileged_bpf_disabled`, Yama `ptrace_scope`, and `suid_dumpable`.
  - **Network Stack Protection:** Checks TCP SYN flood cookies (`tcp_syncookies`), reverse-path filtering (`rp_filter`), ICMP redirect blocking, and MPTCP stack state.
  - **SUID Privilege Escalation Scanner:** Scans `/usr/bin`, `/usr/sbin`, `/usr/local/bin`, and `/usr/local/sbin` against a curated Linux baseline and flags high-risk GTFOBins SUID vectors.
  - **Filesystem, Mounts, MAC & SSH:** Audits `/dev/shm` (`noexec,nosuid,nodev`), `/etc/shadow` permissions, AppArmor/SELinux enforcement, Firewall status (`ufw`/`firewalld`/`nftables`), SSH `PermitRootLogin`, and password hashing algorithms.
- **1-Click Auto-Harden Engine**:
  - Safely persists hardened sysctl configurations to `/etc/sysctl.d/99-genesis-seek-hardening.conf`, secures `/dev/shm` and `/etc/shadow`, configures UFW/SSH protections, and reloads live policies via `pkexec` in one click.
- **New UI Dashboard Tab & Bridge Endpoint**:
  - Added **System Audit & Hardening** tab in `ui/index.html` & `ui/app.js` with live percentage badge, individual Auto-Fix buttons, and 1-click full hardening.
  - Added `GET /audit` endpoint on the local loopback bridge (`127.0.0.1:49152/audit`).

---

## [v0.4.0 Enterprise] — 2026-11-14
### Mail Gateway, Stream Gateway, DNS Sinkhole & Zero-FP Installer Guard

#### 🚀 New Features
- **RFC 5322 Mail Gateway & Multi-Part MIME Unpacker (`src-tauri/src/scanner.rs`, `src-tauri/src/realtime_shield.rs`)**:
  - Inspects `.eml`, `.msg`, `.oft`, and `.mbox` mail spools on disk and via a live HTTP Mail Gateway endpoint (`POST http://127.0.0.1:49152/gateway/scan-email`).
  - Parses email headers (`From`, `Reply-To`, `Return-Path`, `Authentication-Results`, `Received-SPF`) to detect display-name brand spoofing, cross-domain `Reply-To` phishing lures, and `spf=fail` / `dkim=fail` / `dmarc=fail` authentication anomalies.
  - Recursively unpacks nested `multipart/*` MIME boundaries (`base64` and `quoted-printable`), inspects HTML body URLs (`http://`, `https://`, `file://`, UNC `\\server\share` NTLM traps), and scans every decoded attachment through the full 5-layer engine (YARA, SHA-256 SQLite DB, recursive `.zip`/`.tar.gz`, Office macros, PDF `FlateDecode` streams, `.lnk`, and ClamAV `clamd`).
- **ICAP-Style Local Stream & Proxy Gateway (`POST /gateway/scan-stream`)**:
  - Scans raw byte streams in-memory (`http://127.0.0.1:49152/gateway/scan-stream`) for browser downloads, local proxies, and mail relays before payloads touch user folders.
- **OS Network & DNS Sinkhole Gateway + Outbound WAN SMB Port 445 Relay Guard (`src-tauri/src/threat_intel_and_net.rs`)**:
  - Optional OS-level DNS Sinkhole Gateway (`0.0.0.0` blocklist in `C:\Windows\System32\drivers\etc\hosts` and `/etc/hosts` bounded by `# >>> GENESIS SEEK GATEWAY SINKHOLE START/END <<<`) protecting non-browser apps, mail clients, and CLI tools, with 1-click clean rollback.
  - Detects outbound TCP port `445` (`SMB`) connections to public WAN IPv4/IPv6 addresses (`Exploit.Net.OutboundWanSmbRelay_CVE_2023_23397`) while allowing RFC 1918 private LAN shares.
- **Interactive Mail & Network Gateway Dashboard (`ui/index.html`, `ui/app.js`)**:
  - Added 1-click OS DNS Sinkhole toggle and an interactive `.eml` / MIME Phishing & Attachment Spoof Tester in the **Network & Threat Feeds** tab.

#### 🛠️ Fixes & Zero False-Positive Hardening
- **Windows `.msi` & Official Installer Allowlisting (`src-tauri/src/scanner.rs`, `src-tauri/src/process_guard.rs`)**:
  - Excluded `.msi` / `.msp` / `.mst` OLE2 Windows Installer packages from `Heur.Entropy.EncryptedContainer` and `Heur.Archive.Ole2EmbeddedExecutable`.
  - Recognized trusted installer filenames (`Firefox Installer.exe`, `*setup*.exe`, `*install*.exe`, `vc_redist*.exe`, `EdgeUpdate*.exe`) and 7-Zip SFX temporary extraction folders (`AppData\Local\Temp\7z...\setup-stub.exe`) to prevent false-positive quarantines during legitimate software installations.
  - Ignored in-progress browser partial downloads (`.crdownload`, `.part`, `.opdownload`, `.partial`, `.tmp`) in the real-time watcher until the browser finishes writing and renaming the file.

---

## [v0.3.8 Enterprise] — 2026-11-14
### System Watcher Ransomware Rollback, Live Memory Hollowing Guard, Deep Unpacking & XPI Builder

- **System Watcher Pre-Encryption Shadow Journal & Auto-Rollback (`src-tauri/src/realtime_shield.rs`)**:
  - Maintains bounded in-memory pre-encryption snapshots of user documents and automatically restores clean files if overwritten with high-entropy ransomware ciphertext ($H \ge 7.20$) or renamed to ransomware extensions (`.locked`, `.lockbit`, `.encrypted`, `.ryuk`, `.akira`, `.blackcat`) while terminating volatile-path offending processes.
- **Live Process Memory Hollowing & Reflective DLL Scanner (`src-tauri/src/process_guard.rs`)**:
  - Walks private/anonymous executable virtual memory (`VirtualQueryEx` + `ReadProcessMemory` on Windows; `/proc/<pid>/maps` + `/proc/<pid>/mem` + `memfd:` on Linux) to detect unbacked PE/ELF headers, MZ-stomped Cobalt Strike beacons, `ReflectiveLoader` exports, and Stephen Fewer x64 PEB-walk shellcode stubs.
- **Recursive Multi-Layer Unpacker & Optional ClamAV `clamd` Bridge (`src-tauri/src/scanner.rs`)**:
  - Recursive `.zip`/OpenXML (`ZipSlip` & `ZipBomb` guards, Office `vbaProject.bin`/OLE2 macro scanning), `.tar.gz`/GZIP, PDF `FlateDecode` stream decompression (`/OpenAction`/`/JS`/`/Launch`), Base64/UTF-16LE stagers, MS-SHLLINK `.lnk` binary parser, NTFS `:Zone.Identifier` MotW inspection, and automatic local `clamd` (`zINSTREAM\0`) socket integration.
- **Multi-Ancestor ASR & Root-Anchored Quarantine Guard (`src-tauri/src/process_guard.rs`, `src-tauri/src/quarantine.rs`)**:
  - 4-hop parent/ancestor Office & PDF reader shell blocking, LSASS `MiniDump`/`SAM` protection, recursive Windows Scheduled Task XML auditing, Linux `fanotify` fail-open watchdog, and strict OS binary & symlink quarantine protection.
- **Pure-Rust POSIX PKZIP Firefox `.xpi` Builder (`src-tauri/src/extension_installer.rs`)**:
  - Generates standard PKZIP `.xpi` archives with POSIX `/` entry names and BOM-free UTF-8 `manifest.json`, served directly at `http://127.0.0.1:49152/genesis-seek-browser-guard.xpi`.

---

## [v0.3.7 Enterprise] — 2026-11-12
### Browser Guard Security Hardening, Update Notifier & Outlook CVE Defense

- **DOM XSS Elimination (`browser-extension/content_guard.js`)**: Replaced `innerHTML` block banners with safe DOM nodes and strict text content.
- **Bridge CORS & Endpoint Protection (`src-tauri/src/realtime_shield.rs`)**: Hardened `/sentinel-profile` and loopback origin validation.
- **Tab Memory Leak Fix & Offline Heuristic Fallback (`browser-extension/background.js`)**: Added `chrome.tabs.onRemoved` storage cleanup and offline block warning banners.
- **Update Notifier & Transparent Icons**: Added live extension update badge (`NEW`), popup notification banner, and true-alpha PNG icons (`16x16` to `128x128`).
- **Outlook Unsafe Action & NTLM Leak Detection (`CVE-2023-23397` / `CVE-2024-21413`)**: Added YARA and scanner heuristics for `.msg`, `.eml`, `.oft`, and `.rtf` credential-leak exploits.

---

## [v0.3.5 Enterprise] — 2026-10-28
- **Cross-OS Kernel & Host Hardening (`src-tauri/src/kernel_defense.rs`)**: Linux KSPP sysctl hardening (`net.mptcp.enabled=0`, `kernel.unprivileged_bpf_disabled=1`, `kernel.kptr_restrict=2`, `kernel.dmesg_restrict=1`, `kernel.yama.ptrace_scope=1`) and Windows `HideFileExt=0` + Vulnerable Driver Blocklist enforcement (`CVE-2024-21338`).
- **Live Sentinel Bridge (`/sentinel-profile`)**: Published `sentinel_profile.json` via `127.0.0.1:49152/sentinel-profile`.

---

## [v0.3.0 – v0.3.4 Enterprise] — 2026-10-16
- Initial Enterprise architecture: Pure-Rust YARA engine, SQLite $O(1)$ hash database, Windows `NtSuspendProcess` & Linux `fanotify` pre-execution shield, ChaCha20-Poly1305 `.gvault` encrypted quarantine, Abuse.ch MalwareBazaar/URLhaus/PhishStats threat feeds, native Windows system tray persistence, and Dual Theme UI (Obsidian Night & Warm Cream Light).
