# 🛡️ Genesis Seek — Lightweight Cross-Platform Anti-Malware, Real-Time Shield & Browser Guard

<p align="center">
  <img src="ui/assets/logo-emblem-night.jpg" alt="Genesis Seek Obsidian Night Emblem" width="220" />
  <img src="ui/assets/logo-emblem-cream.jpg" alt="Genesis Seek Warm Cream Emblem" width="220" />
</p>

**Genesis Seek** is an ultra-lightweight (~14 MB RAM footprint), enterprise-grade endpoint & browser security suite engineered in **Rust + Tauri v2** for **Windows and Linux**, paired with a real-time **Manifest V3 Browser Guard Extension**.

---

## 📥 Downloads & Installation (v0.4.0 Enterprise)

### 🪟 Windows (10 / 11)
* **Standalone Binary**: [**genesis-seek.exe**](https://github.com/Coraje187/Genesis-Seek/releases/download/v0.4.0/genesis-seek.exe) *(Includes native system tray indicator and background persistence)*
* **NSIS Setup Installer**: [**Genesis.Seek_0.4.0_x64-setup.exe**](https://github.com/Coraje187/Genesis-Seek/releases/download/v0.4.0/Genesis.Seek_0.4.0_x64-setup.exe)
* **MSI Enterprise Package**: [**Genesis.Seek_0.4.0_x64_en-US.msi**](https://github.com/Coraje187/Genesis-Seek/releases/download/v0.4.0/Genesis.Seek_0.4.0_x64_en-US.msi)
* **Portable Archive**: [**genesis-seek-v0.4.0-windows-x86_64.zip**](https://github.com/Coraje187/Genesis-Seek/releases/download/v0.4.0/genesis-seek-v0.4.0-windows-x86_64.zip)

### 🐧 Linux (Arch / CachyOS, Ubuntu, Debian, Fedora)
* **One-Line Automatic Terminal Installer**:
  ```bash
  curl -sSL https://raw.githubusercontent.com/Coraje187/Genesis-Seek/main/install.sh | bash
  ```
* **Standalone AppImage**: [**Genesis-Seek-0.4.0-x86_64.AppImage**](https://github.com/Coraje187/Genesis-Seek/releases/download/v0.4.0/Genesis-Seek-0.4.0-x86_64.AppImage)
* **Linux Archive**: [**genesis-seek-v0.4.0-linux-x86_64.tar.gz**](https://github.com/Coraje187/Genesis-Seek/releases/download/v0.4.0/genesis-seek-v0.4.0-linux-x86_64.tar.gz)

### 🌐 Browser Guard Extensions

| Browser | Package / Link | Installation Guide |
| :--- | :--- | :--- |
| **Microsoft Edge, Chrome & Brave** | [**`Genesis-Seek-Browser-Guard-for-Chrome-and-Edge-v0.4.0.zip`**](https://github.com/Coraje187/Genesis-Seek/releases/download/v0.4.0/Genesis-Seek-Browser-Guard-for-Chrome-and-Edge-v0.4.0.zip) | Extract zip, navigate to `edge://extensions` or `chrome://extensions`, enable **Developer mode**, and click **"Load unpacked"**. |
| **Mozilla Firefox** | [**`Genesis-Seek-Browser-Guard-for-Firefox-v0.4.0.xpi`**](https://github.com/Coraje187/Genesis-Seek/releases/download/v0.4.0/Genesis-Seek-Browser-Guard-for-Firefox-v0.4.0.xpi) | Drag and drop the `.xpi` into Firefox, or load via `about:debugging#/runtime/this-firefox`. |
| **Mozilla Add-ons (AMO)** | [**Official Firefox AMO Store**](https://addons.mozilla.org/en-US/firefox/addon/genesis-seek-browser-guard/) | 1-Click official store installation and auto-updates. |

---

## ✨ Core Enterprise Protection Layers (v0.4.0)

1. **Multi-Engine File, Archive & Container Scanner ([`src-tauri/src/scanner.rs`](src-tauri/src/scanner.rs))**
   - **Recursive Unpacking & De-Obfuscation**: Inspects nested `.zip`/OpenXML (with ZipSlip, ZipBomb, encrypted executable dropper, and Office `vbaProject.bin`/OLE2 macro detection), `.tar.gz`/`.tgz`/GZIP, PDF `FlateDecode` streams (`/OpenAction`/`/JS`/`/Launch`), Base64/UTF-16LE stagers, 64 KB EOF overlays, and optional local ClamAV `clamd` (`zINSTREAM\0`) socket scanning.
   - **Pure-Rust YARA Pattern Engine**: Supports multi-pattern threshold conditions (`all of them`, `2 of them`), raw hex byte rules (`{ 18 a0 22 00 }`), and hot-reloading `.yar` files from `rules/`.
   - **SQLite $O(1)$ Threat Hash Database**: Indexed local `threat_hashes.db` with `PRAGMA quick_check` self-healing and empty/allowlisted hash filtering.
   - **Microsecond In-Memory LRU Verdict Cache**: Caches verified verdicts keyed by device, inode/creation ticks, mtime, and size to eliminate redundant disk I/O.
   - **PE/ELF & Masquerade Heuristics**: Detects tampered UPX headers (`UPX0`/`UPX1` without `UPX!`), PE process-injection API triads, ELF `memfd_create`/`ptrace` stealth, disguised `MZ`/`\x7FELF` magic headers, and double extensions.

2. **Pre-Execution Blocking & Real-Time Shield ([`src-tauri/src/realtime_shield.rs`](src-tauri/src/realtime_shield.rs) & [`src-tauri/src/process_guard.rs`](src-tauri/src/process_guard.rs))**
   - **Windows Instant Thread Suspension**: Intercepts volatile execution paths (`Downloads`, `AppData\Local\Temp`, `Public`), immediately suspends all process threads via `NtSuspendProcess` (`ntdll.dll`), verifies image integrity, and either resumes (`NtResumeProcess`) or terminates + isolates.
   - **Linux Kernel Pre-Exec (`fanotify`) with Watchdog Safety**: Blocks untrusted binary execution using `FAN_OPEN_EXEC_PERM | FAN_CLOSE_WRITE` with self/child PID exclusion, trusted OS binary allowlisting (`/usr/bin`, `/bin`, `/usr/lib/systemd`), a 250 ms fail-open scan watchdog, async post-verdict quarantine, and automated fallback to user-space watcher.
   - **Active Ransomware Canary Decoys**: Arms hidden decoys (`.genesis-seek-canary/`), neutralizes suspect processes running from temp/download folders on trip, and restores decoys automatically.

3. **Cross-OS Kernel & Sysctl Audit / Hardening ([`src-tauri/src/kernel_defense.rs`](src-tauri/src/kernel_defense.rs))**
   - **Read-Only KSPP & Host Audit**: Live inspection of Linux KSPP sysctl settings (`net.mptcp.enabled`, `kernel.unprivileged_bpf_disabled`, `kernel.kptr_restrict`) and Windows `HideFileExt` state without mutating system settings until explicitly requested.
   - **1-Click Sysctl & Driver Hardening**: Applies Linux KSPP hardening (`/etc/sysctl.d/99-genesis-seek-mptcp.conf`) to reduce `CVE-2024-1086`, `CVE-2024-26923`, and `CVE-2023-4911` LPE exposure, or Windows `HideFileExt=0` & Vulnerable Driver Blocklist enforcement (`CVE-2024-43468`, `CVE-2024-21338`).

4. **Live Cloud Threat Intelligence, Optional VirusTotal v3 API & Network Guard ([`src-tauri/src/threat_intel_and_net.rs`](src-tauri/src/threat_intel_and_net.rs))**
   - **Zero-Telemetry Feeds**: Automated background sync with **Abuse.ch MalwareBazaar** (batch inserted into SQLite), **Abuse.ch URLhaus**, and **PhishStats**.
   - **Dynamic Browser Guard Rule Sync**: Compiles active malicious domains directly into Manifest V3 `DeclarativeNetRequest` rulesets.
   - **VirusTotal v3 Multi-Engine Cloud Lookup**: Optional zero-upload SHA-256 and domain reputation check across 70+ antivirus engines.
   - **Active TCP Socket Guard**: Inspects live sockets to flag reverse-shell ports (`4444`, `1337`), Stratum mining pools, and C2 beacons.

5. **ChaCha20-Poly1305 Encrypted Quarantine Vault ([`src-tauri/src/quarantine.rs`](src-tauri/src/quarantine.rs))**
   - Neutralizes malware payloads using **ChaCha20-Poly1305** authenticated encryption with a local 256-bit vault key into `.gvault` files.
   - Strips all execution bits (`chmod 000` / read-only ACLs), safely shreds original files, and supports 1-click **Restore** with automatic SHA-256 allowlisting or permanent shredding.

6. **Windows Native System Tray & 24/7 Background Persistence ([`src-tauri/src/tray_indicator.rs`](src-tauri/src/tray_indicator.rs))**
   - **System Tray Notification Icon**: Runs in the Windows taskbar notification area next to the clock with live tooltip (`Genesis Seek — 100% Protected (Real-Time Shield Active)`).
   - **Always-On Shield**: Closing the window with the **"X"** button or minimizing quietly hides the dashboard into the system tray while keeping all background protection active.
   - **Quick Actions Menu**: Right-click the tray icon to **Open Dashboard**, **Run Quick Scan**, or **Quit**.

7. **Dual Theme System ("🌙 Obsidian Night" & "☀️ Warm Cream Light")**
   - Seamless switching between themes with zero-flicker pre-paint memory.

---

## 📋 Changelog

### 🚀 What's New in v0.4.0 Enterprise (Mail Gateway, Stream Gateway, DNS Sinkhole & Zero-FP Installer Guard)
* **RFC 5322 Mail Gateway & Multi-Part MIME Unpacker (`scanner.rs`, `realtime_shield.rs`):**
  - Inspects `.eml`, `.msg`, `.oft`, and `.mbox` mail spools alongside a live HTTP Mail Gateway endpoint (`POST http://127.0.0.1:49152/gateway/scan-email`).
  - Parses headers (`From`, `Reply-To`, `Return-Path`, `Authentication-Results`) for display-name brand spoofing, cross-domain `Reply-To` phishing, and `spf=fail` / `dkim=fail` / `dmarc=fail` anomalies.
  - Recursively decodes `multipart/*` boundaries (`base64` & `quoted-printable`), inspects HTML body links for phishing/UNC/homograph URLs, and routes every attachment (`.zip`, `.tar.gz`, Office macros, PDFs, `.lnk`, executables) through the full 5-layer scanner.
* **ICAP-Style Local Stream & Proxy Gateway (`POST /gateway/scan-stream`):**
  - Scans raw byte streams in-memory (`127.0.0.1:49152/gateway/scan-stream`) for browser downloads, local proxies, and mail relays before files touch user folders.
* **OS Network & DNS Sinkhole Gateway + Outbound WAN SMB Relay Guard (`threat_intel_and_net.rs`):**
  - Optional OS-level `/etc/hosts` & `C:\Windows\System32\drivers\etc\hosts` DNS Sinkhole Gateway (`0.0.0.0`) protecting non-browser apps, mail clients, and CLI tools, with 1-click clean rollback.
  - Detects outbound port `445` (`SMB`) connections to public WAN IP addresses (`Exploit.Net.OutboundWanSmbRelay_CVE_2023_23397`) while allowing normal RFC 1918 LAN file shares.
* **Zero False-Positive Installer & MSI Guard (`scanner.rs`, `process_guard.rs`, `realtime_shield.rs`):**
  - Eliminated false-positive quarantines on Windows `.msi` packages (OLE2 Compound Documents), official software installers (`Firefox Installer.exe`, 7-Zip SFX `setup-stub.exe` / `7zS...` / `7zO...` temp folders), and in-progress browser downloads (`.crdownload`, `.part`, `.opdownload`).

### 🚀 What's New in v0.3.8 Enterprise (System Watcher Rollback, Memory Hollowing Guard, Deep Unpacking & XPI Fix)
* **System Watcher Pre-Encryption Shadow Journal & Automatic File Rollback (`realtime_shield.rs`):**
  - Maintains bounded pre-encryption snapshots of user documents and automatically rolls files back to their clean state if overwritten with high-entropy ransomware ciphertext ($H \ge 7.20$) or renamed to ransomware extensions (`.locked`, `.lockbit`, `.encrypted`, `.ryuk`, `.akira`, `.blackcat`, etc.) while terminating volatile-path offending processes.
* **Live Process Memory Hollowing & Reflective DLL Scanner (`process_guard.rs`):**
  - Scans private/anonymous executable memory pages (`VirtualQueryEx` + `ReadProcessMemory` on Windows; `/proc/<pid>/exe`, `/proc/<pid>/maps`, and `/proc/<pid>/mem` on Linux) for unbacked PE/ELF headers, MZ-stomped Cobalt Strike beacons, `ReflectiveLoader` exports, and Stephen Fewer x64 PEB-walk shellcode stubs without false-positiving on browser/JIT pages.
* **MS-SHLLINK (`.lnk`) Binary Parser, NTFS MotW (`:Zone.Identifier`) & Multi-Ancestor ASR (`scanner.rs`, `process_guard.rs`, `quarantine.rs`):**
  - Added structured MS-SHLLINK `.lnk` parsing (`LinkInfo` local & UNC share suffixes, PowerShell prefix-shortened `-e`/`-enc` detection, document-icon masquerading), NTFS `:Zone.Identifier` (`ZoneId=3/4`) script dropper inspection, 4-hop parent/ancestor Office & Linux PDF reader ASR rules, LSASS `MiniDump`/`SAM` credential-dumping guards, recursive `C:\Windows\System32\Tasks` XML auditing, and root-anchored OS binary & symlink quarantine safeguards.
* **Pure-Rust POSIX Firefox `.xpi` Builder & Profile Provisioning (`extension_installer.rs`, `realtime_shield.rs`):**
  - Added `build_valid_firefox_xpi_bytes()` generating standard PKZIP `.xpi` archives with POSIX `/` entry names and BOM-free `manifest.json`, served directly at `http://127.0.0.1:49152/genesis-seek-browser-guard.xpi` (`Content-Type: application/x-xpinstall`), with marker-scoped `user.js` management and isolated Chromium staging (`Genesis-Seek-Browser-Guard-Chromium`).
* **Recursive Multi-Layer Archive, PDF & Macro Unpacker (`scanner.rs`):**
  - Added bounded pure-Rust inspection of nested `.zip`/OpenXML containers (`ZipSlip` path traversal, `ZipBomb` ratio/size bounds, encrypted executable droppers, Office `vbaProject.bin`/OLE2 macro payloads), `.tar.gz`/`.tgz`/GZIP streams, PDF `FlateDecode` object streams (`/OpenAction`/`/AA` + `/JS`/`/Launch`), and Base64 + UTF-16LE obfuscated scripts.
  - Added 64 KB trailing overlay sampling on >2 MB files and deep PE/ELF heuristics (tampered UPX sections without `UPX!`, PE `VirtualAllocEx`/`WriteProcessMemory`/`CreateRemoteThread` triad, ELF `memfd_create`/`ptrace` stealth).
  - Upgraded pure-Rust YARA parser to support raw hex byte patterns (`{ 18 a0 22 00 }`), `all of them`, and `N of them` threshold conditions, plus 5 new Linux & Windows rules (`XorDDoS`/`Mirai`, `Kinsing`/`Sysrv`, `BPFDoor`, `Perfctl`, LSASS/`Mimikatz`) in `rules/default_enterprise.yar`.
  - Added optional local ClamAV `clamd` socket hook (`zINSTREAM\0` via Unix domain sockets & `127.0.0.1:3310` with 60s failure backoff) and SQLite `PRAGMA quick_check` corruption recovery with empty/invalid/allowlisted hash filtering.
* **Kernel Deadlock Safety, Canary Neutralization & Bridge Hardening (`realtime_shield.rs`, `process_guard.rs`):**
  - Added self/child PID exclusion, trusted OS binary allowlisting (`/usr/bin`, `/bin`, `/usr/lib/systemd`), a fail-open watchdog timeout, and non-blocking post-verdict async quarantine to Linux `fanotify` pre-exec handling.
  - Wired active termination & quarantine of volatile-path processes on Ransomware Canary trip, and added Windows Registry `Run`/`RunOnce` + Linux `/etc/ld.so.preload`, `/etc/crontab`, `.profile`, `.zshrc` persistence audits.
  - Hardened the `127.0.0.1:49152` Browser Guard bridge with a 16-worker concurrency cap, `Host:` DNS-rebinding validation, `Sec-Fetch-Site: cross-site` restrictions on `/sentinel-profile` & `/install-firefox`, a bounded `last_logged` domain map, and a 2048-character URL cap.
* **Threat-Intel Anti-Poisoning & Read-Only Kernel Audits (`threat_intel_and_net.rs`, `kernel_defense.rs`):**
  - Bounded `reqwest` feed downloads to `MAX_FEED_BYTES`, rejected HTML captive-portal responses, and enforced `PROTECTED_SAFE_DOMAINS` + strict DNS label validation across URLhaus/PhishStats parsers.
  - Made `audit_linux_kernel_mptcp()` strictly read-only on Windows and replaced unverified CVE labels with verified NVD/MITRE CVEs and Linux KSPP hardening descriptions.

### 🚀 What's New in v0.3.7 Enterprise (Browser Guard Security & Update Notifier)
* **Browser Guard Security Hardening:**
  - **DOM XSS Elimination (`content_guard.js`):** Replaced unsanitized `innerHTML` block banners with safe DOM node creation and strict text nodes.
  - **Bridge CORS & Endpoint Protection (`realtime_shield.rs`):** Restricted `/sentinel-profile` against cross-origin web requests from external sites; hardened loopback origin checks.
  - **Tab Memory Leak Fix (`background.js`):** Added `chrome.tabs.onRemoved` cleanup to prevent unbounded accumulation of closed tab verdicts in local storage.
  - **In-Page Alert Fallback:** Ensured the offline heuristic analyzer sends in-page block warning banners even when the desktop bridge is temporarily disconnected.
* **Update Notifier Feature:**
  - Added background extension update checker and popup UI notification banner alerting users immediately when a new browser extension version or app release is available.
  - Added toolbar badge notification (`NEW`) on update detection.
* **True Transparent Firefox & Chromium Extension Icons:**
  - Re-rendered pixel-perfect PNG icons (`16x16`, `32x32`, `48x48`, `128x128`) from vector SVG masters.
  - Completely eliminated the opaque black square bounding box in Firefox toolbar and add-on manager views.
* **Synchronized Package Releases:**
  - Regenerated `genesis-seek-browser-guard-firefox.zip` and updated release asset manifests for v0.3.7.
* **Outlook Unsafe Action & NTLM Leak Detection (`CVE-2023-23397` / `CVE-2024-21413`):** Added [`Genesis_Outlook_UnsafeAction_NTLM_Spoof_CVE_2023_23397`](rules/cve_sentinel_heuristics.yar) to the bundled YARA heuristics, expanded `scanner.rs` content inspection to `.msg`, `.eml`, `.oft`, and `.rtf` files, and updated `sentinel_profile.json` (`SIG-WIN-OUTLOOK-02`) to close the Windows Active KEV gap.

### 🚀 What's New in v0.3.5 Enterprise (Cross-OS Kernel & Host Hardening + KSPP LPE Shield)
* **Linux Kernel LPE & Info-Leak Sysctl Hardening:** Expanded `kernel_defense.rs` to lock down `kernel.unprivileged_bpf_disabled=1`, `kernel.kptr_restrict=2`, `kernel.dmesg_restrict=1`, and `kernel.yama.ptrace_scope=1` alongside `net.mptcp.enabled=0`, reinforcing KSPP protections against `CVE-2024-1086`, `CVE-2024-26923`, and eBPF attack vectors.
* **Windows Host & Driver Blocklist Hardening:** Supports `HideFileExt=0` hardening in Windows Explorer (`CVE-2024-43468` disguised extension mitigation) and enables the Windows Vulnerable Driver Blocklist (`VulnerableDriverBlocklistEnable=1` for `CVE-2024-21338` BYOVD defense).
* **Live Sentinel Bridge (`/sentinel-profile`):** Added `/sentinel-profile` to the local loopback bridge (`127.0.0.1:49152`) and published `sentinel_profile.json` for real-time 100% protection health verification.

### What's New in v0.3.4 Enterprise (CVE Sentinel Hardening & 100% Protection)
* **Vulnerability & Patch Gap Hardening:** Integrated CVE Sentinel heuristics and defenses directly into the Genesis-Seek core engine:
  - **Unicode Right-to-Left Override (`RLO`) Masquerade Blocker (`CVE-2024-43468`):** Detects deceptive `\u202E`, braille whitespace padding, and hidden `.hta`/executable extensions.
  - **NTLM Relay Shortcut & Theme Inspector (`CVE-2024-43451`):** Inspects `.url` and `.theme` files to block spontaneous SMB/WebDAV credential leakage.
  - **BYOVD Blinding & IOCTL Defense (`CVE-2024-21338`):** Flags payloads attempting to exploit `appid.sys` to disable AV kernel callbacks.
  - **Linux Kernel `nf_tables` & Memory Corruption Rules (`CVE-2024-1086`, `CVE-2024-26923`):** Proactively blocks compiled exploit binaries attempting root privilege escalation via user namespaces.
  - **Network RCE Heuristic Signatures:** Added PoC detection for Windows TCP/IP IPv6 underflow (`CVE-2024-38063`), Wi-Fi beacon attacks (`CVE-2024-30078`), and OpenSSH `regreSSHion` (`CVE-2024-6387`).

### What's New in v0.3.3 Enterprise (Kernel MPTCP & KSPP Shield Release)
* **Linux Kernel MPTCP & KSPP Sysctl Shield:** Real-time inspection and 1-click KSPP hardening for the Linux Multipath TCP subsystem (`net.mptcp.enabled = 0`) with persistent `/etc/sysctl.d/99-genesis-seek-mptcp.conf` deployment.
* **Kernel Advisory Dashboard Banner:** Proactively alerts Linux users if their kernel networking stack is exposed, with direct links to audit and harden the host.
* **Desktop Launcher & Icon Hotfix:** Resolved desktop entry launcher branding to guarantee official 512×512 branding (`genesis-seek.png`) and updated enterprise tagline across all Linux environments.

### What's New in v0.3.2 Enterprise
* **Interactive Threat Alert UI:** Replaced aggressive popups with a sleek, non-repulsive dark/cream decision window allowing users to instantly **Allow & Trust** or **Quarantine Threat**.
* **Multi-Drive Protection:** Auto-discovers and recursively monitors secondary and external drives (`D:\`, `E:\`, `I:\` on Windows; `/media`, `/run/media`, `/mnt` on Linux).
* **Game Repack & Crack Heuristics:** Added non-destructive classification for FitGirl, DODI, EMPRESS, and Goldberg Steam emulators (`rules/riskware_and_repack.yar`).
* **Linux Boot Daemon Persistence:** Auto-configures both systemd user service (`genesis-seek.service`) and XDG autostart (`genesis-seek.desktop`) with `--minimized` boot and `SIGHUP` immunity.
* **Windows Autostart Integration:** Automatically registers persistence into Windows Startup folder with background tray minimization.

### What's New in v0.3.0 Enterprise
* **Engine:** Upgraded pure-Rust YARA signature engine and in-memory LRU verdict cache for microsecond binary re-checks.
* **Pre-Execution Defense:** Added low-level thread suspension on Windows (`NtSuspendProcess`) and kernel `fanotify` on Linux.
* **Vault:** Added 256-bit ChaCha20-Poly1305 authenticated encryption for all quarantined threats (`.gvault`).
* **Threat Intel:** Integrated zero-telemetry community feeds (MalwareBazaar, URLhaus, PhishStats) with dynamic browser rule sync.
* **Taskbar Tray:** Added native Windows system tray icon and window close interception to keep real-time shields running 24/7.
* **Browser Guard:** Created dedicated Manifest V3 builds for Microsoft Edge / Google Chrome (`service_worker`) and Mozilla Firefox (`scripts` + Gecko ID).
* **Branding:** Added Genesis Seek Enterprise v0.3.0 version indicators and Genesis Grid Labs copyright notices.

---

## 🚀 Building & Testing

### Run Tests
```bash
cd src-tauri
cargo test
```

### Build Optimized Native Binary
```bash
cd src-tauri
cargo build --release
```
The compiled binary will be located at `src-tauri/target/release/genesis-seek` (or `genesis-seek.exe` on Windows).

---

## 📄 License & Copyright

© 2026 **Genesis Grid Labs**. All rights reserved. Free, Secure, Plug-and-Play Local AI & Security Grid.
Visit: [genesisgridlabs.xyz](https://genesisgridlabs.xyz)
