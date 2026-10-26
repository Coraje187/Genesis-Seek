# 🛡️ Genesis Seek — Lightweight Cross-Platform Anti-Malware, Real-Time Shield & Browser Guard

<p align="center">
  <img src="ui/assets/logo-emblem-night.jpg" alt="Genesis Seek Obsidian Night Emblem" width="220" />
  <img src="ui/assets/logo-emblem-cream.jpg" alt="Genesis Seek Warm Cream Emblem" width="220" />
</p>

**Genesis Seek** is an ultra-lightweight (~14 MB RAM footprint), enterprise-grade endpoint & browser security suite engineered in **Rust + Tauri v2** for **Windows and Linux**, paired with a real-time **Manifest V3 Browser Guard Extension**.

---

## 📥 Downloads & Installation (v0.3.1 Enterprise)

### 🪟 Windows (10 / 11)
* **Standalone Binary**: [**genesis-seek.exe**](https://github.com/Coraje187/Genesis-Seek/releases/download/v0.3.1/genesis-seek.exe) *(Includes native system tray indicator and background persistence)*
* **Portable Archive**: [**genesis-seek-v0.3.1-windows-x86_64.zip**](https://github.com/Coraje187/Genesis-Seek/releases/download/v0.3.1/genesis-seek-v0.3.1-windows-x86_64.zip)

### 🐧 Linux (Arch / CachyOS, Ubuntu, Debian, Fedora)
* **One-Line Automatic Terminal Installer**:
  ```bash
  curl -sSL https://raw.githubusercontent.com/Coraje187/Genesis-Seek/main/install.sh | bash
  ```
* **Standalone AppImage**: [**Genesis-Seek-0.3.1-x86_64.AppImage**](https://github.com/Coraje187/Genesis-Seek/releases/download/v0.3.1/Genesis-Seek-0.3.1-x86_64.AppImage)
* **Linux Archive**: [**genesis-seek-v0.3.1-linux-x86_64.tar.gz**](https://github.com/Coraje187/Genesis-Seek/releases/download/v0.3.1/genesis-seek-v0.3.1-linux-x86_64.tar.gz)

### 🌐 Browser Guard Extensions

| Browser | Package / Link | Installation Guide |
| :--- | :--- | :--- |
| **Microsoft Edge, Chrome & Brave** | [**`Genesis-Seek-Browser-Guard-for-Chrome-and-Edge-v0.3.1.zip`**](https://github.com/Coraje187/Genesis-Seek/releases/download/v0.3.1/Genesis-Seek-Browser-Guard-for-Chrome-and-Edge-v0.3.1.zip) | Extract zip, navigate to `edge://extensions` or `chrome://extensions`, enable **Developer mode**, and click **"Load unpacked"**. |
| **Mozilla Firefox** | [**`Genesis-Seek-Browser-Guard-for-Firefox-v0.3.1.xpi`**](https://github.com/Coraje187/Genesis-Seek/releases/download/v0.3.1/Genesis-Seek-Browser-Guard-for-Firefox-v0.3.1.xpi) | Drag and drop the `.xpi` into Firefox, or load via `about:debugging#/runtime/this-firefox`. |
| **Mozilla Add-ons (AMO)** | [**Official Firefox AMO Store**](https://addons.mozilla.org/en-US/firefox/addon/genesis-seek-browser-guard/) | 1-Click official store installation and auto-updates. |

---

## ✨ Core Enterprise Protection Layers (v0.3.1)

1. **Multi-Engine File & Directory Scanner ([`src-tauri/src/scanner.rs`](src-tauri/src/scanner.rs))**
   - **YARA-X & Pure-Rust Pattern Engine**: Loads custom and community `.yar` rules from `rules/` with dynamic hot-reloading at runtime.
   - **SQLite $O(1)$ Threat Hash Database**: Indexed local database `threat_hashes.db` for instant offline hash lookups without API rate limits.
   - **Microsecond In-Memory LRU Verdict Cache**: Caches verified clean files keyed by device, inode, mtime, and size to eliminate redundant disk I/O.
   - **Heuristic & Header Analysis**: Detects disguised executable magic headers (`MZ` / `\x7FELF` disguised as images or office docs), double extensions (`invoice.pdf.exe`), and packed payloads.

2. **Pre-Execution Blocking & Real-Time Shield ([`src-tauri/src/realtime_shield.rs`](src-tauri/src/realtime_shield.rs) & [`src-tauri/src/process_guard.rs`](src-tauri/src/process_guard.rs))**
   - **Windows Instant Thread Suspension**: Intercepts volatile execution paths (`Downloads`, `AppData\Local\Temp`, `Public`), immediately suspends all process threads via `NtSuspendProcess` (`ntdll.dll`), verifies image integrity, and either resumes (`NtResumeProcess`) or terminates + isolates.
   - **Linux Kernel Pre-Exec (`fanotify`)**: Blocks untrusted binary execution at instruction zero using `FAN_OPEN_EXEC_PERM | FAN_CLOSE_WRITE`, with automated fallback to unprivileged user-space watcher if root capabilities are absent.
   - **Ransomware Canary Decoy Tripwires**: Arms hidden decoy documents (`.genesis-seek-canary/`) and triggers instant Critical mitigation if tampering is detected.

3. **Live Cloud Threat Intelligence, Optional VirusTotal v3 API & Network Guard ([`src-tauri/src/threat_intel_and_net.rs`](src-tauri/src/threat_intel_and_net.rs))**
   - **Zero-Telemetry Feeds**: Automated background sync with **Abuse.ch MalwareBazaar** (batch inserted into SQLite), **Abuse.ch URLhaus**, and **PhishStats**.
   - **Dynamic Browser Guard Rule Sync**: Compiles active malicious domains directly into Manifest V3 `DeclarativeNetRequest` rulesets.
   - **VirusTotal v3 Multi-Engine Cloud Lookup**: Optional zero-upload SHA-256 and domain reputation check across 70+ antivirus engines.
   - **Active TCP Socket Guard**: Inspects live sockets to flag reverse-shell ports (`4444`, `1337`), Stratum mining pools, and C2 beacons.

4. **ChaCha20-Poly1305 Encrypted Quarantine Vault ([`src-tauri/src/quarantine.rs`](src-tauri/src/quarantine.rs))**
   - Neutralizes malware payloads using **ChaCha20-Poly1305** authenticated encryption with a local 256-bit vault key into `.gvault` files.
   - Strips all execution bits (`chmod 000` / read-only ACLs), safely shreds original files, and supports 1-click **Restore** with automatic SHA-256 allowlisting or permanent shredding.

5. **Windows Native System Tray & 24/7 Background Persistence ([`src-tauri/src/tray_indicator.rs`](src-tauri/src/tray_indicator.rs))**
   - **System Tray Notification Icon**: Runs in the Windows taskbar notification area next to the clock with live tooltip (`Genesis Seek — 100% Protected (Real-Time Shield Active)`).
   - **Always-On Shield**: Closing the window with the **"X"** button or minimizing quietly hides the dashboard into the system tray while keeping all background protection active.
   - **Quick Actions Menu**: Right-click the tray icon to **Open Dashboard**, **Run Quick Scan**, or **Quit**.

6. **Dual Theme System ("🌙 Obsidian Night" & "☀️ Warm Cream Light")**
   - Seamless switching between themes with zero-flicker pre-paint memory.

---

## 📋 Changelog

### 🚀 What's New in v0.3.1 Enterprise
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
