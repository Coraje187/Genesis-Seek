# 🛡️ Genesis Seek — Lightweight Cross-Platform Anti-Malware, Real-Time Shield & Browser Guard

<p align="center">
  <img src="ui/assets/logo-emblem-night.jpg" alt="Genesis Seek Obsidian Night Emblem" width="220" />
  <img src="ui/assets/logo-emblem-cream.jpg" alt="Genesis Seek Warm Cream Emblem" width="220" />
</p>

**Genesis Seek** is an ultra-lightweight (~14 MB RAM footprint), Malwarebytes-inspired enterprise-tier endpoint & browser security suite engineered in **Rust + Tauri v2** for **Windows and Linux**, paired with a real-time **Manifest V3 Browser Guard Extension**.

---

## 📥 Downloads & Quick Installation (v0.3.0)

### 🪟 Windows (10 / 11)
* **Standalone Binary**: [**genesis-seek.exe**](https://github.com/Coraje187/Genesis-Seek/releases/download/v0.3.0/genesis-seek.exe)
* **Portable Archive**: [**genesis-seek-v0.3.0-windows-x86_64.zip**](https://github.com/Coraje187/Genesis-Seek/releases/download/v0.3.0/genesis-seek-v0.3.0-windows-x86_64.zip)

### 🐧 Linux (Arch / CachyOS, Ubuntu, Debian, Fedora)
* **One-Line Automatic Installer**:
  ```bash
  curl -sSL https://raw.githubusercontent.com/Coraje187/Genesis-Seek/main/install.sh | bash
  ```
* **Standalone AppImage**: [**Genesis-Seek-0.3.0-x86_64.AppImage**](https://github.com/Coraje187/Genesis-Seek/releases/download/v0.3.0/Genesis-Seek-0.3.0-x86_64.AppImage)
* **Linux Archive**: [**genesis-seek-v0.3.0-linux-x86_64.tar.gz**](https://github.com/Coraje187/Genesis-Seek/releases/download/v0.3.0/genesis-seek-v0.3.0-linux-x86_64.tar.gz)

### 🌐 Browser Guard (Mozilla Firefox)
* **Official Signed Add-on**: [**Add to Firefox (Mozilla AMO)**](https://addons.mozilla.org/en-US/firefox/addon/genesis-seek-browser-guard/) *(1-Click Permanent Install)*

---

## ✨ Core Enterprise Protection Layers (v0.3.0)

1. **Multi-Engine File & Directory Scanner ([`src-tauri/src/scanner.rs`](src-tauri/src/scanner.rs))**
   - **YARA-X & Pure-Rust Pattern Engine**: Loads custom and community `.yar` rules from `rules/` with dynamic hot-reloading at runtime.
   - **SQLite $O(1)$ Threat Hash Database**: Indexed local database `threat_hashes.db` for instant offline hash lookups without API rate limits.
   - **Microsecond In-Memory LRU Verdict Cache**: Caches verified clean files keyed by device, inode, mtime, and size to eliminate redundant disk I/O.
   - **Heuristic & Header Analysis**: Detects disguised executable magic headers (`MZ` / `\x7FELF` disguised as images or office docs), double extensions (`invoice.pdf.exe`), and packed payloads.

2. **Pre-Execution Blocking & Real-Time Shield ([`src-tauri/src/realtime_shield.rs`](src-tauri/src/realtime_shield.rs) & [`src-tauri/src/process_guard.rs`](src-tauri/src/process_guard.rs))**
   - **Linux Kernel Pre-Exec (`fanotify`)**: Blocks untrusted binary execution at instruction zero using `FAN_OPEN_EXEC_PERM | FAN_CLOSE_WRITE`, with automated fallback to unprivileged user-space watcher if root capabilities are absent.
   - **Windows Instant Thread Suspension**: Intercepts volatile execution paths (`Downloads`, `AppData\Local\Temp`, `Public`), immediately suspends all process threads via `NtSuspendProcess` (`ntdll.dll`), verifies image integrity, and either resumes (`NtResumeProcess`) or terminates + isolates.
   - **Ransomware Canary Decoy Tripwires**: Arms hidden decoy documents (`.genesis-seek-canary/`) and triggers instant Critical mitigation if tampering is detected.

3. **Live Cloud Threat Intelligence, Optional VirusTotal v3 API & Network Guard ([`src-tauri/src/threat_intel_and_net.rs`](src-tauri/src/threat_intel_and_net.rs))**
   - **Zero-Telemetry Feeds**: Automated background sync with **Abuse.ch MalwareBazaar** (batch inserted into SQLite), **Abuse.ch URLhaus**, and **PhishStats**.
   - **Dynamic Browser Guard Rule Sync**: Compiles active malicious domains directly into Manifest V3 `DeclarativeNetRequest` rulesets.
   - **VirusTotal v3 Multi-Engine Cloud Lookup**: Optional zero-upload SHA-256 and domain reputation check across 70+ antivirus engines.
   - **Active TCP Socket Guard**: Inspects live sockets to flag reverse-shell ports (`4444`, `1337`), Stratum mining pools, and C2 beacons.

4. **ChaCha20-Poly1305 Encrypted Quarantine Vault ([`src-tauri/src/quarantine.rs`](src-tauri/src/quarantine.rs))**
   - Neutralizes malware payloads using **ChaCha20-Poly1305** authenticated encryption with a local 256-bit vault key into `.gvault` files.
   - Strips all execution bits, safely shreds original files, and supports 1-click **Restore** with automatic SHA-256 allowlisting or permanent shredding.

5. **Genesis Seek Browser Guard ([`browser-extension/`](browser-extension/))**
   - **Mozilla Firefox**: Live on [Mozilla Add-ons (AMO)](https://addons.mozilla.org/en-US/firefox/addon/genesis-seek-browser-guard/).
   - Real-time protection against cryptojackers, phishing domains, and drive-by malware.

6. **Dual Theme System ("🌙 Obsidian Night" & "☀️ Warm Cream Light")**
   - Seamless switching between themes with zero-flicker pre-paint memory.

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
