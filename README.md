# 🛡️ Genesis Seek — Lightweight Cross-Platform Anti-Malware, Real-Time Shield & Browser Guard

<p align="center">
  <img src="ui/assets/logo-emblem-night.jpg" alt="Genesis Seek Obsidian Night Emblem" width="220" />
  <img src="ui/assets/logo-emblem-cream.jpg" alt="Genesis Seek Warm Cream Emblem" width="220" />
</p>

**Genesis Seek** is an ultra-lightweight (~14 MB RAM footprint), Malwarebytes-inspired endpoint & browser security suite engineered in **Rust + Tauri v2** for **Windows and Linux**, paired with a real-time **Manifest V3 Browser Guard Extension**.

---

## 📥 Downloads & Quick Installation (v0.2.0)

### 🪟 Windows (10 / 11)
* **Standalone Binary**: [**genesis-seek.exe**](https://github.com/Coraje187/Genesis-Seek/releases/download/v0.2.0/genesis-seek.exe)
* **Portable Archive**: [**genesis-seek-v0.2.0-windows-x86_64.zip**](https://github.com/Coraje187/Genesis-Seek/releases/download/v0.2.0/genesis-seek-v0.2.0-windows-x86_64.zip)

### 🐧 Linux (Arch / CachyOS, Ubuntu, Debian, Fedora)
* **One-Line Automatic Installer**:
  ```bash
  curl -sSL https://raw.githubusercontent.com/Coraje187/Genesis-Seek/main/install.sh | bash
  ```
* **Standalone AppImage**: [**Genesis-Seek-0.2.0-x86_64.AppImage**](https://github.com/Coraje187/Genesis-Seek/releases/download/v0.2.0/Genesis-Seek-0.2.0-x86_64.AppImage)
* **Linux Archive**: [**genesis-seek-v0.2.0-linux-x86_64.tar.gz**](https://github.com/Coraje187/Genesis-Seek/releases/download/v0.2.0/genesis-seek-v0.2.0-linux-x86_64.tar.gz)

### 🌐 Browser Guard (Mozilla Firefox)
* **Official Signed Add-on**: [**Add to Firefox (Mozilla AMO)**](https://addons.mozilla.org/en-US/firefox/addon/genesis-seek-browser-guard/) *(1-Click Permanent Install)*

---

## ✨ Core Protection Layers

1. **Multi-Engine File & Directory Scanner ([`src-tauri/src/scanner.rs`](src-tauri/src/scanner.rs))**
   - **SHA-256 Cryptographic Signatures**: Full-file streaming SHA-256 hash lookup against built-in signatures, live downloaded **Abuse.ch MalwareBazaar** feeds, and the standard EICAR test signature.
   - **Behavioral Heuristics**: Detects reverse shell pipes (`/dev/tcp/`, `nc -e`, `Invoke-PowerShellTcp`), obfuscated PowerShell droppers (`-EncodedCommand`, `FromBase64String`), ransomware shadow-copy deletion (`vssadmin delete shadows`, `wbadmin`), cryptominers (`stratum+tcp://`, `xmrig`), Linux `LD_PRELOAD` rootkits, and browser credential stealers.
   - **Double-Extension Masquerade Detection**: Flags deceptive filenames like `invoice.pdf.exe` or `photo.jpg.scr`.
   - **Shannon Entropy & Packer Analysis**: Computes byte entropy ($0.0 - 8.0\text{ bits/byte}$) on Windows PE (`MZ`) and Linux `ELF` binaries to flag encrypted/packed binaries.

2. **Real-Time File System, Ransomware Canary & Process Shield ([`src-tauri/src/realtime_shield.rs`](src-tauri/src/realtime_shield.rs))**
   - **Real-Time File Watcher**: Uses OS-native file events (`inotify` on Linux, `ReadDirectoryChangesW` on Windows) to monitor `Downloads`, `Desktop`, and `Temp` directories and automatically isolate High/Critical threats.
   - **Ransomware Canary Decoy Tripwires**: Arms hidden decoy files (`.genesis-seek-canary/`) and raises an immediate Critical alert if an unauthorized process modifies or encrypts them.
   - **Background Process Monitor**: Continuously audits running processes for volatile memory execution (`/dev/shm`, `/tmp`, `AppData\Local\Temp`) and masquerading system binaries.

3. **Live Cloud Threat Intelligence, Optional VirusTotal v3 API & Network Socket Inspector ([`src-tauri/src/threat_intel_and_net.rs`](src-tauri/src/threat_intel_and_net.rs))**
   - **Live Abuse.ch Threat Feeds**: Downloads and caches real-time malicious hostnames from **Abuse.ch URLhaus** and recent malware SHA-256 hashes from **Abuse.ch MalwareBazaar**.
   - **Optional VirusTotal v3 Multi-Engine Cloud Lookup (Windows & Linux)**: Supports an optional VirusTotal API key (saved locally in `~/.config/genesis-seek/vt_config.json` with `0600` permissions on Linux or `%APPDATA%\genesis-seek\vt_config.json` on Windows, or via `VIRUSTOTAL_API_KEY`) to check SHA-256 file hashes and domains across 70+ antivirus engines without uploading file contents.
   - **Active TCP Socket Guard**: Inspects `/proc/net/tcp` on Linux and `netstat -ano` on Windows to flag C2 ports (`4444`, `1337`, `31337`), Stratum mining pools (`3333`, `14444`), IRC botnets (`6667`), and Tor relays (`9050`).

4. **Quarantine Vault with False-Positive Allowlisting ([`src-tauri/src/quarantine.rs`](src-tauri/src/quarantine.rs))**
   - Neutralizes suspicious files via XOR payload obfuscation, strips execution permissions (`0600`), stores them as `.gsvault` blobs, and supports one-click **Restore** (with automatic SHA-256 allowlisting so restored files aren't re-quarantined) or **Zero-Fill Shred**.

5. **Genesis Seek Browser Guard + One-Click Installer ([`browser-extension/`](browser-extension/) & [`src-tauri/src/extension_installer.rs`](src-tauri/src/extension_installer.rs))**
   - **Mozilla Firefox**: ✅ **Official Signed Add-on Live on [Mozilla Add-ons (AMO)](https://addons.mozilla.org/en-US/firefox/addon/genesis-seek-browser-guard/)**
   - **Microsoft Edge & Google Chrome**: Cross-platform Manifest V3 architecture ready.
   - Blocks cryptojackers (`coinhive`, `crypto-loot`) and phishing hosts via `declarativeNetRequest` ([`rules.json`](browser-extension/rules.json)).
   - Detects **IDN Homograph (Punycode `xn--`)** attacks, deceptive `.zip`/`.mov` brand spoofing, raw-IP executable downloads, and unencrypted HTTP password forms.
   - Includes a **1-Click Browser Extension Installer & Reminder Banner** directly inside the desktop dashboard that automatically links to the live Mozilla Add-on.

6. **Dual Theme System with Persistent Memory ("🌙 Obsidian Night" & "☀️ Warm Cream Light")**
   - Switch seamlessly between **Obsidian Night** and **Warm Cream Light** in both the Desktop UI and Browser Guard extension. Your preference is saved both in `localStorage` (pre-paint zero-flicker loader) and on disk (`~/.config/genesis-seek/user_preferences.json`).

---

## 🚀 Building & Installing

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
The compiled binary will be located at `src-tauri/target/release/genesis-seek`.
