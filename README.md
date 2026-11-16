# 🛡️ Genesis Seek — Cross-Platform Endpoint Scanner, Real-Time Guard & Browser Extension

<p align="center">
  <img src="ui/assets/logo-emblem-night.jpg" alt="Genesis Seek Obsidian Night Emblem" width="200" />
  <img src="ui/assets/logo-emblem-cream.jpg" alt="Genesis Seek Warm Cream Emblem" width="200" />
</p>

**Genesis Seek (`v0.4.1`)** is a lightweight (~14–34 MB RAM), open-source endpoint and browser security companion built in **Rust + Tauri v2** for **Windows and Linux**, paired with a **Manifest V3 Browser Guard Extension**.

It is designed for users and developers who want transparent, local-first file & archive inspection, YARA rule matching, MalwareBazaar/URLhaus/PhishStats threat feed syncing, pre-encryption file shadow journaling, and browser phishing/homograph filtering without cloud telemetry.

📄 [**Full Changelog (`CHANGELOG.md`)**](CHANGELOG.md) • 🧪 [**Reproducible Test Results (`TEST_RESULTS.md`)**](TEST_RESULTS.md) • 🔒 [**Security Policy (`SECURITY.md`)**](SECURITY.md) • ⚖️ [**MIT License (`LICENSE`)**](LICENSE)

---

## 📥 Downloads & Installation (`v0.4.1`)

### 🪟 Windows (10 / 11 x64)
* **NSIS Setup Installer**: [**`Genesis.Seek_0.4.1_x64-setup.exe`**](https://github.com/Coraje187/Genesis-Seek/releases/download/v0.4.1/Genesis.Seek_0.4.1_x64-setup.exe)
* **MSI Package**: [**`Genesis.Seek_0.4.1_x64_en-US.msi`**](https://github.com/Coraje187/Genesis-Seek/releases/download/v0.4.1/Genesis.Seek_0.4.1_x64_en-US.msi)
* **Standalone Binary**: [**`genesis-seek.exe`**](https://github.com/Coraje187/Genesis-Seek/releases/download/v0.4.1/genesis-seek.exe)
* **Portable Archive**: [**`genesis-seek-v0.4.1-windows-x86_64.zip`**](https://github.com/Coraje187/Genesis-Seek/releases/download/v0.4.1/genesis-seek-v0.4.1-windows-x86_64.zip)

### 🐧 Linux (Ubuntu, Debian, Arch / CachyOS, Fedora x86_64)
* **Standalone AppImage**: [**`Genesis-Seek-0.4.1-x86_64.AppImage`**](https://github.com/Coraje187/Genesis-Seek/releases/download/v0.4.1/Genesis-Seek-0.4.1-x86_64.AppImage)
* **Debian / Ubuntu Package**: [**`Genesis.Seek_0.4.1_amd64.deb`**](https://github.com/Coraje187/Genesis-Seek/releases/download/v0.4.1/Genesis.Seek_0.4.1_amd64.deb)
* **Portable Tarball**: [**`genesis-seek-v0.4.1-linux-x86_64.tar.gz`**](https://github.com/Coraje187/Genesis-Seek/releases/download/v0.4.1/genesis-seek-v0.4.1-linux-x86_64.tar.gz)
* **Installer Script (Inspect First, Then Run)**:
  ```bash
  curl -sSLO https://raw.githubusercontent.com/Coraje187/Genesis-Seek/main/install.sh
  less install.sh   # Review the script before executing
  bash install.sh
  ```

### 🔐 Verifying Release Checksums (`SHA256SUMS.txt`)
Every GitHub Release publishes [`SHA256SUMS.txt`](https://github.com/Coraje187/Genesis-Seek/releases/download/v0.4.1/SHA256SUMS.txt). Verify your download before running:
```bash
# Linux
sha256sum -c SHA256SUMS.txt --ignore-missing

# Windows PowerShell
Get-FileHash .\genesis-seek.exe -Algorithm SHA256
```

### 🌐 Browser Guard Extensions (Manifest V3)

| Browser | Package / Link | Installation |
| :--- | :--- | :--- |
| **Mozilla Firefox (Official Store)** | [**Mozilla Add-ons (AMO)**](https://addons.mozilla.org/en-US/firefox/addon/genesis-seek-browser-guard/) | 1-Click signed installation and automatic updates. |
| **Mozilla Firefox (`.xpi` / Source)** | [**`Genesis-Seek-Browser-Guard-for-Firefox-v0.4.1.xpi`**](https://github.com/Coraje187/Genesis-Seek/releases/download/v0.4.1/Genesis-Seek-Browser-Guard-for-Firefox-v0.4.1.xpi) | Load via `about:debugging#/runtime/this-firefox` (or direct `.xpi` install on Firefox Developer/Nightly/ESR). |
| **Chrome, Edge & Brave** | [**`Genesis-Seek-Browser-Guard-for-Chrome-and-Edge-v0.4.1.zip`**](https://github.com/Coraje187/Genesis-Seek/releases/download/v0.4.1/Genesis-Seek-Browser-Guard-for-Chrome-and-Edge-v0.4.1.zip) | Extract zip, open `chrome://extensions` or `edge://extensions`, enable **Developer mode**, and click **"Load unpacked"**. |

---

## ✨ What Genesis Seek Covers

1. **Multi-Layer File, Archive & Container Scanner ([`src-tauri/src/scanner.rs`](src-tauri/src/scanner.rs))**
   - **Signature & Feed Matching**: Local indexed SQLite database (`threat_hashes.db`) synced with **Abuse.ch MalwareBazaar** SHA-256 hashes, **Abuse.ch URLhaus**, and **PhishStats**, plus optional zero-upload **VirusTotal v3** hash lookups and optional local **ClamAV `clamd`** (`zINSTREAM\0`) socket integration.
   - **Pure-Rust YARA Engine**: Evaluates custom `.yar` rules from [`rules/`](rules/default_enterprise.yar) with support for string literals, raw hex byte patterns (`{ 18 a0 22 00 }`), `any of them`, `all of them`, and `N of them` threshold conditions.
   - **Bounded Container Unpacking**: Recursively inspects nested `.zip`/OOXML archives (`ZipSlip` traversal & `ZipBomb` ratio caps, Office `vbaProject.bin`/OLE2 macro streams), `.tar.gz`/GZIP archives, PDF `FlateDecode` streams (`/OpenAction`/`/JS`/`/Launch`), Base64/UTF-16LE stagers, MS-SHLLINK `.lnk` shortcuts, and NTFS `:Zone.Identifier` (`ZoneId=3/4`) script droppers.
   - **Installer & MSI Allowlisting**: Recognizes OLE2 Windows Installer `.msi`/`.msp` packages, 7-Zip SFX installer stubs (`Temp\7z...\setup-stub.exe`), and partial browser downloads (`.crdownload`, `.part`) to avoid false-positive interruptions during software setup.

2. **Real-Time Watcher, Pre-Execution Guard & Ransomware Rollback ([`src-tauri/src/realtime_shield.rs`](src-tauri/src/realtime_shield.rs) & [`src-tauri/src/process_guard.rs`](src-tauri/src/process_guard.rs))**
   - **Volatile Path Monitoring**: Watches `Downloads`, `Desktop`, and `Temp` (`/tmp`, `/dev/shm`) for newly dropped executables and scripts.
   - **Process & Memory Inspection**: Suspends suspicious volatile-path processes on Windows (`NtSuspendProcess`), supports opt-in Linux `fanotify` pre-exec interception with a 250 ms fail-open watchdog, checks 4-hop Office/PDF-reader → shell parent chains, and scans private/anonymous executable memory for unbacked PE/ELF headers.
   - **Pre-Encryption Shadow Journal & Rollback**: Keeps bounded in-memory snapshots (up to 4 MB per file, 64 MB total) of user documents in monitored folders and restores clean bytes if a file is overwritten with high-entropy ciphertext ($H \ge 7.20$) or renamed to known ransomware extensions (`.locked`, `.lockbit`, `.encrypted`, `.ryuk`, `.akira`).

3. **Opt-In Mail, Stream & OS DNS Sinkhole Gateways ([`src-tauri/src/threat_intel_and_net.rs`](src-tauri/src/threat_intel_and_net.rs))**
   - **RFC 5322 Mail Inspector**: Scans `.eml`, `.msg`, `.oft`, and `.mbox` files for `SPF`/`DKIM`/`DMARC` failures, display-name spoofing, Quoted-Printable HTML smuggling, and malicious MIME attachments.
   - **Opt-In Local HTTP Gateway (`127.0.0.1:49152/gateway/*`)**: Disabled by default to minimize attack surface; when enabled in **Network & Threat Feeds**, local mail relays and proxies can `POST` raw messages or streams with the `X-Genesis-Seek-Client` header.
   - **Opt-In OS DNS Sinkhole & Socket Inspector**: Optional block-scoped `0.0.0.0` hosts sinkhole and live TCP socket monitoring (including outbound WAN SMB port `445` NTLM relay detection for `CVE-2023-23397`).

4. **ChaCha20-Poly1305 Quarantine Vault ([`src-tauri/src/quarantine.rs`](src-tauri/src/quarantine.rs))**
   - Encrypts isolated files into `.gvault` containers using a local 256-bit ChaCha20-Poly1305 key, strips execution permissions, blocks quarantining root-anchored OS binaries (`C:\Windows\System32`, `/usr/bin`), and supports 1-click **Restore + Allowlist**.

---

## ⚠️ Scope, Architecture & Known Limitations

Genesis Seek is built as a **transparent, defense-in-depth companion**—not a replacement for your operating system's kernel security stack:

1. **User-Mode Architecture on Windows**: On Windows, Genesis Seek operates in user mode using filesystem notifications (`ReadDirectoryChangesW`), process snapshots, and `NtSuspendProcess`. Unlike Microsoft Defender or commercial EDRs with Microsoft-signed Early Launch Anti-Malware (**ELAM**) kernel drivers (`PsSetCreateProcessNotifyRoutineEx` / `ObRegisterCallbacks`), a user-mode process cannot intercept kernel-level rootkits or guaranteed pre-instruction execution of every thread before the OS scheduler runs. **We recommend keeping Microsoft Defender (Windows) or AppArmor/SELinux (Linux) enabled alongside Genesis Seek.**
2. **Signature Corpus Scope**: Out of the box, Genesis Seek syncs recent active malware hashes and phishing URLs from Abuse.ch MalwareBazaar, URLhaus, and PhishStats (~200k+ indicators) plus bundled YARA rules. For multi-million legacy signature coverage, install **ClamAV (`clamd`)** locally—Genesis Seek will automatically query `clamd` (`127.0.0.1:3310` or `/run/clamav/clamd.ctl`) alongside its own engines.
3. **Privileged Features Are Opt-In**: Modifying the OS `hosts` file (DNS Sinkhole), applying sysctl/registry kernel hardening, and exposing the local `POST /gateway/*` HTTP endpoints are **disabled by default** and only run when explicitly toggled by the user.
4. **Consumer Firefox Extension Signing**: Standard consumer Firefox Release requires add-ons to be cryptographically signed by Mozilla AMO ([available here](https://addons.mozilla.org/en-US/firefox/addon/genesis-seek-browser-guard/)) or loaded via `about:debugging`. Local unsigned `.xpi` auto-provisioning works natively on Firefox Developer Edition, Nightly, ESR, and Linux distributions that allow unsigned profile extensions.

---

## 🧪 Building & Running Automated Tests

All 24 unit and integration test suites (covering EICAR, nested `.zip`/`.tar.gz`, Office macros, PDF `FlateDecode`, MS-SHLLINK `.lnk`, RFC 5322 `.eml` MIME unpacking, ransomware shadow-journal rollback, unbacked PE/ELF memory detection, `.msi`/installer false-positive checks, and malformed-input parser fuzzing) run offline in `< 2 seconds`:

```bash
cd src-tauri
cargo test
```

See [**`TEST_RESULTS.md`**](TEST_RESULTS.md) for the complete test matrix and methodology.

### Build Optimized Native Binary
```bash
cd src-tauri
cargo build --release
```

---

## 📄 License

Released under the [**MIT License**](LICENSE). Copyright © 2026 **Genesis Grid Labs** ([genesisgridlabs.xyz](https://genesisgridlabs.xyz)).
