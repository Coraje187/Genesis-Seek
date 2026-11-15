# Security Policy

Genesis Seek is security software that runs with elevated access on your machine, so we take vulnerability reports seriously and want to hear about them.

## Supported Versions

Genesis Seek is pre-1.0. Only the latest release receives security fixes.

| Version | Supported          |
| ------- | ------------------ |
| 0.4.x   | :white_check_mark: |
| < 0.4   | :x:                |

## Reporting a Vulnerability

**Please do not open a public issue for security vulnerabilities.**

Use either of these private channels:

1. **GitHub Private Vulnerability Reporting** (preferred): go to the repository's [**Security → Report a vulnerability**](https://github.com/Coraje187/Genesis-Seek/security/advisories/new) page.
2. **Email:** [coraje@genesisgridlabs.xyz](mailto:coraje@genesisgridlabs.xyz)

Please include as much of the following as you can:

- The affected component and version (for example `scanner.rs` ZIP parser, the local bridge on `127.0.0.1:49152`, the Linux installer, the browser extension)
- Your OS and how Genesis Seek was installed
- Steps to reproduce, or a proof of concept (a crafted file, an HTTP request, a script)
- The impact you believe it has (for example scanner bypass, crash or denial of service, privilege escalation, data exposure)
- Whether you plan to publish your findings, and any deadline you are working to

Please do not include live malware in reports. A hash, a minimal crafted file that triggers the behavior, or a description is enough.

## What to Expect

| Step                        | Target                                  |
| --------------------------- | --------------------------------------- |
| Acknowledgement of report   | Within 3 business days                  |
| Initial triage and severity | Within 10 days                          |
| Fix or mitigation           | Critical/High: 30 days, others: 90 days |
| Public disclosure           | After a fix ships, coordinated with you |

These are targets for a small project, not guarantees. If we need more time we will tell you why. We follow coordinated disclosure with a default window of 90 days from your report, and we are happy to credit you in the release notes unless you prefer to stay anonymous.

## Scope

**In scope**

- The desktop application (Rust/Tauri): file scanner and unpackers (ZIP, GZIP, TAR, PDF, OLE2, MIME/mail, LNK), the YARA-style rule engine, the real-time shield, process guard, quarantine vault, threat-intel sync, and hosts-file/DNS sinkhole logic
- The local HTTP bridge (`127.0.0.1:49152`) and its endpoints, including origin, host, and authentication checks
- The Chromium and Firefox Browser Guard extensions
- `install.sh`, `package_release.ps1`, and the build/release workflows
- Anything that lets an attacker **bypass, disable, crash, or abuse** Genesis Seek itself, including file-name or path-based scan exclusions, silent "clean" verdicts on content that was not fully scanned, and parser crashes on crafted input

**Out of scope**

- A missed detection of one specific malware sample or family. Every scanner has these. Please open a normal public issue and attach the SHA-256, not the sample. (A *generic* bypass that lets whole classes of malware evade scanning is in scope.)
- False positives on specific legitimate files, which also belong in public issues
- Findings that require an attacker who already has administrator/root access and could simply disable Genesis Seek
- Vulnerabilities in third-party dependencies that are already tracked upstream, unless Genesis Seek uses them in an exploitable way
- Social engineering, physical access, and denial of service by resource exhaustion on the local machine without a security impact beyond the above

## Safe Harbor

If you act in good faith and follow this policy, we will not pursue or support legal action against you. Good faith means:

- Testing only on systems you own or have permission to test
- Not accessing, modifying, or destroying data that is not yours
- Not degrading service for other people, and not publishing a vulnerability before we have had a reasonable chance to fix it
- Giving us reasonable time to respond before any public disclosure

## Threat Model and Known Limitations

We would rather be upfront about what Genesis Seek is and is not:

- **It is not an audited product.** It has not had an independent security review, and it is not a replacement for Microsoft Defender or another mature endpoint product. Treat it as an additional layer.
- **Detection is signature- and heuristic-based** (hash database, YARA-style rules, format heuristics). It does not have a cloud reputation system or behavioral ML, so novel and targeted malware may go undetected.
- **Scanning has size and depth limits.** Very large files, deeply nested archives, archives with many entries, and unsupported compression methods may be only partially inspected. We are working toward reporting these as "unscanned" rather than "clean".
- **The local bridge trusts the local machine.** It binds to loopback only (`127.0.0.1:49152`), rejects cross-site browser requests, and keeps `POST /gateway/*` endpoints disabled by default (opt-in), but it should not be exposed to other hosts, and other local users or processes are not fully isolated from it. Do not forward or proxy port 49152.
- **The quarantine vault key is stored locally** next to the vault. Encryption exists to neutralize malware and prevent accidental execution; it does not protect quarantined files from an attacker who already runs as your user.
- **Real-time protection runs with elevated privileges** (`fanotify` on Linux, process suspension on Windows) and edits system files when you enable opt-in features like the DNS sinkhole or sysctl hardening. Review what you enable.

## Verifying Releases

- Release artifacts are published at <https://github.com/Coraje187/Genesis-Seek/releases>
- **SHA-256 Checksums**: Every release attaches `SHA256SUMS.txt` containing the SHA-256 digests of all published archives, installers, and browser extension packages:
  ```bash
  # Linux
  sha256sum -c SHA256SUMS.txt --ignore-missing

  # Windows PowerShell
  Get-FileHash .\genesis-seek.exe -Algorithm SHA256
  ```
- **Code Signing Status**: Windows and Linux binaries are currently built from public source via GitHub Actions and are not yet signed with a commercial EV Authenticode certificate or hardware GPG key. Always download directly from official GitHub Releases and verify against `SHA256SUMS.txt` (or build from source with `cargo build --release`).

If you install on Linux using `install.sh`, you are running a script that requests elevated privileges to install into `/usr/local/bin`. We recommend downloading `install.sh`, reading it, and verifying the release checksums first:
```bash
curl -sSLO https://raw.githubusercontent.com/Coraje187/Genesis-Seek/main/install.sh
less install.sh
bash install.sh
```

## Disclosure History

No security advisories have been published yet. Fixed issues will be listed under the repository's **Security → Advisories** tab and in `CHANGELOG.md`.
