# Automated Detection, Clean-Installer & Parser Resilience Test Results (`v0.4.0`)

All detection claims in Genesis Seek are backed by deterministic, reproducible unit and integration tests in [`src-tauri/src/`](src-tauri/src/) that anyone can run locally without network access or proprietary datasets.

## How to Reproduce Locally

```bash
cd src-tauri
cargo test
```

## Summary of Test Suites (24 / 24 Passing)

| Module | Test Suite | What It Verifies | Result |
| :--- | :--- | :--- | :--- |
| `scanner.rs` | `flags_eicar_payload` | Detects standard EICAR signature via SHA-256 + content engine | ✅ Pass |
| `scanner.rs` | `unpacks_nested_zip_archives_and_catches_zipslip_and_macros` | Detects nested `.zip` EICAR (`depth=2`), `../../` ZipSlip traversal, and Office `vbaProject.bin` `AutoOpen` + `Shell` macros; verifies clean `.zip` has 0 false positives | ✅ Pass |
| `scanner.rs` | `unpacks_targz_pdf_flatedecode_and_obfuscated_base64_utf16` | Decompresses `.tar.gz` droppers, PDF `FlateDecode` `/OpenAction` + `/JS` streams, Base64 + UTF-16LE PowerShell stagers, and 64 KB EOF overlays on >2 MB files | ✅ Pass |
| `scanner.rs` | `detects_tampered_upx_pe_injection_and_elf_memfd_stealth` | Detects UPX header tampering (`UPX0`/`UPX1` without `UPX!`), PE `VirtualAllocEx`+`WriteProcessMemory`+`CreateRemoteThread` triad, and ELF `memfd_create`+`ptrace` stealth | ✅ Pass |
| `scanner.rs` | `parses_binary_lnk_and_enforces_motw_zone_identifier` | Parses MS-SHLLINK `.lnk` headers (`LinkInfo` paths, prefix-shortened `-e`/`-enc` PowerShell args, `.pdf` icon masquerading) and NTFS `:Zone.Identifier` (`ZoneId=3`) | ✅ Pass |
| `scanner.rs` | `msi_installers_and_setup_packages_do_not_false_positive` | Verifies high-entropy OLE2 `.msi` packages, embedded custom-action PEs inside `.msi`, `Firefox Installer.exe`, and the real built `Genesis.Seek_0.4.0_x64_en-US.msi` produce **0 false positives** (`scan_buffer_layers(...) == None`) | ✅ Pass |
| `scanner.rs` | `mail_gateway_unpacks_mime_attachments_html_smuggling_and_spoofed_headers` | Verifies RFC 5322 `.eml` MIME attachment unpacking (Base64 `.zip` with EICAR), Quoted-Printable HTML smuggling (`Blob` + `createObjectURL` + `atob`), `spf=fail`/`dmarc=fail` display-name spoofing, and verifies clean `spf=pass` email returns `CLEAN` | ✅ Pass |
| `scanner.rs` | `fuzz_resilience_malformed_and_truncated_parser_inputs_never_panic` | Feeds truncated/corrupt headers and recursive MIME boundaries into `.zip`, `.tar.gz`, PDF `FlateDecode`, `.lnk`, `.msi`, and `.eml` parsers without panicking | ✅ Pass |
| `scanner.rs` | `yara_hex_patterns_and_threshold_conditions_work` | Evaluates raw hex byte rules (`{ 18 a0 22 00 }`), `2 of them`, and `all of them` YARA conditions | ✅ Pass |
| `scanner.rs` | `sqlite_db_filters_empty_hashes_and_Recovers_from_corrupt_file` | Verifies `PRAGMA quick_check` self-healing on corrupt SQLite DB files and rejects empty-file SHA-256 (`e3b0c442...`) | ✅ Pass |
| `realtime_shield.rs` | `system_watcher_journal_automatically_rolls_back_ransomware_encryption_and_renames` | Verifies benign edits update the baseline snapshot, high-entropy overwrites ($H \ge 7.20$) roll back to pre-encryption bytes, and `.lockbit` renames restore the clean file and remove the ransomware artifact | ✅ Pass |
| `realtime_shield.rs` | `validates_trusted_and_untrusted_exec_paths` | Verifies `/usr/bin/sudo`, `/bin/sh`, `/usr/lib/systemd/systemd` are trusted while `/tmp`, `/dev/shm`, `Downloads`, and `AppData\Local\Temp` are flagged as volatile | ✅ Pass |
| `process_guard.rs` | `detects_unbacked_and_stomped_executable_memory_headers` | Detects unbacked PE (`MZ` + `PE\0\0`), MZ-stomped Cobalt Strike beacons, unbacked ELF64, `ReflectiveLoader` exports, and Stephen Fewer x64 PEB-walk stubs in memory buffers while ignoring normal JIT code | ✅ Pass |
| `process_guard.rs` | `flags_multi_ancestor_asr_and_lsass_dumping` | Flags 4-hop Office/PDF-reader → shell chains and `rundll32 comsvcs.dll, MiniDump` LSASS credential dumping | ✅ Pass |
| `process_guard.rs` | `legitimate_installers_and_7zip_temp_stubs_are_trusted_not_flagged` | Verifies `Firefox Installer.exe` and `AppData\Local\Temp\7zS0E9E0266\setup-stub.exe` are recognized as trusted installer activity (`0` false positives) while unknown temp executables (`Temp\7zO495FEBC5\dropper_payload.exe`) are still flagged | ✅ Pass |
| `quarantine.rs` | `blocks_quarantining_protected_system_binaries` | Ensures root-anchored `C:\Windows\System32\svchost.exe` and `/usr/bin/bash` can never be quarantined, while fake `C:\Users\bob\Downloads\Windows\System32\dropper.exe` is allowed to be quarantined | ✅ Pass |
| `threat_intel_and_net.rs` | `validates_and_filters_poisoned_domains` | Rejects `github.com`, `google.com`, `localhost`, IP literals, and malformed strings from feed/sinkhole ingestion | ✅ Pass |
| `threat_intel_and_net.rs` | `network_gateway_sinkhole_preserves_existing_hosts_and_detects_wan_smb_relay` | Verifies `apply_sinkhole_hosts_block` preserves user `hosts` lines on enable/disable, flags outbound WAN TCP port `445` (`Exploit.Net.OutboundWanSmbRelay_CVE_2023_23397`), and allows RFC 1918 LAN port `445` (`192.168.1.50`) | ✅ Pass |
| `extension_installer.rs` | `builds_valid_posix_pkzip_firefox_xpi_without_bom` | Verifies the generated `.xpi` starts with `PK\x03\x04`, uses only forward-slash `/` entry names, and contains a BOM-free UTF-8 `manifest.json` with `browser-guard@genesisseek.io` | ✅ Pass |
