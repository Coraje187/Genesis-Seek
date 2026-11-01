// ==============================================================================
// 🛡️ Genesis Seek — Curated CVE Sentinel Heuristic Signatures (v0.3.4 Enterprise)
// Targets: Zero-Days, KEV Exploits, BYOVD Blindings, and Evasion Patterns
// Synced from Genesis-Seek Vulnerability & Patch Gap Sentinel
// ==============================================================================

rule Genesis_AppID_IOCTL_Exploit_CVE_2024_21338 {
    meta:
        cve = "CVE-2024-21338"
        category = "PrivilegeEscalation.BYOVD"
        severity = "Critical"
        description = "Detects appid.sys IOCTL 0x22a018 exploit payloads attempting to blind antivirus kernel callbacks"
    strings:
        $re = /(\\\\\.\\(smartscreen|appid)|\\Device\\AppID)/i
        $hex_ioctl = { 18 a0 22 00 }
    condition:
        all of them
}

rule Genesis_MSHTML_Unicode_Spoof_CVE_2024_43468 {
    meta:
        cve = "CVE-2024-43468"
        category = "DefenseEvasion.UnicodeSpoof"
        severity = "Critical"
        description = "Detects RLO Unicode evasion, Braille padding, and concealed HTA/executable payloads"
    strings:
        $re = /(\xE2\x80\xAE|<hta:application.{0,500}(mshta\.exe|WScript\.Shell|ActiveXObject))/is
    condition:
        any of them
}

rule Genesis_Malicious_URL_NTLM_Harvest_CVE_2024_43451 {
    meta:
        cve = "CVE-2024-43451"
        category = "CredentialAccess.NTLMSpoof"
        severity = "High"
        description = "Detects .url and .theme shortcut files configured with remote SMB/WebDAV icon handlers"
    strings:
        $re = /\[InternetShortcut\].{0,800}(IconFile\s*=\s*(\\\\[^\r\n]+|https?:\/\/[^\r\n]*@)|URL\s*=\s*file:\/\/\\\\)/is
    condition:
        any of them
}

rule Genesis_Windows_IPv6_Underflow_PoC_CVE_2024_38063 {
    meta:
        cve = "CVE-2024-38063"
        category = "Exploit.PoC.IPv6"
        severity = "Critical"
        description = "Detects Python and Scapy PoC exploit scripts targeting Windows IPv6 underflow in tcpip.sys"
    strings:
        $re = /(IPv6ExtHdrDestOpt.{0,400}IPv6\s*\(\s*dst\s*=|cve[-_]2024[-_]38063)/is
    condition:
        any of them
}

rule Genesis_Windows_WiFi_CVE_2024_30078_PoC {
    meta:
        cve = "CVE-2024-30078"
        category = "Exploit.PoC.WiFi"
        severity = "High"
        description = "Detects 802.11 Wi-Fi beacon frame crafting exploit tools targeting Windows WLAN drivers"
    strings:
        $re = /(Dot11Beacon.{0,400}cve[-_]2024[-_]30078|cve[-_]2024[-_]30078.{0,400}Dot11Beacon)/is
    condition:
        any of them
}

rule Genesis_Linux_CVE_2024_1086_Exploit {
    meta:
        cve = "CVE-2024-1086"
        category = "PrivilegeEscalation.Kernel"
        severity = "Critical"
        description = "Detects compiled PoC and exploit code for nf_tables use-after-free LPE"
    strings:
        $re = /(nftnl_chain_alloc.{0,800}CLONE_NEWUSER|CLONE_NEWUSER.{0,800}nftnl_chain_alloc|cve[-_]2024[-_]1086)/is
    condition:
        any of them
}

rule Genesis_Linux_NFT_Memory_Corruption_CVE_2024_26923 {
    meta:
        cve = "CVE-2024-26923"
        category = "PrivilegeEscalation.Kernel"
        severity = "High"
        description = "Detects netfilter table verdict exploit payloads attempting memory corruption"
    strings:
        $re = /(NFT_MSG_NEWSET.{0,800}nft_verdict|nft_verdict.{0,800}NFT_MSG_NEWSET|cve[-_]2024[-_]26923)/is
    condition:
        any of them
}

rule Genesis_OpenSSH_regreSSHion_Scanner_CVE_2024_6387 {
    meta:
        cve = "CVE-2024-6387"
        category = "Exploit.RemoteShell"
        severity = "High"
        description = "Detects regreSSHion SIGALRM race condition scripts targeting OpenSSH sshd"
    strings:
        $re = /(regreSSHion.{0,400}(SIGALRM|LoginGraceTime)|cve[-_]2024[-_]6387)/is
    condition:
        any of them
}

rule Genesis_Outlook_Moniker_CVE_2024_21413 {
    meta:
        cve = "CVE-2024-21413"
        category = "Exploit.RemoteCodeExecution"
        severity = "Critical"
        description = "Detects Outlook Moniker file:// hyperlink exploit strings bypassing Protected View"
    strings:
        $re = /(file:\/\/\/?\s*\\\\[^"'\s>]+![^"'\s>]+|cve[-_]2024[-_]21413)/is
    condition:
        any of them
}

rule Genesis_Looney_Tunables_CVE_2023_4911 {
    meta:
        cve = "CVE-2023-4911"
        category = "PrivilegeEscalation.Glibc"
        severity = "High"
        description = "Detects dangerous GLIBC_TUNABLES environment variable buffer overflow injection"
    strings:
        $re = /(GLIBC_TUNABLES\s*=\s*[^\s"']+:[^\s"']+:[^\s"']+|cve[-_]2023[-_]4911)/is
    condition:
        any of them
}
