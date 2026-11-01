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
        $dev1 = "\\\\.\\smartscreen" nocase
        $dev2 = "\\\\.\\appid" nocase
        $dev3 = "\\Device\\AppID" nocase
        $hex_ioctl = { 18 a0 22 00 }
    condition:
        ($dev1 or $dev2 or $dev3) and $hex_ioctl
}

rule Genesis_MSHTML_Unicode_Spoof_CVE_2024_43468 {
    meta:
        cve = "CVE-2024-43468"
        category = "DefenseEvasion.UnicodeSpoof"
        severity = "Critical"
        description = "Detects RLO Unicode evasion, Braille padding, and concealed HTA/executable payloads"
    strings:
        $rlo = { E2 80 AE } // UTF-8 U+202E Right-to-Left Override
        $ws_pad = { 20 20 20 20 20 20 }
        $hta = "<hta:application" nocase
        $mshta = "mshta.exe" nocase
    condition:
        $rlo or ($ws_pad and filesize < 1MB) or ($hta and $mshta)
}

rule Genesis_Malicious_URL_NTLM_Harvest_CVE_2024_43451 {
    meta:
        cve = "CVE-2024-43451"
        category = "CredentialAccess.NTLMSpoof"
        severity = "High"
        description = "Detects .url and .theme shortcut files configured with remote SMB/WebDAV icon handlers"
    strings:
        $sec = "[InternetShortcut]" nocase
        $icon = "IconFile=\\\\" nocase
        $url = "URL=file://\\\\" nocase
    condition:
        $sec and ($icon or $url)
}

rule Genesis_Windows_IPv6_Underflow_PoC_CVE_2024_38063 {
    meta:
        cve = "CVE-2024-38063"
        category = "Exploit.PoC.IPv6"
        severity = "Critical"
        description = "Detects Python and Scapy PoC exploit scripts targeting Windows IPv6 underflow in tcpip.sys"
    strings:
        $pkt1 = "IPv6ExtHdrDestOpt" ascii
        $pkt2 = "IPv6(dst=" ascii
        $pkt3 = "cve-2024-38063" nocase ascii
    condition:
        2 of them
}

rule Genesis_Windows_WiFi_CVE_2024_30078_PoC {
    meta:
        cve = "CVE-2024-30078"
        category = "Exploit.PoC.WiFi"
        severity = "High"
        description = "Detects 802.11 Wi-Fi beacon frame crafting exploit tools targeting Windows WLAN drivers"
    strings:
        $dot11 = "Dot11Beacon" nocase ascii
        $cve = "cve-2024-30078" nocase ascii
    condition:
        all of them
}

rule Genesis_Linux_CVE_2024_1086_Exploit {
    meta:
        cve = "CVE-2024-1086"
        category = "PrivilegeEscalation.Kernel"
        severity = "Critical"
        description = "Detects compiled PoC and exploit code for nf_tables use-after-free LPE"
    strings:
        $nf1 = "nftnl_chain_alloc" ascii
        $nf2 = "CLONE_NEWUSER" ascii
        $msg1 = "pwned root" nocase ascii
        $msg2 = "nftables" nocase ascii
    condition:
        uint32(0) == 0x464C457F and ($nf1 or $nf2) and ($msg1 or $msg2)
}

rule Genesis_Linux_NFT_Memory_Corruption_CVE_2024_26923 {
    meta:
        cve = "CVE-2024-26923"
        category = "PrivilegeEscalation.Kernel"
        severity = "High"
        description = "Detects netfilter table verdict exploit payloads attempting memory corruption"
    strings:
        $nft = "NFT_MSG_NEWSET" ascii
        $verd = "nft_verdict" ascii
    condition:
        uint32(0) == 0x464C457F and ($nft or $verd)
}

rule Genesis_OpenSSH_regreSSHion_Scanner_CVE_2024_6387 {
    meta:
        cve = "CVE-2024-6387"
        category = "Exploit.RemoteShell"
        severity = "High"
        description = "Detects regreSSHion SIGALRM race condition scripts targeting OpenSSH sshd"
    strings:
        $s1 = "regreSSHion" nocase ascii
        $s2 = "SIGALRM" ascii
        $s3 = "LoginGraceTime" ascii
    condition:
        2 of them
}
