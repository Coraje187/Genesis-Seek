rule YARA_Linux_Interactive_Reverse_Shell {
    meta:
        description = "Detects interactive bash or netcat reverse shell payloads"
        severity = "Critical"
    strings:
        $bash_tcp = "/dev/tcp/" nocase
        $bash_i = "bash -i >&" nocase
        $nc_exec = "nc -e /bin/sh" nocase
        $mkfifo_nc = "mkfifo /tmp/f;cat /tmp/f|/bin/sh" nocase
    condition:
        any of them
}

rule YARA_Windows_ShadowCopy_Ransomware_Inhibit {
    meta:
        description = "Detects ransomware volume shadow copy deletion and recovery inhibition"
        severity = "Critical"
    strings:
        $vss1 = "vssadmin delete shadows /all /quiet" nocase
        $vss2 = "vssadmin.exe delete shadows" nocase
        $wmic = "wmic shadowcopy delete" nocase
        $bcd = "bcdedit /set {default} recoveryenabled no" nocase
        $wbadmin = "wbadmin delete catalog -quiet" nocase
    condition:
        any of them
}

rule YARA_Stealer_Browser_Credential_Access {
    meta:
        description = "Detects credential stealer targeting browser Login Data and Local State"
        severity = "High"
    strings:
        $chrome_login = "Google\\Chrome\\User Data\\Default\\Login Data" nocase
        $brave_login = "BraveSoftware\\Brave-Browser\\User Data\\Default\\Login Data" nocase
        $firefox_logins = "logins.json" nocase
        $crypt_unprotect = "CryptUnprotectData" nocase
    condition:
        any of them
}

rule YARA_Cryptominer_Stratum_Protocol {
    meta:
        description = "Detects unauthorized XMRig or Stratum cryptocurrency mining client"
        severity = "High"
    strings:
        $s1 = "stratum+tcp://" nocase
        $s2 = "stratum+ssl://" nocase
        $s3 = "donate.v2.xmrig.com" nocase
    condition:
        any of them
}

rule YARA_Linux_XorDDoS_And_Mirai_Botnet {
    meta:
        category = "Malware.Linux.Botnet"
        description = "Detects Mirai and XorDDoS Linux ELF botnet indicators (watchdog tampering, routing probes, init persistence)"
        severity = "Critical"
    strings:
        $s1 = "/dev/watchdog" nocase
        $s2 = "/proc/net/route" nocase
        $s3 = "gcc -o" nocase
        $s4 = "busybox ECCHI" nocase
        $s5 = "/etc/init.d/S90" nocase
        $s6 = "xor_keys" nocase
    condition:
        2 of them
}

rule YARA_Linux_Kinsing_Sysrv_ContainerWorm {
    meta:
        category = "Malware.Linux.ContainerWorm"
        description = "Detects Kinsing / Sysrv Linux cloud and container worm payload indicators"
        severity = "Critical"
    strings:
        $s1 = "kinsing" nocase
        $s2 = "kdevtmpfsi" nocase
        $s3 = "libsystem.so" nocase
        $s4 = "/tmp/.ICEd-unix" nocase
        $s5 = "crontab -l" nocase
        $s6 = "setenforce 0" nocase
        $s7 = "ufw disable" nocase
    condition:
        2 of them
}

rule YARA_Linux_BPFDoor_StealthBackdoor {
    meta:
        category = "Backdoor.Linux.BPFDoor"
        description = "Detects BPFDoor stealth Linux backdoor process masquerading and raw BPF filter indicators"
        severity = "Critical"
    strings:
        $s1 = "hald-addon-acpi" nocase
        $s2 = "/dev/shm/kdmtmpflush" nocase
        $s3 = "PACKET_MR_PROMISC" nocase
        $s4 = "SO_ATTACH_FILTER" nocase
    condition:
        2 of them
}

rule YARA_Linux_Perfctl_Rootkit_Dropper {
    meta:
        category = "Rootkit.Linux.Perfctl"
        description = "Detects Perfctl Linux rootkit and cryptomining dropper artifacts"
        severity = "Critical"
    strings:
        $s1 = "perfctl" nocase
        $s2 = "libgcwrap.so" nocase
        $s3 = "/tmp/.perf.c" nocase
        $s4 = "/usr/bin/perfcc" nocase
    condition:
        2 of them
}

rule YARA_Windows_CredentialDump_LSASS_Mimikatz {
    meta:
        category = "CredentialAccess.LSASSDump"
        description = "Detects Mimikatz and comsvcs.dll MiniDump LSASS credential dumping tools"
        severity = "Critical"
    strings:
        $s1 = "sekurlsa::logonpasswords" nocase
        $s2 = "lsadump::sam" nocase
        $s3 = "privilege::debug" nocase
        $s4 = "comsvcs.dll" nocase
        $s5 = "MiniDump" nocase
    condition:
        2 of them
}
