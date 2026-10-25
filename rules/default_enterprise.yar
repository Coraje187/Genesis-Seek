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
