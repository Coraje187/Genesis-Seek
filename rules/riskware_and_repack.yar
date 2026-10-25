rule RiskWare_GameRepack_FitGirl_Installer {
    meta:
        description = "Detects FitGirl Repack game setup installer and compression stubs"
        threat_name = "RiskWare.Crack.FitGirlRepack"
        category = "RiskWare / Game Repack"
        severity = "Medium"
    strings:
        $s1 = "FitGirl Repack" nocase
        $s2 = "fitgirl-repacks.site" nocase
        $s3 = "cls-magic2_x64.dll" nocase
        $s4 = "cls-lolz_x64.dll" nocase
        $s5 = "cls-srep_x64.dll" nocase
        $s6 = "cls-zstd_x64.dll" nocase
        $s7 = "FitGirl-Repack" nocase
        $s8 = "DRIVECLUB" nocase
    condition:
        ($s1 or $s2 or $s7) or (2 of ($s3, $s4, $s5, $s6))
}

rule RiskWare_GameRepack_Generic_Installer {
    meta:
        description = "Detects generic game repack installers utilizing custom unarc/ISDone compression wrappers"
        threat_name = "RiskWare.Crack.RepackInstaller"
        category = "RiskWare / Game Repack"
        severity = "Medium"
    strings:
        $u1 = "ISDone.dll" nocase
        $u2 = "unarc.dll" nocase
        $u3 = "Unpack error" nocase
        $u4 = "Decompression failed" nocase
        $dodi = "DODI-Repack" nocase
        $dodi2 = "dodi-repacks.site" nocase
    condition:
        ($dodi or $dodi2) or ($u1 and $u2 and ($u3 or $u4))
}

rule RiskWare_Crack_Steam_DRM_Emulator {
    meta:
        description = "Detects modified Steam DRM emulator DLLs and configuration hooks"
        threat_name = "RiskWare.Crack.SteamEmulator"
        category = "RiskWare / Crack"
        severity = "Medium"
    strings:
        $emu1 = "steam_emu.ini" nocase
        $emu2 = "steam_interfaces.txt" nocase
        $goldberg = "Goldberg Steam Emulator" nocase
        $codex = "CODEX64.dll" nocase
        $rune = "RUNE.ini" nocase
        $flt = "FLT.ini" nocase
        $ali = "ALI213.ini" nocase
    condition:
        any of them
}

rule RiskWare_Crack_Keygen_Patcher {
    meta:
        description = "Detects software crack, keygen, and memory patcher tools"
        threat_name = "RiskWare.Crack.GenericPatcher"
        category = "RiskWare / HackTool"
        severity = "Medium"
    strings:
        $k1 = "Keygen" nocase
        $k2 = "Crack / Patch" nocase
        $k3 = "Generate License" nocase
        $k4 = "X-Force 202" nocase
        $k5 = "KMSAuto" nocase
        $k6 = "KMSPico" nocase
    condition:
        2 of them
}
