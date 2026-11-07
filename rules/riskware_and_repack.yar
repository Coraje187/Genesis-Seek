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
        $s5 = "FitGirl-Repack" nocase
    condition:
        any of them
}

rule RiskWare_GameRepack_Generic_Installer {
    meta:
        description = "Detects generic game repack installers utilizing custom unarc/ISDone compression wrappers"
        threat_name = "RiskWare.Crack.RepackInstaller"
        category = "RiskWare / Game Repack"
        severity = "Medium"
    strings:
        $dodi = "DODI-Repack" nocase
        $dodi2 = "dodi-repacks.site" nocase
    condition:
        any of them
}

rule RiskWare_Crack_Steam_DRM_Emulator {
    meta:
        description = "Detects modified Steam DRM emulator DLLs and configuration hooks"
        threat_name = "RiskWare.Crack.SteamEmulator"
        category = "RiskWare / Crack"
        severity = "Medium"
    strings:
        $emu1 = "steam_emu.ini" nocase
        $goldberg = "Goldberg Steam Emulator" nocase
        $codex = "CODEX64.dll" nocase
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
        $k4 = "X-Force 202" nocase
        $k5 = "KMSAuto.Net" nocase
        $k6 = "KMSPico" nocase
    condition:
        any of them
}
