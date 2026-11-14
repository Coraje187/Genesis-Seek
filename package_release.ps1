Add-Type -AssemblyName System.IO.Compression
Add-Type -AssemblyName System.IO.Compression.FileSystem

$base = $PSScriptRoot
if (-not $base) { $base = (Get-Location).Path }
$outDir = Join-Path $base "release_assets"
if (Test-Path $outDir) { Remove-Item -Recurse -Force $outDir }
New-Item -ItemType Directory -Path $outDir | Out-Null

$ver = $env:GITHUB_REF_NAME
if (-not $ver) { $ver = "v0.3.8" }
$verNum = if ($ver.StartsWith('v')) { $ver.Substring(1) } else { $ver }

$Utf8NoBom = [System.Text.UTF8Encoding]::new($false)

function New-PosixZipFromDirectory {
    param(
        [Parameter(Mandatory = $true)][string]$SourceDir,
        [Parameter(Mandatory = $true)][string]$DestZip
    )
    if (Test-Path $DestZip) { Remove-Item -Force $DestZip }
    $normRoot = (Resolve-Path $SourceDir).Path.TrimEnd('\', '/')
    $archive = [System.IO.Compression.ZipFile]::Open($DestZip, [System.IO.Compression.ZipArchiveMode]::Create)
    try {
        $files = [System.IO.Directory]::GetFiles($normRoot, "*", [System.IO.SearchOption]::AllDirectories)
        foreach ($file in $files) {
            $relPath = $file.Substring($normRoot.Length).TrimStart('\', '/').Replace('\', '/')
            [void][System.IO.Compression.ZipFileExtensions]::CreateEntryFromFile(
                $archive,
                $file,
                $relPath,
                [System.IO.Compression.CompressionLevel]::Optimal
            )
        }
    }
    finally {
        $archive.Dispose()
    }
}

Write-Host "Packaging release assets for version $ver in $outDir..."

# 1. Standalone binary (if built)
$exePath = Join-Path $base "src-tauri\target\release\genesis-seek.exe"
if (Test-Path $exePath) {
    Copy-Item $exePath (Join-Path $outDir "genesis-seek.exe")
}

# 2. Browser Guard for Chrome, Edge, and Brave (service_worker Manifest V3)
$chromeStage = Join-Path $outDir "chrome_edge_stage"
New-Item -ItemType Directory -Path $chromeStage | Out-Null
Copy-Item -Recurse (Join-Path $base "browser-extension\*") $chromeStage
$chromeManifest = @"
{
  "manifest_version": 3,
  "name": "Genesis Seek Browser Guard",
  "version": "$verNum",
  "description": "Real-time phishing, IDN homograph, cryptojacking, and drive-by malware blocker synced with Genesis Seek Endpoint Defense.",
  "permissions": [
    "tabs",
    "storage",
    "declarativeNetRequest"
  ],
  "host_permissions": [
    "<all_urls>",
    "http://127.0.0.1:49152/*"
  ],
  "background": {
    "service_worker": "background.js"
  },
  "content_scripts": [
    {
      "matches": ["<all_urls>"],
      "js": ["content_guard.js"],
      "run_at": "document_idle"
    }
  ],
  "declarative_net_request": {
    "rule_resources": [
      {
        "id": "genesis_seek_blocklist",
        "enabled": true,
        "path": "rules.json"
      }
    ]
  },
  "icons": {
    "16": "icons/icon-16.png",
    "32": "icons/icon-32.png",
    "48": "icons/icon-48.png",
    "128": "icons/icon-128.png"
  },
  "action": {
    "default_title": "Genesis Seek Browser Guard",
    "default_popup": "popup.html",
    "default_icon": {
      "16": "icons/icon-16.png",
      "32": "icons/icon-32.png"
    }
  }
}
"@
[System.IO.File]::WriteAllText((Join-Path $chromeStage "manifest.json"), $chromeManifest, $Utf8NoBom)
$chromeZipName = "Genesis-Seek-Browser-Guard-for-Chrome-and-Edge-$ver.zip"
$chromeZipOut = Join-Path $outDir $chromeZipName
New-PosixZipFromDirectory -SourceDir $chromeStage -DestZip $chromeZipOut
Copy-Item $chromeZipOut (Join-Path $base "genesis-seek-browser-guard-chromium.zip") -Force
Remove-Item -Recurse -Force $chromeStage

# 3. Browser Guard for Firefox (scripts + gecko Manifest V3 with strict POSIX paths & zero BOM)
$ffStage = Join-Path $outDir "firefox_stage"
New-Item -ItemType Directory -Path $ffStage | Out-Null
Copy-Item -Recurse (Join-Path $base "browser-extension\*") $ffStage
$ffManifest = @"
{
  "manifest_version": 3,
  "name": "Genesis Seek Browser Guard",
  "version": "$verNum",
  "description": "Real-time phishing, IDN homograph, cryptojacking, and drive-by malware blocker synced with Genesis Seek Endpoint Defense.",
  "permissions": [
    "tabs",
    "storage",
    "declarativeNetRequest"
  ],
  "host_permissions": [
    "<all_urls>",
    "http://127.0.0.1:49152/*"
  ],
  "background": {
    "scripts": ["background.js"]
  },
  "browser_specific_settings": {
    "gecko": {
      "id": "browser-guard@genesisseek.io",
      "strict_min_version": "115.0"
    }
  },
  "content_scripts": [
    {
      "matches": ["<all_urls>"],
      "js": ["content_guard.js"],
      "run_at": "document_idle"
    }
  ],
  "declarative_net_request": {
    "rule_resources": [
      {
        "id": "genesis_seek_blocklist",
        "enabled": true,
        "path": "rules.json"
      }
    ]
  },
  "icons": {
    "16": "icons/icon-16.png",
    "32": "icons/icon-32.png",
    "48": "icons/icon-48.png",
    "128": "icons/icon-128.png"
  },
  "action": {
    "default_title": "Genesis Seek Browser Guard",
    "default_popup": "popup.html",
    "default_icon": {
      "16": "icons/icon-16.png",
      "32": "icons/icon-32.png"
    }
  }
}
"@
[System.IO.File]::WriteAllText((Join-Path $ffStage "manifest.json"), $ffManifest, $Utf8NoBom)
$ffZipName = "Genesis-Seek-Browser-Guard-for-Firefox-$ver.zip"
$ffXpiName = "Genesis-Seek-Browser-Guard-for-Firefox-$ver.xpi"
$ffZipOut = Join-Path $outDir $ffZipName
New-PosixZipFromDirectory -SourceDir $ffStage -DestZip $ffZipOut
Copy-Item $ffZipOut (Join-Path $outDir $ffXpiName) -Force
Copy-Item $ffZipOut (Join-Path $base "genesis-seek-browser-guard-firefox.zip") -Force
Remove-Item -Recurse -Force $ffStage

# 4. Windows zip package
if (Test-Path $exePath) {
    $winStaging = Join-Path $outDir "windows_stage"
    New-Item -ItemType Directory -Path $winStaging | Out-Null
    Copy-Item $exePath (Join-Path $winStaging "genesis-seek.exe")
    Copy-Item -Recurse (Join-Path $base "rules") (Join-Path $winStaging "rules")
    Copy-Item -Recurse (Join-Path $base "browser-extension") (Join-Path $winStaging "browser-extension")
    Copy-Item (Join-Path $base "README.md") (Join-Path $winStaging "README.md")
    Compress-Archive -Path (Join-Path $winStaging "*") -DestinationPath (Join-Path $outDir "genesis-seek-$ver-windows-x86_64.zip") -Force
    Remove-Item -Recurse -Force $winStaging
}

# 5. Linux installer package
$linStaging = Join-Path $outDir "linux_stage"
New-Item -ItemType Directory -Path $linStaging | Out-Null
Copy-Item (Join-Path $base "install.sh") (Join-Path $linStaging "install.sh")
Copy-Item -Recurse (Join-Path $base "rules") (Join-Path $linStaging "rules")
Copy-Item -Recurse (Join-Path $base "browser-extension") (Join-Path $linStaging "browser-extension")
Copy-Item (Join-Path $base "README.md") (Join-Path $linStaging "README.md")
Compress-Archive -Path (Join-Path $linStaging "*") -DestinationPath (Join-Path $outDir "genesis-seek-$ver-linux-installer.zip") -Force
Remove-Item -Recurse -Force $linStaging

Write-Host "Packaging complete. Generated assets in ${outDir}:"
Get-ChildItem $outDir | Select-Object Name, Length
