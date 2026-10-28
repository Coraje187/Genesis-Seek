#!/usr/bin/env bash
# ==============================================================================
#  🛡️ Genesis Seek v0.3.2 — Enterprise-Grade Linux Installer & Auto-Start Daemon
#  Endpoint Defense, fanotify Pre-Execution Blocking, YARA-X, Encrypted Quarantine
# ==============================================================================
set -euo pipefail

REPO="Coraje187/Genesis-Seek"
VERSION="v0.3.2"
BIN_NAME="genesis-seek"
INSTALL_BIN="/usr/local/bin/${BIN_NAME}"
POLKIT_POLICY="/usr/share/polkit-1/actions/io.genesisseek.security.policy"
DESKTOP_DIR="${HOME}/.local/share/applications"
DESKTOP_FILE="${DESKTOP_DIR}/genesis-seek.desktop"
AUTOSTART_DIR="${HOME}/.config/autostart"
AUTOSTART_FILE="${AUTOSTART_DIR}/genesis-seek.desktop"
SYSTEMD_USER_DIR="${HOME}/.config/systemd/user"
SYSTEMD_SERVICE="${SYSTEMD_USER_DIR}/genesis-seek.service"
ICON_DIR="${HOME}/.local/share/icons/hicolor/512x512/apps"
CONFIG_DIR="${HOME}/.config/genesis-seek"
RULES_DIR="${CONFIG_DIR}/rules"

echo "=========================================================="
echo "  🛡️ Installing Genesis Seek ($VERSION) Enterprise Tier"
echo "=========================================================="

mkdir -p "${CONFIG_DIR}" "${RULES_DIR}" "${DESKTOP_DIR}" "${ICON_DIR}" "${AUTOSTART_DIR}" "${SYSTEMD_USER_DIR}"

SOURCE_BIN=""
if [[ -f "./src-tauri/target/release/${BIN_NAME}" ]]; then
    SOURCE_BIN="./src-tauri/target/release/${BIN_NAME}"
elif [[ -f "./${BIN_NAME}" ]]; then
    SOURCE_BIN="./${BIN_NAME}"
elif [[ -f "./release_assets/${BIN_NAME}" ]]; then
    SOURCE_BIN="./release_assets/${BIN_NAME}"
elif [[ -f "./genesis-seek-linux-x86_64" ]]; then
    SOURCE_BIN="./genesis-seek-linux-x86_64"
fi

# If local binary not found, download from GitHub release
if [[ -z "${SOURCE_BIN}" || ! -f "${SOURCE_BIN}" ]]; then
    TEMP_DIR=$(mktemp -d)
    trap 'rm -rf "$TEMP_DIR"' EXIT
    echo "--> Downloading Genesis Seek binary from GitHub Releases (${VERSION})..."

    DOWNLOAD_CANDIDATES=(
        "https://github.com/${REPO}/releases/download/${VERSION}/genesis-seek-linux-x86_64"
        "https://github.com/${REPO}/releases/download/${VERSION}/genesis-seek"
        "https://github.com/${REPO}/releases/download/${VERSION}/Genesis-Seek-0.3.2-x86_64.AppImage"
        "https://github.com/${REPO}/releases/download/${VERSION}/Genesis-Seek-${VERSION#v}-x86_64.AppImage"
    )

    for url in "${DOWNLOAD_CANDIDATES[@]}"; do
        echo "    Trying: $url"
        if command -v curl >/dev/null 2>&1; then
            if curl -fsSL "$url" -o "$TEMP_DIR/$BIN_NAME" 2>/dev/null; then
                if [[ -s "$TEMP_DIR/$BIN_NAME" ]]; then
                    SOURCE_BIN="$TEMP_DIR/$BIN_NAME"
                    break
                fi
            fi
        elif command -v wget >/dev/null 2>&1; then
            if wget -q "$url" -O "$TEMP_DIR/$BIN_NAME" 2>/dev/null; then
                if [[ -s "$TEMP_DIR/$BIN_NAME" ]]; then
                    SOURCE_BIN="$TEMP_DIR/$BIN_NAME"
                    break
                fi
            fi
        fi
    done

    # Fallback: check tarball
    if [[ -z "${SOURCE_BIN}" || ! -s "${SOURCE_BIN}" ]]; then
        TAR_URL="https://github.com/${REPO}/releases/download/${VERSION}/genesis-seek-${VERSION}-linux-x86_64.tar.gz"
        echo "    Trying tarball: $TAR_URL"
        if curl -fsSL "$TAR_URL" -o "$TEMP_DIR/gs.tar.gz" 2>/dev/null; then
            tar -xzf "$TEMP_DIR/gs.tar.gz" -C "$TEMP_DIR" 2>/dev/null || true
            if [[ -f "$TEMP_DIR/$BIN_NAME" ]]; then
                SOURCE_BIN="$TEMP_DIR/$BIN_NAME"
            fi
        fi
    fi

    # Fallback: local compile if cargo is present
    if [[ -z "${SOURCE_BIN}" || ! -f "${SOURCE_BIN}" ]]; then
        if [[ -d "./src-tauri" ]] && command -v cargo >/dev/null 2>&1; then
            echo "⚙️ Compiling Genesis Seek release binary locally..."
            (cd src-tauri && cargo build --release)
            SOURCE_BIN="./src-tauri/target/release/${BIN_NAME}"
        fi
    fi
fi

if [[ -z "${SOURCE_BIN}" || ! -f "${SOURCE_BIN}" ]]; then
    echo "❌ Could not download or locate genesis-seek binary."
    exit 1
fi

chmod +x "${SOURCE_BIN}"

# 1. Install to /usr/local/bin if sudo available, otherwise $HOME/.local/bin
TARGET_EXEC="${INSTALL_BIN}"
if command -v sudo >/dev/null 2>&1 && sudo -v 2>/dev/null; then
    echo "🔐 Installing to ${INSTALL_BIN} with root/capabilities..."
    sudo install -m 0755 "${SOURCE_BIN}" "${INSTALL_BIN}"
    TARGET_EXEC="${INSTALL_BIN}"

    # Grant Linux capabilities for fanotify Pre-Exec blocking without needing full root GUI launch
    if command -v setcap >/dev/null 2>&1; then
        sudo setcap 'cap_sys_admin,cap_dac_read_search,cap_sys_ptrace,cap_kill+ep' "${INSTALL_BIN}" 2>/dev/null || true
        echo "✅ Granted capabilities: cap_sys_admin,cap_dac_read_search,cap_sys_ptrace,cap_kill+ep"
    fi

    # Install Polkit policy
    if [[ -d "/usr/share/polkit-1/actions" ]]; then
        sudo tee "${POLKIT_POLICY}" >/dev/null <<'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE policyconfig PUBLIC
 "-//freedesktop//DTD PolicyKit Policy Configuration 1.0//EN"
 "http://www.freedesktop.org/standards/PolicyKit/1/policyconfig.dtd">
<policyconfig>
  <vendor>Genesis Grid Labs</vendor>
  <vendor_url>https://genesisgridlabs.xyz</vendor_url>
  <action id="io.genesisseek.security.pkexec.run">
    <description>Run Genesis Seek Enterprise Endpoint Defense with Kernel Pre-Execution Shield</description>
    <message>Authentication is required to enable Genesis Seek fanotify Kernel Pre-Execution Shield</message>
    <defaults>
      <allow_any>auth_admin</allow_any>
      <allow_inactive>auth_admin</allow_inactive>
      <allow_active>auth_admin_keep</allow_active>
    </defaults>
    <annotate key="org.freedesktop.policykit.exec.path">/usr/local/bin/genesis-seek</annotate>
    <annotate key="org.freedesktop.policykit.exec.allow_gui">true</annotate>
  </action>
</policyconfig>
EOF
        echo "✅ Installed Polkit policy at ${POLKIT_POLICY}"
    fi
else
    USER_BIN="${HOME}/.local/bin/${BIN_NAME}"
    mkdir -p "${HOME}/.local/bin"
    cp -f "${SOURCE_BIN}" "${USER_BIN}"
    chmod +x "${USER_BIN}"
    TARGET_EXEC="${USER_BIN}"
    echo "⚠️ Installed to ${USER_BIN} (User-Space Watcher mode). Run installer with sudo for fanotify Tier 1."
fi

# 2. Copy YARA rules
if [[ -d "./rules" ]]; then
    cp -f ./rules/*.yar "${RULES_DIR}/" 2>/dev/null || true
fi

# 3. Download / copy desktop icon
ICON_URL="https://raw.githubusercontent.com/${REPO}/main/ui/assets/logo-mark.svg"
if [[ -f "./ui/assets/logo-mark.svg" ]]; then
    cp -f "./ui/assets/logo-mark.svg" "${ICON_DIR}/genesis-seek.svg"
else
    curl -fsSL "$ICON_URL" -o "${ICON_DIR}/genesis-seek.svg" 2>/dev/null || true
fi

# 4. Create Desktop Application Menu Launcher
cat > "${DESKTOP_FILE}" <<EOF
[Desktop Entry]
Type=Application
Name=Genesis Seek
Comment=Enterprise Endpoint, Process & Browser Protection (fanotify + YARA-X)
Exec=${TARGET_EXEC}
Icon=genesis-seek
Terminal=false
Categories=Utility;Security;System;
StartupNotify=false
EOF
chmod +x "${DESKTOP_FILE}"

# 5. Create Autostart on Boot (XDG Autostart) - starts minimized to tray
cat > "${AUTOSTART_FILE}" <<EOF
[Desktop Entry]
Type=Application
Name=Genesis Seek
Comment=Genesis Seek Enterprise Endpoint Defense (Background Shield)
Exec=${TARGET_EXEC} --minimized
Icon=genesis-seek
Terminal=false
Categories=Utility;Security;System;
X-GNOME-Autostart-enabled=true
StartupNotify=false
EOF
chmod +x "${AUTOSTART_FILE}"

# 6. Create and Enable systemd User Service (24/7 background persistence)
if command -v systemctl >/dev/null 2>&1; then
    cat > "${SYSTEMD_SERVICE}" <<EOF
[Unit]
Description=Genesis Seek Enterprise Real-Time Shield
After=graphical-session.target network.target

[Service]
Type=simple
ExecStart=${TARGET_EXEC} --minimized
Restart=always
RestartSec=3
Environment="WEBKIT_DISABLE_DMABUF_RENDERER=1"
Environment="WEBKIT_DISABLE_COMPOSITING_MODE=1"

[Install]
WantedBy=default.target
EOF

    systemctl --user daemon-reload 2>/dev/null || true
    systemctl --user enable genesis-seek.service 2>/dev/null || true
    systemctl --user restart genesis-seek.service 2>/dev/null || true
    echo "✅ Configured systemd user service: starts automatically on boot & restarts if killed."
else
    # Non-systemd fallback: start in background now
    nohup "${TARGET_EXEC}" --minimized >/dev/null 2>&1 &
fi

echo ""
echo "=========================================================="
echo "  ✅ Genesis Seek ($VERSION) installed successfully!"
echo "=========================================================="
echo "  • Executable: ${TARGET_EXEC}"
echo "  • Start on Boot: Configured (systemd user service + XDG autostart)"
echo "  • System Tray: Active in background"
echo "  • Launch Dashboard anytime from your App Menu or by running:"
echo "      genesis-seek"
echo "=========================================================="
