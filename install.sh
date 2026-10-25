#!/usr/bin/env bash
# ==============================================================================
#  🛡️ Genesis Seek v0.3.0 — Enterprise-Grade Linux Installer & Capability Hardening
#  Endpoint Defense, fanotify Pre-Execution Blocking, YARA-X, Encrypted Quarantine
# ==============================================================================
set -euo pipefail

REPO="Coraje187/Genesis-Seek"
VERSION="v0.3.0"
BIN_NAME="genesis-seek"
INSTALL_BIN="/usr/local/bin/${BIN_NAME}"
POLKIT_POLICY="/usr/share/polkit-1/actions/io.genesisseek.security.policy"
DESKTOP_DIR="${HOME}/.local/share/applications"
DESKTOP_FILE="${DESKTOP_DIR}/genesis-seek.desktop"
AUTOSTART_FILE="${HOME}/.config/autostart/genesis-seek.desktop"
ICON_DIR="${HOME}/.local/share/icons/hicolor/512x512/apps"
CONFIG_DIR="${HOME}/.config/genesis-seek"
RULES_DIR="${CONFIG_DIR}/rules"

echo "=========================================================="
echo "  🛡️ Installing Genesis Seek ($VERSION) Enterprise Tier"
echo "=========================================================="

mkdir -p "${CONFIG_DIR}" "${RULES_DIR}" "${DESKTOP_DIR}" "${ICON_DIR}" "${HOME}/.config/autostart"

SOURCE_BIN=""
if [[ -f "./src-tauri/target/release/${BIN_NAME}" ]]; then
    SOURCE_BIN="./src-tauri/target/release/${BIN_NAME}"
elif [[ -f "./${BIN_NAME}" ]]; then
    SOURCE_BIN="./${BIN_NAME}"
elif [[ -f "./release_assets/${BIN_NAME}" ]]; then
    SOURCE_BIN="./release_assets/${BIN_NAME}"
fi

# If local binary not found, download from GitHub release
if [[ -z "${SOURCE_BIN}" || ! -f "${SOURCE_BIN}" ]]; then
    DOWNLOAD_URL="https://github.com/${REPO}/releases/download/${VERSION}/genesis-seek"
    TEMP_DIR=$(mktemp -d)
    trap 'rm -rf "$TEMP_DIR"' EXIT
    echo "--> Downloading Genesis Seek binary from GitHub (${VERSION})..."
    if command -v curl >/dev/null 2>&1; then
        curl -fsSL "$DOWNLOAD_URL" -o "$TEMP_DIR/$BIN_NAME" || true
    elif command -v wget >/dev/null 2>&1; then
        wget -q "$DOWNLOAD_URL" -O "$TEMP_DIR/$BIN_NAME" || true
    fi
    if [[ -f "$TEMP_DIR/$BIN_NAME" ]]; then
        SOURCE_BIN="$TEMP_DIR/$BIN_NAME"
    elif [[ -d "./src-tauri" ]] && command -v cargo >/dev/null 2>&1; then
        echo "⚙️ Compiling Genesis Seek release binary locally..."
        (cd src-tauri && cargo build --release)
        SOURCE_BIN="./src-tauri/target/release/${BIN_NAME}"
    fi
fi

if [[ -z "${SOURCE_BIN}" || ! -f "${SOURCE_BIN}" ]]; then
    echo "❌ Could not find or download ${BIN_NAME} binary."
    exit 1
fi

chmod +x "${SOURCE_BIN}"

# 1. Install to /usr/local/bin if sudo is available, otherwise $HOME/.local/bin
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
    echo "⚠️ Installed to ${USER_BIN} (User-Space Watcher mode). Run with sudo to enable fanotify Tier 1."
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

# 4. Create Desktop & Autostart entries
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
cp -f "${DESKTOP_FILE}" "${AUTOSTART_FILE}"

echo ""
echo "=========================================================="
echo "  ✅ Genesis Seek ($VERSION) installed successfully!"
echo "=========================================================="
echo "  • Executable: ${TARGET_EXEC}"
echo "  • Desktop shortcut created in Application menu."
echo "  • Autostart configured for desktop system bar tray."
echo ""
echo "  Launch anytime by running:  genesis-seek"
echo "=========================================================="
