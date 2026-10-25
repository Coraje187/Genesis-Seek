#!/usr/bin/env bash
# ==============================================================================
# Genesis Seek v0.3.0 — Enterprise-Grade Linux Installer & Capability Hardening
# Grants Linux Kernel Capabilities (CAP_SYS_ADMIN, CAP_DAC_READ_SEARCH,
# CAP_SYS_PTRACE, CAP_KILL) for Instruction-Zero fanotify Pre-Execution Blocking
# while allowing normal desktop launch without full root privileges.
# ==============================================================================
set -euo pipefail

BIN_NAME="genesis-seek"
INSTALL_BIN="/usr/local/bin/${BIN_NAME}"
POLKIT_POLICY="/usr/share/polkit-1/actions/io.genesisseek.security.policy"
DESKTOP_FILE="${HOME}/.local/share/applications/genesis-seek.desktop"
AUTOSTART_FILE="${HOME}/.config/autostart/genesis-seek.desktop"
CONFIG_DIR="${HOME}/.config/genesis-seek"
RULES_DIR="${CONFIG_DIR}/rules"

echo "🛡️  Genesis Seek Enterprise Tier (v0.3.0) — Linux Installer"
echo "------------------------------------------------------------"

mkdir -p "${CONFIG_DIR}" "${RULES_DIR}" "${HOME}/.local/share/applications" "${HOME}/.config/autostart"

# 1. Locate or build the compiled genesis-seek binary
SOURCE_BIN=""
if [[ -f "./src-tauri/target/release/${BIN_NAME}" ]]; then
    SOURCE_BIN="./src-tauri/target/release/${BIN_NAME}"
elif [[ -f "./${BIN_NAME}" ]]; then
    SOURCE_BIN="./${BIN_NAME}"
else
    echo "⚙️  Compiling Genesis Seek release binary (cargo build --release)..."
    (cd src-tauri && cargo build --release)
    SOURCE_BIN="./src-tauri/target/release/${BIN_NAME}"
fi

if [[ ! -f "${SOURCE_BIN}" ]]; then
    echo "❌ Could not find or build ${BIN_NAME} binary."
    exit 1
fi

# 2. Copy local YARA rules if present
if [[ -d "./rules" ]]; then
    cp -f ./rules/*.yar "${RULES_DIR}/" 2>/dev/null || true
fi

# 3. Install binary to /usr/local/bin and grant Linux capabilities via setcap
echo "🔐 Installing ${BIN_NAME} to ${INSTALL_BIN} and applying kernel capabilities..."
sudo install -m 0755 "${SOURCE_BIN}" "${INSTALL_BIN}"

if command -v setcap >/dev/null 2>&1; then
    sudo setcap 'cap_sys_admin,cap_dac_read_search,cap_sys_ptrace,cap_kill+ep' "${INSTALL_BIN}"
    echo "✅ Granted capabilities: cap_sys_admin,cap_dac_read_search,cap_sys_ptrace,cap_kill+ep"
    getcap "${INSTALL_BIN}" || true
else
    echo "⚠️  'setcap' (libcap2-bin) not found. Install libcap2-bin to enable unprivileged fanotify Tier 1."
fi

# 4. Install Polkit policy for privilege escalation fallback
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

# 5. Create Desktop Launcher & Autostart Entry
cat > "${DESKTOP_FILE}" <<EOF
[Desktop Entry]
Type=Application
Name=Genesis Seek Security Suite
Comment=Enterprise-Grade Endpoint, Process & Browser Protection (fanotify + YARA-X)
Exec=${INSTALL_BIN}
Icon=security-high
Terminal=false
Categories=System;Security;Utility;
StartupNotify=false
EOF

cp -f "${DESKTOP_FILE}" "${AUTOSTART_FILE}"
echo "✅ Installed Desktop & Autostart entries."
echo "🚀 Installation complete! Run '${BIN_NAME}' to launch Genesis Seek with Kernel Pre-Exec (fanotify) active."
