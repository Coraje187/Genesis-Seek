#!/usr/bin/env bash
# ==============================================================================
#  🛡️ Genesis Seek — One-Line Linux Installer
#  Endpoint Defense, Behavioral Heuristics & Real-Time Shield
# ==============================================================================
set -e

REPO="Coraje187/Genesis-Seek"
VERSION="v0.2.0"
INSTALL_DIR="$HOME/.local/bin"
DESKTOP_DIR="$HOME/.local/share/applications"
ICON_DIR="$HOME/.local/share/icons/hicolor/512x512/apps"

echo "=========================================================="
echo "  🛡️ Installing Genesis Seek ($VERSION) for Linux"
echo "=========================================================="

mkdir -p "$INSTALL_DIR" "$DESKTOP_DIR" "$ICON_DIR"

# Download the latest Linux AppImage from GitHub release
DOWNLOAD_URL="https://github.com/$REPO/releases/download/$VERSION/genesis-seek-v0.1.0-linux-x86_64.tar.gz"
TEMP_DIR=$(mktemp -d)
trap 'rm -rf "$TEMP_DIR"' EXIT

echo "--> Downloading Genesis Seek bundle from GitHub..."
if command -v curl >/dev/null 2>&1; then
    curl -fsSL "$DOWNLOAD_URL" -o "$TEMP_DIR/bundle.tar.gz"
elif command -v wget >/dev/null 2>&1; then
    wget -q "$DOWNLOAD_URL" -O "$TEMP_DIR/bundle.tar.gz"
else
    echo "Error: curl or wget is required to download Genesis Seek."
    exit 1
fi

echo "--> Extracting into $INSTALL_DIR..."
tar -xzf "$TEMP_DIR/bundle.tar.gz" -C "$TEMP_DIR"

if [ -f "$TEMP_DIR/genesis-seek-v0.1.0-linux-x86_64/genesis-seek" ]; then
    cp "$TEMP_DIR/genesis-seek-v0.1.0-linux-x86_64/genesis-seek" "$INSTALL_DIR/genesis-seek"
    chmod +x "$INSTALL_DIR/genesis-seek"
else
    echo "Error: Could not find extracted binary."
    exit 1
fi

# Download desktop icon
ICON_URL="https://raw.githubusercontent.com/$REPO/main/ui/assets/logo-mark.svg"
curl -fsSL "$ICON_URL" -o "$ICON_DIR/genesis-seek.svg" 2>/dev/null || true

# Register Desktop Application entry
cat << 'EOF' > "$DESKTOP_DIR/genesis-seek.desktop"
[Desktop Entry]
Name=Genesis Seek
Comment=Endpoint Threat Defense & Browser Guard
Exec=genesis-seek
Icon=genesis-seek
Terminal=false
Type=Application
Categories=Utility;Security;System;
StartupNotify=true
EOF

chmod +x "$DESKTOP_DIR/genesis-seek.desktop"

echo ""
echo "=========================================================="
echo "  ✅ Genesis Seek installed successfully!"
echo "=========================================================="
echo "  • Executable: $INSTALL_DIR/genesis-seek"
echo "  • Desktop shortcut created in Application menu."
echo ""
echo "  Launch anytime by running:  genesis-seek"
echo "  Or search 'Genesis Seek' in your application launcher."
echo ""
echo "  🌐 Firefox Browser Guard:"
echo "  Install with 1-click in the app, or directly from AMO:"
echo "  https://addons.mozilla.org/en-US/firefox/addon/genesis-seek-browser-guard/"
echo "=========================================================="
