#!/bin/bash
# Install hotspot files from this repo to their system locations
set -euo pipefail

if [ "$(id -u)" -ne 0 ]; then
    echo "This script must be run as root (sudo ./install.sh)"
    exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

echo "Installing hotspot files..."

install -m 0755 "$SCRIPT_DIR/hotspot" /usr/local/bin/hotspot
install -m 0644 "$SCRIPT_DIR/dnsmasq.conf" /etc/dnsmasq.d/hotspot.conf

if [ -f "$SCRIPT_DIR/hostapd.conf" ]; then
    install -m 0600 "$SCRIPT_DIR/hostapd.conf" /etc/hostapd/hostapd.conf
elif [ ! -f /etc/hostapd/hostapd.conf ]; then
    echo "WARNING: hostapd.conf not found locally or at /etc/hostapd/hostapd.conf"
    echo "You must create /etc/hostapd/hostapd.conf with your SSID and passphrase before running the hotspot."
fi

# --- Web interface ---
echo "Installing web interface..."

WEB_DIR="/usr/local/lib/hotspot-web"
VENV_DIR="/opt/hotspot-web/venv"

# Create venv and install dependencies
if [ ! -d "$VENV_DIR" ]; then
    echo "Creating Python venv at $VENV_DIR..."
    mkdir -p /opt/hotspot-web
    python3 -m venv "$VENV_DIR"
fi
"$VENV_DIR/bin/pip" install --quiet -r "$SCRIPT_DIR/web/requirements.txt"

# Copy web files
mkdir -p "$WEB_DIR"
cp -r "$SCRIPT_DIR/web/"* "$WEB_DIR/"

# Install systemd unit
install -m 0644 "$SCRIPT_DIR/hotspot-web.service" /etc/systemd/system/hotspot-web.service
systemctl daemon-reload
systemctl enable hotspot-web

# Generate Flask secret key if it doesn't exist (separate from auth token)
if [ ! -f /etc/hotspot-web.secret ]; then
    (umask 077; openssl rand -hex 32 > /etc/hotspot-web.secret)
fi

# Generate admin token if it doesn't exist
if [ ! -f /etc/hotspot-web.token ]; then
    (umask 077; openssl rand -hex 16 > /etc/hotspot-web.token)
    echo "Admin token generated. View with: sudo cat /etc/hotspot-web.token"
else
    echo "Admin token already exists at /etc/hotspot-web.token"
fi

echo "Done. Run 'hotspot start' to start."
