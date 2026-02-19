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

echo "Done. Run 'hotspot start' to start."
