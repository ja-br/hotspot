#!/bin/bash
# Install hotspot files from this repo to their system locations
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

echo "Installing hotspot files..."

sudo install -m 0755 "$SCRIPT_DIR/hotspot" /usr/local/bin/hotspot
sudo install -m 0644 "$SCRIPT_DIR/dnsmasq.conf" /etc/dnsmasq.d/hotspot.conf
sudo install -m 0600 "$SCRIPT_DIR/hostapd.conf" /etc/hostapd/hostapd.conf
sudo install -m 0644 "$SCRIPT_DIR/nftables-hotspot.conf" /etc/nftables-hotspot.conf
sudo install -m 0644 "$SCRIPT_DIR/tayga.conf" /etc/tayga.conf

echo "Done. Run 'hotspot start' to start."
