"""Hotspot Web Interface — Flask app with live status, client list, logs, and config editor."""

import hmac
import json
import logging
import os
import re
import shutil
import subprocess
import threading
import time
from collections import deque
from pathlib import Path

from flask import (
    Flask,
    Response,
    abort,
    jsonify,
    redirect,
    render_template,
    request,
    url_for,
)

app = Flask(__name__)

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------
TOKEN_FILE = "/etc/hotspot-web.token"
HOSTAPD_CONF = "/etc/hostapd/hostapd.conf"
STATE_FILE = "/run/hotspot.state"
LEASE_FILE = "/var/lib/misc/dnsmasq.leases"
LOG_FILE = "/var/log/dnsmasq-hotspot.log"
MAX_LOG_LINES = 500
MAX_SSE_CLIENTS = 4

# ---------------------------------------------------------------------------
# Auth helpers
# ---------------------------------------------------------------------------

def _read_token():
    try:
        return Path(TOKEN_FILE).read_text().strip()
    except OSError:
        return None


def _check_token():
    """Return True if the request carries a valid admin token."""
    expected = _read_token()
    if not expected:
        abort(503, "Admin token not configured")
    token = request.headers.get("Authorization", "")
    if token.startswith("Bearer "):
        token = token[7:]
    else:
        token = request.form.get("token", "")
    if not token:
        abort(401, "Missing admin token")
    if not hmac.compare_digest(token, expected):
        abort(403, "Invalid admin token")


# ---------------------------------------------------------------------------
# StatusPoller — single background thread, shared state dict
# ---------------------------------------------------------------------------

log = logging.getLogger(__name__)


class StatusPoller:
    def __init__(self):
        self._lock = threading.Lock()
        self._state = {}
        self._version = 0
        self._last_success = time.monotonic()
        self._thread = threading.Thread(target=self._poll_loop, daemon=True)
        self._thread.start()

    def _poll_loop(self):
        while True:
            try:
                data = self._gather()
                now = time.monotonic()
                with self._lock:
                    self._state = data
                    self._state["data_stale"] = False
                    self._version += 1
                    self._last_success = now
            except Exception:
                log.exception("StatusPoller gather failed")
                with self._lock:
                    if time.monotonic() - self._last_success > 10:
                        self._state["data_stale"] = True
            time.sleep(2)

    def get(self):
        with self._lock:
            return dict(self._state), self._version

    # -- data gathering (runs every 2s in bg thread) --

    def _gather(self):
        d = {}
        d["hotspot_running"] = Path(STATE_FILE).exists()

        # Uptime
        if d["hotspot_running"]:
            try:
                d["uptime_s"] = int(time.time() - Path(STATE_FILE).stat().st_mtime)
            except OSError:
                d["uptime_s"] = 0
        else:
            d["uptime_s"] = 0

        # Interface status (no subprocess)
        for iface in ("wwan0", "clat", "wlan0"):
            try:
                d[f"{iface}_up"] = Path(f"/sys/class/net/{iface}/operstate").read_text().strip() == "up"
            except OSError:
                d[f"{iface}_up"] = False

        # SSID from hostapd config
        try:
            for line in Path(HOSTAPD_CONF).read_text().splitlines():
                if line.startswith("ssid="):
                    d["ssid"] = line.split("=", 1)[1]
                    break
        except OSError:
            d["ssid"] = "unknown"

        # IPv6 address on wwan0
        try:
            r = subprocess.run(
                ["ip", "-6", "-o", "addr", "show", "wwan0", "scope", "global"],
                capture_output=True, text=True, timeout=5,
            )
            addrs = re.findall(r"inet6\s+(\S+)", r.stdout)
            d["wwan0_ipv6"] = addrs[0] if addrs else None
        except (subprocess.TimeoutExpired, OSError):
            d["wwan0_ipv6"] = None

        # IPv4 address on clat
        try:
            r = subprocess.run(
                ["ip", "-4", "-o", "addr", "show", "clat"],
                capture_output=True, text=True, timeout=5,
            )
            addrs = re.findall(r"inet\s+(\S+)", r.stdout)
            d["clat_ipv4"] = addrs[0] if addrs else None
        except (subprocess.TimeoutExpired, OSError):
            d["clat_ipv4"] = None

        # Firewall loaded?
        try:
            r = subprocess.run(
                ["nft", "list", "table", "ip", "hotspot_nat"],
                capture_output=True, timeout=5,
            )
            d["firewall_loaded"] = r.returncode == 0
        except (subprocess.TimeoutExpired, OSError):
            d["firewall_loaded"] = False

        # Clients (hostapd_cli all_sta)
        d["clients"] = self._gather_clients()

        return d

    def _gather_clients(self):
        clients = []
        try:
            r = subprocess.run(
                ["hostapd_cli", "all_sta"],
                capture_output=True, text=True, timeout=5,
            )
            if r.returncode == 0:
                clients = _parse_hostapd_sta(r.stdout)
        except (subprocess.TimeoutExpired, OSError):
            pass

        # Merge with DHCP leases
        leases = _read_leases()
        lease_by_mac = {l["mac"]: l for l in leases}
        for c in clients:
            info = lease_by_mac.pop(c["mac"], {})
            c["ip"] = info.get("ip", "")
            c["hostname"] = info.get("hostname", "")
        # Add leased-but-not-associated clients
        for l in lease_by_mac.values():
            clients.append({
                "mac": l["mac"],
                "ip": l.get("ip", ""),
                "hostname": l.get("hostname", ""),
                "rx_bytes": 0,
                "tx_bytes": 0,
                "connected_time": 0,
                "associated": False,
            })
        return clients


def _parse_hostapd_sta(text):
    """Parse hostapd_cli all_sta output into a list of client dicts."""
    clients = []
    current = None
    for line in text.splitlines():
        line = line.strip()
        if re.match(r"^[0-9a-fA-F]{2}(:[0-9a-fA-F]{2}){5}$", line):
            if current:
                clients.append(current)
            current = {
                "mac": line.lower(),
                "rx_bytes": 0,
                "tx_bytes": 0,
                "connected_time": 0,
                "associated": True,
            }
        elif current and "=" in line:
            key, _, val = line.partition("=")
            try:
                if key == "rx_bytes":
                    current["rx_bytes"] = int(val)
                elif key == "tx_bytes":
                    current["tx_bytes"] = int(val)
                elif key == "connected_time":
                    current["connected_time"] = int(val)
            except ValueError:
                pass
    if current:
        clients.append(current)
    return clients


def _read_leases():
    """Read dnsmasq leases file."""
    leases = []
    try:
        for line in Path(LEASE_FILE).read_text().splitlines():
            parts = line.split()
            if len(parts) >= 4:
                leases.append({
                    "mac": parts[1].lower(),
                    "ip": parts[2],
                    "hostname": parts[3] if parts[3] != "*" else "",
                })
    except OSError:
        pass
    return leases


def _format_bytes(n):
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024:
            return f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} TB"


def _format_duration(s):
    if s < 60:
        return f"{s}s"
    if s < 3600:
        return f"{s // 60}m {s % 60}s"
    h = s // 3600
    m = (s % 3600) // 60
    return f"{h}h {m}m"


app.jinja_env.globals["format_bytes"] = _format_bytes
app.jinja_env.globals["format_duration"] = _format_duration

# Lazy-init poller (avoids subprocess spam at import time during dev/testing)
_poller = None
_poller_init_lock = threading.Lock()


def _get_poller():
    global _poller
    if _poller is None:
        with _poller_init_lock:
            if _poller is None:
                _poller = StatusPoller()
    return _poller

# SSE connection counter
_sse_clients = 0
_sse_lock = threading.Lock()

# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.route("/")
def index():
    return redirect(url_for("dashboard"))


@app.route("/dashboard")
def dashboard():
    state, _ = _get_poller().get()
    return render_template("dashboard.html", state=state)


@app.route("/clients")
def clients():
    state, _ = _get_poller().get()
    return render_template("clients.html", clients=state.get("clients", []))


@app.route("/logs")
def logs():
    try:
        n = min(int(request.args.get("n", 100)), MAX_LOG_LINES)
    except (ValueError, TypeError):
        n = 100
    lines = []
    try:
        with open(LOG_FILE) as f:
            lines = list(deque(f, maxlen=n))
    except OSError:
        pass
    return render_template("logs.html", lines=lines, n=n)


@app.route("/config")
def config():
    fields = _read_hostapd_config()
    return render_template("config.html", fields=fields)


@app.route("/config", methods=["POST"])
def config_save():
    _check_token()

    ssid = request.form.get("ssid", "").strip()
    passphrase = request.form.get("wpa_passphrase", "").strip()
    channel_str = request.form.get("channel", "").strip()
    hw_mode = request.form.get("hw_mode", "g").strip()

    errors = []
    if not ssid or len(ssid) > 32:
        errors.append("SSID must be 1-32 characters")
    if not passphrase or len(passphrase) < 8 or len(passphrase) > 63:
        errors.append("Passphrase must be 8-63 characters")
    if passphrase and (re.search(r"[\x00\n\r]", passphrase) or not passphrase.isprintable()):
        errors.append("Passphrase contains invalid characters")
    valid_channels_g = set(range(1, 14))  # 1-13
    valid_channels_a = {36, 40, 44, 48, 52, 56, 60, 64,
                        100, 104, 108, 112, 116, 120, 124, 128, 132, 136, 140, 144,
                        149, 153, 157, 161, 165}
    if channel_str.lower() == "auto" or channel_str == "0":
        channel = 0
    elif channel_str.isdigit():
        channel = int(channel_str)
        valid = valid_channels_a if hw_mode == "a" else valid_channels_g
        if channel not in valid:
            errors.append(f"Invalid channel {channel} for {'5 GHz' if hw_mode == 'a' else '2.4 GHz'}")
            channel = 0
    else:
        errors.append("Channel must be auto or a valid channel number")
        channel = 0
    if hw_mode not in ("g", "a"):
        errors.append("hw_mode must be g or a")

    if errors:
        fields = _read_hostapd_config()
        fields.update({"ssid": ssid, "wpa_passphrase": passphrase,
                        "channel": channel_str, "hw_mode": hw_mode})
        return render_template("config.html", fields=fields, errors=errors), 400

    # Read current config, update only the known fields
    conf_path = Path(HOSTAPD_CONF)
    try:
        original = conf_path.read_text()
    except OSError:
        abort(500, "Cannot read hostapd.conf")

    new_conf = _update_hostapd_config(original, ssid, passphrase, channel, hw_mode)

    # Write to .new
    new_path = Path(HOSTAPD_CONF + ".new")
    new_path.write_text(new_conf)

    # Validate with hostapd -t
    try:
        r = subprocess.run(
            ["hostapd", "-t", str(new_path)],
            capture_output=True, text=True, timeout=5,
        )
        if r.returncode != 0:
            new_path.unlink(missing_ok=True)
            errors.append(f"hostapd validation failed: {r.stderr.strip()}")
            fields = {"ssid": ssid, "wpa_passphrase": passphrase,
                      "channel": str(channel), "hw_mode": hw_mode}
            return render_template("config.html", fields=fields, errors=errors), 400
    except (subprocess.TimeoutExpired, OSError) as e:
        new_path.unlink(missing_ok=True)
        abort(500, f"hostapd validation error: {e}")

    # Backup and atomic rename
    bak_path = Path(HOSTAPD_CONF + ".bak")
    try:
        shutil.copy2(str(conf_path), str(bak_path))
    except OSError:
        pass  # backup is best-effort
    os.replace(str(new_path), str(conf_path))

    fields = _read_hostapd_config()
    return render_template("config.html", fields=fields,
                           success="Configuration saved. Changes take effect after restarting the hotspot.")


@app.route("/stop", methods=["POST"])
def stop():
    _check_token()
    # Start hotspot stop in background after a short delay
    def _delayed_stop():
        time.sleep(1)
        subprocess.Popen(
            ["hotspot", "stop"],
            start_new_session=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    threading.Thread(target=_delayed_stop, daemon=True).start()
    return render_template("stopping.html")


# -- API endpoints --

@app.route("/api/status")
def api_status():
    state, _ = _get_poller().get()
    # Remove non-serializable bits
    safe = {k: v for k, v in state.items() if k != "clients"}
    safe["client_count"] = len(state.get("clients", []))
    return jsonify(safe)


@app.route("/api/clients")
def api_clients():
    state, _ = _get_poller().get()
    return jsonify(state.get("clients", []))


@app.route("/api/events")
def api_events():
    global _sse_clients
    with _sse_lock:
        if _sse_clients >= MAX_SSE_CLIENTS:
            abort(429, "Too many SSE connections")
        _sse_clients += 1

    def generate():
        global _sse_clients
        last_version = 0
        try:
            while True:
                state, version = _get_poller().get()
                if version != last_version:
                    last_version = version
                    safe = {k: v for k, v in state.items() if k != "clients"}
                    safe["client_count"] = len(state.get("clients", []))
                    yield f"data: {json.dumps(safe)}\n\n"
                time.sleep(2)
        finally:
            with _sse_lock:
                _sse_clients -= 1

    return Response(generate(), mimetype="text/event-stream",
                    headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


# ---------------------------------------------------------------------------
# Hostapd config helpers
# ---------------------------------------------------------------------------

def _read_hostapd_config():
    """Read hostapd.conf and return a dict of editable fields."""
    fields = {"ssid": "", "wpa_passphrase": "", "channel": "0", "hw_mode": "g"}
    try:
        for line in Path(HOSTAPD_CONF).read_text().splitlines():
            line = line.strip()
            if line.startswith("#") or "=" not in line:
                continue
            key, _, val = line.partition("=")
            if key in fields:
                fields[key] = val
    except OSError:
        pass
    return fields


def _update_hostapd_config(original, ssid, passphrase, channel, hw_mode):
    """Update known fields in hostapd config text, preserving all other lines."""
    updates = {
        "ssid": ssid,
        "wpa_passphrase": passphrase,
        "channel": str(channel),
        "hw_mode": hw_mode,
    }
    seen = set()
    lines = []
    for line in original.splitlines():
        stripped = line.strip()
        if stripped.startswith("#") or "=" not in stripped:
            lines.append(line)
            continue
        key, _, _ = stripped.partition("=")
        if key in updates:
            lines.append(f"{key}={updates[key]}")
            seen.add(key)
        else:
            lines.append(line)
    # Append any missing keys
    for key, val in updates.items():
        if key not in seen:
            lines.append(f"{key}={val}")
    return "\n".join(lines) + "\n"
