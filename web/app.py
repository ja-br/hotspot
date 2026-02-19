"""Hotspot Web Interface — Flask app with live status, client list, logs, and config editor."""

import hmac
import ipaddress
import json
import logging
import os
import re
import shutil
import socket
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

DNSMASQ_PID_FILE = "/run/dnsmasq-hotspot.pid"
MONITORED_IFACES = ("wwan0", "clat", "wlan0")
SERVICES = {
    "hostapd":     {"label": "WiFi AP",    "pid_file": None,              "systemd": "hostapd",     "restartable": True},
    "dnsmasq":     {"label": "DHCP / DNS", "pid_file": DNSMASQ_PID_FILE, "systemd": None,          "restartable": False},
    "clatd":       {"label": "464XLAT",    "pid_file": None,              "systemd": "clatd",       "restartable": True},
    "hotspot-web": {"label": "Web UI",     "pid_file": None,              "systemd": "hotspot-web", "restartable": False},
}
DIAG_TIMEOUT = 10
MAX_PING_COUNT = 4

# ---------------------------------------------------------------------------
# Auth helpers
# ---------------------------------------------------------------------------

def _read_token():
    try:
        return Path(TOKEN_FILE).read_text().strip()
    except OSError:
        return None


def _check_token():
    """Abort if the request does not carry a valid admin token."""
    expected = _read_token()
    if not expected:
        abort(503, "Admin token not configured")
    token = request.headers.get("Authorization", "")
    if token.startswith("Bearer "):
        token = token[7:]
    else:
        token = request.form.get("token", "") or request.args.get("token", "")
    if not token:
        abort(401, "Missing admin token")
    if not hmac.compare_digest(token, expected):
        abort(403, "Invalid admin token")


def _check_token_or_redirect(endpoint):
    """For GET pages that require auth — return True if valid, False otherwise."""
    expected = _read_token()
    if not expected:
        return False
    token = request.headers.get("Authorization", "")
    if token.startswith("Bearer "):
        token = token[7:]
    else:
        token = request.args.get("token", "")
    if not token:
        return False
    return hmac.compare_digest(token, expected)


# ---------------------------------------------------------------------------
# Diagnostic helpers
# ---------------------------------------------------------------------------

_diag_semaphore = threading.Semaphore(1)


def _validate_target(target):
    """Validate and sanitize a ping/DNS target. Returns (sanitized, None) or (None, error)."""
    if not target or not isinstance(target, str):
        return None, "Target is required"
    target = target.strip()
    if not target:
        return None, "Target is required"
    if len(target) > 253:
        return None, "Target too long (max 253 characters)"

    # Try as IP address first
    try:
        addr = ipaddress.ip_address(target)
        if addr.is_loopback:
            return None, "Loopback addresses are not allowed"
        if addr.is_link_local:
            return None, "Link-local addresses are not allowed"
        if isinstance(addr, ipaddress.IPv4Address):
            if ipaddress.ip_address(target) in ipaddress.ip_network("192.168.4.0/24"):
                return None, "Hotspot subnet addresses are not allowed"
        if isinstance(addr, ipaddress.IPv6Address):
            if addr.ipv4_mapped:
                return None, "IPv4-mapped IPv6 addresses are not allowed"
        return target, None
    except ValueError:
        pass

    # Validate as hostname
    if target.endswith("."):
        target = target[:-1]
    labels = target.split(".")
    if not labels or any(l == "" for l in labels):
        return None, "Invalid hostname"
    label_re = re.compile(r"^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?$")
    for label in labels:
        if len(label) > 63:
            return None, f"Label '{label}' exceeds 63 characters"
        if not label_re.match(label):
            return None, f"Invalid label '{label}'"
    return target, None


def _run_diag(args, timeout=DIAG_TIMEOUT):
    """Run a diagnostic subprocess safely. Returns (stdout, stderr, returncode)."""
    try:
        r = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
        return r.stdout, r.stderr, r.returncode
    except subprocess.TimeoutExpired:
        return "", "Command timed out", -1
    except FileNotFoundError:
        return "", "Command not found", -1
    except OSError as e:
        return "", str(e), -1


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
        self._prev_cpu_times = None
        self._prev_iface_stats = {}
        self._prev_iface_time = 0.0
        self._service_pids = {}
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

        # Hostname
        try:
            d["hostname"] = socket.gethostname()
        except OSError:
            d["hostname"] = "unknown"

        # Hotspot uptime
        if d["hotspot_running"]:
            try:
                d["uptime_s"] = int(time.time() - Path(STATE_FILE).stat().st_mtime)
            except OSError:
                d["uptime_s"] = 0
        else:
            d["uptime_s"] = 0

        # Interface status (no subprocess)
        for iface in MONITORED_IFACES:
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

        # IPv6 gateway
        try:
            r = subprocess.run(
                ["ip", "-6", "route", "show", "default"],
                capture_output=True, text=True, timeout=5,
            )
            m = re.match(r"default\s+via\s+(\S+)\s+dev\s+(\S+)", r.stdout.strip())
            if m:
                d["gw6_addr"] = m.group(1)
                d["gw6_dev"] = m.group(2)
            else:
                d["gw6_addr"] = None
                d["gw6_dev"] = None
        except (subprocess.TimeoutExpired, OSError):
            d["gw6_addr"] = None
            d["gw6_dev"] = None

        # System info (CPU, mem, load, disk, uptime — all from /proc and os)
        self._gather_system_info(d)

        # Interface traffic (sysfs only)
        self._gather_iface_traffic(d)

        # Interface details for status page
        self._gather_iface_details(d)

        # Service status
        self._gather_services(d)

        # Clients (hostapd_cli all_sta)
        d["clients"] = self._gather_clients()

        return d

    def _gather_system_info(self, d):
        """Read CPU, memory, load, uptime, disk from /proc and os — no subprocesses."""
        # CPU usage from /proc/stat delta
        try:
            line = Path("/proc/stat").read_text().split("\n", 1)[0]
            parts = line.split()
            # user, nice, system, idle, iowait, irq, softirq, steal
            if len(parts) >= 8:
                times = tuple(int(x) for x in parts[1:8])
                if self._prev_cpu_times:
                    deltas = tuple(a - b for a, b in zip(times, self._prev_cpu_times))
                    total = sum(deltas)
                    idle = deltas[3]  # idle is 4th field (index 3)
                    d["cpu_pct"] = round((1 - idle / total) * 100, 1) if total > 0 else 0
                else:
                    d["cpu_pct"] = 0
                self._prev_cpu_times = times
            else:
                d["cpu_pct"] = 0
        except (OSError, ValueError, ZeroDivisionError):
            d["cpu_pct"] = 0

        # Memory from /proc/meminfo
        try:
            meminfo = {}
            for line in Path("/proc/meminfo").read_text().splitlines():
                parts = line.split()
                if len(parts) >= 2:
                    meminfo[parts[0].rstrip(":")] = int(parts[1])
            mem_total = meminfo.get("MemTotal", 0)
            mem_avail = meminfo.get("MemAvailable", 0)
            mem_used = mem_total - mem_avail
            d["mem_total_kb"] = mem_total
            d["mem_used_kb"] = mem_used
            d["mem_pct"] = round(mem_used / mem_total * 100, 1) if mem_total > 0 else 0
        except (OSError, ValueError, ZeroDivisionError):
            d["mem_total_kb"] = 0
            d["mem_used_kb"] = 0
            d["mem_pct"] = 0

        # Load average from /proc/loadavg
        try:
            parts = Path("/proc/loadavg").read_text().split()
            d["load_1"] = float(parts[0])
            d["load_5"] = float(parts[1])
            d["load_15"] = float(parts[2])
        except (OSError, ValueError, IndexError):
            d["load_1"] = 0
            d["load_5"] = 0
            d["load_15"] = 0

        # System uptime from /proc/uptime
        try:
            d["sys_uptime_s"] = int(float(Path("/proc/uptime").read_text().split()[0]))
        except (OSError, ValueError, IndexError):
            d["sys_uptime_s"] = 0

        # Disk usage
        try:
            st = os.statvfs("/")
            total = st.f_blocks * st.f_frsize
            free = st.f_bavail * st.f_frsize
            used = total - free
            d["disk_total"] = total
            d["disk_used"] = used
            d["disk_pct"] = round(used / total * 100, 1) if total > 0 else 0
        except OSError:
            d["disk_total"] = 0
            d["disk_used"] = 0
            d["disk_pct"] = 0

    def _gather_iface_traffic(self, d):
        """Read per-interface byte/packet counters from sysfs. Compute rates from deltas."""
        now = time.monotonic()
        elapsed = now - self._prev_iface_time if self._prev_iface_time else 0
        iface_traffic = {}

        for iface in MONITORED_IFACES:
            stats = {}
            base = f"/sys/class/net/{iface}/statistics"
            for key in ("rx_bytes", "tx_bytes", "rx_packets", "tx_packets", "rx_errors", "tx_errors"):
                try:
                    stats[key] = int(Path(f"{base}/{key}").read_text().strip())
                except (OSError, ValueError):
                    stats[key] = 0

            # Compute rates
            prev = self._prev_iface_stats.get(iface, {})
            if elapsed > 0 and prev:
                stats["rx_bps"] = max(0, int((stats["rx_bytes"] - prev.get("rx_bytes", 0)) / elapsed))
                stats["tx_bps"] = max(0, int((stats["tx_bytes"] - prev.get("tx_bytes", 0)) / elapsed))
            else:
                stats["rx_bps"] = 0
                stats["tx_bps"] = 0

            iface_traffic[iface] = stats
            self._prev_iface_stats[iface] = {"rx_bytes": stats["rx_bytes"], "tx_bytes": stats["tx_bytes"]}

        self._prev_iface_time = now
        d["iface_traffic"] = iface_traffic

        # Flat keys for SSE
        for iface in MONITORED_IFACES:
            t = iface_traffic.get(iface, {})
            d[f"{iface}_rx_bps"] = t.get("rx_bps", 0)
            d[f"{iface}_tx_bps"] = t.get("tx_bps", 0)

    def _gather_iface_details(self, d):
        """Gather per-interface details (MTU, operstate, addresses) from sysfs and existing data."""
        iface_details = {}
        for iface in MONITORED_IFACES:
            info = {"name": iface, "up": d.get(f"{iface}_up", False)}

            # MTU from sysfs
            try:
                info["mtu"] = int(Path(f"/sys/class/net/{iface}/mtu").read_text().strip())
            except (OSError, ValueError):
                info["mtu"] = 0

            # Addresses — reuse existing data, no extra subprocess
            addrs = []
            if iface == "wwan0" and d.get("wwan0_ipv6"):
                addrs.append(f"inet6 {d['wwan0_ipv6']}")
            elif iface == "clat" and d.get("clat_ipv4"):
                addrs.append(f"inet {d['clat_ipv4']}")
            elif iface == "wlan0":
                addrs.append("inet 192.168.4.1/24")
            info["addresses"] = addrs

            # Traffic from iface_traffic
            traffic = d.get("iface_traffic", {}).get(iface, {})
            info["rx_bytes"] = traffic.get("rx_bytes", 0)
            info["tx_bytes"] = traffic.get("tx_bytes", 0)
            info["rx_packets"] = traffic.get("rx_packets", 0)
            info["tx_packets"] = traffic.get("tx_packets", 0)
            info["rx_errors"] = traffic.get("rx_errors", 0)
            info["tx_errors"] = traffic.get("tx_errors", 0)
            info["rx_bps"] = traffic.get("rx_bps", 0)
            info["tx_bps"] = traffic.get("tx_bps", 0)

            iface_details[iface] = info
        d["iface_details"] = iface_details

    def _gather_services(self, d):
        """Check service status via PID files and /proc. Minimal subprocess use."""
        services = {}
        for name, svc in SERVICES.items():
            info = {"label": svc["label"], "running": False, "pid": None}
            pid = None

            # Get PID
            if svc["pid_file"]:
                try:
                    pid = int(Path(svc["pid_file"]).read_text().strip())
                except (OSError, ValueError):
                    pid = None
            elif svc["systemd"]:
                # Use cached PID if we have one
                cached = self._service_pids.get(name)
                if cached and Path(f"/proc/{cached}/stat").exists():
                    pid = cached
                else:
                    # Look up PID from systemd (only when cache miss)
                    try:
                        r = subprocess.run(
                            ["systemctl", "show", "-p", "MainPID", "--value", svc["systemd"]],
                            capture_output=True, text=True, timeout=5,
                        )
                        p = int(r.stdout.strip())
                        pid = p if p > 0 else None
                    except (subprocess.TimeoutExpired, OSError, ValueError):
                        pid = None

            # Check if PID is alive
            if pid:
                if Path(f"/proc/{pid}/stat").exists():
                    info["running"] = True
                    info["pid"] = pid
                    self._service_pids[name] = pid
                else:
                    self._service_pids.pop(name, None)

            services[name] = info

        d["services"] = services

        # Flat keys for SSE
        d["svc_hostapd"] = services.get("hostapd", {}).get("running", False)
        d["svc_dnsmasq"] = services.get("dnsmasq", {}).get("running", False)
        d["svc_clatd"] = services.get("clatd", {}).get("running", False)
        d["svc_hotspotweb"] = services.get("hotspot-web", {}).get("running", False)

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


def _format_rate(bps):
    """Format bytes/sec to human-readable rate."""
    if bps < 1024:
        return f"{bps} B/s"
    elif bps < 1024 * 1024:
        return f"{bps / 1024:.1f} KB/s"
    else:
        return f"{bps / (1024 * 1024):.1f} MB/s"


app.jinja_env.globals["format_bytes"] = _format_bytes
app.jinja_env.globals["format_duration"] = _format_duration
app.jinja_env.globals["format_rate"] = _format_rate

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


# -- Status pages --

@app.route("/status/interfaces")
def status_interfaces():
    state, _ = _get_poller().get()
    return render_template("status/interfaces.html",
                           ifaces=state.get("iface_details", {}))


@app.route("/status/services")
def status_services():
    state, _ = _get_poller().get()
    return render_template("status/services.html",
                           services=state.get("services", {}),
                           svc_meta=SERVICES,
                           firewall_loaded=state.get("firewall_loaded", False))


@app.route("/status/services/<name>/restart", methods=["POST"])
def service_restart(name):
    _check_token()
    svc = SERVICES.get(name)
    if not svc or not svc["restartable"]:
        abort(404)

    def _do_restart():
        time.sleep(1)
        try:
            subprocess.run(["systemctl", "restart", svc["systemd"]], timeout=15)
        except (subprocess.TimeoutExpired, OSError):
            pass

    threading.Thread(target=_do_restart, daemon=True).start()
    return jsonify({"ok": True, "message": f"Restarting {svc['label']}..."})


@app.route("/status/firewall")
def status_firewall():
    if not _check_token_or_redirect("status_firewall"):
        return render_template("status/firewall.html", authed=False, rules="")
    try:
        r = subprocess.run(
            ["nft", "list", "ruleset"],
            capture_output=True, text=True, timeout=10,
        )
        rules = r.stdout if r.returncode == 0 else f"Error: {r.stderr}"
    except (subprocess.TimeoutExpired, OSError) as e:
        rules = f"Error: {e}"
    return render_template("status/firewall.html", authed=True, rules=rules)


# -- Diagnostic pages --

@app.route("/diag/arp")
def diag_arp():
    if not _check_token_or_redirect("diag_arp"):
        return render_template("diag/arp.html", authed=False, entries=[])
    try:
        text = Path("/proc/net/arp").read_text()
        lines = text.strip().splitlines()[1:]  # skip header
        entries = []
        for line in lines:
            parts = line.split()
            if len(parts) >= 6:
                entries.append({
                    "ip": parts[0],
                    "flags": parts[2],
                    "mac": parts[3],
                    "iface": parts[5],
                })
    except OSError:
        entries = []
    return render_template("diag/arp.html", authed=True, entries=entries)


@app.route("/diag/routes")
def diag_routes():
    if not _check_token_or_redirect("diag_routes"):
        return render_template("diag/routes.html", authed=False, ipv4="", ipv6="")
    stdout4, _, _ = _run_diag(["ip", "-4", "route"])
    stdout6, _, _ = _run_diag(["ip", "-6", "route"])
    return render_template("diag/routes.html", authed=True, ipv4=stdout4, ipv6=stdout6)


@app.route("/diag/ping", methods=["GET"])
def diag_ping_form():
    if not _check_token_or_redirect("diag_ping_form"):
        return render_template("diag/ping.html", authed=False, output=None, target="")
    return render_template("diag/ping.html", authed=True, output=None, target="")


@app.route("/diag/ping", methods=["POST"])
def diag_ping_run():
    _check_token()
    target = request.form.get("target", "")
    sanitized, err = _validate_target(target)
    if err:
        return render_template("diag/ping.html", authed=True, output=f"Error: {err}", target=target)

    if not _diag_semaphore.acquire(blocking=False):
        return render_template("diag/ping.html", authed=True,
                               output="Error: Another diagnostic is already running. Try again shortly.",
                               target=target)
    try:
        stdout, stderr, rc = _run_diag(
            ["ping", "-c", str(MAX_PING_COUNT), "-W", "3", sanitized],
            timeout=DIAG_TIMEOUT,
        )
        output = stdout if stdout else stderr
    finally:
        _diag_semaphore.release()

    return render_template("diag/ping.html", authed=True, output=output, target=target)


@app.route("/diag/dns", methods=["GET"])
def diag_dns_form():
    if not _check_token_or_redirect("diag_dns_form"):
        return render_template("diag/dns.html", authed=False, output=None, target="", qtype="A")
    return render_template("diag/dns.html", authed=True, output=None, target="", qtype="A")


@app.route("/diag/dns", methods=["POST"])
def diag_dns_run():
    _check_token()
    target = request.form.get("target", "")
    qtype = request.form.get("qtype", "A").upper()
    valid_qtypes = {"A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA", "PTR"}
    if qtype not in valid_qtypes:
        qtype = "A"

    sanitized, err = _validate_target(target)
    if err:
        return render_template("diag/dns.html", authed=True, output=f"Error: {err}",
                               target=target, qtype=qtype)

    if not _diag_semaphore.acquire(blocking=False):
        return render_template("diag/dns.html", authed=True,
                               output="Error: Another diagnostic is already running. Try again shortly.",
                               target=target, qtype=qtype)
    try:
        # Try nslookup first (more commonly available), fall back to dig
        stdout, stderr, rc = _run_diag(
            ["nslookup", f"-type={qtype}", sanitized],
            timeout=DIAG_TIMEOUT,
        )
        if rc == -1 and "not found" in stderr:
            stdout, stderr, rc = _run_diag(
                ["dig", sanitized, qtype, "+noall", "+answer", "+comments"],
                timeout=DIAG_TIMEOUT,
            )
        output = stdout if stdout else stderr
    finally:
        _diag_semaphore.release()

    return render_template("diag/dns.html", authed=True, output=output,
                           target=target, qtype=qtype)


# -- API endpoints --

@app.route("/api/status")
def api_status():
    state, _ = _get_poller().get()
    # Remove non-serializable bits and large dicts
    exclude = {"clients", "iface_traffic", "iface_details", "services"}
    safe = {k: v for k, v in state.items() if k not in exclude}
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
                    exclude = {"clients", "iface_traffic", "iface_details", "services"}
                    safe = {k: v for k, v in state.items() if k not in exclude}
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
