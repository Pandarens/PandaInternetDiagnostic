"""Router drivers. Each returns a normalized dict:

{type, reachable, auth, model, firmware, uptime_sec, cpu_load, mem_pct, temperature, clients,
 wan: {link, connected, proto, ip, gateway, dns, uptime_sec, error_code, error_text, link_speed_mbps, rx_errors, ...},
 ports: [{name, link, speed_mbps, duplex}], optics: {rx_dbm, tx_dbm, temp_c, ...}, log: [str], notes: [str], raw: {...},
 devices: [...], wifi_radios: [{band, channel, width, ssid, txpower}], wifi_scan: [{ssid, bssid, channel, signal_dbm, width}]}
"""
import json
import re
import ssl
import urllib.error
import urllib.parse
import urllib.request

UA = {"User-Agent": "PandaInternetDiagnostic/1.0"}


def _http(url, data=None, headers=None, timeout=5, method=None, context=None):
    h = dict(UA)
    h.update(headers or {})
    if isinstance(data, dict):
        data = urllib.parse.urlencode(data).encode()
    req = urllib.request.Request(url, data=data, headers=h, method=method)
    with urllib.request.urlopen(req, timeout=timeout, context=context) as r:
        return r.status, r.read().decode("utf-8", errors="replace")


def _empty(kind):
    return {"type": kind, "reachable": False, "auth": None, "model": None, "firmware": None,
            "uptime_sec": None, "cpu_load": None, "mem_pct": None, "temperature": None, "clients": None,
            "wan": {}, "ports": [], "optics": {}, "log": [], "notes": [], "raw": {},
            # devices: [{name, ip, mac, conn, down_bps, up_bps, down_bytes, up_bytes, signal_dbm}]
            "devices": [], "wifi_radios": [], "wifi_scan": []}


def _to_int(v):
    try:
        return int(float(str(v).strip()))
    except (TypeError, ValueError):
        return None


def _to_float(v):
    try:
        return float(str(v).strip())
    except (TypeError, ValueError):
        return None


INSECURE = ssl._create_unverified_context()  # home routers use self-signed certificates


def http_json(url, **kw):
    status, body = _http(url, **kw)
    return json.loads(body)


def first(*vals):
    for v in vals:
        if v not in (None, "", [], {}):
            return v
    return None


def parse_dbm(v):
    """Optical power in various vendor encodings -> dBm."""
    if v in (None, ""):
        return None
    s = str(v).strip().lower().replace("dbm", "").strip()
    try:
        f = float(s)
    except ValueError:
        m = re.search(r"-?\d+(?:\.\d+)?", s)
        if not m:
            return None
        f = float(m.group(0))
    if f < -100 or f > 100:      # ZTE reports e.g. -2034 meaning -20.34 dBm; some report 1/10000 mW
        f = f / 100.0 if abs(f) < 10000 else f / 1000.0
    return round(f, 2)


class RouterDriver:
    """Interface for router drivers."""
    kind = "base"

    def collect(self, full=True):
        raise NotImplementedError


def band_of(channel):
    ch = _to_int(channel)
    if ch is None:
        return None
    return "2.4" if ch <= 14 else ("6" if ch > 177 else "5")
