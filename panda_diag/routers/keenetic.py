"""Keenetic (Zyxel Keenetic, Keenetic Giga/Ultra/Viva/Hero/...) — RCI HTTP API."""
import hashlib
import http.cookiejar
import json
import urllib.error
import urllib.request

from .base import UA, _empty, _to_float, _to_int, band_of


class KeeneticRouter:
    kind = "keenetic"

    def __init__(self, host, username, password, timeout=6):
        self.base = f"http://{host}"
        self.username = username or "admin"
        self.password = password or ""
        self.timeout = timeout
        self.opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))

    def _open(self, path, payload=None):
        data = json.dumps(payload).encode() if payload is not None else None
        req = urllib.request.Request(self.base + path, data=data, headers=dict(UA, **{"Content-Type": "application/json"}))
        return self.opener.open(req, timeout=self.timeout)

    def login(self):
        try:
            self._open("/auth")
            return True  # no password configured on the router
        except urllib.error.HTTPError as e:
            if e.code != 401:
                raise
            realm, challenge = e.headers.get("X-NDM-Realm"), e.headers.get("X-NDM-Challenge")
        md5 = hashlib.md5(f"{self.username}:{realm}:{self.password}".encode()).hexdigest()
        pwd = hashlib.sha256((challenge + md5).encode()).hexdigest()
        try:
            self._open("/auth", {"login": self.username, "password": pwd})
            return True
        except urllib.error.HTTPError:
            return False

    def rci(self, path):
        with self._open("/rci/" + path) as r:
            return json.loads(r.read().decode("utf-8", errors="replace"))

    def collect(self, full=True):
        out = _empty(self.kind)
        try:
            ok = self.login()
        except Exception as e:  # noqa: BLE001
            out["notes"].append(f"Keenetic не отвечает: {e}")
            return out
        out["reachable"] = True
        if not ok:
            out["auth"] = "failed"
            out["notes"].append("Keenetic: неверный логин/пароль администратора.")
            return out
        out["auth"] = "ok"
        raw = out["raw"]
        for key, path in (("version", "show/version"), ("system", "show/system"), ("interface", "show/interface"),
                          ("internet", "show/internet/status"), ("hotspot", "show/ip/hotspot"),
                          ("log", "show/log?max-lines=150")):
            if not full and key in ("hotspot", "log"):
                continue
            try:
                raw[key] = self.rci(path)
            except Exception:  # noqa: BLE001
                pass

        ver = raw.get("version") or {}
        out["model"] = ver.get("model") or ver.get("device")
        out["firmware"] = ver.get("release") or ver.get("title")
        sysinfo = raw.get("system") or {}
        out["cpu_load"] = _to_float(sysinfo.get("cpuload"))
        mem = str(sysinfo.get("memory") or "")
        if "/" in mem:
            used, total = (_to_int(x) for x in mem.split("/")[:2])
            if used is not None and total:
                out["mem_pct"] = round(100 * used / total, 1)
        out["uptime_sec"] = _to_int(sysinfo.get("uptime"))

        wan = out["wan"]
        inet = raw.get("internet") or {}
        if inet:
            wan["internet_check"] = inet.get("internet")
            wan["gateway"] = (inet.get("gateway") or {}).get("interface") if isinstance(inet.get("gateway"), dict) else inet.get("gateway")

        ifaces = raw.get("interface") or {}
        wan_iface = None
        for name, i in ifaces.items():
            if not isinstance(i, dict):
                continue
            itype = i.get("type", "")
            if itype == "Port" or (i.get("link") is not None and i.get("speed")):
                out["ports"].append({"name": i.get("label") or name, "link": i.get("link") == "up",
                                     "speed_mbps": _to_int(i.get("speed")), "duplex": i.get("duplex"),
                                     "wan": str(i.get("role", "")).find("inet") >= 0 or "WAN" in str(i.get("description", "")).upper()})
            if i.get("defaultgw") or (i.get("global") and itype in ("PPPoE", "L2TP", "PPTP", "GigabitEthernet", "Vlan", "IPoE", "UsbLte", "UsbQmi")):
                if wan_iface is None or i.get("defaultgw"):
                    wan_iface = (name, i)
            if itype.startswith("WifiMaster") or itype in ("WifiMaster",):
                ch = _to_int(i.get("channel"))
                out["wifi_radios"].append({"band": band_of(ch), "channel": ch, "width": _to_int(i.get("bandwidth")),
                                           "iface": name, "enabled": i.get("state") == "up", "txpower": i.get("power")})
            if itype == "AccessPoint" and i.get("ssid"):
                for r in out["wifi_radios"]:
                    if name.startswith(r["iface"]) and not r.get("ssid"):
                        r["ssid"] = i.get("ssid")
        if wan_iface:
            name, i = wan_iface
            wan.update({"iface": name, "proto": i.get("type"), "connected": i.get("connected") == "yes",
                        "link": i.get("link") == "up" if i.get("link") else None, "ip": i.get("address"),
                        "uptime_sec": _to_int(i.get("uptime")), "state": i.get("state")})
            if i.get("type") in ("PPPoE", "L2TP", "PPTP") and i.get("via"):
                via = ifaces.get(i["via"]) or {}
                wan["link"] = via.get("link") == "up" if via.get("link") else wan.get("link")
        for p in out["ports"]:
            if p["wan"]:
                wan.setdefault("link_speed_mbps", p["speed_mbps"])
                if wan.get("link") is None:
                    wan["link"] = p["link"]

        if full:
            for path in ("show/site-survey?name=WifiMaster0", "show/site-survey?name=WifiMaster1"):
                try:
                    res = self.rci(path)
                    for ap in (res.get("ap") or res.get("site-survey") or []) if isinstance(res, dict) else []:
                        out["wifi_scan"].append({"ssid": ap.get("essid") or ap.get("ssid"), "bssid": ap.get("mac") or ap.get("bssid"),
                                                 "channel": _to_int(ap.get("channel")), "signal_dbm": _to_int(ap.get("rssi")),
                                                 "width": _to_int(ap.get("bandwidth"))})
                except Exception:  # noqa: BLE001
                    pass

        hosts = (raw.get("hotspot") or {}).get("host") or []
        for h in hosts:
            if not h.get("active"):
                continue
            conn = "Wi-Fi" if h.get("ssid") else "LAN"
            if h.get("ssid") and h.get("ap"):
                conn = f"Wi-Fi {h.get('ap')}"
            out["devices"].append({"mac": (h.get("mac") or "").lower(), "ip": h.get("ip"),
                                   "name": h.get("name") or h.get("hostname"), "conn": conn,
                                   "down_bytes": _to_int(h.get("rxbytes")), "up_bytes": _to_int(h.get("txbytes")),
                                   "signal_dbm": _to_int(h.get("rssi")), "link_mbps": _to_int(h.get("speed"))})

        logs = (raw.get("log") or {}).get("log") or {}
        items = logs.values() if isinstance(logs, dict) else logs
        lines = []
        for e in items:
            msg = e.get("message")
            msg = msg.get("message") if isinstance(msg, dict) else msg
            text = f"{e.get('timestamp')} {e.get('ident')}: {msg}"
            if any(w in text.lower() for w in ("pppoe", "dhcp", "link", "wan", "error", "failed", "down", "carrier", "ipoe", "internet")):
                lines.append(text)
        out["log"] = lines[-40:]
        return out
