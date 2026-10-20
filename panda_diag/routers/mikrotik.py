"""MikroTik RouterOS 7 REST API."""
import base64
import json
import re
import ssl
import urllib.error

from .base import _http, _empty, _to_int, _to_float, band_of


# =========================================================================== MikroTik (RouterOS 7 REST)

class MikroTikRouter:
    kind = "mikrotik"

    def __init__(self, host, username, password, https=True, wan_interface="ether1", timeout=5):
        self.base = f"{'https' if https else 'http'}://{host}/rest"
        self.auth = "Basic " + base64.b64encode(f"{username}:{password}".encode()).decode()
        self.wan = wan_interface
        self.timeout = timeout
        self.ctx = ssl._create_unverified_context() if https else None  # router uses a self-signed cert
        self.has_password = bool(password)

    def _req(self, path, payload=None):
        data = json.dumps(payload).encode() if payload is not None else None
        _, body = _http(self.base + path, data=data, timeout=self.timeout, context=self.ctx,
                        headers={"Authorization": self.auth, "Content-Type": "application/json"},
                        method="POST" if payload is not None else "GET")
        return json.loads(body)

    def collect(self, full=True):
        out = _empty(self.kind)
        if not self.has_password:
            out["auth"] = "no_password"
            out["notes"].append("Логин/пароль MikroTik не заданы в config.json (нужен пользователь с правами read и включённый www/www-ssl).")
        try:
            res = self._req("/system/resource")
        except urllib.error.HTTPError as e:
            out["reachable"] = True
            out["auth"] = "failed"
            out["notes"].append(f"MikroTik REST: HTTP {e.code} — проверьте логин/пароль и права пользователя.")
            return out
        except Exception as e:  # noqa: BLE001
            if "HANDSHAKE" in str(e).upper():
                out["notes"].append("MikroTik REST: на сервисе www-ssl не назначен сертификат. Создайте его (System → Certificates) "
                                    "или включите сервис www (порт 80) и поставьте \"https\": false в config.json.")
            else:
                out["notes"].append(f"MikroTik REST API недоступен ({e}). Включите www-ssl или www в IP → Services.")
            return out
        out["reachable"] = True
        out["auth"] = "ok"
        out["raw"]["resource"] = res
        out["model"] = res.get("board-name")
        out["firmware"] = res.get("version")
        out["cpu_load"] = _to_float(res.get("cpu-load"))
        total, free = _to_int(res.get("total-memory")), _to_int(res.get("free-memory"))
        if total and free is not None:
            out["mem_pct"] = round(100 * (1 - free / total), 1)
        out["uptime_sec"] = _ros_duration(res.get("uptime"))
        wan = out["wan"]

        try:
            ifaces = self._req("/interface")
            out["raw"]["interface"] = ifaces
            for i in ifaces:
                if i.get("type") not in ("ether", "pppoe-out", "lte", "vlan", "bridge", "wlan", "wifi"):
                    continue
                port = {"name": i.get("name"), "link": i.get("running") == "true", "type": i.get("type"),
                        "link_downs": _to_int(i.get("link-downs")), "rx_errors": _to_int(i.get("rx-error")),
                        "tx_errors": _to_int(i.get("tx-error")), "rx_drops": _to_int(i.get("rx-drop")),
                        "last_down": i.get("last-link-down-time"), "last_up": i.get("last-link-up-time"),
                        "wan": i.get("name") == self.wan}
                out["ports"].append(port)
                if port["wan"]:
                    wan.update({"link": port["link"], "link_downs": port["link_downs"], "rx_errors": port["rx_errors"],
                                "tx_errors": port["tx_errors"], "last_link_down": port["last_down"]})
        except Exception as e:  # noqa: BLE001
            out["notes"].append(f"Не удалось прочитать интерфейсы: {e}")

        try:
            mon = self._req("/interface/ethernet/monitor", {"numbers": self.wan, "once": True})
            mon = mon[0] if isinstance(mon, list) and mon else mon
            out["raw"]["wan_monitor"] = mon
            wan["phy_status"] = mon.get("status")
            wan["link_speed_mbps"] = _rate_mbps(mon.get("rate"))
            wan["full_duplex"] = mon.get("full-duplex") == "true" if mon.get("full-duplex") else None
            if any(k.startswith("sfp-") for k in mon):
                out["optics"] = {
                    "rx_dbm": _to_float(mon.get("sfp-rx-power")), "tx_dbm": _to_float(mon.get("sfp-tx-power")),
                    "temp_c": _to_float(mon.get("sfp-temperature")), "voltage": _to_float(mon.get("sfp-supply-voltage")),
                    "rx_loss": mon.get("sfp-rx-loss") == "true", "tx_fault": mon.get("sfp-tx-fault") == "true",
                    "module": " ".join(x for x in (mon.get("sfp-vendor-name"), mon.get("sfp-vendor-part-number")) if x),
                }
        except Exception:  # noqa: BLE001
            pass

        try:
            stats = self._req("/interface/ethernet/print", {"stats": True, ".query": [f"name={self.wan}"]})
            if stats:
                s = stats[0]
                out["raw"]["wan_stats"] = s
                wan["fcs_errors"] = _to_int(s.get("rx-fcs-error"))
                wan["align_errors"] = _to_int(s.get("rx-align-error"))
                wan["rx_too_short"] = _to_int(s.get("rx-too-short"))
        except Exception:  # noqa: BLE001
            pass

        try:
            pppoe = self._req("/interface/pppoe-client")
            if pppoe:
                p = pppoe[0]
                wan["proto"] = "pppoe"
                wan["pppoe_running"] = p.get("running") == "true"
                mon = self._req("/interface/pppoe-client/monitor", {"numbers": p.get("name"), "once": True})
                mon = mon[0] if isinstance(mon, list) and mon else mon
                out["raw"]["pppoe_monitor"] = mon
                wan["connected"] = mon.get("status") == "connected"
                wan["pppoe_status"] = mon.get("status")
                wan["ip"] = mon.get("local-address")
                wan["uptime_sec"] = _ros_duration(mon.get("uptime"))
        except Exception:  # noqa: BLE001
            pass

        try:
            dhcp = self._req("/ip/dhcp-client")
            for d in dhcp:
                if d.get("interface") == self.wan or not wan.get("proto"):
                    wan.setdefault("proto", "dhcp")
                    wan["dhcp_status"] = d.get("status")
                    if wan.get("proto") == "dhcp":
                        wan["connected"] = d.get("status") == "bound"
                        wan["ip"] = d.get("address")
                        wan["gateway"] = d.get("gateway")
        except Exception:  # noqa: BLE001
            pass

        if full:
            self._devices(out)
            self._wifi(out)
        if full:
            try:
                log = self._req("/log")
                keep = [f"{l.get('time')} [{l.get('topics')}] {l.get('message')}" for l in log
                        if re.search(r"pppoe|dhcp|interface|link|error|critical|warning", f"{l.get('topics')} {l.get('message')}", re.I)]
                out["log"] = keep[-40:]
            except Exception:  # noqa: BLE001
                pass
        return out

    def _devices(self, out):
        devs = {}
        try:
            for l in self._req("/ip/dhcp-server/lease"):
                mac = (l.get("mac-address") or "").lower()
                devs[mac] = {"mac": mac, "ip": l.get("address"), "name": l.get("comment") or l.get("host-name"), "conn": "LAN"}
        except Exception:  # noqa: BLE001
            pass
        for path in ("/interface/wifi/registration-table", "/interface/wireless/registration-table"):
            try:
                for r in self._req(path):
                    mac = (r.get("mac-address") or "").lower()
                    d = devs.setdefault(mac, {"mac": mac})
                    d["conn"] = f"Wi-Fi ({r.get('interface')})"
                    d["signal_dbm"] = _to_int(str(r.get("signal") or r.get("signal-strength") or "").split("@")[0])
            except Exception:  # noqa: BLE001
                pass
        try:
            # Kid Control tracks live per-device rates (RouterOS 7). Needs at least one "kid" rule to be populated.
            for k in self._req("/ip/kid-control/device"):
                mac = (k.get("mac-address") or "").lower()
                d = devs.setdefault(mac, {"mac": mac, "ip": k.get("ip-address"), "name": k.get("name")})
                d["down_bps"] = _bps(k.get("rate-down"))
                d["up_bps"] = _bps(k.get("rate-up"))
                d["down_bytes"] = _to_int(k.get("bytes-down"))
                d["up_bytes"] = _to_int(k.get("bytes-up"))
        except Exception:  # noqa: BLE001
            pass
        out["devices"] = [d for d in devs.values() if d.get("mac")]
        if out["devices"] and not any(d.get("down_bps") is not None for d in out["devices"]):
            out["notes"].append("Скорость по устройствам на MikroTik: добавьте любое правило в IP → Kid Control, тогда появится статистика IP → Kid Control → Devices.")

    def _wifi(self, out):
        for path in ("/interface/wifi", "/interface/wireless"):
            try:
                for w in self._req(path):
                    ch = w.get("channel.frequency") or w.get("frequency") or w.get(".about") or ""
                    freq = _to_int(re.sub(r"[^0-9].*$", "", str(w.get("frequency") or w.get("channel.frequency") or "")))
                    chan = _freq_to_channel(freq)
                    out["wifi_radios"].append({"band": band_of(chan), "channel": chan, "freq": freq,
                                               "width": _to_int(re.sub(r"[^0-9].*$", "", str(w.get("channel-width") or w.get("channel.width") or "").replace("20/40", "40"))),
                                               "ssid": w.get("ssid") or w.get("configuration.ssid"), "iface": w.get("name"),
                                               "enabled": w.get("disabled") != "true", "raw_channel": ch})
            except Exception:  # noqa: BLE001
                pass


def _bps(v):
    """'12.5Mbps' / '800kbps' / '1200' -> bit/s"""
    if v in (None, ""):
        return None
    m = re.match(r"([\d.]+)\s*([kMG]?)", str(v))
    if not m:
        return None
    return int(float(m.group(1)) * {"": 1, "k": 1e3, "M": 1e6, "G": 1e9}[m.group(2)])


def _freq_to_channel(freq):
    if not freq:
        return None
    if 2412 <= freq <= 2472:
        return (freq - 2407) // 5
    if freq == 2484:
        return 14
    if 5000 < freq < 5900:
        return (freq - 5000) // 5
    if 5950 <= freq <= 7125:
        return (freq - 5950) // 5
    return None


def _rate_mbps(rate):
    if not rate:
        return None
    m = re.match(r"(\d+(?:\.\d+)?)([MG])", str(rate))
    if not m:
        return None
    return int(float(m.group(1)) * (1000 if m.group(2) == "G" else 1))


def _ros_duration(s):
    """'1w2d03:04:05' -> seconds"""
    if not s:
        return None
    total = 0
    for num, unit in re.findall(r"(\d+)([wdhms])", s):
        total += int(num) * {"w": 604800, "d": 86400, "h": 3600, "m": 60, "s": 1}[unit]
    m = re.search(r"(\d+):(\d+):(\d+)$", s)
    if m:
        total += int(m.group(1)) * 3600 + int(m.group(2)) * 60 + int(m.group(3))
    return total
