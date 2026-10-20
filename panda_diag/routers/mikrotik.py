"""MikroTik RouterOS: REST (v7, www/www-ssl) or the native API (v6/v7, ports 8728/8729)."""
import base64
import json
import re
import socket
import ssl
import urllib.error

from .base import _http, _empty, _to_int, _to_float, band_of


class AuthError(Exception):
    pass


# =========================================================================== transports

class RestTransport:
    def __init__(self, host, username, password, https=True, timeout=5):
        self.name = "REST " + ("HTTPS" if https else "HTTP")
        self.base = f"{'https' if https else 'http'}://{host}/rest"
        self.auth = "Basic " + base64.b64encode(f"{username}:{password}".encode()).decode()
        self.timeout = timeout
        self.ctx = ssl._create_unverified_context() if https else None  # routers use self-signed certificates

    def req(self, path, payload=None):
        data = json.dumps(payload).encode() if payload is not None else None
        try:
            _, body = _http(self.base + path, data=data, timeout=self.timeout, context=self.ctx,
                            headers={"Authorization": self.auth, "Content-Type": "application/json"},
                            method="POST" if payload is not None else "GET")
        except urllib.error.HTTPError as e:
            if e.code in (401, 403):
                raise AuthError(f"HTTP {e.code}") from e
            raise
        return json.loads(body)

    def close(self):
        pass


def _enc_len(n):
    if n < 0x80:
        return bytes([n])
    if n < 0x4000:
        return (n | 0x8000).to_bytes(2, "big")
    if n < 0x200000:
        return (n | 0xC00000).to_bytes(3, "big")
    if n < 0x10000000:
        return (n | 0xE0000000).to_bytes(4, "big")
    return b"\xF0" + n.to_bytes(4, "big")


class ApiTransport:
    """RouterOS API protocol (length-prefixed words). Speaks the same paths/payloads as the REST transport."""

    def __init__(self, host, username, password, use_ssl=False, timeout=5):
        self.name = "API-SSL" if use_ssl else "API"
        port = 8729 if use_ssl else 8728
        raw = socket.create_connection((host, port), timeout=timeout)
        if use_ssl:
            ctx = ssl._create_unverified_context()
            ctx.set_ciphers("ALL:@SECLEVEL=0")  # RouterOS without a certificate uses anonymous DH ciphers
            raw = ctx.wrap_socket(raw, server_hostname=host)
        self.sock = raw
        self.sock.settimeout(timeout)
        self.buf = b""
        status, attrs = self._talk(["/login", f"=name={username}", f"=password={password}"])
        if status != "!done":
            self.close()
            raise AuthError(attrs[0].get("message", "login failed") if attrs else "login failed")

    def _send(self, words):
        self.sock.sendall(b"".join(_enc_len(len(w.encode())) + w.encode() for w in words) + b"\x00")

    def _recv_exact(self, n):
        while len(self.buf) < n:
            chunk = self.sock.recv(65536)
            if not chunk:
                raise ConnectionError("connection closed")
            self.buf += chunk
        out, self.buf = self.buf[:n], self.buf[n:]
        return out

    def _read_word(self):
        b = self._recv_exact(1)[0]
        if b < 0x80:
            n = b
        elif b < 0xC0:
            n = ((b & 0x3F) << 8) | self._recv_exact(1)[0]
        elif b < 0xE0:
            n = ((b & 0x1F) << 16) | int.from_bytes(self._recv_exact(2), "big")
        elif b < 0xF0:
            n = ((b & 0x0F) << 24) | int.from_bytes(self._recv_exact(3), "big")
        else:
            n = int.from_bytes(self._recv_exact(4), "big")
        return self._recv_exact(n).decode("utf-8", errors="replace")

    def _talk(self, words):
        self._send(words)
        rows = []
        while True:
            sentence = []
            while True:
                w = self._read_word()
                if w == "":
                    break
                sentence.append(w)
            if not sentence:
                continue
            kind, attrs = sentence[0], {}
            for w in sentence[1:]:
                if w.startswith("="):
                    k, _, v = w[1:].partition("=")
                    attrs[k] = v
            if kind == "!re":
                rows.append(attrs)
            elif kind in ("!done", "!empty"):
                return "!done", rows
            elif kind in ("!trap", "!fatal"):
                # drain until !done after a trap
                if kind == "!fatal":
                    return kind, [attrs]
                rows = [attrs]
                status = kind
                while True:
                    s2 = []
                    while True:
                        w = self._read_word()
                        if w == "":
                            break
                        s2.append(w)
                    if s2 and s2[0] == "!done":
                        return status, rows

    def req(self, path, payload=None):
        if payload is None:
            words = [path.rstrip("/") + "/print"]
        else:
            words = [path]
            for k, v in payload.items():
                if k == ".query":
                    words += ["?" + q for q in v]
                elif v is True:
                    words.append(f"={k}=")
                else:
                    words.append(f"={k}={v}")
        status, rows = self._talk(words)
        if status != "!done":
            raise RuntimeError((rows[0] if rows else {}).get("message", status))
        return rows

    def close(self):
        try:
            self.sock.close()
        except OSError:
            pass


TRANSPORTS = {
    "rest-https": lambda h, u, p: RestTransport(h, u, p, True),
    "rest-http": lambda h, u, p: RestTransport(h, u, p, False),
    "api": lambda h, u, p: ApiTransport(h, u, p, False),
    "api-ssl": lambda h, u, p: ApiTransport(h, u, p, True),
}


def _why(exc):
    s = str(exc)
    if "HANDSHAKE" in s.upper():
        return "на сервисе www-ssl не назначен сертификат"
    if "refused" in s.lower() or "10061" in s:
        return "сервис выключен"
    if "timed out" in s.lower() or "10060" in s:
        return "порт закрыт фаерволом"
    return s[:80]


# =========================================================================== MikroTik

class MikroTikRouter:
    kind = "mikrotik"

    def __init__(self, host, username, password, https=True, wan_interface="ether1", timeout=5, transport="auto"):
        self.host, self.username, self.password = host, username or "admin", password or ""
        self.wan = wan_interface
        self.timeout = timeout
        self.has_password = bool(password)
        if transport in (None, "", "auto"):
            self.order = ["rest-https", "rest-http", "api", "api-ssl"] if https else ["rest-http", "rest-https", "api", "api-ssl"]
        else:
            self.order = [transport]
        self.t = None

    def _connect(self, out):
        tried = []
        for name in self.order:
            try:
                t = TRANSPORTS[name](self.host, self.username, self.password)
                res = t.req("/system/resource")
                res = res[0] if isinstance(res, list) and res else res
                self.t = t
                out["transport"] = t.name
                return res
            except AuthError as e:
                out["reachable"] = True
                out["auth"] = "failed"
                out["notes"].append(f"MikroTik ({name}): неверный логин или пароль ({e}). Проверьте их в настройках «Роутер и модем».")
                return None
            except Exception as e:  # noqa: BLE001
                tried.append(f"{name}: {_why(e)}")
        out["notes"].append("MikroTik: не удалось подключиться (" + "; ".join(tried) + "). "
                            "Откройте «Настройки → Роутер и модем» — там есть готовый скрипт, который включит доступ.")
        out["access_hint"] = "mikrotik_setup"
        return None

    def _req(self, path, payload=None):
        return self.t.req(path, payload)

    def collect(self, full=True):
        out = _empty(self.kind)
        if not self.has_password:
            out["auth"] = "no_password"
            out["access_hint"] = "mikrotik_setup"
            out["notes"].append("Не указан логин/пароль MikroTik — введите их в «Настройки → Роутер и модем».")
            return out
        res = self._connect(out)
        if res is None:
            return out
        try:
            return self._collect(out, res, full)
        finally:
            self.t.close()

    def _collect(self, out, res, full):
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
