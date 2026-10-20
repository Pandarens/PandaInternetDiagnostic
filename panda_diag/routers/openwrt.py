"""OpenWrt / LEDE / ImmortalWrt (and many ISP routers on OpenWrt) — ubus JSON-RPC over HTTP."""
import json
import urllib.request

from .base import UA, _empty, _to_float, _to_int, band_of

NULL_SESSION = "0" * 32


class OpenWrtRouter:
    kind = "openwrt"

    def __init__(self, host, username, password, timeout=6):
        self.url = f"http://{host}/ubus"
        self.username = username or "root"
        self.password = password or ""
        self.timeout = timeout
        self.session = NULL_SESSION
        self._id = 0

    def call(self, obj, method, args=None):
        self._id += 1
        payload = {"jsonrpc": "2.0", "id": self._id, "method": "call",
                   "params": [self.session, obj, method, args or {}]}
        req = urllib.request.Request(self.url, data=json.dumps(payload).encode(),
                                     headers=dict(UA, **{"Content-Type": "application/json"}))
        with urllib.request.urlopen(req, timeout=self.timeout) as r:
            res = json.loads(r.read().decode())
        result = res.get("result")
        if not result or result[0] != 0:
            raise RuntimeError(f"ubus {obj}.{method}: code {result[0] if result else res.get('error')}")
        return result[1] if len(result) > 1 else {}

    def collect(self, full=True):
        out = _empty(self.kind)
        try:
            res = self.call("session", "login", {"username": self.username, "password": self.password})
            self.session = res["ubus_rpc_session"]
        except Exception as e:  # noqa: BLE001
            out["notes"].append(f"OpenWrt ubus: вход не выполнен ({e}). Нужен пакет uhttpd-mod-ubus и пароль root.")
            return out
        out["reachable"] = True
        out["auth"] = "ok"
        raw = out["raw"]
        try:
            b = self.call("system", "board")
            raw["board"] = b
            out["model"] = b.get("model")
            out["firmware"] = (b.get("release") or {}).get("description")
            i = self.call("system", "info")
            raw["info"] = i
            out["uptime_sec"] = i.get("uptime")
            mem = i.get("memory") or {}
            if mem.get("total"):
                out["mem_pct"] = round(100 * (1 - (mem.get("available") or mem.get("free", 0)) / mem["total"]), 1)
            load = i.get("load") or []
            if load:
                out["cpu_load"] = round(load[0] / 65536 * 100, 1)  # 1-min load average ×100 (per whole system)
        except Exception:  # noqa: BLE001
            pass

        wan = out["wan"]
        for name in ("wan", "wan6", "WAN", "internet"):
            try:
                st = self.call(f"network.interface.{name}", "status")
            except Exception:  # noqa: BLE001
                continue
            raw[f"iface_{name}"] = st
            addrs = st.get("ipv4-address") or []
            wan.update({"iface": name, "proto": st.get("proto"), "connected": bool(st.get("up")) and bool(addrs or name == "wan6"),
                        "uptime_sec": st.get("uptime"), "ip": addrs[0]["address"] if addrs else None,
                        "dns": st.get("dns-server")})
            dev = st.get("l3_device") or st.get("device")
            if st.get("errors"):
                wan["error_code"] = ",".join(e.get("code", "") for e in st["errors"])
                wan["error_text"] = {"AUTH_FAILED": "Ошибка авторизации PPPoE (логин/пароль)",
                                     "NO_DEVICE": "Нет устройства WAN", "NO_CARRIER": "Нет линка на WAN-порту"}.get(
                    st["errors"][0].get("code"), st["errors"][0].get("code"))
            try:
                phys = st.get("device") or dev
                ds = self.call("network.device", "status", {"name": phys})
                raw["wan_device"] = ds
                wan["link"] = ds.get("carrier")
                sp = str(ds.get("speed") or "")
                wan["link_speed_mbps"] = _to_int(sp.rstrip("FH")) if sp and sp[0].isdigit() else None
                wan["full_duplex"] = sp.endswith("F") if sp else None
                s = ds.get("statistics") or {}
                wan.update({"rx_errors": s.get("rx_errors"), "tx_errors": s.get("tx_errors"),
                            "fcs_errors": s.get("rx_crc_errors"), "rx_bytes_total": s.get("rx_bytes"),
                            "tx_bytes_total": s.get("tx_bytes")})
            except Exception:  # noqa: BLE001
                pass
            break

        if not full:
            return out
        try:
            devs = self.call("network.device", "status")
            for name, d in devs.items():
                if d.get("type") == "Network device" and not name.startswith(("lo", "br-", "wlan", "phy", "ifb", "pppoe")):
                    sp = str(d.get("speed") or "")
                    out["ports"].append({"name": name, "link": d.get("carrier"),
                                         "speed_mbps": _to_int(sp.rstrip("FH")) if sp[:1].isdigit() else None,
                                         "duplex": "full" if sp.endswith("F") else ("half" if sp.endswith("H") else None),
                                         "wan": name == (raw.get("wan_device") or {}).get("name") if raw.get("wan_device") else False,
                                         "rx_errors": (d.get("statistics") or {}).get("rx_errors")})
        except Exception:  # noqa: BLE001
            pass

        hints = {}
        try:
            hints = self.call("luci-rpc", "getHostHints")
        except Exception:  # noqa: BLE001
            pass
        devices = {}
        for mac, h in hints.items():
            devices[mac.lower()] = {"mac": mac.lower(), "name": h.get("name"), "ip": (h.get("ipaddrs") or [None])[0], "conn": "LAN"}

        try:
            radios = self.call("iwinfo", "devices").get("devices", [])
        except Exception:  # noqa: BLE001
            radios = []
        for r in radios:
            try:
                info = self.call("iwinfo", "info", {"device": r})
                ch = _to_int(info.get("channel"))
                width = _to_int("".join(c for c in str(info.get("htmode") or "") if c.isdigit()))
                out["wifi_radios"].append({"band": band_of(ch), "channel": ch, "width": width, "ssid": info.get("ssid"),
                                           "iface": r, "txpower": info.get("txpower"), "enabled": True,
                                           "noise_dbm": info.get("noise")})
                for sta in self.call("iwinfo", "assoclist", {"device": r}).get("results", []):
                    mac = sta.get("mac", "").lower()
                    d = devices.setdefault(mac, {"mac": mac})
                    d.update({"conn": f"Wi-Fi {band_of(ch)}", "signal_dbm": sta.get("signal"),
                              "link_mbps": _to_float((sta.get("rx") or {}).get("rate", 0)) / 1000 if sta.get("rx") else None})
                for ap in self.call("iwinfo", "scan", {"device": r}).get("results", []):
                    out["wifi_scan"].append({"ssid": ap.get("ssid"), "bssid": ap.get("bssid"), "channel": _to_int(ap.get("channel")),
                                             "signal_dbm": _to_int(ap.get("signal")),
                                             "width": _to_int("".join(c for c in str((ap.get("ht_operation") or {}).get("secondary_channel_offset", "")) if c.isdigit()))})
            except Exception:  # noqa: BLE001
                continue

        out["devices"] = list(devices.values())
        if out["devices"]:
            out["notes"].append("OpenWrt: объём трафика по устройствам — установите пакет luci-app-nlbwmon (Bandwidth Monitor).")

        try:
            log = self.call("log", "read", {"lines": 200, "stream": False})
            lines = [l.get("msg", "") for l in log.get("log", [])]
            out["log"] = [l for l in lines if any(w in l.lower() for w in ("pppd", "wan", "link is", "dhcp", "carrier", "netifd"))][-40:]
        except Exception:  # noqa: BLE001
            pass
        return out
