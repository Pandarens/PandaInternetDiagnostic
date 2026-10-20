"""Xiaomi / Redmi routers (MiWiFi web API)."""
import hashlib
import json
import random
import re
import time
import urllib.error
import uuid

from .base import _http, _empty, _to_int, _to_float, band_of


# =========================================================================== Xiaomi (MiWiFi)

XIAOMI_KEY = "a2ffa5c9be07488bbb04a3a47d3c5f6a"

# PPPoE error codes shown by MiWiFi web UI (same numbering as Windows RAS errors).
PPPOE_ERRORS = {
    "691": "Неверный логин/пароль PPPoE или учётная запись заблокирована (долг, смена тарифа)",
    "678": "Сервер PPPoE провайдера не отвечает — нет сигнала от провайдера (оптика/ONT/кабель WAN)",
    "651": "Сервер PPPoE провайдера не отвечает — проблема на линии или у провайдера",
    "676": "Сервер PPPoE занят / сессия уже открыта на другом устройстве",
    "619": "Соединение PPPoE разорвано провайдером",
    "629": "Соединение PPPoE закрыто удалённой стороной",
    "718": "Сервер PPPoE не завершил авторизацию (таймаут на стороне провайдера)",
    "734": "Ошибка согласования протокола PPP",
    "33": "Сервер PPPoE не найден (нет ответа PADO) — нет связи с провайдером на уровне линии",
    "34": "Сервер PPPoE не ответил на авторизацию",
}

# MiWiFi API calls that only READ state. Nothing here changes router settings.
XIAOMI_ENDPOINTS = [
    "misystem/status",
    "misystem/newstatus",
    "xqnetwork/pppoe_status",
    "xqnetwork/wan_info",
    "xqnetwork/mode",
    "xqnetwork/wifi_detail_all",
    "xqnetwork/wifi_diag_detail_all",
    "xqnetwork/wifi_list",
    "xqnetwork/wifi_connect_devices",
    "xqnetwork/lan_info",
    "xqnetwork/wan_speed",
    "xqnetwork/check_wan_type",
    "misystem/devicelist",
    "misystem/topo_graph",
    "misystem/qos_info",
    "misystem/sys_log",
    "xqsystem/vpn_status",
    "xqsystem/check_rom_update",
]


class XiaomiRouter:
    kind = "xiaomi"

    def __init__(self, host, password, username="admin", timeout=5):
        self.host = host
        self.password = password or ""
        self.username = username or "admin"
        self.timeout = timeout
        self.base = f"http://{host}/cgi-bin/luci"
        self.token = None
        self.sha256 = False
        self.key = XIAOMI_KEY

    def _get(self, path, auth=True):
        url = f"{self.base}/;stok={self.token}/api/{path}" if auth else f"{self.base}/api/{path}"
        _, body = _http(url, timeout=self.timeout)
        return json.loads(body)

    def init_info(self):
        return self._get("xqsystem/init_info", auth=False)

    def _hash(self, s):
        return (hashlib.sha256 if self.sha256 else hashlib.sha1)(s.encode()).hexdigest()

    def login(self):
        try:
            _, page = _http(f"{self.base}/web", timeout=self.timeout)
            m = re.search(r"key\s*:\s*'([0-9a-f]{32})'", page)
            if m:
                self.key = m.group(1)
        except Exception:  # noqa: BLE001
            pass
        mac = ":".join(re.findall("..", f"{uuid.getnode():012x}"))
        nonce = f"0_{mac}_{int(time.time())}_{random.randint(0, 9999)}"
        pwd = self._hash(nonce + self._hash(self.password + self.key))
        _, body = _http(f"{self.base}/api/xqsystem/login",
                        data={"username": self.username, "password": pwd, "logtype": "2", "nonce": nonce},
                        timeout=self.timeout)
        res = json.loads(body)
        self.token = res.get("token")
        return bool(self.token), res

    def collect(self, full=True):
        out = _empty(self.kind)
        try:
            info = self.init_info()
        except Exception as e:  # noqa: BLE001
            out["notes"].append(f"Веб-интерфейс Xiaomi не отвечает: {e}")
            return out
        out["reachable"] = True
        out["raw"]["init_info"] = info
        self.sha256 = str(info.get("newEncryptMode", "0")) == "1"
        out["model"] = " ".join(str(x) for x in (info.get("routername") or info.get("routerName"),
                                                  info.get("hardware"), info.get("modules", {}).get("model") if isinstance(info.get("modules"), dict) else None) if x)
        out["firmware"] = info.get("romversion")
        if not self.password:
            out["auth"] = "no_password"
            out["notes"].append("Пароль администратора Xiaomi не указан — введите его в «Настройки → Роутер и модем» — доступна только общая информация.")
            return out
        try:
            ok, res = self.login()
        except Exception as e:  # noqa: BLE001
            ok, res = False, {"error": str(e)}
        if not ok:
            out["auth"] = "failed"
            out["notes"].append(f"Не удалось войти в роутер Xiaomi (code={res.get('code')}, {res.get('msg') or res.get('error') or ''}). Проверьте пароль.")
            return out
        out["auth"] = "ok"
        for ep in (XIAOMI_ENDPOINTS if full else XIAOMI_ENDPOINTS[:4]):
            try:
                data = self._get(ep)
                if isinstance(data, dict) and data.get("code") not in (None, 0):
                    continue
                out["raw"][ep] = data
            except (urllib.error.HTTPError, ValueError):
                continue
            except Exception:  # noqa: BLE001
                continue
        self._normalize(out)
        return out

    def _normalize(self, out):
        raw = out["raw"]
        st = raw.get("misystem/status") or {}
        wan = out["wan"]

        cpu = st.get("cpu") or {}
        out["cpu_load"] = _to_float(cpu.get("load"))
        if out["cpu_load"] is not None and out["cpu_load"] <= 1:
            out["cpu_load"] = round(out["cpu_load"] * 100, 1)
        mem = st.get("mem") or {}
        usage = _to_float(mem.get("usage"))
        out["mem_pct"] = round(usage * 100, 1) if usage is not None and usage <= 1 else usage
        out["temperature"] = _to_float(st.get("temperature"))
        out["uptime_sec"] = _to_int(st.get("upTime"))
        cnt = st.get("count") or {}
        out["clients"] = _to_int(cnt.get("online") or cnt.get("all"))
        hw = st.get("hardware") or {}
        if hw.get("platform") and not out["model"]:
            out["model"] = hw.get("platform")
        if hw.get("version"):
            out["firmware"] = hw.get("version")
        w = st.get("wan") or {}
        if w:
            wan["down_bps"] = _to_int(w.get("downspeed"))
            wan["up_bps"] = _to_int(w.get("upspeed"))
            wan["iface"] = w.get("devname")

        pp = raw.get("xqnetwork/pppoe_status") or {}
        if pp:
            wan["proto"] = pp.get("proto")
            ip = pp.get("ip") or {}
            addr = ip.get("address") if isinstance(ip, dict) else ip
            wan["ip"] = addr if addr and addr != "0.0.0.0" else None
            wan["gateway"] = pp.get("gw")
            wan["dns"] = pp.get("dns")
            code = pp.get("errcode") or pp.get("errorCode")
            if code not in (None, "", 0, "0"):
                wan["error_code"] = str(code)
                wan["error_text"] = pp.get("errmsg") or PPPOE_ERRORS.get(str(code), "Ошибка подключения WAN")
            status = _to_int(pp.get("status"))
            wan["status_code"] = status
            wan["connected"] = bool(wan["ip"]) and status in (None, 2)
            wan["uptime_sec"] = _to_int(pp.get("uptime"))

        wi = raw.get("xqnetwork/wan_info") or {}
        info = wi.get("info") if isinstance(wi.get("info"), dict) else wi
        if info:
            link = info.get("link")
            if link is not None:
                wan["link"] = str(link) in ("1", "true", "True", "up")
            details = info.get("details") or {}
            wan.setdefault("proto", details.get("wanType"))
            wan["mac"] = info.get("mac")
            wan["mtu"] = info.get("mtu")
            if info.get("uptime") is not None and not wan.get("uptime_sec"):
                wan["uptime_sec"] = _to_int(info.get("uptime"))
            ipv4 = info.get("ipv4")
            if isinstance(ipv4, list) and ipv4 and not wan.get("ip"):
                wan["ip"] = ipv4[0].get("ip") if isinstance(ipv4[0], dict) else ipv4[0]
            if "status" in info and wan.get("connected") is None:
                wan["connected"] = str(info.get("status")) in ("1", "2", "connected", "up")

        # Port link speeds are reported in different places depending on firmware; look everywhere.
        out["ports"] = _find_ports(raw)
        for p in out["ports"]:
            if p.get("wan") and p.get("speed_mbps"):
                wan["link_speed_mbps"] = p["speed_mbps"]
            if p.get("wan") and p.get("link") is not None and wan.get("link") is None:
                wan["link"] = p["link"]

        diag = raw.get("xqnetwork/wifi_diag_detail_all") or raw.get("xqnetwork/wifi_detail_all") or {}
        for item in diag.get("info", []) if isinstance(diag.get("info"), list) else []:
            ci = item.get("channelInfo") or {}
            ch = _to_int(ci.get("channel") or item.get("channel"))
            out["wifi_radios"].append({
                "band": band_of(ch), "channel": ch, "width": _to_int(ci.get("bandwidth") or item.get("bandwidth")),
                "ssid": item.get("ssid"), "enabled": str(item.get("status")) == "1",
                "txpower": item.get("txpwr"), "iface": item.get("ifname") or item.get("device"),
            })

        scan = raw.get("xqnetwork/wifi_list") or {}
        for ap in scan.get("list", []) if isinstance(scan.get("list"), list) else []:
            sig = _to_int(ap.get("signal"))
            if sig is not None and sig > 0:   # percent -> dBm
                sig = round(sig / 2 - 100)
            out["wifi_scan"].append({"ssid": ap.get("ssid"), "bssid": ap.get("bssid"), "channel": _to_int(ap.get("channel")),
                                     "signal_dbm": sig, "width": _to_int(ap.get("bandwidth"))})

        # Per-device traffic: misystem/status "dev" has live speeds, devicelist has names/IPs/connection type.
        names = {}
        for d in (raw.get("misystem/devicelist") or {}).get("list", []) or []:
            mac = (d.get("mac") or "").lower()
            ips = d.get("ip") or []
            ip0 = ips[0] if ips and isinstance(ips[0], dict) else {}
            conn = {0: "LAN", 1: "Wi-Fi 2.4", 2: "Wi-Fi 5", 3: "Гостевая"}.get(_to_int(d.get("type")), None)
            stat = d.get("statistics") or {}
            names[mac] = {"name": d.get("oname") or d.get("name"), "ip": ip0.get("ip"), "conn": conn,
                          "down_bps": _to_int(ip0.get("downspeed") or stat.get("downspeed")),
                          "up_bps": _to_int(ip0.get("upspeed") or stat.get("upspeed")),
                          "down_bytes": _to_int(stat.get("download")), "up_bytes": _to_int(stat.get("upload")),
                          "online_sec": _to_int(stat.get("online") or ip0.get("online"))}
        for d in st.get("dev", []) or []:
            mac = (d.get("mac") or "").lower()
            e = names.setdefault(mac, {"name": d.get("devname")})
            e.update({"down_bps": _to_int(d.get("downspeed")), "up_bps": _to_int(d.get("upspeed")),
                      "down_bytes": _to_int(d.get("download")), "up_bytes": _to_int(d.get("upload"))})
            e.setdefault("name", d.get("devname"))
        for mac, e in names.items():
            e["mac"] = mac
            e["down_bps"] = (e.get("down_bps") or 0) * 8   # MiWiFi reports bytes/s
            e["up_bps"] = (e.get("up_bps") or 0) * 8
            out["devices"].append(e)
        if wan.get("down_bps") is not None:
            wan["down_bps"] *= 8
            wan["up_bps"] = (wan.get("up_bps") or 0) * 8

        log = raw.get("misystem/sys_log")
        if isinstance(log, dict):
            lines = log.get("log") or log.get("data") or []
            if isinstance(lines, str):
                lines = lines.splitlines()
            out["log"] = [l for l in lines if re.search(r"ppp|wan|link|dhcp|err|fail|down|up", str(l), re.I)][-40:]


def _find_ports(raw):
    """Walk all MiWiFi responses looking for port descriptions with link/speed fields."""
    ports = []

    def walk(o, ctx=""):
        if isinstance(o, dict):
            keys = {k.lower(): k for k in o}
            speed_key = next((keys[k] for k in keys if k in ("speed", "linkspeed", "link_speed", "rate")), None)
            link_key = next((keys[k] for k in keys if k in ("link", "linkstatus", "link_status", "status")), None)
            name_key = next((keys[k] for k in keys if k in ("port", "name", "portname", "ifname", "devname", "type")), None)
            if speed_key and (link_key or name_key) and _to_int(o.get(speed_key)) is not None:
                name = str(o.get(name_key)) if name_key else ctx
                ports.append({
                    "name": name,
                    "speed_mbps": _to_int(o.get(speed_key)),
                    "link": (str(o.get(link_key)).lower() in ("1", "true", "up", "connected")) if link_key else None,
                    "duplex": o.get("duplex"),
                    "wan": "wan" in (name + ctx).lower(),
                    "source": ctx,
                })
            for k, v in o.items():
                walk(v, f"{ctx}.{k}" if ctx else k)
        elif isinstance(o, list):
            for i, v in enumerate(o):
                walk(v, f"{ctx}[{i}]")

    for ep, data in raw.items():
        if ep in ("misystem/devicelist", "misystem/topo_graph"):
            continue
        walk(data, ep)
    return ports[:16]
