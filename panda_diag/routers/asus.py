"""ASUS routers (ASUSWRT / Merlin) — appGet.cgi API used by the ASUS Router mobile app."""
import base64
import http.cookiejar
import json
import re
import urllib.parse
import urllib.request

from .base import _empty, _to_float, _to_int, band_of

APP_UA = "asusrouter-Android-DUTUtil-1.0.0.245"

# ASUSWRT rc/states: wanX_state_t / wanX_sbstate_t / wanX_auxstate_t
WAN_STATE = {0: "инициализация", 1: "подключение", 2: "подключено", 3: "отключено", 4: "остановлено",
             5: "отключено в настройках", 6: "остановка"}
WAN_SBSTATE = {0: None, 1: "неверный IP-адрес от провайдера", 2: "нет активности PPP (провайдер не отвечает)",
               3: "ошибка авторизации PPPoE (логин/пароль)", 4: "DHCP не получил адрес от провайдера",
               5: "конфликт IP с провайдером", 6: "провайдер не отвечает", 7: "нет ответа от PPPoE-сервера"}
WAN_AUXSTATE = {0: None, 1: "кабель WAN не подключён (нет линка на WAN-порту)", 2: "нет интернет-активности",
                3: "конфликт адресов LAN/WAN"}


class AsusRouter:
    kind = "asus"

    def __init__(self, host, username, password, timeout=6):
        self.base = f"http://{host}"
        self.username = username or "admin"
        self.password = password or ""
        self.timeout = timeout
        self.jar = http.cookiejar.CookieJar()
        self.opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(self.jar))
        self.token = None

    def _post(self, path, data):
        req = urllib.request.Request(self.base + path, data=urllib.parse.urlencode(data).encode(),
                                     headers={"User-Agent": APP_UA, "Referer": self.base + "/",
                                              **({"Cookie": f"asus_token={self.token}"} if self.token else {})})
        with self.opener.open(req, timeout=self.timeout) as r:
            return r.read().decode("utf-8", errors="replace")

    def login(self):
        auth = base64.b64encode(f"{self.username}:{self.password}".encode()).decode()
        body = self._post("/login.cgi", {"login_authorization": auth})
        try:
            self.token = json.loads(body).get("asus_token")
        except ValueError:
            self.token = None
        return bool(self.token)

    def hook(self, hooks):
        body = self._post("/appGet.cgi", {"hook": ";".join(hooks)})
        try:
            return json.loads(body)
        except ValueError:
            return {"_text": body}

    def collect(self, full=True):
        out = _empty(self.kind)
        try:
            ok = self.login()
        except Exception as e:  # noqa: BLE001
            out["notes"].append(f"ASUS не отвечает: {e}")
            return out
        out["reachable"] = True
        if not ok:
            out["auth"] = "failed"
            out["notes"].append("ASUS: неверный логин/пароль (или слишком много попыток — роутер блокирует вход на несколько минут).")
            return out
        out["auth"] = "ok"
        nv = ["productid", "firmver", "buildno", "extendno", "wan0_state_t", "wan0_sbstate_t", "wan0_auxstate_t",
              "wan0_proto", "wan0_ipaddr", "wan0_gateway", "wan0_dns", "link_internet", "wan0_realip_state",
              "wl0_channel", "wl1_channel", "wl2_channel", "wl0_chanspec", "wl1_chanspec", "wl0_bw", "wl1_bw",
              "wl0_ssid", "wl1_ssid", "wl0_radio", "wl1_radio", "wl0_txpower", "wl1_txpower"]
        data = {}
        try:
            data.update(self.hook([f"nvram_get({k})" for k in nv]))
            data.update(self.hook(["cpu_usage(appobj)", "memory_usage(appobj)", "uptime()", "wanlink()", "netdev(appobj)"]))
        except Exception as e:  # noqa: BLE001
            out["notes"].append(f"ASUS appGet: {e}")
        out["raw"]["appget"] = data
        out["model"] = data.get("productid")
        out["firmware"] = ".".join(str(x) for x in (data.get("firmver"), data.get("buildno"), data.get("extendno")) if x)

        cpu = data.get("cpu_usage") or {}
        loads = []
        for i in range(1, 9):
            tot, usg = _to_int(cpu.get(f"cpu{i}_total")), _to_int(cpu.get(f"cpu{i}_usage"))
            if tot:
                loads.append(100 * usg / tot)
        if loads:
            out["cpu_load"] = round(sum(loads) / len(loads), 1)
        mem = data.get("memory_usage") or {}
        if _to_int(mem.get("mem_total")):
            out["mem_pct"] = round(100 * _to_int(mem.get("mem_used")) / _to_int(mem.get("mem_total")), 1)
        up = str(data.get("uptime") or "")
        m = re.search(r"\((\d+) secs", up)
        out["uptime_sec"] = int(m.group(1)) if m else None

        wan = out["wan"]
        st, sb, aux = (_to_int(data.get(k)) for k in ("wan0_state_t", "wan0_sbstate_t", "wan0_auxstate_t"))
        wan["proto"] = data.get("wan0_proto")
        wan["ip"] = data.get("wan0_ipaddr") if data.get("wan0_ipaddr") not in ("0.0.0.0", "") else None
        wan["gateway"] = data.get("wan0_gateway")
        wan["state_code"] = st
        wan["connected"] = st == 2 if st is not None else None
        wan["status_text"] = WAN_STATE.get(st)
        if aux == 1:
            wan["link"] = False
        elif st == 2:
            wan["link"] = True
        reasons = [t for t in (WAN_SBSTATE.get(sb), WAN_AUXSTATE.get(aux)) if t]
        if reasons:
            wan["error_code"] = f"state={st} sbstate={sb} auxstate={aux}"
            wan["error_text"] = "; ".join(reasons)
        wanlink = data.get("wanlink") or {}
        if isinstance(wanlink, dict) and wanlink.get("statusstr"):
            wan["status_text"] = wanlink.get("statusstr")

        for idx in range(3):
            ch = _to_int(str(data.get(f"wl{idx}_chanspec") or "").split("/")[0].rstrip("lu")) or _to_int(data.get(f"wl{idx}_channel"))
            if data.get(f"wl{idx}_ssid") is None and ch is None:
                continue
            spec = str(data.get(f"wl{idx}_chanspec") or "")
            width = _to_int(spec.split("/")[1]) if "/" in spec else ({"0": 20, "1": 20, "2": 40, "3": 80, "5": 160}.get(str(data.get(f"wl{idx}_bw"))))
            if spec.endswith(("l", "u")):
                width = 40
            out["wifi_radios"].append({"band": band_of(ch) or ("2.4" if idx == 0 else "5"), "channel": ch or None,
                                       "width": width, "ssid": data.get(f"wl{idx}_ssid"),
                                       "enabled": str(data.get(f"wl{idx}_radio", "1")) == "1",
                                       "txpower": data.get(f"wl{idx}_txpower"), "auto": ch in (0, None)})

        nd = data.get("netdev") or {}
        if nd.get("INTERNET_rx"):
            wan["rx_bytes_total"] = int(str(nd["INTERNET_rx"]), 16) if str(nd["INTERNET_rx"]).startswith("0x") else _to_int(nd["INTERNET_rx"])
            wan["tx_bytes_total"] = int(str(nd["INTERNET_tx"]), 16) if str(nd.get("INTERNET_tx", "0")).startswith("0x") else _to_int(nd.get("INTERNET_tx"))

        if full:
            try:
                cl = (self.hook(["get_clientlist()"]).get("get_clientlist") or {})
                for mac in cl.get("maclist", []):
                    c = cl.get(mac) or {}
                    if str(c.get("isOnline")) != "1":
                        continue
                    wl = str(c.get("isWL"))
                    out["devices"].append({
                        "mac": mac.lower(), "ip": c.get("ip"), "name": c.get("nickName") or c.get("name"),
                        "conn": {"0": "LAN", "1": "Wi-Fi 2.4", "2": "Wi-Fi 5", "3": "Wi-Fi 5-2"}.get(wl, "?"),
                        "signal_dbm": _to_int(c.get("rssi")), "link_mbps": _to_float(c.get("curRx")),
                        "down_bytes": _to_int(c.get("totalRx")), "up_bytes": _to_int(c.get("totalTx")),
                    })
            except Exception:  # noqa: BLE001
                pass
            try:
                body = self._post("/appGet.cgi", {"hook": "nvram_dump(syslog.log,)"})
                lines = [l for l in body.splitlines() if re.search(r"wan|ppp|dhcp|link|carrier|eth0|err", l, re.I)]
                out["log"] = lines[-40:]
            except Exception:  # noqa: BLE001
                pass
        if not any(d.get("down_bytes") for d in out["devices"]) and out["devices"]:
            out["notes"].append("ASUS: трафик по устройствам доступен при включённом «Анализаторе трафика» (Adaptive QoS → Traffic Analyzer).")
        return out
