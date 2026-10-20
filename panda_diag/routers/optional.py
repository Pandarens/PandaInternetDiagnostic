"""Drivers that rely on optional third-party packages (installed with `pip install -r requirements-optional.txt`).

TP-Link uses per-model encrypted login schemes (RSA + AES); the `tplinkrouterc6u` package implements all of them
(Archer C/AX/BE, Deco, MR/MX LTE, EX/XC, VX, TL-WR with new firmware).
Huawei LTE modems (B310/B315/B525/B535/B618/E5186/E3372 HiLink…) use the `huawei-lte-api` package.
"""
from .base import _empty, _to_float, _to_int


def _attr(o, *names):
    for n in names:
        v = getattr(o, n, None)
        if v not in (None, ""):
            return v
    return None


class TplinkRouter:
    kind = "tplink"

    def __init__(self, host, username, password):
        self.host = host
        self.username = username or "admin"
        self.password = password or ""

    def collect(self, full=True):
        out = _empty(self.kind)
        try:
            from tplinkrouterc6u import TplinkRouterProvider  # type: ignore
        except ImportError:
            out["notes"].append("Для TP-Link установите модуль: pip install tplinkrouterc6u")
            return out
        try:
            router = TplinkRouterProvider.get_client(f"http://{self.host}", self.password, self.username)
            router.authorize()
        except Exception as e:  # noqa: BLE001
            out["reachable"] = True
            out["auth"] = "failed"
            out["notes"].append(f"TP-Link: вход не выполнен ({e}). Учтите: TP-Link пускает только одного администратора — закройте веб-интерфейс.")
            return out
        out["reachable"] = True
        out["auth"] = "ok"
        try:
            fw = router.get_firmware()
            out["model"] = _attr(fw, "model")
            out["firmware"] = _attr(fw, "firmware_version")
            st = router.get_status()
            out["cpu_load"] = (_to_float(_attr(st, "cpu_usage")) or 0) * 100 or None
            out["mem_pct"] = (_to_float(_attr(st, "mem_usage")) or 0) * 100 or None
            out["clients"] = _to_int(_attr(st, "clients_total"))
            wan = out["wan"]
            ip = _attr(st, "wan_ipv4_addr")
            wan["ip"] = str(ip) if ip else None
            wan["gateway"] = str(_attr(st, "wan_ipv4_gateway") or "") or None
            wan["connected"] = bool(ip) and str(ip) != "0.0.0.0"
            wan["uptime_sec"] = _to_int(_attr(st, "wan_ipv4_uptime"))
            for d in _attr(st, "devices") or []:
                conn = str(_attr(d, "type") or "")
                out["devices"].append({
                    "mac": str(_attr(d, "macaddr") or "").lower().replace("-", ":"), "ip": str(_attr(d, "ipaddr") or ""),
                    "name": _attr(d, "hostname"), "conn": conn.replace("Connection.", "").replace("HOST_", "") or None,
                    "down_bps": (_to_int(_attr(d, "down_speed")) or 0) * 8 if _attr(d, "down_speed") is not None else None,
                    "up_bps": (_to_int(_attr(d, "up_speed")) or 0) * 8 if _attr(d, "up_speed") is not None else None,
                    "signal_dbm": _to_int(_attr(d, "signal")),
                    "down_bytes": _to_int(_attr(d, "packets_received")), "up_bytes": _to_int(_attr(d, "packets_sent")),
                })
            try:
                ipv4 = router.get_ipv4_status()
                wan["proto"] = str(_attr(ipv4, "wan_ipv4_conntype") or "") or None
            except Exception:  # noqa: BLE001
                pass
            for band, attr in (("2.4", "wifi_2g_enable"), ("5", "wifi_5g_enable"), ("6", "wifi_6g_enable")):
                v = getattr(st, attr, None)
                if v is not None:
                    out["wifi_radios"].append({"band": band, "channel": None, "enabled": bool(v)})
            out["raw"]["status"] = {k: str(v) for k, v in vars(st).items() if k != "devices"}
        except Exception as e:  # noqa: BLE001
            out["notes"].append(f"TP-Link: ошибка чтения статуса: {e}")
        finally:
            try:
                router.logout()
            except Exception:  # noqa: BLE001
                pass
        return out


LTE_STATUS = {"900": "подключение", "901": "подключено", "902": "отключено", "903": "отключение",
              "7": "нет доступа к сети (SIM/тариф)", "11": "нет доступа к сети", "14": "сеть отклонила регистрацию",
              "112": "автоподключение выключено", "113": "автоподключение в роуминге выключено"}


class HuaweiLteRouter:
    kind = "huawei_lte"

    def __init__(self, host, username, password):
        self.url = f"http://{username or 'admin'}:{password or ''}@{host}/"

    def collect(self, full=True):
        out = _empty(self.kind)
        try:
            from huawei_lte_api.Client import Client  # type: ignore
            from huawei_lte_api.Connection import Connection  # type: ignore
        except ImportError:
            out["notes"].append("Для 4G-модемов Huawei установите модуль: pip install huawei-lte-api")
            return out
        try:
            with Connection(self.url, timeout=6) as conn:
                c = Client(conn)
                out["reachable"] = True
                out["auth"] = "ok"
                info = c.device.information()
                out["model"] = info.get("DeviceName")
                out["firmware"] = info.get("SoftwareVersion")
                sig = c.device.signal()
                st = c.monitoring.status()
                tr = c.monitoring.traffic_statistics()
                out["raw"].update({"signal": sig, "status": st, "traffic": tr})
                code = str(st.get("ConnectionStatus"))
                wan = out["wan"]
                wan.update({"proto": "lte", "connected": code == "901", "status_text": LTE_STATUS.get(code, code),
                            "ip": st.get("WanIPAddress"), "uptime_sec": _to_int(tr.get("CurrentConnectTime")),
                            "down_bps": (_to_int(tr.get("CurrentDownloadRate")) or 0) * 8,
                            "up_bps": (_to_int(tr.get("CurrentUploadRate")) or 0) * 8,
                            "link": st.get("SimStatus") == "1"})
                if code not in ("901", "900"):
                    wan["error_code"] = code
                    wan["error_text"] = LTE_STATUS.get(code, "Модем не подключён к сети оператора")
                out["cellular"] = {k: _to_float(str(sig.get(k) or "").replace("dBm", "").replace("dB", "")) for k in ("rsrp", "rsrq", "rssi", "sinr")}
                out["cellular"].update({"band": sig.get("band"), "cell_id": sig.get("cell_id"), "pci": sig.get("pci"),
                                        "network": st.get("CurrentNetworkTypeEx") or st.get("CurrentNetworkType")})
        except Exception as e:  # noqa: BLE001
            out["notes"].append(f"Huawei LTE: {e}")
        return out
