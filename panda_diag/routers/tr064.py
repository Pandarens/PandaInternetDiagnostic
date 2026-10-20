"""TR-064 (AVM Fritz!Box and other CPEs that expose it on port 49000). Includes DSL line quality and hosts."""
import re
import urllib.error
import urllib.request

from .base import UA, _empty, _to_int, band_of

DSL_STATUS = {"Up": "линия синхронизирована", "NoSignal": "НЕТ СИГНАЛА на линии DSL", "Initializing": "синхронизация линии",
              "EstablishingLink": "установка связи", "Error": "ошибка линии", "Disabled": "DSL выключен"}


class Tr064Router:
    kind = "tr064"

    def __init__(self, host, username, password, timeout=6):
        self.base = f"http://{host}:49000"
        self.timeout = timeout
        mgr = urllib.request.HTTPPasswordMgrWithDefaultRealm()
        mgr.add_password(None, self.base, username or "", password or "")
        self.opener = urllib.request.build_opener(urllib.request.HTTPDigestAuthHandler(mgr))
        self.services = {}

    def _discover(self):
        for desc in ("/tr64desc.xml", "/igddesc.xml"):
            try:
                with self.opener.open(urllib.request.Request(self.base + desc, headers=UA), timeout=self.timeout) as r:
                    xml = r.read().decode("utf-8", errors="replace")
            except Exception:  # noqa: BLE001
                continue
            for stype, ctrl in re.findall(r"<serviceType>([^<]+)</serviceType>.*?<controlURL>([^<]+)</controlURL>", xml, re.S):
                self.services.setdefault(stype.rsplit(":", 1)[0], (stype, ctrl))
            m = re.search(r"<modelName>([^<]*)</modelName>", xml)
            return m.group(1) if m else "TR-064"
        return None

    def soap(self, service_prefix, action, args=None):
        for key, (stype, ctrl) in self.services.items():
            if key.endswith(service_prefix):
                break
        else:
            raise KeyError(service_prefix)
        a = "".join(f"<{k}>{v}</{k}>" for k, v in (args or {}).items())
        body = (f'<?xml version="1.0"?><s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" '
                f's:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/"><s:Body><u:{action} xmlns:u="{stype}">{a}'
                f'</u:{action}></s:Body></s:Envelope>').encode()
        req = urllib.request.Request(self.base + ctrl, data=body, headers=dict(UA, **{
            "Content-Type": 'text/xml; charset="utf-8"', "SOAPAction": f'"{stype}#{action}"'}))
        with self.opener.open(req, timeout=self.timeout) as r:
            xml = r.read().decode("utf-8", errors="replace")
        return dict(re.findall(r"<(New[\w-]+)>([^<]*)</\1>", xml))

    def collect(self, full=True):
        out = _empty(self.kind)
        model = self._discover()
        if not model:
            out["notes"].append("TR-064 (порт 49000) недоступен — включите «Доступ для приложений» в настройках роутера.")
            return out
        out["reachable"] = True
        out["model"] = model
        raw = out["raw"]
        wan = out["wan"]

        def q(svc, action, args=None):
            try:
                res = self.soap(svc, action, args)
                raw[f"{svc}#{action}"] = res
                out["auth"] = "ok"
                return res
            except urllib.error.HTTPError as e:
                if e.code == 401:
                    out["auth"] = "failed"
                return {}
            except Exception:  # noqa: BLE001
                return {}

        di = q("DeviceInfo", "GetInfo")
        out["firmware"] = di.get("NewSoftwareVersion")
        out["uptime_sec"] = _to_int(di.get("NewUpTime"))
        lp = q("WANCommonInterfaceConfig", "GetCommonLinkProperties")
        if lp:
            wan["link"] = lp.get("NewPhysicalLinkStatus") == "Up"
            wan["phy_status"] = lp.get("NewPhysicalLinkStatus")
            wan["access_type"] = lp.get("NewWANAccessType")
            wan["link_speed_mbps"] = (_to_int(lp.get("NewLayer1DownstreamMaxBitRate")) or 0) // 1_000_000 or None
        for svc in ("WANPPPConnection", "WANIPConnection"):
            st = q(svc, "GetInfo")
            if st.get("NewConnectionStatus"):
                wan["proto"] = "pppoe" if "PPP" in svc else "ip"
                wan["connected"] = st["NewConnectionStatus"] == "Connected"
                wan["status_text"] = st["NewConnectionStatus"]
                wan["uptime_sec"] = _to_int(st.get("NewUptime"))
                wan["ip"] = st.get("NewExternalIPAddress")
                err = st.get("NewLastConnectionError")
                if err and err != "ERROR_NONE":
                    from .upnp import UPNP_ERRORS
                    wan["error_code"] = err
                    wan["error_text"] = UPNP_ERRORS.get(err, err)
                break
        dsl = q("WANDSLInterfaceConfig", "GetInfo")
        if dsl:
            dstats = q("WANDSLInterfaceConfig", "GetStatisticsTotal")
            out["dsl"] = {
                "status": dsl.get("NewStatus"), "status_text": DSL_STATUS.get(dsl.get("NewStatus"), dsl.get("NewStatus")),
                "down_kbps": _to_int(dsl.get("NewDownstreamCurrRate")), "up_kbps": _to_int(dsl.get("NewUpstreamCurrRate")),
                "down_max_kbps": _to_int(dsl.get("NewDownstreamMaxRate")), "up_max_kbps": _to_int(dsl.get("NewUpstreamMaxRate")),
                "snr_down_db": (_to_int(dsl.get("NewDownstreamNoiseMargin")) or 0) / 10,
                "snr_up_db": (_to_int(dsl.get("NewUpstreamNoiseMargin")) or 0) / 10,
                "atten_down_db": (_to_int(dsl.get("NewDownstreamAttenuation")) or 0) / 10,
                "atten_up_db": (_to_int(dsl.get("NewUpstreamAttenuation")) or 0) / 10,
                "crc_errors": _to_int(dstats.get("NewCRCErrors")), "fec_errors": _to_int(dstats.get("NewFECErrors")),
                "errored_seconds": _to_int(dstats.get("NewErroredSecs")), "severely_errored_seconds": _to_int(dstats.get("NewSeverelyErroredSecs")),
            }
            wan["link"] = dsl.get("NewStatus") == "Up"
        if full:
            mon = q("WANCommonInterfaceConfig", "X_AVM-DE_GetOnlineMonitor", {"NewSyncGroupIndex": 0})
            if mon:
                try:
                    wan["down_bps"] = int(str(mon.get("Newds_current_bps", "0")).split(",")[0]) * 8
                    wan["up_bps"] = int(str(mon.get("Newus_current_bps", "0")).split(",")[0]) * 8
                except ValueError:
                    pass
            n = _to_int(q("Hosts", "GetHostNumberOfEntries").get("NewHostNumberOfEntries")) or 0
            for i in range(min(n, 80)):
                h = q("Hosts", "GetGenericHostEntry", {"NewIndex": i})
                if h.get("NewActive") == "1":
                    out["devices"].append({"mac": (h.get("NewMACAddress") or "").lower(), "ip": h.get("NewIPAddress"),
                                           "name": h.get("NewHostName"), "conn": "Wi-Fi" if h.get("NewInterfaceType") == "802.11" else "LAN"})
            raw.pop("Hosts#GetGenericHostEntry", None)
            for idx in (1, 2, 3):
                w = q("WLANConfiguration", "GetInfo") if idx == 1 else {}
                if idx > 1:
                    try:
                        stype, ctrl = next(v for k, v in self.services.items() if k.endswith("WLANConfiguration"))
                        ctrl = ctrl[:-1] + str(idx)
                        self.services[f"WLANConfiguration{idx}"] = (stype, ctrl)
                        w = q(f"WLANConfiguration{idx}", "GetInfo")
                    except StopIteration:
                        w = {}
                if w.get("NewChannel"):
                    ch = _to_int(w.get("NewChannel"))
                    out["wifi_radios"].append({"band": band_of(ch), "channel": ch, "ssid": w.get("NewSSID"),
                                               "enabled": w.get("NewEnable") == "1", "standard": w.get("NewStandard")})
            log = q("DeviceInfo", "GetDeviceLog").get("NewDeviceLog", "")
            out["log"] = [l for l in log.splitlines() if re.search(r"DSL|PPP|Internet|WAN|Verbindung|connection|Zeitüberschreitung|LCP|Sync", l, re.I)][:40]
        if out["auth"] is None:
            out["notes"].append("Fritz!Box/TR-064: введите логин и пароль роутера в «Настройки → Роутер и модем».")
        return out
