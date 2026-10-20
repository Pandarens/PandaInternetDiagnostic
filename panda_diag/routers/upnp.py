"""UPnP IGD (most consumer routers) + DSL line stats when exposed."""
import re
import socket

from .base import _http, _empty, _to_int, _to_float  # noqa: F401


# =========================================================================== UPnP IGD (most consumer routers)

WAN_SERVICES = ("urn:schemas-upnp-org:service:WANIPConnection:", "urn:schemas-upnp-org:service:WANPPPConnection:")
WAN_CIF = "urn:schemas-upnp-org:service:WANCommonInterfaceConfig:"


def ssdp_discover(gateway=None, timeout=2.5):
    msg = ("M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 2\r\n"
           "ST: urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\n\r\n").encode()
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    found = []
    try:
        s.sendto(msg, ("239.255.255.250", 1900))
        while True:
            data, addr = s.recvfrom(4096)
            m = re.search(r"^location:\s*(\S+)", data.decode(errors="ignore"), re.I | re.M)
            if m and m.group(1) not in found and (gateway is None or addr[0] == gateway):
                found.append(m.group(1))
    except OSError:
        pass
    finally:
        s.close()
    return found


class UpnpRouter:
    kind = "upnp"

    def __init__(self, gateway, timeout=4):
        self.gateway = gateway
        self.timeout = timeout

    def _soap(self, control_url, service, action):
        body = (f'<?xml version="1.0"?><s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" '
                f's:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/"><s:Body>'
                f'<u:{action} xmlns:u="{service}"/></s:Body></s:Envelope>').encode()
        _, xml = _http(control_url, data=body, timeout=self.timeout,
                       headers={"Content-Type": 'text/xml; charset="utf-8"', "SOAPAction": f'"{service}#{action}"'})
        return dict(re.findall(r"<(New\w+)>([^<]*)</\1>", xml))

    def collect(self, full=True):
        out = _empty(self.kind)
        locs = ssdp_discover(self.gateway)
        if not locs:
            out["notes"].append("Роутер не отвечает по UPnP (отключён в настройках) — состояние WAN роутера недоступно.")
            return out
        try:
            _, desc = _http(locs[0], timeout=self.timeout)
        except Exception as e:  # noqa: BLE001
            out["notes"].append(f"UPnP описание недоступно: {e}")
            return out
        out["reachable"] = True
        out["auth"] = "ok"
        base = re.search(r"^(https?://[^/]+)", locs[0]).group(1)
        m = re.search(r"<modelName>([^<]*)</modelName>", desc)
        out["model"] = m.group(1) if m else None
        services = re.findall(r"<serviceType>([^<]+)</serviceType>.*?<controlURL>([^<]+)</controlURL>", desc, re.S)
        wan = out["wan"]
        for stype, ctrl in services:
            url = ctrl if ctrl.startswith("http") else base + (ctrl if ctrl.startswith("/") else "/" + ctrl)
            try:
                if stype.startswith(WAN_SERVICES):
                    st = self._soap(url, stype, "GetStatusInfo")
                    out["raw"][stype + "#GetStatusInfo"] = st
                    if st.get("NewConnectionStatus") and (wan.get("connected") is not True):
                        wan["connected"] = st["NewConnectionStatus"] == "Connected"
                        wan["status_text"] = st["NewConnectionStatus"]
                        wan["proto"] = "pppoe" if "PPP" in stype else "ip"
                        wan["uptime_sec"] = _to_int(st.get("NewUptime"))
                        err = st.get("NewLastConnectionError")
                        if err and err != "ERROR_NONE":
                            wan["error_code"] = err
                            wan["error_text"] = UPNP_ERRORS.get(err, err)
                    ip = self._soap(url, stype, "GetExternalIPAddress").get("NewExternalIPAddress")
                    if ip and ip != "0.0.0.0":
                        wan["ip"] = ip
                elif stype.startswith(WAN_CIF):
                    lp = self._soap(url, stype, "GetCommonLinkProperties")
                    out["raw"][stype + "#GetCommonLinkProperties"] = lp
                    if lp.get("NewPhysicalLinkStatus"):
                        wan["link"] = lp["NewPhysicalLinkStatus"] == "Up"
                        wan["phy_status"] = lp["NewPhysicalLinkStatus"]
                    mx = _to_int(lp.get("NewLayer1DownstreamMaxBitRate"))
                    if mx:
                        wan["link_speed_mbps"] = mx // 1_000_000
            except Exception:  # noqa: BLE001
                continue
        return out


UPNP_ERRORS = {
    "ERROR_ISP_TIME_OUT": "Провайдер не отвечает (таймаут) — нет связи на линии",
    "ERROR_COMMAND_ABORTED": "Подключение прервано",
    "ERROR_NOT_ENABLED_FOR_INTERNET": "WAN не включён для Интернета",
    "ERROR_BAD_PHONE_NUMBER": "Неверные параметры подключения",
    "ERROR_USER_DISCONNECT": "Отключено пользователем",
    "ERROR_ISP_DISCONNECT": "Провайдер разорвал соединение",
    "ERROR_IDLE_DISCONNECT": "Отключено по простою",
    "ERROR_FORCED_DISCONNECT": "Принудительное отключение",
    "ERROR_SERVER_OUT_OF_RESOURCES": "Сервер провайдера перегружен",
    "ERROR_RESTRICTED_LOGON_HOURS": "Вход запрещён в это время",
    "ERROR_ACCOUNT_DISABLED": "Учётная запись отключена провайдером (долг/блокировка)",
    "ERROR_ACCOUNT_EXPIRED": "Учётная запись истекла",
    "ERROR_PASSWORD_EXPIRED": "Пароль истёк",
    "ERROR_AUTHENTICATION_FAILURE": "Ошибка авторизации у провайдера (логин/пароль)",
    "ERROR_NO_DIALTONE": "Нет сигнала на линии (DSL/оптика)",
    "ERROR_NO_CARRIER": "Нет несущей — нет сигнала от провайдера",
    "ERROR_NO_ANSWER": "Провайдер не отвечает",
    "ERROR_LINE_BUSY": "Линия занята",
    "ERROR_UNSUPPORTED_BITSPERSECOND": "Неподдерживаемая скорость линии",
    "ERROR_TOO_MANY_LINE_ERRORS": "Слишком много ошибок на линии (плохой сигнал/кабель)",
    "ERROR_IP_CONFIGURATION": "Ошибка получения IP от провайдера",
    "ERROR_UNKNOWN": "Неизвестная ошибка",
}
