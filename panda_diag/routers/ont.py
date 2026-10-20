"""Optical terminals (GPON/EPON ONT): read optical RX/TX power, temperature and PON link state.

Experimental: ONT web interfaces differ between firmware builds and ISP customisations.
Supported: Huawei HG8245/HG8145/HG8546/EG8145/HS8145 and ZTE F660/F670/F680/F6600 families.
"""
import base64
import hashlib
import http.cookiejar
import re
import urllib.parse
import urllib.request

from .base import INSECURE, UA, _empty, parse_dbm


class _Web:
    def __init__(self, base, timeout=6):
        self.base = base
        self.timeout = timeout
        self.jar = http.cookiejar.CookieJar()
        self.opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(self.jar),
                                                  urllib.request.HTTPSHandler(context=INSECURE))

    def req(self, path, data=None, headers=None):
        if isinstance(data, dict):
            data = urllib.parse.urlencode(data).encode()
        r = urllib.request.Request(self.base + path, data=data, headers=dict(UA, **(headers or {})))
        with self.opener.open(r, timeout=self.timeout) as resp:
            return resp.read().decode("utf-8", errors="replace")


def _optics_from_text(text):
    """Find RX/TX power, temperature in any ONT page/JS/XML."""
    o = {}
    pats = {
        "rx_dbm": [r"RxPower['\"]?\s*[,:=]\s*['\"]?(-?[\d.]+)", r"Fnt_RxPower[^>]*>\s*(-?[\d.]+)",
                   r"(?:RX|Rx|Receive)\s*(?:optical\s*)?power[^-\d]{0,40}(-?[\d.]+)"],
        "tx_dbm": [r"TxPower['\"]?\s*[,:=]\s*['\"]?(-?[\d.]+)", r"Fnt_TxPower[^>]*>\s*(-?[\d.]+)",
                   r"(?:TX|Tx|Transmit)\s*(?:optical\s*)?power[^-\d]{0,40}(-?[\d.]+)"],
        "temp_c": [r"(?:Temperature|WorkTemperature)['\"]?\s*[,:=]\s*['\"]?(-?[\d.]+)"],
    }
    for key, plist in pats.items():
        for p in plist:
            m = re.search(p, text, re.I)
            if m:
                o[key] = parse_dbm(m.group(1)) if key != "temp_c" else float(m.group(1))
                break
    return o


class HuaweiOnt:
    kind = "ont_huawei"

    def __init__(self, host, username, password):
        self.web = _Web(f"http://{host}")
        self.username = username or "root"
        self.password = password or "admin"

    def collect(self, full=True):
        out = _empty(self.kind)
        w = self.web
        try:
            w.req("/")
        except Exception as e:  # noqa: BLE001
            out["notes"].append(f"ONT Huawei не отвечает: {e}")
            return out
        out["reachable"] = True
        try:
            token = w.req("/asp/GetRandCount.asp", data=b"").strip().lstrip("﻿")
            self.web.jar.set_cookie(http.cookiejar.Cookie(0, "Cookie", "body:Language:english:id=-1", None, False,
                                                          self.web.base.split("//")[1], False, False, "/", True, False,
                                                          None, False, None, None, {}))
            w.req("/login.cgi", data={"UserName": self.username,
                                      "PassWord": base64.b64encode(self.password.encode()).decode(),
                                      "Language": "english", "x.X_HW_Token": token})
        except Exception as e:  # noqa: BLE001
            out["notes"].append(f"ONT Huawei: вход не выполнен ({e})")
            return out
        text = ""
        for page in ("/html/amp/opticinfo/opticinfo.asp", "/html/ssmp/opticinfo/opticinfo.asp"):
            try:
                text = w.req(page)
                if "stOpticInfo" in text or "Optic" in text:
                    break
            except Exception:  # noqa: BLE001
                continue
        m = re.search(r"new\s+stOpticInfo\(([^)]*)\)", text)
        if m:
            args = re.findall(r'"([^"]*)"', m.group(1))
            # domain, TxPower, RxPower, Voltage, Temperature, Bias, ...
            if len(args) >= 6:
                out["optics"] = {"tx_dbm": parse_dbm(args[1]), "rx_dbm": parse_dbm(args[2]),
                                 "voltage_mv": args[3], "temp_c": parse_dbm(args[4]), "bias_ma": args[5]}
        if not out["optics"]:
            out["optics"] = _optics_from_text(text)
        out["auth"] = "ok" if out["optics"] else "failed"
        if not out["optics"]:
            out["notes"].append("ONT Huawei: не удалось прочитать оптические параметры (проверьте логин/пароль ONT — часто root/admin или telecomadmin/admintelecom).")
        try:
            st = w.req("/html/amp/ponstatus/ponstatus.asp") if full else ""
            m = re.search(r"var\s+ontPonState\s*=\s*['\"]?(\w+)", st) or re.search(r"(O[1-7])\b", st)
            if m:
                out["optics"]["pon_state"] = m.group(1)
        except Exception:  # noqa: BLE001
            pass
        return out


class ZteOnt:
    kind = "ont_zte"

    def __init__(self, host, username, password):
        self.web = _Web(f"http://{host}")
        self.username = username or "admin"
        self.password = password or "admin"

    def collect(self, full=True):
        out = _empty(self.kind)
        w = self.web
        try:
            page = w.req("/")
        except Exception as e:  # noqa: BLE001
            out["notes"].append(f"ONT ZTE не отвечает: {e}")
            return out
        out["reachable"] = True
        try:
            tok = re.search(r'Frm_Logintoken"\)\.value\s*=\s*"(\d+)"', page)
            chk = re.search(r'Frm_Loginchecktoken"\)\.value\s*=\s*"(\w+)"', page)
            rnd = re.search(r"UserRandomNum\s*=\s*['\"]?(\d+)", page) or re.search(r'id="UserRandomNum"[^>]*value="(\d+)"', page)
            data = {"action": "login", "Username": self.username,
                    "Frm_Logintoken": tok.group(1) if tok else ""}
            if rnd:  # newer firmware: sha256(password + random)
                data["Password"] = hashlib.sha256((self.password + rnd.group(1)).encode()).hexdigest()
                data["UserRandomNum"] = rnd.group(1)
            else:
                data["Password"] = self.password
            if chk:
                data["Frm_Loginchecktoken"] = chk.group(1)
            w.req("/", data=data)
        except Exception as e:  # noqa: BLE001
            out["notes"].append(f"ONT ZTE: вход не выполнен ({e})")
        texts = []
        for path in ("/getpage.gch?pid=1002&nextpage=pon_status_link_info_t.gch",
                     "/getpage.gch?pid=1002&nextpage=gpon_status_link_info_t.gch",
                     "/?_type=menuData&_tag=optical_info_lua.lua",
                     "/?_type=menuData&_tag=pon_status_link_info_lua.lua"):
            try:
                t = w.req(path)
                texts.append(t)
                o = _optics_from_text(t)
                if o.get("rx_dbm") is not None:
                    out["optics"] = o
                    break
            except Exception:  # noqa: BLE001
                continue
        out["auth"] = "ok" if out["optics"] else "failed"
        if not out["optics"]:
            out["notes"].append("ONT ZTE: оптические параметры не прочитаны (логин/пароль ONT — часто admin/admin или указан на наклейке).")
        joined = "\n".join(texts)
        m = re.search(r"(?:RegStatus|ONU\s*State|OnuState)[^\w]{0,20}(\w+)", joined, re.I)
        if m:
            out["optics"]["pon_state"] = m.group(1)
        return out


def make_ont(cfg):
    if not cfg or not cfg.get("host"):
        return None
    t = (cfg.get("type") or "auto").lower()
    if t == "auto":
        try:
            page = _Web(f"http://{cfg['host']}", timeout=3).req("/")
            t = "zte" if re.search(r"zte|Frm_Logintoken|ZXHN", page, re.I) else "huawei"
        except Exception:  # noqa: BLE001
            t = "huawei"
    cls = ZteOnt if t == "zte" else HuaweiOnt
    return cls(cfg["host"], cfg.get("username"), cfg.get("password"))
