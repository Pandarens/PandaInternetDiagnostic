"""Router auto-detection and driver factory."""
import re
import urllib.error
import urllib.request

from .asus import AsusRouter
from .base import INSECURE, UA
from .keenetic import KeeneticRouter
from .mikrotik import MikroTikRouter
from .ont import make_ont
from .openwrt import OpenWrtRouter
from .optional import HuaweiLteRouter, TplinkRouter
from .snmp import SnmpRouter
from .tr064 import Tr064Router
from .upnp import UpnpRouter
from .xiaomi import XiaomiRouter

SUPPORTED = {
    "xiaomi": "Xiaomi / Redmi (MiWiFi)",
    "mikrotik": "MikroTik (RouterOS 7 REST)",
    "keenetic": "Keenetic (RCI API)",
    "asus": "ASUS (ASUSWRT / Merlin)",
    "openwrt": "OpenWrt / ImmortalWrt (ubus)",
    "tplink": "TP-Link (Archer, Deco, MR/MX LTE…) — нужен pip install tplinkrouterc6u",
    "tr064": "AVM Fritz!Box и др. TR-064 (вкл. DSL-статистику)",
    "huawei_lte": "Huawei 4G/LTE модемы (HiLink) — нужен pip install huawei-lte-api",
    "upnp": "Любой роутер с UPnP IGD (только состояние WAN)",
    "snmp": "Любое устройство с SNMP v2c (порты, ошибки, скорости)",
}

# OUI prefixes -> vendor (most common home router vendors in RU/KZ/UA/EU)
OUI = {
    "MikroTik": ["64-d1-54", "18-fd-74", "2c-c8-1b", "48-8f-5a", "4c-5e-0c", "6c-3b-6b", "b8-69-f4", "c4-ad-34",
                 "cc-2d-e0", "d4-01-c3", "dc-2c-6e", "e4-8d-8c", "74-4d-28", "08-55-31", "78-9a-18", "d4-ca-6d"],
    "Xiaomi": ["28-6c-07", "34-ce-00", "50-64-2b", "64-09-80", "78-11-dc", "8c-be-be", "9c-9d-7e", "d4-35-38",
               "f0-b4-29", "24-cf-24", "e4-46-da", "88-c3-97", "c8-bf-4c", "cc-d8-43", "3c-cd-57", "a4-a9-30",
               "58-ea-1f", "64-64-4a", "d4-da-21", "ac-c1-ee", "f4-6a-dd", "88-28-7d", "54-48-e6", "8c-53-c3"],
    "Keenetic": ["50-ff-20", "ec-43-f6", "50-67-f0", "40-4a-03", "5c-f4-ab", "e8-37-7a", "b0-b2-dc", "fc-f5-28",
                 "90-ef-68", "cc-5d-4e", "c8-6c-87", "54-83-3a", "00-23-f8", "bc-cf-4f"],
    "ASUS": ["04-d4-c4", "08-60-6e", "0c-9d-92", "10-7b-44", "14-da-e9", "1c-87-2c", "24-4b-fe", "2c-56-dc",
             "30-5a-3a", "38-d5-47", "40-b0-76", "4c-ed-fb", "50-eb-f6", "60-45-cb", "70-4d-7b", "74-d0-2b",
             "88-d7-f6", "9c-5c-8e", "a8-5e-45", "ac-22-0b", "b0-6e-bf", "c8-7f-54", "d4-5d-64", "e8-9c-25",
             "f0-79-59", "fc-34-97", "3c-7c-3f", "7c-10-c9", "d8-50-e6", "04-42-1a"],
    "TP-Link": ["14-cc-20", "18-a6-f7", "30-b5-c2", "50-c7-bf", "54-af-97", "60-32-b1", "64-70-02", "6c-5a-b0",
                "98-da-c4", "a0-f3-c1", "b0-4e-26", "c0-06-c3", "c4-6e-1f", "d8-07-b6", "e8-48-b8", "f4-f2-6d",
                "1c-61-b4", "3c-84-6a", "5c-a6-e6", "78-8c-b5", "9c-a2-f4", "ac-84-c6", "b0-a7-b9", "cc-32-e5",
                "e4-c3-2a", "ec-08-6b", "f0-a7-31", "50-91-e3", "00-31-92", "28-87-ba", "3c-52-a1", "68-ff-7b"],
    "AVM": ["3c-a6-2f", "44-4e-6d", "7c-ff-4d", "98-9b-cb", "c0-25-06", "dc-39-6f", "e0-28-6d", "2c-91-ab", "38-10-d5"],
    "Huawei": ["00-e0-fc", "08-19-a6", "20-f3-a3", "48-46-fb", "5c-7d-5e", "70-72-3c", "80-b6-86", "ac-e2-15",
               "e8-cd-2d", "f4-c7-14", "00-9a-cd", "24-df-6a", "34-6b-d3", "50-01-6b", "64-16-f0", "e0-24-7f"],
    "ZTE": ["00-19-c6", "08-18-1a", "34-4b-50", "4c-09-d4", "6c-a7-5f", "80-b0-7b", "98-f5-37", "c8-64-c7",
            "d0-5b-a8", "f4-6d-e2", "fc-2d-5e", "dc-02-8e", "00-26-ed"],
    "Tenda": ["c8-3a-35", "cc-b2-55", "d8-32-14", "50-2b-73", "04-95-e6"],
    "D-Link": ["00-1e-58", "1c-7e-e5", "28-10-7b", "34-08-04", "78-54-2e", "b0-c5-54", "c4-a8-1d", "f0-7d-68", "1c-af-f7"],
    "Ubiquiti": ["04-18-d6", "24-a4-3c", "44-d9-e7", "68-72-51", "78-8a-20", "80-2a-a8", "b4-fb-e4", "dc-9f-db", "f0-9f-c2", "fc-ec-da"],
    "Netis": ["04-8d-38", "e8-1b-69"],
}
VENDOR_DRIVER = {"MikroTik": "mikrotik", "Xiaomi": "xiaomi", "Keenetic": "keenetic", "ASUS": "asus",
                 "TP-Link": "tplink", "AVM": "tr064"}


def vendor_by_mac(mac):
    if not mac:
        return None
    p = mac.lower().replace(":", "-")[:8]
    for vendor, prefixes in OUI.items():
        if p in prefixes:
            return vendor
    return None


def _fetch(url, timeout=3):
    try:
        req = urllib.request.Request(url, headers=UA)
        with urllib.request.urlopen(req, timeout=timeout, context=INSECURE if url.startswith("https") else None) as r:
            return r.status, dict(r.headers), r.read(30000).decode("utf-8", errors="replace")
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers or {}), ""
    except Exception:  # noqa: BLE001
        return None, {}, ""


def fingerprint(host):
    """Guess router family from its web interface."""
    code, headers, body = _fetch(f"http://{host}/")
    if code is None:
        code, headers, body = _fetch(f"https://{host}/")
    text = (body + " " + " ".join(f"{k}:{v}" for k, v in headers.items())).lower()
    if "x-ndm" in text or "keenetic" in text or "ndms" in text:
        return "keenetic"
    c2, h2, _ = _fetch(f"http://{host}/auth")
    if any(k.lower().startswith("x-ndm") for k in h2):
        return "keenetic"
    if "asustek" in text or "asus router" in text or "httpd/2.0" in text and "asus" in text:
        return "asus"
    if "miwifi" in text or "xiaoqiang" in text:
        return "xiaomi"
    c3, _, b3 = _fetch(f"http://{host}/cgi-bin/luci/api/xqsystem/init_info")
    if c3 == 200 and "romversion" in b3:
        return "xiaomi"
    if "mikrotik" in text or "routeros" in text or "webfig" in text:
        return "mikrotik"
    if "tp-link" in text or "tplink" in text or "tp_link" in text:
        return "tplink"
    if "fritz!box" in text or "avm" in text and "fritz" in text:
        return "tr064"
    if "openwrt" in text or "luci" in text or "immortalwrt" in text:
        return "openwrt"
    c4, _, b4 = _fetch(f"http://{host}/api/device/basic_information")
    if c4 == 200 and "<response>" in b4.lower():
        return "huawei_lte"
    title = re.search(r"<title>([^<]*)</title>", body, re.I)
    return {"_title": title.group(1).strip() if title else None}


def detect(host, mac=None, forced=None):
    if forced and forced != "auto":
        return forced, {"method": "config"}
    vendor = vendor_by_mac(mac)
    if vendor in VENDOR_DRIVER:
        return VENDOR_DRIVER[vendor], {"method": "mac", "vendor": vendor}
    fp = fingerprint(host)
    if isinstance(fp, str):
        return fp, {"method": "web", "vendor": vendor}
    return "upnp", {"method": "fallback", "vendor": vendor, "web_title": fp.get("_title")}


def make_driver(kind, rcfg, host):
    u, p = rcfg.get("username"), rcfg.get("password")
    if kind == "xiaomi":
        return XiaomiRouter(host, p, u or "admin")
    if kind == "mikrotik":
        return MikroTikRouter(host, u or "admin", p or "", rcfg.get("https", True), rcfg.get("wan_interface") or "ether1")
    if kind == "keenetic":
        return KeeneticRouter(host, u, p)
    if kind == "asus":
        return AsusRouter(host, u, p)
    if kind == "openwrt":
        return OpenWrtRouter(host, u if u and u != "admin" else "root", p)
    if kind == "tplink":
        return TplinkRouter(host, u, p)
    if kind == "tr064":
        return Tr064Router(host, u, p)
    if kind == "huawei_lte":
        return HuaweiLteRouter(host, u, p)
    if kind == "snmp":
        return SnmpRouter(host, rcfg.get("snmp_community") or "public", rcfg.get("wan_interface"))
    return UpnpRouter(host)


def _has_wan(r):
    return bool(r and r.get("auth") == "ok" and any(v is not None for v in r.get("wan", {}).values()))


def collect_router(rcfg, gateway, gw_mac, full=True, cache=None):
    """Collect router state; falls back to UPnP / SNMP when the vendor API is not accessible."""
    host = rcfg.get("host") or gateway
    if not host or rcfg.get("type") == "none":
        return None
    cache = cache if cache is not None else {}
    if cache.get("host") != host:
        kind, how = detect(host, gw_mac, rcfg.get("type"))
        cache.clear()
        cache.update({"host": host, "kind": kind, "how": how})
    kind = cache["kind"]
    res = make_driver(kind, rcfg, host).collect(full)
    res["detected_by"] = cache["how"]
    if not _has_wan(res) and kind not in ("upnp", "snmp"):
        for fb in ("upnp", "snmp"):
            alt = make_driver(fb, rcfg, host).collect(full)
            if _has_wan(alt) or alt.get("ports"):
                res["fallback"] = fb
                for k in ("wan", "ports", "optics", "devices", "model", "firmware", "uptime_sec", "cpu_load",
                          "mem_pct", "temperature", "sfp", "wifi_radios"):
                    if not res.get(k) and alt.get(k):
                        res[k] = alt[k]
                res["notes"] += [f"Данные WAN получены через {fb.upper()}."]
                break
    return res


def collect_ont(ocfg, full=True):
    drv = make_ont(ocfg)
    return drv.collect(full) if drv else None


__all__ = ["SUPPORTED", "collect_router", "collect_ont", "detect", "vendor_by_mac", "fingerprint"]
