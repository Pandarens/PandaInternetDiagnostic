"""Settings: defaults merged with config.json.

exe build: data and config live in %LOCALAPPDATA%\\PandaInternetDiagnostic (the exe can sit in Downloads);
a config.json next to the exe still wins (portable mode). Source checkout: everything stays in the project folder.
"""
import copy
import json
import os
import sys

APP_NAME = "PandaInternetDiagnostic"
FROZEN = getattr(sys, "frozen", False)

if FROZEN:
    EXE_DIR = os.path.dirname(sys.executable)
    BASE_DIR = os.path.join(os.environ.get("LOCALAPPDATA") or os.path.expanduser("~"), APP_NAME)
    _portable = os.path.join(EXE_DIR, "config.json")
    CONFIG_PATH = _portable if os.path.exists(_portable) else os.path.join(BASE_DIR, "config.json")
else:
    BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    EXE_DIR = BASE_DIR
    CONFIG_PATH = os.path.join(BASE_DIR, "config.json")
DATA_DIR = os.path.join(BASE_DIR, "data")
# downloaded code updates (hot-reloaded bundles)
UPDATES_DIR = os.path.join(BASE_DIR, "app")

DEFAULTS = {
    # Public hosts used to decide "is the internet there at all".
    "anchors": ["1.1.1.1", "8.8.8.8", "9.9.9.9"],
    # Gateway / first provider hop / provider modem are discovered automatically; set to force.
    "gateway": None,
    "isp_hop": None,
    "dns_test_name": "www.google.com",
    "http_check_url": "http://www.msftconnecttest.com/connecttest.txt",
    "http_check_expect": "Microsoft Connect Test",
    "ping_interval_sec": 1.0,
    "ping_timeout_ms": 1000,
    "slow_checks_interval_sec": 15,
    "system_checks_interval_sec": 20,
    "router_checks_interval_sec": 30,
    # How many consecutive seconds without internet count as an outage (shorter = "micro-drop").
    "outage_threshold_sec": 3,
    # Your plan speed (Mbit/s) - lets the tool detect a saturated channel. null = unknown.
    "tariff_mbps": None,
    "web_host": "127.0.0.1",
    "web_port": 8765,
    "speedtest_url": "https://speed.cloudflare.com/__down?bytes={bytes}",
    # Router access. type: "auto" | "xiaomi" | "mikrotik" | "keenetic" | "asus" | "openwrt" | "tplink"
    #                     | "tr064" | "huawei_lte" | "upnp" | "snmp" | "none"
    "router": {
        "type": "auto",
        "host": None,               # default: gateway IP
        "username": "admin",
        "password": "",
        "https": True,              # MikroTik REST only
        "wan_interface": "ether1",  # MikroTik / SNMP: name of the WAN port
        "snmp_community": "public",
    },
    # Optical terminal (GPON ONT) from the provider. type: "auto" | "huawei" | "zte". host e.g. "192.168.100.1"
    "ont": {
        "type": "auto",
        "host": None,
        "username": "",
        "password": "",
    },
}


def _merge(base, extra):
    for k, v in extra.items():
        if isinstance(v, dict) and isinstance(base.get(k), dict):
            _merge(base[k], v)
        else:
            base[k] = v
    return base


def load():
    cfg = copy.deepcopy(DEFAULTS)
    if os.path.exists(CONFIG_PATH):
        with open(CONFIG_PATH, "r", encoding="utf-8-sig") as f:
            _merge(cfg, json.load(f))
    os.makedirs(DATA_DIR, exist_ok=True)
    return cfg


def write_example():
    path = os.path.join(BASE_DIR, "config.example.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump(DEFAULTS, f, ensure_ascii=False, indent=2)
    return path
