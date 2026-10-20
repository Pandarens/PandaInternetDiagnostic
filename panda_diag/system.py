"""Local machine probes: adapters, Wi-Fi, routes, DNS, HTTP, throughput, Windows event log."""
import ipaddress
import json
import random
import re
import socket
import struct
import subprocess
import time
import urllib.request

CREATE_NO_WINDOW = 0x08000000


def _run(args, timeout=20, encoding="utf-8"):
    try:
        p = subprocess.run(args, capture_output=True, timeout=timeout, creationflags=CREATE_NO_WINDOW)
        return p.stdout.decode(encoding, errors="replace")
    except Exception:  # noqa: BLE001
        return ""


def powershell(script, timeout=25):
    full = "[Console]::OutputEncoding=[Text.Encoding]::UTF8;$ErrorActionPreference='SilentlyContinue';" + script
    return _run(["powershell", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", full],
                timeout=timeout)


def _json(text):
    text = (text or "").strip()
    if not text:
        return None
    try:
        return json.loads(text)
    except ValueError:
        return None


def _as_list(v):
    if v is None:
        return []
    return v if isinstance(v, list) else [v]


# ---------------------------------------------------------------- adapters / routes

_NET_PS = r"""
$routes = Get-NetRoute -AddressFamily IPv4 -DestinationPrefix 0.0.0.0/0 | Sort-Object {$_.RouteMetric + $_.InterfaceMetric}
$ad = Get-NetAdapter -Physical | ForEach-Object {
  $s = Get-NetAdapterStatistics -Name $_.Name
  $ip = Get-NetIPAddress -InterfaceIndex $_.ifIndex -AddressFamily IPv4 | Select-Object -First 1
  $dns = (Get-DnsClientServerAddress -InterfaceIndex $_.ifIndex -AddressFamily IPv4).ServerAddresses
  $sd = Get-NetAdapterAdvancedProperty -Name $_.Name | Where-Object { $_.RegistryKeyword -eq '*SpeedDuplex' } | Select-Object -First 1
  $eee = Get-NetAdapterAdvancedProperty -Name $_.Name | Where-Object { $_.RegistryKeyword -match 'EEE|GreenEthernet|PowerSavingMode' } | ForEach-Object { "$($_.DisplayName)=$($_.DisplayValue)" }
  [pscustomobject]@{
    name=$_.Name; description=$_.InterfaceDescription; status="$($_.Status)"; index=$_.ifIndex
    media="$($_.PhysicalMediaType)"; mac=$_.MacAddress
    link_bps=[int64]$_.ReceiveLinkSpeed; tx_link_bps=[int64]$_.TransmitLinkSpeed; full_duplex=$_.FullDuplex
    driver=$_.DriverDescription; driver_version=$_.DriverVersionString; driver_service=$_.DriverName
    speed_duplex_setting = $(if ($sd) { "$($sd.DisplayValue)" } else { $null })
    power_saving = @($eee)
    rx_bytes=[int64]$s.ReceivedBytes; tx_bytes=[int64]$s.SentBytes
    rx_errors=[int64]$s.ReceivedPacketErrors; tx_errors=[int64]$s.OutboundPacketErrors
    rx_discards=[int64]$s.ReceivedDiscardedPackets; tx_discards=[int64]$s.OutboundDiscardedPackets
    ipv4 = $(if ($ip) { "$($ip.IPAddress)/$($ip.PrefixLength)" } else { $null })
    ip_origin = $(if ($ip) { "$($ip.PrefixOrigin)" } else { $null })
    dns=@($dns)
  }
}
[pscustomobject]@{
  routes=@($routes | ForEach-Object { [pscustomobject]@{ index=$_.ifIndex; alias=$_.InterfaceAlias; gateway=$_.NextHop; metric=$_.RouteMetric + $_.InterfaceMetric } })
  adapters=@($ad)
} | ConvertTo-Json -Depth 5 -Compress
"""


def network_state():
    data = _json(powershell(_NET_PS)) or {}
    adapters = _as_list(data.get("adapters"))
    routes = _as_list(data.get("routes"))
    by_index = {a.get("index"): a for a in adapters}
    primary = None
    gateway = None
    for r in routes:
        a = by_index.get(r.get("index"))
        if a and a.get("status") == "Up":
            primary, gateway = a, r.get("gateway")
            break
    if primary is None:
        up = [a for a in adapters if a.get("status") == "Up"]
        primary = up[0] if up else (adapters[0] if adapters else None)
    if primary is not None:
        primary["is_wifi"] = is_wifi(primary)
    return {"adapters": adapters, "routes": routes, "primary": primary, "gateway": gateway}


def is_wifi(adapter):
    text = " ".join(str(adapter.get(k) or "") for k in ("media", "description", "name")).lower()
    return any(w in text for w in ("802.11", "wireless", "wi-fi", "wifi", "wlan", "беспровод"))


def gateway_mac(ip):
    out = _run(["arp", "-a", ip], encoding="oem")
    m = re.search(re.escape(ip) + r"\s+([0-9a-f]{2}(?:-[0-9a-f]{2}){5})", out, re.I)
    return m.group(1).lower() if m else None


# ---------------------------------------------------------------- Wi-Fi

_WIFI_KEYS = {
    "state": ("state", "состояние"),
    "ssid": ("ssid",),
    "bssid": ("bssid", "ap bssid"),
    "radio": ("radio type", "тип радио", "тип радиомодуля"),
    "band": ("band", "диапазон"),
    "channel": ("channel", "канал"),
    "rx_mbps": ("receive rate (mbps)", "скорость приема (мбит/с)", "скорость приёма (мбит/с)"),
    "tx_mbps": ("transmit rate (mbps)", "скорость передачи (мбит/с)"),
    "signal": ("signal", "сигнал"),
    "rssi": ("rssi",),
    "auth": ("authentication", "проверка подлинности"),
}


def wifi_state():
    out = _run(["netsh", "wlan", "show", "interfaces"], encoding="oem")
    if not out or ":" not in out:
        return None
    result = {}
    for line in out.splitlines():
        if ":" not in line:
            continue
        key, _, val = line.partition(":")
        key, val = key.strip().lower(), val.strip()
        for field, names in _WIFI_KEYS.items():
            if key in names and field not in result:
                result[field] = val
    if not result.get("state") and not result.get("ssid"):
        return None
    if "bssid" in result:
        # partition() split the MAC on the first colon
        m = re.search(r"bssid\s*:\s*([0-9a-f:]{17})", out, re.I)
        result["bssid"] = m.group(1).lower() if m else result["bssid"]
    m = re.search(r"(\d+)\s*%", result.get("signal", ""))
    result["signal_pct"] = int(m.group(1)) if m else None
    m = re.search(r"-?\d+", result.get("rssi", ""))
    rssi = int(m.group(0)) if m else None
    if rssi is None and result["signal_pct"] is not None:
        rssi = round(result["signal_pct"] / 2 - 100)  # Windows maps -100..-50 dBm to 0..100 %
    result["rssi_dbm"] = rssi
    st = result.get("state", "").lower()
    result["connected"] = st in ("connected", "подключено") or bool(result.get("bssid"))
    for k in ("rx_mbps", "tx_mbps", "channel"):
        try:
            result[k] = float(result[k].replace(",", ".")) if k != "channel" else int(result[k])
        except (KeyError, ValueError):
            result[k] = None
    return result


# ---------------------------------------------------------------- DNS

def _dns_query_packet(name, qid):
    header = struct.pack(">HHHHHH", qid, 0x0100, 1, 0, 0, 0)
    q = b"".join(bytes([len(p)]) + p.encode("ascii") for p in name.split(".")) + b"\x00"
    return header + q + struct.pack(">HH", 1, 1)


DNS_RCODES = {0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN", 4: "NOTIMP", 5: "REFUSED"}


def dns_query(server, name, timeout=2.0):
    """Raw UDP DNS query. Returns dict(ok, ms, rcode, answers)."""
    qid = random.randint(0, 0xFFFF)
    pkt = _dns_query_packet(name, qid)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    t0 = time.perf_counter()
    try:
        s.sendto(pkt, (server, 53))
        while True:
            data, _ = s.recvfrom(2048)
            if len(data) >= 12 and struct.unpack(">H", data[:2])[0] == qid:
                break
        ms = round((time.perf_counter() - t0) * 1000, 1)
        flags, _qd, an = struct.unpack(">HHH", data[2:8])
        rcode = flags & 0xF
        return {"server": server, "ok": rcode in (0, 3), "ms": ms, "rcode": DNS_RCODES.get(rcode, str(rcode)),
                "answers": an}
    except socket.timeout:
        return {"server": server, "ok": False, "ms": None, "rcode": "TIMEOUT", "answers": 0}
    except OSError as e:
        return {"server": server, "ok": False, "ms": None, "rcode": f"ERROR {e.errno}", "answers": 0}
    finally:
        s.close()


def dns_check(servers, name):
    servers = [s for s in (servers or []) if _is_ipv4(s)]
    results = {"system": [dns_query(s, name) for s in servers]}
    results["public"] = [dns_query(s, name) for s in ("1.1.1.1", "8.8.8.8")]
    return results


def _is_ipv4(s):
    try:
        return isinstance(ipaddress.ip_address(s), ipaddress.IPv4Address)
    except ValueError:
        return False


# ---------------------------------------------------------------- HTTP

def http_check(url, expect=None, timeout=5):
    t0 = time.perf_counter()
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "PandaInternetDiagnostic/1.0", "Cache-Control": "no-cache"})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            body = r.read(4096).decode("utf-8", errors="replace")
            final = r.geturl()
            code = r.status
        ms = round((time.perf_counter() - t0) * 1000)
        ok = code == 200 and (expect is None or expect in body)
        res = {"ok": ok, "code": code, "ms": ms, "final_url": final}
        if not ok:
            res["note"] = "redirect/подмена ответа (captive portal, блокировка или прокси)" if code == 200 else f"HTTP {code}"
        return res
    except Exception as e:  # noqa: BLE001
        return {"ok": False, "code": None, "ms": None, "error": f"{type(e).__name__}: {e}"}


def tcp_connect(host, port, timeout=2.0):
    t0 = time.perf_counter()
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return {"ok": True, "ms": round((time.perf_counter() - t0) * 1000, 1)}
    except OSError as e:
        return {"ok": False, "ms": None, "error": str(e)}


# ---------------------------------------------------------------- throughput

def speedtest(url_tpl, seconds=8, streams=6, chunk=25_000_000, ping_targets=None):
    """Download in parallel streams for N seconds; returns Mbit/s. Each stream re-requests 25 MB chunks
    (Cloudflare refuses single requests of 100 MB and more).
    ping_targets {name: ip}: pinged every 250 ms during the download -> latency under load (router/bufferbloat test)."""
    import threading
    from . import icmp
    total = [0]
    lock = threading.Lock()
    stop = time.perf_counter() + seconds
    errors = []
    loaded = {k: [] for k in (ping_targets or {})}

    def pinger():
        time.sleep(1.5)  # let TCP ramp up first
        while time.perf_counter() < stop:
            for k, ip in (ping_targets or {}).items():
                r = icmp.ping(ip, 1000)
                loaded[k].append(r["rtt"] if r["ok"] else None)
            time.sleep(0.25)

    if ping_targets:
        threading.Thread(target=pinger, daemon=True).start()

    def worker():
        while time.perf_counter() < stop:
            try:
                req = urllib.request.Request(url_tpl.format(bytes=chunk), headers={"User-Agent": "PandaInternetDiagnostic/1.0"})
                with urllib.request.urlopen(req, timeout=10) as r:
                    while time.perf_counter() < stop:
                        b = r.read(65536)
                        if not b:
                            break
                        with lock:
                            total[0] += len(b)
            except Exception as e:  # noqa: BLE001
                errors.append(str(e))
                return

    t0 = time.perf_counter()
    threads = [threading.Thread(target=worker, daemon=True) for _ in range(streams)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(seconds + 12)
    elapsed = max(time.perf_counter() - t0, 0.001)
    mbps = round(total[0] * 8 / elapsed / 1e6, 1)
    res = {"mbps": mbps, "bytes": total[0], "seconds": round(elapsed, 1), "errors": errors[:2]}
    if ping_targets:
        res["loaded"] = {}
        for k, vals in loaded.items():
            ok = [v for v in vals if v is not None]
            res["loaded"][k] = icmp.series_stats(ok, len(vals) - len(ok), len(vals))
    return res


# ---------------------------------------------------------------- Windows event log

_EVENTS_PS = r"""
$since = (Get-Date).AddHours(-%(hours)d)
$out = @()
$out += Get-WinEvent -FilterHashtable @{LogName='System'; StartTime=$since; Level=1,2,3} -MaxEvents 400 |
  Where-Object { $_.ProviderName -match 'Dhcp|DNS|Tcpip|NDIS|e1|rt6|Realtek|Intel|Killer|igc|e2f|netw|bcm|mrvl|Qualcomm|Atheros|Wlan|NetAdapter|NCSI|%(driver)s' -or $_.Id -in 27,32,4201,4202,1014,1001,1003 } |
  Select-Object -First 60
$out += Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-WLAN-AutoConfig/Operational'; StartTime=$since; Id=8003,11004,11005,11006,12013,8002} -MaxEvents 60
$out += Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-NCSI/Operational'; StartTime=$since; Id=4042} -MaxEvents 30
$out | Sort-Object TimeCreated -Descending | Select-Object -First 80 | ForEach-Object {
  [pscustomobject]@{ time=$_.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss'); id=$_.Id; source=$_.ProviderName; level="$($_.LevelDisplayName)";
    message=(($_.Message -split "`n") | Select-Object -First 3) -join ' ' }
} | ConvertTo-Json -Compress
"""


def recent_events(hours=24, driver=None):
    drv = re.sub(r"[^A-Za-z0-9_]", "", driver or "") or "zzzz"
    return _as_list(_json(powershell(_EVENTS_PS % {"hours": hours, "driver": drv}, timeout=40)))


def human_bps(bps):
    if not bps:
        return "—"
    if bps >= 1e9:
        return f"{bps / 1e9:g} Гбит/с"
    return f"{bps / 1e6:g} Мбит/с"


def now_str():
    return time.strftime("%Y-%m-%d %H:%M:%S")


def hostname():
    return socket.gethostname()


def is_private(ip):
    try:
        a = ipaddress.ip_address(ip)
        return a.is_private or a in ipaddress.ip_network("100.64.0.0/10")
    except ValueError:
        return False


def is_cgnat(ip):
    try:
        return ipaddress.ip_address(ip) in ipaddress.ip_network("100.64.0.0/10")
    except ValueError:
        return False

