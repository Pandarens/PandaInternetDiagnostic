"""ICMP ping and traceroute through the Windows IP Helper API (no admin rights, no locale-dependent parsing)."""
import ctypes
import socket
import struct
import threading
from ctypes import wintypes

IP_SUCCESS = 0
IP_DEST_NET_UNREACHABLE = 11002
IP_DEST_HOST_UNREACHABLE = 11003
IP_REQ_TIMED_OUT = 11010
IP_TTL_EXPIRED_TRANSIT = 11013

STATUS_TEXT = {
    IP_SUCCESS: "ok",
    IP_DEST_NET_UNREACHABLE: "net_unreachable",
    IP_DEST_HOST_UNREACHABLE: "host_unreachable",
    IP_REQ_TIMED_OUT: "timeout",
    IP_TTL_EXPIRED_TRANSIT: "ttl_expired",
}


class IP_OPTION_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("Ttl", ctypes.c_ubyte),
        ("Tos", ctypes.c_ubyte),
        ("Flags", ctypes.c_ubyte),
        ("OptionsSize", ctypes.c_ubyte),
        ("OptionsData", ctypes.c_void_p),
    ]


class ICMP_ECHO_REPLY(ctypes.Structure):
    _fields_ = [
        ("Address", wintypes.ULONG),
        ("Status", wintypes.ULONG),
        ("RoundTripTime", wintypes.ULONG),
        ("DataSize", wintypes.USHORT),
        ("Reserved", wintypes.USHORT),
        ("Data", ctypes.c_void_p),
        ("Options", IP_OPTION_INFORMATION),
    ]


_iphlp = ctypes.WinDLL("iphlpapi.dll", use_last_error=True)
_iphlp.IcmpCreateFile.restype = ctypes.c_void_p
_iphlp.IcmpCloseHandle.argtypes = [ctypes.c_void_p]
_iphlp.IcmpSendEcho.argtypes = [
    ctypes.c_void_p, wintypes.ULONG, ctypes.c_void_p, wintypes.WORD,
    ctypes.POINTER(IP_OPTION_INFORMATION), ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD,
]
_iphlp.IcmpSendEcho.restype = wintypes.DWORD

_local = threading.local()
_PAYLOAD = b"PandaInternetDiagnostic-ping-32b"


def _handle():
    h = getattr(_local, "h", None)
    if h is None:
        h = _iphlp.IcmpCreateFile()
        _local.h = h
    return h


def _ip_to_ulong(ip):
    return struct.unpack("<I", socket.inet_aton(ip))[0]


def _ulong_to_ip(v):
    return socket.inet_ntoa(struct.pack("<I", v))


def ping(ip, timeout_ms=1000, ttl=128, size=32):
    """Return dict(ok, rtt, status, addr). rtt in ms (int) when ok."""
    try:
        dest = _ip_to_ulong(ip)
    except OSError:
        return {"ok": False, "rtt": None, "status": "bad_address", "addr": None}
    payload = (_PAYLOAD * (size // len(_PAYLOAD) + 1))[:size]
    req = ctypes.create_string_buffer(payload, len(payload))
    reply_size = ctypes.sizeof(ICMP_ECHO_REPLY) + len(payload) + 64
    reply = ctypes.create_string_buffer(reply_size)
    opts = IP_OPTION_INFORMATION(Ttl=ttl)
    n = _iphlp.IcmpSendEcho(_handle(), dest, req, len(payload), ctypes.byref(opts),
                            reply, reply_size, timeout_ms)
    if n == 0:
        err = ctypes.get_last_error()
        return {"ok": False, "rtt": None, "status": STATUS_TEXT.get(err, f"error_{err}"), "addr": None}
    r = ICMP_ECHO_REPLY.from_buffer(reply)
    st = STATUS_TEXT.get(r.Status, f"status_{r.Status}")
    return {
        "ok": r.Status == IP_SUCCESS,
        "rtt": r.RoundTripTime if r.Status in (IP_SUCCESS, IP_TTL_EXPIRED_TRANSIT) else None,
        "status": st,
        "addr": _ulong_to_ip(r.Address),
    }


def ping_series(ip, count=10, timeout_ms=1000, interval=0.0):
    """Ping several times; return stats dict."""
    import time
    rtts, lost = [], 0
    for i in range(count):
        r = ping(ip, timeout_ms)
        if r["ok"]:
            rtts.append(r["rtt"])
        else:
            lost += 1
        if interval and i < count - 1:
            time.sleep(interval)
    return series_stats(rtts, lost, count)


def series_stats(rtts, lost, count):
    if not count:
        return {"sent": 0, "lost": 0, "loss": 0.0, "min": None, "avg": None, "max": None, "jitter": None}
    out = {"sent": count, "lost": lost, "loss": round(100.0 * lost / count, 1),
           "min": None, "avg": None, "max": None, "jitter": None}
    if rtts:
        out["min"] = min(rtts)
        out["max"] = max(rtts)
        out["avg"] = round(sum(rtts) / len(rtts), 1)
        if len(rtts) > 1:
            out["jitter"] = round(sum(abs(a - b) for a, b in zip(rtts, rtts[1:])) / (len(rtts) - 1), 1)
        else:
            out["jitter"] = 0.0
    return out


def traceroute(ip, max_hops=15, timeout_ms=800, probes=2):
    """Return list of hops: {ttl, addr, rtt, reached}."""
    hops = []
    for ttl in range(1, max_hops + 1):
        addr, rtts = None, []
        reached = False
        for _ in range(probes):
            r = ping(ip, timeout_ms, ttl=ttl)
            if r["addr"] and r["status"] in ("ok", "ttl_expired"):
                addr = r["addr"]
                if r["rtt"] is not None:
                    rtts.append(r["rtt"])
                if r["status"] == "ok":
                    reached = True
        hops.append({"ttl": ttl, "addr": addr, "rtt": min(rtts) if rtts else None, "reached": reached})
        if reached:
            break
    return hops
