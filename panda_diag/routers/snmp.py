"""Generic SNMP v2c driver (works with MikroTik, Keenetic, Ubiquiti, Cisco, managed switches, many ONTs/ISP CPEs).

Minimal BER encoder/decoder — no third-party packages needed.
"""
import random
import socket
import struct

from .base import _empty

# ------------------------------------------------------------------ BER


def _len(n):
    if n < 0x80:
        return bytes([n])
    b = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(b)]) + b


def _tlv(t, v):
    return bytes([t]) + _len(len(v)) + v


def _int(n):
    return _tlv(0x02, n.to_bytes((n.bit_length() + 8) // 8 or 1, "big", signed=True))


def _oid(oid):
    parts = [int(x) for x in oid.strip(".").split(".")]
    out = bytes([parts[0] * 40 + parts[1]])
    for p in parts[2:]:
        enc = [p & 0x7F]
        p >>= 7
        while p:
            enc.insert(0, 0x80 | (p & 0x7F))
            p >>= 7
        out += bytes(enc)
    return _tlv(0x06, out)


def _parse(data, pos=0):
    t = data[pos]
    pos += 1
    ln = data[pos]
    pos += 1
    if ln & 0x80:
        k = ln & 0x7F
        ln = int.from_bytes(data[pos:pos + k], "big")
        pos += k
    return t, data[pos:pos + ln], pos + ln


def _decode(t, v):
    if t in (0x30, 0xA2):
        items, p = [], 0
        while p < len(v):
            tt, vv, p = _parse(v, p)
            items.append(_decode(tt, vv))
        return items
    if t == 0x02:
        return int.from_bytes(v, "big", signed=True)
    if t in (0x41, 0x42, 0x43, 0x46):
        return int.from_bytes(v, "big")
    if t == 0x04:
        try:
            return v.decode("utf-8")
        except UnicodeDecodeError:
            return v.hex(":")
    if t == 0x40:
        return socket.inet_ntoa(v)
    if t == 0x06:
        parts = [v[0] // 40, v[0] % 40]
        n = 0
        for b in v[1:]:
            n = (n << 7) | (b & 0x7F)
            if not b & 0x80:
                parts.append(n)
                n = 0
        return ".".join(map(str, parts))
    if t in (0x05, 0x80, 0x81, 0x82):
        return None if t == 0x05 else ("END" if t == 0x82 else "NOSUCH")
    return v


class Snmp:
    def __init__(self, host, community="public", timeout=1.5, retries=1):
        self.host, self.community, self.timeout, self.retries = host, community, timeout, retries

    def _request(self, pdu_type, oids, non_rep=0, max_rep=0):
        rid = random.randint(1, 0x7FFFFFFF)
        vbs = b"".join(_tlv(0x30, _oid(o) + b"\x05\x00") for o in oids)
        pdu = _tlv(pdu_type, _int(rid) + _int(non_rep) + _int(max_rep) + _tlv(0x30, vbs))
        msg = _tlv(0x30, _int(1) + _tlv(0x04, self.community.encode()) + pdu)
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(self.timeout)
        try:
            for _ in range(self.retries + 1):
                try:
                    s.sendto(msg, (self.host, 161))
                    data, _ = s.recvfrom(65535)
                    t, v, _ = _parse(data)
                    _ver, _comm, resp = _decode(t, v)
                    _rid, err, _idx, binds = resp
                    if err:
                        return []
                    return [(b[0], b[1]) for b in binds]
                except socket.timeout:
                    continue
            raise TimeoutError("SNMP timeout")
        finally:
            s.close()

    def get(self, *oids):
        return dict(self._request(0xA0, list(oids)))

    def walk(self, base, limit=512):
        out, cur = {}, base
        while len(out) < limit:
            binds = self._request(0xA5, [cur], 0, 30)
            if not binds:
                break
            for oid, val in binds:
                if not oid.startswith(base + ".") or val == "END":
                    return out
                out[oid] = val
                cur = oid
        return out


IF = "1.3.6.1.2.1.2.2.1"
IFX = "1.3.6.1.2.1.31.1.1.1"


class SnmpRouter:
    kind = "snmp"

    def __init__(self, host, community="public", wan_interface=None):
        self.snmp = Snmp(host, community or "public")
        self.wan_name = (wan_interface or "").lower()

    def collect(self, full=True):
        out = _empty(self.kind)
        try:
            sysv = self.snmp.get("1.3.6.1.2.1.1.1.0", "1.3.6.1.2.1.1.3.0", "1.3.6.1.2.1.1.5.0")
        except (TimeoutError, OSError):
            out["notes"].append("SNMP не отвечает (выключен или другое community).")
            return out
        out["reachable"] = True
        out["auth"] = "ok"
        out["model"] = str(sysv.get("1.3.6.1.2.1.1.1.0") or "")[:120]
        ticks = sysv.get("1.3.6.1.2.1.1.3.0")
        out["uptime_sec"] = ticks // 100 if isinstance(ticks, int) else None

        def col(base, c):
            return {oid.rsplit(".", 1)[1]: v for oid, v in self.snmp.walk(f"{base}.{c}").items()}

        descr, oper, itype = col(IF, 2), col(IF, 8), col(IF, 3)
        in_err, out_err = col(IF, 14), col(IF, 20)
        names, alias, hspeed = col(IFX, 1), col(IFX, 18), col(IFX, 15)
        hc_in, hc_out = col(IFX, 6), col(IFX, 10)
        fcs = {oid.rsplit(".", 1)[1]: v for oid, v in self.snmp.walk("1.3.6.1.2.1.10.7.2.1.3").items()}
        try:
            loads = list(self.snmp.walk("1.3.6.1.2.1.25.3.3.1.2").values())
            if loads:
                out["cpu_load"] = round(sum(loads) / len(loads), 1)
        except (TimeoutError, OSError):
            pass

        for idx, d in descr.items():
            name = str(names.get(idx) or d)
            text = f"{name} {alias.get(idx, '')} {d}".lower()
            is_wan = (self.wan_name and self.wan_name == name.lower()) or any(w in text for w in ("wan", "internet", "pppoe-out", "ppp0"))
            p = {"name": name, "alias": alias.get(idx), "link": oper.get(idx) == 1, "speed_mbps": hspeed.get(idx),
                 "rx_errors": in_err.get(idx), "tx_errors": out_err.get(idx), "fcs_errors": fcs.get(idx),
                 "rx_bytes_total": hc_in.get(idx), "tx_bytes_total": hc_out.get(idx), "wan": bool(is_wan)}
            if any(x in text for x in ("loopback", "lo0", "null", "imq", "ifb", "dummy")):
                continue
            # keep physical ports (ethernet, wifi, sfp) and the WAN; skip tunnels/vlans/bridges
            if not is_wan and itype.get(idx) not in (6, 62, 69, 71, 117):
                continue
            out["ports"].append(p)
        wan_ports = [p for p in out["ports"] if p["wan"]]
        if wan_ports:
            w = wan_ports[0]
            out["wan"].update({"iface": w["name"], "link": w["link"], "link_speed_mbps": w["speed_mbps"],
                               "rx_errors": w["rx_errors"], "tx_errors": w["tx_errors"], "fcs_errors": w["fcs_errors"],
                               "rx_bytes_total": w["rx_bytes_total"], "tx_bytes_total": w["tx_bytes_total"]})
        else:
            out["notes"].append("SNMP: WAN-интерфейс не определён автоматически — укажите имя WAN-порта в «Настройки → Роутер и модем».")
        if "routeros" in out["model"].lower() or "mikrotik" in out["model"].lower():
            self._mikrotik_extras(out)
        if full:
            self._arp_devices(out)
        return out

    def _mikrotik_extras(self, out):
        """MIKROTIK-MIB: SFP optics (mtxrOpticalTable) and health."""
        base = "1.3.6.1.4.1.14988.1.1.19.1.1"
        try:
            names = {o.rsplit(".", 1)[1]: v for o, v in self.snmp.walk(base + ".2").items()}
            for idx, name in names.items():
                vals = self.snmp.get(*[f"{base}.{c}.{idx}" for c in (3, 4, 6, 9, 10)])
                rx_loss, tx_fault, temp, txp, rxp = (vals.get(f"{base}.{c}.{idx}") for c in (3, 4, 6, 9, 10))
                if not isinstance(rxp, int) or (rxp == 0 and not txp and not temp):
                    continue  # DAC/copper module or no DDM support
                optic = {"module": name, "rx_dbm": round(rxp / 1000, 2), "tx_dbm": round(txp / 1000, 2) if isinstance(txp, int) else None,
                         "temp_c": temp, "rx_loss": rx_loss == 1, "tx_fault": tx_fault == 1}
                out.setdefault("sfp", []).append(optic)
                wan_name = out["wan"].get("iface")
                if name == wan_name or not out["optics"]:
                    out["optics"] = optic if name == wan_name else out["optics"]
        except (TimeoutError, OSError):
            pass
        try:
            t = self.snmp.get("1.3.6.1.4.1.14988.1.1.3.10.0", "1.3.6.1.4.1.14988.1.1.3.11.0")
            temp = t.get("1.3.6.1.4.1.14988.1.1.3.10.0") or t.get("1.3.6.1.4.1.14988.1.1.3.11.0")
            if isinstance(temp, int):
                out["temperature"] = temp / 10 if temp > 150 else temp
        except (TimeoutError, OSError):
            pass

    def _arp_devices(self, out):
        """ipNetToMediaPhysAddress: devices the router currently sees."""
        try:
            arp = self.snmp.walk("1.3.6.1.2.1.4.22.1.2", limit=400)
        except (TimeoutError, OSError):
            return
        for oid, mac in arp.items():
            ip = ".".join(oid.split(".")[-4:])
            if isinstance(mac, str) and len(mac) == 17:
                out["devices"].append({"mac": mac.lower(), "ip": ip, "name": None, "conn": None})
