"""History analysis: the culprit of an unstable connection must be named correctly."""
import os
import socket
import sys
import threading
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from panda_diag import stability  # noqa: E402
from panda_diag.routers import mikrotik  # noqa: E402

DAY = 86400


def ev(start, area, kind="outage", dur=60, **detail):
    ctx = detail.pop("ctx", {})
    return {"start": start, "end": start + dur, "kind": kind, "title": "t", "cause": "c",
            "detail": dict(area=area, ctx=ctx, **detail)}


def at(hour, day=0):
    base = time.mktime(time.strptime("2026-10-10 00:00", "%Y-%m-%d %H:%M"))
    return base + day * DAY + hour * 3600


def hourly(home=0.0, line=0.0, inet=0.0, hours=24, evening_rtt=None, night_rtt=None):
    rows = {"gateway": [], "isp_hop": [], "anchor:1.1.1.1": []}
    for h in range(hours):
        ts = at(h)
        hr = time.localtime(ts).tm_hour
        rtt = evening_rtt if evening_rtt and 18 <= hr <= 23 else (night_rtt or 10)
        for k, loss in (("gateway", home), ("isp_hop", line), ("anchor:1.1.1.1", inet)):
            rows[k].append((ts, 3600, int(3600 * loss / 100), 1.0 if k == "gateway" else rtt))
    return rows


class Stability(unittest.TestCase):
    def test_router_is_named(self):
        evs = [ev(at(10), "router", router_reboot=True), ev(at(14), "router"), ev(at(20), "router", router_hang=True),
               ev(at(22), "isp")]
        v = stability.analyze(evs, hourly(), 20 * 3600)["verdict"]
        self.assertEqual(v["culprit"], "router")
        self.assertGreaterEqual(v["confidence"], 50)
        self.assertIn("роутер", v["headline"])

    def test_single_drop_is_only_a_guess(self):
        r = stability.analyze([ev(at(12), "router", recovered_before_check=True)], hourly(), 20 * 3600)
        self.assertLess(r["verdict"]["confidence"], 50)
        self.assertTrue(r["verdict"]["headline"].startswith("Возможная причина"))
        self.assertTrue(any("один обрыв" in p for p in r["patterns"]))
        self.assertIn("Единственный раз", r["verdict"]["explanation"])

    def test_provider_with_evening_pattern(self):
        evs = [ev(at(h, d), "isp") for d, h in ((0, 19), (1, 20), (2, 21), (3, 22))]
        r = stability.analyze(evs, hourly(), 4 * DAY, period_hours=96)
        self.assertEqual(r["verdict"]["culprit"], "provider")
        self.assertTrue(any("вечером" in p for p in r["patterns"]))
        self.assertIn("Прошу проверить", r["verdict"]["provider_text"])

    def test_daily_forced_reconnect(self):
        evs = [ev(at(3, d), "wan", dur=20) for d in range(4)]
        r = stability.analyze(evs, hourly(), 4 * DAY, period_hours=96)
        self.assertEqual(r["verdict"]["culprit"], "line")
        self.assertTrue(any("раз в сутки" in p for p in r["patterns"]))

    def test_weak_wifi(self):
        evs = [ev(at(h), "wifi", ctx={"wifi_rssi": -79}) for h in (9, 12, 15)]
        r = stability.analyze(evs, hourly(), 20 * 3600, is_wifi=True)
        self.assertEqual(r["verdict"]["culprit"], "wifi")
        self.assertTrue(any("-79" in p for p in r["patterns"]))

    def test_chronic_loss_at_home_without_drops(self):
        r = stability.analyze([], hourly(home=3.0, line=3.0, inet=3.0), 20 * 3600, is_wifi=True)
        self.assertEqual(r["verdict"]["culprit"], "wifi")

    def test_chronic_loss_on_provider_line(self):
        r = stability.analyze([], hourly(home=0, line=4.0, inet=4.0), 20 * 3600)
        self.assertEqual(r["verdict"]["culprit"], "line")

    def test_evening_congestion(self):
        r = stability.analyze([], hourly(evening_rtt=90, night_rtt=12), 24 * 3600)
        self.assertEqual(r["verdict"]["culprit"], "provider")

    def test_stable_and_not_enough_data(self):
        self.assertEqual(stability.analyze([], hourly(), 20 * 3600)["verdict"]["culprit"], "none")
        self.assertEqual(stability.analyze([], {}, 600)["verdict"]["culprit"], "unknown")

    def test_sleep_is_not_blamed(self):
        evs = [{"start": at(1), "end": at(8), "kind": "sleep", "title": "", "cause": "", "detail": {"area": "sleep"}}]
        self.assertEqual(stability.analyze(evs, hourly(), 20 * 3600)["verdict"]["culprit"], "none")


class RouterScanData(unittest.TestCase):
    def test_neighbours_without_width(self):
        """Xiaomi/Keenetic scans often have no channel width (None) — must not crash the analysis."""
        from panda_diag import wifi
        scan = [{"ssid": "a", "bssid": "00:00:00:00:00:01", "channel": 6, "signal_dbm": -60, "width": None},
                {"ssid": "b", "bssid": "00:00:00:00:00:02", "channel": 44, "signal_dbm": -70, "width": None},
                {"ssid": "c", "bssid": "00:00:00:00:00:03", "channel": 1, "signal_dbm": None}]
        res = wifi.analyze(scan, radios=[{"band": "2.4", "channel": 6, "width": None}, {"band": "5", "channel": 44, "width": None}])
        self.assertIn("2.4", res["bands"])
        self.assertIn("5", res["bands"])

    def test_xiaomi_scan_normalize(self):
        from panda_diag.routers.base import _empty
        from panda_diag.routers.xiaomi import XiaomiRouter
        out = _empty("xiaomi")
        out["raw"] = {"xqnetwork/wifi_list": {"list": [{"ssid": "x", "bssid": "aa", "channel": "11", "signal": "70"}]}}
        XiaomiRouter("x", "")._normalize(out)
        self.assertIsNone(out["wifi_scan"][0]["width"])
        from panda_diag import wifi
        wifi.analyze(out["wifi_scan"], radios=[{"band": "2.4", "channel": 1}])


class FakeRouterOS(threading.Thread):
    """Minimal RouterOS API server: /login and /system/resource/print."""

    def __init__(self):
        super().__init__(daemon=True)
        self.srv = socket.socket()
        self.srv.bind(("127.0.0.1", 0))
        self.srv.listen(1)
        self.port = self.srv.getsockname()[1]

    def run(self):
        c, _ = self.srv.accept()
        t = mikrotik.ApiTransport.__new__(mikrotik.ApiTransport)
        t.sock, t.buf = c, b""
        while True:
            try:
                words = []
                while True:
                    w = t._read_word()
                    if w == "":
                        break
                    words.append(w)
            except Exception:  # noqa: BLE001
                return
            if words[0] == "/login":
                if "=password=secret" in words:
                    t._send(["!done"])
                else:
                    t._send(["!trap", "=message=invalid user name or password (6)"])
                    t._send(["!done"])
            elif words[0] == "/system/resource/print":
                t._send(["!re", "=board-name=CCR1009-8G-1S-1S+", "=cpu-load=7", "=uptime=1w2d03:04:05", "=version=7.16"])
                t._send(["!done"])


class RouterOsApi(unittest.TestCase):
    def test_login_and_print(self):
        srv = FakeRouterOS()
        srv.start()
        orig = socket.create_connection
        socket.create_connection = lambda addr, timeout=None: orig(("127.0.0.1", srv.port), timeout)
        try:
            t = mikrotik.ApiTransport("router", "admin", "secret")
            rows = t.req("/system/resource")
            t.close()
        finally:
            socket.create_connection = orig
        self.assertEqual(rows[0]["board-name"], "CCR1009-8G-1S-1S+")
        self.assertEqual(mikrotik._ros_duration(rows[0]["uptime"]), 7 * 86400 + 2 * 86400 + 3 * 3600 + 4 * 60 + 5)

    def test_wrong_password(self):
        srv = FakeRouterOS()
        srv.start()
        orig = socket.create_connection
        socket.create_connection = lambda addr, timeout=None: orig(("127.0.0.1", srv.port), timeout)
        try:
            with self.assertRaises(mikrotik.AuthError):
                mikrotik.ApiTransport("router", "admin", "bad")
        finally:
            socket.create_connection = orig

    def test_length_encoding_roundtrip(self):
        for n in (0, 5, 0x7F, 0x80, 0x3FFF, 0x4000, 0x1FFFFF, 0x200000):
            b = mikrotik._enc_len(n)
            self.assertEqual(len(b), 1 if n < 0x80 else 2 if n < 0x4000 else 3 if n < 0x200000 else 4)


if __name__ == "__main__":
    unittest.main()
