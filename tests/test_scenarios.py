"""Simulated failure scenarios: the analyzer must name the exact cause. Run: python -m unittest discover tests"""
import copy
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from panda_diag import analyzer, wifi  # noqa: E402
from panda_diag.routers.xiaomi import XiaomiRouter  # noqa: E402
from panda_diag.routers.base import _empty  # noqa: E402


def ok(avg=1.0, loss=0.0):
    return {"sent": 20, "lost": int(loss / 5), "loss": loss, "min": avg, "avg": avg, "max": avg, "jitter": 0.2}


def dead():
    return {"sent": 20, "lost": 20, "loss": 100.0, "min": None, "avg": None, "max": None, "jitter": None}


BASE = {
    "time": "now", "host": "pc",
    "net": {"primary": {"name": "Ethernet", "status": "Up", "is_wifi": False, "link_bps": 1_000_000_000, "full_duplex": True,
                        "description": "Realtek PCIe GbE Family Controller", "ipv4": "192.168.1.10/24", "dns": ["192.168.1.1"],
                        "rx_errors": 0, "tx_errors": 0}},
    "gateway": "192.168.1.1", "gateway_mac": "aa-bb-cc-dd-ee-ff",
    "path": {"isp_hop": "10.0.0.1x", "modem_hop": None},
    "pings": {"gateway": dict(ok(0.5), ip="192.168.1.1"), "isp_hop": dict(ok(2), ip="95.1.1.1"),
              "anchor:1.1.1.1": dict(ok(10), ip="1.1.1.1"), "anchor:8.8.8.8": dict(ok(12), ip="8.8.8.8")},
    "dns": {"system": [{"server": "192.168.1.1", "ok": True, "ms": 5, "rcode": "NOERROR"}],
            "public": [{"server": "1.1.1.1", "ok": True, "ms": 5, "rcode": "NOERROR"}]},
    "http": {"ok": True}, "gateway_tcp": {80: {"ok": True}},
    "router": {"type": "xiaomi", "model": "Xiaomi AX3000", "wan": {"link": True, "connected": True, "link_speed_mbps": 1000},
               "ports": [], "notes": [], "log": []},
    "events": [],
}


def snap(**changes):
    s = copy.deepcopy(BASE)
    for path, val in changes.items():
        cur = s
        keys = path.split("__")
        for k in keys[:-1]:
            cur = cur[k]
        cur[keys[-1]] = val
    return s


def internet_down(s, upto):
    """Kill everything beyond `upto` in the chain."""
    order = ["gateway", "modem", "isp_hop"]
    alive = True
    for k in order:
        if k in s["pings"]:
            if not alive:
                s["pings"][k] = dict(dead(), ip=s["pings"][k]["ip"])
            if k == upto:
                alive = False
    for k in list(s["pings"]):
        if k.startswith("anchor:"):
            s["pings"][k] = dict(dead(), ip=s["pings"][k]["ip"])
    return s


class Scenarios(unittest.TestCase):
    def verdict(self, s):
        return analyzer.analyze(s)["verdict"]

    def test_all_good(self):
        v = self.verdict(snap())
        self.assertEqual(v["level"], "ok")

    def test_cable_unplugged_pc(self):
        s = snap(net__primary__status="Disconnected")
        s["pings"] = {k: dict(dead(), ip=v["ip"]) for k, v in s["pings"].items()}
        v = self.verdict(s)
        self.assertEqual(v["area"], "pc")
        self.assertIn("кабель", v["title"].lower())

    def test_gigabit_negotiated_100(self):
        v = self.verdict(snap(net__primary__link_bps=100_000_000))
        self.assertIn("100 Мбит/с", v["title"])
        self.assertIn("8 жил", v["advice"])

    def test_xiaomi_wan_port_100(self):
        s = snap()
        s["router"]["wan"]["link_speed_mbps"] = 100
        v = self.verdict(s)
        self.assertIn("WAN-порт роутера работает на 100", v["title"])

    def test_wan_link_down_optics_cable(self):
        s = internet_down(snap(), "gateway")
        s["router"]["wan"] = {"link": False, "connected": False}
        v = self.verdict(s)
        self.assertEqual(v["title"], "Нет линка на WAN-порту роутера")

    def test_pppoe_auth_691(self):
        s = internet_down(snap(), "gateway")
        s["router"]["wan"] = {"link": True, "connected": False, "proto": "pppoe", "error_code": "691",
                              "error_text": "Неверный логин/пароль PPPoE или учётная запись заблокирована (долг, смена тарифа)"}
        v = self.verdict(s)
        self.assertIn("логин/пароль PPPoE", v["title"])

    def test_no_internet_into_router_unknown_router(self):
        s = internet_down(snap(), "gateway")
        s["router"] = {"type": "upnp", "wan": {}, "notes": []}
        v = self.verdict(s)
        self.assertEqual(v["title"], "Интернет не поступает в роутер")

    def test_provider_core_down(self):
        s = internet_down(snap(), "isp_hop")
        v = self.verdict(s)
        self.assertEqual(v["title"], "Сеть провайдера не пропускает в интернет")

    def test_modem_dead_double_nat(self):
        s = snap()
        s["path"]["modem_hop"] = "192.168.100.1"
        s["pings"]["modem"] = dict(ok(1), ip="192.168.100.1")
        s = internet_down(s, "gateway")
        v = self.verdict(s)
        self.assertIn("Модем/ONT провайдера", v["title"])

    def test_router_dead(self):
        s = snap(gateway_tcp={}, gateway_mac=None)
        s["pings"] = {k: dict(dead(), ip=v["ip"]) for k, v in s["pings"].items()}
        v = self.verdict(s)
        self.assertEqual(v["area"], "router")
        self.assertEqual(v["code"], "router_hung")

    def test_weak_optics(self):
        s = snap()
        s["router"]["optics"] = {"rx_dbm": -28.4, "tx_dbm": 2.1}
        v = self.verdict(s)
        self.assertIn("слишком слабый оптический сигнал", v["title"])

    def test_los(self):
        s = internet_down(snap(), "gateway")
        s["ont"] = {"optics": {"rx_dbm": -40.0, "rx_loss": True}, "notes": []}
        f = [x["title"] for x in analyzer.analyze(s)["findings"]]
        self.assertTrue(any("LOS" in t for t in f))

    def test_dns_dead_internet_ok(self):
        s = snap()
        s["dns"]["system"] = [{"server": "10.10.10.10", "ok": False, "ms": None, "rcode": "TIMEOUT"}]
        v = self.verdict(s)
        self.assertIn("DNS-сервер не отвечает", v["title"])

    def test_loss_on_isp_line(self):
        s = snap()
        s["pings"]["isp_hop"] = dict(ok(3, 10), ip="95.1.1.1")
        s["pings"]["anchor:1.1.1.1"] = dict(ok(12, 10), ip="1.1.1.1")
        s["pings"]["anchor:8.8.8.8"] = dict(ok(12, 10), ip="8.8.8.8")
        v = self.verdict(s)
        self.assertIn("линии провайдера", v["title"])

    def test_wifi_loss_local(self):
        s = snap(net__primary__is_wifi=True)
        s["wifi"] = {"connected": True, "rssi_dbm": -80, "signal_pct": 40, "ssid": "home", "channel": 6, "rx_mbps": 20}
        s["pings"]["gateway"] = dict(ok(30, 8), ip="192.168.1.1")
        f = analyzer.analyze(s)["findings"]
        areas = [x["area"] for x in f if x["level"] == "warning"]
        self.assertIn("wifi", areas)

    def test_dsl_no_signal(self):
        s = internet_down(snap(), "gateway")
        s["router"] = {"type": "tr064", "wan": {"link": False}, "dsl": {"status": "NoSignal", "status_text": "НЕТ СИГНАЛА"}, "notes": []}
        f = [x["title"] for x in analyzer.analyze(s)["findings"] if x["level"] == "critical"]
        self.assertTrue(any("DSL" in t for t in f))


class PlainLanguage(unittest.TestCase):
    def test_every_failure_has_plain_answer(self):
        from panda_diag import simple
        cases = {
            "cable": snap(net__primary__status="Disconnected"),
            "isp": internet_down(snap(), "isp_hop"),
            "into_router": internet_down(snap(), "gateway"),
            "nic100": snap(net__primary__link_bps=100_000_000),
        }
        cases["into_router"]["router"] = {"type": "upnp", "wan": {}, "notes": []}
        for name, s in cases.items():
            r = simple.summarize(s, analyzer.analyze(s))
            self.assertIn(r["code"], simple.PLAIN, name)
            self.assertTrue(r["steps"], name)
            self.assertNotIn("WAN", r["headline"], name)  # no jargon in the headline
        r = simple.summarize(cases["isp"], analyzer.analyze(cases["isp"]))
        self.assertTrue(r["call_provider"])
        self.assertIn("Прошу проверить", r["provider_text"])
        states = {c["key"]: c["state"] for c in r["checks"]}
        self.assertEqual(states["router"], "ok")
        self.assertEqual(states["provider"], "bad")

    def test_all_good_plain(self):
        from panda_diag import simple
        r = simple.summarize(snap(), analyzer.analyze(snap()))
        self.assertEqual(r["status"], "good")


class RouterFaults(unittest.TestCase):
    def test_router_hung_wired_link_up(self):
        s = snap(gateway_tcp={})
        s["pings"] = {k: dict(dead(), ip=v["ip"]) for k, v in s["pings"].items()}
        v = analyzer.analyze(s)["verdict"]
        self.assertEqual(v["code"], "router_hung")

    def test_router_dead_on_wifi(self):
        s = snap(gateway_tcp={}, net__primary__is_wifi=True)
        s["wifi"] = {"connected": True, "rssi_dbm": -50, "signal_pct": 100, "ssid": "home", "channel": 36, "rx_mbps": 800}
        s["pings"] = {k: dict(dead(), ip=v["ip"]) for k, v in s["pings"].items()}
        self.assertEqual(analyzer.analyze(s)["verdict"]["code"], "router_dead")

    def test_router_dns_broken(self):
        s = snap()
        s["dns"]["system"] = [{"server": "192.168.1.1", "ok": False, "ms": None, "rcode": "TIMEOUT"}]
        self.assertEqual(analyzer.analyze(s)["verdict"]["code"], "router_dns_broken")

    def test_router_weak_under_load(self):
        s = snap(speedtest={"mbps": 300, "bytes": 3e8, "seconds": 8, "loaded": {"gateway": ok(45, 0), "isp_hop": ok(60, 0)}})
        codes = [f.get("code") for f in analyzer.analyze(s)["findings"]]
        self.assertIn("router_weak_load", codes)

    def test_bufferbloat(self):
        s = snap(speedtest={"mbps": 300, "bytes": 3e8, "seconds": 8, "loaded": {"gateway": ok(1, 0), "isp_hop": ok(150, 0)}})
        codes = [f.get("code") for f in analyzer.analyze(s)["findings"]]
        self.assertIn("bufferbloat", codes)


class History(unittest.TestCase):
    def ev(self, start, area, kind="outage", **detail):
        return {"start": start, "end": start + 60, "kind": kind, "cause": "x", "title": "t", "detail": dict(area=area, **detail)}

    def test_router_unstable_and_merge(self):
        from panda_diag import simple
        evs = [self.ev(1000, "router", router_reboot=True), self.ev(5000, "router"), self.ev(9000, "router")]
        v = simple.history_verdict(evs)
        self.assertEqual(v[0]["code"], "router_unstable")
        self.assertIn("блок питания", " ".join(v[0]["steps"]))
        r = simple.merge_history(simple.summarize(snap(), analyzer.analyze(snap())), v)
        self.assertEqual(r["status"], "bad")
        self.assertIn("Роутер регулярно зависает", r["headline"])

    def test_provider_unstable_gives_script(self):
        from panda_diag import simple
        evs = [self.ev(1000, "wan"), self.ev(5000, "isp")]
        r = simple.merge_history(simple.summarize(snap(), analyzer.analyze(snap())), simple.history_verdict(evs))
        self.assertTrue(r["call_provider"])
        self.assertIn("регулярно пропадает", r["provider_text"])


class WifiAdvice(unittest.TestCase):
    def test_moves_off_crowded_channel(self):
        scan = [{"ssid": f"n{i}", "bssid": f"00:00:00:00:00:{i:02x}", "channel": 6, "signal_dbm": -50} for i in range(6)]
        scan += [{"ssid": "x", "bssid": "11:00:00:00:00:01", "channel": 1, "signal_dbm": -85}]
        res = wifi.analyze(scan, radios=[{"band": "2.4", "channel": 6, "width": 40}])
        self.assertEqual(res["bands"]["2.4"]["best"], 11)
        self.assertTrue(any("6 → 11" in a for a in res["advice"]))
        self.assertTrue(any("20 МГц" in a for a in res["advice"]))

    def test_dfs_warning(self):
        res = wifi.analyze([], radios=[{"band": "5", "channel": 100, "width": 80}])
        self.assertTrue(any("DFS" in a for a in res["advice"]))


class XiaomiParsing(unittest.TestCase):
    def test_normalize(self):
        out = _empty("xiaomi")
        out["raw"] = {
            "misystem/status": {"cpu": {"load": 0.31}, "mem": {"usage": 0.62}, "temperature": 0, "upTime": "8000",
                                "wan": {"downspeed": "1250000", "upspeed": "125000", "devname": "eth1"},
                                "dev": [{"mac": "AA:BB:CC:00:00:01", "devname": "PC", "downspeed": "1000000", "upspeed": "1000", "download": "5", "upload": "6"}]},
            "xqnetwork/pppoe_status": {"proto": "pppoe", "status": 4, "ip": {"address": "0.0.0.0"}, "errcode": "678"},
            "xqnetwork/wan_info": {"info": {"link": 1, "mac": "x", "details": {"wanType": "pppoe"}}},
            "xqnetwork/wifi_detail_all": {"info": [{"ssid": "home", "status": "1", "channelInfo": {"channel": 149, "bandwidth": "80"}}]},
            "misystem/newstatus": {"wan": {"port": "WAN", "link": 1, "speed": 100}},
        }
        XiaomiRouter("x", "")._normalize(out)
        w = out["wan"]
        self.assertFalse(w["connected"])
        self.assertIn("не отвечает", w["error_text"])
        self.assertEqual(w["link_speed_mbps"], 100)
        self.assertEqual(out["devices"][0]["down_bps"], 8_000_000)
        self.assertEqual(out["wifi_radios"][0]["band"], "5")
        self.assertEqual(w["down_bps"], 10_000_000)


class OutageDetector(unittest.TestCase):
    def test_outage_and_blip(self):
        from panda_diag import monitor
        cfg = {"outage_threshold_sec": 3, "anchors": ["1.1.1.1"], "ping_timeout_ms": 1000}
        m = monitor.Monitor.__new__(monitor.Monitor)
        m.cfg = cfg
        m.store = monitor.Store(os.path.join(tempfile.mkdtemp(), "t.sqlite"))
        m.net, m.wifi, m.targets = {"primary": {"status": "Up"}}, None, {}
        m.down_since = m.outage_id = m.outage_chain = None
        m.counts = {"outages": 0, "blips": 0, "downtime": 0.0}
        m.settings = {"notify": False}
        m.pool = type("P", (), {"submit": lambda self, *a, **k: None})()
        up = {"gateway": {"ok": True}, "isp_hop": {"ok": True}, "anchor:1.1.1.1": {"ok": True}}
        down = {"gateway": {"ok": True}, "isp_hop": {"ok": False}, "anchor:1.1.1.1": {"ok": False}}
        t = 1000.0
        for res in [up, down, up]:          # 1-second drop -> micro-drop
            m._tick(t, res)
            t += 1
        for res in [down] * 6 + [up]:        # 6-second drop -> outage
            m._tick(t, res)
            t += 1
        ev = m.store.events(0)
        kinds = sorted(e["kind"] for e in ev)
        self.assertEqual(kinds, ["blip", "outage"])
        outage = next(e for e in ev if e["kind"] == "outage")
        self.assertIn("перестал поступать в роутер", outage["cause"])
        self.assertAlmostEqual(outage["end"] - outage["start"], 6, delta=0.01)


if __name__ == "__main__":
    unittest.main()
