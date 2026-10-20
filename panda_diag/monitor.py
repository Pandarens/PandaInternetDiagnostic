"""Continuous monitoring: 1-second pings along the chain, outage/micro-drop detection with root-cause capture,
quality degradation alerts, router/device load tracking, history in SQLite."""
import collections
import json
import os
import sqlite3
import threading
import time
from concurrent.futures import ThreadPoolExecutor

from . import analyzer, config, icmp, probe, routers, service, simple, system

TARGET_LABELS = {"gateway": "Роутер", "modem": "Модем/ONT", "ont": "ONT", "isp_hop": "Провайдер (1-й узел)"}


def _dur(sec):
    sec = int(sec)
    if sec < 60:
        return f"{sec} с"
    if sec < 3600:
        return f"{sec // 60} мин {sec % 60} с"
    return f"{sec // 3600} ч {sec % 3600 // 60} мин"


class Store:
    def __init__(self, path):
        self.db = sqlite3.connect(path, check_same_thread=False)
        self.lock = threading.Lock()
        with self.lock:
            self.db.executescript("""
                PRAGMA journal_mode=WAL;
                CREATE TABLE IF NOT EXISTS samples(ts REAL, target TEXT, rtt REAL);
                CREATE INDEX IF NOT EXISTS samples_ts ON samples(ts);
                CREATE TABLE IF NOT EXISTS events(id INTEGER PRIMARY KEY, ts_start REAL, ts_end REAL, kind TEXT,
                    severity TEXT, title TEXT, cause TEXT, detail TEXT);
                CREATE INDEX IF NOT EXISTS events_ts ON events(ts_start);
                CREATE TABLE IF NOT EXISTS snapshots(id INTEGER PRIMARY KEY, ts REAL, event_id INTEGER, data TEXT);
            """)

    def add_samples(self, rows):
        with self.lock:
            self.db.executemany("INSERT INTO samples VALUES (?,?,?)", rows)
            self.db.commit()

    def add_event(self, ts_start, kind, severity, title, cause="", detail=None, ts_end=None):
        with self.lock:
            cur = self.db.execute("INSERT INTO events(ts_start, ts_end, kind, severity, title, cause, detail) VALUES (?,?,?,?,?,?,?)",
                                  (ts_start, ts_end, kind, severity, title, cause, json.dumps(detail or {}, ensure_ascii=False, default=str)))
            self.db.commit()
            return cur.lastrowid

    def update_event(self, eid, **fields):
        if "detail" in fields:
            fields["detail"] = json.dumps(fields["detail"], ensure_ascii=False, default=str)
        sets = ", ".join(f"{k}=?" for k in fields)
        with self.lock:
            self.db.execute(f"UPDATE events SET {sets} WHERE id=?", (*fields.values(), eid))
            self.db.commit()

    def add_snapshot(self, event_id, data):
        with self.lock:
            self.db.execute("INSERT INTO snapshots(ts, event_id, data) VALUES (?,?,?)",
                            (time.time(), event_id, json.dumps(data, ensure_ascii=False, default=str)))
            self.db.commit()

    def events(self, since):
        with self.lock:
            rows = self.db.execute("SELECT id, ts_start, ts_end, kind, severity, title, cause, detail FROM events "
                                   "WHERE ts_start >= ? ORDER BY ts_start DESC LIMIT 500", (since,)).fetchall()
        return [{"id": r[0], "start": r[1], "end": r[2], "kind": r[3], "severity": r[4], "title": r[5], "cause": r[6],
                 "detail": json.loads(r[7] or "{}")} for r in rows]

    def event(self, eid):
        with self.lock:
            r = self.db.execute("SELECT id, ts_start, ts_end, kind, severity, title, cause, detail FROM events WHERE id=?",
                                (eid,)).fetchone()
        if not r:
            return None
        return {"id": r[0], "start": r[1], "end": r[2], "kind": r[3], "severity": r[4], "title": r[5], "cause": r[6],
                "detail": json.loads(r[7] or "{}")}

    def snapshot_for(self, event_id):
        with self.lock:
            r = self.db.execute("SELECT data FROM snapshots WHERE event_id=? ORDER BY id DESC LIMIT 1", (event_id,)).fetchone()
        return json.loads(r[0]) if r else None

    def samples(self, since, step=1):
        with self.lock:
            rows = self.db.execute("SELECT ts, target, rtt FROM samples WHERE ts >= ? ORDER BY ts", (since,)).fetchall()
        out = collections.defaultdict(list)
        if step <= 1:
            for ts, t, rtt in rows:
                out[t].append([round(ts, 1), rtt])
            return out
        buckets = collections.defaultdict(lambda: [0, 0, 0.0, 0])  # (key)->[n, lost, sum_rtt, max]
        for ts, t, rtt in rows:
            b = buckets[(t, int(ts // step) * step)]
            b[0] += 1
            if rtt is None:
                b[1] += 1
            else:
                b[2] += rtt
                b[3] = max(b[3], rtt)
        for (t, ts), (n, lost, s, mx) in sorted(buckets.items(), key=lambda kv: kv[0][1]):
            avg = round(s / (n - lost), 1) if n > lost else None
            out[t].append([ts, avg, round(100 * lost / n, 1), mx])
        return out

    def coverage(self, since, gap=120):
        """Time ranges when monitoring was actually running (from stored samples), merged across gaps < `gap` s."""
        with self.lock:
            rows = self.db.execute("SELECT DISTINCT CAST(ts / 60 AS INTEGER) FROM samples WHERE ts >= ? ORDER BY 1", (since,)).fetchall()
        segs = []
        for (m,) in rows:
            t = m * 60
            if segs and t - segs[-1][1] <= gap:
                segs[-1][1] = t + 60
            else:
                segs.append([t, t + 60])
        return segs

    def prune(self, days=14):
        cut = time.time() - days * 86400
        with self.lock:
            self.db.execute("DELETE FROM samples WHERE ts < ?", (cut,))
            self.db.commit()


class Monitor:
    def __init__(self, cfg=None, controller=None, quit_event=None):
        self.cfg = cfg or config.load()
        self.controller = controller
        self.quit_event = quit_event or threading.Event()
        self.update = {"checking": False, "applying": False, "last_check": None, "info": None, "error": None,
                       "updated_from": getattr(controller, "reloaded_from", None)}
        self.store = Store(os.path.join(config.DATA_DIR, "history.sqlite"))
        self.pool = ThreadPoolExecutor(max_workers=12)
        self.stop_flag = threading.Event()
        self.lock = threading.RLock()
        self.targets = {}
        self.window = collections.defaultdict(lambda: collections.deque(maxlen=300))
        self.pending = []
        self.started = time.time()
        self.router_cache = {}
        self.path_cache = {}
        self.net = {}
        self.wifi = None
        self.router = None
        self.ont = None
        self.load = {"wan": {}, "devices": [], "pc": {}, "ports": []}
        self._prev_counters = {}
        self.dns = None
        self.http = None
        self.last_diag = None
        self.diag_running = False
        self.down_since = None
        self.outage_id = None
        self.outage_chain = None
        self.last_degrade = {}
        self.counts = {"outages": 0, "blips": 0, "downtime": 0.0}
        self._last_sys = {}
        self.check = {"running": False, "steps": {}, "result": None, "started": None, "finished": None, "speed": False}
        self.settings = service.load_settings()
        self.enabled = bool(self.settings.get("monitoring", True))
        self._gw_mac = None

    # ----------------------------------------------------------------- lifecycle
    def start(self):
        # network discovery takes ~10 s (traceroute); run it in the background so the window opens instantly
        threading.Thread(target=self._initial_discovery, daemon=True).start()
        for fn in (self._ping_loop, self._loop(self.refresh_slow, self.cfg["slow_checks_interval_sec"]),
                   self._loop(self.refresh_system, self.cfg["system_checks_interval_sec"]),
                   self._loop(self.refresh_router, self.cfg["router_checks_interval_sec"]),
                   self._loop(self.refresh_path, 600), self._loop(self._flush, 5, gated=False),
                   self._loop(self._quality_check, 60), self._loop(lambda: self.store.prune(), 86400, gated=False)):
            threading.Thread(target=fn, daemon=True).start()
        threading.Thread(target=self._auto_update_loop, daemon=True).start()
        self.pool.submit(self.run_diagnosis)

    def _initial_discovery(self):
        try:
            self.refresh_system()
            self.refresh_path()
        except Exception as e:  # noqa: BLE001
            print(f"[monitor] discovery: {e}")

    def stop(self):
        self.stop_flag.set()
        self._flush()
        # the DB connection is left to the GC: background threads may still be finishing their last write
        self.pool.shutdown(wait=False, cancel_futures=True)

    # ----------------------------------------------------------------- self-update
    def check_update(self, apply_auto=False):
        from . import updater
        if self.update["checking"] or self.update["applying"]:
            return self.update
        self.update["checking"] = True
        self.update["error"] = None
        try:
            info = updater.check(self.controller)
            self.update["info"] = info
            if apply_auto and info.get("available") and info.get("can_apply") and not self.check["running"]:
                self.apply_update()
        except Exception as e:  # noqa: BLE001
            self.update["error"] = f"Не удалось проверить обновления: {e}"
        finally:
            self.update["checking"] = False
            self.update["last_check"] = time.time()
        return self.update

    def apply_update(self):
        from . import updater
        info = self.update.get("info") or {}
        if not info.get("can_apply") or self.update["applying"]:
            return False
        self.update["applying"] = True
        try:
            updater.apply(info, self.controller)  # the launcher then reloads the code (or relaunches the new exe)
            return True
        except Exception as e:  # noqa: BLE001
            self.update["error"] = str(e)
            self.update["applying"] = False
            return False

    def _auto_update_loop(self):
        if self.stop_flag.wait(45):  # let the first diagnosis finish first
            return
        while not self.stop_flag.is_set():
            if self.settings.get("auto_update", True) and self.controller:
                self.check_update(apply_auto=True)
            if self.stop_flag.wait(6 * 3600):
                return

    def _loop(self, fn, period, gated=True):
        def run():
            while not self.stop_flag.is_set():
                if gated and not self.enabled:
                    self.stop_flag.wait(1)
                    continue
                try:
                    fn()
                except Exception as e:  # noqa: BLE001
                    print(f"[monitor] {fn.__name__}: {e}")
                self.stop_flag.wait(period)
        run.__name__ = getattr(fn, "__name__", "loop")
        return run

    # ----------------------------------------------------------------- targets & discovery
    def refresh_path(self):
        gw = self.cfg.get("gateway") or self.net.get("gateway")
        if not gw:
            return
        path = probe.discover_path(self.cfg["anchors"][1] if len(self.cfg["anchors"]) > 1 else "8.8.8.8", gw)
        path["gateway"] = gw
        t = {"gateway": gw}
        if path.get("modem_hop"):
            t["modem"] = path["modem_hop"]
        if (self.cfg.get("ont") or {}).get("host"):
            t["ont"] = self.cfg["ont"]["host"]
        isp = self.cfg.get("isp_hop") or path.get("isp_hop") or (self.path_cache.get("isp_hop") if self.path_cache.get("gateway") == gw else None)
        if isp:
            t["isp_hop"] = isp
            path["isp_hop"] = isp
        for a in self.cfg["anchors"]:
            t[f"anchor:{a}"] = a
        with self.lock:
            if path.get("isp_hop"):
                self.path_cache = path
            self.targets = t

    # ----------------------------------------------------------------- 1-second ping loop
    def _ping_loop(self):
        interval = self.cfg["ping_interval_sec"]
        nxt = time.time()
        while not self.stop_flag.is_set():
            if not self.enabled:
                self.stop_flag.wait(1)
                nxt = time.time()
                continue
            ts = time.time()
            targets = dict(self.targets)
            if targets:
                futs = {k: self.pool.submit(icmp.ping, ip, self.cfg["ping_timeout_ms"]) for k, ip in targets.items()}
                res = {k: f.result() for k, f in futs.items()}
                with self.lock:
                    for k, r in res.items():
                        rtt = r["rtt"] if r["ok"] else None
                        self.window[k].append((ts, rtt))
                        self.pending.append((ts, k, rtt))
                self._tick(ts, res)
            nxt += interval
            delay = nxt - time.time()
            if delay < 0:
                nxt = time.time()
                delay = 0
            self.stop_flag.wait(delay)

    def _chain_state(self, res):
        return {k: res[k]["ok"] for k in res}

    def _classify_chain(self, chain):
        """Fast root cause from which hops answered during the outage."""
        if self.net.get("primary", {}).get("status") not in (None, "Up"):
            return "pc", "Отключился сетевой адаптер ПК (кабель/Wi-Fi)"
        if chain.get("gateway") is False:
            if self.wifi is not None:
                return "wifi", "Пропала связь ПК ↔ роутер (Wi-Fi или роутер завис)"
            # cable link stayed up (the switch chip is powered) but the router itself is silent
            return "router", "Роутер перестал отвечать (завис или перезагружается)"
        if chain.get("modem") is False:
            return "modem", "Не отвечает модем/ONT провайдера"
        if chain.get("ont") is False:
            return "optics", "Не отвечает ONT (оптический терминал)"
        if chain.get("isp_hop") is False:
            return "wan", "Интернет перестал поступать в роутер (нет связи с первым узлом провайдера)"
        if chain.get("isp_hop") is True:
            return "isp", "Сбой в сети провайдера (до провайдера связь есть, дальше — нет)"
        return "internet", "Нет доступа в интернет"

    def _tick(self, ts, res):
        anchors = [v for k, v in res.items() if k.startswith("anchor:")]
        down = bool(anchors) and not any(a["ok"] for a in anchors)
        thr = self.cfg["outage_threshold_sec"]
        if down:
            if self.down_since is None:
                self.down_since = ts
                self.outage_chain = self._chain_state(res)
            elif self.outage_id is None and ts - self.down_since >= thr - 0.01:
                area, cause = self._classify_chain(self.outage_chain)
                self.outage_id = self.store.add_event(self.down_since, "outage", "critical", "Обрыв интернета", cause,
                                                      {"area": area, "chain": self.outage_chain, "targets": self.targets})
                self.counts["outages"] += 1
                eid = self.outage_id
                self.pool.submit(self._capture_outage, eid)
                self._notify("Интернет пропал", cause)
        elif self.down_since is not None:
            dur = ts - self.down_since
            if self.outage_id is not None:
                self.store.update_event(self.outage_id, ts_end=ts)
                self.counts["downtime"] += dur
                area, _ = self._classify_chain(self.outage_chain)
                self._notify("Интернет вернулся", f"Не было {_dur(dur)}. Причина и подробности — в программе.")
                if area in ("router", "wifi"):
                    self.pool.submit(self._post_router_outage, self.outage_id, dur)
            else:
                area, cause = self._classify_chain(self.outage_chain)
                self.store.add_event(self.down_since, "blip", "warning", f"Микрообрыв {dur:.0f} с", cause,
                                     {"area": area, "chain": self.outage_chain}, ts_end=ts)
                self.counts["blips"] += 1
            self.down_since = None
            self.outage_id = None
            self.outage_chain = None

    def _notify(self, title, body):
        if self.settings.get("notify", True):
            service.notify(title, body, f"http://127.0.0.1:{self.cfg['web_port']}/")

    def _post_router_outage(self, eid, dur):
        """After the router came back: did it reboot by itself or just hang?"""
        time.sleep(20)  # let the router finish booting its web/API services
        gw = self.net.get("gateway")
        try:
            r = routers.collect_router(self.cfg["router"], gw, system.gateway_mac(gw), False, self.router_cache) if gw else None
        except Exception:  # noqa: BLE001
            r = None
        up = (r or {}).get("uptime_sec")
        ev = self.store.event(eid)
        if not ev:
            return
        detail = ev["detail"]
        if up is not None and up < dur + 300:
            cause = "Роутер сам перезагрузился"
            detail["router_reboot"] = True
        elif up is not None and detail.get("area") == "router":
            cause = f"Роутер завис на {_dur(dur)} и сам «отвис» (без перезагрузки)"
            detail["router_hang"] = True
        else:
            cause = ev["cause"] or "Роутер перестал отвечать (завис или перезагружается)"
        if detail.get("router_reboot") or detail.get("router_hang"):
            detail["area"] = "router"
        detail["router_uptime_after"] = up
        self.store.update_event(eid, cause=cause, detail=detail)

    # ----------------------------------------------------------------- on/off & settings
    def set_settings(self, monitoring=None, notify=None, autostart=None, auto_update=None):
        if auto_update is not None:
            self.settings["auto_update"] = bool(auto_update)
        now = time.time()
        if monitoring is not None and bool(monitoring) != self.enabled:
            self.enabled = bool(monitoring)
            self.settings["monitoring"] = self.enabled
            if not self.enabled:
                self.down_since = self.outage_id = self.outage_chain = None
            self.store.add_event(now, "change", "info", "Мониторинг включён" if self.enabled else "Мониторинг выключен", "")
        if notify is not None:
            self.settings["notify"] = bool(notify)
        if autostart is not None:
            service.set_autostart(bool(autostart))
        service.save_settings(self.settings)
        self.settings["autostart"] = service.autostart_enabled()
        return dict(self.settings)

    def _capture_outage(self, eid):
        """Deep diagnosis while the internet is down: this is what tells the real reason."""
        try:
            snap = probe.collect(self.cfg, quick=True, router_cache=self.router_cache, path_cache=self.path_cache)
            res = analyzer.analyze(snap, self.cfg)
            v = res["verdict"]
            old = self.store.event(eid) or {"detail": {}, "cause": ""}
            serious = v["level"] in ("critical", "warning")
            # a deep check that finds nothing serious (outage already over) must not overwrite the fast classification
            detail = {"area": v["area"] if serious else old["detail"].get("area"), "verdict": v, "findings": res["findings"][:12],
                      "chain": old["detail"].get("chain"), "fast_cause": old["cause"],
                      "recovered_before_check": not serious}
            cause = v["title"] if serious else old["cause"]
            self.store.update_event(eid, cause=cause, detail=detail)
            self.store.add_snapshot(eid, snap)
        except Exception as e:  # noqa: BLE001
            print(f"[monitor] outage capture failed: {e}")

    # ----------------------------------------------------------------- periodic checks
    def _flush(self):
        with self.lock:
            rows, self.pending = self.pending, []
        if rows:
            self.store.add_samples(rows)

    def refresh_slow(self):
        primary = self.net.get("primary") or {}
        self.dns = system.dns_check(primary.get("dns") or [], self.cfg["dns_test_name"])
        self.http = system.http_check(self.cfg["http_check_url"], self.cfg["http_check_expect"])

    def refresh_system(self):
        net = system.network_state()
        prev = self.net.get("primary") or {}
        cur = net.get("primary") or {}
        now = time.time()
        if prev:
            if prev.get("status") != cur.get("status"):
                self.store.add_event(now, "change", "warning" if cur.get("status") != "Up" else "info",
                                     f"Адаптер {cur.get('name')}: {prev.get('status')} → {cur.get('status')}", "")
            if prev.get("link_bps") and cur.get("link_bps") and prev["link_bps"] != cur["link_bps"]:
                self.store.add_event(now, "change", "warning", f"Скорость линка ПК изменилась: {system.human_bps(prev['link_bps'])} → "
                                     f"{system.human_bps(cur['link_bps'])}", "Пересогласование линка — признак плохого кабеля/порта.")
            de = (cur.get("rx_errors") or 0) - (prev.get("rx_errors") or 0)
            if de > 10:
                self.store.add_event(now, "change", "warning", f"Сетевая карта: +{de} ошибок приёма", "Битые кадры — кабель/порт.")
            dt = now - self._last_sys.get("t", now)
            if dt > 0 and prev.get("rx_bytes") is not None and cur.get("rx_bytes") is not None:
                self.load["pc"] = {"down_bps": max(0, (cur["rx_bytes"] - prev["rx_bytes"]) * 8 / dt),
                                   "up_bps": max(0, (cur["tx_bytes"] - prev["tx_bytes"]) * 8 / dt)}
        self._last_sys["t"] = now
        wifi_now = system.wifi_state() if cur.get("is_wifi") else None
        if self.wifi and wifi_now:
            if self.wifi.get("bssid") != wifi_now.get("bssid") and wifi_now.get("bssid"):
                self.store.add_event(now, "change", "info", f"Wi-Fi: переключение на другую точку ({wifi_now.get('bssid')}, канал {wifi_now.get('channel')})")
            if self.wifi.get("channel") != wifi_now.get("channel") and wifi_now.get("channel"):
                self.store.add_event(now, "change", "info", f"Wi-Fi: канал сменился {self.wifi.get('channel')} → {wifi_now.get('channel')}",
                                     "Роутер сменил канал (авто-выбор или DFS-радар) — во время смены связь прерывается.")
        gw = net.get("gateway")
        mac = system.gateway_mac(gw) if gw else None
        if mac and self._gw_mac and gw == self._gw_mac[0] and mac != self._gw_mac[1]:
            self.store.add_event(now, "change", "warning", f"Сменился MAC-адрес роутера ({self._gw_mac[1]} → {mac})",
                                 "Конфликт IP-адресов или второй роутер/DHCP в сети — возможны обрывы у всех устройств",
                                 {"area": "router", "gateway_mac_change": True})
        if mac:
            self._gw_mac = (gw, mac)
        self.net = net
        self.wifi = wifi_now
        if not self.targets and net.get("gateway"):
            self.refresh_path()

    def refresh_router(self):
        gw = self.net.get("gateway")
        if not gw:
            return
        r = routers.collect_router(self.cfg["router"], gw, system.gateway_mac(gw), True, self.router_cache)
        now = time.time()
        if r is None:
            return
        old = self.router or {}
        ow, nw = old.get("wan") or {}, r.get("wan") or {}
        if ow:
            if ow.get("link") is True and nw.get("link") is False:
                self.store.add_event(now, "router", "critical", "Роутер: пропал линк на WAN-порту", "Кабель/ONT провайдера")
            if ow.get("connected") is True and nw.get("connected") is False:
                self.store.add_event(now, "router", "critical", "Роутер: WAN отключился", nw.get("error_text") or "")
            if (nw.get("link_downs") or 0) > (ow.get("link_downs") or 0):
                self.store.add_event(now, "router", "warning", f"Роутер: WAN-линк падал (всего {nw['link_downs']})", "Физический обрыв линии к ONT")
            if ow.get("link_speed_mbps") and nw.get("link_speed_mbps") and ow["link_speed_mbps"] != nw["link_speed_mbps"]:
                self.store.add_event(now, "router", "warning", f"Скорость WAN-порта: {ow['link_speed_mbps']} → {nw['link_speed_mbps']} Мбит/с",
                                     "Пересогласование — плохой кабель/порт")
            if (ow.get("uptime_sec") or 0) > (nw.get("uptime_sec") or 0) + 60 and nw.get("uptime_sec") is not None:
                self.store.add_event(now, "router", "warning", "WAN-подключение переустановлено", nw.get("error_text") or "")
            oo, no = old.get("optics") or {}, r.get("optics") or {}
            if no.get("rx_dbm") is not None and oo.get("rx_dbm") is not None and no["rx_dbm"] - oo["rx_dbm"] < -2:
                self.store.add_event(now, "router", "warning", f"Оптика: сигнал упал {oo['rx_dbm']} → {no['rx_dbm']} дБм", "")
        if old.get("uptime_sec") and r.get("uptime_sec") is not None and r["uptime_sec"] < old["uptime_sec"]:
            self.store.add_event(now, "router", "critical", "Роутер перезагрузился", "Питание, зависание или перегрев")
        self._compute_load(r, now)
        self.router = r
        if (self.cfg.get("ont") or {}).get("host"):
            try:
                self.ont = routers.collect_ont(self.cfg["ont"], False)
            except Exception:  # noqa: BLE001
                pass

    def _compute_load(self, r, now):
        """Rates from byte counters when the router only gives totals."""
        prev = self._prev_counters
        dt = now - prev.get("t", now)
        wan = dict(r.get("wan") or {})
        if wan.get("down_bps") is None and wan.get("rx_bytes_total") is not None and dt > 0 and prev.get("wan_rx") is not None:
            wan["down_bps"] = max(0, (wan["rx_bytes_total"] - prev["wan_rx"]) * 8 / dt)
            wan["up_bps"] = max(0, (wan["tx_bytes_total"] - prev["wan_tx"]) * 8 / dt)
        devs = []
        prev_dev = prev.get("dev", {})
        cur_dev = {}
        for d in r.get("devices") or []:
            d = dict(d)
            key = d.get("mac") or d.get("ip")
            if d.get("down_bytes") is not None:
                cur_dev[key] = (d.get("down_bytes"), d.get("up_bytes") or 0)
                if d.get("down_bps") is None and key in prev_dev and dt > 0:
                    pdn, pup = prev_dev[key]
                    d["down_bps"] = max(0, (d["down_bytes"] - pdn) * 8 / dt)
                    d["up_bps"] = max(0, ((d.get("up_bytes") or 0) - pup) * 8 / dt)
            devs.append(d)
        ports = []
        prev_ports = prev.get("ports", {})
        cur_ports = {}
        for p in r.get("ports") or []:
            if p.get("rx_bytes_total") is None:
                continue
            cur_ports[p["name"]] = (p["rx_bytes_total"], p["tx_bytes_total"] or 0)
            if p["name"] in prev_ports and dt > 0:
                prx, ptx = prev_ports[p["name"]]
                ports.append({"name": p["name"], "alias": p.get("alias"), "rx_bps": max(0, (p["rx_bytes_total"] - prx) * 8 / dt),
                              "tx_bps": max(0, (p["tx_bytes_total"] - ptx) * 8 / dt), "speed_mbps": p.get("speed_mbps"),
                              "wan": p.get("wan")})
        devs.sort(key=lambda d: -((d.get("down_bps") or 0) + (d.get("up_bps") or 0)))
        self._prev_counters = {"t": now, "wan_rx": wan.get("rx_bytes_total"), "wan_tx": wan.get("tx_bytes_total"),
                               "dev": cur_dev, "ports": cur_ports}
        self.load.update({"wan": {"down_bps": wan.get("down_bps"), "up_bps": wan.get("up_bps"),
                                  "link_mbps": wan.get("link_speed_mbps")},
                          "devices": devs, "ports": sorted(ports, key=lambda p: -(p["rx_bps"] + p["tx_bps"]))})
        tariff = self.cfg.get("tariff_mbps")
        if tariff and wan.get("down_bps") and wan["down_bps"] > tariff * 1e6 * 0.85:
            self._maybe_degrade("load", now, f"Канал загружен: {system.human_bps(wan['down_bps'])} из {tariff} Мбит/с",
                                "Топ: " + ", ".join(f"{d.get('name') or d.get('ip')}: {system.human_bps(d.get('down_bps'))}" for d in devs[:3]))

    # ----------------------------------------------------------------- quality degradation
    def stats(self, key, seconds=60):
        cut = time.time() - seconds
        with self.lock:
            data = [r for t, r in self.window.get(key, ()) if t >= cut]
        rtts = [r for r in data if r is not None]
        return icmp.series_stats(rtts, len(data) - len(rtts), len(data))

    def _maybe_degrade(self, kind, now, title, cause, detail=None):
        if now - self.last_degrade.get(kind, 0) < 300:
            return
        self.last_degrade[kind] = now
        self.store.add_event(now, "degradation", "warning", title, cause, detail)

    def _quality_check(self):
        if self.down_since is not None:
            return
        now = time.time()
        gw = self.stats("gateway")
        isp = self.stats("isp_hop") if "isp_hop" in self.targets else None
        anc = [self.stats(k) for k in self.targets if k.startswith("anchor:")]
        anc = [a for a in anc if a["sent"]]
        if not anc or not gw["sent"]:
            return
        loss = min(a["loss"] for a in anc)
        detail = {"gateway": gw, "isp_hop": isp, "anchors": anc}
        if gw["loss"] >= 3:
            self._maybe_degrade("lan_loss", now, f"Потери до роутера {gw['loss']}% за минуту",
                                "Проблема в домашней сети: " + ("Wi-Fi помехи/слабый сигнал" if self.wifi else "кабель/порт/роутер"), detail)
        elif isp and isp["loss"] >= 3 and loss >= 3:
            self._maybe_degrade("isp_loss", now, f"Потери на линии к провайдеру {isp['loss']}%",
                                "Роутер в норме, потери начинаются на участке роутер → провайдер (оптика/кабель/ONT или перегрузка канала)", detail)
        elif loss >= 3:
            self._maybe_degrade("net_loss", now, f"Потери в интернет {loss}%", "До провайдера чисто — потери в сети провайдера/магистрали", detail)
        lat = min(a["avg"] for a in anc if a["avg"] is not None) if any(a["avg"] is not None for a in anc) else None
        jit = max((a["jitter"] or 0) for a in anc)
        if isp and isp.get("avg") and gw.get("avg") is not None and isp["avg"] - gw["avg"] > 30:
            self._maybe_degrade("isp_lat", now, f"Пинг до провайдера вырос до {isp['avg']} мс",
                                "Канал загружен (кто-то качает) или проблема линии. " + self._top_consumers(), detail)
        elif gw.get("avg") and gw["avg"] > (25 if self.wifi else 5):
            self._maybe_degrade("lan_lat", now, f"Пинг до роутера {gw['avg']} мс",
                                "Перегружен роутер или Wi-Fi эфир", detail)
        elif jit > 40 and lat:
            self._maybe_degrade("jitter", now, f"Нестабильный пинг: джиттер {jit} мс", self._top_consumers(), detail)

    def _top_consumers(self):
        devs = [d for d in self.load.get("devices") or [] if (d.get("down_bps") or 0) > 1e6]
        if not devs:
            return ""
        return "Больше всего качают: " + ", ".join(f"{d.get('name') or d.get('ip') or d.get('mac')} ({system.human_bps(d['down_bps'])})" for d in devs[:3])

    # ----------------------------------------------------------------- on-demand full diagnosis
    def run_diagnosis(self, speedtest=False):
        if self.diag_running:
            return self.last_diag
        self.diag_running = True
        try:
            snap = probe.collect(self.cfg, quick=False, router_cache=self.router_cache, path_cache=self.path_cache,
                                 with_speedtest=speedtest)
            res = analyzer.analyze(snap, self.cfg)
            self.last_diag = {"time": time.time(), "snapshot": snap, "analysis": res}
            if snap.get("router") and not self.router:
                self.router = snap["router"]
            return self.last_diag
        finally:
            self.diag_running = False

    # ----------------------------------------------------------------- one-button check for everyone
    def start_check(self, speed=True):
        with self.lock:
            if self.check["running"]:
                return False
            self.check = {"running": True, "steps": {}, "result": None, "started": time.time(), "finished": None, "speed": speed}
        threading.Thread(target=self._run_check, args=(speed,), daemon=True).start()
        return True

    def _run_check(self, speed):
        def progress(name, state):
            self.check["steps"][name] = state
        try:
            snap = probe.collect(self.cfg, quick=False, router_cache=self.router_cache, path_cache=self.path_cache,
                                 with_speedtest=speed, progress=progress, ping_count=10)
            res = analyzer.analyze(snap, self.cfg)
            self.last_diag = {"time": time.time(), "snapshot": snap, "analysis": res}
            if snap.get("router") and not self.router:
                self.router = snap["router"]
            summary = simple.summarize(snap, res)
            hist = simple.history_verdict(self.store.events(time.time() - 48 * 3600))
            self.check["result"] = simple.merge_history(summary, hist)
        except Exception as e:  # noqa: BLE001
            self.check["result"] = {"status": "warn", "headline": "Проверка не завершилась", "explanation": str(e),
                                    "steps": ["Нажмите «Проверить ещё раз»."], "checks": [], "others": []}
        finally:
            self.check["running"] = False
            self.check["finished"] = time.time()

    def journal_plain(self, hours=24):
        since = time.time() - hours * 3600
        ev = self.store.events(since)
        drops = [e for e in ev if e["kind"] in ("outage", "blip")]
        items = [{"id": e["id"], "start": e["start"], "end": e["end"], "kind": e["kind"], "area": simple.event_area(e),
                  "cause": simple.plain_cause(e), "provider": simple.event_area(e) in simple.PROVIDER_AREAS} for e in drops]
        return {"since": since, "now": time.time(), "items": items, "verdicts": simple.history_verdict(ev),
                "covered": self.store.coverage(since), "monitoring": self.enabled}

    def history_plain(self, hours=24):
        ev = self.store.events(time.time() - hours * 3600)
        outs = [e for e in ev if e["kind"] in ("outage", "blip")]
        total = sum((e["end"] or time.time()) - e["start"] for e in outs if e["kind"] == "outage")
        causes = {}
        for e in outs:
            c = simple.plain_cause(e) or "—"
            causes[c] = causes.get(c, 0) + 1
        last = outs[0] if outs else None
        return {"outages": sum(1 for e in outs if e["kind"] == "outage"), "blips": sum(1 for e in outs if e["kind"] == "blip"),
                "downtime_sec": total, "top_cause": max(causes.items(), key=lambda kv: kv[1])[0] if causes else None,
                "last": dict({k: last[k] for k in ("start", "end", "kind")}, cause=simple.plain_cause(last)) if last else None,
                "monitoring_sec": time.time() - self.started}

    # ----------------------------------------------------------------- state for the UI
    def state(self):
        tg = dict(self.targets)
        rows = []
        for k, ip in tg.items():
            s1, s5 = self.stats(k, 60), self.stats(k, 300)
            with self.lock:
                last = self.window[k][-1][1] if self.window[k] else None
            label = TARGET_LABELS.get(k) or (f"Интернет {ip}" if k.startswith("anchor:") else k)
            rows.append({"key": k, "ip": ip, "label": label, "last": last, "m1": s1, "m5": s5})
        now = time.time()
        down = self.down_since is not None
        r = self.router or {}
        diag = self.last_diag or {}
        an = diag.get("analysis") or {}
        snap = diag.get("snapshot") or {}
        return {
            "now": now, "uptime": now - self.started, "internet": not down,
            "down_for": now - self.down_since if down else 0,
            "counts": self.counts, "targets": rows,
            "pc": self.net.get("primary"), "wifi": self.wifi, "gateway": self.net.get("gateway"),
            "dns": self.dns, "http": self.http,
            "router": {k: r.get(k) for k in ("type", "model", "firmware", "uptime_sec", "cpu_load", "mem_pct", "temperature",
                                             "wan", "ports", "optics", "notes", "fallback", "wifi_radios", "dsl", "cellular", "sfp")} if r else None,
            "ont": self.ont,
            "load": self.load,
            "diag": {"time": diag.get("time"), "running": self.diag_running, "verdict": an.get("verdict"),
                     "findings": an.get("findings"), "wifi_analysis": snap.get("wifi_analysis"),
                     "wifi_scan": snap.get("wifi_scan"), "path": snap.get("path"), "speedtest": snap.get("speedtest")},
        }
