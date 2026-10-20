"""Entry point.

  python -m panda_diag              — continuous monitoring + web dashboard (default)
  python -m panda_diag diag [--speed]  — one-shot full diagnosis in the console (+ HTML report)
  python -m panda_diag events [--hours 24] — outage history summary
  python -m panda_diag router-dump  — save raw router API answers (for support / new firmware)
  python -m panda_diag init         — create config.json with defaults
"""
import argparse
import html
import json
import os
import sys
import time
import webbrowser

from . import analyzer, config, probe, routers, system

COL = {"critical": "\033[91m", "warning": "\033[93m", "info": "\033[96m", "ok": "\033[92m", "end": "\033[0m", "b": "\033[1m"}
ICON = {"critical": "✖", "warning": "▲", "info": "•", "ok": "✔"}


def _console():
    if sys.stdout is None or not getattr(sys.stdout, "isatty", lambda: False)():
        for k in COL:  # log file / pythonw: no ANSI colour codes
            COL[k] = ""
    if sys.stdout is None:  # pythonw (silent autostart): no console at all
        return
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:  # noqa: BLE001
        pass
    if sys.stdout.isatty():
        os.system("")  # enable ANSI colors in the Windows console


def print_findings(res):
    v = res["verdict"]
    print(f"\n{COL['b']}ИТОГ: {COL[v['level']]}{v['title']}{COL['end']}\n")
    for f in res["findings"]:
        print(f"{COL[f['level']]}{ICON[f['level']]} {f['title']}{COL['end']}")
        if f.get("detail"):
            for line in f["detail"].splitlines():
                print(f"    {line}")
        if f.get("advice"):
            print(f"    → {f['advice']}")


def print_snapshot(s):
    pc = (s.get("net") or {}).get("primary") or {}
    print(f"{COL['b']}ПК:{COL['end']} {pc.get('name')} ({pc.get('description')}), {pc.get('status')}, линк {system.human_bps(pc.get('link_bps'))}, IP {pc.get('ipv4')}")
    if s.get("wifi"):
        w = s["wifi"]
        print(f"{COL['b']}Wi-Fi:{COL['end']} {w.get('ssid')} {w.get('rssi_dbm')} дБм, канал {w.get('channel')}, {w.get('rx_mbps')}/{w.get('tx_mbps')} Мбит/с")
    r = s.get("router") or {}
    print(f"{COL['b']}Роутер:{COL['end']} {s.get('gateway')} [{s.get('gateway_vendor') or '?'}] драйвер={r.get('type')}"
          f"{' +' + r['fallback'] if r.get('fallback') else ''} модель={r.get('model') or '—'}")
    wan = r.get("wan") or {}
    if wan:
        print(f"   WAN: линк={wan.get('link')} подключено={wan.get('connected')} скорость порта={wan.get('link_speed_mbps')} "
              f"IP={wan.get('ip')} ошибка={wan.get('error_text') or '—'}")
    p = s.get("path") or {}
    print(f"{COL['b']}Маршрут:{COL['end']} модем провайдера={p.get('modem_hop') or 'нет'}, первый узел провайдера={p.get('isp_hop') or '?'}")
    for k, st in (s.get("pings") or {}).items():
        print(f"   {k:<18} {st['ip']:<16} потери {st['loss']:>5}%  ср {st['avg'] if st['avg'] is not None else '—':>6} мс  джиттер {st['jitter'] if st['jitter'] is not None else '—'}")
    wa = s.get("wifi_analysis")
    if wa:
        print(f"{COL['b']}Wi-Fi рекомендации:{COL['end']}")
        for a in wa["advice"]:
            print(f"   • {a}")
    devs = [d for d in r.get("devices") or [] if d.get("down_bps")]
    if devs:
        print(f"{COL['b']}Топ потребителей:{COL['end']}")
        for d in sorted(devs, key=lambda d: -d["down_bps"])[:10]:
            print(f"   {d.get('name') or d.get('ip') or d.get('mac'):<30} ↓ {system.human_bps(d['down_bps'])}  ↑ {system.human_bps(d.get('up_bps'))}")
    if s.get("speedtest"):
        print(f"{COL['b']}Скорость:{COL['end']} {s['speedtest']['mbps']} Мбит/с")


def html_report(s, res, path):
    rows = "".join(
        f"<div class='f {f['level']}'><b>{html.escape(f['title'])}</b><div>{html.escape(f.get('detail') or '').replace(chr(10), '<br>')}</div>"
        f"{'<div>→ ' + html.escape(f['advice']) + '</div>' if f.get('advice') else ''}</div>" for f in res["findings"])
    body = f"""<!doctype html><meta charset="utf-8"><title>Отчёт диагностики сети</title>
<style>body{{font:14px system-ui;max-width:900px;margin:30px auto;padding:0 16px;color:#16181d;background:#fff}}
.f{{border-left:4px solid #ccc;padding:8px 12px;margin:8px 0;background:#f6f7f9}}.critical{{border-color:#d92d20}}.warning{{border-color:#d98a00}}
.info{{border-color:#2e6be6}}.ok{{border-color:#12a150}}pre{{background:#f6f7f9;padding:12px;overflow:auto;font-size:12px}}</style>
<h1>Диагностика сети — {html.escape(s['time'])}</h1><p>Компьютер: {html.escape(s.get('host', ''))}</p>
<h2>Итог: {html.escape(res['verdict']['title'])}</h2>{rows}
<h2>Сырые данные</h2><pre>{html.escape(json.dumps({k: v for k, v in s.items() if k != 'events'}, ensure_ascii=False, indent=1, default=str))}</pre>"""
    with open(path, "w", encoding="utf-8") as f:
        f.write(body)


def cmd_diag(cfg, speed):
    print("Диагностика… (15–40 секунд)")
    s = probe.collect(cfg, with_speedtest=speed)
    res = analyzer.analyze(s, cfg)
    from . import simple
    sm = simple.summarize(s, res)
    col = {"good": "ok", "warn": "warning", "bad": "critical"}[sm["status"]]
    print(f"\n{COL['b']}{COL[col]}{sm['headline']}{COL['end']}\n{sm['explanation']}")
    for i, st in enumerate(sm.get("steps") or [], 1):
        print(f"  {i}. {st}")
    if sm.get("provider_text"):
        print(f"\nТекст для провайдера:\n  {sm['provider_text']}")
    if sm.get("speed_mbps") is not None:
        print(f"\nСкорость: {sm['speed_mbps']:.0f} Мбит/с — {sm['speed_text']}")
    print(f"\n{'-' * 60}\nТехнические подробности:\n")
    print_snapshot(s)
    print_findings(res)
    path = os.path.join(config.DATA_DIR, f"report_{time.strftime('%Y%m%d_%H%M%S')}.html")
    html_report(s, res, path)
    print(f"\nОтчёт сохранён: {path}")


def cmd_events(cfg, hours):
    from .monitor import Store
    st = Store(os.path.join(config.DATA_DIR, "history.sqlite"))
    ev = st.events(time.time() - hours * 3600)
    if not ev:
        print("Событий нет.")
        return
    for e in reversed(ev):
        d = f"{e['end'] - e['start']:.0f} с" if e["end"] else ""
        print(f"{time.strftime('%d.%m %H:%M:%S', time.localtime(e['start']))}  {e['kind']:<11} {d:>7}  {e['title']} — {e['cause']}")


def cmd_router_dump(cfg):
    net = system.network_state()
    gw = cfg.get("gateway") or net.get("gateway")
    mac = system.gateway_mac(gw)
    print(f"Шлюз {gw}, MAC {mac}, производитель {routers.vendor_by_mac(mac)}")
    print("Определение типа:", routers.detect(gw, mac, cfg["router"].get("type")))
    r = routers.collect_router(cfg["router"], gw, mac, True, {})
    path = os.path.join(config.DATA_DIR, f"router_dump_{time.strftime('%Y%m%d_%H%M%S')}.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump(r, f, ensure_ascii=False, indent=2, default=str)
    print("Заметки:", *(r or {}).get("notes", []), sep="\n  ")
    print(f"Сохранено: {path}")


def cmd_monitor(cfg, open_browser=True, controller=None, reloaded=False):
    import threading
    import urllib.request
    from . import service, updater
    from .monitor import Monitor
    from .web import serve
    host, port = cfg["web_host"], cfg["web_port"]
    url = f"http://{'127.0.0.1' if host in ('0.0.0.0', '') else host}:{port}/"
    if not reloaded:
        try:  # already running (e.g. started with Windows)? just show its window
            with urllib.request.urlopen(url + "api/check", timeout=2):
                pass
            print(f"Программа уже работает: {url}")
            if open_browser:
                service.open_ui(url)
            return
        except Exception:  # noqa: BLE001
            pass
    threading.Thread(target=updater.cleanup_after_exe_update, daemon=True).start()
    quit_event = threading.Event()
    mon = Monitor(cfg, controller=controller, quit_event=quit_event)
    mon.start()
    srv = None
    for attempt in range(20):  # after a hot reload the old server may need a moment to release the port
        try:
            srv = serve(mon, host, port)
            break
        except OSError:
            time.sleep(0.5)
    if srv is None:
        mon.stop()
        raise RuntimeError(f"Порт {port} занят")
    print(f"Мониторинг запущен. Панель: {url}\nДанные: {config.DATA_DIR}\nCtrl+C — остановить.")
    if open_browser:
        service.open_ui(url)
    wake = controller.reload_event if controller else threading.Event()
    last = None
    try:
        while not (wake.is_set() or quit_event.is_set()):
            wake.wait(1)
            st = "НЕТ ИНТЕРНЕТА" if mon.down_since else "ok"
            if st != last:
                print(f"{time.strftime('%H:%M:%S')}  {COL['critical'] if mon.down_since else COL['ok']}{st}{COL['end']}")
                last = st
    except KeyboardInterrupt:
        pass
    mon.stop()
    srv.shutdown()
    srv.server_close()


def main(argv=None, controller=None):
    _console()
    ap = argparse.ArgumentParser(prog="panda_diag", description="Диагностика и мониторинг интернет-подключения")
    ap.add_argument("cmd", nargs="?", default="monitor", choices=["monitor", "diag", "events", "router-dump", "init"])
    ap.add_argument("--speed", action="store_true", help="добавить тест скорости в diag")
    ap.add_argument("--hours", type=float, default=24)
    ap.add_argument("--no-browser", action="store_true")
    ap.add_argument("--port", type=int, help="порт окна программы (по умолчанию 8765)")
    ap.add_argument("--reloaded", action="store_true", help=argparse.SUPPRESS)
    ap.add_argument("--after-update", action="store_true", help=argparse.SUPPRESS)
    a = ap.parse_args(argv)
    if a.cmd == "init":
        if os.path.exists(config.CONFIG_PATH):
            print(f"Уже существует: {config.CONFIG_PATH}")
        else:
            with open(config.CONFIG_PATH, "w", encoding="utf-8") as f:
                json.dump(config.DEFAULTS, f, ensure_ascii=False, indent=2)
            print(f"Создан {config.CONFIG_PATH}")
        return
    cfg = config.load()
    if a.port:
        cfg["web_port"] = a.port
    if a.cmd == "diag":
        cmd_diag(cfg, a.speed)
    elif a.cmd == "events":
        cmd_events(cfg, a.hours)
    elif a.cmd == "router-dump":
        cmd_router_dump(cfg)
    else:
        cmd_monitor(cfg, not a.no_browser, controller, a.reloaded or a.after_update)


if __name__ == "__main__":
    main()
