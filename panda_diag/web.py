"""Local web UI + JSON API (127.0.0.1 only)."""
import json
import pkgutil
import threading
import time
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from . import __version__, fixes


def _json_default(o):
    return str(o)


def _page(name):
    # pkgutil works both from a source folder and from the zipped code bundle used by the exe
    return pkgutil.get_data(__package__, f"web/{name}")


def make_handler(mon):
    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):  # silence
            pass

        def _send(self, code, body, ctype="application/json; charset=utf-8"):
            if not isinstance(body, (bytes, bytearray)):
                body = json.dumps(body, ensure_ascii=False, default=_json_default).encode()
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Cache-Control", "no-store")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def _json_body(self):
            """Mutating endpoints require a JSON content type: browsers send it cross-site only after a CORS
            preflight we never approve, so other websites can't trigger these actions."""
            if not self.headers.get("Content-Type", "").startswith("application/json"):
                return None
            n = int(self.headers.get("Content-Length") or 0)
            try:
                return json.loads(self.rfile.read(n) or b"{}")
            except ValueError:
                return None

        def _app_info(self):
            ctrl = mon.controller
            return {"version": __version__, "launcher": getattr(ctrl, "launcher_version", None),
                    "admin": fixes.is_admin(), "frozen": bool(getattr(__import__("sys"), "frozen", False)),
                    "bundle": getattr(ctrl, "bundle", None), "update": mon.update,
                    "settings": dict(mon.settings, monitoring=mon.enabled), "fixes": fixes.catalog()}

        def do_GET(self):  # noqa: N802
            u = urllib.parse.urlparse(self.path)
            q = dict(urllib.parse.parse_qsl(u.query))
            if u.path in ("/", "/simple"):
                return self._send(200, _page("simple.html"), "text/html; charset=utf-8")
            if u.path in ("/pro", "/index.html"):
                return self._send(200, _page("index.html"), "text/html; charset=utf-8")
            if u.path == "/favicon.ico":
                return self._send(200, _page("icon.ico"), "image/x-icon")
            if u.path == "/api/app":
                return self._send(200, self._app_info())
            if u.path == "/api/check":
                c = dict(mon.check)
                c["steps"] = dict(c["steps"])
                c["internet"] = mon.down_since is None
                c["down_for"] = time.time() - mon.down_since if mon.down_since else 0
                c["history"] = mon.history_plain(float(q.get("hours", 24)))
                c["settings"] = dict(mon.settings, monitoring=mon.enabled)
                c["version"] = __version__
                c["update"] = {k: mon.update.get(k) for k in ("applying", "updated_from")}
                c["update"]["available"] = bool((mon.update.get("info") or {}).get("available"))
                c["update"]["latest"] = (mon.update.get("info") or {}).get("latest")
                return self._send(200, c)
            if u.path == "/api/journal":
                return self._send(200, mon.journal_plain(float(q.get("hours", 24))))
            if u.path == "/api/state":
                return self._send(200, mon.state())
            if u.path == "/api/samples":
                minutes = float(q.get("minutes", 15))
                step = 1 if minutes <= 30 else (10 if minutes <= 180 else 60)
                since = time.time() - minutes * 60
                return self._send(200, {"step": step, "since": since, "series": mon.store.samples(since, step),
                                        "targets": mon.targets})
            if u.path == "/api/events":
                return self._send(200, mon.store.events(time.time() - float(q.get("hours", 24)) * 3600))
            if u.path.startswith("/api/event/"):
                eid = int(u.path.rsplit("/", 1)[1])
                return self._send(200, {"event": mon.store.event(eid), "snapshot": mon.store.snapshot_for(eid)})
            if u.path == "/api/diagnosis":
                return self._send(200, mon.last_diag or {})
            return self._send(404, {"error": "not found"})

        def do_POST(self):  # noqa: N802
            u = urllib.parse.urlparse(self.path)
            q = dict(urllib.parse.parse_qsl(u.query))
            if u.path == "/api/check":
                started = mon.start_check(speed=q.get("speed", "1") == "1")
                return self._send(200 if started else 409, {"started": started})
            if u.path == "/api/diagnose":
                if mon.diag_running:
                    return self._send(409, {"error": "Диагностика уже выполняется"})
                d = mon.run_diagnosis(speedtest=q.get("speed") == "1")
                return self._send(200, {"ok": True, "time": d.get("time") if d else None})

            body = self._json_body()
            if body is None:
                return self._send(415, {"error": "application/json required"})
            if u.path == "/api/settings":
                try:
                    st = mon.set_settings(**{k: body[k] for k in ("monitoring", "notify", "autostart", "auto_update") if k in body})
                except OSError as e:
                    return self._send(500, {"error": str(e)})
                return self._send(200, st)
            if u.path == "/api/fix":
                res = fixes.run(str(body.get("action")))
                return self._send(200, res)
            if u.path == "/api/update/check":
                mon.check_update(apply_auto=False)
                return self._send(200, mon.update)
            if u.path == "/api/update/apply":
                if mon.update.get("info") is None:
                    mon.check_update(apply_auto=False)
                ok = mon.apply_update()
                return self._send(200 if ok else 409, mon.update)
            if u.path == "/api/quit":
                threading.Timer(0.5, mon.quit_event.set).start()
                return self._send(200, {"ok": True})
            return self._send(404, {"error": "not found"})

    return H


def serve(mon, host, port):
    srv = ThreadingHTTPServer((host, port), make_handler(mon))
    srv.daemon_threads = True
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv
