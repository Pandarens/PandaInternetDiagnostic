"""Stable launcher for the exe build.

The exe contains only the Python runtime, the standard-library modules the app needs and this launcher.
The application code (package `panda_diag`) is loaded from a zip bundle:
  1. the newest valid bundle downloaded by the updater into %LOCALAPPDATA%\\PandaInternetDiagnostic\\app,
  2. otherwise the bundle embedded into the exe at build time.
When the app asks for a reload (code update), the launcher drops the old modules and imports the new bundle
in the same process — no reinstall, no restart of the program.

LAUNCHER_VERSION changes only when the exe itself must be replaced (new Python, new stdlib module, launcher fix).
"""
import importlib
import os
import re
import sys
import threading
import traceback
import zipfile

# --- standard-library modules used by panda_diag. They must be imported here so PyInstaller bundles them:
# the app code itself is shipped as a zip and is invisible to PyInstaller's analysis.
# tests/test_launcher_deps.py fails if the app starts using a module that is missing from this list.
import argparse, base64, collections, copy, ctypes, ctypes.wintypes, hashlib, html, http.client, http.cookiejar  # noqa: E401,F401
import http.server, ipaddress, json, pkgutil, random, shutil, socket, socketserver, sqlite3, ssl, struct  # noqa: E401,F401
import subprocess, tempfile, time, urllib.error, urllib.parse, urllib.request, uuid, webbrowser, zipimport  # noqa: E401,F401
import concurrent.futures, email.utils, platform, getpass, locale, string, textwrap, datetime, io  # noqa: E401,F401

LAUNCHER_VERSION = "1.0.0"
APP_NAME = "PandaInternetDiagnostic"
PKG = "panda_diag"


def _ver(s):
    return tuple(int(x) for x in re.findall(r"\d+", s or "0")[:3]) or (0,)


def _bundle_info(path):
    """(version, min_launcher) read from panda_diag/__init__.py inside a bundle zip, or None if invalid."""
    try:
        with zipfile.ZipFile(path) as z:
            if z.testzip() is not None:
                return None
            src = z.read(f"{PKG}/__init__.py").decode("utf-8")
    except Exception:  # noqa: BLE001
        return None
    v = re.search(r'__version__\s*=\s*"([^"]+)"', src)
    ml = re.search(r'MIN_LAUNCHER\s*=\s*"([^"]+)"', src)
    return (v.group(1) if v else "0", ml.group(1) if ml else "0")


def updates_dir():
    return os.path.join(os.environ.get("LOCALAPPDATA") or os.path.expanduser("~"), APP_NAME, "app")


def embedded_bundle():
    if getattr(sys, "frozen", False):
        p = os.path.join(getattr(sys, "_MEIPASS", os.path.dirname(sys.executable)), f"{PKG}.zip")
        return p if os.path.exists(p) else None
    return None


def pick_bundle():
    """Newest compatible bundle: downloaded update or the embedded one. None = run from source (dev)."""
    cands = []
    emb = embedded_bundle()
    if emb:
        info = _bundle_info(emb)
        if info:
            cands.append((_ver(info[0]), emb))
    elif not getattr(sys, "frozen", False) and os.environ.get("PANDA_USE_BUNDLES") != "1":
        return None  # source checkout: always run the working tree
    d = updates_dir()
    if os.path.isdir(d):
        for name in os.listdir(d):
            if not (name.startswith(PKG + "-") and name.endswith(".zip")):
                continue
            p = os.path.join(d, name)
            info = _bundle_info(p)
            if info and _ver(info[1]) <= _ver(LAUNCHER_VERSION):
                cands.append((_ver(info[0]), p))
    if not cands:
        return None
    return max(cands)[1]


def mark_bad(path):
    try:
        os.replace(path, path + ".bad")
    except OSError:
        pass


class Controller:
    """Handed to the app so it can request a hot code reload or an exe restart."""

    def __init__(self):
        self.launcher_version = LAUNCHER_VERSION
        self.bundle = None
        self.reload_event = threading.Event()
        self.reload_to = None
        self.restart_exe = None
        self.reloaded_from = None

    def request_reload(self, bundle_path=None):
        self.reload_to = bundle_path or "auto"
        self.reload_event.set()

    def request_exe_restart(self, new_exe_cmd):
        self.restart_exe = new_exe_cmd
        self.reload_event.set()


def _purge():
    for name in list(sys.modules):
        if name == PKG or name.startswith(PKG + "."):
            del sys.modules[name]
    sys.path[:] = [p for p in sys.path if not (p.endswith(".zip") and os.path.basename(p).startswith(PKG))]
    zipimport._zip_directory_cache.clear() if hasattr(zipimport, "_zip_directory_cache") else None
    importlib.invalidate_caches()


def _setup_log():
    """No console in the exe: send output and errors to %LOCALAPPDATA%\\PandaInternetDiagnostic\\app.log."""
    if sys.stdout is not None and sys.stderr is not None:
        return
    d = os.path.dirname(updates_dir())
    try:
        os.makedirs(d, exist_ok=True)
        path = os.path.join(d, "app.log")
        if os.path.exists(path) and os.path.getsize(path) > 2_000_000:
            os.replace(path, path + ".1")
        f = open(path, "a", encoding="utf-8-sig" if not os.path.exists(path) else "utf-8", buffering=1)
        sys.stdout = sys.stderr = f
        print(f"\n===== {time.strftime('%Y-%m-%d %H:%M:%S')} start, launcher {LAUNCHER_VERSION}, args {sys.argv[1:]}")
    except OSError:
        pass


def main():
    _setup_log()
    ctrl = Controller()
    argv = sys.argv[1:]
    forced = None
    while True:
        bundle = forced if forced and forced != "auto" else pick_bundle()
        forced = None
        _purge()
        if bundle:
            sys.path.insert(0, bundle)
        ctrl.bundle = bundle
        ctrl.reload_event.clear()
        ctrl.reload_to = None
        try:
            app = importlib.import_module(f"{PKG}.__main__")
            app.main(argv, controller=ctrl)
        except SystemExit:
            raise
        except Exception:  # noqa: BLE001
            traceback.print_exc()
            if bundle and bundle != embedded_bundle():
                mark_bad(bundle)  # broken update -> fall back to the previous good code
                continue
            raise
        if ctrl.restart_exe:
            subprocess.Popen(ctrl.restart_exe, close_fds=True)
            sys.stdout.flush()
            os._exit(0)  # don't wait for background worker threads: the new exe is already starting
        if ctrl.reload_to:
            ctrl.reloaded_from = getattr(sys.modules.get(PKG), "__version__", None)
            forced = ctrl.reload_to
            argv = [a for a in argv if a not in ("--open", "--no-browser", "--reloaded")] + ["--no-browser", "--reloaded"]
            continue
        return


if __name__ == "__main__":
    main()
