"""Self-update from GitHub Releases.

Every release carries:
  update.json                 {"version", "min_launcher", "notes", "bundle": {"name", "sha256"}, "exe": {"name", "sha256", "launcher_version"}}
  panda_diag-<version>.zip    application code -> hot-reloaded inside the running process (no restart)
  PandaInternetDiagnostic.exe full program     -> used only when the launcher itself is too old (swap + quick relaunch)
Downloads are checked against the SHA-256 published in update.json before use.
"""
import hashlib
import json
import os
import re
import sys
import time
import urllib.request

from . import GITHUB_REPO, MIN_LAUNCHER, __version__, config  # noqa: F401

# PANDA_UPDATE_API: point the updater at a test server (used by the release checklist)
API_LATEST = os.environ.get("PANDA_UPDATE_API") or f"https://api.github.com/repos/{GITHUB_REPO}/releases/latest"
RELEASES_PAGE = f"https://github.com/{GITHUB_REPO}/releases/latest"
UA = {"User-Agent": f"PandaInternetDiagnostic/{__version__}", "Accept": "application/vnd.github+json"}


def ver(s):
    return tuple(int(x) for x in re.findall(r"\d+", str(s or "0"))[:3]) or (0,)


def _get(url, timeout=15):
    req = urllib.request.Request(url, headers=UA)
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read()


def check(controller=None):
    """Look at the latest GitHub release. Returns a dict describing what (if anything) can be installed."""
    rel = json.loads(_get(API_LATEST))
    assets = {a["name"]: a["browser_download_url"] for a in rel.get("assets", [])}
    manifest = json.loads(_get(assets["update.json"])) if "update.json" in assets else {}
    latest = manifest.get("version") or rel.get("tag_name", "").lstrip("v")
    launcher = getattr(controller, "launcher_version", None)
    info = {"current": __version__, "latest": latest, "available": ver(latest) > ver(__version__),
            "notes": manifest.get("notes") or rel.get("body") or "", "published": rel.get("published_at"),
            "page": rel.get("html_url") or RELEASES_PAGE, "kind": None, "can_apply": False}
    if not info["available"]:
        return info
    b, e = manifest.get("bundle") or {}, manifest.get("exe") or {}
    needs_exe = launcher is None or ver(manifest.get("min_launcher")) > ver(launcher)
    if not needs_exe and b.get("name") in assets:
        info.update(kind="code", url=assets[b["name"]], sha256=b.get("sha256"), name=b["name"])
    elif e.get("name") in assets and (launcher is None or ver(e.get("launcher_version")) >= ver(manifest.get("min_launcher"))):
        # (a release whose exe can't run its own code would make the app swap exes forever — skip such releases)
        info.update(kind="exe", url=assets[e["name"]], sha256=e.get("sha256"), name=e["name"])
    # the code bundle can be applied only by the exe launcher; the exe only when actually running as exe
    info["can_apply"] = bool(controller) and info["kind"] is not None and (info["kind"] == "code" or config.FROZEN)
    return info


def _download(url, dest, sha256):
    tmp = dest + ".part"
    h = hashlib.sha256()
    req = urllib.request.Request(url, headers={"User-Agent": UA["User-Agent"]})
    with urllib.request.urlopen(req, timeout=60) as r, open(tmp, "wb") as f:
        while True:
            chunk = r.read(1 << 16)
            if not chunk:
                break
            h.update(chunk)
            f.write(chunk)
    if not sha256 or h.hexdigest().lower() != sha256.lower():
        os.remove(tmp)
        raise ValueError("Контрольная сумма обновления не совпала — файл повреждён или подменён, установка отменена")
    os.replace(tmp, dest)
    return dest


def apply(info, controller):
    """Install an update found by check(). Code updates hot-reload; exe updates swap the file and relaunch."""
    if not info.get("can_apply"):
        raise RuntimeError("Обновление можно установить только в exe-версии программы")
    if info["kind"] == "code":
        os.makedirs(config.UPDATES_DIR, exist_ok=True)
        dest = os.path.join(config.UPDATES_DIR, info["name"])
        _download(info["url"], dest, info.get("sha256"))
        _cleanup_bundles(keep=dest)
        controller.request_reload(dest)
        return "reload"
    exe = sys.executable
    new = exe + ".new"
    _download(info["url"], new, info.get("sha256"))
    old = exe + ".old"
    if os.path.exists(old):
        os.remove(old)
    os.replace(exe, old)          # Windows allows renaming a running exe
    os.replace(new, exe)
    controller.request_exe_restart([exe, "monitor", "--no-browser", "--after-update"])
    return "restart"


def cleanup_after_exe_update():
    if config.FROZEN:
        old = sys.executable + ".old"
        for _ in range(60):
            try:
                if os.path.exists(old):
                    os.remove(old)
                return
            except OSError:
                time.sleep(1)  # previous process may still be exiting


def _cleanup_bundles(keep):
    d = config.UPDATES_DIR
    files = sorted((f for f in os.listdir(d) if f.endswith(".zip")), key=lambda n: ver(n), reverse=True)
    for name in files[2:]:  # keep the newest two (rollback safety)
        p = os.path.join(d, name)
        if p != keep:
            try:
                os.remove(p)
            except OSError:
                pass
