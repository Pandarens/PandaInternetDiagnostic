"""User settings, Windows autostart and toast notifications."""
import json
import os
import subprocess
import sys
import threading

from . import config

SETTINGS_PATH = os.path.join(config.DATA_DIR, "settings.json")
DEFAULT_SETTINGS = {"monitoring": True, "notify": True, "auto_update": True}
STARTUP_NAME = "PandaInternetDiagnostic.vbs"
CREATE_NO_WINDOW = 0x08000000


def load_settings():
    s = dict(DEFAULT_SETTINGS)
    try:
        with open(SETTINGS_PATH, "r", encoding="utf-8") as f:
            s.update(json.load(f))
    except (OSError, ValueError):
        pass
    s["autostart"] = autostart_enabled()
    return s


def save_settings(s):
    os.makedirs(config.DATA_DIR, exist_ok=True)
    data = {k: v for k, v in s.items() if k in DEFAULT_SETTINGS}
    with open(SETTINGS_PATH, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)


# ------------------------------------------------------------------ autostart (per-user Startup folder)

def _startup_dir():
    return os.path.join(os.environ.get("APPDATA", ""), "Microsoft", "Windows", "Start Menu", "Programs", "Startup")


def _startup_path():
    return os.path.join(_startup_dir(), STARTUP_NAME)


def launch_command():
    """Command line that starts monitoring silently (no console window)."""
    if getattr(sys, "frozen", False):
        return f'"{sys.executable}" monitor --no-browser'
    exe = sys.executable
    pyw = os.path.join(os.path.dirname(exe), "pythonw.exe")
    if os.path.exists(pyw):
        exe = pyw
    return f'"{exe}" -m panda_diag monitor --no-browser'


TASK_NAME = "PandaInternetDiagnostic"


def _is_admin():
    from .fixes import is_admin
    return is_admin()


def _task_exists():
    try:
        p = subprocess.run(["schtasks", "/Query", "/TN", TASK_NAME], capture_output=True, timeout=15, creationflags=CREATE_NO_WINDOW)
        return p.returncode == 0
    except Exception:  # noqa: BLE001
        return False


def autostart_enabled():
    return os.path.exists(_startup_path()) or _task_exists()


def set_autostart(enabled):
    """Elevated exe -> Task Scheduler task with highest privileges at logon (no UAC prompt every boot).
    Otherwise -> a hidden launcher in the user's Startup folder."""
    path = _startup_path()
    if not enabled:
        if os.path.exists(path):
            os.remove(path)
        if _task_exists():
            subprocess.run(["schtasks", "/Delete", "/TN", TASK_NAME, "/F"], capture_output=True, timeout=15,
                           creationflags=CREATE_NO_WINDOW)
        return False
    if config.FROZEN and _is_admin():
        p = subprocess.run(["schtasks", "/Create", "/TN", TASK_NAME, "/TR", f'"{sys.executable}" monitor --no-browser',
                            "/SC", "ONLOGON", "/RL", "HIGHEST", "/F", "/DELAY", "0000:30"],
                           capture_output=True, timeout=20, creationflags=CREATE_NO_WINDOW)
        if p.returncode == 0:
            return True
    os.makedirs(_startup_dir(), exist_ok=True)
    cmd = launch_command().replace('"', '""')
    vbs = (f'Set sh = CreateObject("WScript.Shell")\r\n'
           f'sh.CurrentDirectory = "{config.BASE_DIR}"\r\n'
           f'sh.Run "{cmd}", 0, False\r\n')
    with open(path, "w", encoding="utf-16", newline="") as f:  # UTF-16 so paths with Cyrillic work in WSH
        f.write(vbs)
    return True


# ------------------------------------------------------------------ app window

def _edge():
    for base in (os.environ.get("ProgramFiles(x86)"), os.environ.get("ProgramFiles"), os.environ.get("LOCALAPPDATA")):
        if base:
            p = os.path.join(base, "Microsoft", "Edge", "Application", "msedge.exe")
            if os.path.exists(p):
                return p
    return None


def open_ui(url):
    """Open the UI as an app-like window (Edge --app, own profile so it never mixes with the user's browsing);
    falls back to the default browser."""
    edge = _edge()
    profile = os.path.join(config.BASE_DIR, "ui-profile")
    if edge:
        try:
            subprocess.Popen([edge, f"--app={url}", "--window-size=1000,880", f"--user-data-dir={profile}",
                              "--no-first-run", "--no-default-browser-check"], creationflags=CREATE_NO_WINDOW)
            return
        except Exception:  # noqa: BLE001
            pass
    try:
        subprocess.Popen(["explorer.exe", url])  # explorer opens URLs in the user's (non-elevated) default browser
    except Exception:  # noqa: BLE001
        import webbrowser
        webbrowser.open(url)


# ------------------------------------------------------------------ toast notifications

_TOAST_PS = r"""
[Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime] | Out-Null
[Windows.Data.Xml.Dom.XmlDocument, Windows.Data.Xml.Dom.XmlDocument, ContentType = WindowsRuntime] | Out-Null
$t = [System.Security.SecurityElement]::Escape('%(title)s')
$b = [System.Security.SecurityElement]::Escape('%(body)s')
$xml = New-Object Windows.Data.Xml.Dom.XmlDocument
$xml.LoadXml("<toast activationType='protocol' launch='%(url)s'><visual><binding template='ToastGeneric'><text>$t</text><text>$b</text></binding></visual></toast>")
$app = '{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}\WindowsPowerShell\v1.0\powershell.exe'
[Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier($app).Show([Windows.UI.Notifications.ToastNotification]::new($xml))
"""


def notify(title, body, url="http://127.0.0.1:8765/"):
    """Windows 10/11 toast; silently ignored if unavailable."""
    def run():
        script = _TOAST_PS % {"title": title.replace("'", "''"), "body": body.replace("'", "''")[:250], "url": url}
        try:
            subprocess.run(["powershell", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", script],
                           capture_output=True, timeout=20, creationflags=CREATE_NO_WINDOW)
        except Exception:  # noqa: BLE001
            pass
    threading.Thread(target=run, daemon=True).start()
