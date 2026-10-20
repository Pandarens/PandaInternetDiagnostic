"""One-click fixes. Most need administrator rights (the exe always runs elevated)."""
import ctypes
import subprocess

from . import system

CREATE_NO_WINDOW = 0x08000000


def is_admin():
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:  # noqa: BLE001
        return False


def _run(args, timeout=60):
    p = subprocess.run(args, capture_output=True, timeout=timeout, creationflags=CREATE_NO_WINDOW)
    out = (p.stdout or b"").decode("oem", errors="replace") + (p.stderr or b"").decode("oem", errors="replace")
    return p.returncode == 0, out.strip()


def _ps(script, timeout=60):
    p = subprocess.run(["powershell", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", script],
                       capture_output=True, timeout=timeout, creationflags=CREATE_NO_WINDOW)
    return p.returncode == 0, ((p.stdout or b"") + (p.stderr or b"")).decode("utf-8", errors="replace").strip()


def _primary():
    return (system.network_state().get("primary") or {})


def _q(s):
    return "'" + str(s).replace("'", "''") + "'"


# action id -> (title, needs_admin, needs_reboot, description)
ACTIONS = {
    "flush_dns": ("Очистить DNS-кэш", False, False, "Помогает, когда отдельные сайты не открываются или открываются старые адреса."),
    "renew_ip": ("Заново получить IP от роутера", False, False, "Компьютер на пару секунд отключится от сети и получит адрес заново."),
    "restart_adapter": ("Перезапустить сетевую карту", True, False, "Выключит и включит сетевой адаптер (около 10 секунд без сети)."),
    "public_dns": ("Поставить быстрые DNS (1.1.1.1 и 8.8.8.8)", True, False, "Только для этого компьютера. Вернуть можно кнопкой «DNS автоматически»."),
    "auto_dns": ("DNS автоматически (как было)", True, False, "Вернёт получение DNS от роутера."),
    "disable_eee": ("Отключить энергосбережение сетевой карты", True, False, "Убирает кратковременные разрывы кабеля на картах Realtek/Intel."),
    "reset_stack": ("Сбросить сетевые настройки Windows", True, True, "Сброс Winsock и TCP/IP. Потребуется перезагрузка компьютера."),
    "location": ("Разрешить доступ к местоположению", False, False,
                 "Windows 11 разрешает сканировать соседние Wi-Fi сети только программам с доступом к местоположению."),
}


def run(action):
    if action not in ACTIONS:
        return {"ok": False, "message": "Неизвестное действие"}
    title, need_admin, reboot, _ = ACTIONS[action]
    if need_admin and not is_admin():
        return {"ok": False, "message": "Нужны права администратора — запустите программу от имени администратора."}
    pc = _primary()
    name, idx = pc.get("name"), pc.get("index")
    if action == "flush_dns":
        ok, out = _run(["ipconfig", "/flushdns"])
    elif action == "renew_ip":
        ok, out = _run(["ipconfig", "/renew"] + ([name] if name else []), timeout=90)
    elif action == "restart_adapter":
        if not name:
            return {"ok": False, "message": "Сетевой адаптер не найден"}
        ok, out = _ps(f"Restart-NetAdapter -Name {_q(name)} -Confirm:$false", timeout=90)
    elif action == "public_dns":
        if idx is None:
            return {"ok": False, "message": "Сетевой адаптер не найден"}
        ok, out = _ps(f"Set-DnsClientServerAddress -InterfaceIndex {int(idx)} -ServerAddresses ('1.1.1.1','8.8.8.8')")
        _run(["ipconfig", "/flushdns"])
    elif action == "auto_dns":
        if idx is None:
            return {"ok": False, "message": "Сетевой адаптер не найден"}
        ok, out = _ps(f"Set-DnsClientServerAddress -InterfaceIndex {int(idx)} -ResetServerAddresses")
        _run(["ipconfig", "/flushdns"])
    elif action == "disable_eee":
        if not name:
            return {"ok": False, "message": "Сетевой адаптер не найден"}
        ok, out = _ps(
            f"$a={_q(name)}; $n=0; Get-NetAdapterAdvancedProperty -Name $a | "
            "Where-Object { $_.RegistryKeyword -match 'EEE|GreenEthernet|PowerSavingMode|EnableGreenEthernet|AdvancedEEE' } | "
            "ForEach-Object { $off = ($_.ValidRegistryValues | Where-Object { $_ -eq '0' } | Select-Object -First 1); "
            "if ($off -ne $null) { Set-NetAdapterAdvancedProperty -Name $a -RegistryKeyword $_.RegistryKeyword -RegistryValue $off -NoRestart; $n++ } }; "
            "if ($n -gt 0) { Restart-NetAdapter -Name $a -Confirm:$false }; \"changed=$n\"", timeout=90)
        if ok and "changed=0" in out:
            return {"ok": True, "message": "У этой сетевой карты нет включённого энергосбережения — менять нечего."}
    elif action == "reset_stack":
        ok1, o1 = _run(["netsh", "winsock", "reset"])
        ok2, o2 = _run(["netsh", "int", "ip", "reset"])
        ok, out = ok1 and ok2, o1 + "\n" + o2
    elif action == "location":
        ok, out = _run(["cmd", "/c", "start", "", "ms-settings:privacy-location"])
        return {"ok": ok, "message": "Открыл настройки. Включите «Службы определения местоположения» и «Разрешить приложениям рабочего стола»."}
    else:
        return {"ok": False, "message": "Не реализовано"}
    msg = f"Готово: {title.lower()}." if ok else f"Не получилось: {out[-300:]}"
    if ok and reboot:
        msg += " Перезагрузите компьютер, чтобы изменения вступили в силу."
    return {"ok": ok, "message": msg, "reboot": reboot and ok}


def catalog():
    return [{"id": k, "title": v[0], "admin": v[1], "reboot": v[2], "text": v[3]} for k, v in ACTIONS.items()]


# plain-language problem code -> suggested fixes
FIXES_FOR = {
    "dns_dead": ["public_dns", "flush_dns"], "dns_primary_dead": ["public_dns"], "dns_slow": ["public_dns"],
    "router_dns_broken": ["public_dns"], "dns_blocked": ["flush_dns", "reset_stack"], "http_fail": ["flush_dns"],
    "dhcp_fail": ["renew_ip", "restart_adapter"], "no_gateway": ["renew_ip", "restart_adapter"],
    "nic_errors": ["restart_adapter"], "events_link": ["disable_eee", "restart_adapter"], "pc_unstable": ["disable_eee"],
    "nic_100": ["restart_adapter"], "events_ports": ["reset_stack"], "lan_loss": ["restart_adapter"],
}
