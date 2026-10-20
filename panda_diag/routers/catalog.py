"""What the settings screen asks for each router family, plus where to find the credentials."""

# field: (label, kind, default, hint)
F_USER = ("username", "Логин", "text")
F_PASS = ("password", "Пароль", "password")

CATALOG = {
    "xiaomi": {
        "name": "Xiaomi / Redmi", "needs_password": True, "fields": [F_PASS], "defaults": {"username": "admin"},
        "help": "Пароль администратора — тот, что вы задали при первой настройке роутера (часто совпадает с паролем Wi-Fi). "
                "Им же входите на 192.168.31.1 или в приложение Mi Wi-Fi.",
        "gives": "статус WAN и код ошибки PPPoE, скорость портов, нагрузка по устройствам, каналы Wi-Fi и соседние сети, CPU, память, температура",
    },
    "mikrotik": {
        "name": "MikroTik", "needs_password": True, "fields": [F_USER, F_PASS], "defaults": {"username": "admin"},
        "advanced": [("transport", "Способ подключения", "select", ["auto", "rest-https", "rest-http", "api", "api-ssl"]),
                     ("wan_interface", "WAN-порт", "text")],
        "help": "Логин и пароль из Winbox/WebFig. Безопаснее создать отдельного пользователя только на чтение — "
                "готовый скрипт ниже (вставьте в New Terminal).",
        "gives": "линк и ошибки WAN-порта, падения линка, PPPoE/DHCP, оптика SFP, журнал, устройства и их трафик, Wi-Fi",
    },
    "keenetic": {
        "name": "Keenetic", "needs_password": True, "fields": [F_USER, F_PASS], "defaults": {"username": "admin"},
        "help": "Логин и пароль, которыми вы входите на my.keenetic.net (по умолчанию логин admin).",
        "gives": "статус подключения к провайдеру, порты, устройства и их трафик, журнал, Wi-Fi и соседние сети",
    },
    "asus": {
        "name": "ASUS", "needs_password": True, "fields": [F_USER, F_PASS], "defaults": {"username": "admin"},
        "help": "Логин и пароль от router.asus.com / 192.168.50.1 (по умолчанию логин admin). "
                "ASUS блокирует вход на несколько минут после нескольких ошибок.",
        "gives": "причина отключения WAN (кабель, PPPoE, DHCP), CPU, память, клиенты, журнал, каналы Wi-Fi",
    },
    "openwrt": {
        "name": "OpenWrt", "needs_password": True, "fields": [F_USER, F_PASS], "defaults": {"username": "root"},
        "help": "Пароль пользователя root из LuCI.",
        "gives": "линк и ошибки WAN, ошибки PPPoE, порты, Wi-Fi клиенты и сигнал, соседние сети, журнал",
    },
    "tplink": {
        "name": "TP-Link", "needs_password": True, "fields": [F_PASS], "defaults": {"username": "admin"},
        "help": "Пароль от веб-интерфейса tplinkwifi.net (локальный пароль, не от TP-Link ID). "
                "Закройте веб-интерфейс в браузере — TP-Link пускает только одного администратора.",
        "gives": "статус WAN, устройства и их скорость, загрузка CPU и памяти",
    },
    "tr064": {
        "name": "Fritz!Box / TR-064", "needs_password": True, "fields": [F_USER, F_PASS], "defaults": {"username": ""},
        "help": "Пользователь и пароль от fritz.box. Включите «Доступ для приложений» (Heimnetz → Netzwerk → Netzwerkeinstellungen).",
        "gives": "качество DSL-линии (SNR, затухание, CRC), статус подключения и ошибки, устройства, журнал",
    },
    "huawei_lte": {
        "name": "Huawei 4G-модем", "needs_password": True, "fields": [F_USER, F_PASS], "defaults": {"username": "admin"},
        "help": "Логин и пароль от 192.168.8.1 (по умолчанию admin и пароль с наклейки).",
        "gives": "уровень сигнала 4G (RSRP, SINR), диапазон, вышка, статус подключения, трафик",
    },
    "upnp": {
        "name": "Роутер с UPnP", "needs_password": False, "fields": [],
        "help": "Пароль не нужен. Если программа не видит роутер — включите UPnP в его настройках.",
        "gives": "статус WAN и последняя ошибка подключения",
    },
    "snmp": {
        "name": "Устройство с SNMP", "needs_password": False, "fields": [("snmp_community", "SNMP community", "password")],
        "advanced": [("wan_interface", "WAN-порт", "text")], "defaults": {"snmp_community": "public"},
        "help": "Community обычно public. Включите SNMP v2c в настройках роутера.",
        "gives": "состояние и скорость портов, ошибки, трафик, температура, оптика SFP (MikroTik)",
    },
}

ONT_HELP = ("Оптический терминал (ONT) провайдера — коробочка, куда входит оптический кабель. Обычно 192.168.100.1 (Huawei) "
            "или 192.168.1.1 (ZTE). Логин/пароль на наклейке снизу или у провайдера (часто root/admin, "
            "telecomadmin/admintelecom, admin/admin). Даёт уровень оптического сигнала и состояние линии.")


def mikrotik_script(pc_ip, username="panda", password="ПРИДУМАЙТЕ_ПАРОЛЬ"):
    """RouterOS commands: read-only user + API allowed only from this PC (no certificate needed)."""
    ip = pc_ip or "0.0.0.0/0"
    if "/" not in ip:
        ip += "/32"
    return (f'/user add name={username} group=read password="{password}" comment="Panda Internet Diagnostic"\n'
            f"/ip service set api disabled=no address={ip}\n"
            f':put "Готово. Логин {username}, способ подключения API"')


def describe(kind):
    c = CATALOG.get(kind) or CATALOG["upnp"]
    return {"kind": kind, "name": c["name"], "needs_password": c["needs_password"],
            "fields": [{"key": f[0], "label": f[1], "type": f[2]} for f in c["fields"]],
            "advanced": [{"key": f[0], "label": f[1], "type": f[2], "options": f[3] if len(f) > 3 else None}
                         for f in c.get("advanced", [])],
            "defaults": c.get("defaults", {}), "help": c["help"], "gives": c["gives"]}


def all_kinds():
    return [{"kind": k, "name": v["name"]} for k, v in CATALOG.items()]
