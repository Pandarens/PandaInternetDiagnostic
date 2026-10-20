"""Turns a snapshot into human-readable findings and a single root-cause verdict."""
from .system import human_bps

CRIT, WARN, INFO, OK = "critical", "warning", "info", "ok"
ORDER = {CRIT: 0, WARN: 1, INFO: 2, OK: 3}

# Where in the chain a problem is (used to pick the root cause: the closest broken link wins).
LAYER = {"pc": 1, "wifi": 2, "lan": 2, "router": 3, "wan": 4, "optics": 4, "modem": 4, "isp": 5,
         "internet": 6, "dns": 7, "http": 8, "load": 9, "info": 10}


def _f(level, area, title, detail="", advice=""):
    return {"level": level, "area": area, "title": title, "detail": detail, "advice": advice}


def _c(code, *a, **k):
    """Finding with a stable code (used by the plain-language layer)."""
    d = _f(*a, **k)
    d["code"] = code
    return d


def _p(snap, key):
    return (snap.get("pings") or {}).get(key)


def _alive(st):
    return st is not None and st.get("loss", 100) < 100


def _fmt(st):
    if not st:
        return "—"
    if st.get("avg") is None:
        return f"потери {st['loss']}%"
    return f"потери {st['loss']}%, задержка {st['avg']} мс (мин {st['min']}, макс {st['max']}), джиттер {st['jitter']} мс"


def analyze(snap, cfg=None):
    cfg = cfg or {}
    F = []
    net = snap.get("net") or {}
    pc = net.get("primary") or {}
    wifi = snap.get("wifi")
    router = snap.get("router") or {}
    wan = router.get("wan") or {}
    path = snap.get("path") or {}
    gw = _p(snap, "gateway")
    modem = _p(snap, "modem")
    ont_ping = _p(snap, "ont")
    isp = _p(snap, "isp_hop")
    anchors = {k.split(":", 1)[1]: v for k, v in (snap.get("pings") or {}).items() if k.startswith("anchor:")}
    anchors_up = [a for a, st in anchors.items() if _alive(st)]
    internet_ok = bool(anchors_up)
    is_wifi = bool(pc.get("is_wifi"))

    # ------------------------------------------------------------------ PC adapter
    if not pc or pc.get("status") != "Up":
        st = pc.get("status") if pc else "нет адаптеров"
        if is_wifi or (wifi is not None and not wifi.get("connected")):
            F.append(_c("wifi_disconnected", CRIT, "wifi", "Компьютер не подключён к Wi-Fi",
                        f"Состояние адаптера: {st}", "Подключитесь к сети; если сеть не видна — роутер выключен или завис."))
        else:
            F.append(_c("cable_pc", CRIT, "pc", "Сетевой кабель не подключён / нет линка на сетевой карте",
                        f"Адаптер «{pc.get('name', '?')}»: {st}",
                        "Проверьте кабель ПК↔роутер с обеих сторон, горит ли индикатор порта на роутере; попробуйте другой порт/кабель."))
    else:
        ip = pc.get("ipv4") or ""
        if ip.startswith("169.254") or pc.get("ip_origin") == "WellKnown":
            F.append(_c("dhcp_fail", CRIT, "router", "ПК не получил IP-адрес от роутера (DHCP не работает)",
                        f"Адрес {ip} — автоконфигурация Windows.",
                        "Перезагрузите роутер; проверьте, что DHCP-сервер на роутере включён и пул адресов не исчерпан."))
        if not snap.get("gateway"):
            F.append(_c("no_gateway", CRIT, "pc", "Нет шлюза по умолчанию", "Windows не знает, куда отправлять трафик в интернет.",
                        "Переподключите сеть или выполните «ipconfig /renew»."))
        if not is_wifi:
            _check_ethernet(pc, F)

    # ------------------------------------------------------------------ Wi-Fi client
    if wifi and wifi.get("connected"):
        dbm = wifi.get("rssi_dbm")
        if dbm is not None and dbm < -75:
            F.append(_c("wifi_weak", WARN, "wifi", f"Очень слабый сигнал Wi-Fi: {dbm} дБм ({wifi.get('signal_pct')}%)",
                        f"Сеть {wifi.get('ssid')}, канал {wifi.get('channel')}.",
                        "Подойдите ближе к роутеру, переставьте роутер, используйте mesh/повторитель или кабель."))
        elif dbm is not None and dbm < -67:
            F.append(_c("wifi_medium", INFO, "wifi", f"Средний сигнал Wi-Fi: {dbm} дБм", f"Сеть {wifi.get('ssid')}, канал {wifi.get('channel')}.",
                        "При ухудшении возможны просадки скорости и пинга."))
        rx = wifi.get("rx_mbps")
        if rx is not None and rx < 50:
            F.append(_c("wifi_slow", WARN, "wifi", f"Низкая канальная скорость Wi-Fi: {rx:g} Мбит/с",
                        f"Тип: {wifi.get('radio')}.", "Сигнал слабый или сильные помехи на канале — см. рекомендации по каналам."))

    # ------------------------------------------------------------------ router reachability
    gw_tcp = snap.get("gateway_tcp") or {}
    gw_tcp_ok = any(v.get("ok") for v in gw_tcp.values())
    if snap.get("gateway") and gw is not None:
        if not _alive(gw):
            # ARP cache keeps a hung router's MAC for minutes, so only real answers prove it is alive
            if gw_tcp_ok or internet_ok:
                F.append(_c("router_noping", INFO, "router", "Роутер не отвечает на ping, но доступен",
                            "Похоже, ICMP запрещён на роутере. Остальные проверки продолжаются." ))
            elif not is_wifi and pc.get("status") == "Up":
                # the cable link is up (router's switch chip has power) but the router's CPU answers nothing
                F.append(_c("router_hung", CRIT, "router", "Роутер завис",
                            f"Кабель к роутеру подключён (линк {human_bps(pc.get('link_bps'))}), но роутер {snap['gateway']} "
                            "не отвечает ни на ping, ни на веб-интерфейс, ни на ARP.",
                            "Выключите роутер из розетки на 30 секунд и включите. Если зависает регулярно — неисправен блок питания, "
                            "перегрев или прошивка."))
            else:
                F.append(_c("router_dead", CRIT, "router", "Роутер не отвечает",
                            f"Шлюз {snap['gateway']}: {_fmt(gw)}; веб-интерфейс тоже недоступен.",
                            "Роутер завис или выключен. Проверьте питание и индикаторы, перезагрузите его."))
        else:
            lan_word = "Wi-Fi" if is_wifi else "локальной сети (кабель/порт)"
            if gw["loss"] >= 2:
                F.append(_c("lan_loss", WARN, "wifi" if is_wifi else "lan", f"Потери пакетов до роутера: {gw['loss']}%",
                            _fmt(gw), f"Проблема внутри дома: {lan_word}. "
                            + ("Помехи/слабый сигнал — смените канал, подойдите ближе." if is_wifi else "Замените кабель, проверьте порт.")))
            lim = 15 if is_wifi else 3
            if gw.get("avg") and gw["avg"] > lim or (gw.get("jitter") or 0) > (10 if is_wifi else 3):
                F.append(_c("lan_latency", WARN, "wifi" if is_wifi else "router", f"Высокая/нестабильная задержка до роутера: {gw['avg']} мс",
                            _fmt(gw), "Роутер перегружен (CPU) или Wi-Fi эфир загружен."
                            if is_wifi else "Для кабеля норма < 1–2 мс. Роутер перегружен или неисправен порт/кабель."))

    # ------------------------------------------------------------------ router API data
    _check_router(router, F, cfg, internet_ok)
    ont = snap.get("ont")
    if ont:
        _check_optics(ont.get("optics") or {}, F, "ONT")
        for n in ont.get("notes") or []:
            F.append(_f(INFO, "optics", "ONT", n))

    # ------------------------------------------------------------------ path beyond router
    gw_ok = _alive(gw) or gw_tcp_ok
    if gw_ok and not internet_ok:
        if modem is not None and not _alive(modem):
            F.append(_c("modem_dead", CRIT, "modem", f"Модем/ONT провайдера ({path.get('modem_hop')}) не отвечает",
                        "Ваш роутер работает, но устройство провайдера за ним — нет.",
                        "Проверьте питание ONT/модема, индикаторы (PON должен гореть, LOS — не гореть), кабель между ONT и роутером."))
        elif wan.get("link") is False:
            pass  # already reported by router checks
        elif isp is not None and not _alive(isp):
            detail = f"Роутер отвечает ({_fmt(gw)}), но первый узел провайдера {path.get('isp_hop')} — нет."
            if wan.get("connected") is True:
                F.append(_c("isp_outage_wan_up", CRIT, "isp", "Нет связи с оборудованием провайдера при поднятом WAN",
                            detail + " WAN роутера подключён — обрыв дальше по линии провайдера.",
                            "Авария у провайдера или проблема на линии/OLT. Позвоните в поддержку — укажите время сбоя."))
            else:
                F.append(_c("no_internet_into_router", CRIT, "wan", "Интернет не поступает в роутер",
                            detail + (f" Статус WAN: {wan.get('status_text') or wan.get('error_text') or 'нет данных'}." if wan else ""),
                            "Проверьте ONT/модем: индикатор LOS (красный) = обрыв/загрязнение оптики, нет PON = нет регистрации у провайдера. "
                            "Если индикаторы в норме — звоните провайдеру."))
        elif isp is not None and _alive(isp):
            F.append(_c("isp_core", CRIT, "isp", "Сеть провайдера не пропускает в интернет",
                        f"Узел провайдера {path.get('isp_hop')} отвечает ({_fmt(isp)}), но внешние серверы — нет.",
                        "Авария на магистрали провайдера или блокировка (например, за неуплату — проверьте личный кабинет)."))
        else:
            F.append(_c("no_internet_generic", CRIT, "wan", "Нет доступа в интернет за роутером",
                        "Роутер доступен, внешние адреса не отвечают.",
                        "Проверьте статус WAN в роутере, кабель/ONT, баланс у провайдера."))
    elif internet_ok:
        down = [a for a in anchors if a not in anchors_up]
        if down:
            F.append(_c("partial_internet", WARN, "internet", "Часть внешних серверов недоступна", ", ".join(down),
                        "Возможна частичная авария маршрутизации у провайдера."))
        _check_quality(snap, F, is_wifi)

    # ------------------------------------------------------------------ DNS / HTTP
    dns = snap.get("dns") or {}
    sys_dns = dns.get("system") or []
    pub_dns = dns.get("public") or []
    if internet_ok:
        if sys_dns and not any(d["ok"] for d in sys_dns):
            if any(d["ok"] for d in pub_dns) and any(d["server"] == snap.get("gateway") for d in sys_dns):
                F.append(_c("router_dns_broken", CRIT, "router", "Сломался DNS-сервер внутри роутера",
                            f"Компьютер получает DNS от роутера ({snap.get('gateway')}), а он не отвечает. Интернет при этом есть.",
                            "Перезагрузите роутер. Если повторяется — пропишите в роутере DNS 1.1.1.1 и 8.8.8.8 или обновите прошивку."))
            elif any(d["ok"] for d in pub_dns):
                F.append(_c("dns_dead", CRIT, "dns", "DNS-сервер не отвечает — сайты не открываются, хотя интернет есть",
                            "Серверы: " + ", ".join(f"{d['server']} ({d['rcode']})" for d in sys_dns),
                            "Пропишите DNS 1.1.1.1 и 8.8.8.8 в настройках роутера (или адаптера)."))
            else:
                F.append(_c("dns_blocked", CRIT, "dns", "Все DNS-запросы блокируются", "Ни один DNS-сервер не ответил по UDP/53.",
                            "Проверьте фаервол/антивирус/VPN на ПК; возможна блокировка у провайдера."))
        else:
            if sys_dns and not sys_dns[0]["ok"]:
                F.append(_c("dns_primary_dead", WARN, "dns", f"Основной DNS-сервер {sys_dns[0]['server']} не отвечает",
                            "Windows сначала ждёт ответа от него (~1 с) и только потом спрашивает следующий — сайты открываются с задержкой, "
                            "иногда «не открываются с первого раза».",
                            "Уберите неработающий сервер из настроек DNS (адаптер/DHCP на роутере) или почините его."))
            slow = [d for d in sys_dns if d["ok"] and d["ms"] and d["ms"] > 150]
            if slow:
                F.append(_c("dns_slow", WARN, "dns", "Медленный DNS", ", ".join(f"{d['server']}: {d['ms']} мс" for d in slow),
                            "Сайты открываются с задержкой. Используйте 1.1.1.1 / 8.8.8.8."))
        http = snap.get("http") or {}
        if http and not http.get("ok") and any(d["ok"] for d in sys_dns + pub_dns):
            F.append(_c("http_fail", WARN, "http", "HTTP-проверка не прошла", http.get("note") or http.get("error") or "",
                        "Возможна авторизация в сети (captive portal), прокси или блокировка фаерволом."))

    # ------------------------------------------------------------------ path info
    if path.get("double_nat"):
        F.append(_c("double_nat", INFO, "info", "Двойной NAT", f"За вашим роутером ещё один роутер/модем ({path.get('modem_hop')}).",
                    "Лишний NAT добавляет задержку и мешает играм/пробросу портов. Переведите модем провайдера в режим моста (bridge)."))
    if path.get("cgnat"):
        F.append(_c("cgnat", INFO, "info", "CGNAT у провайдера (адрес 100.64.x.x)", "У вас нет «белого» IP.",
                    "Проброс портов и доступ извне невозможны; при необходимости закажите у провайдера белый IP."))

    _check_events(snap.get("events") or [], F)
    _check_load(snap, F, cfg)
    _check_speedtest(snap, F)

    if not [f for f in F if f["level"] in (CRIT, WARN)]:
        F.append(_c("all_ok", OK, "internet", "Проблем не обнаружено",
                    "Вся цепочка ПК → роутер → провайдер → интернет работает." if internet_ok else ""))
    F.sort(key=lambda f: (ORDER[f["level"]], LAYER.get(f["area"], 99)))
    verdict = F[0]
    return {"verdict": verdict, "findings": F, "internet_ok": internet_ok}


def _check_ethernet(pc, F):
    bps = pc.get("link_bps") or 0
    desc = f"{pc.get('description', '')} {pc.get('driver', '')}".lower()
    gig_nic = any(w in desc for w in ("gbe", "gigabit", "2.5g", "2.5 g", "5g", "10g", "i211", "i219", "i225", "i226", "rtl8125", "killer e2", "1000"))
    setting = (pc.get("speed_duplex_setting") or "").lower()
    manual = bool(setting) and not any(w in setting for w in ("auto", "авто"))
    if bps and bps <= 100_000_000 and (gig_nic or bps < 100_000_000):
        F.append(_c("nic_100", WARN, "lan", f"Сетевая карта работает на {human_bps(bps)} вместо 1 Гбит/с",
                    f"Адаптер {pc.get('description')}. Настройка скорости: {pc.get('speed_duplex_setting') or 'нет данных'}.",
                    ("Скорость выставлена вручную — поставьте «Автосогласование». " if manual else "")
                    + "Причины: кабель с 2 парами (4 жилы) или повреждён/плохо обжат, кабель категории ниже 5e, неисправный порт роутера, "
                    "100-мегабитный порт/свитч на пути. Гигабиту нужны все 8 жил."))
    if pc.get("full_duplex") is False:
        F.append(_c("nic_half", WARN, "lan", "Полудуплексный режим на сетевой карте", "Это вызывает коллизии и потери.",
                    "Поставьте «Автосогласование» и проверьте кабель."))
    errs = (pc.get("rx_errors") or 0) + (pc.get("tx_errors") or 0)
    if errs > 50:
        F.append(_c("nic_errors", WARN, "lan", f"Ошибки на сетевой карте: приём {pc.get('rx_errors')}, передача {pc.get('tx_errors')}",
                    "Счётчик с момента включения ПК.", "Битые пакеты = проблема кабеля/разъёма/порта. Замените патч-корд."))
    ps = [x for x in pc.get("power_saving") or [] if any(w in x.lower() for w in ("enabled", "вкл", "=on", "on"))]
    if ps:
        F.append(_c("nic_eee", INFO, "lan", "Включено энергосбережение сетевой карты", "; ".join(ps),
                    "Energy-Efficient Ethernet / Green Ethernet на некоторых картах Realtek вызывает кратковременные разрывы линка. "
                    "Если есть обрывы — отключите в свойствах адаптера."))


def _check_router(r, F, cfg, internet_ok):
    if not r:
        return
    wan = r.get("wan") or {}
    name = f"{r.get('model') or r.get('type')}"
    for n in r.get("notes") or []:
        F.append(_f(INFO, "router", f"Роутер ({r.get('type')})", n))
    if wan.get("link") is False:
        F.append(_c("wan_nolink", CRIT, "wan", "Нет линка на WAN-порту роутера",
                    f"{name}: кабель от провайдера/ONT не определяется роутером ({wan.get('phy_status') or 'link down'}).",
                    "Проверьте кабель между ONT/модемом и WAN-портом роутера, питание ONT. Попробуйте другой кабель."))
    elif wan.get("connected") is False:
        err = wan.get("error_text")
        F.append(_c("wan_disconnected", CRIT, "wan", "Роутер не подключён к провайдеру" + (f": {err}" if err else ""),
                    f"{name}: протокол {wan.get('proto') or '?'}, статус {wan.get('status_text') or wan.get('pppoe_status') or wan.get('dhcp_status') or '—'}"
                    + (f", код {wan.get('error_code')}" if wan.get("error_code") else ""),
                    "Если ошибка авторизации — проверьте логин/пароль PPPoE и баланс. Если провайдер не отвечает — проблема на линии/оптике."))
    elif wan.get("error_text") and not internet_ok:
        F.append(_c("wan_last_error", WARN, "wan", f"Последняя ошибка WAN: {wan['error_text']}", f"Код: {wan.get('error_code')}"))

    sp = wan.get("link_speed_mbps")
    if sp and sp <= 100 and wan.get("link") is not False:
        F.append(_c("wan_100", WARN, "wan", f"WAN-порт роутера работает на {sp} Мбит/с",
                    f"{name}: линк с ONT/провайдером согласован только на {sp} Мбит/с — тариф выше {sp} Мбит/с получить невозможно.",
                    "Замените кабель ONT↔роутер на исправный Cat5e/Cat6 (все 8 жил), проверьте, что порт ONT гигабитный (LAN1 обычно GE), "
                    "что скорость порта WAN не зафиксирована вручную."))
    if wan.get("full_duplex") is False:
        F.append(_c("wan_half", WARN, "wan", "WAN-порт в полудуплексе", name, "Проверьте кабель и настройки скорости порта."))
    for p in r.get("ports") or []:
        if p.get("wan") or not p.get("link"):
            continue
        if p.get("speed_mbps") and p["speed_mbps"] <= 100 and (r.get("type") not in ("snmp",) or "ether" in str(p.get("name")).lower()):
            F.append(_c("lanport_100", INFO, "lan", f"Порт {p.get('name')} роутера работает на {p['speed_mbps']} Мбит/с",
                        "Устройство на этом порту подключено не на гигабите.", "Проверьте кабель к этому устройству."))
    fcs = (wan.get("fcs_errors") or 0) + (wan.get("align_errors") or 0)
    if fcs > 0 or (wan.get("rx_errors") or 0) > 100:
        F.append(_c("wan_crc", WARN, "wan", "Ошибки на кабеле WAN",
                    f"CRC/FCS: {fcs}, rx-errors: {wan.get('rx_errors')}, tx-errors: {wan.get('tx_errors')}",
                    "Повреждён кабель или разъём между роутером и ONT/провайдером — замените патч-корд."))
    if (wan.get("link_downs") or 0) > 2:
        F.append(_c("wan_flaps", WARN, "wan", f"WAN-линк падал {wan['link_downs']} раз с момента загрузки роутера",
                    f"Последнее падение: {wan.get('last_link_down') or '—'}",
                    "Физические обрывы: ONT перезагружается (питание, перегрев) или плохой контакт кабеля."))
    if r.get("cpu_load") is not None and r["cpu_load"] > 85:
        F.append(_c("router_cpu", WARN, "router", f"Процессор роутера загружен на {r['cpu_load']}%", name,
                    "Роутер не справляется: много торрентов/устройств, VPN на роутере. Это даёт пинг и обрывы."))
    if r.get("mem_pct") is not None and r["mem_pct"] > 92:
        F.append(_c("router_mem", WARN, "router", f"Память роутера заполнена на {r['mem_pct']}%", name, "Перезагрузите роутер; обновите прошивку."))
    if r.get("temperature") and r["temperature"] > 85:
        F.append(_c("router_hot", WARN, "router", f"Перегрев роутера: {r['temperature']} °C", name, "Обеспечьте вентиляцию, уберите с тёплых поверхностей."))
    if r.get("uptime_sec") is not None and r["uptime_sec"] < 900:
        F.append(_c("router_rebooted", INFO, "router", "Роутер недавно перезагрузился", f"Аптайм {r['uptime_sec'] // 60} мин.",
                    "Если вы его не перезагружали — возможны скачки питания или зависания (перегрев, сбой прошивки)."))
    if wan.get("uptime_sec") is not None and wan.get("connected") and wan["uptime_sec"] < 900:
        F.append(_c("wan_reconnected", INFO, "wan", "Подключение к провайдеру переустановлено недавно", f"WAN аптайм {wan['uptime_sec'] // 60} мин."))
    _check_optics(r.get("optics") or {}, F, f"SFP {name}")
    dsl = r.get("dsl")
    if dsl:
        if dsl.get("status") != "Up":
            F.append(_c("dsl_down", CRIT, "wan", f"DSL: {dsl.get('status_text')}", "Линия не синхронизирована.",
                        "Проверьте телефонный кабель, сплиттер, параллельные телефоны. Если не помогает — повреждение линии, звоните провайдеру."))
        elif dsl.get("snr_down_db", 99) < 6:
            F.append(_c("dsl_snr", WARN, "wan", f"DSL: низкий запас по шуму (SNR {dsl['snr_down_db']} дБ)",
                        f"Затухание {dsl.get('atten_down_db')} дБ, CRC {dsl.get('crc_errors')}",
                        "При SNR < 6 дБ линия рвётся. Уберите скрутки/параллельные аппараты, попросите провайдера снизить профиль."))
    cell = r.get("cellular")
    if cell:
        rsrp, sinr = cell.get("rsrp"), cell.get("sinr")
        if rsrp is not None and rsrp < -105 or sinr is not None and sinr < 0:
            F.append(_c("lte_weak", WARN, "wan", f"Слабый сигнал 4G: RSRP {rsrp} дБм, SINR {sinr} дБ",
                        f"Band {cell.get('band')}, сота {cell.get('cell_id')}",
                        "Переставьте модем к окну/выше, используйте внешнюю антенну, направленную на вышку."))
    errs = [l for l in r.get("log") or [] if any(w in l.lower() for w in ("fail", "error", "timeout", "terminat", "down", "lost", "ошиб"))]
    if errs:
        F.append(_f(INFO, "router", f"Журнал роутера: {len(errs)} событий связи", "\n".join(errs[-8:])))


def _check_optics(o, F, where):
    if not o:
        return
    rx, tx = o.get("rx_dbm"), o.get("tx_dbm")
    if o.get("rx_loss") or (rx is not None and rx < -30):
        F.append(_c("optics_los", CRIT, "optics", f"{where}: нет оптического сигнала (LOS)", f"RX = {rx} дБм",
                    "Обрыв оптоволокна, выдернут/повреждён оптический патч-корд, или авария на дереве PON у провайдера. Звоните провайдеру."))
    elif rx is not None and rx < -27:
        F.append(_c("optics_weak", CRIT, "optics", f"{where}: слишком слабый оптический сигнал {rx} дБм",
                    "Норма GPON: от −8 до −27 дБм (оптимально −15…−24).",
                    "Загрязнён разъём, перегиб/излом кабеля, плохая сварка. Требуется выезд монтажника провайдера."))
    elif rx is not None and rx < -25:
        F.append(_c("optics_marginal", WARN, "optics", f"{where}: оптический сигнал на грани {rx} дБм",
                    "Близко к границе −27 дБм — возможны обрывы при перепадах температуры.",
                    "Проверьте, нет ли перегибов кабеля; попросите провайдера проверить линию."))
    elif rx is not None and rx > -8:
        F.append(_c("optics_overload", WARN, "optics", f"{where}: перегрузка приёмника {rx} дБм", "Сигнал сильнее нормы.", "Провайдеру нужно установить аттенюатор."))
    elif rx is not None:
        F.append(_c("optics_ok", OK, "optics", f"{where}: оптика в норме, RX {rx} дБм" + (f", TX {tx} дБм" if tx is not None else "")))
    if o.get("tx_fault"):
        F.append(_c("optics_txfault", CRIT, "optics", f"{where}: неисправность передатчика (TX fault)", "", "Замените SFP-модуль/ONT."))
    if o.get("temp_c") and o["temp_c"] > 75:
        F.append(_c("optics_hot", WARN, "optics", f"{where}: перегрев оптического модуля {o['temp_c']} °C", "", "Улучшите охлаждение."))
    if o.get("pon_state") and str(o["pon_state"]).upper() not in ("O5", "UP", "OPERATION", "5"):
        F.append(_c("pon_state", WARN, "optics", f"{where}: состояние PON {o['pon_state']}", "O5 = рабочее, O1–O4 = регистрация не завершена, O7 = авария.",
                    "Если состояние не O5 — ONT не зарегистрирован на OLT провайдера."))


def _check_quality(snap, F, is_wifi):
    gw = _p(snap, "gateway")
    isp = _p(snap, "isp_hop")
    anchors = [v for k, v in (snap.get("pings") or {}).items() if k.startswith("anchor:") and _alive(v)]
    if not anchors:
        return
    worst_loss = max(a["loss"] for a in anchors)
    best_avg = min(a["avg"] for a in anchors if a["avg"] is not None)
    gw_loss = gw["loss"] if gw else 0
    if worst_loss >= 2 and worst_loss > gw_loss + 1:
        if isp and _alive(isp) and isp["loss"] >= 2:
            F.append(_c("isp_loss", WARN, "isp", f"Потери пакетов начинаются на линии провайдера ({isp['loss']}%)",
                        f"До роутера: {gw_loss}%; до узла провайдера {isp.get('ip')}: {isp['loss']}%; до интернета: {worst_loss}%.",
                        "Проблема на участке роутер→провайдер: оптика/кабель/ONT или перегрузка у провайдера. Если потери постоянные — заявка провайдеру."))
        else:
            F.append(_c("net_loss", WARN, "internet", f"Потери пакетов в интернет {worst_loss}%",
                        f"До роутера {gw_loss}%, до провайдера {isp['loss'] if isp else '—'}% — потери дальше, в сети провайдера/магистрали."))
    if gw and gw.get("avg") is not None and isp and isp.get("avg") is not None:
        hop = isp["avg"] - gw["avg"]
        if hop > 25 and isp["loss"] < 50:
            F.append(_c("isp_latency", WARN, "isp", f"Высокая задержка до первого узла провайдера: {isp['avg']} мс",
                        f"Роутер {gw['avg']} мс → провайдер {isp['avg']} мс.",
                        "Канал загружен (кто-то качает — см. «Нагрузка») или проблема на линии. Норма для оптики < 5 мс."))
    if best_avg > 120:
        F.append(_c("high_ping", WARN, "internet", f"Высокий пинг в интернет: {best_avg} мс",
                    "До ближайших публичных серверов.", "Проверьте загрузку канала; при постоянной проблеме — провайдер."))
    jit = max((a.get("jitter") or 0) for a in anchors)
    if jit > 30:
        F.append(_c("jitter", WARN, "internet", f"Нестабильный пинг (джиттер {jit} мс)", "Будут лаги в играх и звонках.",
                    "Чаще всего — загрузка канала (bufferbloat) или Wi-Fi помехи. Включите SQM/QoS на роутере."))


def _check_events(events, F):
    if not events:
        return
    groups = {}
    for e in events:
        src, eid = e.get("source") or "", e.get("id")
        if eid == 8003 or "WLAN" in src and eid in (8003, 11004, 11005, 11006, 12013):
            k = "wlan"
        elif "Tcpip" in src and eid in (4227, 4231, 4266):
            k = "ports"
        elif eid == 1014 or "DNS" in src:
            k = "dns"
        elif "Dhcp" in src:
            k = "dhcp"
        elif eid in (27, 4201, 4202) or "NCSI" not in src and any(w in src.lower() for w in ("e1", "rt6", "realtek", "intel", "ndis", "netadapter", "igc", "killer")):
            k = "link"
        elif "NCSI" in src:
            k = "ncsi"
        else:
            k = "other"
        groups.setdefault(k, []).append(e)
    titles = {"wlan": "Отключения Wi-Fi", "dns": "Таймауты DNS", "dhcp": "Ошибки DHCP", "link": "Разрывы линка сетевой карты",
              "ncsi": "Windows фиксировала потерю интернета", "other": "Прочие сетевые события",
              "ports": "Исчерпание TCP/UDP-портов Windows"}
    hints = {"link": "Частые разрывы линка: кабель/порт/энергосбережение сетевой карты.",
             "ports": "Какая-то программа открывает тысячи соединений (торрент, майнер, зависший софт, вирус) — "
                      "новые соединения не создаются и «интернет пропадает» только на этом ПК. "
                      "Найдите виновника: netstat -ano | find /c \"TIME_WAIT\" и Диспетчер задач → Производительность → Ресурсы → Сеть."}
    for k, items in groups.items():
        lvl = WARN if (k in ("link", "wlan") and len(items) >= 2) or k == "ports" else INFO
        F.append(_c(f"events_{k}", lvl, "pc" if k == "link" else ("wifi" if k == "wlan" else "info"),
                    f"Журнал Windows за 24 ч: {titles[k]} — {len(items)}",
                    "\n".join(f"{e['time']} [{e['source']} {e['id']}] {e['message'][:160]}" for e in items[:6]),
                    hints.get(k, "")))


def _check_load(snap, F, cfg):
    r = snap.get("router") or {}
    wan = r.get("wan") or {}
    devs = [d for d in r.get("devices") or [] if (d.get("down_bps") or 0) + (d.get("up_bps") or 0) > 0]
    tariff = (cfg or {}).get("tariff_mbps")
    down = wan.get("down_bps")
    if down and tariff and down > tariff * 1e6 * 0.8:
        top = sorted(devs, key=lambda d: -(d.get("down_bps") or 0))[:3]
        F.append(_c("saturated", WARN, "load", f"Канал загружен: {human_bps(down)} из {tariff} Мбит/с",
                    "Больше всего качают: " + ", ".join(f"{d.get('name') or d.get('ip') or d.get('mac')} ({human_bps(d.get('down_bps'))})" for d in top),
                    "Полная загрузка канала вызывает рост пинга. Ограничьте скорость для этих устройств или включите QoS/SQM."))


def _check_loaded_latency(snap, st, pc, F):
    """Router stress test: latency to the router and to the provider while the channel is fully loaded."""
    loaded = st.get("loaded") or {}
    idle_gw, idle_isp = _p(snap, "gateway"), _p(snap, "isp_hop")
    lg, li = loaded.get("gateway"), loaded.get("isp_hop")
    is_wifi = bool(pc.get("is_wifi"))
    if lg and lg.get("sent") and idle_gw and idle_gw.get("avg") is not None:
        rise = (lg["avg"] if lg.get("avg") is not None else 1000) - idle_gw["avg"]
        if lg["loss"] >= 10 or rise > (40 if is_wifi else 15):
            F.append(_c("router_weak_load", WARN, "wifi" if is_wifi else "router",
                        "Под нагрузкой Wi-Fi захлёбывается" if is_wifi else "Роутер не справляется с нагрузкой",
                        f"Пинг до роутера в покое {idle_gw['avg']} мс, во время скачивания {lg.get('avg')} мс, потери {lg['loss']}%.",
                        "Wi-Fi эфир забит — подключитесь к 5 ГГц или кабелем." if is_wifi else
                        "Процессор роутера не тянет вашу скорость: при загрузке он тормозит и может зависать. "
                        "Обновите прошивку или замените роутер на более мощный."))
            return
    if li and li.get("sent") and idle_isp and idle_isp.get("avg") is not None:
        rise = (li["avg"] if li.get("avg") is not None else 1000) - idle_isp["avg"]
        if rise > 60 or li["loss"] >= 10:
            F.append(_c("bufferbloat", WARN, "load", "Пинг сильно растёт, когда кто-то качает (bufferbloat)",
                        f"До провайдера в покое {idle_isp['avg']} мс, при загрузке {li.get('avg')} мс, потери {li['loss']}%.",
                        "Во время загрузок будут лаги в играх и звонках. Включите в роутере SQM / Smart QoS / «Адаптивный QoS» "
                        "и ограничьте скорость на ~90% от тарифа."))
            return
    if lg and lg.get("avg") is not None:
        F.append(_c("router_load_ok", OK, "router", "Роутер выдерживает полную нагрузку",
                    f"Пинг до роутера при скачивании: {lg['avg']} мс" + (f", до провайдера: {li['avg']} мс" if li and li.get("avg") is not None else "")))


def _check_speedtest(snap, F):
    st = snap.get("speedtest")
    if not st:
        return
    mbps = st.get("mbps") or 0
    if not st.get("bytes"):
        F.append(_c("speed_fail", INFO, "load", "Тест скорости не выполнен", "; ".join(st.get("errors") or []) or "нет данных",
                    "Сервер теста недоступен — повторите позже."))
        return
    pc = (snap.get("net") or {}).get("primary") or {}
    _check_loaded_latency(snap, st, pc, F)
    wan_sp = ((snap.get("router") or {}).get("wan") or {}).get("link_speed_mbps")
    if 85 <= mbps <= 97:
        where = []
        if (pc.get("link_bps") or 0) <= 100_000_000 and not pc.get("is_wifi"):
            where.append("сетевая карта ПК на 100 Мбит/с")
        if wan_sp and wan_sp <= 100:
            where.append("WAN-порт роутера на 100 Мбит/с")
        F.append(_c("speed_100cap", WARN, "lan", f"Скорость упирается в ~100 Мбит/с ({mbps} Мбит/с)",
                    "Характерный «потолок» 100-мегабитного линка. " + ("Найдено: " + ", ".join(where) if where else
                                                                       "Ищите 100-мегабитный участок: кабель, порт ONT, свитч, или тариф 100 Мбит/с."),
                    "Замените кабели на Cat5e/Cat6 с 8 жилами, проверьте скорость портов."))
    else:
        F.append(_c("speed_info", INFO, "load", f"Скорость загрузки: {mbps} Мбит/с", f"Тест {st.get('seconds')} с, {st.get('bytes', 0) // 1_000_000} МБ."))
