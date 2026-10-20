"""Plain-language layer: turns technical findings into a short answer anyone can follow."""
import time

# where: which part of the picture to highlight (computer, link, router, line, provider, sites, speed)
# call: should the user call the provider
PLAIN = {
    "cable_pc": ("link", "Кабель от компьютера не подключён",
                 "Компьютер не видит сетевой кабель — связи с роутером нет.",
                 ["Проверьте, что кабель плотно вставлен в компьютер и в роутер (должен щёлкнуть).",
                  "Посмотрите на роутер: возле этого гнезда должен гореть или мигать огонёк.",
                  "Вставьте кабель в другое гнездо роутера (они обычно жёлтые, с цифрами 1–4).",
                  "Если не помогло — замените кабель."], False),
    "wifi_disconnected": ("link", "Компьютер не подключён к Wi-Fi",
                          "Компьютер сейчас не соединён с вашей Wi-Fi сетью.",
                          ["Нажмите на значок сети в правом нижнем углу экрана и выберите свою сеть.",
                           "Если вашей сети нет в списке — проверьте, включён ли роутер (горят ли огоньки).",
                           "Выключите роутер из розетки на 30 секунд и включите снова, подождите 2 минуты."], False),
    "dhcp_fail": ("router", "Роутер не выдал компьютеру адрес",
                  "Компьютер подключён к роутеру, но роутер его «не пускает» в сеть.",
                  ["Выключите роутер из розетки на 30 секунд и включите снова.",
                   "Подождите 2–3 минуты и нажмите «Проверить ещё раз»."], False),
    "no_gateway": ("computer", "Компьютер не знает дорогу в интернет",
                   "Настройки сети на компьютере сбились.",
                   ["Отключите и снова подключите Wi-Fi или сетевой кабель.",
                    "Перезагрузите компьютер."], False),
    "router_dead": ("router", "Роутер не отвечает",
                    "Роутер завис или выключен — без него интернета не будет.",
                    ["Проверьте, что роутер включён в розетку и на нём горят огоньки.",
                     "Выключите роутер из розетки, подождите 30 секунд, включите снова.",
                     "Подождите 2–3 минуты, пока он загрузится, и проверьте ещё раз."], False),
    "router_hung": ("router", "Роутер завис",
                    "Кабель к роутеру подключён, но сам роутер ничего не отвечает — он «повис».",
                    ["Выключите роутер из розетки, подождите 30 секунд, включите снова.",
                     "Подождите 2–3 минуты и нажмите «Проверить ещё раз».",
                     "Если роутер зависает часто — проверьте блок питания (греется, гудит, «не родной») и не перегревается ли сам роутер. "
                     "Если не помогает — роутер неисправен, его пора менять."], False),
    "router_dns_broken": ("router", "Роутер не помогает открывать сайты",
                          "Интернет есть, но встроенная в роутер «адресная книга» сайтов (DNS) сломалась.",
                          ["Перезагрузите роутер (выключить из розетки на 30 секунд).",
                           "Если повторяется — в настройках роутера укажите DNS 1.1.1.1 и 8.8.8.8 или обновите его прошивку."], False),
    "router_weak_load": ("router", "Роутер не справляется, когда качаете",
                         "Пока ничего не качается — всё нормально, но при загрузке роутер начинает тормозить. "
                         "Отсюда лаги, обрывы видео и зависания при скачивании.",
                         ["Обновите прошивку роутера.",
                          "Если роутер старый или дешёвый, а тариф быстрый — роутер не тянет скорость, его стоит заменить."], False),
    "bufferbloat": ("speed", "Когда кто-то качает — всё начинает лагать",
                    "Во время загрузок пинг сильно вырастает: игры и видеозвонки будут тормозить.",
                    ["В настройках роутера включите функцию QoS / Smart QoS / SQM (приоритет трафика).",
                     "Поставьте торренты и большие загрузки на ночь."], False),
    "modem_dead": ("line", "Не отвечает модем (терминал) провайдера",
                   "Ваш роутер работает, но коробочка провайдера, к которой он подключён, не отвечает.",
                   ["Найдите устройство провайдера (модем/оптический терминал — обычно белая коробочка, куда приходит провод из подъезда).",
                    "Проверьте, что оно включено в розетку и горят огоньки.",
                    "Выключите его из розетки на 30 секунд и включите снова, подождите 3 минуты.",
                    "Если горит красный огонёк LOS или ALARM — звоните провайдеру."], True),
    "wan_nolink": ("line", "В роутер не приходит провод от провайдера",
                   "Роутер не видит кабель, по которому приходит интернет.",
                   ["Найдите на роутере гнездо WAN или INTERNET (обычно синее или другого цвета).",
                    "Проверьте, что кабель в нём сидит плотно; выньте и вставьте до щелчка.",
                    "Если у вас оптика — проверьте, что терминал провайдера включён и кабель от него идёт в это гнездо.",
                    "Перезагрузите терминал провайдера и роутер (выключить на 30 секунд)."], True),
    "wan_disconnected": ("provider", "Роутер не может подключиться к провайдеру",
                         "Провод есть, но провайдер не пускает роутер в интернет.",
                         ["Проверьте баланс в личном кабинете провайдера (часто причина — не оплачено).",
                          "Перезагрузите роутер.",
                          "Если не помогло — позвоните провайдеру."], True),
    "no_internet_into_router": ("line", "Интернет не приходит от провайдера",
                                "Ваш компьютер и роутер в порядке, но от провайдера в роутер ничего не поступает. "
                                "Скорее всего обрыв на линии, проблема с оптикой или авария у провайдера.",
                                ["Посмотрите на терминал/модем провайдера: если горит красный огонёк LOS — обрыв оптического кабеля.",
                                 "Выключите терминал провайдера и роутер на 30 секунд, включите снова.",
                                 "Проверьте баланс в личном кабинете.",
                                 "Если не помогло — звоните провайдеру, это их зона ответственности."], True),
    "isp_outage_wan_up": ("provider", "Авария у провайдера",
                          "Ваше оборудование работает и подключено, но сеть провайдера не отвечает.",
                          ["Вы ничего не можете исправить сами — проблема у провайдера.",
                           "Позвоните провайдеру или проверьте новости об аварии на его сайте."], True),
    "isp_core": ("provider", "Авария в сети провайдера",
                 "До провайдера связь есть, но дальше в интернет он вас не пускает. Возможна авария или блокировка за неуплату.",
                 ["Проверьте баланс в личном кабинете провайдера.",
                  "Если всё оплачено — звоните провайдеру: у них авария."], True),
    "no_internet_generic": ("provider", "Нет интернета за роутером",
                            "Роутер работает, но интернет через него не идёт.",
                            ["Перезагрузите роутер и устройство провайдера (выключить на 30 секунд).",
                             "Проверьте баланс.", "Если не помогло — звоните провайдеру."], True),
    "dns_dead": ("sites", "Интернет есть, но сайты не открываются",
                 "Сломан «телефонный справочник» интернета (DNS) — компьютер не может найти адреса сайтов.",
                 ["Перезагрузите роутер.",
                  "Если не помогло — в настройках роутера пропишите DNS 1.1.1.1 и 8.8.8.8 (или попросите знакомого/мастера)."], False),
    "dns_blocked": ("sites", "Сайты не открываются: что-то блокирует",
                    "Интернет есть, но поиск адресов сайтов блокируется — часто это антивирус, VPN или фаервол.",
                    ["Отключите VPN, если он включён.", "Временно отключите антивирус и проверьте ещё раз.",
                     "Перезагрузите компьютер."], False),
    "dns_primary_dead": ("sites", "Сайты открываются с задержкой",
                         "Интернет работает, но один из серверов поиска адресов (DNS) не отвечает, и компьютер каждый раз "
                         "ждёт его около секунды. На скорость скачивания это не влияет — только на открытие сайтов.",
                         ["Перезагрузите роутер — иногда этого достаточно.",
                          "Если не помогло — попросите мастера убрать неработающий DNS из настроек сети "
                          "(или указать 1.1.1.1 и 8.8.8.8)."], False),
    "dns_slow": ("sites", "Сайты долго начинают открываться", "Сервер поиска адресов (DNS) отвечает медленно.",
                 ["В настройках роутера можно указать DNS 1.1.1.1 и 8.8.8.8 — они быстрее."], False),
    "http_fail": ("sites", "Сайты подменяются или требуют вход",
                  "Похоже, сеть требует авторизации (как в кафе/гостинице) или работает блокировка.",
                  ["Откройте любой сайт в браузере — возможно, появится страница входа.", "Отключите VPN/прокси."], False),
    "wifi_weak": ("link", "Слабый сигнал Wi-Fi",
                  "Компьютер далеко от роутера или сигналу мешают стены — отсюда обрывы и низкая скорость.",
                  ["Сядьте ближе к роутеру или переставьте роутер повыше и ближе к центру квартиры.",
                   "Уберите роутер из шкафа, от зеркал, аквариумов и микроволновки.",
                   "Для дальних комнат купите усилитель Wi-Fi (mesh-систему) или подключите кабель."], False),
    "wifi_slow": ("link", "Wi-Fi работает медленно", "Связь между компьютером и роутером слабая или с помехами.",
                  ["Подойдите ближе к роутеру.", "Подключитесь к сети с пометкой 5G / 5GHz, если она есть."], False),
    "lan_loss": ("link", "Связь с роутером нестабильна",
                 "Данные теряются уже между компьютером и роутером — проблема внутри дома, а не у провайдера.",
                 ["Если по Wi-Fi — подойдите ближе к роутеру.", "Если по кабелю — замените кабель или гнездо в роутере.",
                  "Перезагрузите роутер."], False),
    "lan_latency": ("router", "Роутер отвечает медленно", "Роутер перегружен или эфир Wi-Fi забит.",
                    ["Перезагрузите роутер.", "Если такое часто — роутер слабый для вашего количества устройств, подумайте о замене."], False),
    "nic_100": ("link", "Кабель работает в 10 раз медленнее, чем может",
                "Подключение между компьютером и роутером работает на 100 Мбит/с вместо 1000. Обычно виноват кабель: "
                "в нём работают не все жилы, он повреждён или плохо обжат.",
                ["Замените сетевой кабель на новый (категория Cat5e или Cat6).",
                 "Попробуйте другое гнездо на роутере.",
                 "Если не помогло — вызовите мастера проверить обжим кабеля."], False),
    "wan_100": ("line", "Кабель от провайдера к роутеру ограничивает скорость до 100 Мбит/с",
                "Роутер соединён с провайдером только на 100 Мбит/с — быстрее этого интернет не будет, даже если тариф больше.",
                ["Замените кабель между устройством провайдера и роутером на новый Cat5e/Cat6.",
                 "Проверьте, что кабель вставлен в гигабитное гнездо терминала провайдера (обычно LAN1 / GE).",
                 "Если не помогло — проблема в порте роутера или терминала, обратитесь к мастеру."], False),
    "nic_errors": ("link", "Кабель к компьютеру повреждён", "Сетевая карта получает испорченные данные.",
                   ["Замените сетевой кабель.", "Попробуйте другое гнездо на роутере."], False),
    "wan_crc": ("line", "Кабель от провайдера к роутеру повреждён", "На кабеле интернета много ошибок.",
                ["Замените короткий кабель между терминалом провайдера и роутером."], False),
    "wan_flaps": ("line", "Кабель от провайдера к роутеру периодически отваливается",
                  "Связь роутера с устройством провайдера несколько раз пропадала физически.",
                  ["Проверьте, плотно ли сидит кабель в обоих гнёздах.",
                   "Проверьте питание терминала провайдера (не перегревается ли, не отходит ли блок питания).",
                   "Замените кабель."], False),
    "router_cpu": ("router", "Роутер не справляется с нагрузкой", "Процессор роутера загружен почти полностью.",
                   ["Перезагрузите роутер.", "Остановите торренты и большие загрузки.",
                    "Если роутер старый — его пора заменить."], False),
    "router_mem": ("router", "Роутер перегружен", "Память роутера заполнена.", ["Перезагрузите роутер."], False),
    "router_hot": ("router", "Роутер перегревается", "Перегрев приводит к зависаниям и обрывам.",
                   ["Поставьте роутер на открытое место, не накрывайте его, уберите от батарей."], False),
    "dsl_down": ("line", "Нет сигнала на телефонной линии", "Модем не видит сигнал провайдера на телефонном проводе.",
                 ["Проверьте провода телефонной линии и сплиттер.", "Звоните провайдеру."], True),
    "dsl_snr": ("line", "Плохое качество телефонной линии", "Из-за помех на линии связь рвётся.",
                ["Уберите лишние телефоны и удлинители с линии.", "Сообщите провайдеру о плохой линии."], True),
    "lte_weak": ("line", "Слабый сигнал мобильной сети (4G)", "Модем плохо ловит сеть оператора.",
                 ["Поставьте модем у окна, повыше.", "Используйте внешнюю антенну."], False),
    "optics_los": ("line", "Нет сигнала в оптическом кабеле",
                   "В устройство провайдера не приходит свет по оптоволокну — кабель оборван, выдернут или повреждён.",
                   ["Проверьте тонкий оптический провод (обычно жёлтый или белый): не выдернут ли он, нет ли перегиба.",
                    "Ничего не разбирайте — звоните провайдеру, нужен монтажник."], True),
    "optics_weak": ("line", "Очень слабый сигнал в оптическом кабеле",
                    "Свет по оптоволокну приходит, но слишком слабый — отсюда обрывы.",
                    ["Проверьте, нет ли перегибов оптического провода, не зажат ли он дверью или мебелью.",
                     "Звоните провайдеру — нужен монтажник для проверки линии."], True),
    "optics_marginal": ("line", "Сигнал в оптическом кабеле на грани",
                        "Оптика работает, но близко к пределу — возможны обрывы.",
                        ["Проверьте, нет ли перегибов оптического провода.", "Сообщите провайдеру при повторных обрывах."], True),
    "optics_txfault": ("line", "Неисправен оптический модуль", "", ["Звоните провайдеру для замены оборудования."], True),
    "pon_state": ("line", "Терминал провайдера не зарегистрирован в сети", "Оптический терминал не может подключиться к станции провайдера.",
                  ["Перезагрузите терминал провайдера.", "Если не помогло — звоните провайдеру."], True),
    "isp_loss": ("line", "Связь с провайдером нестабильна",
                 "Дома всё в порядке, а данные теряются на линии до провайдера.",
                 ["Перезагрузите терминал провайдера и роутер.",
                  "Если повторяется — звоните провайдеру: это проблема их линии."], True),
    "net_loss": ("provider", "Интернет работает с перебоями у провайдера", "Потери данных в сети провайдера.",
                 ["Подождите — возможно, временная перегрузка.", "Если долго — сообщите провайдеру."], True),
    "isp_latency": ("provider", "Высокий пинг до провайдера",
                    "Задержка появляется на участке до провайдера: канал загружен или проблема линии.",
                    ["Проверьте, не качает ли кто-то большие файлы (торренты, обновления, видео в 4K).",
                     "Если никто не качает — сообщите провайдеру."], False),
    "high_ping": ("provider", "Высокий пинг", "Сайты и игры отвечают с большой задержкой.",
                  ["Остановите большие загрузки.", "Если долго — сообщите провайдеру."], False),
    "jitter": ("provider", "Нестабильный пинг", "Будут лаги в играх и видеозвонках.",
               ["Остановите торренты и большие загрузки на других устройствах.", "Подключите компьютер кабелем, если сейчас Wi-Fi."], False),
    "saturated": ("speed", "Интернет полностью загружен", "Кто-то в доме качает и забирает весь канал.",
                  ["Посмотрите вкладку «Нагрузка» в подробностях, чтобы узнать какое устройство.",
                   "Поставьте загрузку на паузу."], False),
    "speed_100cap": ("speed", "Скорость упирается в 100 Мбит/с",
                     "Где-то на пути стоит старый кабель или гнездо, которое не пропускает больше 100 Мбит/с.",
                     ["Замените сетевые кабели на новые Cat5e/Cat6.", "Проверьте, какой у вас тариф: может, он и есть 100 Мбит/с."], False),
    "events_ports": ("computer", "Программа на компьютере «забивает» интернет",
                     "Какая-то программа открывает тысячи соединений — из-за этого интернет иногда пропадает только на этом компьютере.",
                     ["Закройте торрент-клиенты и лишние программы.", "Проверьте компьютер антивирусом.",
                      "Перезагрузите компьютер."], False),
    "events_link": ("link", "Кабель к компьютеру периодически отключается",
                    "Windows фиксировала, что сетевой кабель «отваливался».",
                    ["Замените сетевой кабель.", "Проверьте, плотно ли он сидит в гнёздах."], False),
    "events_wlan": ("link", "Wi-Fi периодически отключается", "Компьютер несколько раз терял связь с Wi-Fi.",
                    ["Подойдите ближе к роутеру.", "Смените канал Wi-Fi (см. подсказки в подробностях)."], False),
}

MINOR_SKIP = {"router_noping", "router_load_ok", "all_ok", "optics_ok", "speed_info", "double_nat", "cgnat", "wifi_medium", "router_rebooted",
              "wan_reconnected", "events_other", "events_ncsi", "events_dns", "events_dhcp", "nic_eee", "lanport_100",
              "wan_last_error", "partial_internet", "speed_fail"}

CHECK_LABELS = [
    ("computer", "Компьютер"),
    ("link", "Связь с роутером"),
    ("router", "Роутер"),
    ("line", "Линия провайдера"),
    ("provider", "Интернет"),
    ("sites", "Сайты открываются"),
    ("speed", "Скорость"),
]


def _speed_text(mbps):
    if mbps is None:
        return None
    if mbps < 5:
        return "очень медленно — тяжело даже смотреть видео"
    if mbps < 25:
        return "хватит на сайты и видео в обычном качестве"
    if mbps < 100:
        return "хватит на Full HD видео и видеозвонки"
    if mbps < 300:
        return "хорошая скорость — 4K видео, игры, несколько устройств"
    return "отличная скорость"


def _alive(st):
    return st is not None and st.get("loss", 100) < 100


def checks_from(snap, res):
    """Traffic-light status of each link in the chain."""
    by_where = {}
    for f in res["findings"]:
        if f.get("code") in MINOR_SKIP or f["level"] not in ("critical", "warning"):
            continue
        p = PLAIN.get(f.get("code"))
        where = p[0] if p else {"pc": "computer", "wifi": "link", "lan": "link", "router": "router", "wan": "line",
                                "optics": "line", "modem": "line", "isp": "provider", "internet": "provider",
                                "dns": "sites", "http": "sites", "load": "speed"}.get(f["area"], "provider")
        lvl = "bad" if f["level"] == "critical" else "warn"
        if by_where.get(where) != "bad":
            by_where[where] = lvl
    pc = (snap.get("net") or {}).get("primary") or {}
    pings = snap.get("pings") or {}
    anchors_ok = any(_alive(v) for k, v in pings.items() if k.startswith("anchor:"))
    texts = {
        "computer": f"{pc.get('name') or 'адаптер'}: {'подключён' if pc.get('status') == 'Up' else 'отключён'}",
        "link": (f"Wi-Fi, сигнал {(snap.get('wifi') or {}).get('signal_pct', '?')}%" if pc.get("is_wifi")
                 else f"кабель, {round((pc.get('link_bps') or 0) / 1e6)} Мбит/с"),
        "router": "отвечает" if _alive(pings.get("gateway")) or snap.get("gateway_mac") else "не отвечает",
        "line": "связь с провайдером есть" if _alive(pings.get("isp_hop")) else ("нет связи" if pings.get("isp_hop") else "—"),
        "provider": "есть" if anchors_ok else "нет",
        "sites": "открываются" if (snap.get("http") or {}).get("ok") else "не открываются",
    }
    st = snap.get("speedtest")
    if st and st.get("bytes"):
        texts["speed"] = f"{st['mbps']:.0f} Мбит/с"
    out = []
    # anything downstream of a broken link cannot be judged
    broken = False
    for key, label in CHECK_LABELS:
        if key == "speed" and not st:
            continue
        state = by_where.get(key, "ok")
        if broken and state == "ok" and key in ("router", "line", "provider", "sites", "speed"):
            state = "skip"
        out.append({"key": key, "label": label, "state": state, "text": texts.get(key) if state != "skip" else "не проверить"})
        if state == "bad":
            broken = True
    return out


def summarize(snap, res):
    findings = [f for f in res["findings"] if f["level"] in ("critical", "warning") and f.get("code") not in MINOR_SKIP]
    main = findings[0] if findings else None
    st = snap.get("speedtest")
    speed = st.get("mbps") if st and st.get("bytes") else None
    out = {"time": time.time(), "checks": checks_from(snap, res), "speed_mbps": speed, "speed_text": _speed_text(speed),
           "others": [], "call_provider": False}

    if main is None:
        out.update({"status": "good", "headline": "С интернетом всё в порядке",
                    "explanation": "Компьютер, роутер, линия провайдера и интернет работают нормально.",
                    "steps": [], "where": None})
        if not res.get("internet_ok"):
            out.update({"status": "bad", "headline": "Интернета нет", "explanation": "Точную причину определить не удалось.",
                        "steps": ["Перезагрузите роутер и устройство провайдера (выключить на 30 секунд).",
                                  "Если не помогло — звоните провайдеру."], "call_provider": True})
    else:
        p = PLAIN.get(main.get("code"))
        if p:
            where, headline, expl, steps, call = p
        else:
            where, headline, expl, steps, call = (None, main["title"], main.get("detail") or "",
                                                  [main["advice"]] if main.get("advice") else [], False)
        out.update({"status": "bad" if main["level"] == "critical" else "warn", "headline": headline,
                    "explanation": expl, "steps": steps, "where": where, "call_provider": call, "code": main.get("code")})
        seen = {headline}
        for f in findings[1:]:
            q = PLAIN.get(f.get("code"))
            h = q[1] if q else f["title"]
            if h in seen:
                continue
            seen.add(h)
            out["others"].append({"headline": h, "text": q[2] if q else (f.get("advice") or ""),
                                  "steps": q[3] if q else [], "level": f["level"], "code": f.get("code")})
            if len(out["others"]) >= 4:
                break
    if out["call_provider"]:
        out["provider_text"] = provider_script(snap, res, out)
    wa = snap.get("wifi_analysis")
    if wa:
        out["wifi_tips"] = [a for a in wa.get("advice", []) if "переключите" in a or "DFS" in a or "Слабый" in a][:3]
    if snap.get("wifi_location_blocked"):
        out.setdefault("others", []).append({
            "headline": "Нет разрешения на сканирование Wi-Fi", "level": "warning", "fixes": ["location"],
            "text": "Windows не даёт программе видеть соседние сети без доступа к местоположению — без этого не подобрать лучший канал.",
            "steps": ["Нажмите «Разрешить» и включите доступ к местоположению для приложений рабочего стола."]})
    r = snap.get("router") or {}
    from .routers import catalog
    info = catalog.CATALOG.get(r.get("type")) or {}
    if info.get("needs_password") and r.get("auth") != "ok":
        out["router_access"] = {"name": info["name"], "model": r.get("model"), "gives": info["gives"], "auth": r.get("auth")}
    add_fixes(out)
    return out


def add_fixes(out):
    from .fixes import FIXES_FOR
    out["fixes"] = list(FIXES_FOR.get(out.get("code"), []))
    for o in out.get("others") or []:
        o.setdefault("fixes", list(FIXES_FOR.get(o.get("code"), [])))
    return out


# ------------------------------------------------------------------ history (monitoring) in plain words

AREA_PLAIN = {
    "pc": "Отключался сетевой адаптер компьютера",
    "wifi": "Пропадала связь по Wi-Fi с роутером",
    "lan": "Пропадала связь по кабелю с роутером",
    "router": "Роутер переставал отвечать (кабель к нему был подключён)",
    "modem": "Не отвечал модем/терминал провайдера",
    "optics": "Не отвечал оптический терминал",
    "wan": "Интернет переставал приходить от провайдера",
    "isp": "Сбой в сети провайдера",
    "internet": "Интернет был недоступен",
    "router_dns": "Не работал DNS роутера — связь была, но сайты не открывались",
    "dns": "Не работал DNS провайдера — связь была, но сайты не открывались",
}
PROVIDER_AREAS = {"modem", "optics", "wan", "isp", "dns"}


def event_area(e):
    d = e.get("detail") or {}
    if d.get("router_reboot") or d.get("router_hang"):
        return "router"
    return d.get("area") or "internet"


def plain_cause(e):
    d = e.get("detail") or {}
    if e.get("kind") == "partial":
        return "Часть интернета была недоступна (сбой маршрутизации у провайдера)"
    if d.get("router_reboot") or d.get("router_hang"):
        return e.get("cause")
    return AREA_PLAIN.get(event_area(e), e.get("cause") or "Интернет был недоступен")


def _times(evs, n=6):
    return ", ".join(time.strftime("%d.%m %H:%M", time.localtime(e["start"])) +
                     (f" ({int(e['end'] - e['start'])} с)" if e.get("end") else "") for e in sorted(evs, key=lambda e: e["start"])[-n:])


def history_verdict(events):
    """Conclusions from the outage history."""
    drops = [e for e in events if e["kind"] in ("outage", "blip")]
    by = {}
    for e in drops:
        by.setdefault(event_area(e), []).append(e)
    out = []
    router = by.get("router", [])
    if len(router) >= 2:
        reboots = sum(1 for e in router if (e.get("detail") or {}).get("router_reboot"))
        out.append({"code": "router_unstable", "level": "critical" if len(router) >= 3 else "warning",
                    "headline": f"Роутер регулярно зависает ({len(router)} раз)",
                    "text": ("Роутер сам перезагружался " + _plural_times(reboots) + ". " if reboots else "") +
                            "Похоже, он неисправен или перегревается. Это не провайдер — проблема в вашем роутере.",
                    "steps": ["Проверьте блок питания роутера: если он сильно греется, гудит или он «не родной» — замените. "
                              "Слабый блок питания — самая частая причина зависаний.",
                              "Поставьте роутер на открытое место, не накрывайте и уберите от батареи.",
                              "Обновите прошивку роутера или сбросьте его на заводские настройки (лучше с мастером).",
                              "Если роутеру больше 4–5 лет или зависания продолжаются — его пора заменить."],
                    "times": _times(router), "call_provider": False})
    prov = [e for a in PROVIDER_AREAS for e in by.get(a, [])]
    if len(prov) >= 2:
        out.append({"code": "provider_unstable", "level": "critical" if len(prov) >= 3 else "warning",
                    "headline": f"Провайдер отключал интернет {_plural_times(len(prov))}",
                    "text": "Ваш компьютер и роутер в это время работали — интернет пропадал на стороне провайдера.",
                    "steps": ["Сообщите провайдеру время обрывов (список ниже) и попросите проверить линию.",
                              "Если обрывы продолжаются — требуйте выезд мастера или перерасчёт."],
                    "times": _times(prov, 10), "call_provider": True})
    wifi_ev = by.get("wifi", [])
    if len(wifi_ev) >= 3:
        out.append({"code": "wifi_unstable", "level": "warning", "headline": f"Wi-Fi часто отваливается ({len(wifi_ev)} раз)",
                    "text": "Связь между компьютером и роутером по Wi-Fi регулярно пропадает.",
                    "steps": ["Сядьте ближе к роутеру или подключите компьютер кабелем.",
                              "Смените канал Wi-Fi (подсказка — в разделе Wi-Fi для специалистов).",
                              "Если пропадает у всех устройств сразу — роутер зависает: проверьте его блок питания."],
                    "times": _times(wifi_ev), "call_provider": False})
    pc = by.get("pc", []) + by.get("lan", [])
    if len(pc) >= 2:
        out.append({"code": "pc_unstable", "level": "warning", "headline": f"Сетевое подключение компьютера отваливается ({len(pc)} раз)",
                    "text": "Пропадала связь на участке компьютер — роутер (кабель, гнездо или сетевая карта).",
                    "steps": ["Замените сетевой кабель и попробуйте другое гнездо на роутере.",
                              "В настройках сетевой карты отключите энергосбережение (Energy Efficient Ethernet / Green Ethernet)."],
                    "times": _times(pc), "call_provider": False})
    conflicts = [e for e in events if (e.get("detail") or {}).get("gateway_mac_change")]
    if conflicts:
        out.append({"code": "ip_conflict", "level": "warning", "headline": "В сети появляется второй роутер или конфликт адресов",
                    "text": "Адрес роутера периодически «перехватывает» другое устройство — из-за этого связь рвётся у всех.",
                    "steps": ["Проверьте, не подключён ли в сеть второй роутер (например, старый — его надо перевести в режим точки доступа).",
                              "Обратитесь к мастеру: нужно найти устройство с таким же адресом."],
                    "times": _times(conflicts), "call_provider": False})
    return out


def _plural_times(n):
    m, h = n % 10, n % 100
    return f"{n} " + ("раз" if m == 1 and h != 11 else ("раза" if 2 <= m <= 4 and not 10 <= h < 20 else "раз"))


def merge_history(summary, verdicts):
    """Add monitoring conclusions to a one-shot check result."""
    if not verdicts:
        return summary
    summary["history"] = verdicts
    top = verdicts[0]
    if summary["status"] == "good":
        summary.update({"status": "warn" if top["level"] == "warning" else "bad", "headline": top["headline"],
                        "explanation": "Прямо сейчас интернет работает, но мониторинг заметил: " + top["text"],
                        "steps": top["steps"], "code": top["code"], "where": "router" if top["code"] == "router_unstable" else None,
                        "history_times": top.get("times")})
        if top.get("call_provider"):
            summary["call_provider"] = True
            summary["provider_text"] = ("Здравствуйте. У меня регулярно пропадает интернет: " + top["times"] +
                                        ". По данным программы мониторинга мой роутер в это время работал, "
                                        "связь пропадала на вашей стороне. Прошу проверить линию. Номер договора / адрес: ____________")
        rest = verdicts[1:]
    else:
        rest = verdicts
    for v in rest:
        summary.setdefault("others", []).insert(0, {"headline": v["headline"], "text": v["text"], "steps": v["steps"],
                                                    "level": v["level"], "code": v["code"]})
    return add_fixes(summary)


def merge_stability(summary, stab):
    """Add the history-based verdict ("why is it unstable") to a one-shot check result."""
    summary["stability"] = stab
    v = (stab or {}).get("verdict") or {}
    if v.get("culprit") in (None, "none", "unknown") or v.get("confidence", 0) < 40:
        return add_fixes(summary)
    hist = {"headline": v["headline"], "text": v.get("explanation") or "", "steps": v.get("steps") or [],
            "level": "critical" if v["confidence"] >= 70 else "warning", "code": "stability_" + v["culprit"],
            "fixes": v.get("fixes") or []}
    if summary["status"] == "good":
        summary.update({"status": "warn" if hist["level"] == "warning" else "bad", "headline": v["headline"],
                        "explanation": "Прямо сейчас интернет работает, но по истории наблюдения: " + hist["text"],
                        "steps": hist["steps"], "code": hist["code"], "history_times": v.get("times"),
                        "confidence": v["confidence"], "patterns": stab.get("patterns") or [],
                        "where": {"router": "router", "wifi": "link", "cable": "link", "pc": "computer", "line": "line",
                                  "provider": "provider", "dns": "sites"}.get(v["culprit"])})
        if v.get("call_provider") and v.get("provider_text"):
            summary["call_provider"] = True
            summary["provider_text"] = v["provider_text"]
        summary = add_fixes(summary)
        summary["fixes"] = list(dict.fromkeys((summary.get("fixes") or []) + hist["fixes"]))
        return summary
    summary.setdefault("others", []).insert(0, hist)
    return add_fixes(summary)


def provider_script(snap, res, out):
    r = snap.get("router") or {}
    wan = r.get("wan") or {}
    facts = [f"Сегодня в {time.strftime('%H:%M')} у меня не работает интернет."]
    facts.append("Я проверил программой диагностики: компьютер и роутер работают исправно.")
    if wan.get("link") is False:
        facts.append("Роутер не видит кабель от вашего оборудования (нет линка на WAN-порту).")
    elif wan.get("error_text"):
        facts.append(f"Роутер показывает ошибку подключения: {wan['error_text']}" + (f" (код {wan.get('error_code')})" if wan.get("error_code") else "") + ".")
    o = r.get("optics") or (snap.get("ont") or {}).get("optics") or {}
    if o.get("rx_dbm") is not None:
        facts.append(f"Уровень оптического сигнала на терминале: {o['rx_dbm']} дБм.")
    path = snap.get("path") or {}
    isp = (snap.get("pings") or {}).get("isp_hop")
    if isp and path.get("isp_hop"):
        facts.append(f"Ваш узел {path['isp_hop']} " + ("отвечает, но дальше в интернет трафик не проходит." if _alive(isp)
                                                       else "не отвечает."))
    facts.append("Прошу проверить мою линию. Номер договора / адрес: ____________")
    return " ".join(facts)
