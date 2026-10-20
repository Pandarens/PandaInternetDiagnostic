"""Why is the internet unstable? Looks at the whole monitoring history (not a single check) and names the culprit
with a confidence level and the evidence behind it.

Inputs: events from the store (outages, micro-drops, DNS/partial failures, router reboots, sleep) with the context
captured at the moment of each drop, and hourly packet-loss/latency statistics per segment of the chain.
"""
import math
import time

# area recorded by the monitor -> culprit
AREA_CULPRIT = {"pc": "pc", "wifi": "wifi", "lan": "cable", "router": "router", "router_dns": "router",
                "modem": "line", "optics": "line", "wan": "line", "isp": "provider", "internet": "provider", "dns": "dns"}

VERDICTS = {
    "router": dict(
        headline="Причина нестабильности — ваш роутер",
        steps=["Проверьте блок питания роутера: греется, гудит, «не родной» — замените. Это самая частая причина зависаний.",
               "Поставьте роутер на открытое место, уберите от батареи, не накрывайте.",
               "Обновите прошивку роутера.",
               "Если не помогло или роутеру больше 4–5 лет — замените его."],
        call=False, fixes=[]),
    "wifi": dict(
        headline="Причина нестабильности — Wi-Fi между компьютером и роутером",
        steps=["Сядьте ближе к роутеру или подключите компьютер кабелем — это сразу покажет, Wi-Fi ли виноват.",
               "Смените канал Wi-Fi на свободный (подсказка — в разделе Wi-Fi для специалистов).",
               "Подключайтесь к сети 5 ГГц, если сигнал позволяет.",
               "Для дальних комнат поставьте mesh-систему или усилитель."],
        call=False, fixes=[]),
    "cable": dict(
        headline="Причина нестабильности — кабель между компьютером и роутером",
        steps=["Замените сетевой кабель (Cat5e/Cat6).", "Вставьте кабель в другое гнездо роутера.",
               "Отключите энергосбережение сетевой карты (кнопка ниже)."],
        call=False, fixes=["disable_eee", "restart_adapter"]),
    "pc": dict(
        headline="Причина нестабильности — сетевая карта этого компьютера",
        steps=["Отключите энергосбережение сетевой карты (кнопка ниже).",
               "Обновите драйвер сетевой карты с сайта производителя ноутбука/материнской платы.",
               "Проверьте кабель и гнездо в компьютере."],
        call=False, fixes=["disable_eee", "restart_adapter"]),
    "line": dict(
        headline="Причина нестабильности — линия провайдера до вашего дома",
        steps=["Посмотрите на терминал/модем провайдера во время обрыва: красный LOS — обрыв оптики, мигает PON — нет регистрации.",
               "Проверьте, не пережат ли оптический или телефонный кабель, плотно ли вставлен кабель терминал → роутер.",
               "Позвоните провайдеру и назовите время обрывов (список ниже) — нужна проверка линии мастером."],
        call=True, fixes=[]),
    "provider": dict(
        headline="Причина нестабильности — сеть провайдера",
        steps=["Ваше оборудование работает исправно — сами вы это не исправите.",
               "Позвоните провайдеру, назовите время обрывов (список ниже) и потребуйте проверку или перерасчёт.",
               "Если обрывы продолжаются неделями — стоит сменить провайдера."],
        call=True, fixes=[]),
    "dns": dict(
        headline="Причина — DNS провайдера: связь есть, но сайты не открываются",
        steps=["Поставьте быстрые DNS 1.1.1.1 и 8.8.8.8 (кнопка ниже) — это решает проблему без провайдера."],
        call=False, fixes=["public_dns"]),
}


def _w(e):
    """Weight of a drop: long outages matter more than 1-second blips, but many blips still add up."""
    d = (e["end"] or time.time()) - e["start"]
    return 1.0 + min(max(d, 0), 900) / 60.0


def _culprit(e):
    d = e.get("detail") or {}
    if d.get("router_reboot") or d.get("router_hang"):
        return "router"
    ctx = d.get("ctx") or {}
    if ctx.get("pc_status") not in (None, "Up"):
        return "pc"
    return AREA_CULPRIT.get(d.get("area"), "provider")


def _fmt_t(ts):
    return time.strftime("%d.%m %H:%M", time.localtime(ts))


def _dur(sec):
    sec = int(sec)
    if sec < 60:
        return f"{sec} с"
    if sec < 3600:
        return f"{sec // 60} мин"
    return f"{sec // 3600} ч {sec % 3600 // 60} мин"


def _plural(n, a, b, c):
    m, h = n % 10, n % 100
    return f"{n} " + (a if m == 1 and h != 11 else b if 2 <= m <= 4 and not 10 <= h < 20 else c)


def _periodicity(starts):
    """Drops that repeat at a steady interval point to a schedule: forced PPPoE reconnect, DHCP lease, reboot loop."""
    if len(starts) < 3:
        return None
    gaps = [b - a for a, b in zip(starts, starts[1:]) if b - a > 120]
    if len(gaps) < 2:
        return None
    mean = sum(gaps) / len(gaps)
    std = math.sqrt(sum((g - mean) ** 2 for g in gaps) / len(gaps))
    if mean <= 0 or std / mean > 0.15:
        return None
    return mean


def _segment_quality(hourly):
    """hourly: {target_key: [(hour_ts, sent, lost, avg_rtt), ...]} -> average loss/latency per segment + evening vs night."""
    def agg(rows):
        sent = sum(r[1] for r in rows)
        lost = sum(r[2] for r in rows)
        rtts = [(r[3], r[1] - r[2]) for r in rows if r[3] is not None and r[1] > r[2]]
        n = sum(w for _, w in rtts)
        return {"sent": sent, "loss": round(100 * lost / sent, 2) if sent else None,
                "avg": round(sum(a * w for a, w in rtts) / n, 1) if n else None}

    seg = {"home": agg(hourly.get("gateway", []))}
    if hourly.get("isp_hop"):
        seg["line"] = agg(hourly["isp_hop"])
    # internet = the best-behaving public server each hour (one bad server must not look like a broken internet)
    anchors = [k for k in hourly if k.startswith("anchor:")]
    best = {}
    for k in anchors:
        for h, sent, lost, avg in hourly[k]:
            cur = best.get(h)
            if sent and (cur is None or lost / sent < cur[2] / max(cur[1], 1)):
                best[h] = (h, sent, lost, avg)
    rows = sorted(best.values())
    seg["internet"] = agg(rows)
    ev = [r for r in rows if 18 <= time.localtime(r[0]).tm_hour <= 23]
    night = [r for r in rows if 2 <= time.localtime(r[0]).tm_hour <= 6]
    if ev and night:
        seg["evening"], seg["night"] = agg(ev), agg(night)
    return seg


def analyze(events, hourly=None, monitored_sec=0, is_wifi=False, period_hours=24):
    drops = [e for e in events if e["kind"] in ("outage", "blip")]
    soft = [e for e in events if e["kind"] in ("dns", "partial")]
    reboots = [e for e in events if e["kind"] == "router" and "перезагрузился" in (e.get("title") or "")]
    sleeps = [e for e in events if e["kind"] == "sleep"]
    seg = _segment_quality(hourly or {})
    out = {"period_hours": period_hours, "monitored_sec": monitored_sec,
           "outages": sum(1 for e in drops if e["kind"] == "outage"), "blips": sum(1 for e in drops if e["kind"] == "blip"),
           "downtime_sec": round(sum((e["end"] or time.time()) - e["start"] for e in drops if e["kind"] == "outage")),
           "segments": seg, "patterns": [], "evidence": [], "scores": {}}

    # ---------------------------------------------------------------- score culprits from drops
    scores, by = {}, {}
    for e in drops + soft:
        c = _culprit(e)
        w = _w(e) * (0.6 if e in soft else 1.0)
        if (e.get("detail") or {}).get("recovered_before_check"):
            w *= 0.5  # cause guessed from the first seconds only; the deep check ran after recovery
        scores[c] = scores.get(c, 0) + w
        by.setdefault(c, []).append(e)
    for e in reboots:  # a router reboot is itself a drop for every device in the house
        scores["router"] = scores.get("router", 0) + 2
        by.setdefault("router", []).append(e)
    total = sum(scores.values())
    out["scores"] = {k: round(v / total * 100) for k, v in scores.items()} if total else {}

    # ---------------------------------------------------------------- chronic quality (packet loss by segment)
    chronic = None
    home, line, inet = (seg.get(k) or {} for k in ("home", "line", "internet"))
    hl, ll, il = home.get("loss") or 0, line.get("loss"), inet.get("loss") or 0
    if home.get("sent", 0) > 600:
        if hl >= 1.0:
            chronic = ("wifi" if is_wifi else "cable",
                       f"Пакеты теряются уже между компьютером и роутером: {hl}% (норма — 0%).")
        elif ll is not None and ll - hl >= 1.0 and il >= 1.0:
            chronic = ("line", f"Потери начинаются на участке роутер → провайдер: до роутера {hl}%, до провайдера {ll}%, в интернет {il}%.")
        elif il - max(hl, ll or 0) >= 1.0:
            chronic = ("provider", f"До провайдера связь чистая, а дальше теряется {il}% пакетов — проблема в сети провайдера.")
    ev, ni = seg.get("evening"), seg.get("night")
    if ev and ni and ev.get("avg") and ni.get("avg") and ev["avg"] > ni["avg"] * 1.8 and ev["avg"] - ni["avg"] > 25:
        out["patterns"].append(f"Вечером (18–23 ч) пинг растёт до {ev['avg']} мс против {ni['avg']} мс ночью — "
                               "сеть провайдера перегружена в час пик.")
        if not chronic:
            chronic = ("provider", "Вечерняя перегрузка сети провайдера.")
    if chronic:
        scores[chronic[0]] = scores.get(chronic[0], 0) + 3
        out["evidence"].append(chronic[1])

    # ---------------------------------------------------------------- patterns across drops
    starts = sorted(e["start"] for e in drops)
    hours = [time.localtime(t).tm_hour for t in starts]
    if len(drops) >= 3:
        evening = sum(1 for h in hours if 18 <= h <= 23)
        night = sum(1 for h in hours if 0 <= h <= 6)
        if evening / len(hours) >= 0.6:
            out["patterns"].append(f"{_plural(evening, 'обрыв', 'обрыва', 'обрывов')} из {len(hours)} — вечером (18–23 ч): "
                                   "типичная перегрузка сети провайдера в час пик.")
            scores["provider"] = scores.get("provider", 0) + 1
        elif night / len(hours) >= 0.6:
            out["patterns"].append("Обрывы в основном ночью — похоже на плановые работы или переподключение у провайдера.")
    period = _periodicity(starts)
    if period:
        if 82800 <= period <= 90000:
            out["patterns"].append(f"Обрывы повторяются почти ровно раз в сутки (около {time.strftime('%H:%M', time.localtime(starts[-1]))}) — "
                                   "провайдер принудительно переподключает сессию (PPPoE/DHCP). Попросите провайдера отключить разрыв "
                                   "сессии или перенести его на ночь.")
            scores["line"] = scores.get("line", 0) + 2
        else:
            out["patterns"].append(f"Обрывы повторяются с постоянным интервалом ~{_dur(period)} — так ведёт себя роутер, "
                                   "который перезагружается или не может продлить адрес (DHCP) у провайдера.")
            scores["router"] = scores.get("router", 0) + 1

    ctxs = [(e.get("detail") or {}).get("ctx") or {} for e in drops]
    weak = [c["wifi_rssi"] for c in ctxs if c.get("wifi_rssi") is not None and c["wifi_rssi"] < -70]
    if weak and len(weak) >= max(1, len(drops) // 2):
        out["patterns"].append(f"Во время {_plural(len(weak), 'обрыва', 'обрывов', 'обрывов')} сигнал Wi-Fi был слабым "
                               f"(до {min(weak)} дБм).")
        scores["wifi"] = scores.get("wifi", 0) + 2
    loaded = [c for c in ctxs if (c.get("wan_load_pct") or 0) >= 80]
    if loaded and len(loaded) >= max(1, len(drops) // 2):
        out["patterns"].append(f"{_plural(len(loaded), 'обрыв', 'обрыва', 'обрывов')} случились, когда канал был загружен "
                               "на 80% и больше — роутер или канал не выдерживает нагрузку.")
        scores["router"] = scores.get("router", 0) + 1
    hot = [c for c in ctxs if (c.get("router_cpu") or 0) >= 85]
    if hot:
        out["patterns"].append(f"Во время {_plural(len(hot), 'обрыва', 'обрывов', 'обрывов')} процессор роутера был загружен на 85%+.")
        scores["router"] = scores.get("router", 0) + 1
    if reboots:
        out["patterns"].append(f"Роутер сам перезагружался {_plural(len(reboots), 'раз', 'раза', 'раз')}.")
    if sleeps:
        out["patterns"].append(f"Компьютер уходил в сон {_plural(len(sleeps), 'раз', 'раза', 'раз')} — эти периоды не считаются обрывами.")

    # ---------------------------------------------------------------- evidence for the top culprit
    total = sum(scores.values())
    if not total:
        if monitored_sec < 3600:
            out["verdict"] = {"culprit": "unknown", "confidence": 0, "headline": "Пока мало данных",
                              "explanation": "Оставьте программу включённой хотя бы на несколько часов (лучше на сутки) — "
                                             "она запомнит каждый обрыв и покажет, кто виноват.", "steps": [], "fixes": []}
        else:
            out["verdict"] = {"culprit": "none", "confidence": 90, "headline": "Интернет работает стабильно",
                              "explanation": f"За {_dur(monitored_sec)} наблюдения не было ни одного обрыва и заметных потерь пакетов.",
                              "steps": [], "fixes": []}
        return out
    top = max(scores, key=scores.get)
    share = scores[top] / total
    n = len(by.get(top, [])) or 1
    # few incidents = weak evidence: 1 drop -> at most ~40 %, 5+ drops -> full weight
    confidence = round(min(95, share * 100 * min(1.0, 0.25 + 0.15 * n)))
    evs = by.get(top, [])
    out["evidence"] = _evidence(top, evs, drops, is_wifi) + out["evidence"]
    v = VERDICTS[top]
    times = ", ".join(_fmt_t(e["start"]) + (f" ({_dur(e['end'] - e['start'])})" if e.get("end") else "")
                      for e in sorted(evs, key=lambda e: e["start"])[-10:])
    headline = v["headline"]
    if confidence < 50:
        headline = headline.replace("Причина нестабильности — ", "Возможная причина — ").replace("Причина — ", "Возможная причина — ")
        cnt = len(drops) or n
        so_far = "Пока был всего один обрыв" if cnt == 1 else f"Пока было всего {_plural(cnt, 'обрыв', 'обрыва', 'обрывов')}"
        out["patterns"].append(so_far + " — для уверенного вывода оставьте наблюдение включённым подольше.")
    out["verdict"] = {"culprit": top, "confidence": confidence, "headline": headline,
                      "explanation": " ".join(out["evidence"][:2]) or "",
                      "steps": v["steps"], "fixes": v["fixes"], "call_provider": v["call"], "times": times}
    if v["call"] and evs:
        out["verdict"]["provider_text"] = (
            f"Здравствуйте. У меня нестабильный интернет: за последние {_plural(period_hours, 'час', 'часа', 'часов')} "
            f"он пропадал {_plural(len(evs), 'раз', 'раза', 'раз')}: {times}. "
            "Программа мониторинга показывает, что мой роутер и компьютер в это время работали, а связь пропадала "
            + ("на линии до вашего оборудования" if top == "line" else "в вашей сети") +
            ". Прошу проверить линию и сообщить результат. Номер договора / адрес: ____________")
    if share < 0.6 and len(scores) > 1:
        second = sorted(scores, key=scores.get, reverse=True)[1]
        out["verdict"]["also"] = VERDICTS[second]["headline"].replace("Причина нестабильности — ", "").replace("Причина — ", "")
    return out


def _evidence(top, evs, drops, is_wifi):
    n, total = len(evs), len(drops) or len(evs)
    of = f"{n} из {total}" if total and total != n else f"{n}"

    def times_phrase(k):
        if k == 1 and total <= 1:
            return "Единственный раз"
        if k == total:
            return f"Все {k} раз" if k > 1 else "Единственный раз"
        return f"В {k} из {total} случаев"
    lines = []
    if top == "router":
        reb = sum(1 for e in evs if (e.get("detail") or {}).get("router_reboot") or e["kind"] == "router")
        hang = sum(1 for e in evs if (e.get("detail") or {}).get("router_hang"))
        quiet = sum(1 for e in evs if (e.get("detail") or {}).get("area") == "router" and e["kind"] in ("outage", "blip"))
        if quiet:
            lines.append(f"{times_phrase(quiet)} роутер переставал отвечать, хотя кабель к нему был подключён.")
        if reb:
            lines.append(f"Роутер сам перезагружался {_plural(reb, 'раз', 'раза', 'раз')}.")
        if hang:
            lines.append(f"Роутер зависал и «отвисал» без перезагрузки {_plural(hang, 'раз', 'раза', 'раз')}.")
        dns = sum(1 for e in evs if (e.get("detail") or {}).get("area") == "router_dns")
        if dns:
            lines.append(f"{_plural(dns, 'раз', 'раза', 'раз')} не работал DNS внутри роутера — сайты не открывались.")
    elif top == "wifi":
        lines.append(f"{times_phrase(n)} пропадала связь компьютера с роутером по Wi-Fi, а сам роутер и провайдер работали.")
    elif top == "cable":
        lines.append(f"{times_phrase(n)} связь пропадала уже между компьютером и роутером (по кабелю).")
    elif top == "pc":
        lines.append(f"{times_phrase(n)} отключалась сама сетевая карта компьютера.")
    elif top == "line":
        lines.append(f"{times_phrase(n)} роутер работал, но не получал связь от провайдера — обрыв на линии/оптике/терминале.")
    elif top == "provider":
        lines.append(f"{times_phrase(n)} дом и линия до провайдера работали, а пропадала связь внутри сети провайдера.")
        part = sum(1 for e in evs if e["kind"] == "partial")
        if part:
            lines.append(f"{_plural(part, 'раз', 'раза', 'раз')} часть интернета была недоступна — сбой маршрутизации у провайдера.")
    elif top == "dns":
        lines.append(f"{_plural(n, 'раз', 'раза', 'раз')} связь была, но DNS провайдера не отвечал — сайты не открывались.")
    return lines
