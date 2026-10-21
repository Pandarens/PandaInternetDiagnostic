"""Wi-Fi air analysis: scan neighbours and recommend channel / width / band."""
import re

from .system import _run

CH24 = [1, 6, 11]                  # the only non-overlapping 20 MHz channels every client supports
CH24_EU = [1, 5, 9, 13]            # 4-channel plan, allowed in RU/KZ/EU (some US-market clients can't use 12-13)
CH5_NODFS = [36, 40, 44, 48, 149, 153, 157, 161, 165]
CH5_DFS = [52, 56, 60, 64, 100, 104, 108, 112, 116, 120, 124, 128, 132, 136, 140, 144]
BLOCKS_80 = [(36, 40, 44, 48), (52, 56, 60, 64), (100, 104, 108, 112), (116, 120, 124, 128),
             (132, 136, 140, 144), (149, 153, 157, 161)]

LOCATION_BLOCKED = False

_SCAN_KEYS = {
    "ssid": re.compile(r"^SSID\s+\d+\s*:\s*(.*)$", re.I),
    "bssid": re.compile(r"^BSSID\s+\d+\s*:\s*([0-9a-f:]{17})", re.I),
    "signal": re.compile(r"^(?:Signal|Сигнал)\s*:\s*(\d+)\s*%", re.I),
    "channel": re.compile(r"^(?:Channel|Канал)\s*:\s*(\d+)", re.I),
    "radio": re.compile(r"^(?:Radio type|Тип радио\w*)\s*:\s*(.*)$", re.I),
    "band": re.compile(r"^(?:Band|Диапазон)\s*:\s*(.*)$", re.I),
}


def scan_from_pc():
    """Neighbour APs visible to this PC's Wi-Fi adapter (netsh). Returns [] on wired-only PCs."""
    global LOCATION_BLOCKED
    out = _run(["netsh", "wlan", "show", "networks", "mode=bssid"], encoding="oem")
    # Windows 11 24H2+: Wi-Fi scanning requires the Location permission for desktop apps
    LOCATION_BLOCKED = bool(re.search(r"location|местоположени", out, re.I))
    aps, ssid, cur = [], None, None
    for raw in out.splitlines():
        line = raw.strip()
        m = _SCAN_KEYS["ssid"].match(line)
        if m:
            ssid = m.group(1).strip()
            continue
        m = _SCAN_KEYS["bssid"].match(line)
        if m:
            cur = {"ssid": ssid, "bssid": m.group(1).lower()}
            aps.append(cur)
            continue
        if cur is None:
            continue
        for k in ("signal", "channel", "radio", "band"):
            m = _SCAN_KEYS[k].match(line)
            if m:
                cur[k] = m.group(1).strip()
    for ap in aps:
        pct = int(ap.pop("signal", 0) or 0)
        ap["signal_dbm"] = round(pct / 2 - 100)
        ap["channel"] = int(ap["channel"]) if str(ap.get("channel", "")).isdigit() else None
        radio = ap.get("radio", "")
        ap["width"] = 80 if "ac" in radio or "ax" in radio or "be" in radio else (40 if "n" in radio else 20)
        if ap["channel"] and ap["channel"] <= 14:
            ap["width"] = 20  # 2.4 GHz networks almost always fall back to 20 MHz in busy air
    return aps


def _weight(dbm):
    if dbm is None:
        return 0.5
    return max(0.0, (dbm + 95) / 10.0)   # -45 dBm -> 5.0, -85 dBm -> 1.0, below -95 -> 0


def _overlap_24(ch, other, width=20):
    d = abs(ch - other)
    span = 5 if (width or 20) <= 20 else 7
    return max(0.0, (span - d) / span)


def _score_24(ch, aps):
    return round(sum(_weight(a["signal_dbm"]) * _overlap_24(ch, a["channel"], a.get("width") or 20) for a in aps), 2)


def _block_of(ch):
    for b in BLOCKS_80:
        if ch in b:
            return b
    return (ch,)


def _score_5(ch, aps, width):
    if width >= 80:
        group = set(_block_of(ch))
    elif width == 40:
        b = _block_of(ch)
        i = b.index(ch) if ch in b else 0
        group = set(b[(i // 2) * 2:(i // 2) * 2 + 2]) if len(b) == 4 else {ch}
    else:
        group = {ch}
    s = 0.0
    for a in aps:
        their = set(_block_of(a["channel"])) if (a.get("width") or 20) >= 80 else {a["channel"]}
        if group & their:
            s += _weight(a["signal_dbm"])
    return round(s, 2)


def signal_quality(dbm):
    if dbm is None:
        return None
    if dbm >= -55:
        return "отличный"
    if dbm >= -67:
        return "хороший"
    if dbm >= -75:
        return "слабый — возможны обрывы и низкая скорость"
    return "очень слабый — обрывы гарантированы"


def analyze(scan, own_ssids=(), own_bssids=(), radios=(), client=None):
    """
    scan: list of neighbour APs [{ssid,bssid,channel,signal_dbm,width}]
    radios: own router radios [{band, channel, width, ssid}]
    client: this PC's Wi-Fi connection (from system.wifi_state()) or None
    Returns {bands: {...}, advice: [str], neighbours: n}
    """
    own_ssids = {s for s in own_ssids if s}
    own_prefixes = {b[:14] for b in own_bssids if b}
    neighbours = [a for a in scan if a.get("channel") and a.get("ssid") not in own_ssids
                  and (a.get("bssid") or "")[:14] not in own_prefixes]
    n24 = [a for a in neighbours if a["channel"] <= 14]
    n5 = [a for a in neighbours if 30 <= a["channel"] <= 177]
    advice = []
    result = {"neighbours": len(neighbours), "bands": {}, "advice": advice}

    current = {}
    for r in radios or []:
        if r.get("band") and r.get("channel"):
            current[r["band"]] = r
    if client and client.get("channel"):
        b = "2.4" if client["channel"] <= 14 else "5"
        current.setdefault(b, {"band": b, "channel": client["channel"], "ssid": client.get("ssid")})

    # ---- 2.4 GHz
    if n24 or "2.4" in current:
        scores = {c: _score_24(c, n24) for c in sorted(set(CH24 + CH24_EU))}
        best = min(CH24, key=lambda c: scores[c])
        best_eu = min(CH24_EU, key=lambda c: scores[c])
        cur = current.get("2.4", {}).get("channel")
        cur_score = _score_24(cur, n24) if cur else None
        band = {"scores": scores, "best": best, "best_any": best_eu, "current": cur, "current_score": cur_score,
                "networks": len(n24), "per_channel": _count_by_channel(n24)}
        result["bands"]["2.4"] = band
        width = current.get("2.4", {}).get("width")
        if cur and cur_score is not None and cur_score > scores[best] * 1.3 + 1:
            advice.append(f"2.4 ГГц: переключите канал {cur} → {best} (загрузка эфира {cur_score} → {scores[best]}).")
        elif cur:
            advice.append(f"2.4 ГГц: текущий канал {cur} оптимален или близок к оптимальному.")
        else:
            advice.append(f"2.4 ГГц: лучший канал — {best}.")
        if cur and cur not in CH24 + CH24_EU:
            advice.append(f"2.4 ГГц: канал {cur} перекрывает сразу два «чистых» канала — используйте только 1, 6 или 11.")
        if best_eu in (12, 13) and scores[best_eu] < scores[best] * 0.6:
            advice.append(f"2.4 ГГц: канал {best_eu} свободнее, но часть устройств (iPhone/ноутбуки, купленные в США) его не видят.")
        if (width or 20) > 20 or len(n24) > 5:
            advice.append("2.4 ГГц: ширину канала ставьте 20 МГц — 40 МГц в многоквартирном доме только ухудшает связь.")

    # ---- 5 GHz
    if n5 or "5" in current:
        cand = CH5_NODFS + CH5_DFS
        cur_r = current.get("5", {})
        cur = cur_r.get("channel")
        width = cur_r.get("width") or 80
        scores80 = {c: _score_5(c, n5, 80) for c in cand}
        scores20 = {c: _score_5(c, n5, 20) for c in cand}
        best_nodfs = min(CH5_NODFS, key=lambda c: (scores80[c], c))
        best_any = min(cand, key=lambda c: (scores80[c], c in CH5_DFS, c))
        cur_score = _score_5(cur, n5, width) if cur else None
        band = {"scores80": scores80, "scores20": scores20, "best": best_nodfs, "best_dfs": best_any,
                "current": cur, "current_score": cur_score, "networks": len(n5), "per_channel": _count_by_channel(n5)}
        result["bands"]["5"] = band
        if cur and cur_score is not None and cur_score > scores80[best_nodfs] * 1.3 + 1:
            advice.append(f"5 ГГц: переключите канал {cur} → {best_nodfs} (блок {'-'.join(map(str, _block_of(best_nodfs)))}).")
        elif cur:
            advice.append(f"5 ГГц: текущий канал {cur} в порядке.")
        else:
            advice.append(f"5 ГГц: лучший канал — {best_nodfs}.")
        if cur and cur in CH5_DFS:
            advice.append(f"5 ГГц: канал {cur} — DFS (общий с радарами). При обнаружении радара роутер "
                          f"отключает Wi-Fi на 1–10 минут — частая причина «необъяснимых» обрывов. Рекомендуется {best_nodfs}.")
        if scores80[best_nodfs] > 3:
            advice.append("5 ГГц: эфир плотный — уменьшите ширину канала до 40 МГц для стабильности.")
        else:
            advice.append("5 ГГц: используйте ширину 80 МГц (эфир свободный) — максимум скорости.")

    # ---- client side
    if client and client.get("connected"):
        dbm = client.get("rssi_dbm")
        q = signal_quality(dbm)
        ch = client.get("channel") or 0
        if q:
            advice.append(f"Ваш ПК: сигнал {dbm} дБм ({q}), канал {ch}, скорость {client.get('rx_mbps')}/{client.get('tx_mbps')} Мбит/с.")
        if ch and ch <= 14 and n5 is not None and any(r.get("band") == "5" for r in (radios or [])):
            advice.append("ПК подключён к 2.4 ГГц — если сигнал позволяет, подключитесь к сети 5 ГГц (в 3–10 раз быстрее, меньше помех).")
        if dbm is not None and dbm < -72:
            advice.append("Слабый сигнал: переставьте роутер выше/ближе к центру квартиры, уберите от зеркал/металла/аквариумов, "
                          "или поставьте mesh-систему/повторитель. На 5 ГГц стены гасят сигнал сильнее, чем на 2.4.")
    return result


def _count_by_channel(aps):
    out = {}
    for a in aps:
        out[a["channel"]] = out.get(a["channel"], 0) + 1
    return dict(sorted(out.items()))
