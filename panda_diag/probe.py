"""Full diagnostic snapshot of the whole chain: PC -> Wi-Fi/LAN -> router -> modem/ONT -> provider -> internet."""
import time
from concurrent.futures import ThreadPoolExecutor

from . import icmp, routers, system, wifi


def discover_path(target="8.8.8.8", gateway=None):
    """Traceroute to find: the provider modem (private hop after our router) and the first provider hop."""
    hops = icmp.traceroute(target, max_hops=10, timeout_ms=700, probes=2)
    path = {"hops": hops, "modem_hop": None, "isp_hop": None, "double_nat": False, "cgnat": False}
    seen_gw = False
    for h in hops:
        a = h["addr"]
        if not a:
            continue
        if a == gateway or (not seen_gw and h["ttl"] == 1):
            seen_gw = True
            continue
        if system.is_cgnat(a):
            path["cgnat"] = True
        if system.is_private(a) and not system.is_cgnat(a) and path["isp_hop"] is None:
            if path["modem_hop"] is None:
                path["modem_hop"] = a
                path["double_nat"] = True
            continue
        if path["isp_hop"] is None:
            path["isp_hop"] = a
            break
    return path


def collect(cfg, quick=False, router_cache=None, path_cache=None, with_speedtest=False, progress=None, ping_count=None):
    """progress(step, state): step in computer/link/router/line/provider/sites/speed, state in run/done."""
    def step(name, state="done"):
        if progress:
            try:
                progress(name, state)
            except Exception:  # noqa: BLE001
                pass

    t0 = time.time()
    snap = {"time": system.now_str(), "host": system.hostname()}
    step("computer", "run")
    net = system.network_state()
    step("computer")
    step("link", "run")
    snap["net"] = net
    gw = cfg.get("gateway") or net.get("gateway")
    snap["gateway"] = gw
    snap["gateway_mac"] = system.gateway_mac(gw) if gw else None
    snap["gateway_vendor"] = routers.vendor_by_mac(snap["gateway_mac"])
    primary = net.get("primary") or {}
    snap["wifi"] = system.wifi_state() if primary.get("is_wifi") or not primary else None

    if path_cache and path_cache.get("gateway") == gw and path_cache.get("isp_hop"):
        path = path_cache
    else:
        path = discover_path(cfg["anchors"][1] if len(cfg["anchors"]) > 1 else "8.8.8.8", gw) if gw else {}
        path["gateway"] = gw
        if path_cache is not None and path.get("isp_hop"):
            path_cache.clear()
            path_cache.update(path)
    if cfg.get("isp_hop"):
        path["isp_hop"] = cfg["isp_hop"]
    snap["path"] = path

    count = ping_count or (5 if quick else 20)
    targets = {}
    if gw:
        targets["gateway"] = gw
    if path.get("modem_hop"):
        targets["modem"] = path["modem_hop"]
    if (cfg.get("ont") or {}).get("host") and cfg["ont"]["host"] != path.get("modem_hop"):
        targets["ont"] = cfg["ont"]["host"]
    if path.get("isp_hop"):
        targets["isp_hop"] = path["isp_hop"]
    for a in cfg["anchors"]:
        targets[f"anchor:{a}"] = a

    with ThreadPoolExecutor(max_workers=16) as ex:
        fut_pings = {k: ex.submit(icmp.ping_series, ip, count, cfg["ping_timeout_ms"], 0.2) for k, ip in targets.items()}
        dns_servers = primary.get("dns") or []
        fut_dns = ex.submit(system.dns_check, dns_servers, cfg["dns_test_name"])
        fut_http = ex.submit(system.http_check, cfg["http_check_url"], cfg["http_check_expect"])
        fut_gw_tcp = ex.submit(lambda: {p: system.tcp_connect(gw, p, 1.5) for p in (80, 443)} if gw else {})
        fut_router = ex.submit(routers.collect_router, cfg["router"], gw, snap["gateway_mac"], not quick, router_cache)
        fut_ont = ex.submit(routers.collect_ont, cfg.get("ont"), not quick)
        fut_events = None if quick else ex.submit(system.recent_events, 24, primary.get("driver_service"))
        fut_scan = None if quick else ex.submit(wifi.scan_from_pc)

        # wait in chain order so progress is reported step by step
        pings = {}
        for k in ("gateway", "modem", "ont"):
            if k in fut_pings:
                pings[k] = fut_pings[k].result()
        snap["gateway_tcp"] = fut_gw_tcp.result()
        step("link")
        step("router", "run")
        try:
            snap["router"] = fut_router.result()
        except Exception as e:  # noqa: BLE001
            snap["router"] = {"type": "error", "notes": [f"Ошибка опроса роутера: {e}"], "wan": {}, "ports": []}
        step("router")
        step("line", "run")
        if "isp_hop" in fut_pings:
            pings["isp_hop"] = fut_pings["isp_hop"].result()
        step("line")
        step("provider", "run")
        pings.update({k: f.result() for k, f in fut_pings.items()})
        snap["pings"] = {k: dict(v, ip=targets[k]) for k, v in pings.items()}
        step("provider")
        step("sites", "run")
        snap["dns"] = fut_dns.result()
        snap["http"] = fut_http.result()
        step("sites")
        try:
            snap["ont"] = fut_ont.result()
        except Exception as e:  # noqa: BLE001
            snap["ont"] = {"type": "error", "notes": [str(e)]}
        snap["events"] = fut_events.result() if fut_events else []
        pc_scan = fut_scan.result() if fut_scan else []

    r = snap.get("router") or {}
    scan = (r.get("wifi_scan") or []) + pc_scan
    own_ssids = {x.get("ssid") for x in r.get("wifi_radios") or []}
    if snap["wifi"] and snap["wifi"].get("ssid"):
        own_ssids.add(snap["wifi"]["ssid"])
    own_bssids = {snap["wifi"].get("bssid")} if snap["wifi"] else set()
    if scan or r.get("wifi_radios") or snap["wifi"]:
        snap["wifi_analysis"] = wifi.analyze(scan, own_ssids, own_bssids, r.get("wifi_radios"), snap["wifi"])
        snap["wifi_scan"] = scan
    snap["wifi_location_blocked"] = wifi.LOCATION_BLOCKED
    if with_speedtest:
        step("speed", "run")
        pt = {k: targets[k] for k in ("gateway", "isp_hop") if k in targets}
        snap["speedtest"] = system.speedtest(cfg["speedtest_url"], ping_targets=pt)
        step("speed")
    snap["duration_sec"] = round(time.time() - t0, 1)
    return snap
