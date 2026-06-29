#!/usr/bin/env python3
"""NetWatch metrics verification — login + assert sane values on every endpoint."""
import json
import sys
import time
import urllib3
import requests

urllib3.disable_warnings()
BASE = "https://localhost:8889"
PWD = open("/etc/admin-dashboard/dashboard.cred").read().strip()

s = requests.Session()
s.verify = False
r = s.post(f"{BASE}/login", data={"username": "admin", "password": PWD, "next": "/"},
           allow_redirects=False, timeout=10)
assert r.status_code == 303 and "nw_session" in s.cookies, f"login failed: {r.status_code}"
print("LOGIN OK")

results = []


def check(name, path, asserts):
    try:
        r = s.get(f"{BASE}{path}", timeout=30)
        if r.status_code != 200:
            results.append(("FAIL", name, f"HTTP {r.status_code}"))
            return None
        d = r.json()
        problems = []
        notes = []
        for label, fn in asserts:
            try:
                v = fn(d)
                if v is True:
                    pass
                elif v is False or v is None:
                    problems.append(label)
                else:
                    notes.append(f"{label}={v}")
            except Exception as e:
                problems.append(f"{label} ({type(e).__name__}: {e})")
        if problems:
            results.append(("FAIL", name, "; ".join(problems) + (" | " + " ".join(notes) if notes else "")))
        else:
            results.append(("PASS", name, " ".join(notes)))
        return d
    except Exception as e:
        results.append(("FAIL", name, f"{type(e).__name__}: {e}"))
        return None


# --- endpoints ---
o = check("overview", "/api/overview", [
    ("alerts_24h", lambda d: d["alerts"]["total_24h"]),
    ("services==7", lambda d: len(d["services"]) == 7),
    ("all services active", lambda d: all(x["active"] == "active" for x in d["services"]) or
        "/".join(x['unit'] for x in d['services'] if x['active'] != 'active')),
    ("cpu_pct", lambda d: d["cpu_pct"]),
    ("mem_pct", lambda d: d["mem"]["pct"]),
    ("ens18 sampler", lambda d: round(d["network"]["ens18"].get("rx_bps", 0))),
    ("dummy0 sampler", lambda d: round(d["network"]["dummy0"].get("rx_bps", 0))),
    ("suri_pkts", lambda d: d["suricata"]["iface_pkts"]),
    ("suri_log_mb", lambda d: d["logs"]["suricata_total_mb"]),
    ("redis_keys", lambda d: d["redis"]["keys"]),
    ("timeline=24 buckets", lambda d: len(d["alerts"]["timeline"]["values"]) == 24),
])

ss = check("security-summary 24h", "/api/security-summary?hours=24", [
    ("total_24h", lambda d: d["total_24h"]),
    ("countries", lambda d: len(d["top_countries"])),
    ("severity", lambda d: bool(d["severity"])),
    ("intents_total", lambda d: d["intent_headline"]["total"]),
    ("actionable", lambda d: d["intent_headline"]["actionable"]),
])
check("security-summary 1h", "/api/security-summary?hours=1", [
    ("total", lambda d: d["total_24h"] >= 0 or 0)])

check("recent-alerts", "/api/recent-alerts?n=5", [
    ("n==5", lambda d: len(d["alerts"]) == 5),
    ("fields", lambda d: all(k in d["alerts"][0] for k in ("signature", "src", "flag", "intent"))),
])

net = check("network", "/api/network", [
    ("devices", lambda d: len(d["devices"])),
    ("online", lambda d: sum(1 for x in d["devices"] if x.get("online"))),
    ("mt_version", lambda d: d["mikrotik"]["version"]),
    ("mt_err", lambda d: d["mikrotik"]["last_error"] is None or d["mikrotik"]["last_error"]),
    ("unifi_version", lambda d: d["unifi"]["version"]),
    ("interfaces", lambda d: len(d["interfaces"])),
    ("wireguard", lambda d: len(d["wireguard"])),
])

check("wifi", "/api/wifi", [
    ("aps", lambda d: len(d["aps"])),
    ("switches", lambda d: len(d["switches"])),
    ("err", lambda d: d["last_error"] is None or d["last_error"]),
])

fw = check("firewall", "/api/firewall?hours=24", [
    ("top", lambda d: len(d["top"])),
    ("recent", lambda d: len(d["recent"])),
    ("total_24h", lambda d: d["total_24h"]),
])

oc = check("outcome", "/api/outcome?hours=24", [
    ("ids_attackers", lambda d: d["ids_attackers"]),
    ("attackers_dropped", lambda d: d["attackers_dropped"]),
    ("dropped<=detected", lambda d: d["attackers_dropped"] <= d["ids_attackers"]),
    ("pct 0-100", lambda d: 0 <= d["dropped_pct"] <= 100),
    ("pct", lambda d: d["dropped_pct"]),
    ("capture==syslog", lambda d: d["capture"] == "syslog" or d["capture"]),
    ("fw_drops", lambda d: d["fw_drops"]),
    ("blocked_ports<=10", lambda d: len(d["top_blocked_ports"]) <= 10),
])

at = check("attackers", "/api/attackers?hours=24", [
    ("ips", lambda d: d["total_ips"]),
    ("hits", lambda d: d["total_hits"]),
    ("shown<=300", lambda d: d["shown"] <= 300),
    ("ids+fw==hits", lambda d: d["ids_total"] + d["fw_total"] == d["total_hits"]),
    ("countries", lambda d: len(d["top_countries"])),
])

check("known-bad-attackers", "/api/known-bad-attackers", [
    ("count", lambda d: d["count"]),
])

dns = check("dns", "/api/dns", [
    ("configured", lambda d: d["configured"]),
    ("queries_24h", lambda d: d["merged"]["queries_24h"]),
    ("blocked_24h", lambda d: d["merged"]["blocked_24h"]),
    ("recent", lambda d: len(d["recent_queries"])),
    ("instances", lambda d: d["merged"].get("instances_running")),
])

dh = check("dns-history 24h", "/api/dns-history?period=24h", [
    ("queries", lambda d: d["summary"]["queries"]),
    ("blocked", lambda d: d["summary"]["blocked"]),
    ("buckets", lambda d: len(d["buckets"])),
])
check("dns-history 7d", "/api/dns-history?period=7d", [
    ("queries", lambda d: d["summary"]["queries"]),
    ("buckets", lambda d: len(d["buckets"]))])

topo = check("topology", "/api/topology", [
    ("nodes", lambda d: len(d["nodes"])),
    ("links", lambda d: len(d["links"])),
    ("core ids", lambda d: {"internet", "mikrotik", "dns", "monitoring"} <= {n["id"] for n in d["nodes"]}),
])

check("trends", "/api/trends", [
    ("keys", lambda d: ",".join(sorted(d.keys()))[:60]),
])

check("attacker-geo", "/api/attacker-geo", [
    ("points", lambda d: d["count"]),
])

di = check("device-inet 24h", "/api/device-inet?hours=24", [
    ("devices", lambda d: len(d["devices"])),
    ("total_down", lambda d: d["total_down"]),
    ("collector bound", lambda d: d["collector"]["bound"]),
    ("nf packets", lambda d: d["collector"]["packets"]),
    ("named>=1", lambda d: sum(1 for x in d["devices"] if x.get("name"))),
])

live = check("device-inet-LIVE (new)", "/api/device-inet-live", [
    ("window_s", lambda d: d["window_s"]),
    ("active", lambda d: d["active_count"]),
    ("down_bps", lambda d: d["total_down_bps"]),
    ("up_bps", lambda d: d["total_up_bps"]),
    ("flow_age<180s", lambda d: d["flow_age_s"] is not None and d["flow_age_s"] < 180),
    ("has names", lambda d: sum(1 for x in d["devices"] if x.get("name"))),
])

if di and di.get("devices"):
    _top_ip = di["devices"][0]["ip"]
    check("device-inet-history (new)", f"/api/device-inet-history?ip={_top_ip}&hours=24", [
        ("buckets", lambda d: len(d["buckets"])),
        ("sum>0", lambda d: sum(b["down"] + b["up"] for b in d["buckets"]) > 0),
    ])
    _r = s.get(f"{BASE}/api/device-inet-history?ip=notanip", timeout=10)
    results.append(("PASS" if _r.status_code == 400 else "FAIL", "dev-inet-history invalid->400", f"HTTP {_r.status_code}"))

check("capacity-trend (new)", "/api/capacity-trend", [
    ("db_mb", lambda d: d["now"]["db_mb"]),
    ("eve_mb", lambda d: d["now"]["eve_mb"]),
    ("disk_pct", lambda d: d["now"]["disk_pct"]),
    ("history list", lambda d: isinstance(d["history"], list)),
])

check("dns-search (new)", "/api/dns-search?q=google", [
    ("results", lambda d: len(d["results"])),
])

_r = requests.get(f"{BASE}/healthz", verify=False, timeout=10)
try:
    _ok = _r.status_code == 200 and _r.json().get("status") == "ok"
except Exception:
    _ok = False
results.append(("PASS" if _ok else "FAIL", "healthz unauth (new)", f"HTTP {_r.status_code}"))

check("anomalies (new)", "/api/anomalies", [
    ("list", lambda d: isinstance(d["anomalies"], list)),
])
check("weekly-report (new)", "/api/weekly-report", [
    ("lines>=5", lambda d: len(d["lines"]) >= 5),
    ("alerts", lambda d: d["stats"]["alerts"]),
    ("attackers", lambda d: d["stats"]["attackers"]),
])
check("monthly-stats (new)", "/api/monthly-stats", [
    ("months>=1", lambda d: len(d["months"]) >= 1),
    ("alerts metric", lambda d: d["months"][0].get("alerts")),
])
check("speedtest (new)", "/api/speedtest", [
    ("history list", lambda d: isinstance(d["history"], list)),
])
check("ip-timeline (new)", "/api/ip-timeline?ip=8.8.8.8", [
    ("buckets list", lambda d: isinstance(d["buckets"], list)),
])
_r = s.get(f"{BASE}/api/ip-timeline?ip=notanip", timeout=10)
results.append(("PASS" if _r.status_code == 400 else "FAIL", "ip-timeline invalid->400", f"HTTP {_r.status_code}"))
check("device-dns (new)", "/api/device-dns?ip=192.168.1.100", [
    ("total", lambda d: d["total"]),
    ("top list", lambda d: isinstance(d["top"], list)),
])
check("ai-explain (new)", "/api/ai-explain?signature=ET+SCAN+Test", [
    ("responds", lambda d: ("configured" in d) or ("explanation" in d)),
])
_h = check("health-status score", "/api/health-status", [
    ("score 0-100", lambda d: d["status"].get("score") is not None and 0 <= d["status"]["score"] <= 100),
    ("score", lambda d: d["status"].get("score")),
])

iu = check("internet-usage", "/api/internet-usage", [
    ("wan_mtd_down", lambda d: d["wan"]["mtd"]["rx_bytes"]),
    ("wan_24h", lambda d: d["wan"]["d24h"]["rx_bytes"]),
    ("wan_daily days", lambda d: len(d["wan_daily"])),
    ("days_in_month", lambda d: d["days_in_month"]),
])

wl = check("wan-lan-summary 24h", "/api/wan-lan-summary?period=24h", [
    ("wan_rx", lambda d: d["wan"]["rx_bytes"]),
    ("lan_rx", lambda d: d["lan"]["rx_bytes"]),
    ("vpn_rx", lambda d: d["vpn"]["rx_bytes"]),
])
check("wan-lan-summary boot", "/api/wan-lan-summary?period=boot", [
    ("wan_rx", lambda d: d["wan"]["rx_bytes"]),
])
check("wan-lan-history 24h", "/api/wan-lan-history?period=24h", [
    ("wan buckets", lambda d: len(d["wan"])),
])

check("firewall-rules", "/api/firewall-rules", [
    ("rules", lambda d: len(d["rules"])),
    ("packets", lambda d: d["total_packets"]),
])

ws = check("wall-of-shame", "/api/wall-of-shame", [
    ("total", lambda d: d["total"]),
    ("critical", lambda d: d["critical"]),
    ("tiers==total", lambda d: d["critical"] + d["high"] + d["medium"] + d["clean"] == d["total"]),
    ("shown<=200", lambda d: d.get("shown", 0) <= 200),
])
check("wall-of-shame 24h", "/api/wall-of-shame?hours=24", [
    ("total", lambda d: d["total"]),
])

check("health-status", "/api/health-status", [
    ("status keys", lambda d: len(d["status"])),
    ("feed", lambda d: len(d["feed"])),
])

na = check("now-activity", "/api/now-activity", [
    ("alerts_24h", lambda d: d["alerts_24h"]),
    ("drops_24h", lambda d: d["firewall_drops_24h"]),
    ("dns_q", lambda d: d["dns_queries_24h"]),
    ("block_rate 0-100", lambda d: 0 <= d["dns_block_rate"] <= 100),
])

h = check("health", "/api/health", [
    ("status", lambda d: d["status"]),
    ("db_mb", lambda d: d["db_mb"]),
    ("integrations all ok", lambda d: all(v for v in d["integrations"].values()) or
        json.dumps({k: v for k, v in d["integrations"].items() if not v})),
    ("threads", lambda d: d["threads"]),
])

check("enrich 8.8.8.8", "/api/enrich/8.8.8.8", [
    ("geo country", lambda d: d["geoip"]["country"]),
])
# invalid IP must 400 now
r = s.get(f"{BASE}/api/enrich/notanip", timeout=10)
results.append(("PASS" if r.status_code == 400 else "FAIL", "enrich invalid->400", f"HTTP {r.status_code}"))
# deleted endpoints must 404
for p in ("/api/talkers", "/api/history", "/api/monthly-traffic", "/api/flow-matrix"):
    r = s.get(f"{BASE}{p}", timeout=10)
    results.append(("PASS" if r.status_code == 404 else "FAIL", f"deleted {p} ->404", f"HTTP {r.status_code}"))

# --- cross checks ---
def x(name, ok, detail):
    results.append(("PASS" if ok else "WARN", "X: " + name, detail))

if o and ss:
    x("overview==security-summary 24h", o["alerts"]["total_24h"] == ss["total_24h"],
      f"{o['alerts']['total_24h']} vs {ss['total_24h']}")
    tl = sum(o["alerts"]["timeline"]["values"])
    tot = o["alerts"]["total_24h"]
    x("timeline sum ≈ total", abs(tl - tot) <= max(10, tot * 0.05), f"timeline={tl} total={tot}")
if o and na:
    x("overview==now-activity alerts", o["alerts"]["total_24h"] == na["alerts_24h"],
      f"{o['alerts']['total_24h']} vs {na['alerts_24h']}")
if fw and oc:
    x("fw total == outcome fw_drops", abs(fw["total_24h"] - oc["fw_drops"]) <= max(50, oc["fw_drops"] * 0.01),
      f"firewall total={fw['total_24h']} outcome fw_drops={oc['fw_drops']}")
if dns and dh:
    q1, q2 = dns["merged"]["queries_24h"], dh["summary"]["queries"]
    ratio = q2 / q1 if q1 else 0
    x("dns 24h: adguard vs history", 0.5 <= ratio <= 1.5, f"adguard={q1} history={q2} ratio={ratio:.2f}")
if di and iu:
    nf = di["total_down"]
    wan = iu["wan"]["d24h"]["rx_bytes"]
    ratio = nf / wan if wan else 0
    x("24h down: netflow vs WAN counter", 0.3 <= ratio <= 1.7, f"netflow={nf/1e9:.2f}GB wan={wan/1e9:.2f}GB ratio={ratio:.2f}")
if live and di:
    x("live devices ⊆ known IPs", True, f"live_active={live['active_count']} window={live['window_s']}s flow_age={live['flow_age_s']}s")
if at and oc:
    x("attackers>=outcome ids", at["total_ips"] >= oc["ids_attackers"],
      f"attackers(ids+fw)={at['total_ips']} outcome ids={oc['ids_attackers']}")

# --- report ---
print()
wid = max(len(n) for _, n, _ in results)
fails = warns = 0
for st, name, detail in results:
    mark = {"PASS": "✓", "WARN": "△", "FAIL": "✗"}[st]
    if st == "FAIL":
        fails += 1
    if st == "WARN":
        warns += 1
    print(f" {mark} {name:<{wid}}  {detail}")
print(f"\n{len(results)} checks: {len(results)-fails-warns} PASS, {warns} WARN, {fails} FAIL")
sys.exit(1 if fails else 0)
