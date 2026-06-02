"""'How is the network right now' verdict + human-readable events feed."""
from __future__ import annotations
import json
import time
import psutil

from store import store
from sysinfo import SERVICES, service_status, suricata_socket_stat
import mikrotik_client
import unifi_client

def _build_health_status() -> dict:
    """Produce a single 'how is the network right now' verdict in plain Czech.

    Levels: ok | warn | bad
    """
    issues: list[dict] = []

    # Services
    bad_services = []
    for unit, label, _ in SERVICES:
        s = service_status(unit)
        if s["active"] != "active":
            bad_services.append(label)
    if bad_services:
        issues.append({
            "level": "bad",
            "icon": "❌",
            "text": f"Služba neběží: {', '.join(bad_services)}",
        })

    # Recent critical alerts
    crit_24h = store._query(
        "SELECT COUNT(*) AS n FROM alerts WHERE ts > ? AND severity = 1",
        (time.time() - 86400,)
    )
    crit = crit_24h[0]["n"] if crit_24h else 0
    if crit > 0:
        issues.append({
            "level": "warn",
            "icon": "⚠️",
            "text": f"{crit} kritických alertů za 24h",
        })

    # Known-bad attackers (AbuseIPDB ≥ 80 or VT ≥ 5) in last 24h
    bad_attackers = store._query("""
        SELECT COUNT(DISTINCT a.src_ip) AS n
        FROM alerts a
        JOIN enrichment e ON a.src_ip = e.ip
        WHERE a.ts > ?
          AND (e.abuse_score >= 80 OR e.vt_malicious >= 5)
    """, (time.time() - 86400,))
    nbad = bad_attackers[0]["n"] if bad_attackers else 0
    if nbad > 0:
        # Firewall/IDS already blocked these → informational, NOT a warning.
        # Doesn't downgrade the banner from green.
        issues.append({
            "level": "info",
            "icon": "🛡️",
            "text": f"{nbad} škodlivých IP odraženo (firewall + IDS) · jen FYI",
        })

    # Suricata drops
    suri_iface = suricata_socket_stat()
    if suri_iface.get("drop", 0) > 0:
        issues.append({
            "level": "warn",
            "icon": "📉",
            "text": f"Suricata ztrácí pakety ({suri_iface['drop']})",
        })

    # Disk space
    disk = psutil.disk_usage("/")
    if disk.percent > 90:
        issues.append({"level": "bad", "icon": "💾", "text": f"Disk plný: {disk.percent}%"})
    elif disk.percent > 80:
        issues.append({"level": "warn", "icon": "💾", "text": f"Disk skoro plný: {disk.percent}%"})

    # MikroTik unreachable
    if mikrotik_client.client and mikrotik_client.client.get().get("last_error"):
        issues.append({
            "level": "bad", "icon": "🔌",
            "text": "MikroTik API nedostupné",
        })
    if unifi_client.client and unifi_client.client.get().get("last_error"):
        issues.append({
            "level": "warn", "icon": "📡",
            "text": "UniFi API nedostupné",
        })

    # Banner level: bad > warn > (info/none → green). Info items NEVER turn it yellow.
    _crit = store._query("SELECT COUNT(*) AS n FROM alerts WHERE ts > ? AND severity = 1", (time.time() - 3600,))
    crit_count = _crit[0]["n"] if _crit else 0   # skutečně KRITICKÉ (severity 1), konzistentní s donutem Závažnost
    new_devs_5min = len(store.devices_first_seen_recently(minutes=5))
    has_bad = any(i["level"] == "bad" for i in issues)
    has_warn = any(i["level"] == "warn" for i in issues)

    if has_bad:
        level = "bad"
        headline = "Pozor · něco nefunguje"
        sub = "Něco vyžaduje akci — viz seznam níže, klikni pro detail."
    elif has_warn:
        level = "warn"
        n_warn = sum(1 for i in issues if i["level"] == "warn")
        headline = f"Vše běží · {n_warn} {'věc ke kontrole' if n_warn == 1 else 'věci ke kontrole'}"
        sub = "Nic akutního, jen FYI · firewall + IDS drží situaci pod kontrolou."
    else:
        # Green — even if there are info chips (e.g. bad IPs blocked).
        level = "ok"
        headline = "Klid · vše OK"
        sub = (f"Posledních 60 min: ✓ {crit_count} kritických alertů · "
               f"✓ {new_devs_5min} nových zařízení · ✓ všechny služby běží. "
               "Firewall + IDS drží perimetr.")

    return {"level": level, "headline": headline, "sub": sub, "issues": issues}


def _build_events_feed(max_items: int = 20) -> list[dict]:
    """A human-readable feed of recent significant events, newest first."""
    events: list[dict] = []
    now = time.time()

    # Recent alerts grouped by source IP (within 10 min window)
    grouped = store._query("""
        SELECT src_ip, COUNT(*) AS hits, MAX(ts) AS last_ts, MAX(signature) AS sig, country_code
        FROM alerts WHERE ts > ?
        GROUP BY src_ip ORDER BY last_ts DESC LIMIT 20
    """, (now - 3600,))
    for g in grouped:
        if not g["src_ip"]:
            continue
        events.append({
            "ts": g["last_ts"],
            "icon": "🚨",
            "kind": "alert",
            "title": f"Útočník {g['src_ip']}",
            "text": f"{g['hits']}× alertů za poslední hodinu — poslední: {(g['sig'] or '?')[:50]}",
            "ip": g["src_ip"],
        })

    # Newly seen devices
    new_devs = store.devices_first_seen_recently(minutes=60)
    for d in new_devs[:10]:
        host = d.get("hostname") or "(neznámé)"
        events.append({
            "ts": d["first_seen"],
            "icon": "📱",
            "kind": "device",
            "title": "Nové zařízení v síti",
            "text": f"{host} · {d.get('ip','?')} · {d.get('vendor') or 'neznámý vendor'}",
        })

    # Firewall drop spikes
    spikes = store._query("""
        SELECT src_ip, COUNT(*) AS n, MAX(ts) AS last_ts
        FROM firewall_drops WHERE ts > ?
        GROUP BY src_ip HAVING n >= 50 ORDER BY n DESC LIMIT 5
    """, (now - 3600,))
    for s in spikes:
        events.append({
            "ts": s["last_ts"],
            "icon": "🚧",
            "kind": "firewall",
            "title": f"Firewall pětkrát dropuje {s['src_ip']}",
            "text": f"{s['n']} dropů za posledních 60 min",
            "ip": s["src_ip"],
        })

    # Recent push notifications sent
    notifs = store._query(
        "SELECT ts, kind, key, payload FROM notifications WHERE ts > ? ORDER BY ts DESC LIMIT 5",
        (now - 24 * 3600,)
    )
    for n in notifs:
        try:
            payload = json.loads(n["payload"]) if n.get("payload") else {}
        except Exception:
            payload = {}
        events.append({
            "ts": n["ts"],
            "icon": "🔔",
            "kind": "notify",
            "title": payload.get("title") or n["kind"],
            "text": (payload.get("body") or "")[:120],
        })

    events.sort(key=lambda x: x["ts"], reverse=True)
    out = []
    for e in events[:max_items]:
        # human-readable timedelta in Czech
        delta = now - (e["ts"] or now)
        if delta < 60:
            ago = "právě teď"
        elif delta < 3600:
            ago = f"před {int(delta/60)} min"
        elif delta < 86400:
            ago = f"před {int(delta/3600)} h"
        else:
            ago = f"před {int(delta/86400)} dny"
        e["ago"] = ago
        out.append(e)
    return out
