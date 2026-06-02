"""ntfy push notifications + rule engine.

Background thread evaluates rules on a fixed cadence and pushes deduped
notifications via the self-hosted ntfy server.
"""

from __future__ import annotations

import time
from threading import Thread
from typing import Any

import requests
from requests.auth import HTTPBasicAuth

import config
from store import store

# ---------------------------------------------------------------------------
# ntfy publisher
# ---------------------------------------------------------------------------

def _auth():
    return HTTPBasicAuth(config.NTFY_USER, config.NTFY_PASS or "") if config.NTFY_PASS else None


def publish(topic: str, title: str, body: str, priority: int = 3, tags: list[str] | None = None) -> bool:
    """priority: 1=min ... 5=max. tags: emoji-style strings."""
    if not config.NTFY_PASS:
        return False
    headers = {
        "Title": title,
        "Priority": str(priority),
        "X-Title": title,
    }
    if tags:
        headers["Tags"] = ",".join(tags)
    try:
        r = requests.post(
            f"{config.NTFY_URL}/{topic}",
            data=body.encode("utf-8"),
            headers=headers,
            auth=_auth(),
            timeout=5,
        )
        return r.status_code in (200, 201)
    except Exception:
        return False


def fire(kind: str, key: str, title: str, body: str, *,
         topic: str | None = None, priority: int = 3, tags: list[str] | None = None,
         cooldown_min: int | None = None) -> bool:
    """Send a notification only if (kind, key) wasn't fired recently."""
    cd = cooldown_min if cooldown_min is not None else config.NOTIFY_COOLDOWN_MIN
    if store.notify_was_recent(kind, key, cd):
        return False
    topic = topic or config.NTFY_TOPIC_SECURITY
    ok = publish(topic, title, body, priority=priority, tags=tags)
    if ok:
        store.notify_record(kind, key, {"title": title, "body": body, "topic": topic, "priority": priority})
    return ok


# ---------------------------------------------------------------------------
# Rules
# ---------------------------------------------------------------------------

def _rule_critical_alert_burst() -> None:
    """Suricata: ≥3 unique src IPs hitting same critical (sev<=1) signature in 10min."""
    cutoff = time.time() - 10 * 60
    rows = store._query(
        "SELECT signature, COUNT(DISTINCT src_ip) AS n_src, COUNT(*) AS hits "
        "FROM alerts WHERE ts > ? AND severity = 1 GROUP BY signature HAVING n_src >= 3",
        (cutoff,)
    )
    for r in rows:
        sig = (r["signature"] or "?")[:80]
        fire(
            kind="critical-burst",
            key=sig,
            title=f"⚠️ Kritický burst: {sig}",
            body=f"{r['n_src']} unikátních zdrojů, {r['hits']} alertů za 10 min.\nOtevři dashboard a EveBox.",
            priority=5,
            tags=["warning", "rotating_light"],
        )


def _rule_known_bad_attacker() -> None:
    """Source IP with AbuseIPDB score >= 80 OR VT malicious >= 5."""
    cutoff = time.time() - 60 * 60
    attackers = store._query(
        "SELECT a.src_ip, COUNT(*) AS hits FROM alerts a WHERE a.ts > ? AND a.src_ip IS NOT NULL "
        "GROUP BY a.src_ip ORDER BY hits DESC LIMIT 50",
        (cutoff,)
    )
    for a in attackers:
        ip = a["src_ip"]
        en = store.get_enrichment(ip, max_age_hours=72)
        if not en:
            continue
        bad_abuse = (en.get("abuse_score") or 0) >= 80
        bad_vt = (en.get("vt_malicious") or 0) >= 5
        if not (bad_abuse or bad_vt):
            continue
        reasons = []
        if bad_abuse:
            reasons.append(f"AbuseIPDB {en['abuse_score']}/100 ({en.get('abuse_reports',0)} reportů)")
        if bad_vt:
            reasons.append(f"VT {en['vt_malicious']} malicious")
        fire(
            kind="known-bad-ip",
            key=ip,
            title=f"🚩 Známě špatná IP útočí: {ip}",
            body=f"{a['hits']} alertů za hod.\n{en.get('vt_country') or en.get('abuse_country') or '?'} · {en.get('abuse_isp') or en.get('vt_as_owner') or '?'}\n{' · '.join(reasons)}",
            priority=4,
            tags=["triangular_flag_on_post"],
            cooldown_min=180,
        )


def _rule_new_device() -> None:
    """Brand-new MAC seen on the network in the last 5 min."""
    devs = store.devices_first_seen_recently(minutes=5)
    for d in devs:
        host = d.get("hostname") or "(neznámé)"
        vendor = d.get("vendor") or "?"
        ip = d.get("ip") or "?"
        mac = d.get("mac")
        fire(
            kind="new-device",
            key=mac,
            topic=config.NTFY_TOPIC_INFO,
            title=f"📱 Nové zařízení v síti",
            body=f"{host} ({mac})\nIP: {ip} · Vendor: {vendor}",
            priority=3,
            tags=["mobile_phone_off"],
            cooldown_min=24 * 60,   # one alert per MAC per day
        )


def _rule_service_down() -> None:
    """Any of our critical services went down."""
    # We don't have direct access to current service status here; the
    # dashboard endpoint already shows that. Push if any of the unit
    # status files report not-active.
    import subprocess
    units = ["suricata-wan", "ntopng-wan", "evebox-local", "tzsp-replay"]
    for u in units:
        try:
            r = subprocess.run(["systemctl", "is-active", u], capture_output=True, text=True, timeout=2)
            state = r.stdout.strip()
            if state != "active":
                fire(
                    kind="service-down",
                    key=u,
                    title=f"❌ Služba {u} neběží",
                    body=f"Stav: {state}\nZkontroluj 'journalctl -u {u}'",
                    priority=5,
                    tags=["x", "rotating_light"],
                    cooldown_min=15,
                )
        except Exception:
            pass


def _rule_firewall_drop_spike() -> None:
    """Sudden spike: >100 drops from a single source in 10 min."""
    cutoff = time.time() - 10 * 60
    rows = store._query(
        "SELECT src_ip, COUNT(*) AS hits FROM firewall_drops WHERE ts > ? AND src_ip IS NOT NULL "
        "GROUP BY src_ip HAVING hits > 100 ORDER BY hits DESC LIMIT 5",
        (cutoff,)
    )
    for r in rows:
        ip = r["src_ip"]
        en = store.get_enrichment(ip, max_age_hours=72) or {}
        country = en.get("abuse_country") or en.get("vt_country") or "?"
        fire(
            kind="drop-spike",
            key=ip,
            title=f"🚧 Firewall drop spike: {ip}",
            body=f"{r['hits']} dropů za 10 min · {country}",
            priority=4,
            tags=["construction"],
        )


RULES = [
    _rule_critical_alert_burst,
    _rule_known_bad_attacker,
    _rule_new_device,
    _rule_service_down,
    _rule_firewall_drop_spike,
]


def _loop() -> None:
    # Allow other modules to fully start
    time.sleep(15)
    while True:
        for rule in RULES:
            try:
                rule()
            except Exception:
                pass
        time.sleep(60)  # evaluate rules every minute


def start_background() -> None:
    Thread(target=_loop, daemon=True).start()
