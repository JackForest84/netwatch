"""Parse MikroTik firewall log entries into structured rows.

MikroTik prefix=<chain> log entries look like:
  "input: in:ether1 out:(unknown 0), proto TCP (SYN), 1.2.3.4:42:42-> 10.0.0.5:22, len 60"
  "drop input: in:ether1 out:(none), src-mac aa:..., proto UDP, 1.2.3.4:5678->10.0.0.5:53, len 100"

We accept both the bare and the more verbose forms. Anything we can't parse
falls into the raw column for later inspection.
"""

from __future__ import annotations

import re
import time
from datetime import datetime, timezone, timedelta
from threading import Thread
from typing import Iterable

import config
import mikrotik_client
from store import store

# Common parts
_RE_IP_PORT = r"(?P<src_ip>\d{1,3}(?:\.\d{1,3}){3})(?::(?P<src_port>\d+))?->(?P<dst_ip>\d{1,3}(?:\.\d{1,3}){3})(?::(?P<dst_port>\d+))?"
_RE_PROTO  = r"proto (?P<proto>\w+)"
_RE_IFACE  = r"in:(?P<iin>[^\s,]+) out:(?P<iout>[^\s,]+)"
_RE_CHAIN  = r"^(?P<chain>[a-zA-Z\-_]+)?:?\s*"

PARSE = re.compile(
    rf"{_RE_CHAIN}.*?{_RE_IFACE}.*?{_RE_PROTO}.*?{_RE_IP_PORT}",
    re.IGNORECASE,
)


def _parse_mt_time(time_str: str) -> float:
    """MikroTik /log entries have time like 'sep/01 15:23:42' or 'oct/14 02:11:05'.

    Best-effort: assume current year, server local TZ.
    """
    if not time_str:
        return time.time()
    try:
        # Some routers return ISO; try that first
        return datetime.fromisoformat(time_str).timestamp()
    except Exception:
        pass
    try:
        now = datetime.now()
        # "sep/01 15:23:42" or "01:23:42" if same day
        parts = time_str.split()
        if len(parts) == 2:
            mon_day, hms = parts
            mon_str, day_str = mon_day.split("/")
            months = {"jan":1,"feb":2,"mar":3,"apr":4,"may":5,"jun":6,
                      "jul":7,"aug":8,"sep":9,"oct":10,"nov":11,"dec":12}
            mon = months.get(mon_str.lower(), now.month)
            day = int(day_str)
            h, m, s = (int(x) for x in hms.split(":"))
            dt = datetime(now.year, mon, day, h, m, s)
            if dt > now + timedelta(days=2):  # year rollover
                dt = dt.replace(year=now.year - 1)
            return dt.timestamp()
        elif len(parts) == 1 and parts[0].count(":") == 2:
            h, m, s = (int(x) for x in parts[0].split(":"))
            dt = now.replace(hour=h, minute=m, second=s, microsecond=0)
            if dt > now:
                dt -= timedelta(days=1)
            return dt.timestamp()
    except Exception:
        pass
    return time.time()


def _parse_entry(e: dict) -> dict | None:
    msg = e.get("message") or ""
    topics = e.get("topics") or ""
    if "firewall" not in topics and "drop" not in msg.lower():
        return None
    m = PARSE.search(msg)
    if not m:
        return {
            "ts": _parse_mt_time(e.get("time", "")),
            "chain": None, "src_ip": None, "dst_ip": None,
            "src_port": None, "dst_port": None, "proto": None,
            "iface_in": None, "iface_out": None,
            "raw": msg,
        }
    g = m.groupdict()
    return {
        "ts": _parse_mt_time(e.get("time", "")),
        "chain": (g.get("chain") or "").strip(":").strip() or None,
        "src_ip": g.get("src_ip"),
        "dst_ip": g.get("dst_ip"),
        "src_port": int(g["src_port"]) if g.get("src_port") else None,
        "dst_port": int(g["dst_port"]) if g.get("dst_port") else None,
        "proto": (g.get("proto") or "").upper() or None,
        "iface_in": g.get("iin"),
        "iface_out": g.get("iout"),
        "raw": msg,
    }


def harvest_once() -> int:
    if not mikrotik_client.client:
        return 0
    logs = mikrotik_client.client.get().get("logs_recent") or []
    drops: list[dict] = []
    for e in logs:
        d = _parse_entry(e)
        if d and d.get("src_ip"):
            drops.append(d)
    if drops:
        return store.insert_drops(drops)
    return 0


def _loop() -> None:
    time.sleep(10)
    seen_msgs: set[str] = set()
    while True:
        try:
            import firewall_syslog
            if firewall_syslog.recent():
                # syslog push is live and authoritative → don't double-count via poll
                time.sleep(30)
                continue
            if mikrotik_client.client:
                logs = mikrotik_client.client.get().get("logs_recent") or []
                new_drops = []
                for e in logs:
                    sig = f"{e.get('time','')}|{(e.get('message') or '')[:200]}"
                    if sig in seen_msgs:
                        continue
                    seen_msgs.add(sig)
                    d = _parse_entry(e)
                    if d:
                        new_drops.append(d)
                if new_drops:
                    store.insert_drops(new_drops)
                # Cap memory of seen_msgs
                if len(seen_msgs) > 5000:
                    seen_msgs = set(list(seen_msgs)[-2500:])
        except Exception:
            pass
        time.sleep(30)


def start_background() -> None:
    Thread(target=_loop, daemon=True).start()
