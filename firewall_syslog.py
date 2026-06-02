"""Lossless firewall-drop capture via remote syslog (ADR 0009).

The old path polled `/rest/log` for the last 50 lines every 30 s — under WAN
attack volume the router's in-memory log ring buffer wraps faster than that, so
drops were lost and the dashboard could only confirm ~87 % of IDS-detected IPs.

Here the MikroTik pushes every WAN deny/blocklist-drop (log-prefix `IN_DENY_WAN`)
to this server over UDP syslog; we ingest 100 % of them in real time. While syslog
is flowing, `firewall_log` polling stands down (see `recent()`), so there is no
double-counting.
"""

from __future__ import annotations

import logging
import socket
import time
from threading import Thread

import config
from firewall_log import _parse_entry
from store import store

log = logging.getLogger("netwatch.fwsyslog")

# Only ingest our WAN deny/drop lines (ignore address-list adds, IPsec, etc.).
_DROP_MARKERS = ("IN_DENY_WAN",)

_last_packet_ts = 0.0


def recent(within_s: float = 300) -> bool:
    """True if a syslog drop arrived recently → the REST poll fallback stands down
    so the two sources don't both write firewall_drops."""
    return (time.time() - _last_packet_ts) < within_s


def _message_body(raw: str) -> str:
    """Reduce an RFC3164 syslog line ('<pri>mon dd hh:mm:ss host topics MSG') to the
    firewall message, starting at our log-prefix so `_parse_entry` sees the in:/proto/
    IP->IP tail it expects."""
    for m in _DROP_MARKERS:
        j = raw.find(m)
        if j != -1:
            return raw[j:]
    return raw


def _loop() -> None:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        sock.bind(("0.0.0.0", config.FIREWALL_SYSLOG_PORT))
    except OSError as e:
        log.warning("firewall syslog bind failed on udp/%s — %s", config.FIREWALL_SYSLOG_PORT, e)
        return
    log.info("firewall syslog collector listening on udp/%s", config.FIREWALL_SYSLOG_PORT)
    sock.settimeout(2.0)
    global _last_packet_ts
    buf: list[dict] = []
    last_flush = time.time()
    while True:
        try:
            data, _ = sock.recvfrom(8192)
            raw = data.decode("utf-8", "replace").strip()
            if not any(m in raw for m in _DROP_MARKERS):
                continue
            _last_packet_ts = time.time()
            d = _parse_entry({"message": _message_body(raw), "topics": "firewall", "time": ""})
            if d and d.get("src_ip"):
                d["ts"] = time.time()
                buf.append(d)
        except socket.timeout:
            pass
        except Exception:
            log.warning("syslog parse failed", exc_info=True)
        if buf and (time.time() - last_flush) > 2:
            try:
                store.insert_drops(buf)
            except Exception:
                log.warning("syslog insert_drops failed", exc_info=True)
            buf = []
            last_flush = time.time()


def start_background() -> None:
    Thread(target=_loop, daemon=True).start()
