"""Speedtest bez závislostí: Cloudflare __down/__up + TCP latence (vlna 3).

Měří cestu server → internet (server visí na 2.5G switchi za MikroTikem, takže
prakticky měří WAN). Běží à 6 h + na vyžádání z UI; výsledky v tabulce speedtest.
Spotřeba dat ~33 MB na test (4× denně ≈ 130 MB/den) — u optiky zanedbatelné.
"""
from __future__ import annotations

import logging
import socket
import threading
import time

import requests

from store import store

log = logging.getLogger("netwatch.speedtest")

INTERVAL_S = 6 * 3600
DOWN_BYTES = 25_000_000
UP_BYTES = 8_000_000
_running = threading.Lock()   # jen jeden test naráz (ať si neměří sám do cesty)


def _latency_ms(host: str = "1.1.1.1", port: int = 443, n: int = 5) -> float | None:
    vals = []
    for _ in range(n):
        t0 = time.perf_counter()
        try:
            s = socket.create_connection((host, port), timeout=3)
            s.close()
            vals.append((time.perf_counter() - t0) * 1000)
        except Exception:
            pass
    vals.sort()
    return round(vals[len(vals) // 2], 1) if vals else None


def run_test() -> dict | None:
    if not _running.acquire(blocking=False):
        return None   # už běží
    try:
        lat = _latency_ms()
        t0 = time.perf_counter()
        got = 0
        with requests.get(f"https://speed.cloudflare.com/__down?bytes={DOWN_BYTES}",
                          stream=True, timeout=60) as r:
            r.raise_for_status()
            for chunk in r.iter_content(256 * 1024):
                got += len(chunk)
        down = round(got * 8 / (time.perf_counter() - t0) / 1e6, 1)

        t0 = time.perf_counter()
        requests.post("https://speed.cloudflare.com/__up", data=b"\0" * UP_BYTES, timeout=60)
        up = round(UP_BYTES * 8 / (time.perf_counter() - t0) / 1e6, 1)

        store._exec("INSERT INTO speedtest (ts, down_mbps, up_mbps, latency_ms) VALUES (?,?,?,?)",
                    (time.time(), down, up, lat))
        log.info("speedtest: ↓%.1f ↑%.1f Mb/s · %s ms", down, up, lat)
        return {"down_mbps": down, "up_mbps": up, "latency_ms": lat}
    except Exception:
        log.warning("speedtest selhal", exc_info=True)
        return None
    finally:
        _running.release()


def run_async() -> bool:
    """Spustí test na pozadí (tlačítko v UI). False = už běží."""
    if _running.locked():
        return False
    threading.Thread(target=run_test, daemon=True, name="speedtest-once").start()
    return True


def _loop() -> None:
    time.sleep(300)   # první test 5 min po startu (ať nezkresluje warmup)
    while True:
        run_test()
        time.sleep(INTERVAL_S)


def start_background() -> None:
    threading.Thread(target=_loop, daemon=True, name="speedtest").start()
