"""Snapshot per-device and per-interface traffic into SQLite every 5 min."""

from __future__ import annotations

import logging
import time
from threading import Thread

import mikrotik_client
import ntopng_client
from store import store

log = logging.getLogger("netwatch")

SNAPSHOT_INTERVAL_S = 5 * 60


def _classify_interface(name: str, kind: str | None, comment: str | None) -> str | None:
    """WAN / LAN / VPN classification. Returns None for skipped interfaces.

    LAN = the `bridge` aggregate ONLY. We must NOT also sum the bridge member
    ports (ether1-4) or the VLAN SVIs — on RouterOS the same frames are counted
    on the bridge AND on every member/vlan, so summing them double/triple-counts
    (that's why LAN looked like 55 GB instead of ~43 GB).
    """
    name_l = (name or "").lower()
    comment_l = (comment or "").lower()
    if "wan" in comment_l or name_l == "ether5":
        return "wan"
    if kind == "lte":
        return "wan"   # LTE failover = taky WAN (jinak se provoz při výpadku optiky nepočítá)
    if kind == "wg" or "vpn" in comment_l or "vpn" in name_l:
        return "vpn"
    # LAN = bridge aggregate only (single source of truth for internal traffic)
    if kind == "bridge":
        return "lan"
    return None


def _snapshot_devices() -> None:
    if not ntopng_client.client:
        return
    snap = ntopng_client.client.get()
    hosts = snap.get("hosts_local", [])
    samples = []
    for h in hosts:
        if not h.get("ip"):
            continue
        if (h.get("tx_bytes") or 0) + (h.get("rx_bytes") or 0) == 0:
            continue
        samples.append({
            "ip": h.get("ip"),
            "mac": h.get("mac"),
            "name": h.get("name"),
            "tx_bytes": h.get("tx_bytes", 0),
            "rx_bytes": h.get("rx_bytes", 0),
        })
    if samples:
        store.insert_device_traffic(samples)


def _snapshot_interfaces() -> None:
    if not mikrotik_client.client:
        return
    snap = mikrotik_client.client.get()
    ifaces = snap.get("interfaces", [])
    samples = []
    for i in ifaces:
        cat = _classify_interface(i.get("name"), i.get("type"), i.get("comment"))
        if not cat:
            continue
        samples.append({
            "name": i.get("name"),
            "category": cat,
            "rx_bytes": i.get("rx_byte") or 0,
            "tx_bytes": i.get("tx_byte") or 0,
        })
    if samples:
        store.insert_interface_traffic(samples)


def _loop() -> None:
    time.sleep(70)
    while True:
        try:
            _snapshot_devices()
        except Exception:
            log.warning("snapshot zařízení selhal", exc_info=True)
        try:
            _snapshot_interfaces()
        except Exception:
            log.warning("snapshot rozhraní selhal", exc_info=True)
        time.sleep(SNAPSHOT_INTERVAL_S)


def start_background() -> None:
    Thread(target=_loop, daemon=True).start()
