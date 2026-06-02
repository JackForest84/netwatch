"""MikroTik RouterOS 7 REST API client with background polling cache."""

from __future__ import annotations

import json
import time
import urllib3
from threading import Lock, Thread
from typing import Any

import requests
from requests.auth import HTTPBasicAuth

import config

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class MikroTikClient:
    """Polls MikroTik REST endpoints in the background and serves cached snapshots."""

    def __init__(self) -> None:
        self.session = requests.Session()
        self.session.auth = HTTPBasicAuth(config.MIKROTIK_USER, config.MIKROTIK_PASS or "")
        self.session.verify = config.MIKROTIK_VERIFY_TLS
        self.session.headers["Accept"] = "application/json"
        self.timeout = 6

        self.lock = Lock()
        self.snapshot: dict[str, Any] = {
            "resource": {},
            "interfaces": [],
            "leases": [],
            "arp": [],
            "connections_count": 0,
            "wireguard_peers": [],
            "port_forwards": [],
            "logs_recent": [],
            "last_fetch": None,
            "last_error": None,
        }
        Thread(target=self._loop, daemon=True).start()

    def _get(self, path: str) -> Any:
        url = f"{config.MIKROTIK_URL}{path}"
        r = self.session.get(url, timeout=self.timeout)
        r.raise_for_status()
        return r.json()

    def _fetch_all(self) -> dict[str, Any]:
        data: dict[str, Any] = {}

        # System resources
        try:
            data["resource"] = self._get("/rest/system/resource")
        except Exception as e:
            data["resource"] = {}
            data["_resource_err"] = str(e)

        # Interfaces
        try:
            ifaces_raw = self._get("/rest/interface")
            ifaces = []
            for i in ifaces_raw:
                if i.get("name", "").startswith("lo"):
                    continue
                ifaces.append({
                    "name": i.get("name"),
                    "type": i.get("type"),
                    "running": i.get("running") == "true",
                    "disabled": i.get("disabled") == "true",
                    "rx_byte": int(i.get("rx-byte", 0)),
                    "tx_byte": int(i.get("tx-byte", 0)),
                    "rx_packet": int(i.get("rx-packet", 0)),
                    "tx_packet": int(i.get("tx-packet", 0)),
                    "mac": i.get("mac-address"),
                    "comment": i.get("comment") or "",
                })
            data["interfaces"] = ifaces
        except Exception:
            data["interfaces"] = []

        # DHCP leases
        try:
            raw = self._get("/rest/ip/dhcp-server/lease")
            leases = []
            for l in raw:
                leases.append({
                    "ip": l.get("active-address") or l.get("address"),
                    "mac": (l.get("active-mac-address") or l.get("mac-address") or "").upper(),
                    "hostname": l.get("host-name") or "",
                    "status": l.get("status"),
                    "last_seen": l.get("last-seen"),
                    "expires_after": l.get("expires-after"),
                    "dynamic": l.get("dynamic") == "true",
                    "blocked": l.get("blocked") == "true",
                    "server": l.get("server"),
                    "comment": l.get("comment") or "",
                })
            data["leases"] = leases
        except Exception:
            data["leases"] = []

        # ARP table
        try:
            raw = self._get("/rest/ip/arp")
            arp = []
            for a in raw:
                arp.append({
                    "ip": a.get("address"),
                    "mac": (a.get("mac-address") or "").upper(),
                    "interface": a.get("interface"),
                    "complete": a.get("complete") == "true",
                    "dynamic": a.get("dynamic") == "true",
                })
            data["arp"] = arp
        except Exception:
            data["arp"] = []

        # Connection count (slow on large tables — count only)
        try:
            raw = self._get("/rest/ip/firewall/connection")
            data["connections_count"] = len(raw)
        except Exception:
            data["connections_count"] = 0

        # Firewall filter rules with hit counts (bytes + packets per rule)
        try:
            raw = self._get("/rest/ip/firewall/filter")
            rules = []
            for r in raw:
                rules.append({
                    "id":       r.get(".id"),
                    "chain":    r.get("chain"),
                    "action":   r.get("action"),
                    "comment":  r.get("comment") or "",
                    "bytes":    int(r.get("bytes", 0)),
                    "packets":  int(r.get("packets", 0)),
                    "disabled": r.get("disabled") == "true",
                    "dynamic":  r.get("dynamic") == "true",
                    "invalid":  r.get("invalid") == "true",
                })
            data["firewall_rules"] = rules
        except Exception:
            data["firewall_rules"] = []

        # Active inbound port-forwards (dst-nat from WAN) = the real exposed surface (ADR 0005)
        try:
            raw = self._get("/rest/ip/firewall/nat")
            pfs = []
            for n in raw:
                if n.get("action") != "dst-nat" or n.get("disabled") == "true":
                    continue
                iface = (n.get("in-interface") or "").lower()
                iflist = (n.get("in-interface-list") or "").lower()
                if "wan" not in iface and "wan" not in iflist:
                    continue  # internal redirect (e.g. force-DNS), not a WAN exposure
                pfs.append({
                    "dst_port": n.get("dst-port"),
                    "protocol": n.get("protocol"),
                    "to": n.get("to-addresses"),
                    "comment": n.get("comment") or "",
                })
            data["port_forwards"] = pfs
        except Exception:
            data["port_forwards"] = []

        # WireGuard peers (if configured)
        try:
            raw = self._get("/rest/interface/wireguard/peers")
            peers = []
            for p in raw:
                peers.append({
                    "interface": p.get("interface"),
                    "comment": p.get("comment") or "",
                    "endpoint": p.get("current-endpoint-address"),
                    "rx": int(p.get("rx", 0)),
                    "tx": int(p.get("tx", 0)),
                    "last_handshake": p.get("last-handshake"),
                    "disabled": p.get("disabled") == "true",
                })
            data["wireguard_peers"] = peers
        except Exception:
            data["wireguard_peers"] = []

        # Recent log entries (last 50 from system log)
        try:
            raw = self._get("/rest/log")
            logs = []
            for l in raw[-50:]:
                logs.append({
                    "time": l.get("time"),
                    "topics": l.get("topics"),
                    "message": l.get("message"),
                })
            data["logs_recent"] = logs
        except Exception:
            data["logs_recent"] = []

        data["last_fetch"] = time.time()
        return data

    def _loop(self) -> None:
        while True:
            try:
                snap = self._fetch_all()
                with self.lock:
                    snap["last_error"] = None
                    self.snapshot = snap
            except Exception as e:
                with self.lock:
                    self.snapshot["last_error"] = str(e)
                    self.snapshot["last_fetch"] = time.time()
            time.sleep(config.API_POLL_SECONDS)

    def get(self) -> dict[str, Any]:
        with self.lock:
            return dict(self.snapshot)


# Module-level singleton
client = MikroTikClient() if config.MIKROTIK_PASS else None
