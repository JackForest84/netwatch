"""AdGuard Home REST API client - supports multiple instances.

Each instance is polled in its own background thread; the dashboard surfaces
merged stats across all instances plus per-instance breakdowns.
"""

from __future__ import annotations

import time
from threading import Lock, Thread
from typing import Any

import requests
from requests.auth import HTTPBasicAuth

import config


class AdGuardInstance:
    def __init__(self, conf: dict) -> None:
        self.name = conf.get("name", "?")
        self.url = (conf.get("url") or "").rstrip("/")
        self.session = requests.Session()
        self.session.auth = HTTPBasicAuth(conf.get("user", ""), conf.get("pass", ""))
        self.session.headers["Accept"] = "application/json"
        self.timeout = 5
        self.lock = Lock()
        self.snapshot: dict[str, Any] = {
            "name": self.name,
            "url": self.url,
            "status": {},
            "stats": {},
            "querylog_recent": [],
            "clients": [],
            "last_fetch": None,
            "last_error": None,
        }
        Thread(target=self._loop, daemon=True).start()

    def _get(self, path: str, params: dict | None = None) -> Any:
        r = self.session.get(f"{self.url}{path}", params=params or {}, timeout=self.timeout)
        r.raise_for_status()
        return r.json()

    def _fetch(self) -> dict[str, Any]:
        data: dict[str, Any] = {"name": self.name, "url": self.url}
        try:
            data["status"] = self._get("/control/status")
        except Exception:
            data["status"] = {}
        try:
            data["stats"] = self._get("/control/stats")
        except Exception:
            data["stats"] = {}
        # Persistent clients (named ones, with display names + identifiers)
        try:
            cl = self._get("/control/clients")
            data["clients"] = cl.get("clients") if isinstance(cl, dict) else cl
        except Exception:
            data["clients"] = []
        # Recent query log (last 50)
        try:
            ql = self._get("/control/querylog", params={"limit": 50})
            data["querylog_recent"] = ql.get("data", [])[:50] if isinstance(ql, dict) else []
        except Exception:
            data["querylog_recent"] = []
        data["last_fetch"] = time.time()
        return data

    def _loop(self) -> None:
        while True:
            try:
                snap = self._fetch()
                with self.lock:
                    snap["last_error"] = None
                    self.snapshot = snap
            except Exception as e:
                with self.lock:
                    self.snapshot["last_error"] = str(e)
                    self.snapshot["last_fetch"] = time.time()
            time.sleep(config.ADGUARD_POLL_SECONDS)

    def get(self) -> dict[str, Any]:
        with self.lock:
            return dict(self.snapshot)


class AdGuardClient:
    """Multi-instance wrapper. Provides per-instance and merged views."""

    def __init__(self, instances_conf: list[dict]) -> None:
        self.instances: list[AdGuardInstance] = [AdGuardInstance(c) for c in instances_conf]

    def get_all(self) -> list[dict]:
        return [inst.get() for inst in self.instances]

    def merged(self) -> dict[str, Any]:
        snaps = self.get_all()
        running = sum(1 for s in snaps if s.get("status", {}).get("running"))
        total_q = sum((s.get("stats") or {}).get("num_dns_queries", 0) for s in snaps)
        total_blocked = sum((s.get("stats") or {}).get("num_blocked_filtering", 0) for s in snaps)
        total_safesearch = sum((s.get("stats") or {}).get("num_replaced_safesearch", 0) for s in snaps)
        total_safebrowsing = sum((s.get("stats") or {}).get("num_replaced_safebrowsing", 0) for s in snaps)
        total_parental = sum((s.get("stats") or {}).get("num_replaced_parental", 0) for s in snaps)
        avg_proc = 0.0
        if snaps:
            procs = [(s.get("stats") or {}).get("avg_processing_time", 0) for s in snaps]
            avg_proc = sum(procs) / len(procs) if procs else 0

        # Merge top lists by summing across instances. Items in AdGuard look like
        # {"some.domain.com": 123}.
        from collections import Counter
        def merge_top(key: str) -> list[dict]:
            c: Counter = Counter()
            for s in snaps:
                items = (s.get("stats") or {}).get(key) or []
                for item in items:
                    if isinstance(item, dict):
                        for dom, cnt in item.items():
                            c[dom] += cnt
            return [{"name": k, "count": v} for k, v in c.most_common(20)]

        return {
            "instances_total": len(snaps),
            "instances_running": running,
            "queries_24h": total_q,
            "blocked_24h": total_blocked,
            "safesearch_24h": total_safesearch,
            "safebrowsing_24h": total_safebrowsing,
            "parental_24h": total_parental,
            "block_rate_pct": round(total_blocked * 100 / total_q, 1) if total_q else 0,
            "avg_processing_s": round(avg_proc, 4),
            "top_clients": merge_top("top_clients"),
            "top_queried": merge_top("top_queried_domains"),
            "top_blocked": merge_top("top_blocked_domains"),
            "top_upstreams": merge_top("top_upstreams_responses"),
            "per_instance": [
                {
                    "name": s["name"],
                    "url": s["url"],
                    "running": (s.get("status") or {}).get("running"),
                    "version": (s.get("status") or {}).get("version"),
                    "queries_24h": (s.get("stats") or {}).get("num_dns_queries", 0),
                    "blocked_24h": (s.get("stats") or {}).get("num_blocked_filtering", 0),
                    "block_rate_pct": round((s.get("stats") or {}).get("num_blocked_filtering", 0)
                                            * 100 / max((s.get("stats") or {}).get("num_dns_queries", 1), 1), 1),
                    "avg_processing_s": round((s.get("stats") or {}).get("avg_processing_time", 0), 4),
                    "dns_addresses": (s.get("status") or {}).get("dns_addresses", []),
                    "last_error": s.get("last_error"),
                }
                for s in snaps
            ],
        }

    def recent_queries(self, limit: int = 30) -> list[dict]:
        """Most recent queries across instances, sorted by time desc."""
        all_q: list[dict] = []
        for s in self.get_all():
            name = s.get("name")
            for q in s.get("querylog_recent", []):
                q = dict(q)
                q["__instance"] = name
                all_q.append(q)
        all_q.sort(key=lambda x: x.get("time", ""), reverse=True)
        return all_q[:limit]


client = AdGuardClient(config.ADGUARD_INSTANCES) if config.ADGUARD_INSTANCES else None
