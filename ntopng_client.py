"""ntopng REST API v2 client with cookie-session and cached polling.

Surfaces:
  - system_stats (epoch, mem, CPU, alerts queue)
  - active_hosts (local devices with traffic counts)
  - top_local_hosts (top talkers by bytes/throughput)
  - apps (DPI application breakdown)
"""

from __future__ import annotations

import time
from threading import Lock, Thread
from typing import Any

import requests

import config


class NtopngClient:
    def __init__(self) -> None:
        self.session = requests.Session()
        self.timeout = 6
        self.ifid = config.NTOPNG_IFID
        self.logged_in = False
        self.lock = Lock()
        self.snapshot: dict[str, Any] = {
            "system_stats": {},
            "hosts_local": [],
            "top_talkers": [],
            "apps": [],
            "interfaces": [],
            "last_fetch": None,
            "last_error": None,
        }
        if config.NTOPNG_PASS:
            Thread(target=self._loop, daemon=True).start()

    def _login(self) -> bool:
        try:
            r = self.session.post(
                f"{config.NTOPNG_URL}/authorize.html",
                data={
                    "user": config.NTOPNG_USER,
                    "password": config.NTOPNG_PASS or "",
                    "referer": "",
                },
                timeout=self.timeout,
                allow_redirects=False,
            )
            # 302 + any session_* cookie means success
            cookies = self.session.cookies.get_dict()
            self.logged_in = r.status_code == 302 and any(k.startswith("session") for k in cookies)
            return self.logged_in
        except Exception:
            self.logged_in = False
            return False

    def _get(self, path: str, params: dict | None = None) -> Any:
        for _ in range(2):
            if not self.logged_in and not self._login():
                raise RuntimeError("ntopng login failed")
            r = self.session.get(
                f"{config.NTOPNG_URL}{path}",
                params=params or {},
                timeout=self.timeout,
                allow_redirects=False,
            )
            if r.status_code in (302, 401, 403):
                # session expired
                self.logged_in = False
                continue
            r.raise_for_status()
            try:
                return r.json()
            except Exception:
                return {}
        raise RuntimeError("ntopng auth retry exhausted")

    def _fetch(self) -> dict[str, Any]:
        data: dict[str, Any] = {}
        try:
            d = self._get("/lua/rest/v2/get/system/stats.lua")
            data["system_stats"] = d.get("rsp", {})
        except Exception as e:
            data["system_stats"] = {}
            data["_sys_err"] = str(e)

        # Interfaces overview
        try:
            d = self._get("/lua/rest/v2/get/interface/data.lua", {"ifid": self.ifid})
            data["interfaces"] = [d.get("rsp", {})] if d.get("rsp") else []
        except Exception:
            data["interfaces"] = []

        # Active local hosts with traffic (sorted by bytes desc, paginated)
        try:
            d = self._get("/lua/rest/v2/get/host/active.lua",
                          {"ifid": self.ifid, "mode": "local", "perPage": 100,
                           "sortColumn": "column_traffic", "sortOrder": "desc"})
            rsp = d.get("rsp") or {}
            hosts_raw = rsp.get("data") if isinstance(rsp, dict) else rsp
            if not isinstance(hosts_raw, list):
                hosts_raw = []
            hosts: list[dict] = []
            for h in hosts_raw:
                if not isinstance(h, dict):
                    continue
                ip = h.get("ip") or h.get("name")
                if not ip:
                    continue
                # Skip IPv6 link-local entries — they duplicate the IPv4 host
                if str(ip).startswith("fe80:"):
                    continue
                bytes_obj = h.get("bytes") or {}
                thpt = h.get("thpt") or {}
                flows = h.get("num_flows") or {}
                hosts.append({
                    "ip": ip,
                    "name": (h.get("name") or ip).split(" ")[0],
                    "mac": (h.get("mac") or "").upper(),
                    "tx_bytes": int((bytes_obj.get("sent") if isinstance(bytes_obj, dict) else 0) or 0),
                    "rx_bytes": int((bytes_obj.get("recvd") if isinstance(bytes_obj, dict) else 0) or 0),
                    "total_bytes": int((bytes_obj.get("total") if isinstance(bytes_obj, dict) else bytes_obj) or 0),
                    "thpt_bps": float((thpt.get("bps") if isinstance(thpt, dict) else thpt) or 0),
                    "thpt_pps": float((thpt.get("pps") if isinstance(thpt, dict) else 0) or 0),
                    "active_flows": int((flows.get("total") if isinstance(flows, dict) else flows) or 0),
                    "num_alerts": int(h.get("num_alerts") or 0),
                    "country": h.get("country"),
                    "last_seen": h.get("last_seen"),
                })
            data["hosts_local"] = hosts
        except Exception as e:
            data["hosts_local"] = []
            data["_hosts_err"] = str(e)

        # Top talkers = same list, top 15 by total_bytes
        hosts = data.get("hosts_local", [])
        top = sorted(hosts, key=lambda h: h["total_bytes"], reverse=True)[:15]
        data["top_talkers"] = top

        # L7/DPI app breakdown — ntopng community REST API is limited, skip for now
        data["apps"] = []

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
            time.sleep(60)

    def get(self) -> dict[str, Any]:
        with self.lock:
            return dict(self.snapshot)


client = NtopngClient() if config.NTOPNG_PASS else None
