"""UniFi Network Integration API client with background polling cache."""

from __future__ import annotations

import time
import urllib3
from threading import Lock, Thread
from typing import Any

import requests

import config

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class UnifiClient:
    """Polls UniFi REST endpoints in the background and serves cached snapshots."""

    def __init__(self) -> None:
        self.session = requests.Session()
        self.session.headers.update({
            "X-API-KEY": config.UNIFI_API_KEY or "",
            "Accept": "application/json",
        })
        self.session.verify = config.UNIFI_VERIFY_TLS
        self.timeout = 8
        self.base = f"{config.UNIFI_URL}/proxy/network/integration/v1"
        self.site_id = config.UNIFI_SITE_ID

        self.lock = Lock()
        self.snapshot: dict[str, Any] = {
            "info": {},
            "devices": [],
            "clients": [],
            "last_fetch": None,
            "last_error": None,
        }
        Thread(target=self._loop, daemon=True).start()

    def _get_paginated(self, path: str, limit: int = 200) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        offset = 0
        while True:
            url = f"{self.base}{path}"
            r = self.session.get(url, params={"offset": offset, "limit": limit}, timeout=self.timeout)
            r.raise_for_status()
            data = r.json()
            page = data.get("data", [])
            out.extend(page)
            total = data.get("totalCount", len(out))
            if len(out) >= total or not page:
                break
            offset += limit
        return out

    def _get_one(self, path: str) -> dict[str, Any]:
        r = self.session.get(f"{self.base}{path}", timeout=self.timeout)
        r.raise_for_status()
        return r.json()

    def _fetch_all(self) -> dict[str, Any]:
        data: dict[str, Any] = {}

        try:
            data["info"] = self._get_one("/info")
        except Exception:
            data["info"] = {}

        # Devices (APs and switches)
        try:
            raw = self._get_paginated(f"/sites/{self.site_id}/devices")
            devices = []
            for d in raw:
                devices.append({
                    "id": d.get("id"),
                    "name": d.get("name") or "?",
                    "model": d.get("model") or "?",
                    "mac": (d.get("macAddress") or "").upper(),
                    "ip": d.get("ipAddress"),
                    "state": d.get("state"),
                    "features": d.get("features", []),
                    "uptime": d.get("uptimeSec"),
                    "version": d.get("firmwareVersion"),
                })
            data["devices"] = devices
        except Exception as e:
            data["devices"] = []
            data["_devices_err"] = str(e)

        # Clients (connected wireless / wired)
        try:
            raw = self._get_paginated(f"/sites/{self.site_id}/clients")
            clients = []
            for c in raw:
                clients.append({
                    "id": c.get("id"),
                    "name": c.get("name") or c.get("displayName") or c.get("macAddress"),
                    "mac": (c.get("macAddress") or "").upper(),
                    "ip": c.get("ipAddress"),
                    "type": c.get("type"),                # WIRED / WIRELESS
                    "connected_at": c.get("connectedAt"),
                    "access_id": c.get("access", {}).get("id") if isinstance(c.get("access"), dict) else None,
                    "uplink_device_id": c.get("uplinkDeviceId"),
                })
            data["clients"] = clients
        except Exception:
            data["clients"] = []

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


client = UnifiClient() if config.UNIFI_API_KEY else None
