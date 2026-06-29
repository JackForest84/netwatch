"""NetFlow v9 collector — REAL per-device internet traffic (download/upload).

MikroTik Traffic-Flow exports NetFlow v9 to udp/2055 (interfaces bridge+ether5).
Records are unidirectional (IN_BYTES) + carry NAT fields. Per-device attribution
(IPv4, LAN = 192.168.0.0/16):
  - src is a LAN device, dst is internet      -> that device's UPLOAD
  - postNAT-dst (field 226) is a LAN device   -> that device's DOWNLOAD
    (download enters on ether5 as dst=WAN-IP; field 226 holds the real device IP)

Accumulates per-device bytes and every FLUSH_S writes the delta to store.db
(table device_inet). Runs as a daemon thread started from app.py.
"""
from __future__ import annotations

import ipaddress
import logging
import socket
import struct
import threading
import time
from collections import defaultdict

from store import store

log = logging.getLogger("netwatch.netflow")

NETFLOW_PORT = 2055
FLUSH_S = 60
_LAN = ipaddress.ip_network("192.168.0.0/16")

# NetFlow v9 field type IDs we read
F_IN_BYTES, F_SRC, F_DST, F_PNAT_DST = 1, 8, 12, 226


def _is_dev(ip: str | None) -> bool:
    try:
        return bool(ip) and ipaddress.ip_address(ip) in _LAN
    except Exception:
        return False


def _is_inet(ip: str | None) -> bool:
    try:
        a = ipaddress.ip_address(ip)
        return a not in _LAN and not a.is_multicast and not a.is_reserved and not a.is_loopback
    except Exception:
        return False


def _num(b: bytes) -> int:
    return int.from_bytes(b, "big") if b else 0


def _ip4(b: bytes) -> str | None:
    return ".".join(map(str, b)) if len(b) == 4 else None


class NetflowCollector:
    def __init__(self) -> None:
        self.templates: dict[tuple[int, int], list[tuple[int, int]]] = {}
        self.up: dict[str, int] = defaultdict(int)
        self.down: dict[str, int] = defaultdict(int)
        self.lock = threading.Lock()
        self.packets = 0
        self.last_packet: float | None = None
        self.bound = False
        # live view: last completed flush window (for rolling ~1-2 min rates)
        self.last_rows: dict[str, tuple[int, int]] = {}   # ip -> (down, up)
        self.last_window: float = 0.0
        self.window_start: float = time.time()

    def _parse(self, data: bytes) -> None:
        if len(data) < 20 or struct.unpack("!H", data[:2])[0] != 9:
            return
        source_id = struct.unpack("!I", data[16:20])[0]
        self.packets += 1
        self.last_packet = time.time()
        off = 20
        while off + 4 <= len(data):
            fsid, length = struct.unpack("!HH", data[off:off + 4])
            if length < 4:
                break
            body = data[off + 4: off + length]
            if fsid == 0:  # template flowset
                p = 0
                while p + 4 <= len(body):
                    tid, fc = struct.unpack("!HH", body[p:p + 4])
                    p += 4
                    fields = []
                    for _ in range(fc):
                        if p + 4 > len(body):
                            break
                        ft, fl = struct.unpack("!HH", body[p:p + 4])
                        p += 4
                        fields.append((ft, fl))
                    if fields:
                        self.templates[(source_id, tid)] = fields
            elif fsid > 255:  # data flowset
                tmpl = self.templates.get((source_id, fsid))
                if not tmpl:
                    off += length
                    continue
                rl = sum(fl for _, fl in tmpl)
                p = 0
                while rl and p + rl <= len(body):
                    rec: dict[int, bytes] = {}
                    q = p
                    for ft, fl in tmpl:
                        if ft in (F_IN_BYTES, F_SRC, F_DST, F_PNAT_DST):
                            rec[ft] = body[q:q + fl]
                        q += fl
                    p += rl
                    src = _ip4(rec.get(F_SRC, b""))
                    dst = _ip4(rec.get(F_DST, b""))
                    pnat = _ip4(rec.get(F_PNAT_DST, b""))
                    by = _num(rec.get(F_IN_BYTES, b""))
                    if not by:
                        continue
                    if _is_dev(src) and not _is_dev(dst):
                        with self.lock:
                            self.up[src] += by
                    elif _is_dev(pnat) and _is_inet(src):
                        with self.lock:
                            self.down[pnat] += by
                    elif _is_dev(dst) and _is_inet(src):
                        with self.lock:
                            self.down[dst] += by
            off += length

    def _flush(self) -> None:
        now = time.time()
        with self.lock:
            ips = set(self.up) | set(self.down)
            rows = [(ip, int(self.down.get(ip, 0)), int(self.up.get(ip, 0))) for ip in ips]
            # rotate the live window even when empty, so live() rates stay honest
            self.last_rows = {ip: (d, u) for ip, d, u in rows}
            self.last_window = now - self.window_start
            self.window_start = now
            self.up.clear()
            self.down.clear()
        if not rows:
            return
        try:
            store.insert_device_inet(rows)
        except Exception:
            log.exception("netflow flush failed")

    def _serve(self) -> None:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            s.bind(("0.0.0.0", NETFLOW_PORT))
            self.bound = True
            log.info("netflow collector listening on udp/%d", NETFLOW_PORT)
        except Exception:
            log.exception("netflow bind failed on udp/%d", NETFLOW_PORT)
            return
        s.settimeout(FLUSH_S)
        last = time.time()
        while True:
            try:
                data, _ = s.recvfrom(8192)
                self._parse(data)
            except socket.timeout:
                pass
            except Exception:
                pass
            if time.time() - last >= FLUSH_S:
                self._flush()
                last = time.time()

    def start(self) -> None:
        threading.Thread(target=self._serve, daemon=True, name="netflow").start()

    def live(self) -> dict:
        """Rolling per-device rates: last completed flush window + the in-progress
        one (= data over the past ~60-120 s). NetFlow records arrive on flow expiry,
        so a shorter window would be lumpy, not more 'real-time' (ADR 0003)."""
        now = time.time()
        with self.lock:
            acc: dict[str, list[int]] = {ip: [d, u] for ip, (d, u) in self.last_rows.items()}
            for ip, b in self.down.items():
                acc.setdefault(ip, [0, 0])[0] += b
            for ip, b in self.up.items():
                acc.setdefault(ip, [0, 0])[1] += b
            window = max(1.0, self.last_window + (now - self.window_start))
            last_packet = self.last_packet
        devices = [
            {"ip": ip, "down_bytes": d, "up_bytes": u,
             "down_bps": round(d * 8 / window), "up_bps": round(u * 8 / window)}
            for ip, (d, u) in acc.items() if d + u > 0
        ]
        devices.sort(key=lambda x: x["down_bytes"] + x["up_bytes"], reverse=True)
        return {"window_s": round(window), "devices": devices, "last_packet": last_packet}

    def health(self) -> dict:
        return {"bound": self.bound, "packets": self.packets, "last_packet": self.last_packet}


collector = NetflowCollector()


def start_background() -> None:
    collector.start()
