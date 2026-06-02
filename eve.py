"""eve.json tail: background thread keeping a rolling window of recent Suricata events."""
from __future__ import annotations
import json
import time
from collections import deque
from pathlib import Path
from threading import Lock, Thread

EVE_PATH = Path("/var/log/suricata/eve.json")


class EveTail:
    """Background thread that tails eve.json and keeps recent events in memory.

    Keeps alerts in a separate, larger deque so KPIs over 24h don't lose them
    when high-volume flow/stats events push them out of the general buffer.
    """

    def __init__(self, path: Path, max_events: int = 2000, max_alerts: int = 2000) -> None:
        self.path = path
        self.events: deque[dict] = deque(maxlen=max_events)
        self.alerts: deque[dict] = deque(maxlen=max_alerts)
        self.lock = Lock()
        self.inode = None
        self.pos = 0
        self._stop = False
        self.thread = Thread(target=self._run, daemon=True)
        self.thread.start()

    def _seed_from_tail(self) -> None:
        """Read last 2 MB so the live tail is warm; SQLite holds the 30d history."""
        try:
            size = self.path.stat().st_size
            with self.path.open("rb") as f:
                start = max(0, size - 2 * 1024 * 1024)
                f.seek(start)
                if start > 0:
                    f.readline()  # discard partial line
                for raw in f:
                    self._ingest(raw)
                self.pos = f.tell()
                self.inode = self.path.stat().st_ino
        except FileNotFoundError:
            pass

    def _ingest(self, raw: bytes) -> None:
        try:
            ev = json.loads(raw)
        except Exception:
            return
        with self.lock:
            self.events.append(ev)
            if ev.get("event_type") == "alert":
                self.alerts.append(ev)

    def _run(self) -> None:
        self._seed_from_tail()
        while not self._stop:
            try:
                st = self.path.stat()
            except FileNotFoundError:
                time.sleep(2)
                continue
            if self.inode is None or st.st_ino != self.inode or st.st_size < self.pos:
                self.inode = st.st_ino
                self.pos = 0
            if st.st_size > self.pos:
                try:
                    with self.path.open("rb") as f:
                        f.seek(self.pos)
                        for raw in f:
                            if raw.endswith(b"\n"):
                                self._ingest(raw)
                                self.pos = f.tell()
                            else:
                                break
                except Exception:
                    pass
            time.sleep(1)

    def snapshot(self) -> list[dict]:
        with self.lock:
            return list(self.events)

    def snapshot_alerts(self) -> list[dict]:
        with self.lock:
            return list(self.alerts)


eve_tail = EveTail(EVE_PATH)
