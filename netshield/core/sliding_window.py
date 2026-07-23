"""Zaman pencereli IP paket sayacı."""

import time
from collections import defaultdict, deque


class SW:
    """Belirli bir zaman aralığındaki kayıtları IP bazında sayar."""

    def __init__(self, window: float = 1.0) -> None:
        self.w = window
        self._d = defaultdict(deque)

    def add(self, ip: str, ts: float | None = None) -> int:
        if ts is None:
            ts = time.monotonic()

        records = self._d[ip]
        records.append(ts)

        cutoff = ts - self.w
        while records and records[0] < cutoff:
            records.popleft()

        return len(records)

    def count(self, ip: str) -> int:
        ts = time.monotonic()
        records = self._d[ip]

        cutoff = ts - self.w
        while records and records[0] < cutoff:
            records.popleft()

        return len(records)

    def purge(self) -> None:
        now = time.monotonic()

        inactive_ips = [
            ip
            for ip, records in self._d.items()
            if not records or now - records[-1] > 120
        ]

        for ip in inactive_ips:
            del self._d[ip]
