from collections import deque
from dataclasses import dataclass
from typing import Deque, Dict, Hashable, Optional
import time

@dataclass
class SlidingCounter:
    """
    Sliding window: store timestamps in a deque and remove entries older than window_sec
    """
    window_sec: int
    data: Dict[Hashable, Deque[float]]

    def __init__(self, window_sec: int):
        self.window_sec = int(window_sec)
        self.data = {}

    def add(self, key: Hashable, ts: Optional[float] = None) -> int:
        if ts is None:
            ts = time.time()
        q = self.data.get(key)
        if q is None:
            q = deque()
            self.data[key] = q
        q.append(ts)
        self._cleanup(q, ts)
        return len(q)

    def count(self, key: Hashable, now: Optional[float] = None) -> int:
        if now is None:
            now = time.time()
        q = self.data.get(key)
        if not q:
            return 0
        self._cleanup(q, now)
        return len(q)

    def _cleanup(self, q: Deque[float], now: float) -> None:
        border = now - self.window_sec
        while q and q[0] < border:
            q.popleft()