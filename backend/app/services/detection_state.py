"""
Detection state (roadmap S6.2): the sliding windows and alert cooldowns the
anomaly detector keeps, in memory or in Redis.

    windows    recent probes per source (port scans, connection rate) and per
               source and login port (brute force), each trimmed to its window
    cooldowns  "this rule already alerted on this source" markers

With REDIS_URL set they live in Redis, so

  - a backend restart keeps them: a scan that started before the restart
    and goes on after it is still one scan, and a cooldown still holds;
  - several backend processes share them: a cooldown is claimed with an
    atomic SET NX, so only one process raises a given alert.

    windows    sorted set per key (score = probe time), trimmed by score and
               to the newest MAX entries, expiring after twice the window
    cooldowns  SET kguard:cd:<rule> 1 NX EX <cooldown seconds>

The short-lived trackers (half-open SYNs, spoofing and amplification
counters, a few seconds each) stay in memory.

If Redis cannot be reached, detection carries on with in-memory state and
says so (status "memory fallback"); Redis is tried again every 30 seconds.
"""

import json
import logging
import time
from collections import deque
from dataclasses import asdict
from typing import Any, Deque, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

PREFIX = "kguard:"
RETRY_SECONDS = 30


class MemoryState:
    name = "memory"

    def __init__(self):
        self.windows: Dict[str, Deque[Tuple[float, dict]]] = {}
        self.cooldowns: Dict[str, float] = {}  # key -> monotonic expiry

    def add(self, key: str, probes: List[dict], window_seconds: float, maxlen: int) -> List[dict]:
        window = self.windows.get(key)
        if window is None:
            window = self.windows[key] = deque()
        for p in probes:
            window.append((p["time"], p))
        while len(window) > maxlen:
            window.popleft()
        newest = max((t for t, _ in window), default=0.0)
        while window and window[0][0] < newest - window_seconds:
            window.popleft()
        return [p for _, p in sorted(window, key=lambda item: item[0])]

    def claim(self, key: str, seconds: float) -> bool:
        now = time.monotonic()
        if self.cooldowns.get(key, 0) > now:
            return False
        self.cooldowns[key] = now + seconds
        return True

    def start(self, key: str, seconds: float) -> None:
        self.cooldowns[key] = time.monotonic() + seconds

    def in_cooldown(self, key: str) -> bool:
        return self.cooldowns.get(key, 0) > time.monotonic()

    def forget_idle(self, idle_before: float) -> None:
        """Drop windows whose newest probe is older than idle_before, and expired cooldowns"""
        for key in [k for k, w in self.windows.items() if not w or w[-1][0] < idle_before]:
            del self.windows[key]
        now = time.monotonic()
        for key in [k for k, until in self.cooldowns.items() if until <= now]:
            del self.cooldowns[key]

    def clear(self) -> None:
        self.windows.clear()
        self.cooldowns.clear()

    def sizes(self) -> Dict[str, int]:
        return {"windows": len(self.windows), "cooldowns": len(self.cooldowns)}


class RedisState:
    name = "redis"

    def __init__(self, url: str):
        import redis

        self.client = redis.Redis.from_url(url, socket_timeout=2, socket_connect_timeout=2)
        self.client.ping()

    @staticmethod
    def _member(probe: dict) -> str:
        return json.dumps(probe, sort_keys=True, separators=(",", ":"))

    def add(self, key: str, probes: List[dict], window_seconds: float, maxlen: int) -> List[dict]:
        rkey = f"{PREFIX}w:{key}"
        pipe = self.client.pipeline(transaction=True)
        if probes:
            pipe.zadd(rkey, {self._member(p): p["time"] for p in probes})
        pipe.zrevrange(rkey, 0, 0, withscores=True)
        newest = pipe.execute()[-1]
        if not newest:
            return []
        cutoff = newest[0][1] - window_seconds
        pipe = self.client.pipeline(transaction=True)
        pipe.zremrangebyscore(rkey, "-inf", f"({cutoff}")
        pipe.zremrangebyrank(rkey, 0, -maxlen - 1)  # keep the newest maxlen
        pipe.expire(rkey, int(window_seconds * 2) + 60)
        pipe.zrange(rkey, 0, -1)
        members = pipe.execute()[-1]
        return [json.loads(m) for m in members]

    def claim(self, key: str, seconds: float) -> bool:
        return bool(self.client.set(f"{PREFIX}cd:{key}", 1, nx=True, ex=max(1, int(seconds))))

    def start(self, key: str, seconds: float) -> None:
        self.client.set(f"{PREFIX}cd:{key}", 1, ex=max(1, int(seconds)))

    def in_cooldown(self, key: str) -> bool:
        return bool(self.client.exists(f"{PREFIX}cd:{key}"))

    def forget_idle(self, idle_before: float) -> None:
        pass  # keys expire by themselves

    def clear(self) -> None:
        keys = list(self.client.scan_iter(f"{PREFIX}*", count=1000))
        for i in range(0, len(keys), 500):
            self.client.delete(*keys[i:i + 500])

    def sizes(self) -> Dict[str, int]:
        windows = sum(1 for _ in self.client.scan_iter(f"{PREFIX}w:*", count=1000))
        cooldowns = sum(1 for _ in self.client.scan_iter(f"{PREFIX}cd:*", count=1000))
        return {"windows": windows, "cooldowns": cooldowns}


class DetectionState:
    """Redis when configured and reachable, otherwise memory"""

    def __init__(self, redis_url: str = ""):
        self.memory = MemoryState()
        self.redis: Optional[RedisState] = None
        self.redis_url = ""
        self.last_error: Optional[str] = None
        self.retry_at = 0.0
        self.configure(redis_url)

    def configure(self, redis_url: str) -> None:
        self.redis_url = redis_url
        self.redis = None
        self.retry_at = 0.0
        if redis_url:
            self._connect()

    def _connect(self) -> None:
        try:
            self.redis = RedisState(self.redis_url)
            if self.last_error:
                logger.info("Detection state: Redis reachable again")
            self.last_error = None
        except Exception as e:
            self.redis = None
            self.retry_at = time.monotonic() + RETRY_SECONDS
            if self.last_error is None:
                logger.error(f"Detection state: cannot reach Redis ({e}); using memory")
            self.last_error = str(e)

    @property
    def backend(self):
        if self.redis is None and self.redis_url and time.monotonic() >= self.retry_at:
            self._connect()
        return self.redis or self.memory

    def _call(self, method: str, *args):
        store = self.backend
        try:
            return getattr(store, method)(*args)
        except Exception as e:
            if store is self.memory:
                raise
            logger.error(f"Detection state: Redis failed ({e}); using memory")
            self.redis = None
            self.last_error = str(e)
            self.retry_at = time.monotonic() + RETRY_SECONDS
            return getattr(self.memory, method)(*args)

    # Probes are dataclasses in the detector; stored as plain dicts
    def add(self, key: str, probes: List[Any], window_seconds: float, maxlen: int) -> List[dict]:
        return self._call("add", key, [asdict(p) if not isinstance(p, dict) else p for p in probes],
                          window_seconds, maxlen)

    def claim(self, key: str, seconds: float) -> bool:
        return self._call("claim", key, seconds)

    def start(self, key: str, seconds: float) -> None:
        self._call("start", key, seconds)

    def in_cooldown(self, key: str) -> bool:
        return self._call("in_cooldown", key)

    def forget_idle(self, idle_before: float) -> None:
        self._call("forget_idle", idle_before)

    def clear(self) -> None:
        self.memory.clear()
        if self.redis is not None:
            try:
                self.redis.clear()
            except Exception as e:
                logger.error(f"Detection state: cannot clear Redis: {e}")

    @property
    def status(self) -> str:
        if not self.redis_url:
            return "memory"
        return "redis" if self.backend is self.redis else "memory fallback"

    def get_stats(self) -> Dict[str, Any]:
        try:
            sizes = self.backend.sizes()
        except Exception:
            sizes = {}
        return {"backend": self.status, "last_error": self.last_error, **sizes}
