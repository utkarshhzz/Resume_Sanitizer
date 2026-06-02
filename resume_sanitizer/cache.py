from __future__ import annotations

import asyncio
import io
import logging
from abc import ABC, abstractmethod
from collections import OrderedDict
from typing import Any

from redis import asyncio as aioredis
from redis.exceptions import RedisError

from resume_sanitizer.config import settings
from resume_sanitizer.exceptions import CacheError

logger = logging.getLogger(__name__)

class BaseCache(ABC):
    """Abstract base class for our caching layer."""
    
    @abstractmethod
    async def get(self, key: str) -> bytes | None:
        pass

    @abstractmethod
    async def set(self, key: str, value: bytes, ttl: int) -> None:
        pass


class InMemoryCache(BaseCache):
    """
    A simple in-memory cache using an OrderedDict for LRU (Least Recently Used) eviction.
    Perfect for local development or a single-instance deployment without Redis.
    """
    def __init__(self, max_size: int = 500):
        self.cache: OrderedDict[str, tuple[bytes, float]] = OrderedDict()
        self.max_size = max_size
        self.lock = asyncio.Lock()

    async def get(self, key: str) -> bytes | None:
        async with self.lock:
            if key not in self.cache:
                return None
            
            value, expire_at = self.cache[key]
            
            # Evict if expired
            if asyncio.get_running_loop().time() > expire_at:
                del self.cache[key]
                return None
            
            # Move to end to mark as recently used
            self.cache.move_to_end(key)
            return value

    async def set(self, key: str, value: bytes, ttl: int) -> None:
        async with self.lock:
            expire_at = asyncio.get_running_loop().time() + ttl
            self.cache[key] = (value, expire_at)
            self.cache.move_to_end(key)
            
            # Enforce max size (LRU eviction)
            if len(self.cache) > self.max_size:
                self.cache.popitem(last=False)


class RedisCache(BaseCache):
    """
    Production-ready Redis cache.
    Uses async redis to handle high-throughput without blocking the server.
    """
    def __init__(self, redis_url: str):
        self.redis_url = redis_url
        self._pool = None

    @property
    def redis(self) -> aioredis.Redis:
        if self._pool is None:
            # Connect lazily so the app doesn't crash on startup if Redis is temporarily down
            self._pool = aioredis.from_url(self.redis_url)
        return self._pool

    async def get(self, key: str) -> bytes | None:
        try:
            val = await self.redis.get(key)
            return val if val else None
        except RedisError as e:
            logger.warning(f"Redis get failed for {key}: {e}. Degrading gracefully.")
            return None

    async def set(self, key: str, value: bytes, ttl: int) -> None:
        try:
            await self.redis.set(key, value, ex=ttl)
        except RedisError as e:
            logger.warning(f"Redis set failed for {key}: {e}. Degrading gracefully.")


def get_cache() -> BaseCache:
    """Factory function to get the configured cache backend."""
    if settings.CACHE_BACKEND == "redis":
        return RedisCache(settings.REDIS_URL)
    return InMemoryCache()
