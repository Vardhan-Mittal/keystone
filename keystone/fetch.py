"""Cached async HTTP.

Every raw response is persisted under data/cache/ keyed by URL, so that:
  1. re-running ingestion during development is instant, and
  2. the demo can never be broken by a rate limit or an upstream outage.

Set KEYSTONE_OFFLINE=1 to refuse network access entirely and replay from cache.
"""
import asyncio
import hashlib
import json
import re
from pathlib import Path
from typing import Any, Callable

import httpx

from .config import CACHE_DIR, HTTP_CONCURRENCY, HTTP_TIMEOUT, OFFLINE

_sem: asyncio.Semaphore | None = None


def _semaphore() -> asyncio.Semaphore:
    global _sem
    if _sem is None:
        _sem = asyncio.Semaphore(HTTP_CONCURRENCY)
    return _sem


class OfflineMiss(RuntimeError):
    """Asked for something not in cache while running offline."""


def _cache_path(kind: str, key: str) -> Path:
    """Readable filename where possible, hashed when the key is unsafe/long."""
    slug = re.sub(r"[^A-Za-z0-9._@-]+", "_", key).strip("_")[:80]
    digest = hashlib.sha256(key.encode()).hexdigest()[:12]
    return CACHE_DIR / kind / f"{slug}--{digest}.json"


def cache_read(kind: str, key: str) -> Any | None:
    p = _cache_path(kind, key)
    if not p.exists():
        return None
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return None  # corrupt entry: treat as a miss rather than crashing


def cache_write(kind: str, key: str, value: Any) -> None:
    p = _cache_path(kind, key)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(value), encoding="utf-8")


async def get_json(
    client: httpx.AsyncClient,
    url: str,
    *,
    kind: str,
    key: str | None = None,
    extract: Callable[[Any], Any] | None = None,
    headers: dict[str, str] | None = None,
    retries: int = 3,
) -> Any | None:
    """GET url, cache the (optionally reduced) JSON, return it.

    `extract` runs before caching. npm's full package documents can be megabytes
    and we need three fields, so reducing first keeps the cache small enough to
    commit-adjacent and fast to replay.

    Returns None for 404 and for persistent failures; callers treat missing data
    as "unknown" rather than fatal, since one dead package should not abort a
    1500-package ingest.
    """
    ckey = key or url
    hit = cache_read(kind, ckey)
    if hit is not None:
        return hit

    if OFFLINE:
        raise OfflineMiss(f"{kind}:{ckey} not cached and KEYSTONE_OFFLINE=1")

    last_exc: Exception | None = None
    for attempt in range(retries):
        try:
            async with _semaphore():
                r = await client.get(url, headers=headers, timeout=HTTP_TIMEOUT)
            if r.status_code == 404:
                cache_write(kind, ckey, None)
                return None
            if r.status_code in (429, 500, 502, 503, 504):
                # Exponential, not linear: npm's search endpoint throttles in
                # bursts and a linear backoff just lands inside the same window.
                last_exc = RuntimeError(f"HTTP {r.status_code}")
                await asyncio.sleep(2.0 * (2**attempt))
                continue
            r.raise_for_status()
            data = r.json()
            value = extract(data) if extract else data
            cache_write(kind, ckey, value)
            return value
        except (httpx.HTTPError, json.JSONDecodeError) as exc:
            last_exc = exc
            await asyncio.sleep(1.0 * (attempt + 1))

    print(f"  ! giving up on {kind}:{ckey} ({last_exc})")
    return None


async def post_json(
    client: httpx.AsyncClient,
    url: str,
    payload: Any,
    *,
    kind: str,
    key: str,
    retries: int = 3,
) -> Any | None:
    """POST with the same caching contract (used for OSV's batch endpoint)."""
    hit = cache_read(kind, key)
    if hit is not None:
        return hit
    if OFFLINE:
        raise OfflineMiss(f"{kind}:{key} not cached and KEYSTONE_OFFLINE=1")

    for attempt in range(retries):
        try:
            async with _semaphore():
                r = await client.post(url, json=payload, timeout=HTTP_TIMEOUT)
            if r.status_code in (429, 500, 502, 503, 504):
                await asyncio.sleep(1.5 * (attempt + 1))
                continue
            r.raise_for_status()
            data = r.json()
            cache_write(kind, key, data)
            return data
        except (httpx.HTTPError, json.JSONDecodeError) as exc:
            print(f"  ! osv attempt {attempt + 1} failed: {exc}")
            await asyncio.sleep(1.0 * (attempt + 1))
    return None
