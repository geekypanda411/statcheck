"""Shared HTTP infrastructure for threat-intelligence providers.

- resilient ``requests.Session`` factory (retries incl. 429/Retry-After);
- bounded on-disk response cache keyed by ``(provider, key)`` with a TTL.

API keys are never logged or written to the cache: only response payloads are
stored under the statcheck cache directory.
"""

from __future__ import annotations

import logging
import os
import threading
import time
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from pathlib import Path

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from src.core.cache import cache_dir, read_json, write_json

logger = logging.getLogger(__name__)

DEFAULT_USER_AGENT = "Statcheck/0.2 (static analyzer)"
DEFAULT_TTL_SECONDS = 24 * 3600
DEFAULT_MAX_CACHE_ENTRIES = 1024

# flock/msvcrt coordinate separate processes; these locks also coordinate
# threads, which share the process-level file-lock semantics on some systems.
_CACHE_THREAD_LOCKS: dict[str, threading.Lock] = {}
_CACHE_THREAD_LOCKS_GUARD = threading.Lock()


def build_session(retries: int = 3, backoff: float = 2.0, user_agent: str = DEFAULT_USER_AGENT) -> requests.Session:
    """Session with automatic retries for 429/5xx (honors Retry-After)."""
    session = requests.Session()
    retry_strategy = Retry(
        total=retries,
        backoff_factor=backoff,
        status_forcelist=[429, 500, 502, 503, 504],
        respect_retry_after_header=True,
        allowed_methods=["GET", "POST"],
    )
    adapter = HTTPAdapter(max_retries=retry_strategy)
    session.mount("https://", adapter)
    session.mount("http://", adapter)
    session.headers["User-Agent"] = user_agent
    return session


def _thread_lock(path: Path) -> threading.Lock:
    key = str(path)
    with _CACHE_THREAD_LOCKS_GUARD:
        return _CACHE_THREAD_LOCKS.setdefault(key, threading.Lock())


@contextmanager
def _locked_cache_index(index_path: Path) -> Iterator[None]:
    """Serialize the complete read/fetch/write transaction across processes."""
    index_path.parent.mkdir(parents=True, exist_ok=True)
    lock_path = index_path.with_suffix(index_path.suffix + ".lock")
    with _thread_lock(index_path), open(lock_path, "a+b") as lock_file:
        if os.name == "posix":
            import fcntl

            fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX)
        elif os.name == "nt":  # pragma: no cover - exercised on Windows
            import msvcrt

            lock_file.seek(0)
            if not lock_file.read(1):
                lock_file.write(b"\0")
                lock_file.flush()
            lock_file.seek(0)
            msvcrt.locking(lock_file.fileno(), msvcrt.LK_LOCK, 1)  # type: ignore[attr-defined]
        try:
            yield
        finally:
            if os.name == "posix":
                fcntl.flock(lock_file.fileno(), fcntl.LOCK_UN)
            elif os.name == "nt":  # pragma: no cover - exercised on Windows
                lock_file.seek(0)
                msvcrt.locking(lock_file.fileno(), msvcrt.LK_UNLCK, 1)  # type: ignore[attr-defined]


def _prune_entries(index: dict, now: float, ttl_seconds: int, max_entries: int) -> dict:
    """Drop malformed/expired entries and retain the newest bounded history."""
    fresh = []
    for key, entry in index.items():
        if not isinstance(entry, dict) or "data" not in entry:
            continue
        try:
            fetched_at = float(entry.get("fetched_at", 0))
        except (TypeError, ValueError):
            continue
        if now - fetched_at < ttl_seconds:
            fresh.append((key, fetched_at, entry))

    fresh.sort(key=lambda item: (item[1], str(item[0])), reverse=True)
    return {key: entry for key, _fetched_at, entry in fresh[:max_entries]}


def cached_response(
    provider: str,
    key: str,
    fetch: Callable[[], object],
    ttl_seconds: int = DEFAULT_TTL_SECONDS,
    max_entries: int = DEFAULT_MAX_CACHE_ENTRIES,
):
    """Disk-backed response cache returning ``(data, from_cache)``.

    Entries older than ``ttl_seconds`` are removed during every transaction;
    at most ``max_entries`` newest responses are retained per provider. The
    lock covers the fetch as well as persistence so concurrent runs cannot
    lose updates or duplicate an in-flight lookup. Failed fetches (``None``)
    are never cached.
    """
    if max_entries < 1:
        raise ValueError("max_entries must be at least one")

    index_path = cache_dir() / "ti" / f"{provider}.json"
    with _locked_cache_index(index_path):
        now = time.time()
        raw_index = read_json(index_path)
        index = raw_index if isinstance(raw_index, dict) else {}
        index = _prune_entries(index, now, ttl_seconds, max_entries)

        entry = index.get(key)
        if isinstance(entry, dict):
            # Persist eviction even on read-heavy workloads that only hit.
            if index != raw_index:
                write_json(index_path, index)
            logger.debug(f"TI cache hit for {provider}/{key}")
            return entry.get("data"), True

        data = fetch()
        if data is None:
            if index != raw_index:
                write_json(index_path, index)
            return None, False

        index[key] = {"fetched_at": now, "data": data}
        index = _prune_entries(index, now, ttl_seconds, max_entries)
        write_json(index_path, index)
        logger.debug(f"TI cache miss for {provider}/{key}; stored response.")
        return data, False
