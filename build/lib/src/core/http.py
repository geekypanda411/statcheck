"""Shared HTTP infrastructure for threat-intelligence providers.

- one resilient ``requests.Session`` factory (retries incl. 429, Retry-After,
  bounded user agent);
- a small on-disk response cache keyed by ``(provider, key)`` with a TTL so
  repeat analyses of the same sample do not burn API quota.

API keys are never logged or written to the cache: only response payloads
are stored, under the statcheck cache directory.
"""

from __future__ import annotations

import logging
import time
from collections.abc import Callable

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from src.core.cache import cache_dir, read_json, write_json

logger = logging.getLogger(__name__)

DEFAULT_USER_AGENT = "Statcheck/0.2 (static analyzer)"
DEFAULT_TTL_SECONDS = 24 * 3600


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


def cached_response(provider: str, key: str, fetch: Callable[[], object], ttl_seconds: int = DEFAULT_TTL_SECONDS):
    """Disk-backed response cache for a TI provider.

    Returns ``(data, from_cache)``. ``data`` may be ``None`` when the fetch
    failed; failures are never cached.
    """
    index_path = cache_dir() / "ti" / f"{provider}.json"
    index = read_json(index_path) or {}

    entry = index.get(key)
    now = time.time()
    if isinstance(entry, dict) and (now - entry.get("fetched_at", 0)) < ttl_seconds:
        logger.debug(f"TI cache hit for {provider}/{key}")
        return entry.get("data"), True

    data = fetch()
    if data is None:
        return None, False

    index[key] = {"fetched_at": now, "data": data}
    write_json(index_path, index)
    logger.debug(f"TI cache miss for {provider}/{key}; stored response.")
    return data, False
