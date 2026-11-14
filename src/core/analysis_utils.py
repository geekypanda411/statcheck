"""Shared, deterministic analysis helpers.

Single implementation points for entropy and ordering so every plugin
produces byte-identical output for the same input.
"""

from __future__ import annotations

import math


def shannon_entropy(data: bytes) -> float:
    """Shannon entropy of a byte sequence (0.0 to 8.0), single pass.

    Equivalent to the historical per-plugin implementations (rounded to 4
    decimal places) but O(n) instead of O(256*n).
    """
    if not data:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    n = len(data)
    entropy = 0.0
    for c in counts:
        if c:
            p = c / n
            entropy -= p * math.log2(p)
    return round(entropy, 4)


def sorted_unique(items) -> list:
    """Deterministic dedupe: sorted list of unique values."""
    return sorted(set(items))


def sorted_unique_capped(items, cap: int | None = None) -> list:
    """``sorted_unique`` with an optional determinism-preserving cap.

    The cap truncates the *sorted* list, so repeated runs with the same input
    produce identical output even when capped.
    """
    values = sorted(set(items))
    if cap is not None and len(values) > cap:
        return values[:cap]
    return values
