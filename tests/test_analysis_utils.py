"""Tests for shared analysis utilities (entropy, deterministic helpers)."""

from __future__ import annotations

import math
import os
import random

from src.core.analysis_utils import shannon_entropy, sorted_unique, sorted_unique_capped


def test_entropy_empty():
    assert shannon_entropy(b"") == 0.0


def test_entropy_uniform_single_byte():
    assert shannon_entropy(b"\x00" * 100) == 0.0
    assert shannon_entropy(b"\xff" * 4096) == 0.0


def test_entropy_uniform_all_256():
    # Exactly one occurrence of every byte value -> maximum entropy.
    assert shannon_entropy(bytes(range(256))) == 8.0


def test_entropy_known_half_split():
    # Two equally likely symbols -> 1.0 bit.
    assert shannon_entropy(b"\x00\x01" * 50) == 1.0


def test_entropy_matches_naive_implementation():
    random.seed(1234)
    data = bytes(random.randrange(256) for _ in range(1000))
    counts = [data.count(x) for x in range(256)]
    n = len(data)
    naive = round(-sum((c / n) * math.log2(c / n) for c in counts if c), 4)
    assert shannon_entropy(data) == naive


def test_entropy_single_pass_is_fast_on_large_input():
    # 16 MiB would be ~4 billion byte comparisons with the old data.count
    # loop; the shared helper must stay comfortably under a second.
    import time

    data = os.urandom(16 * 1024 * 1024)
    start = time.perf_counter()
    shannon_entropy(data)
    elapsed = time.perf_counter() - start
    assert elapsed < 2.0, f"entropy took {elapsed:.2f}s for 16 MiB"


def test_sorted_unique():
    assert sorted_unique(["b", "a", "b", "c", "a"]) == ["a", "b", "c"]


def test_sorted_unique_capped_truncates_sorted_result():
    assert sorted_unique_capped(["z", "a", "m", "b"], cap=2) == ["a", "b"]
    assert sorted_unique_capped(["z", "a"], cap=5) == ["a", "z"]
