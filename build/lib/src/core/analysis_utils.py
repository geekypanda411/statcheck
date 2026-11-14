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


# Common magic signatures for MIME detection (prefix matches).
_MAGIC_SIGNATURES: list[tuple[bytes, str]] = [
    (b"MZ", "application/x-dosexec"),
    (b"\x7fELF", "application/x-elf-executable"),
    (b"\xfe\xed\xfa\xce", "application/x-mach-binary"),
    (b"\xce\xfa\xed\xfe", "application/x-mach-binary"),
    (b"\xfe\xed\xfa\xcf", "application/x-mach-binary"),
    (b"\xcf\xfa\xed\xfe", "application/x-mach-binary"),
    (b"PK\x03\x04", "application/zip"),
    (b"PK\x05\x06", "application/zip"),
    (b"Rar!\x1a\x07", "application/vnd.rar"),
    (b"7z\xbc\xaf\x27\x1c", "application/x-7z-compressed"),
    (b"\x1f\x8b", "application/gzip"),
    (b"BZh", "application/x-bzip2"),
    (b"\xfd7zXZ\x00", "application/x-xz"),
    (b"%PDF", "application/pdf"),
    (b"\x89PNG", "image/png"),
    (b"\xff\xd8\xff", "image/jpeg"),
    (b"GIF87a", "image/gif"),
    (b"GIF89a", "image/gif"),
    (b"OggS", "application/ogg"),
    (b"ID3", "audio/mpeg"),
    (b"SQLite format 3\x00", "application/vnd.sqlite3"),
    (b"\xca\xfe\xba\xbe", "application/java-vm"),  # ambiguous with fat Mach-O
]


def detect_mime_type(data: bytes) -> str | None:
    """Best-effort MIME detection from magic bytes (prefix matches)."""
    for magic, mime in _MAGIC_SIGNATURES:
        if data.startswith(magic):
            return mime
    return None
