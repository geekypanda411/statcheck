"""Tests for magic-byte format detection."""

from __future__ import annotations

import sys
from types import SimpleNamespace

from src.core.format_detect import detect_format

# A plausible Java class file: CAFEBABE magic + minor/major version + a
# small constant pool prefix. Must NOT be detected as Mach-O.
JAVA_CLASS = b"\xca\xfe\xba\xbe" + b"\x00\x34" + b"\x00\x00" + b"\x00\x07" + b"\x07" + b"\x00" * 64


def test_pe_magic(tmp_path):
    f = tmp_path / "sample.exe"
    f.write_bytes(b"MZ" + b"\x90" * 128)
    assert detect_format(f) == "pe"


def test_elf_magic(tmp_path):
    f = tmp_path / "sample.elf"
    f.write_bytes(b"\x7fELF" + b"\x02" + b"\x00" * 120)
    assert detect_format(f) == "elf"


def test_macho_thin_magic(tmp_path):
    for magic in (b"\xfe\xed\xfa\xce", b"\xce\xfa\xed\xfe", b"\xfe\xed\xfa\xcf", b"\xcf\xfa\xed\xfe"):
        f = tmp_path / "sample.macho"
        f.write_bytes(magic + b"\x00" * 64)
        assert detect_format(f) == "macho"


def test_java_class_is_not_macho(tmp_path):
    """Regression: CAFEBABE used to be unconditionally reported as macho."""
    f = tmp_path / "Sample.class"
    f.write_bytes(JAVA_CLASS)
    assert detect_format(f) != "macho"
    assert detect_format(f) == "unknown"


def test_cafebabe_disambiguated_as_macho_when_lief_parses(tmp_path, monkeypatch):
    f = tmp_path / "fat.macho"
    f.write_bytes(b"\xca\xfe\xba\xbe" + b"\x00" * 64)

    class FakeFatBinary:
        def __len__(self):
            return 1  # one recovered architecture => genuine fat Mach-O

    fake_lief = SimpleNamespace(MachO=SimpleNamespace(parse=lambda p: FakeFatBinary()))
    monkeypatch.setitem(sys.modules, "lief", fake_lief)
    assert detect_format(f) == "macho"


def test_cafebabe_is_unknown_when_lief_recovers_nothing(tmp_path, monkeypatch):

    class EmptyFatBinary:
        def __len__(self):
            return 0

    fake_lief = SimpleNamespace(MachO=SimpleNamespace(parse=lambda p: EmptyFatBinary()))
    monkeypatch.setitem(sys.modules, "lief", fake_lief)
    f = tmp_path / "empty.macho"
    f.write_bytes(b"\xca\xfe\xba\xbe" + b"\x00" * 64)
    assert detect_format(f) == "unknown"


def test_short_file_is_unknown(tmp_path):
    f = tmp_path / "tiny.bin"
    f.write_bytes(b"MZ")
    assert detect_format(f) == "unknown"


def test_unreadable_file_is_unknown(tmp_path):
    assert detect_format(tmp_path / "does-not-exist.bin") == "unknown"


def test_garbage_is_unknown(tmp_path):
    f = tmp_path / "garbage.bin"
    f.write_bytes(b"\x01\x02\x03\x04" + b"random" * 32)
    assert detect_format(f) == "unknown"
