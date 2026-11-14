"""Target file format detection based on magic bytes.

Detection rules:
- ``MZ`` -> ``pe``
- ``\\x7fELF`` -> ``elf``
- Mach-O thin magics -> ``macho``
- ``CAFEBABE`` is ambiguous: it is both the fat/universal Mach-O magic and
  the Java class file magic. We disambiguate by asking LIEF to parse the file
  as Mach-O; if that fails the file is reported as ``unknown`` (Java classes
  are not a supported analysis format).
- Short or unreadable files -> ``unknown``
"""

from __future__ import annotations

import logging
from pathlib import Path

logger = logging.getLogger(__name__)

MACHO_THIN_MAGICS = (
    b"\xfe\xed\xfa\xce",  # Mach-O 32-bit big-endian
    b"\xce\xfa\xed\xfe",  # Mach-O 32-bit little-endian
    b"\xfe\xed\xfa\xcf",  # Mach-O 64-bit big-endian
    b"\xcf\xfa\xed\xfe",  # Mach-O 64-bit little-endian
    b"\xca\xfe\xba\xbf",  # Mach-O 64-bit fat (universal)
)
AMBIGUOUS_MAGIC = b"\xca\xfe\xba\xbe"  # fat Mach-O 32-bit OR Java class file


def detect_format(file_path: str | Path) -> str:
    """Return 'pe', 'elf', 'macho', or 'unknown' for the given file."""
    try:
        with open(file_path, "rb") as f:
            magic = f.read(4)
    except OSError as e:
        logger.warning(f"Format auto-detection failed for {file_path}: {e}")
        return "unknown"

    if len(magic) < 4:
        return "unknown"

    if magic.startswith(b"MZ"):
        return "pe"
    if magic.startswith(b"\x7fELF"):
        return "elf"
    if magic in MACHO_THIN_MAGICS:
        return "macho"
    if magic == AMBIGUOUS_MAGIC:
        return _disambiguate_cafebabe(file_path)
    return "unknown"


def _disambiguate_cafebabe(file_path: str | Path) -> str:
    """Separate fat Mach-O binaries from Java class files sharing CAFEBABE."""
    try:
        import lief

        parsed = lief.MachO.parse(str(file_path))
        if parsed is None:
            return "unknown"
        # Java class files parse into an *empty* FatBinary; only accept the
        # file as Mach-O when LIEF actually recovered architectures from it.
        try:
            if len(parsed) == 0:
                return "unknown"
        except TypeError:
            pass  # Not a container object; treat as parsed Mach-O.
        return "macho"
    except Exception as e:  # LIEF raises a wide variety on garbage input.
        logger.debug(f"LIEF did not accept {file_path} as Mach-O: {e}")
    return "unknown"
