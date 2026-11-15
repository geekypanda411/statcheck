#!/usr/bin/env bash
# Fetch pinned external analysis tools into bin/.
#
# Existing binaries are never overwritten. Downloaded release archives are
# verified against the SHA-256 digests pinned below before extracting them.

set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BIN_DIR="$PROJECT_ROOT/bin"
PYTHON="${PYTHON:-python3}"

if ! command -v "$PYTHON" >/dev/null 2>&1; then
    echo "ERROR: Python 3 is required to verify and extract release ZIPs." >&2
    exit 1
fi

mkdir -p "$BIN_DIR"
TMP_DIR="$(mktemp -d "$BIN_DIR/.fetch-tools.XXXXXX")"
cleanup() {
    rm -rf -- "$TMP_DIR"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM HUP

fetch() {
    local name="$1" url="$2" expected_sha256="$3" archive_member="$4"
    local dest="$BIN_DIR/$name"

    if [[ -e "$dest" ]]; then
        echo "SKIP: $dest already exists (delete it to re-fetch)."
        return 0
    fi

    local archive="$TMP_DIR/$name.zip"
    local extracted="$TMP_DIR/$name"
    echo "Fetching $name from $url ..."
    if command -v curl >/dev/null 2>&1; then
        curl -fSL --retry 3 -o "$archive" "$url"
    elif command -v wget >/dev/null 2>&1; then
        wget -O "$archive" "$url"
    else
        echo "ERROR: neither curl nor wget is available." >&2
        return 1
    fi

    "$PYTHON" - "$archive" "$archive_member" "$expected_sha256" "$extracted" <<'PY'
import hashlib
import shutil
import sys
from pathlib import Path
from zipfile import BadZipFile, ZipFile

archive_path = Path(sys.argv[1])
member_name = sys.argv[2]
expected_sha256 = sys.argv[3]
output_path = Path(sys.argv[4])

with archive_path.open("rb") as stream:
    actual_sha256 = hashlib.file_digest(stream, "sha256").hexdigest()
if actual_sha256 != expected_sha256:
    raise SystemExit(
        f"ERROR: SHA-256 mismatch for {archive_path.name}: "
        f"expected {expected_sha256}, got {actual_sha256}"
    )

try:
    with ZipFile(archive_path) as archive:
        members = [
            info
            for info in archive.infolist()
            if not info.is_dir() and info.filename == member_name
        ]
        if len(members) != 1:
            raise SystemExit(
                f"ERROR: expected one {member_name!r} member in {archive_path.name}; "
                f"found {len(members)}"
            )
        with archive.open(members[0]) as source, output_path.open("xb") as destination:
            shutil.copyfileobj(source, destination)
except (BadZipFile, OSError) as error:
    raise SystemExit(f"ERROR: could not extract {archive_path.name}: {error}") from error
PY

    chmod 0755 "$extracted"
    mv "$extracted" "$dest"
    echo "OK: $dest (archive SHA-256 verified)"
}

# Pinned Linux x86-64 releases. Update the versions, SHA-256 digests, and
# tools_config.json.example tool names together. Digests come from the
# `digest` field of each asset returned by GitHub's release API.
CAPA_VERSION="v10.0.0"
FLOSS_VERSION="v3.2.0"
CAPA_SHA256="96cb5115f495024a478b0e9f9f77f9027058155589235fbd4c50e7382055fcca"
FLOSS_SHA256="c449366960b688769b6510662cd6db6a3bf9edada4e8a8878056becd324df52c"

fetch "capa-${CAPA_VERSION}-linux" \
    "https://github.com/mandiant/capa/releases/download/${CAPA_VERSION}/capa-${CAPA_VERSION}-linux.zip" \
    "$CAPA_SHA256" \
    "capa"

fetch "floss-${FLOSS_VERSION}-linux" \
    "https://github.com/mandiant/flare-floss/releases/download/${FLOSS_VERSION}/floss-${FLOSS_VERSION}-linux.zip" \
    "$FLOSS_SHA256" \
    "floss"

echo
echo "Done. Existing binaries were left untouched; all new downloads passed SHA-256 verification."
echo "When updating a release, update its pinned digest from the upstream GitHub release API."
echo "Ensure the 'tool' values in tools_config.json match the installed names."
echo "Populate yara_rules/ (gitignored) for the yara_scanner plugin."
