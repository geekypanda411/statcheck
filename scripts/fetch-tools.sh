#!/usr/bin/env bash
# Fetch pinned external analysis tools into bin/.
#
# Never overwrites an existing binary without explicit confirmation.
# Verify upstream checksums (published on the release pages) afterwards.

set -euo pipefail

BIN_DIR="$(cd "$(dirname "$0")/.." && pwd)/bin"
mkdir -p "$BIN_DIR"

fetch() {
    local name="$1" url="$2"
    local dest="$BIN_DIR/$name"

    if [[ -e "$dest" ]]; then
        echo "SKIP: $dest already exists (delete it to re-fetch)."
        return 0
    fi

    echo "Fetching $name from $url ..."
    local tmp="$dest.part"
    if command -v curl >/dev/null 2>&1; then
        curl -fSL --retry 3 -o "$tmp" "$url"
    elif command -v wget >/dev/null 2>&1; then
        wget -O "$tmp" "$url"
    else
        echo "ERROR: neither curl nor wget is available." >&2
        exit 1
    fi

    chmod +x "$tmp"
    mv "$tmp" "$dest"
    echo "OK: $dest"
}

# Pinned releases - update versions in tools_config.json.example to match.
CAPA_VERSION="v10.0.0"
FLOSS_VERSION="v3.2.0"

fetch "capa-${CAPA_VERSION#v}.0.0-linux" \
    "https://github.com/mandiant/capa/releases/download/${CAPA_VERSION}/capa-linux" \
    || true

fetch "floss-${FLOSS_VERSION#v}.0.0-linux" \
    "https://github.com/mandiant/flare-floss/releases/download/${FLOSS_VERSION}/floss-linux" \
    || true

echo
echo "Done. Remember to:"
echo "  1. verify checksums against the upstream release pages"
echo "  2. update the 'tool' values in tools_config.json"
echo "  3. populate yara_rules/ (gitignored) for the yara_scanner plugin"
