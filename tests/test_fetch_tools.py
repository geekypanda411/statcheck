import hashlib
import os
import re
import stat
import subprocess
import sys
from pathlib import Path
from zipfile import ZipFile

SOURCE_SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "fetch-tools.sh"


def _prepare_fixture(root: Path, *, bad_capa_checksum: bool = False) -> dict[str, str]:
    fixture_dir = root / "fixtures"
    fixture_dir.mkdir()
    digests = {}
    for asset, member in (("capa-v10.0.0-linux", "capa"), ("floss-v3.2.0-linux", "floss")):
        archive_path = fixture_dir / f"{asset}.zip"
        with ZipFile(archive_path, "w") as archive:
            archive.writestr(member, f"test {member} executable\n")
        digests[asset] = hashlib.sha256(archive_path.read_bytes()).hexdigest()

    script = root / "scripts" / "fetch-tools.sh"
    script.parent.mkdir()
    text = SOURCE_SCRIPT.read_text()
    replacements = {
        "CAPA_SHA256": "0" * 64 if bad_capa_checksum else digests["capa-v10.0.0-linux"],
        "FLOSS_SHA256": digests["floss-v3.2.0-linux"],
    }
    for variable, digest in replacements.items():
        text, count = re.subn(
            rf'^{variable}="[0-9a-f]+"$',
            f'{variable}="{digest}"',
            text,
            flags=re.MULTILINE,
        )
        assert count == 1
    script.write_text(text)

    fake_bin = root / "fake-bin"
    fake_bin.mkdir()
    fake_curl = fake_bin / "curl"
    fake_curl.write_text(
        """#!/bin/sh
set -eu
output=
url=
while [ "$#" -gt 0 ]; do
    case "$1" in
        -o)
            output=$2
            shift 2
            ;;
        --retry)
            shift 2
            ;;
        -*)
            shift
            ;;
        *)
            url=$1
            shift
            ;;
    esac
done
cp "$FIXTURE_DIR/$(basename "$url")" "$output"
"""
    )
    fake_curl.chmod(fake_curl.stat().st_mode | stat.S_IXUSR)

    env = os.environ.copy()
    env.update(
        {
            "FIXTURE_DIR": str(fixture_dir),
            "PATH": f"{fake_bin}{os.pathsep}{env['PATH']}",
            "PYTHON": sys.executable,
        }
    )
    return env


def _run_fetch(root: Path, env: dict[str, str]) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["bash", str(root / "scripts" / "fetch-tools.sh")],
        capture_output=True,
        text=True,
        env=env,
        cwd=root,
        timeout=10,
        check=False,
    )


def test_fetch_tools_extracts_release_members_to_configured_names(tmp_path):
    env = _prepare_fixture(tmp_path)

    result = _run_fetch(tmp_path, env)

    assert result.returncode == 0, result.stderr
    for name, member in (("capa-v10.0.0-linux", "capa"), ("floss-v3.2.0-linux", "floss")):
        executable = tmp_path / "bin" / name
        assert executable.read_text() == f"test {member} executable\n"
        assert stat.S_IMODE(executable.stat().st_mode) == 0o755
    assert not list((tmp_path / "bin").glob(".fetch-tools.*"))


def test_fetch_tools_aborts_on_checksum_mismatch(tmp_path):
    env = _prepare_fixture(tmp_path, bad_capa_checksum=True)

    result = _run_fetch(tmp_path, env)

    assert result.returncode != 0
    assert "SHA-256 mismatch" in result.stderr
    assert not (tmp_path / "bin" / "capa-v10.0.0-linux").exists()
    assert not (tmp_path / "bin" / "floss-3.2.0-linux").exists()
    assert not list((tmp_path / "bin").glob(".fetch-tools.*"))
