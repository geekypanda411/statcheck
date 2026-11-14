"""Tests for centralized path resolution."""

from __future__ import annotations

from src.core.paths import PROJECT_ROOT, resolve_path


def test_project_root_is_repo_root():
    assert (PROJECT_ROOT / "main.py").is_file()
    assert (PROJECT_ROOT / "src" / "core" / "orchestrator.py").is_file()


def test_resolve_absolute_path_is_unchanged(tmp_path):
    assert resolve_path(str(tmp_path)) == tmp_path.resolve()


def test_resolve_relative_path_uses_project_root():
    p = resolve_path("src/analyzers")
    assert p == (PROJECT_ROOT / "src" / "analyzers").resolve()
    assert p.is_dir()


def test_resolve_relative_path_with_custom_base(tmp_path):
    (tmp_path / "bin").mkdir()
    p = resolve_path("./bin", base=tmp_path)
    assert p == (tmp_path / "bin").resolve()


def test_resolve_path_is_cwd_independent(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    p = resolve_path("src/reporters")
    # Even with CWD=/tmp/..., the path still points into the repo.
    assert p == (PROJECT_ROOT / "src" / "reporters").resolve()


def test_resolve_path_expands_user(monkeypatch, tmp_path):
    monkeypatch.setenv("HOME", str(tmp_path))
    p = resolve_path("~/somewhere")
    assert p == (tmp_path / "somewhere").resolve()


def test_bin_path_resolved_relative_to_config_parent(tmp_path):
    # Simulate: config lives in <tmp>/cfg/tools_config.json with bin_path ./bin
    cfg_dir = tmp_path / "cfg"
    cfg_dir.mkdir()
    (cfg_dir / "bin").mkdir()

    from src.core.orchestrator import Orchestrator

    config = cfg_dir / "tools_config.json"
    config.write_text('{"bin_path": "./bin", "plugins": {}}')
    app = Orchestrator(str(tmp_path / "x.bin"), "pe", str(config), str(tmp_path / "nope.json"))
    assert app.bin_dir == (cfg_dir / "bin").resolve()
