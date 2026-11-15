# Contributing to statcheck

Thanks for considering a contribution!

## Development setup

```bash
git clone https://github.com/geekypanda411/statcheck.git
cd statcheck
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
pre-commit install   # optional but recommended
```

## Workflow

1. Branch from `testdev` (never commit directly to `main`).
2. Keep changes small; one concern per PR.
3. Every new behavior needs a unit test; every fixed crash needs a
   regression test.
4. Make sure the gates pass before pushing:

```bash
make compileall   # syntax/import sanity
make test         # pytest (offline; no network, no repo writes, no malware)
make lint         # ruff check + format --check
make typecheck    # mypy (pragmatic config; tighten module by module)
```

## Test rules

- No network: monkeypatch `requests`, `vt.Client`, and tool subprocesses.
- No writes inside the repository: use `tmp_path`.
- No real malware: use `/bin/true`/`/bin/ls` or synthetic bytes.
- Never execute files from `test_binaries/`.

## Never commit

`.venv/`, `bin/*` binaries (except `bin/README.md` and `.gitkeep`),
`yara_rules/*.yar`, `reports/*`, `test_binaries/*`, `tools_config.json`,
`.env`, API keys, `build/`, `*.egg-info/`, and other generated artifacts.

## Conventional commits

Use `fix:`, `feat:`, `refactor:`, `test:`, `docs:`, `chore:`, `build:`,
`perf:` prefixes; keep each commit green.

## Plugin contract

Do not break the public plugin contract (`name`, `plugin_id`,
`supported_formats`, `depends`, `analyze`) without a compatibility path -
third-party plugins exist. See [docs/plugin-api.md](docs/plugin-api.md).
