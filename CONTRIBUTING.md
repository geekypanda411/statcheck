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
make compileall   # byte-compile sources as a syntax check
make test         # pytest (offline, no network or real malware)
make lint         # ruff check + format --check
make typecheck    # mypy (pragmatic config; tighten module by module)
```

## Test rules

- No network: monkeypatch `requests`, `vt.Client`, and tool subprocesses.
- Test code writes outputs to `tmp_path`, not tracked project files. Tooling
  can still create ignored caches such as `__pycache__/` and `.pytest_cache/`.
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

## Documentation

Update behavior documentation with the code that changes it. In particular:

- document new configuration defaults, precedence, and network activity;
- update [docs/architecture.md](docs/architecture.md) when execution or design
  decisions change;
- keep [docs/plugin-api.md](docs/plugin-api.md) examples aligned with the public
  helper and error contracts;
- update [docs/report-schema.md](docs/report-schema.md) for status, metadata,
  filename, or summary-contract changes;
- run a local Markdown-link check for files you edit.
