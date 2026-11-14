# Baseline (testdev, before improvement work)

Recorded before any behavioral changes described in the improvement plan.

## Environment

- **OS:** Linux
- **Python:** 3.14.4 (project `.venv`)
- **Date of snapshot:** 2026-11-14

## Installed packages (`pip freeze`)

```
aiofiles==25.1.0
aiohappyeyeballs==2.7.1
aiohttp==3.14.2
aiosignal==1.4.0
attrs==26.1.0
certifi==2026.7.22
charset-normalizer==3.4.9
frozenlist==1.8.0
idna==3.18
lief==1.0.0
multidict==6.7.1
pefile==2024.8.26
ppdeep==20260221
propcache==0.5.2
python-dotenv==1.2.2
py-tlsh==5.0.0
requests==2.34.2
urllib3==2.7.0
vt-py==0.22.0
yara-python==4.5.4
yarl==1.24.5
```

Dev tooling added after the snapshot (not part of the runtime baseline):

```
pytest==9.2.0
pytest-cov
ruff==0.17.5
mypy==2.4.1
types-requests
responses
```

## External tools expected under `bin/`

The following binaries are gitignored and must be provisioned manually (see `bin/README.md`):

| Tool | Binary name | Notes |
|---|---|---|
| capa | `capa-v10.0.0-linux` | Capability detection (Mandiant) |
| FLOSS | `floss-3.2.0-linux` | String extraction (Mandiant) |
| QuantumStrand | `quantumstrand-beta3-linux` | String extraction (beta) |
| diec | `diec` (on `PATH`) | Detect It Easy; not bundled in `bin/` |
| YARA rules | `yara_rules/*.yar` | Rule set for `yara_scanner` (gitignored) |

## Known baseline defects (to be fixed in Phase 1)

1. **P0** `add_result(complete_data=...)` `TypeError` — QuantumStrand "no strings" path
   (`src/analyzers/quantumstrand_analyzer.py`).
2. **P0** Duplicate analyzer/reporter registration on repeated `load_*` calls
   (`src/core/orchestrator.py`).
3. **P0** capa `KeyError("capa-all")` when the tool is missing/fails
   (`src/analyzers/capa_analyzer.py`).
4. **P0** diec ignores the configured tool path and crashes with `KeyError("diec-packer")`
   when the tool is absent (`src/analyzers/diec_analyzer.py`).
5. **P0** Resource/Overlay summary drops `raw_output_path` and writes an empty raw file
   (`src/analyzers/resource_overlay_analyzer.py`).
6. **P0** VirusTotal fuzzy query embedded unencoded in the URL; pre-request 20 s sleeps;
   copy-paste "MalwareBazaar" log messages (`src/analyzers/vtcheck_analyzer.py`).
7. **P0** MalwareBazaar crashes on empty `data` responses; no 429 retry handling
   (`src/analyzers/malwarebazaar_analyzer.py`).
8. **P1** Config fallback uses `tools` namespace while consumers read `plugins`
   (`src/core/orchestrator.py::_load_config`).
9. **P1** CWD-relative default paths in `main.py` and `orchestrator.py`.
10. **P1** Invalid `--report` names silently produce no output (`main.py`).
11. **P1** `iocextractor` writes back to `tools_config.json` at runtime.
12. **P1** No subprocess timeouts anywhere (capa/diec/floss/quantumstrand).
13. **P1** O(256·n) entropy implementations in `fileinfo` and `resource_overlay`.

## Test status at baseline

No tests existed (`pytest` collected zero tests). `python -m compileall main.py src`
passed.
