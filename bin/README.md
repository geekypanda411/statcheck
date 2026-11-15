# External tools

`bin/` is **gitignored** - populate it manually or with
`scripts/fetch-tools.sh`. statcheck resolves each tool in this order:

1. `tools_config.json` -> `bin_path` + the plugin's `tool` name;
2. a `PATH` lookup by the same basename.

| Tool | Binary (config `tool`) | Required by | Notes |
|---|---|---|---|
| capa | `capa-v10.0.0-linux` | `capa` | https://github.com/mandiant/capa - download the Linux release, `chmod +x`. |
| FLOSS | `floss-3.2.0-linux` | `floss` | https://github.com/mandiant/flare-floss - Linux release. |
| QuantumStrand | `quantumstrand-beta3-linux` | `quantumstrand` | Beta string extractor; any recent build works. |
| diec | `diec` (on PATH) or `bin/diec` | `diec` | https://github.com/horsicq/DIE-engine - install system-wide or place in `bin/`. |

Also required (not binaries):

| Resource | Location | Used by |
|---|---|---|
| YARA rules (`.yar`/`.yara`) | `yara_rules/` (gitignored) | `yara_scanner` |
| TLD list | cache dir (auto-downloaded from IANA) | `iocextractor` |

## Verification

After placing binaries, check availability:

```bash
statcheck --list-plugins
# External tool availability:
#   capa       OK        tool: capa-v10.0.0-linux
#   diec       MISSING   tool: diec
```

Checksums for pinned releases are published on the upstream GitHub release
pages - verify them before use.

## Optional Python hash wheels

`ppdeep` (SSDeep) and `py-tlsh` (TLSH) are optional at runtime: if the
wheels are unavailable on your platform, `fileinfo` skips those hashes with a
warning and everything else keeps working.
