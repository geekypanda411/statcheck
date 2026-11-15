# External tools and resources

Most files under `bin/` are gitignored. Install trusted binaries yourself or
use the pinned fetch script below. Statcheck resolves an external tool in this
order:

1. executable file at `<bin_path>/<tool>`;
2. executable with that **same configured basename** on `PATH`.

`bin_path` is relative to the selected tool config file's directory; `tool`
defaults to the analyzer ID when omitted. Names below match
[`tools_config.json.example`](../tools_config.json.example).

## Automatic capa and FLOSS provisioning

From the project root, run:

```bash
./scripts/fetch-tools.sh
# Equivalent when the script is not executable:
bash scripts/fetch-tools.sh
```

The script requires Bash, Python 3 with `hashlib.file_digest` (Python 3.11+,
matching the project), and `curl` or `wget`. It downloads **only these pinned
Linux x86-64 releases** into `bin/`:

| Tool | Destination / example `tool` | Upstream |
|---|---|---|
| capa v10.0.0 | `capa-v10.0.0-linux` | [mandiant/capa](https://github.com/mandiant/capa) |
| FLOSS v3.2.0 | `floss-3.2.0-linux` | [mandiant/flare-floss](https://github.com/mandiant/flare-floss) |

For each missing destination, the script downloads the release ZIP, verifies
its SHA-256 against the digest pinned in the script, extracts the expected
member, and installs it with mode 0755. A digest mismatch aborts the script.
Existing destinations are skipped untouched: they are neither overwritten nor
re-verified. Remove a destination yourself if you intentionally want to fetch
it again. The script does not change `tools_config.json`.

It does **not** download DiE, QuantumStrand, YARA rules, or a TLD list.

## Manual tools

| Tool | Example `tool` | Analyzer | Installation |
|---|---|---|---|
| Detect It Easy (`diec`) | `diec` | `diec` | Install from [DIE-engine](https://github.com/horsicq/DIE-engine), or place an executable named `diec` under `bin_path` |
| QuantumStrand | `quantumstrand-beta3-linux` | `quantumstrand` | Obtain a compatible trusted build manually; use this filename or change the plugin's `tool` value |

Verify manually downloaded tools and their provenance. If you use a different
binary name, update both the file and the plugin's `tool` setting, or put the
configured basename on `PATH`.

## Non-binary resources

| Resource | Location | Provisioning |
|---|---|---|
| YARA `.yar`/`.yara` rules | `yara_rules/` by default | Populate manually from a trusted source; the directory is gitignored. `rule_path` can select another file/directory or a precompiled blob |
| IANA TLD list | `<cache>/tlds.txt` by default | Downloaded automatically when IOC extraction has strings and the list is missing/stale; no fetch-script step is needed. A custom `tld_file` overrides the location |

The default cache is `~/.cache/statcheck`, or
`$XDG_CACHE_HOME/statcheck`. See the
[configuration reference](../docs/configuration.md) for custom paths and
refresh behavior.

## Verify resolution

```bash
statcheck --list-plugins
```

The **External tool availability** section prints `OK` or `MISSING` for config
blocks that explicitly define a string `tool`. It does not probe unconfigured
default tool names, execute the binary, validate its version, or test whether
its output parses. Runtime failures and their reasons are covered in
[Troubleshooting](../docs/troubleshooting.md).

## Optional Python hash packages

`ppdeep` (SSDeep) and `py-tlsh` (TLSH) are Python packages, not files fetched
into `bin/`. If unavailable, `fileinfo` logs a warning and omits that hash while
other analysis continues. VT SSDeep search needs SSDeep; MalwareBazaar's TLSH
pivot needs TLSH (its separate ImpHash pivot uses the PE import hash).
