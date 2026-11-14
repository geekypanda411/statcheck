# Configuration reference

Statcheck reads two JSON config files (both CWD-independent; defaults live in
the project root and can be overridden with `--config` / `--reporter-config`):

- `tools_config.json` - external tools, plugin settings, limits
- `reporter_config.json` - reporter settings and section ordering

At startup both files are validated: wrong types are hard errors (exit code
2), unknown keys/plugin ids produce warnings. A missing file falls back to
sane defaults.

## Tool config (`tools_config.json`)

### Top-level keys

| Key | Type | Default | Description |
|---|---|---|---|
| `bin_path` | string | `"./bin"` | Directory holding external tool binaries. **Resolved relative to the config file's directory**, not the CWD. |
| `plugins` | object | `{}` | Per-plugin settings, keyed by `plugin_id`. |
| `limits` | object | (see below) | Global resource limits. |

### Per-plugin settings (common keys)

| Key | Type | Default | Description |
|---|---|---|---|
| `enabled` | bool | `true` | Disable a plugin without removing its block. |
| `tool` | string | `plugin_id` | Binary name looked up in `bin_path`; falls back to a PATH lookup by the same basename. |
| `timeout` | number | `300` (or `--timeout`) | Per-tool subprocess timeout in seconds. |
| Other keys | any | - | Passed straight through to the plugin. |

### Threat-intelligence plugins (`vtlookup`, `malwarebazaar`)

| Key | Default | Description |
|---|---|---|
| `api_key_env` | `VT_API_KEY` / `MB_API_KEY` | Environment variable holding the key. Keys are never written to logs, reports, or the cache. |
| `base_url` | abuse.ch endpoint | Configurable primarily for tests. |
| `cache_ttl_seconds` | `86400` | On-disk response cache TTL (repeat lookups of the same hash skip the API). |
| `lookup_exact_hash` | `true` | SHA-256 lookup. |
| `lookup_fuzzy_hash` | `false` | Fuzzy/similarity pivot (may need a premium key). |
| `fetch_relations_behaviour` (VT) | `false` | Fetch contacted IPs/domains, dropped files, etc. |
| `rate_limit_sleep` (VT) | `20` | Sleep between relation requests (never before the first). |

### IOC extractor (`iocextractor`)

| Key | Default | Description |
|---|---|---|
| `ignore_tags` | `["#winapi", "#code", "#code-junk", "#reloc"]` | String tags excluded from extraction. |
| `tld_file` | cache dir | TLD list location; relative paths resolve against the project root. Updated from IANA with the given freshness; metadata lives in the cache dir, **never in tools_config.json**. |
| `tldupdatefreqdays` | `7` | TLD refresh interval. |
| `exclude_private_ips` | `false` | Drop loopback/private/link-local IPs. |
| `defang` | `false` | Render URLs/domains defanged (`hxxp://evil[.]example[.]com`). |

### YARA scanner (`yara_scanner`)

| Key | Default | Description |
|---|---|---|
| `rule_path` | `"./yara_rules"` | File or directory of `.yar`/`.yara` rules (project-root relative). |
| `precompiled_rules` | `false` | Load a precompiled rule blob instead. |
| `recursive_search` | `true` | Recurse into subdirectories. |
| `fast_match` | `true` | Stop after the first match per string. |
| `timeout` | `60` | YARA engine timeout. |
| `max_matches` | `1000` | Cap on reported matched rules. |
| `ignored_tags` | `["info", "benign", "fp"]` | Rules carrying these tags are not reported. |

### Limits (`limits`)

| Key | Default | Description |
|---|---|---|
| `max_file_bytes` | 2 GiB | Input size guard. |
| `max_resource_bytes` | 100 MiB | Max size of a single extracted artifact. |
| `max_total_extracted_bytes` | 1 GiB | Total extraction budget per run. |
| `max_raw_json_mb` | 512 | Max size of a plugin raw JSON file (oversized payloads are replaced by a truncation stub). |
| `max_summary_items` | 10000 | Max entries per summary category. |
| `max_strings` | 1,000,000 | Strings published to the IOC extractor. |
| `max_ioc_text_mb` | 64 | Text block fed to the IOC regex engine. |
| `max_matches` | 1000 | YARA matches kept per run. |

## Reporter config (`reporter_config.json`)

```json
{
    "reporters": {
        "json_reporter": {
            "enabled": true,
            "output_template": ["fileinfo", "capa", "..."]
        }
    }
}
```

- `enabled` (bool): set `false` to disable a reporter.
- `output_template` (list of strings): `plugin_id`s in the order they should
  appear in the report. Plugins that ran but are not listed are appended at
  the end in sorted order.

## Environment variables

- `VT_API_KEY`, `MB_API_KEY` - TI API keys (loaded from `.env` if present).
- `STATCHHECK_STRICT_JSON` - set to `1` to make report serialization fail on
  unknown object types instead of falling back to `str()`.
- `XDG_CACHE_HOME` - redirects the statcheck cache dir (TLD lists, TI
  responses) away from `~/.cache`.
