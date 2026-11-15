# Configuration reference

Statcheck reads two JSON files:

| File | CLI override | Purpose |
|---|---|---|
| `tools_config.json` | `--config` | External tools, analyzer options, and resource limits |
| `reporter_config.json` | `--reporter-config` | Reporter enablement and section order |

By default, both files are in the project root, independent of the caller's
working directory. A missing file produces a warning and built-in defaults;
invalid JSON or a validation error exits with code 2. Explicit relative CLI
paths follow normal working-directory resolution.

Paths inside the files use different bases:

- `bin_path` is relative to the **tool config file's directory**.
- YARA `rule_path` and IOC `tld_file` are relative to the **project root**.
- Absolute paths are accepted. Use them for resources outside the project
  layout, especially for non-editable installations.

## Validation scope

Validation is deliberately small; it is not a complete schema for every
plugin option.

| Behavior | Scope |
|---|---|
| Hard error (exit 2) | Non-object roots; invalid non-null config blocks; non-string non-null `bin_path` or `tool`; non-boolean non-null `enabled`; a non-null `output_template` that is not a list of strings; non-numeric, non-finite, or non-positive plugin `timeout` and `limits` values |
| Warning only | Unknown top-level keys in either file and unknown **analyzer** IDs in `plugins` |
| Not centrally validated | Plugin-specific option types, unknown plugin-specific keys, unknown limit names, unknown reporter IDs, and every nested `null` case |

For example, `"enabled": "true"` is an error, while a misspelled
plugin-specific option can remain unnoticed until that analyzer runs. Use the
documented JSON types rather than `null`: nested nulls are not consistently
rejected by the lightweight validator and can surface later as analyzer or
reporter failures (exit 1).

## Tool configuration

### Top-level keys

| Key | Type | Default | Description |
|---|---|---|---|
| `bin_path` | string | `"./bin"` | External-binary directory, resolved relative to this config file |
| `plugins` | object | `{}` | Per-analyzer settings keyed by analyzer `plugin_id` |
| `limits` | object | built-in values | Resource limits described below |

### Common analyzer keys

| Key | Default | Description |
|---|---|---|
| `enabled` | `true` for most built-ins | Set `false` to skip an analyzer. **`vtlookup` and `malwarebazaar` are exceptions: both require an explicit `"enabled": true`, even when their config block already exists.** |
| `tool` | analyzer ID | Binary name under `bin_path`; if it is not executable there, statcheck searches `PATH` for the **same basename** |
| `timeout` | `--timeout` value | Subprocess deadline for capa, DiE, FLOSS, and QuantumStrand |
| Other keys | plugin-specific | Passed to the analyzer without general type validation |

For those four subprocess-based analyzers, timeout precedence is:

1. `plugins.<id>.timeout`;
2. the CLI `--timeout` value (default 300 seconds);
3. 300 seconds when no runtime value was supplied programmatically.

The deadline applies separately to each invocation (DiE can invoke its tool
four times). YARA does **not** use this chain: its independent plugin `timeout`
defaults to 60 seconds. TI HTTP timeouts, retries, and relation-request sleeps
are also separate from `--timeout`.

## Threat intelligence: `vtlookup` and `malwarebazaar`

Enabling either plugin permits network requests. Both depend on `fileinfo` and
need their configured API-key environment variable. Each sets
`enabled_by_default = False`, so a config block without explicit
`"enabled": true` remains disabled.

| Plugin | Key | Runtime default | Behavior |
|---|---|---|---|
| Both | `api_key_env` | `VT_API_KEY` / `MB_API_KEY` | Environment variable containing the API key |
| Both | `lookup_exact_hash` | `true` | Look up the file's SHA-256 |
| Both | `cache_ttl_seconds` | `86400` | Freshness TTL for the exact-hash disk cache |
| Both | `lookup_fuzzy_hash` | `false` | Enable the provider's optional similarity pivots |
| VT | `fetch_relations_behaviour` | `false` | After a successful exact lookup, fetch contacted IPs/domains, dropped/bundled files, execution parents, and in-the-wild URLs |
| VT | `relations_result_limit` | `40` | Maximum items requested from **each** relation endpoint |
| VT | `rate_limit_sleep` | `20` | Seconds slept **between** relation requests; none before the first |
| VT | `fuzzy_lookup_limit` | `5` | Maximum results requested for the live SSDeep search; requires an available SSDeep hash and may require premium access |
| MB | `relation_limit` | `10` | Maximum related files kept in the summary for each available TLSH/ImpHash pivot; raw pivot responses are not truncated by this setting |
| MB | `base_url` | `https://mb-api.abuse.ch/api/v1/` | MalwareBazaar endpoint, primarily useful for tests |

`base_url` is **MalwareBazaar-only**; the built-in VT analyzer has no
`base_url` setting. MB fuzzy mode tries TLSH and ImpHash when those hashes are
available and sleeps five seconds before each pivot request.

The supplied [`tools_config.json.example`](../tools_config.json.example)
explicitly sets VT `fetch_relations_behaviour: true` and MB
`lookup_fuzzy_hash: true`. Those are
example opt-ins, **not runtime fallbacks**; its TI blocks still have
`enabled: false`. Omitting these optional lookup keys uses the runtime defaults
in the table.

Only exact-hash responses use the lock-protected disk cache. VT relations, VT
fuzzy searches, and MB fuzzy pivots are always live. Cache maintenance prunes
expired entries and retains at most 1024 entries per provider. MalwareBazaar
uses statcheck's retrying HTTP session for 429, 500, 502, 503, and 504
responses and honors `Retry-After`; VT uses the official `vt-py` client without
that additional retry session. See [Security notes](security.md) for cache
sensitivity and the network inventory.

## IOC extractor: `iocextractor`

| Key | Default | Description |
|---|---|---|
| `ignore_tags` | `["#winapi", "#code", "#code-junk", "#reloc"]` | Exclude merged strings carrying any listed tag before input caps are applied |
| `tld_file` | `<cache>/tlds.txt` | TLD list path; a configured relative path is project-root-relative. Its parent must exist, and an update must be able to create/write the destination |
| `tldupdatefreqdays` | `7` | Check IANA when the list is missing or the last update is older than this interval; write a missing list or a newer IANA version |
| `exclude_private_ips` | `false` | Drop addresses classified as private, loopback, link-local, **or reserved** |
| `defang` | `false` | Defang extracted URLs and domains only; this is not general report sanitization |

When extraction has input strings and the TLD file is missing/stale, statcheck
makes a GET request to IANA. The request contains no sample data. Update
metadata is always `<cache>/tlds.meta.json`, even when `tld_file` points
elsewhere. If the TLD file does not exist after update attempts, a small
built-in fallback (`com`, `net`, `org`, `io`, `xyz`) is used.

Legacy `tldupdatedon` and `tld_version` values in `tools_config.json` are read
only as fallback freshness hints when the corresponding cache metadata fields
are absent. Statcheck never
writes those values, or any other runtime state, back to the config file.

## YARA scanner: `yara_scanner`

| Key | Default | Description |
|---|---|---|
| `rule_path` | `"./yara_rules"` | Project-root-relative rule file, precompiled blob, or directory |
| `precompiled_rules` | `false` | Load a precompiled blob instead of compiling source rules |
| `recursive_search` | `true` | Recurse below a rule directory |
| `fast_match` | `true` | Use YARA fast matching |
| `timeout` | `60` | YARA engine timeout in seconds; independent of CLI `--timeout` |
| `max_matches` | `limits.max_matches`, then 1000 | Plugin-level value overrides the global limit |
| `ignored_tags` | `["info", "benign", "fp"]` | Suppress rules carrying any listed tag |

Ignored-tag filtering happens **before** deterministic sorting and the
`max_matches` cap, so ignored rules cannot consume the cap.

## Resource and overlay extraction: `resource_overlay`

| Key | Default | Description |
|---|---|---|
| `extract_resources` | `true` | Write PE resources only when flagged as risky: entropy above 7.0 or a recognized embedded file type |
| `extract_overlay` | `true` | Write a detected PE or ELF overlay, subject to extraction budgets |
| `max_resource_bytes` | global limit | Per-plugin override for one extracted resource/overlay |
| `max_total_extracted_bytes` | global limit | Per-plugin override for this analyzer's combined extraction budget |

Disabling extraction does not disable parsing, hashes, entropy, or raw JSON
metadata. ELF analysis covers overlays, not PE resources. Resource filenames
are sanitized, and paths in reports are run-directory-relative.

## Resource limits

Set these under top-level `limits`. Values must be finite numbers greater than
zero; integer values are recommended for byte/item counts.

| Key | Default | Actual scope |
|---|---|---|
| `max_file_bytes` | 2 GiB | Reject an oversized target before format detection or analyzers; this early rejection creates no report |
| `max_tool_output_mb` | 512 | Maximum captured **bytes for each of stdout and stderr per subprocess invocation**; exceeding either cap makes the built-in tool analyzer unavailable |
| `max_resource_bytes` | 100 MiB | Maximum size of one resource/overlay extraction |
| `max_total_extracted_bytes` | 1 GiB | Combined resource/overlay extraction budget for one analyzer run |
| `max_raw_json_mb` | 512 | Per raw JSON file: compare the indented serialized JSON's **character count** with `int(value) * 1024²`; oversized content becomes a truncation stub. This is not an exact UTF-8 byte limit |
| `max_summary_items` | 10000 | For built-ins, cap **only the IOC extractor's individual IOC category lists**; it is not a universal cap on every plugin summary |
| `max_strings` | 1,000,000 | Cap FLOSS/QuantumStrand `internal_context` IOC inputs and the sorted, merged IOC input pool. It does not cap QuantumStrand's tag-specific summary lists or raw tool output |
| `max_ioc_text_mb` | 64 | UTF-8 byte cap on the joined text passed to IOC regexes |
| `max_matches` | 1000 | Default YARA match cap unless `plugins.yara_scanner.max_matches` overrides it |

These are resource guards, not a sandbox or a complete memory/disk limit; see
[Security notes](security.md).

## Reporter configuration

```json
{
  "reporters": {
    "json_reporter": {
      "enabled": true,
      "output_template": ["fileinfo", "capa", "iocextractor"]
    },
    "markdown_reporter": {
      "enabled": true,
      "output_template": ["fileinfo", "capa", "iocextractor"]
    }
  }
}
```

- `enabled` defaults to `true` for a discovered, requested reporter.
- `output_template` orders matching `result_summary` sections. Other sections
  are appended in sorted order.
- `--report json`, `--report markdown`, or `--report all` selects formats;
  disabling a reporter in config prevents that report from being written.

## Environment and cache locations

- `VT_API_KEY` and `MB_API_KEY` hold TI credentials (`.env` is supported).
- `STATCHHECK_STRICT_JSON` enables strict **final JSON report** serialization
  when set to **any nonempty value**, including `"0"`. `--debug` also enables
  it. Known dates, paths, sets, and bytes still have explicit serializers;
  unknown object types raise instead of using `str()`. Raw analyzer JSON and
  cache serialization are unaffected. A strict-mode failure is a reporter
  failure and makes the run exit 1.
- `XDG_CACHE_HOME` moves the cache root. The default cache is
  `~/.cache/statcheck`; with it set, the cache is
  `$XDG_CACHE_HOME/statcheck`. It holds TI exact-hash responses and TLD update
  metadata, plus the default TLD list when no custom `tld_file` is configured.
