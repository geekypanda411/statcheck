# Security notes

**statcheck performs static analysis only - it never executes the sample.**
Even so, treat every input as hostile.

## Isolation

- Run statcheck (and the external tools it shells out to) inside a dedicated
  VM or container. External tools parse untrusted input and have had
  vulnerabilities historically.
- The provided Dockerfile runs as a non-root user, but a container is *not*
  a security boundary against malicious file parsers; prefer a disposable VM
  for real malware.

## Sample handling

- Do not submit sensitive or classified samples to third-party services.
  With `vtlookup`/`malwarebazaar` enabled, file **hashes** (and fuzzy hashes
  if enabled) are sent to VirusTotal and abuse.ch. Both TI plugins are
  disabled by default.
- TI responses are cached on disk under `$XDG_CACHE_HOME/statcheck` - wipe
  the directory if that matters for your environment. Cache updates use file
  locks, prune expired entries, and retain at most 1024 entries per provider.

## API keys

- Keys are read from environment variables (`VT_API_KEY`, `MB_API_KEY`),
  optionally loaded from a gitignored `.env` file.
- Keys are never written to reports, logs, or the cache. Verify with
  `grep -r <key> reports/` after a test run if you want to be sure.

## Resource safety

- Every external tool invocation has a timeout (`timeout` config, `--timeout`)
  and its process tree is killed on timeout. Captured output is capped by
  `max_tool_output_mb` (512 MiB by default).
- `max_file_bytes` is enforced centrally. Extraction and raw-output sizes are
  capped via the `limits` config to bound disk use and report generation.
- Run directories contain extracted (potentially malicious) artifacts;
  sanitize before sharing.

## No sandbox guarantees

statcheck does not sandbox external tools, does not restrict their file
system access, and does not sanitize extracted content. Handle all outputs
with the same caution as the original sample.
