# Testdev review findings and remediation

Review baseline: `testdev` at `1a70e90` compared with `main`.
Items are checked only after implementation and regression coverage are in place.

## High severity

- [x] 1. Sanitize named PE resource types and prevent extraction path traversal/collisions.
- [x] 2. Disable VirusTotal and MalwareBazaar by default when no config entry exists.
- [x] 3. Return a failure exit code for analyzer or reporter failures instead of logging success.
- [x] 4. Prevent same-second run-directory and report collisions.
- [x] 5. Repair capa/FLOSS provisioning URLs, output names, and failure handling.
- [x] 6. Enforce input and output resource limits; bound subprocess output and cached file reads.

## Correctness and logic

- [x] 7. Exclude ELF headers and other legitimate structures from overlay detection.
- [x] 8. Do not classify dynamically linked shared objects as statically linked.
- [x] 9. Propagate tool timeouts and align summary/metadata status reporting.
- [x] 10. Extract domains followed by whitespace, ports, and other valid boundaries.
- [x] 11. Apply IOC input limits deterministically after merging concurrent producers.
- [x] 12. Filter ignored YARA rules before applying `max_matches`.
- [x] 13. Fix Authenticode timestamp detection and avoid calling parse failures unsigned.
- [x] 14. Handle nullable MalwareBazaar fields without crashing.
- [x] 15. Generate reports even when every analyzer is disabled or dependency-pruned.

## Performance and lifecycle

- [x] 16. Terminate subprocess descendants on timeout and establish a safe cancellation boundary.
- [x] 17. Prevent lost TI cache updates, stale-entry retention, and whole-history rewrite growth.

## Documentation, packaging, and quality

- [x] 18. Make non-editable/Docker config, tool, rule, and output paths usable and documented.
- [x] 19. Correct installation alternatives and optional/mandatory dependency documentation.
- [x] 20. Correct determinism claims and remove remaining nondeterministic output.
- [x] 21. Fix broken/misleading docs links, TI retry claims, and plugin timeout example.
- [x] 22. Remove stale generated `build/` and `statcheck.egg-info/` artifacts and ignore them.

## Verification

- All 22 findings have implementation and regression coverage.
- Follow-up review also verified full process-tree deadlines, repeated-run
  isolation, pre-detection size enforcement, dependency-deadlock failures,
  cache pruning on read/failure paths, non-finite numeric rejection, partial
  DiE failures, dependency-free shared objects, and additional IOC delimiters.
- Final validation: **195 pytest tests passed**, Ruff passed, mypy passed,
  `git diff --check` passed, and `bash -n scripts/fetch-tools.sh` passed.
- Provisioning URLs and pinned archive digests were verified against the real
  upstream capa v10.0.0 and FLOSS v3.2.0 releases. Docker build verification
  was unavailable because the Docker CLI is not installed.
