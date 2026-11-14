import logging
import os
from pathlib import Path

import yara

from src.analyzers.base_analyzer import BaseAnalyzer
from src.core.paths import resolve_path

logger = logging.getLogger(__name__)

# Module-level cache: compiling a large rule set is expensive, so the same
# rules (same path + same file mtimes/sizes + same mode) are reused across
# runs within one process.
_RULES_CACHE: dict[tuple, object] = {}


def _rules_cache_key(rule_path: Path, precompiled: bool, recursive: bool):
    """Cache key: absolute path + file identity (mtime/size) + mode."""
    if precompiled or rule_path.is_file():
        stat = rule_path.stat()
        return (str(rule_path), precompiled, stat.st_mtime_ns, stat.st_size)

    entries = []
    for root, _dirs, files in os.walk(rule_path):
        for f in files:
            if f.endswith(".yar") or f.endswith(".yara"):
                fp = Path(root) / f
                st = fp.stat()
                entries.append((str(fp.relative_to(rule_path)), st.st_mtime_ns, st.st_size))
        if not recursive:
            break  # Stop after top-level directory if recursive is False
    return (str(rule_path), False, tuple(sorted(entries)))


def _compile_rules(rule_path: Path, precompiled: bool, recursive: bool):
    """Compile (or load) YARA rules; returns (rules, from_cache)."""
    key = _rules_cache_key(rule_path, precompiled, recursive)
    cached = _RULES_CACHE.get(key)
    if cached is not None:
        logger.debug("Reusing cached YARA rules for this process.")
        return cached, True

    rules = None
    if precompiled:
        logger.debug(f"Loading precompiled YARA rules from {rule_path}")
        rules = yara.load(str(rule_path))
    elif rule_path.is_file():
        logger.debug(f"Compiling single YARA rule file: {rule_path}")
        rules = yara.compile(filepath=str(rule_path))
    else:
        logger.debug(f"Compiling YARA rules directory: {rule_path}")
        # Namespaces are stored relative to rule_path so reports do not leak
        # absolute local paths.
        filepaths = {}
        for root, _dirs, files in os.walk(rule_path):
            for f in files:
                if f.endswith(".yar") or f.endswith(".yara"):
                    full_path = os.path.join(root, f)
                    namespace = str(Path(full_path).relative_to(rule_path))
                    filepaths[namespace] = full_path
            if not recursive:
                break
        if not filepaths:
            return None, False
        rules = yara.compile(filepaths=filepaths)

    _RULES_CACHE[key] = rules
    return rules, False


class YaraAnalyzer(BaseAnalyzer):
    name = "YARA Scanner"
    supported_formats = ["all"]
    plugin_id = "yara_scanner"

    # Standalone tool
    depends = {"all": [], "any": []}

    DEFAULT_MAX_MATCHES = 1000

    def analyze(self, target_file, tool_path, plugin_config, run_dir):
        logger.debug(f"Starting YARA scan on {target_file.filename}")

        # LOAD CONFIGURATION (rule_path is project-root relative, not CWD)
        configured_rule_path = plugin_config.get("rule_path", "./yara_rules")
        rule_path = resolve_path(configured_rule_path)
        precompiled = plugin_config.get("precompiled_rules", False)
        recursive = plugin_config.get("recursive_search", True)
        timeout_limit = plugin_config.get("timeout", 60)
        fast_match = plugin_config.get("fast_match", True)
        ignored_tags = set(plugin_config.get("ignored_tags", ["info", "benign", "fp"]))
        max_matches = int(plugin_config.get("max_matches", self.get_limit("max_matches", self.DEFAULT_MAX_MATCHES)))

        if not rule_path.exists():
            reason = f"YARA rule path does not exist: {rule_path}"
            logger.error(reason)
            target_file.add_result(
                self.plugin_id,
                summary_data={
                    "status": "unavailable",
                    "reason": reason,
                },
            )
            return

        # COMPILE / LOAD RULES (cached across runs in this process)
        try:
            rules, from_cache = _compile_rules(rule_path, precompiled, recursive)
        except yara.SyntaxError as e:
            reason = f"YARA syntax error in rules: {e}"
            logger.error(reason)
            target_file.add_result(
                self.plugin_id,
                summary_data={
                    "status": "unavailable",
                    "reason": reason,
                },
            )
            return
        except Exception as e:
            logger.exception(f"Failed to load/compile YARA rules: {e}")
            target_file.add_result(
                self.plugin_id,
                summary_data={
                    "status": "unavailable",
                    "reason": f"failed to compile rules: {e}",
                },
            )
            return

        if rules is None:
            reason = f"No .yar or .yara files found in {rule_path}"
            logger.warning(reason)
            target_file.add_result(
                self.plugin_id,
                summary_data={
                    "status": "unavailable",
                    "reason": reason,
                },
            )
            return

        # SCAN THE FILE
        matches = []
        try:
            logger.debug(
                f"Executing YARA engine (Timeout: {timeout_limit}s, Fast: {fast_match}, "
                f"Cache: {'hit' if from_cache else 'miss'})"
            )
            matches = rules.match(str(target_file.path), timeout=timeout_limit, fast=fast_match)
        except yara.TimeoutError:
            logger.error(f"YARA scan timed out after {timeout_limit} seconds. Rules might be poorly optimized.")
            target_file.add_result(
                self.plugin_id,
                summary_data={
                    "status": "timeout",
                    "reason": f"YARA scan exceeded {timeout_limit}s",
                },
            )
            return
        except Exception as e:
            logger.exception(f"YARA matching engine crashed: {e}")
            target_file.add_result(
                self.plugin_id,
                summary_data={
                    "status": "unavailable",
                    "reason": f"YARA engine error: {e}",
                },
            )
            return

        # Enforce max_matches (deterministic: cap after stable ordering).
        matches = sorted(matches, key=lambda m: (str(m.rule), tuple(m.tags)))
        if len(matches) > max_matches:
            logger.warning(f"yara_scanner: capping matched rules at max_matches ({len(matches)} -> {max_matches}).")
            matches = matches[:max_matches]

        # PARSE RESULTS
        summary_matches = []
        raw_matches = []

        for match in matches:
            # 1. Check against the ignored_tags filter
            if any(tag in ignored_tags for tag in match.tags):
                continue

            rule_name = match.rule
            tags = sorted(match.tags)
            meta = match.meta

            # 2. Extract matched strings with Two-Stage Decoding
            # YARA strings format: (offset, string_identifier, string_data)
            parsed_strings = []
            for string_match in match.strings:
                # For modern YARA versions
                if hasattr(string_match, "instances"):
                    str_id = string_match.identifier
                    for instance in string_match.instances:
                        offset = instance.offset
                        str_data = instance.matched_data

                        try:
                            clean_data = str_data.decode("utf-8", errors="strict")
                            match_type = "text"
                        except UnicodeDecodeError:
                            clean_data = str_data.hex()
                            match_type = "hex"

                        parsed_strings.append(
                            {"offset": hex(offset), "identifier": str(str_id), "type": match_type, "data": clean_data}
                        )

                # For old versions
                else:
                    offset, str_id, str_data = string_match
                    try:
                        clean_data = str_data.decode("utf-8", errors="strict")
                        match_type = "text"
                    except UnicodeDecodeError:
                        clean_data = str_data.hex()
                        match_type = "hex"

                    parsed_strings.append(
                        {"offset": hex(offset), "identifier": str(str_id), "type": match_type, "data": clean_data}
                    )

            parsed_strings.sort(key=lambda p: (p["offset"], p["identifier"]))

            # 3. Append to Raw (goes to disk)
            raw_matches.append({"rule": rule_name, "tags": tags, "meta": meta, "strings": parsed_strings})

            # 4. Append to Summary
            summary_matches.append(
                {
                    "rule": rule_name,
                    "description": meta.get("description", "No description provided."),
                    "author": meta.get("author", "Unknown"),
                    "tags": tags,
                }
            )

        # SAVE TO UNIFIED PACKAGE
        # Always write raw output (even when empty) so the run directory
        # documents that the scan actually ran.
        raw_rel_path = self.save_raw(run_dir, "yara_raw_output.json", {"yara_matches": raw_matches})

        # 2. Add the summary to the TargetFile
        target_file.add_result(
            self.plugin_id,
            summary_data={
                "matched_rules": summary_matches,
                "match_count": len(summary_matches),
                "raw_output_path": raw_rel_path,
            },
        )
        logger.info(f"YARA scan complete. {len(summary_matches)} rules matched.")
