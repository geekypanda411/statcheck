import json
import logging

from src.analyzers.base_analyzer import BaseAnalyzer, resolve_tool_path
from src.core.process import ToolError, ToolTimeout, run_tool

logger = logging.getLogger(__name__)


class QuantumStrandAnalyzer(BaseAnalyzer):
    name = "QUANTUMSTRAND String Extractor BETA"
    supported_formats = ["all"]
    plugin_id = "quantumstrand"

    # Needs no dependencies. Runs immediately.
    depends = {"all": [], "any": []}

    def analyze(self, target_file, tool_path, plugin_config, run_dir):
        logger.debug(f"Starting QUANTUMSTRAND (BETA) analysis on {target_file.filename}")

        min_string_length = plugin_config.get("min_string_length", 5)
        # Default to #winapi, but allow config overrides
        summary_tags = plugin_config.get("summary_tags", ["#winapi"])

        # Resolve the QuantumStrand executable: configured path first, then PATH lookup.
        executable = resolve_tool_path(tool_path)
        if executable is None:
            reason = f"quantumstrand binary not found (configured: '{tool_path}')."
            logger.warning(reason)
            target_file.add_result(
                self.plugin_id,
                summary_data={
                    "status": "unavailable",
                    "reason": reason,
                },
            )
            return

        timeout = self.resolve_timeout(plugin_config)
        max_strings = int(self.get_limit("max_strings"))
        max_output_bytes = int(self.get_limit("max_tool_output_mb")) * 1024 * 1024

        # RUN QS SUBPROCESS (ToolTimeout propagates to the orchestrator so the
        # run metadata records a 'timeout' status for this plugin.)
        try:
            result = run_tool(
                [executable, "-j", "-q", "-n", str(min_string_length), str(target_file.path)],
                timeout=timeout,
                max_output_bytes=max_output_bytes,
            )
        except ToolTimeout:
            # Let timeouts propagate so the orchestrator records a
            # 'timeout' status for this plugin.
            raise
        except ToolError as e:
            logger.error(f"QUANTUMSTRAND execution failed: {e}")
            target_file.add_result(
                self.plugin_id,
                summary_data={
                    "status": "unavailable",
                    "reason": str(e),
                },
            )
            return

        # PARSE JSON
        try:
            qs_json = json.loads(result.stdout)
        except json.JSONDecodeError:
            logger.error("Failed to decode QUANTUMSTRAND JSON.")
            target_file.add_result(
                self.plugin_id,
                summary_data={
                    "status": "unavailable",
                    "reason": "quantumstrand produced invalid JSON output.",
                },
            )
            return

        # EXTRACT METADATA
        meta_block = qs_json.get("meta", {})

        summary = {
            "metadata": {
                "version": meta_block.get("version", "Unknown"),
                "timestamp": meta_block.get("timestamp", "Unknown"),
                "sha256": meta_block.get("sample", {}).get("sha256", "Unknown"),
                "min_str_len": meta_block.get("min_str_len", min_string_length),
            }
        }

        # Initialize holding buckets for dynamic tag extraction
        for tag in summary_tags:
            clean_tag = tag.replace("#", "").replace("-", "_")
            summary[f"{clean_tag}_strings"] = set()

        # EXTRACT & DEDUPLICATE STRINGS (Recursive)
        # use a dictionary to deduplicate strings while combining their tags
        deduped_strings = {}

        def traverse_layout(node):
            # Recursively hunt through the layout tree for the 'strings' arrays.
            if not isinstance(node, dict):
                return

            # Extract strings at the current node
            for s_obj in node.get("strings", []):
                s_val = s_obj.get("string")
                if s_val:
                    tags = s_obj.get("tags", [])

                    # If string exists, merge the new tags into the existing set
                    if s_val not in deduped_strings:
                        deduped_strings[s_val] = set(tags)
                    else:
                        deduped_strings[s_val].update(tags)

            # Recursively dig into children nodes (e.g., .text, .rsrc)
            for child in node.get("children", []):
                traverse_layout(child)

        # Start the traversal at the root of the layout tree
        traverse_layout(qs_json.get("layout", {}))

        if not deduped_strings:
            logger.warning("QUANTUMSTRAND did not find any strings in the file.")
            raw_rel_path = self.save_raw(run_dir, "quantumstrand_raw_output.json", qs_json)
            target_file.add_result(
                self.plugin_id,
                summary_data={"strings_found": 0, "raw_output_path": raw_rel_path},
            )
            return

        # FORMAT FOR IOC EXTRACTOR & SUMMARY
        ioc_extractor_input = []

        for string_val in sorted(deduped_strings):
            tags_set = deduped_strings[string_val]
            # 1. Format the Pub/Sub contract for the IOC Extractor
            ioc_extractor_input.append({"string": string_val, "tags": sorted(tags_set)})

            # 2. Check if this string belongs in our Summary block
            for target_tag in summary_tags:
                if target_tag in tags_set:
                    clean_tag = target_tag.replace("#", "").replace("-", "_")
                    summary[f"{clean_tag}_strings"].add(string_val)

        # Enforce the max_strings limit (Phase 3.4).
        if len(ioc_extractor_input) > max_strings:
            logger.warning(
                f"quantumstrand: capping published strings at max_strings "
                f"({len(ioc_extractor_input)} -> {max_strings})."
            )
            ioc_extractor_input = ioc_extractor_input[:max_strings]

        summary["raw_output_path"] = self.save_raw(run_dir, "quantumstrand_raw_output.json", qs_json)

        # Clean empty lists from the summary (e.g., if no #winapi was found)
        clean_summary = {k: (sorted(v) if isinstance(v, set) else v) for k, v in summary.items() if v}

        # PUBLISH RESULTS
        target_file.add_result(
            self.plugin_id,
            summary_data=clean_summary,
            internal_context_data={"ioc_extractor_input": ioc_extractor_input},
        )
        logger.info(f"QUANTUMSTRAND published {len(ioc_extractor_input)} deduplicated strings.")
