import json
import logging

from src.analyzers.base_analyzer import BaseAnalyzer, resolve_tool_path
from src.core.process import ToolError, run_tool

logger = logging.getLogger(__name__)

class FlossAnalyzer(BaseAnalyzer):
    name = "FLOSS String Extractor"
    supported_formats = ['pe']
    plugin_id = "floss"
    depends = {"all": [], "any": []}

    def analyze(self, target_file, tool_path, plugin_config, run_dir):
        logger.debug(f"Starting FLOSS analysis on {target_file.filename}")
        
        min_length_string = plugin_config.get("min_string_length", 5)
        logger.debug(f"Minimum string length for floss set to {min_length_string}")

        # Resolve the FLOSS executable: configured path first, then PATH lookup.
        executable = resolve_tool_path(tool_path)
        if executable is None:
            reason = f"floss binary not found (configured: '{tool_path}')."
            logger.warning(reason)
            target_file.add_result(self.plugin_id, summary_data={
                "status": "unavailable",
                "reason": reason,
            })
            return

        timeout = self.resolve_timeout(plugin_config)
        max_strings = int(self.get_limit("max_strings"))

        # RUN FLOSS SUBPROCESS (ToolTimeout propagates to the orchestrator so
        # the run metadata records a 'timeout' status for this plugin.)
        try:
            result = run_tool(
                [executable, "-j", "-q", "-n", str(min_length_string), str(target_file.path)],
                timeout=timeout
            )
        except ToolError as e:
            logger.error(f"FLOSS execution failed: {e}")
            target_file.add_result(self.plugin_id, summary_data={
                "status": "unavailable",
                "reason": str(e),
            })
            return

        # PARSE JSON & FLATTEN STRINGS
        try:
            floss_json = json.loads(result.stdout)
        except json.JSONDecodeError:
            logger.error("Failed to decode FLOSS JSON.")
            target_file.add_result(self.plugin_id, summary_data={
                "status": "unavailable",
                "reason": "floss produced invalid JSON output.",
            })
            return

        summary = {}

        # EXTRACT FLOSS METADATA & ANALYSIS STATS
        analysis_block = floss_json.get("analysis", {})
        functions_block = analysis_block.get("functions", {})
        metadata_block = floss_json.get("metadata", {})

        # Get all 'enable_' keys to add to summary
        summary["floss_config"] = {
            k: v for k, v in analysis_block.items() if k.startswith("enable_")
        }

        # 2. Get all 'analyzed_' function counts to add to summary
        summary["floss_functions"] = {
            k: v for k, v in functions_block.items() if k.startswith("analyzed_")
        }

        # 3. Get specific Metadata
        summary["floss_metadata"] = {
            "language": metadata_block.get("language", "Unknown"),
            "language_selected": metadata_block.get("language_selected", "Unknown"),
            "min_length": metadata_block.get("min_length"),
            "version": metadata_block.get("version", "Unknown")
        }

        summary["raw_output_path"] = self.save_raw(run_dir, "floss_raw_output.json", floss_json)

        # EXTRACT & DEDUPLICATE STRINGS using set
        extracted_strings = set()
        strings_block = floss_json.get("strings", {})
        
        # Iterate through every category (decoded, static, stack, etc.)
        for _category, string_list in strings_block.items():
            if isinstance(string_list, list):
                for string_item in string_list:
                    # Check if it's a dict and has the "string" key
                    if isinstance(string_item, dict) and "string" in string_item:
                        extracted_strings.add(string_item["string"])

        # NORMALIZE FOR THE IOC Extractor
        # The Extractor expects a list of dictionaries with "string" and "tags"
        ioc_input_list = [{"string": s, "tags": []} for s in extracted_strings]

        # Enforce the max_strings limit (Phase 3.4).
        if len(ioc_input_list) > max_strings:
            logger.warning(
                f"floss: capping published strings at max_strings "
                f"({len(ioc_input_list)} -> {max_strings})."
            )
            ioc_input_list = ioc_input_list[:max_strings]

        if not ioc_input_list:
            logger.warning("FLOSS did not find any strings in the file.")
            target_file.add_result(self.plugin_id, summary_data=summary)
            return
        
        # PUBLISH TO RESULT COMPLETE
        target_file.add_result(
            self.plugin_id,
            summary_data=summary,
            internal_context_data={
                "ioc_extractor_input": ioc_input_list
            }
        )
        logger.info(f"FLOSS published {len(ioc_input_list)} strings for extraction.")
