import json
import logging
from pathlib import Path

from src.analyzers.base_analyzer import BaseAnalyzer, resolve_tool_path
from src.core.process import ToolError, ToolTimeout, run_tool

logger = logging.getLogger(__name__)


class CapaAnalyzer(BaseAnalyzer):
    name = "capa Capability Analyzer"
    supported_formats = ["all"]
    plugin_id = "capa"
    depends = {"all": [], "any": []}

    def parse_analyzer_output(self, raw_results_dict: dict):
        output_summary: dict = {}

        # Guard: capa may be missing, have failed, or returned invalid JSON.
        capa_all = raw_results_dict.get("capa-all")
        if not isinstance(capa_all, dict):
            logger.debug("No valid 'capa-all' payload to parse; returning empty summary.")
            return output_summary

        # Get all matched rule names
        matched_rules_list = capa_all.get("rules", {})
        if not isinstance(matched_rules_list, dict):
            logger.debug("'capa-all' payload has no rule dict; returning empty summary.")
            return output_summary

        def extract_successful_features(node, matched_set):
            if not isinstance(node, dict):
                return
            # Base case: if this branch failed, ignore it
            if not node.get("success"):
                return

            node_data = node.get("node", {})

            # If we hit a node with an actual matched feature like an API or string
            if node_data.get("type") == "feature":
                feature_obj = node_data.get("feature", {})
                feature_type = feature_obj.get("type")
                feature_value = feature_obj.get(feature_type)

                # Create a clean key e.g. "api: fopen" or "string: 'http://malicious.com'"
                feature_name = f"{feature_type}: {feature_value}"

                matched_set.add(feature_name)

            # Recursively process the 'and'/'or' branches
            for child in node.get("children", []):
                extract_successful_features(child, matched_set)

        # Process each matched rule
        for rule_id, rule_data in matched_rules_list.items():
            if not isinstance(rule_data, dict):
                continue
            meta = rule_data.get("meta", {})

            # Format MITRE ATT&CK data if it exists
            attack_list = []
            for attack in meta.get("attack", []):
                attack_id = attack.get("id", "")
                attack_tactics = attack.get("tactic", "")
                attack_list.append(f"{attack_id} - {attack_tactics}")

            # Temp set to deduplicate locations
            matched_features_temp: set = set()

            for match in rule_data.get("matches", []):
                if len(match) > 1:
                    root_node = match[1]
                    extract_successful_features(root_node, matched_features_temp)

            # Convert sets to sorted lists for deterministic JSON serialization.
            clean_matched_features = sorted(matched_features_temp)

            output_summary[rule_id] = {
                "name": meta.get("name", rule_id),
                "rule_description": meta.get("description", ""),
                "rule_attack": attack_list,
                "mbc": meta.get("mbc", []),
                "namespace": meta.get("namespace", ""),
                "scopes": meta.get("scopes", {}),
                "lib": bool(meta.get("lib", False)),
                "matched_features": clean_matched_features,
            }

        return output_summary

    def analyze(self, target_file, tool_path, plugin_config, run_dir):
        logger.debug(f"Running capa on {target_file.filename}")

        # Resolve the capa executable: configured path first, then PATH lookup.
        executable = resolve_tool_path(tool_path)
        if executable is None:
            reason = (
                f"capa binary not found (configured: '{tool_path}', "
                f"also searched PATH for '{Path(tool_path).name if tool_path else 'capa'}')."
            )
            logger.warning(reason)
            target_file.add_result(
                self.plugin_id,
                summary_data={
                    "status": "unavailable",
                    "reason": reason,
                },
            )
            return
        logger.debug(f"Using capa executable at: {executable}")

        timeout = self.resolve_timeout(plugin_config)
        max_output_bytes = int(self.get_limit("max_tool_output_mb")) * 1024 * 1024
        # Tell capa the sample format explicitly; capa rejects formats it does
        # not know, so anything exotic falls back to 'auto'.
        capa_format = target_file.format if target_file.format in ("pe", "elf") else "auto"
        capa_tasks = {"capa-all": ["-jq", "-f", capa_format]}

        raw_results = {}
        errors = []

        for task_name, flags in capa_tasks.items():
            logger.debug(f"Running capa with flags: {flags}")

            try:
                # -j tells capa to output in pure JSON
                result = run_tool(
                    [executable, *flags, str(target_file.path)],
                    timeout=timeout,
                    max_output_bytes=max_output_bytes,
                )

                if not result.stdout.strip():
                    logger.debug(f"capa flags {flags} returned empty output, skipping.")
                else:
                    capa_data = json.loads(result.stdout)
                    raw_results[task_name] = capa_data
                    logger.debug(f"capa analysis for flags {flags} complete.")

            except ToolTimeout:
                # Let the orchestrator record a timeout instead of a generic tool failure.
                raise
            except ToolError as e:
                logger.warning(f"capa ({flags}) failed to execute: {e}")
                errors.append(str(e))
                break
            except json.JSONDecodeError as e:
                logger.warning(f"capa ({flags}) output could not be parsed as JSON.")
                errors.append(f"invalid JSON output: {e}")
                break

        logger.debug("Parsing capa output")
        parsed_results = self.parse_analyzer_output(raw_results)

        # Always write the raw output, even when empty/failed, so the run
        # directory carries the evidence of what capa actually returned.
        parsed_results["raw_output_path"] = self.save_raw(run_dir, "capa_raw_output.json", raw_results)
        if errors:
            parsed_results["status"] = "unavailable"
            parsed_results["reason"] = "; ".join(errors)
        else:
            parsed_results["status"] = "ok" if "capa-all" in raw_results else "no_output"
            if parsed_results["status"] != "ok":
                parsed_results["reason"] = "capa produced no parseable output for this sample."

        target_file.add_result(self.plugin_id, summary_data=parsed_results)
