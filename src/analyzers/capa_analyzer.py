import subprocess
import logging
from src.analyzers.base_analyzer import BaseAnalyzer
import json
from collections import defaultdict

logger = logging.getLogger(__name__)

class CapaAnalyzer(BaseAnalyzer):
    name = "capa Capability Analyzer"
    supported_formats = ['all']
    plugin_id="capa"
    depends = {"all": [], "any": []}

    def parse_analyzer_output(self, raw_results_dict: dict):
        output_summary = {}

        #Get all matched rule names
        matched_rules_list = (raw_results_dict["capa-all"]).get("rules",{})

        def extract_successful_features(node, matched_set):
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
            meta = rule_data.get("meta", {})
        
            # Format MITRE ATT&CK data if it exists
            attack_list = []
            for attack in meta.get("attack", []):
                attack_id = attack.get("id", "")
                attack_tactics = attack.get("tactic", "")
                attack_list.append(f"{attack_id} - {attack_tactics}")

            # Temp dictionary using sets to deduplicate locations
            matched_features_temp = set()
        
            for match in rule_data.get("matches", []):
                if len(match) > 1:
                    root_node = match[1]
                    extract_successful_features(root_node, matched_features_temp)

            # Convert sets back to lists for JSON serialization
            clean_matched_features = list(matched_features_temp)

            output_summary[rule_id] = {
                "name": meta.get("name", rule_id),
                "rule_description": meta.get("description", ""),
                "rule_attack": attack_list,
                "matched_features": clean_matched_features
            }

        return output_summary

    def analyze(self, target_file, tool_path, plugin_config, run_dir):
        logger.debug(f"Running capa on {target_file.filename}")

        import os
        if not os.path.exists(tool_path):
            logger.error(f"Configured binary not found: {tool_path}")
        else:
            logger.debug(f"Identified tool at path: {tool_path}")

        capa_tasks = {"capa-all":"-jq"}

        raw_results = {}

        for task_name, flag in capa_tasks.items():
            logger.debug(f"Running capa with flag: {flag}")

            try:
                # -j tells capa to output in pure JSON
                result = subprocess.run([tool_path, flag, str(target_file.path)], capture_output=True, text=True, check=True)
                
                if not result.stdout.strip():
                    logger.debug(f"capa flag {flag} returned empty output, SKipping.")
                else:
                    capa_data = json.loads(result.stdout)
                    raw_results[task_name] = capa_data
                    logger.debug(f"capa analysis for flag {flag} complete.")
                
            except subprocess.CalledProcessError as e:
                # Use warning instead of error so that if one check fails the rest are still executed
                logger.warning(f"capa ({flag}) failed to execute: {e.stderr.strip()}")
            except json.JSONDecodeError:
                logger.warning(f"capa ({flag}) output could not be parsed as JSON.")
            except Exception as e:
                logger.exception(f"Unexpected error in capa task '{task_name}'")
        
        logger.debug("Parsing capa output")
        parsed_results = self.parse_analyzer_output(raw_results)

        plugin_dir = self.get_plugin_dir(run_dir)
        raw_output_path = os.path.join(plugin_dir, "capa_raw_output.json")
        with open(raw_output_path, "w") as f:
            json.dump(raw_results, f, indent=4)
        parsed_results["raw_output_path"] = raw_output_path

        target_file.add_result(self.plugin_id,summary_data=parsed_results)