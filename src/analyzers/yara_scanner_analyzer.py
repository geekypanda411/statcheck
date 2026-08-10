import logging
import os
import json
import yara
from src.analyzers.base_analyzer import BaseAnalyzer

logger = logging.getLogger(__name__)

class YaraAnalyzer(BaseAnalyzer):
    name = "YARA Scanner"
    supported_formats = ['all']
    plugin_id = "yara_scanner"
    
    # Standalone tool
    depends = {"all": [], "any": []}

    def analyze(self, target_file, tool_path, plugin_config, run_dir):
        logger.debug(f"Starting YARA scan on {target_file.filename}")
        
        # LOAD CONFIGURATION
        rule_path = plugin_config.get("rule_path", "./yara_rules")
        precompiled = plugin_config.get("precompiled_rules", False)
        recursive = plugin_config.get("recursive_search", True)
        timeout_limit = plugin_config.get("timeout", 60)
        fast_match = plugin_config.get("fast_match", True)
        ignored_tags = set(plugin_config.get("ignored_tags", ["info", "benign", "fp"]))

        if not os.path.exists(rule_path):
            logger.error(f"YARA rule path does not exist: {rule_path}")
            return

        # COMPILE / LOAD RULES
        rules = None
        try:
            if precompiled:
                logger.debug(f"Loading precompiled YARA rules from {rule_path}")
                rules = yara.load(rule_path)
            else:
                if os.path.isfile(rule_path):
                    logger.debug(f"Compiling single YARA rule file: {rule_path}")
                    rules = yara.compile(filepath=rule_path)
                elif os.path.isdir(rule_path):
                    logger.debug(f"Compiling YARA rules directory: {rule_path}")
                    filepaths = {}
                    
                    # Gather all .yar / .yara files
                    for root, _, files in os.walk(rule_path):
                        for f in files:
                            if f.endswith('.yar') or f.endswith('.yara'):
                                full_path = os.path.join(root, f)
                                # yara.compile requires dict of {namespace: filepath}
                                filepaths[full_path] = full_path
                                
                        if not recursive:
                            break  # Stop after top-level directory if recursive is False
                            
                    if not filepaths:
                        logger.warning(f"No .yar or .yara files found in {rule_path}")
                        return
                        
                    rules = yara.compile(filepaths=filepaths)
        except yara.SyntaxError as e:
            logger.error(f"YARA Syntax Error in rules: {e}")
            return
        except Exception as e:
            logger.exception(f"Failed to load/compile YARA rules: {e}")
            return

        # SCAN THE FILE
        matches = []
        try:
            logger.debug(f"Executing YARA engine (Timeout: {timeout_limit}s, Fast: {fast_match})")
            matches = rules.match(str(target_file.path), timeout=timeout_limit, fast=fast_match)
        except yara.TimeoutError:
            logger.error(f"YARA scan timed out after {timeout_limit} seconds. Rules might be poorly optimized.")
        except Exception as e:
            logger.exception(f"YARA matching engine crashed: {e}")
            return

        # PARSE RESULTS
        summary_matches = []
        raw_matches = []

        for match in matches:
            # 1. Check against the ignored_tags filter
            if any(tag in ignored_tags for tag in match.tags):
                continue
            
            rule_name = match.rule
            tags = match.tags
            meta = match.meta
            
            # 2. Extract matched strings with Two-Stage Decoding
            # YARA strings format: (offset, string_identifier, string_data)
            parsed_strings = []
            for string_match in match.strings:
                # For modern YARA versions
                if hasattr(string_match, 'instances'):
                    str_id = string_match.identifier
                    for instance in string_match.instances:
                        offset = instance.offset
                        str_data = instance.matched_data
                        
                        try:
                            clean_data = str_data.decode('utf-8', errors='strict')
                            match_type = "text"
                        except UnicodeDecodeError:
                            clean_data = str_data.hex()
                            match_type = "hex"

                        parsed_strings.append({
                            "offset": hex(offset),
                            "identifier": str_id,
                            "type": match_type,
                            "data": clean_data
                        })

                # For old versions
                else:
                    offset, str_id, str_data = string_match
                    try:
                        clean_data = str_data.decode('utf-8',errors='strict')
                        match_type = "text"
                    except UnicodeDecodeError:
                        clean_data = str_data.hex()
                        match_type = "hex"
                
                    parsed_strings.append({
                        "offset": hex(offset),
                        "identifier": str_id,
                        "type": match_type,
                        "data": clean_data
                    })
            
            # 3. Append to Raw (goes to disk)
            raw_matches.append({
                "rule": rule_name,
                "tags": tags,
                "meta": meta,
                "strings": parsed_strings
            })

            # 4. Append to Summary
            summary_matches.append({
                "rule": rule_name,
                "description": meta.get("description", "No description provided."),
                "author": meta.get("author", "Unknown"),
                "tags": tags
            })

        # SAVE TO UNIFIED PACKAGE
        if not summary_matches:
            logger.info("YARA scan completed. No non-filtered rules matched.")
            return

        # 1. Write the raw output to disk in the plugin's dedicated folder
        plugin_dir = self.get_plugin_dir(run_dir)
        raw_output_path = os.path.join(plugin_dir, "yara_raw_output.json")
        
        try:
            with open(raw_output_path, "w", encoding="utf-8") as f:
                json.dump({"yara_matches": raw_matches}, f, indent=4)
        except Exception as e:
            logger.error(f"Failed to write YARA raw output to disk: {e}")

        # 2. Add the summary to the TargetFile
        target_file.add_result(
            self.plugin_id, 
            summary_data={
                "matched_rules": summary_matches,
                "raw_output_path": os.path.relpath(raw_output_path, start=run_dir)
            }
        )
        logger.info(f"YARA scan complete. {len(summary_matches)} rules matched.")