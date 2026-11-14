import json
import logging
from functools import reduce
from pathlib import Path

from src.analyzers.base_analyzer import BaseAnalyzer, resolve_tool_path
from src.core.process import ToolError, run_tool

logger = logging.getLogger(__name__)

class DIEAnalyzer(BaseAnalyzer):
    name = "Detect It Easy Analyzer"
    supported_formats = ['all']
    plugin_id = "diec"
    depends = {"all": [], "any": []}

    def parse_analyzer_output(self, raw_results_dict: dict):
        output_dict = {}

        relevant_key_dict = {"File_Type":["diec-info","data","Info","File type"],
                             "File_MIME_Type":["diec-info","data","Info","MIME"],
                             "File_Arch":["diec-info","data","Info","Architecture"],
                             "File_Mode":["diec-info","data","Info","Mode"],
                             "File_Size":["diec-info","data","Info","Size"],
                             "File_MD5":["diec-hash","data","Hash","MD5"],
                             "File_SHA256":["diec-hash","data","Hash","SHA256"],
                             "File_Entropy":["diec-entropy","total"],
                             "File_Packing_Status":["diec-entropy","status"]}

        for rkey in relevant_key_dict:
            try:
                # reduce guards non-dict nodes along the key path.
                result = reduce(lambda d, key: d.get(key, {}) if isinstance(d, dict) else {},
                                relevant_key_dict[rkey], raw_results_dict)
                if result != {}:
                    output_dict[rkey] = result
            except Exception:
                continue
        
        #Get Tool chain (guarded: diec may be missing or have failed entirely)
        file_toolchain = {}
        packer_block = raw_results_dict.get("diec-packer")
        detects = packer_block.get("detects", []) if isinstance(packer_block, dict) else []
        if not isinstance(detects, list):
            detects = []

        for detection in detects:
            if not isinstance(detection, dict):
                continue
            tc_filetype = detection.get("filetype")
            if tc_filetype is None:
                continue
            key_base = "toolchain" + "_" + str(tc_filetype)
            tool_list = detection.get("values", [])
            if not isinstance(tool_list, list):
                tool_list = []
            toolchain_temp_list = []
            for tool in tool_list:
                if not isinstance(tool, dict):
                    continue
                toolchain_temp_list.append({"type": tool.get("type"), "string": tool.get("string")})
            file_toolchain[key_base] = toolchain_temp_list

        if file_toolchain:
            output_dict["File_Toolchain"] = file_toolchain
        return output_dict

    def analyze(self, target_file, tool_path, plugin_config, run_dir):
        logger.debug(f"Running diec on {target_file.filename}")

        #Resolve the diec executable: configured path first, then PATH lookup.
        executable = resolve_tool_path(tool_path)
        if executable is None:
            reason = (f"diec binary not found (configured: '{tool_path}', "
                      f"also searched PATH for '{Path(tool_path).name if tool_path else 'diec'}').")
            logger.warning(reason)
            target_file.add_result(self.plugin_id, summary_data={
                "status": "unavailable",
                "reason": reason,
            })
            return
        logger.debug(f"Using diec executable at: {executable}")

        timeout = self.resolve_timeout(plugin_config)
        diec_tasks = {"diec-info":"-ji","diec-entropy":"-je","diec-packer":"-ja", "diec-hash":"-jS"}

        raw_results = {}

        for task_name, flag in diec_tasks.items():
            logger.debug(f"Running diec with flag: {flag}")

            try:
                # -j tells diec to output in pure JSON
                if task_name == "diec-hash":
                    result = run_tool([executable, flag, "Hash", str(target_file.path)], timeout=timeout)
                else:
                    result = run_tool([executable, flag, str(target_file.path)], timeout=timeout)
                
                if not result.stdout.strip():
                    logger.debug(f"DiE flag {flag} returned empty output, skipping.")
                else:
                    diec_data = json.loads(result.stdout)
                    raw_results[task_name] = diec_data
                    logger.debug(f"DiE analysis for flag {flag} complete.")
                
            except ToolError as e:
                # Use warning instead of error so that if one check fails the rest are still executed
                logger.warning(f"DiE ({flag}) failed to execute: {e}")
            except json.JSONDecodeError:
                logger.warning(f"DiE ({flag}) output could not be parsed as JSON.")
            except Exception:
                logger.exception(f"Unexpected error in DiE task '{task_name}'")

        # Always write the raw output, even when empty/failed.
        logger.debug("Parsing diec output")
        parsed_results = self.parse_analyzer_output(raw_results)
        parsed_results["raw_output_path"] = self.save_raw(run_dir, "diec_raw_output.json", raw_results)
        parsed_results["status"] = "ok" if raw_results else "no_output"
        if parsed_results["status"] != "ok":
            parsed_results["reason"] = "diec produced no parseable output for this sample."

        target_file.add_result(self.plugin_id,summary_data=parsed_results)
