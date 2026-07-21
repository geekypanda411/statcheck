import subprocess
import logging
from src.analyzers.base_analyzer import BaseAnalyzer
import json
from functools import reduce

logger = logging.getLogger(__name__)

class DIEAnalyzer(BaseAnalyzer):
    name = "Detect It Easy Analyzer"
    supported_formats = ['all']
    plugin_id = "diec"
    priority = 5

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
                result = reduce(lambda d, key: d.get(key, {}) if isinstance(d, dict) else {}, relevant_key_dict[rkey], raw_results_dict)
                if result != {}:
                    output_dict[rkey] = result
                else:
                    continue
            except Exception:
                continue
        
        #Get Tool chain
        toolchain_list = ((raw_results_dict["diec-packer"]["detects"])[1])["values"]
        file_toolchain = {}
        key_base = "tc"
        key_counter = 1
        for tool in toolchain_list:
            full_key = key_base + str(key_counter)
            subkey_type = tool["type"]
            subkey_string = tool["string"]
            file_toolchain[full_key] = {"type":subkey_type,"string":subkey_string}
            key_counter = key_counter + 1

        output_dict["File_Toolchain"] = file_toolchain
        return output_dict

    def analyze(self, target_file, tool_path, plugin_config):
        logger.debug(f"Running diec on {target_file.filename}")
        logger.debug(f"Ignoring identified tool path: {tool_path} as this analyzer needs diec installed")
        diec_tasks = {"diec-info":"-ji","diec-entropy":"-je","diec-packer":"-ja", "diec-hash":"-jS"}

        raw_results = {}

        for task_name, flag in diec_tasks.items():
            logger.debug(f"Running diec with flag: {flag}")

            try:
                # -j tells diec to output in pure JSON
                if task_name == "diec-hash":
                    result = subprocess.run(["diec", flag,"Hash", str(target_file.path)], capture_output=True, text=True, check=True)
                else:
                    result = subprocess.run(["diec", flag, str(target_file.path)], capture_output=True, text=True, check=True)
                
                if not result.stdout.strip():
                    logger.debug(f"DiE flag {flag} returned empty output, SKipping.")
                else:
                    diec_data = json.loads(result.stdout)
                    raw_results[task_name] = diec_data
                    logger.debug(f"DiE analysis for flag {flag} complete.")
                
            except subprocess.CalledProcessError as e:
                # Use warning instead of error so that if one check fails the rest are still executed
                logger.warning(f"DiE ({flag}) failed to execute: {e.stderr.strip()}")
            except json.JSONDecodeError:
                logger.warning(f"DiE ({flag}) output could not be parsed as JSON.")
            except Exception as e:
                logger.exception(f"Unexpected error in DiE task '{task_name}'")
        
        logger.debug("Parsing diec output")
        parsed_results = self.parse_analyzer_output(raw_results)
        target_file.add_result(self.plugin_id,summary_data=parsed_results,complete_data=raw_results)