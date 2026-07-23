import logging
import os
import vt
import time
from src.analyzers.base_analyzer import BaseAnalyzer

logger = logging.getLogger(__name__)

class VirusTotalAnalyzer(BaseAnalyzer):
    name = "VirusTotal TI Lookup"
    supported_formats = ['all']
    plugin_id = "vtlookup"
    priority = 70

    def analyze(self, target_file, tool_path, plugin_config):
        env_var_name = plugin_config.get("api_key_env", "VT_API_KEY")
        api_key = os.environ.get(env_var_name)

        if not api_key:
            logger.error(f"{self.name} is enabled, but '{env_var_name}' is missing!")
            return

        summary = target_file.results.get("result_summary", {})
        vt_summary = {}
        vt_complete = {}

        # Initialize the official VT client
        try:
            with vt.Client(api_key) as client:
                
                # --- 1. EXACT HASH LOOKUP ---
                if plugin_config.get("lookup_exact_hash", True):
                    sha256 = summary.get("diec", {}).get("File_SHA256")
                    if sha256:
                        logger.info(f"Querying VT for exact hash: {sha256}")
                        try:
                            file_obj = client.get_object(f"/files/{sha256}")

                            raw_data = file_obj.to_dict()
                            vt_complete["exact_hash_match_raw"] = raw_data
                            
                            stats = file_obj.last_analysis_stats
                            
                            vt_summary["exact_match"] = {
                                "malicious_votes": stats.get("malicious", 0),
                                "meaningful_name": file_obj.get("meaningful_name", "Unknown"),
                                "reputation": file_obj.get("reputation", 0),
                                "authentihash": file_obj.get("authentihash"),
                                "first_submission": str(file_obj.get("first_submission_date","Unknown")),
                                "signature_info": file_obj.get("signature_info"),
                                "yara_results_vt": file_obj.get("crowdsourced_yara_results")
                            }

                            if plugin_config.get("fetch_relations_behaviour", False):
                                logger.info(f"fetch_relations_behaviour set to true in config, API Calls will be made to fetch these.")
                                relations_api_endpoints = {
                                    "contacted_ips": "Contacted IPs",
                                    "contacted_domains": "Contacted Domains",
                                    "dropped_files": "Dropped Files",
                                    "bundled_files": "Bundled Files",
                                    "execution_parents": "Execution Parents",
                                    "itw_urls": "In-The-Wild URLs"
                                }

                                vt_summary["relations"] = {}
                                vt_complete["relations_raw"] = {}

                                for endpoint, human_name in relations_api_endpoints.items():
                                    vt_api_sleep_time = 20
                                    logger.info(f"Sleeping 20 Seconds to prevent violation of VT API Ratelimit")
                                    time.sleep(vt_api_sleep_time)

                                    logger.info(f"Fetching VT relations: {human_name}")
                                    try:
                                        max_items = plugin_config.get("relations_result_limit", 40)
                                        logger.debug(f"Maximum {max_items} will be fetched for {human_name} to change please edit tools_config.")
                                        response_it = client.iterator(f'/files/{sha256}/{endpoint}', limit=max_items, batch_size=max_items)

                                        relations_raw_list = []
                                        relations_summary_list = []

                                        for item in response_it:
                                            relations_raw_list.append(item.to_dict())

                                            if endpoint == "itw_urls":
                                                relations_summary_list.append(item.get("url"))
                                            else:
                                                relations_summary_list.append(item.id)

                                        if relations_raw_list:
                                            vt_complete["relations_raw"][endpoint] = relations_raw_list
                                            vt_summary["relations"][endpoint] = relations_summary_list

                                    except vt.error.APIError as e:
                                        if e.code == "ForbiddenError":
                                            logger.debug(f"Skipped {human_name}: Premium API key required.")
                                            vt_summary["relations"][endpoint] = "Premium VT Key Required"
                                        logger.warning(f"Failed to fetch {human_name}: {e}")

                        except vt.error.APIError as e:
                            if e.code == "NotFoundError":
                                vt_summary["exact_match"] = "File not found on VirusTotal."
                            else:
                                logger.error(f"VT Exact Hash Error: {e}")
                    else:
                        logger.warning("No SHA256 found to query VT.")

                # --- 2. FUZZY HASH LOOKUP (SSDeep) ---
                if plugin_config.get("lookup_fuzzy_hash", False):
                    logger.debug(f"Fuzzy Hashing is enabled in config. It requires Premium API and may burn a lot of credits.")
                    ssdeep = summary.get("fuzzyhasher", {}).get("ssdeep")
                    if ssdeep:
                        logger.info("Querying VT for SSDeep similarity...")
                        fuzzy_matches = []
                        
                        try:
                            # client.iterator handles API pagination!
                            # limit to 5 so we don't accidentally burn API quota on a massive search
                            max_fuzzy_lookups = plugin_config.get("fuzzy_lookup_limit", 5)
                            query = f"ssdeep:\"{ssdeep}\""
                            fuzzylookup_it = client.iterator(f'/search?query={query}', limit=max_fuzzy_lookups)
                            
                            for related_file in fuzzylookup_it:
                                fuzzy_matches.append({
                                    "sha256": related_file.id,
                                    "malicious_votes": related_file.last_analysis_stats.get("malicious", 0)
                                })
                            
                            vt_summary["fuzzy_matches"] = fuzzy_matches if fuzzy_matches else "No similar files found."
                        except vt.error.APIError as e:
                            logger.error(f"VT Fuzzy Hash Error: {e}")
                    else:
                        logger.warning("No SSDeep hash found to query VT.")

        except Exception as e:
            logger.exception("A critical error occurred while connecting to VirusTotal.")

        # Save to the TargetFile's Summary component!
        if vt_summary:
            target_file.add_result(self.plugin_id, summary_data=vt_summary, complete_data=vt_complete)
            logger.info("Successfully added VT intelligence to report.")