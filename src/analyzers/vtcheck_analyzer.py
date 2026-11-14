import logging
import os
import time

import vt

from src.analyzers.base_analyzer import BaseAnalyzer
from src.core.http import cached_response

logger = logging.getLogger(__name__)


class VirusTotalAnalyzer(BaseAnalyzer):
    name = "VirusTotal TI Lookup"
    supported_formats = ["all"]
    plugin_id = "vtlookup"
    depends = {"all": ["fileinfo"], "any": []}

    def analyze(self, target_file, tool_path, plugin_config, run_dir):
        env_var_name = plugin_config.get("api_key_env", "VT_API_KEY")
        api_key = os.environ.get(env_var_name)

        if not api_key:
            logger.error(f"{self.name} is enabled, but '{env_var_name}' is missing!")
            return

        summary = target_file.results.get("result_summary", {})
        vt_summary = {}
        vt_complete = {}
        cache_ttl = int(plugin_config.get("cache_ttl_seconds", 24 * 3600))

        # Initialize the official VT client
        try:
            with vt.Client(api_key) as client:
                # --- 1. EXACT HASH LOOKUP (cached on disk to spare quota) ---
                if plugin_config.get("lookup_exact_hash", True):
                    sha256 = summary.get("fileinfo", {}).get("File_SHA256")
                    if sha256:
                        logger.info(f"Querying VT for exact hash: {sha256}")

                        def fetch_vt_exact():
                            try:
                                file_obj = client.get_object(f"/files/{sha256}")
                            except vt.error.APIError as e:
                                if e.code == "NotFoundError":
                                    return {"not_found": True}
                                logger.error(f"VT Exact Hash Error: {e}")
                                return None
                            except Exception as e:
                                logger.error(f"VT Exact Hash Error: {e}")
                                return None

                            raw_data = file_obj.to_dict()
                            stats = file_obj.last_analysis_stats
                            return {
                                "raw": raw_data,
                                "summary": {
                                    "malicious_votes": stats.get("malicious", 0),
                                    "meaningful_name": file_obj.get("meaningful_name", "Unknown"),
                                    "reputation": file_obj.get("reputation", 0),
                                    "authentihash": file_obj.get("authentihash"),
                                    "first_submission": str(file_obj.get("first_submission_date", "Unknown")),
                                    "signature_info": file_obj.get("signature_info"),
                                    "yara_results_vt": file_obj.get("crowdsourced_yara_results"),
                                },
                            }

                        cached, _from_cache = cached_response(
                            "vt", f"files:{sha256}", fetch_vt_exact, ttl_seconds=cache_ttl
                        )

                        if cached and cached.get("not_found"):
                            vt_summary["exact_match"] = "File not found on VirusTotal."
                        elif cached:
                            vt_complete["exact_hash_match_raw"] = cached["raw"]
                            vt_summary["exact_match"] = cached["summary"]
                        else:
                            logger.warning("VT exact hash lookup produced no result.")

                        # --- 1b. RELATIONS (always fetched live: paginated
                        # and premium-gated, not worth caching) ---
                        if (
                            cached
                            and not cached.get("not_found")
                            and plugin_config.get("fetch_relations_behaviour", False)
                        ):
                            logger.info("fetch_relations_behaviour is true; fetching relations.")
                            relations_api_endpoints = {
                                "contacted_ips": "Contacted IPs",
                                "contacted_domains": "Contacted Domains",
                                "dropped_files": "Dropped Files",
                                "bundled_files": "Bundled Files",
                                "execution_parents": "Execution Parents",
                                "itw_urls": "In-The-Wild URLs",
                            }

                            vt_summary["relations"] = {}
                            vt_complete["relations_raw"] = {}

                            for index, (endpoint, human_name) in enumerate(relations_api_endpoints.items()):
                                # Sleep only BETWEEN relation requests, never before
                                # the first one, so single-request runs aren't slowed down.
                                if index > 0:
                                    rate_limit_sleep = plugin_config.get("rate_limit_sleep", 20)
                                    logger.info(f"Sleeping {rate_limit_sleep}s between relation requests.")
                                    time.sleep(rate_limit_sleep)

                                logger.info(f"Fetching VT relations: {human_name}")
                                try:
                                    max_items = plugin_config.get("relations_result_limit", 40)
                                    logger.debug(f"Maximum {max_items} items for {human_name} (configurable).")
                                    response_it = client.iterator(
                                        f"/files/{sha256}/{endpoint}", limit=max_items, batch_size=max_items
                                    )

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
                                        vt_summary["relations"][endpoint] = sorted(
                                            str(x) for x in relations_summary_list
                                        )

                                except vt.error.APIError as e:
                                    if e.code == "ForbiddenError":
                                        logger.debug(f"Skipped {human_name}: premium API key required.")
                                        vt_summary["relations"][endpoint] = "Premium VT Key Required"
                                    logger.warning(f"Failed to fetch {human_name}: {e}")
                    else:
                        logger.warning("No SHA256 found to query VT.")

                # --- 2. FUZZY HASH LOOKUP (SSDeep) ---
                if plugin_config.get("lookup_fuzzy_hash", False):
                    logger.debug("Fuzzy hashing enabled: requires Premium API and may burn a lot of credits.")
                    ssdeep = summary.get("fileinfo", {}).get("File_ssdeep")
                    if ssdeep:
                        logger.info("Querying VT for SSDeep similarity...")
                        fuzzy_matches = []

                        try:
                            # client.iterator handles API pagination!
                            # limit to 5 so we don't accidentally burn API quota on a massive search
                            max_fuzzy_lookups = plugin_config.get("fuzzy_lookup_limit", 5)
                            query = f'ssdeep:"{ssdeep}"'
                            # Pass the query as a request parameter so it is properly
                            # encoded; embedding it raw in the URL breaks on quotes/spaces.
                            fuzzylookup_it = client.iterator(
                                "/search",
                                params={"query": query},
                                limit=max_fuzzy_lookups,
                            )

                            for related_file in fuzzylookup_it:
                                fuzzy_matches.append(
                                    {
                                        "sha256": related_file.id,
                                        "malicious_votes": related_file.last_analysis_stats.get("malicious", 0),
                                    }
                                )

                            vt_summary["fuzzy_matches"] = fuzzy_matches if fuzzy_matches else "No similar files found."
                        except vt.error.APIError as e:
                            logger.error(f"VT Fuzzy Hash Error: {e}")
                    else:
                        logger.warning("No SSDeep hash found to query VT.")

        except Exception:
            logger.exception("A critical error occurred while connecting to VirusTotal.")

        # Save to the TargetFile's Summary component!
        if vt_complete:
            vt_summary["raw_output_path"] = self.save_raw(run_dir, "virustotal_raw_output.json", vt_complete)
            logger.info("Successfully added VirusTotal intelligence to the raw output file.")
        else:
            logger.warning("Complete raw result for VirusTotal analyzer not available.")

        if vt_summary:
            target_file.add_result(self.plugin_id, summary_data=vt_summary)
            logger.info("Successfully added VirusTotal intelligence to report.")
        else:
            logger.warning("Summary result for VirusTotal analyzer not available.")
