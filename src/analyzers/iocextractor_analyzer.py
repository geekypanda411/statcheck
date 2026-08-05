import logging
import re
import os
import time
import requests
import json
from src.analyzers.base_analyzer import BaseAnalyzer

logger = logging.getLogger(__name__)

class IOCExtractorAnalyzer(BaseAnalyzer):
    name = "IOC Extractor"
    supported_formats = ['all']
    plugin_id = "iocextractor"
    
    # Wait for the string generators to finish!
    # (If QS isn't installed/enabled, the Orchestrator safely prunes it and runs this anyway)
    depends = {"all": [], "any": ["floss","quantumstrand"]}

    def _update_tld_list(self, plugin_config):
        #IANA TLD list updater
        tld_file = plugin_config.get("tld_file", "./bin/tlds.txt")
        freq_days = plugin_config.get("tldupdatefreqdays", 7)
        last_update = plugin_config.get("tldupdatedon", 0)
        local_version = plugin_config.get("tld_version", 0)
        
        current_time = int(time.time())
        file_exists = os.path.exists(tld_file)
        
        if not file_exists or (current_time - last_update) > (freq_days * 86400):
            logger.info("Checking IANA for TLD updates...")
            try:
                resp = requests.get("https://data.iana.org/TLD/tlds-alpha-by-domain.txt", timeout=10)
                if resp.status_code == 200:
                    lines = resp.text.splitlines()
                    version_match = re.search(r'Version (\d+)', lines[0])
                    
                    if version_match:
                        iana_version = int(version_match.group(1))
                        if iana_version > local_version or not file_exists:
                            tlds = [line.lower() for line in lines[1:] if line.strip() and not line.startswith("#")]
                            with open(tld_file, "w") as f:
                                f.write("\n".join(tlds))
                            
                            # Write updates back to tools_config.json
                            with open("tools_config.json", "r") as f:
                                master_config = json.load(f)
                            
                            master_config["plugins"][self.plugin_id]["tldupdatedon"] = current_time
                            master_config["plugins"][self.plugin_id]["tld_version"] = max(iana_version, local_version)
                            
                            with open("tools_config.json", "w") as f:
                                json.dump(master_config, f, indent=4)
                                
            except Exception as e:
                logger.warning(f"Failed to fetch TLD updates: {e}")

        if os.path.exists(tld_file):
            with open(tld_file, "r") as f:
                return [line.strip() for line in f if line.strip()]
        return ["com", "net", "org", "io", "xyz"] # Fallback

    def analyze(self, target_file, tool_path, plugin_config):
        logger.debug("Starting Central IOC Extraction...")
        
        # HARVEST PUBLISHED STRINGS
        master_string_pool = set()
        # QS tags to skip
        ignore_tags = {"#winapi", "#common", "#code", "#reloc"}

        # Loop through all complete results to find published inputs
        complete_results = target_file.results.get("result_complete", {})
        for source_plugin_id, data in complete_results.items():
            inputs = data.get("ioc_extractor_input", [])
            for item in inputs:
                # Discard strings that have junk/benign tags
                if not any(tag in ignore_tags for tag in item.get("tags", [])):
                    master_string_pool.add(item["string"])

        if not master_string_pool:
            logger.info("No published strings found for extraction.")
            return

        massive_text_block = "\n".join(master_string_pool)
        tld_list = self._update_tld_list(plugin_config)

        # Initialize holding lists
        raw_urls = []
        raw_regpaths = []
        raw_ips = []
        raw_domains = []
        raw_win_paths = []
        raw_nix_paths = []

        # CASCADING REGEX ENGINE
        
        # URLs (Run First)
        url_regex = r'(?i)\b(?:http|https|ftp|tcp|udp)://[-a-zA-Z0-9+&@#/%?=~_|!:,.;]*[-a-zA-Z0-9+&@#/%=~_|]'
        raw_urls = list(set(re.findall(url_regex, massive_text_block)))
        massive_text_block = re.sub(url_regex, " ", massive_text_block)

        # Registry Keys, gated to pe files only
        if target_file.format == 'pe':
            registry_regex = r'(?i)\b(?:HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER|HKEY_CLASSES_ROOT|HKEY_USERS|HKEY_CURRENT_CONFIG|HKLM|HKCU|HKCR|HKU|HKCC)(?:\\[a-zA-Z0-9_\-\s]{1,255})+'
            raw_regpaths = list(set(re.findall(registry_regex, massive_text_block)))
            massive_text_block = re.sub(registry_regex, " ", massive_text_block)

        # IPs (Safe now that URLs are removed)
        ipv4_regex = r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
        ipv6_regex = r'\b(?:[a-fA-F0-9]{1,4}:){2,7}[a-fA-F0-9]{1,4}\b'
        raw_ips = list(set(re.findall(ipv4_regex, massive_text_block) + re.findall(ipv6_regex, massive_text_block)))
        massive_text_block = re.sub(ipv4_regex, " ", massive_text_block)
        massive_text_block = re.sub(ipv6_regex, " ", massive_text_block)

        # Domains (Positive lookahead ensures it ends at string boundary, slash, or colon)
        # - Negative lookbehind (?<![/\\]) ensures we don't accidentally rip "file.zip" out of a filepath
        # - Positive lookahead (?=\n|:|$) ensures it ends cleanly
        tld_pattern = "|".join(tld_list)
        domain_regex = rf'(?i)(?<![/\\])\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{{0,61}}[a-zA-Z0-9])?\.)+(?:{tld_pattern})(?=\n|:|$)'
        raw_domains = list(set(d.lower() for d in re.findall(domain_regex, massive_text_block)))
        raw_domains = [d for d in raw_domains if len(d) <= 255] # Total DNS limit
        massive_text_block = re.sub(domain_regex, " ", massive_text_block)

        # File Paths (OS Constrained, End of Line Anchored)
        # Windows: Drive letter, forbidden chars < > : " / \ | ? *, segment len 1-255
        win_filepath_regex = r'(?i)\b[A-Z]:(?:\\|\\\\)[^<>:"/\\|?*\n]{1,255}(?:(?:\\|\\\\)[^<>:"/\\|?*\n]{1,255})*(?<![ \.])(?=\n|$)'
        raw_win_paths = list(set(re.findall(win_filepath_regex, massive_text_block)))
        raw_win_paths = [p for p in raw_win_paths if len(p) <= 32760]

        # Unix: Allows spaces anywhere (Adds false positives but unix allows the behavious and a ta may use this), max 4096 length
        unix_filepath_regex = r'(?i)(?:[a-zA-Z0-9_\-\.\ ]{1,255})?(?:/[a-zA-Z0-9_\-\.\ ]{1,255})+(?=\n|$)'
        raw_nix_paths = list(set(re.findall(unix_filepath_regex, massive_text_block)))
        raw_nix_paths = [p for p in raw_nix_paths if len(p) <= 4096]

        # SAVE RESULTS
        summary = {
            "regex_urls": raw_urls,
            "regex_regpath": raw_regpaths,
            "regex_ip": raw_ips,
            "regex_domains": raw_domains,
            "regex_winfilepath": raw_win_paths,
            "regex_unixfilepath": raw_nix_paths
        }

        clean_summary = {k: v for k, v in summary.items() if v}
        
        if clean_summary:
            target_file.add_result(self.plugin_id, summary_data=clean_summary)
            logger.info("Successfully cascaded and extracted IOCs.")
        else:
            logger.info("No valid IOCs extracted.")