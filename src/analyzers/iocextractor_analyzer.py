import logging
import re
import time
from collections import defaultdict
from pathlib import Path

import requests

from src.analyzers.base_analyzer import BaseAnalyzer
from src.core.cache import cache_dir, read_json, write_json
from src.core.paths import resolve_path

logger = logging.getLogger(__name__)

class IOCExtractorAnalyzer(BaseAnalyzer):
    name = "IOC Extractor"
    supported_formats = ['all']
    plugin_id = "iocextractor"
    
    # Wait for the string generators to finish!
    # (If QS isn't installed/enabled, the Orchestrator safely prunes it and runs this anyway)
    depends = {"all": [], "any": ["floss","quantumstrand"]}

    def _tld_file_path(self, plugin_config) -> Path:
        """Resolve the TLD list location.

        A configured relative path is anchored to the project root (never the
        caller's CWD); with no configuration the cache directory is used.
        """
        configured = plugin_config.get("tld_file")
        if configured:
            return resolve_path(configured)
        return cache_dir() / "tlds.txt"

    def _update_tld_list(self, plugin_config):
        #IANA TLD list updater.
        # IMPORTANT: this never writes to tools_config.json. Update metadata
        # lives in the cache dir; legacy keys in the config are read once as
        # a freshness hint only.
        tld_file = self._tld_file_path(plugin_config)
        freq_days = plugin_config.get("tldupdatefreqdays", 7)

        meta_path = cache_dir() / "tlds.meta.json"
        meta = read_json(meta_path) or {}
        last_update = meta.get("tldupdatedon", plugin_config.get("tldupdatedon", 0))
        local_version = meta.get("tld_version", plugin_config.get("tld_version", 0))
        
        current_time = int(time.time())
        file_exists = tld_file.exists()
        
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
                            with open(tld_file, "w", encoding="utf-8") as f:
                                f.write("\n".join(tlds))
                            
                            write_json(meta_path, {
                                "tld_file": str(tld_file),
                                "tldupdatedon": current_time,
                                "tld_version": max(iana_version, local_version),
                            })
                            local_version = max(iana_version, local_version)
                                
            except Exception as e:
                logger.warning(f"Failed to fetch TLD updates: {e}")

        if tld_file.exists():
            with open(tld_file, encoding="utf-8") as f:
                return [line.strip() for line in f if line.strip()]
        return ["com", "net", "org", "io", "xyz"] # Fallback

    def analyze(self, target_file, tool_path, plugin_config, run_dir):
        logger.debug("Starting Central IOC Extraction...")
        
        # QS tags to skip
        ignore_tags = set(plugin_config.get("ignore_tags", ["#winapi", "#code", "#code-junk", "#reloc"]))

        # HARVEST & MERGE PUBLISHED STRINGS
        # defaultdict(set) automatically creates a new set if the string hasn't been seen before
        master_tags_dict = defaultdict(set)

        # Loop through all complete results to find published inputs
        internal_context = target_file.results.get("internal_context", {})
        for _source_plugin_id, data in internal_context.items():
            inputs = data.get("ioc_extractor_input", [])
            for item in inputs:
                s_val = item.get("string")
                if s_val:
                    # .update() merges tags from FLOSS ([]) and QS (["#code"]) flawlessly
                    master_tags_dict[s_val].update(item.get("tags", []))

        master_string_pool = []
        for s_val, merged_tags in master_tags_dict.items():
            if not any(tag in ignore_tags for tag in merged_tags):
                master_string_pool.append(s_val)

        if not master_string_pool:
            logger.info("No published strings found for extraction.")
            return

        # Enforce the max_strings limit (Phase 3.4): cap the input text fed
        # to the regex engine.
        max_strings = int(self.get_limit("max_strings"))
        if len(master_string_pool) > max_strings:
            logger.warning(
                f"iocextractor: capping input strings at max_strings "
                f"({len(master_string_pool)} -> {max_strings})."
            )
            master_string_pool = master_string_pool[:max_strings]

        logger.info(f"Strings passed to Regex: {len(master_string_pool)}")
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
        raw_urls = sorted(set(re.findall(url_regex, massive_text_block)))
        massive_text_block = re.sub(url_regex, " ", massive_text_block)

        # Registry Keys, gated to pe files only
        if target_file.format == 'pe':
            hive_prefixes = ("HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER|HKEY_CLASSES_ROOT|"
                             "HKEY_USERS|HKEY_CURRENT_CONFIG|HKLM|HKCU|HKCR|HKU|HKCC")
            registry_regex = rf'(?i)\b(?:{hive_prefixes})(?:\\[a-zA-Z0-9_\-\s]{{1,255}})+'
            raw_regpaths = sorted(set(re.findall(registry_regex, massive_text_block)))
            massive_text_block = re.sub(registry_regex, " ", massive_text_block)

        # IPs (Safe now that URLs are removed)
        ipv4_regex = r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
        ipv6_regex = r'\b(?:[a-fA-F0-9]{1,4}:){2,7}[a-fA-F0-9]{1,4}\b'
        raw_ips = sorted(set(re.findall(ipv4_regex, massive_text_block)
                             + re.findall(ipv6_regex, massive_text_block)))
        massive_text_block = re.sub(ipv4_regex, " ", massive_text_block)
        massive_text_block = re.sub(ipv6_regex, " ", massive_text_block)

        # Domains (Positive lookahead ensures it ends at string boundary, slash, or colon)
        # - Negative lookbehind (?<![/\\]) ensures we don't accidentally rip "file.zip" out of a filepath
        # - Positive lookahead (?=\n|:|$) ensures it ends cleanly
        tld_pattern = "|".join(tld_list)
        domain_regex = (rf'(?i)(?<![/\\])\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{{0,61}}[a-zA-Z0-9])?\.)+'
                        rf'(?:{tld_pattern})(?=\n|:|$)')
        raw_domains = sorted(set(d.lower() for d in re.findall(domain_regex, massive_text_block)))
        raw_domains = [d for d in raw_domains if len(d) <= 255] # Total DNS limit
        massive_text_block = re.sub(domain_regex, " ", massive_text_block)

        # File Paths (OS Constrained, End of Line Anchored)
        # Windows: Drive letter, forbidden chars < > : " / \ | ? *, segment len 1-255
        win_filepath_regex = (r'(?i)\b[A-Z]:(?:\\|\\\\)[^<>:"/\\|?*\n]{1,255}'
                              r'(?:(?:\\|\\\\)[^<>:"/\\|?*\n]{1,255})*(?<![ \.])(?=\n|$)')
        raw_win_paths = sorted(set(re.findall(win_filepath_regex, massive_text_block)))
        raw_win_paths = [p for p in raw_win_paths if len(p) <= 32760]

        # Unix: Allows spaces anywhere (unix permits this behavior, adds FPs); max 4096 length
        unix_filepath_regex = r'(?i)(?:[a-zA-Z0-9_\-\.\ ]{1,255})?(?:/[a-zA-Z0-9_\-\.\ ]{1,255})+(?=\n|$)'
        raw_nix_paths = sorted(set(re.findall(unix_filepath_regex, massive_text_block)))
        raw_nix_paths = [p for p in raw_nix_paths if len(p) <= 4096]

        # SAVE RESULTS
        # Enforce the max_summary_items limit per category (Phase 3.4).
        max_items = int(self.get_limit("max_summary_items"))
        summary = {
            "regex_urls": raw_urls,
            "regex_regpath": raw_regpaths,
            "regex_ip": raw_ips,
            "regex_domains": raw_domains,
            "regex_winfilepath": raw_win_paths,
            "regex_unixfilepath": raw_nix_paths
        }
        for key, items in summary.items():
            if len(items) > max_items:
                logger.warning(
                    f"iocextractor: capping '{key}' at max_summary_items ({len(items)} -> {max_items})."
                )
                summary[key] = items[:max_items]

        clean_summary = {k: v for k, v in summary.items() if v}
        
        if clean_summary:
            target_file.add_result(self.plugin_id, summary_data=clean_summary)
            logger.info("Successfully cascaded and extracted IOCs.")
        else:
            logger.info("No valid IOCs extracted.")