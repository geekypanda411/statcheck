import json
import os
import logging
import re
import time
from src.reporters.base_reporter import BaseReporter

logger = logging.getLogger(__name__)

class JsonReporter(BaseReporter):
    name = "JSON Report Generator"
    format_id = "json"
    reporter_id = "json_reporter"

    def generate(self, target_file, output_dir, reporter_config):
        logger.debug(f"Starting JSON report generation for {target_file.filename}")

        sanitized_name = re.sub(r'[^a-zA-Z0-9.-]+', '_', target_file.filename)
        timestamp_unix = int(time.time())
        output_filename = f"{sanitized_name}_statcheck_results_{timestamp_unix}.json"
        output_path = os.path.join(output_dir, output_filename)

        #Template based report section sorting
        template_order = reporter_config.get("output_template", [])

        def order_results(raw_data):
            #Orders a dictionary based on the template, placing orphans at the end.
            ordered_data = {}
            
            # Phase 1: Explicitly template-ordered items
            for plugin_id in template_order:
                if plugin_id in raw_data:
                    ordered_data[plugin_id] = raw_data[plugin_id]
                    
            # Phase 2: Orphan catcher (plugins that ran but aren't in the template)
            for plugin_id, data in raw_data.items():
                if plugin_id not in ordered_data:
                    logger.info(f"Plugin with plugin_id: {plugin_id} not found in template, attaching the results at the end. Please revise the template")
                    ordered_data[plugin_id] = data
                    
            return ordered_data

        # Build the final dict, ensuring Metadata is firmly at the top!
        final_ordered_results = {
            "metadata": target_file.results.get("metadata", {}),
            "result_summary": order_results(target_file.results.get("result_summary", {})),
            "result_complete": order_results(target_file.results.get("result_complete", {}))
        }
        
        try:
            with open(output_path, "w", encoding="utf-8") as f:
                json.dump(final_ordered_results, f, indent=4, default=str)
                
            logger.info(f"Successfully generated JSON report at: {output_path}")
            
        except PermissionError:
            logger.error(f"Permission denied: Could not write JSON report to {output_path}")
        except Exception as e:
            # for any unexpected file I/O or serialization errors
            logger.exception(f"An unexpected error occurred while generating JSON report for {target_file.filename}")