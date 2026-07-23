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

    def generate(self, target_file, output_dir):
        logger.debug(f"Starting JSON report generation for {target_file.filename}")

        sanitized_name = re.sub(r'[^a-zA-Z0-9.-]+', '_', target_file.filename)
        timestamp_unix = int(time.time())
        # TODO::Append execution timestamp to output report, so it does not keep on rewriting the old one
        output_filename = f"{sanitized_name}_statcheck_results_{timestamp_unix}.json"
        output_path = os.path.join(output_dir, output_filename)
        
        try:
            with open(output_path, "w", encoding="utf-8") as f:
                json.dump(target_file.results, f, indent=4, default=str)
                
            logger.info(f"Successfully generated JSON report at: {output_path}")
            
        except PermissionError:
            logger.error(f"Permission denied: Could not write JSON report to {output_path}")
        except Exception as e:
            # for any unexpected file I/O or serialization errors
            logger.exception(f"An unexpected error occurred while generating JSON report for {target_file.filename}")