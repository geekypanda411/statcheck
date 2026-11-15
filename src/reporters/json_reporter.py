import datetime
import json
import logging
import os
import re
from pathlib import Path

from src.reporters.base_reporter import BaseReporter

logger = logging.getLogger(__name__)


def _strict_serialization() -> bool:
    """Fail on unknown objects in debug/CI instead of silently calling str()."""
    if os.environ.get("STATCHHECK_STRICT_JSON"):
        return True
    return logger.isEnabledFor(logging.DEBUG)


def _json_default(obj):
    """Explicit serializer for common non-JSON types.

    Unknown types raise in strict mode (debug/CI) and fall back to ``str``
    with a warning in production so a single weird object cannot kill a report.
    """
    if isinstance(obj, (datetime.datetime, datetime.date)):
        return obj.isoformat()
    if isinstance(obj, Path):
        return str(obj)
    if isinstance(obj, (set, frozenset)):
        return sorted(obj)
    if isinstance(obj, bytes):
        return obj.hex()
    if _strict_serialization():
        raise TypeError(f"Cannot serialize object of type {type(obj).__name__} in strict mode")
    logger.warning(f"JSON report: serializing unknown object of type {type(obj).__name__} via str() fallback.")
    return str(obj)


class JsonReporter(BaseReporter):
    name = "JSON Report Generator"
    format_id = "json"
    reporter_id = "json_reporter"

    def generate(self, target_file, run_dir, reporter_config, timestamp):
        logger.debug(f"Starting JSON report generation for {target_file.filename}")

        sanitized_name = re.sub(r"[^a-zA-Z0-9.-]+", "_", target_file.filename)
        timestamp_unix = timestamp
        output_filename = f"{sanitized_name}_statcheck_summary_{timestamp_unix}.json"
        output_path = os.path.join(run_dir, output_filename)

        # Template based report section sorting
        template_order = reporter_config.get("output_template", [])

        def order_results(raw_data):
            # Orders a dictionary based on the template, placing orphans at the end
            # in deterministic (sorted) order.
            ordered_data = {}

            # Phase 1: Explicitly template-ordered items
            for plugin_id in template_order:
                if plugin_id in raw_data:
                    ordered_data[plugin_id] = raw_data[plugin_id]

            # Phase 2: Orphan catcher (plugins that ran but aren't in the template),
            # sorted so identical runs produce byte-identical reports.
            for plugin_id in sorted(raw_data):
                if plugin_id not in ordered_data:
                    logger.info(
                        f"Plugin with plugin_id: {plugin_id} not found in template, "
                        f"attaching the results at the end. Please revise the template"
                    )
                    ordered_data[plugin_id] = raw_data[plugin_id]

            return ordered_data

        # Build the final dict, ensuring Metadata is firmly at the top!
        final_ordered_results = {
            "schema_version": "1.0",
            "metadata": target_file.results.get("metadata", {}),
            "result_summary": order_results(target_file.results.get("result_summary", {})),
        }

        # Let write/serialization failures propagate. The orchestrator must be
        # able to report an unsuccessful run instead of silently returning 0.
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(final_ordered_results, f, indent=4, default=_json_default)

        logger.info(f"Successfully generated JSON report at: {output_path}")
