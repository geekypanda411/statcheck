import logging
import os
import re

from src.reporters.base_reporter import BaseReporter

logger = logging.getLogger(__name__)


def _kv_table(data: dict, indent: str = "") -> list[str]:
    """Render a flat dict as a Markdown table (keys sorted for determinism)."""
    lines = [f"{indent}| Key | Value |", f"{indent}|---|---|"]
    for key in sorted(data, key=str):
        value = data[key]
        lines.append(f"{indent}| {key} | {value} |")
    return lines


def _render_value(value, indent: str = "") -> list[str]:
    """Best-effort Markdown rendering of an arbitrary summary value."""
    if isinstance(value, dict):
        if not value:
            return [f"{indent}*(empty)*"]
        return _kv_table(value, indent)
    if isinstance(value, list):
        if not value:
            return [f"{indent}*(empty)*"]
        if all(isinstance(i, dict) for i in value):
            lines = []
            for item in value:
                lines.append(f"{indent}- " + ", ".join(f"`{k}`: {v}" for k, v in sorted(item.items(), key=str)))
            return lines
        return [f"{indent}- {item}" for item in value]
    # Scalars / strings: one line, backticked for readability.
    return [f"{indent}`{value}`"]


def _linkify(path_value):
    """Turn raw_output_path values into relative Markdown links."""
    text = str(path_value)
    if text and not text.startswith("http"):
        return f"[{text}]({text})"
    return text


class MarkdownReporter(BaseReporter):
    name = "Markdown Report Generator"
    format_id = "markdown"
    reporter_id = "markdown_reporter"

    def generate(self, target_file, run_dir, reporter_config, timestamp):
        logger.debug(f"Starting Markdown report generation for {target_file.filename}")

        sanitized_name = re.sub(r"[^a-zA-Z0-9.-]+", "_", target_file.filename)
        output_filename = f"{sanitized_name}_statcheck_summary_{timestamp}.md"
        output_path = os.path.join(run_dir, output_filename)

        metadata = target_file.results.get("metadata", {})
        summary = target_file.results.get("result_summary", {})
        template_order = reporter_config.get("output_template", [])

        # Order sections by the template first, then sorted orphans.
        ordered_ids = [pid for pid in template_order if pid in summary]
        ordered_ids += sorted(pid for pid in summary if pid not in ordered_ids)

        lines = []
        lines.append(f"# statcheck report: `{target_file.filename}`")
        lines.append("")

        run_meta = metadata.get("run", {})
        if run_meta:
            lines.append("## Run")
            lines.append("")
            lines.extend(_kv_table(run_meta))
            lines.append("")

        plugin_statuses = metadata.get("plugins", {})
        if plugin_statuses:
            lines.append("## Plugin status")
            lines.append("")
            lines.append("| Plugin | Status | Duration (ms) |")
            lines.append("|---|---|---|")
            for plugin_id in sorted(plugin_statuses):
                entry = plugin_statuses[plugin_id]
                lines.append(f"| {plugin_id} | {entry.get('status', 'unknown')} | {entry.get('duration_ms', 'n/a')} |")
            lines.append("")

        analyzed_by = metadata.get("analyzed_by", [])
        if analyzed_by:
            lines.append(f"**Analyzed by:** {', '.join(analyzed_by)}")
            lines.append("")

        for plugin_id in ordered_ids:
            lines.append(f"## {plugin_id}")
            lines.append("")
            section = summary[plugin_id]
            if isinstance(section, dict):
                for key in sorted(section, key=str):
                    value = section[key]
                    rendered = [_linkify(value)] if key in ("raw_output_path", "extracted_to") else _render_value(value)
                    lines.append(f"### {key}")
                    lines.append("")
                    lines.extend(rendered)
                    lines.append("")
            else:
                lines.extend(_render_value(section))
                lines.append("")

        # Propagate failures so the orchestrator can return a failure status.
        with open(output_path, "w", encoding="utf-8") as f:
            f.write("\n".join(lines) + "\n")
        logger.info(f"Successfully generated Markdown report at: {output_path}")
