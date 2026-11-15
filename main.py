import argparse
import logging
import math
import sys
from pathlib import Path

from dotenv import load_dotenv

from src.core.config import ConfigError
from src.core.format_detect import detect_format
from src.core.orchestrator import Orchestrator
from src.core.paths import PROJECT_ROOT

# Anchors all default paths to the project layout instead of the caller's CWD.
SCRIPT_DIR = Path(__file__).resolve().parent

load_dotenv()


def _get_version() -> str:
    try:
        from importlib.metadata import PackageNotFoundError, version

        return version("statcheck")
    except PackageNotFoundError:
        return "0.2.0"


def setup_logging(is_debug: bool, log_file: str):
    log_level = logging.DEBUG if is_debug else logging.INFO
    handlers: list = []
    if log_file:
        handlers.append(logging.FileHandler(log_file))
    else:
        handlers.append(logging.StreamHandler(sys.stdout))
    fmt = "%(asctime)s | %(threadName)-15s | %(name)-20s | %(levelname)-8s | %(message)s"
    logging.basicConfig(level=log_level, format=fmt, handlers=handlers)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="statcheck - Static File Metadata Analyzer")
    parser.add_argument("file", nargs="?", default=None, help="Path to the file to analyze (omit with --list-plugins)")
    parser.add_argument(
        "--format",
        default="auto",
        choices=["auto", "pe", "elf", "macho"],
        help="Target file format, or 'auto' to detect automatically (default: auto)",
    )

    # Allow users to specify multiple report formats (e.g., --report json pdf),
    # or 'all' to generate every enabled report format.
    parser.add_argument(
        "--report", nargs="+", default=["json"], help="Report format(s) to generate (e.g., json, markdown, or 'all')"
    )
    parser.add_argument(
        "--config", default=str(PROJECT_ROOT / "tools_config.json"), help="Path to the tools config JSON"
    )
    parser.add_argument(
        "--reporter-config", default=str(PROJECT_ROOT / "reporter_config.json"), help="Path to the reporter config JSON"
    )
    parser.add_argument(
        "--output-dir", default=str(PROJECT_ROOT / "reports"), help="Directory where run outputs are written"
    )
    parser.add_argument("--workers", type=int, default=10, help="Number of analyzers to run in parallel (default: 10)")
    parser.add_argument(
        "--timeout", type=float, default=300.0, help="Default per-tool subprocess timeout in seconds (default: 300)"
    )
    parser.add_argument("--debug", action="store_true", help="Enable verbose debug logging")
    parser.add_argument("--log-file", type=str, help="Save logs to a specific file instead of printing to screen")
    parser.add_argument("--version", action="version", version=f"statcheck {_get_version()}")
    parser.add_argument("--list-plugins", action="store_true", help="List all discovered analyzers/reporters and exit")
    return parser


def _run(args, logger) -> int:
    # --- Plugin listing works without a target file ---
    if args.list_plugins:
        app = Orchestrator("", "pe", config_path=args.config, reporter_config_path=args.reporter_config)
        plugins = app.list_plugins()
        print("Discovered analyzers:")
        for a in plugins["analyzers"]:
            print(f"  {a['plugin_id']:<20} {', '.join(a['supported_formats']):<10} {a['name']}")
        print("Discovered reporters:")
        for r in plugins["reporters"]:
            print(f"  {r['reporter_id']:<20} {r['format_id']:<10} {r['name']}")
        # Tool availability: warn early when configured external tools are missing.
        configured = app.config.get("plugins", {})
        if configured:
            from src.analyzers.base_analyzer import resolve_tool_path

            print("External tool availability:")
            for plugin_id, plugin_config in sorted(configured.items()):
                tool = plugin_config.get("tool")
                if tool is None or not isinstance(tool, str):
                    continue
                resolved = resolve_tool_path(str(app.bin_dir / tool))
                status = "OK" if resolved else "MISSING"
                print(f"  {plugin_id:<20} {status:<8} tool: {tool}")
        return 0

    if args.workers < 1:
        logger.error("--workers must be at least 1")
        return 2
    if not math.isfinite(args.timeout) or args.timeout <= 0:
        logger.error("--timeout must be a finite number greater than 0")
        return 2

    if not args.file:
        print("error: the 'file' argument is required unless --list-plugins is used", file=sys.stderr)
        return 2

    if not Path(args.file).is_file():
        logger.error(f"File not found: {args.file}")
        return 1

    # Load configuration and enforce the input guard before auto-detection can
    # pass ambiguous inputs to a complex parser such as LIEF.
    app = Orchestrator(
        args.file,
        "unknown" if args.format == "auto" else args.format,
        config_path=args.config,
        reporter_config_path=args.reporter_config,
        workers=args.workers,
        timeout=args.timeout,
    )
    try:
        app.enforce_input_limit()
    except ValueError as e:
        logger.error(str(e))
        return 1

    if args.format == "auto":
        logger.info(f"Initiating format auto detection for file: {args.file}")
        final_format = detect_format(args.file)

        if final_format == "unknown":
            logger.warning("Could not identify file format, only cross-format analyzers will be used.")
        else:
            logger.info(f"Auto detected format {final_format} for file {args.file}")
    else:
        final_format = args.format
        logger.info(f"Manually selected format: {final_format} for file {args.file}")

    app.file_format = final_format
    app.target_file.format = final_format

    # Load Analyzers
    logger.debug("Loading analyzers...")
    app.load_analyzers()
    if not app.analyzers:
        logger.error(f"No analyzers found for format: {final_format}")
        return 1

    # Load only the reporters requested by the user
    logger.debug(f"Loading reporters for formats: {args.report}")
    app.load_reporters(desired_reporter=args.report)

    # Fail loudly when a requested report format does not exist, instead of
    # silently producing no output.
    if "all" not in args.report:
        loaded_formats = {reporter.format_id for reporter in app.reporters}
        missing = [fmt for fmt in args.report if fmt not in loaded_formats]
        if missing:
            valid = ", ".join(sorted(loaded_formats)) if loaded_formats else "none"
            logger.error(f"Unknown report format(s): {', '.join(missing)}. Available formats: {valid}")
            return 2

    # Ensure the reports directory exists, then execute
    reports_dir = Path(args.output_dir)
    reports_dir.mkdir(parents=True, exist_ok=True)
    logger.info("Starting analysis and report generation...")
    succeeded = app.execute(str(reports_dir))
    if not succeeded:
        logger.error("Analysis or report generation completed with failures.")
        return 1
    logger.info("Analysis and report generation completed successfully.")
    return 0


def main(argv=None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    setup_logging(args.debug, args.log_file)
    logger = logging.getLogger(__name__)

    try:
        return _run(args, logger)
    except ConfigError as e:
        logger.error(f"Configuration error: {e}")
        return 2
    except KeyboardInterrupt:
        logger.warning("Aborted by user (Ctrl-C).")
        return 130
    except Exception:
        logger.exception("An unexpected error occurred during the analysis run.")
        return 1


if __name__ == "__main__":
    sys.exit(main())
