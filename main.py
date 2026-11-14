import argparse
import sys
from pathlib import Path

import logging
from dotenv import load_dotenv

from src.core.format_detect import detect_format
from src.core.orchestrator import Orchestrator

# Anchors all default paths to the project layout instead of the caller's CWD.
SCRIPT_DIR = Path(__file__).resolve().parent

load_dotenv()

def setup_logging(is_debug: bool, log_file: str):
    log_level = logging.DEBUG if is_debug else logging.INFO
    handlers = []
    if log_file:
        handlers.append(logging.FileHandler(log_file))
    else:
        handlers.append(logging.StreamHandler(sys.stdout))
    logging.basicConfig(level=log_level, format="%(asctime)s | %(threadName)-15s | %(name)-20s | %(levelname)-8s | %(message)s", handlers=handlers)

def main():
    parser = argparse.ArgumentParser(description="statcheck - Static File Metadata Analyzer")
    parser.add_argument("file", help="Path to the file to analyze")
    parser.add_argument("--format", 
                        required=True, 
                        choices=['auto','pe', 'elf', 'macho'], 
                        help="Target file format, or 'auto' to detect automatically")
    
    # Allow users to specify multiple report formats (e.g., --report json pdf),
    # or 'all' to generate every enabled report format.
    parser.add_argument("--report", nargs='+', default=['json'],
                        help="Report format(s) to generate (e.g., json, pdf, html, or 'all')")
    parser.add_argument("--debug", action="store_true", help="Enable verbose debug logging")
    parser.add_argument("--log-file", type=str, help="Save logs to a specific file instead of printing to screen")
    args = parser.parse_args()

    setup_logging(args.debug, args.log_file)
    logger = logging.getLogger(__name__)
    logger.info(f"Analyzing file: {args.file} with format: {args.format}")

    if not Path(args.file).is_file():
        logger.error(f"File not found: {args.file}")
        sys.exit(1)

    if args.format == 'auto':
        logger.info(f"Initiating format auto detection for file: {args.file}")
        final_format = detect_format(args.file)

        if final_format == "unknown":
            logger.warning("Could not identify file format, only cross-format analyzers will be used.")
        else:
            logger.info(f"Auto detected format {final_format} for file {args.file}")
    else:
        final_format = args.format
        logger.info(f"Manually selected format: {final_format} for file {args.file}")
    
    # Setup Orchestrator (default configs anchored to the project root, not CWD)
    app = Orchestrator(
        args.file,
        final_format,
        config_path=str(SCRIPT_DIR / "tools_config.json"),
        reporter_config_path=str(SCRIPT_DIR / "reporter_config.json"),
    )

    # Load Analyzers
    logger.debug("Loading analyzers...")
    app.load_analyzers(str(SCRIPT_DIR / "src" / "analyzers"))
    if not app.analyzers:
        logger.error(f"No analyzers found for format: {final_format}")
        sys.exit(1)

    # Load only the reporters requested by the user
    logger.debug(f"Loading reporters for formats: {args.report}")
    app.load_reporters(str(SCRIPT_DIR / "src" / "reporters"), desired_reporter=args.report)

    # Fail loudly when a requested report format does not exist, instead of
    # silently producing no output.
    if "all" not in args.report:
        loaded_formats = {reporter.format_id for reporter in app.reporters}
        missing = [fmt for fmt in args.report if fmt not in loaded_formats]
        if missing:
            valid = ", ".join(sorted(loaded_formats)) if loaded_formats else "none"
            logger.error(f"Unknown report format(s): {', '.join(missing)}. Available formats: {valid}")
            sys.exit(2)

    # Ensure reports directory exists, then execute
    reports_dir = SCRIPT_DIR / "reports"
    reports_dir.mkdir(exist_ok=True)
    logger.info("Starting analysis and report generation...")
    app.execute(str(reports_dir))
    logger.info("Analysis and report generation completed successfully.")

if __name__ == "__main__":
    main()
