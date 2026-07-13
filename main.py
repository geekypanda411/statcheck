import argparse
import os
import sys
from src.core.orchestrator import Orchestrator
import logging
import subprocess
import json

def setup_logging(is_debug: bool, log_file: str):
    log_level = logging.DEBUG if is_debug else logging.INFO
    handlers = []
    if log_file:
        handlers.append(logging.FileHandler(log_file))
    else:
        handlers.append(logging.StreamHandler(sys.stdout))
    logging.basicConfig(level=log_level, format="%(asctime)s | %(name)-20s | %(levelname)-8s | %(message)s", handlers=handlers)

def auto_detect_format(file_path: str) -> str:
    logger = logging.getLogger(__name__)
    try:
        logger.debug("Running diec for file format detection")
        result = subprocess.run(["diec","-ji",file_path],capture_output=True, text=True)
        if not result.stdout.strip():
            logger.warning("DiEC returned empty result, could not identify format")
            return "Unknown"
        
        diec_info_data = json.loads(result.stdout)
        logger.debug(f"DiEC Info Data:\n {diec_info_data}")
        file_type = diec_info_data["data"]["Info"]["File type"] or ""
        file_type = file_type.lower()
        logger.debug(f"Identified file format: {file_type}")

        if "pe" in file_type:
            return "pe"
        elif "elf" in file_type:
            return "elf"
        elif "macho" in file_type:
            return "macho"
        else:
            logger.warning(f"Identified file format {file_type} is not supported as of now.")
            return "unknown"
    except Exception as e:
        logger.warning(f"Auto-detect failed: {e}")
        return "unknown"

def main():
    parser = argparse.ArgumentParser(description="statchec - Static File Metadata Analyzer")
    parser.add_argument("file", help="Path to the file to analyze")
    parser.add_argument("--format", 
                        required=True, 
                        choices=['auto','pe', 'elf', 'macho'], 
                        help="Target file format, or 'auto' to detect automatically")
    
    # Allow users to specify multiple report formats (e.g., --report json pdf)
    parser.add_argument("--report", nargs='+', default=['json'], help="Report format(s) to generate (e.g., json, pdf, html)")
    parser.add_argument("--debug", action="store_true", help="Enable verbose debug logging")
    parser.add_argument("--log-file", type=str, help="Save logs to a specific file instead of printing to screen")
    args = parser.parse_args()

    setup_logging(args.debug, args.log_file)
    logger = logging.getLogger(__name__)
    logger.info(f"Analyzing file: {args.file} with format: {args.format}")

    if not os.path.isfile(args.file):
        logger.error(f"File not found: {args.file}")
        sys.exit(1)

    if args.format == 'auto':
        logger.info(f"Initiating format auto detection for file: {args.file}")
        final_format = auto_detect_format(args.file)

        if final_format == "unknown":
            logger.warning("Could Not identify file format, only cross-format analyzers will be used.")
        else:
            logger.info(f"Auto detected format {final_format} for file {args.file}")
    else:
        final_format = args.format
        logger.info(f"Manually Selected format: {final_format} for file {args.file}")
    
    # Setup Orchestrator
    app = Orchestrator(args.file, final_format)

    # Load Analyzers
    logger.debug("Loading analyzers...")
    app.load_analyzers("./src/analyzers")
    if not app.analyzers:
        logger.error(f"No analyzers found for format: {args.format}")
        sys.exit(1)

    # Load only the reporters requested by the user
    logger.debug(f"Loading reporters for formats: {args.report}")
    app.load_reporters("./src/reporters", desired_reporter=args.report)
    
    # Ensure reports directory exists, then execute
    os.makedirs("./reports", exist_ok=True)
    logger.info("Starting analysis and report generation...")
    app.execute("./reports")
    logger.info("Analysis and report generation completed successfully.")

if __name__ == "__main__":
    main()