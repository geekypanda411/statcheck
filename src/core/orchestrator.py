import importlib.util
import logging
from pathlib import Path
from src.core.target_file import TargetFile
from src.analyzers.base_analyzer import BaseAnalyzer
from src.reporters.base_reporter import BaseReporter
import sys
import os
import json

logger = logging.getLogger(__name__)

class Orchestrator:
    def __init__(self, file_path: str, file_format: str, config_path: str = "tools_config.json"):
        self.target_file = TargetFile(file_path)
        self.file_format = file_format.lower()
        self.analyzers = []
        self.reporters = []
        logger.debug(f"Orchestrator initialized for file: {file_path} with format: {file_format}")
        self.config = self._load_config(config_path)
        self.bin_dir = os.path.abspath(self.config.get("bin_path", "./bin"))

    def _load_config(self, config_path: str) -> dict:
        if os.path.exists(config_path):
            with open(config_path, "r") as f:
                return json.load(f)
        else:
            logger.warning(f"Config file {config_path} not found. Using defaults.")
            return {"bin_path": "./bin", "tools": {}}

    def _import_plugin_files(self, file_paths: list):
        if not hasattr(self, '_loaded_modules'):
            self._loaded_modules = []
        
        for file_path in file_paths:
            if file_path.name in ["__init__.py", "base_analyzer.py", "base_reporter.py"]:
                continue
            logger.debug(f"Importing plugin: {file_path}")
            file_path = Path(file_path)
            try:
                module_name = ".".join(file_path.with_suffix("").parts)
                spec = importlib.util.spec_from_file_location(module_name, file_path)
                module = importlib.util.module_from_spec(spec)
                sys.modules[module_name] = module
                self._loaded_modules.append(module)
                
                spec.loader.exec_module(module)
            except Exception as e:
                logger.exception(f"Failed to load plugin file {file_path.name}: {e}")

    def load_analyzers(self, base_plugins_dir: str):
        file_ignore_list = ["__init__.py", "base_analyzer.py"]
        base_path = Path(base_plugins_dir)

        global_plugins = list(base_path.glob("*.py"))
        
        format_folder = base_path / self.file_format

        if format_folder.exists():
            format_plugins = list(format_folder.rglob("*.py"))
        else:
            logger.info(f"No analyzers found for file format {self.file_format}")
            format_plugins = []

        target_files = global_plugins + format_plugins
        
        upd_target_files = []
        for target_file in target_files:
            if target_file.name in file_ignore_list:
                continue
            else:
                upd_target_files.append(target_file)

        logger.debug(f"Targeting {len(upd_target_files)} analyzer files for {self.file_format}.")

        self._import_plugin_files(upd_target_files)

        for analyzer_class in BaseAnalyzer.__subclasses__():
            analyzer = analyzer_class()
            formats = analyzer.supported_formats
            if 'all' in formats or self.file_format in formats:
                self.analyzers.append(analyzer)
                logger.debug(f"Analyzer loaded: {analyzer.name} with Priority: {analyzer.priority}")
            else:
                logger.debug(f"Analyzer {analyzer.name} skipped (unsupported format: {self.file_format})")
        self.analyzers.sort(key=lambda x: x.priority)
        logger.info(f"Total analyzers loaded: {len(self.analyzers)}")
        execution_order = " -> ".join([f"{a.name} (Priority {a.priority})" for a in self.analyzers])
        logger.debug(f"Analyzer Execution Order: {execution_order}")

    def load_reporters(self, reporter_dir: str, desired_reporter: list):
        file_ignore_list = ["__init__.py", "base_reporter.py"]
        base_path = Path(reporter_dir)

        all_py_files = list(base_path.glob("*.py"))
        available_reporters = []
        
        for py_file in all_py_files:
            if py_file.name in file_ignore_list:
                continue
            else:
                available_reporters.append(py_file)
        logger.debug(f"Total reporters identified: {len(available_reporters)}")

        self._import_plugin_files(available_reporters)
        
        for reporter_class in BaseReporter.__subclasses__():
            reporter = reporter_class()
            if 'all' in desired_reporter or reporter.format_id in desired_reporter:
                self.reporters.append(reporter)
                logger.debug(f"Reporter loaded: {reporter.name} (format: {reporter.format_id})")
            else:
                logger.debug(f"Reporter {reporter.name} skipped (unsupported format: {reporter.format_id})")
        logger.info(f"Total reporters loaded: {len(self.reporters)}")

    def execute(self, report_dir: str):
        # 1. Run Analyzers
        logger.info("Starting analysis...")
        for analyzer in self.analyzers:
            plugin_config = self.config.get("plugins",{}).get(analyzer.plugin_id, {})

            if plugin_config.get("enabled", False) is False:
                logger.debug(f"Skipping analyzer: {analyzer.name} disabled in config or absent from config")
                continue

            logger.debug(f"Executing Analyzer: '{analyzer.name}'")
            try:
                configured_tool_name = plugin_config.get("tool", analyzer.plugin_id)
                tool_path = os.path.join(self.bin_dir, configured_tool_name)
                logger.debug(f"Identified tool path: '{tool_path}'")
                analyzer.analyze(self.target_file, tool_path, plugin_config)
            except Exception as e:
                logger.exception(f"Error occurred while analyzing with {analyzer.name}: {e}")
        logger.info("Analysis completed. Generating reports...")

        # 2. Generate Reports
        for reporter in self.reporters:
            logger.debug(f"Generating report using: {reporter.name}")
            try:
                reporter.generate(self.target_file, report_dir)
            except Exception as e:
                logger.exception(f"Error occurred while generating report with {reporter.name}: {e}")
        logger.info("Report generation completed.")