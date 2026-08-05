import importlib.util
import logging
from pathlib import Path
from src.core.target_file import TargetFile
from src.analyzers.base_analyzer import BaseAnalyzer
from src.reporters.base_reporter import BaseReporter
import sys
import os
import json
import concurrent.futures

logger = logging.getLogger(__name__)

class Orchestrator:
    def __init__(self, file_path: str, file_format: str, config_path: str = "tools_config.json",reporter_config_path: str = "reporter_config.json"):
        self.target_file = TargetFile(file_path, file_format)
        self.file_format = file_format.lower()
        self.analyzers = []
        self.reporters = []
        logger.debug(f"Orchestrator initialized for file: {file_path} with format: {file_format}")
        self.config = self._load_config(config_path)
        self.reporter_config = self._load_config(reporter_config_path)
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
                logger.debug(f"Analyzer loaded: {analyzer.name}")
            else:
                logger.debug(f"Analyzer {analyzer.name} skipped (unsupported format: {self.file_format})")
        logger.info(f"Total analyzers loaded: {len(self.analyzers)}")

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
        logger.info("Pre-Processing analyzer dependencies..")

        #Identify plugins set as active in config
        active_plugin_ids = set()
        for analyzer in self.analyzers:
            plugin_config = self.config.get("plugins", {}).get(analyzer.plugin_id, {})
            if plugin_config.get("enabled", True):
                active_plugin_ids.add(analyzer.plugin_id)
            else:
                logger.info(f"Analyzer Disabled by Config: {analyzer.name}")

        #Handle cascading scenarios where plugin c depends on plugin b which depends on plugin a
        #And plugin a being disabled essentially should prevent execution of plugin b and by extension plugin c
        while True:
            removed_any = False
            for analyzer in self.analyzers:
                if analyzer.plugin_id in active_plugin_ids:
                    
                    deps = analyzer.depends
                    all_deps = deps.get("all", [])
                    any_deps = deps.get("any", [])
                    
                    # Check 'all' logic: strict dependencies
                    missing_all = [dep for dep in all_deps if dep not in active_plugin_ids]
                    
                    # B. Check 'any' logic: If 'any' is defined, at least one should be active
                    missing_any = False
                    if any_deps:
                        has_active_any = any(dep in active_plugin_ids for dep in any_deps)
                        if not has_active_any:
                            missing_any = True
                            
                    if missing_all or missing_any:
                        reason = f"Missing 'all' deps: {missing_all}." if missing_all else f"None of 'any' deps enabled: {any_deps}."
                        logger.warning(f"Cascading Skip: '{analyzer.name}' will not run. {reason}")
                        
                        active_plugin_ids.remove(analyzer.plugin_id)
                        removed_any = True
            
            # If we made it through the whole list without removing anything, the graph is stable!
            if not removed_any:
                break
        
        pending_analyzers = [a for a in self.analyzers if a.plugin_id in active_plugin_ids]

        if not pending_analyzers:
            logger.warning("No analyzers are enabled or have satisfied dependencies. Exiting analysis phase.")
            return

        logger.info(f"Starting parallel analysis phase with {len(pending_analyzers)} analyzers...")

        # Tracks {Future_Object: Analyzer_Object}
        running_futures = {}
        # Tracks plugin_ids that are done
        completed_plugins = set()

        # 10 plugins can run simultaneously
        with concurrent.futures.ThreadPoolExecutor(max_workers=10, thread_name_prefix="Worker") as executor:
            
            # Keep looping as long as there is work to do or threads currently running
            while pending_analyzers or running_futures:
                
                # 1. Find plugins that are ready to run
                ready_to_run = []
                for analyzer in pending_analyzers:
                    # Check if ALL dependencies are in the completed set
                    deps = analyzer.depends
                    all_deps = deps.get("all", [])
                    any_deps = deps.get("any", [])
                    
                    # Hard dependencies ('all') must have finished
                    all_deps_met = all(dep in completed_plugins for dep in all_deps)
                    
                    # Aggregate dependencies ('any')
                    # dynamically filter the list to ONLY look at the ones that survived the pruning phase
                    active_any_deps = [dep for dep in any_deps if dep in active_plugin_ids]
                    any_deps_met = all(dep in completed_plugins for dep in active_any_deps)
                    
                    # Only append if BOTH dependency sets are perfectly satisfied
                    if all_deps_met and any_deps_met:
                        ready_to_run.append(analyzer)

                # 2. Schedule the ready plugins
                for analyzer in ready_to_run:
                    pending_analyzers.remove(analyzer)
                    
                    plugin_config = self.config.get("plugins", {}).get(analyzer.plugin_id, {})

                    logger.debug(f"Scheduling analyzer: {analyzer.name}")
                    configured_tool_name = plugin_config.get("tool", analyzer.plugin_id)
                    tool_path = str(str(self.bin_dir) + "/" + configured_tool_name)
                    
                    # Submit to the thread pool and store the Future
                    future = executor.submit(analyzer.analyze, self.target_file, tool_path, plugin_config)
                    running_futures[future] = analyzer

                # 3. Deadlock Protection
                # If nothing is running, and there are still pending plugins, it means a 
                # dependency is missing (e.g., waiting on a plugin_id that doesn't exist)
                if not running_futures and pending_analyzers:
                    stuck = [a.plugin_id for a in pending_analyzers]
                    logger.error(f"Deadlock detected! Unmet dependencies for: {stuck}")
                    break

                # 4. Wait for AT LEAST ONE plugin to finish
                if running_futures:
                    # The Orchestrator sleeps here until any thread finishes
                    done, _ = concurrent.futures.wait(
                        running_futures.keys(), 
                        return_when=concurrent.futures.FIRST_COMPLETED
                    )

                    # Process the ones that just finished
                    for future in done:
                        analyzer = running_futures.pop(future)
                        try:
                            # Calling .result() raises any exceptions that happened inside the thread
                            future.result()
                            logger.info(f"Completed: {analyzer.name}")
                        except Exception as e:
                            logger.exception(f"Analyzer '{analyzer.name}' crashed!")
                        
                        # Even if it crashed, we mark it completed so the pipeline doesn't freeze.
                        # Downstream plugins will run, gracefully realize data is missing, and exit.
                        completed_plugins.add(analyzer.plugin_id)
        logger.info("Analysis phase complete. Starting reporting phase...")

        self.target_file.results["metadata"]["analyzed_by"] = list(completed_plugins)

        # 2. Generate Reports
        for reporter in self.reporters:

            rep_config = self.reporter_config.get("reporters", {}).get(reporter.reporter_id, {})

            if rep_config.get("enabled", True) is False:
                logger.debug(f"Skipping Reporter: {reporter.name} (Disabled in config)")
                continue

            logger.debug(f"Generating report using: {reporter.name}")

            try:
                reporter.generate(self.target_file, report_dir, rep_config)
            except Exception as e:
                logger.exception(f"Error occurred while generating report with {reporter.name}: {e}")
        logger.info("Report generation completed.")