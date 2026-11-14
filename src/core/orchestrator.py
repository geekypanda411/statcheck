import concurrent.futures
import importlib.util
import json
import logging
import os
import re
import sys
import time
from pathlib import Path

from src.analyzers.base_analyzer import BaseAnalyzer, RuntimeContext
from src.core.config import validate_reporter_config, validate_tool_config
from src.core.paths import PROJECT_ROOT, resolve_path
from src.core.target_file import TargetFile
from src.reporters.base_reporter import BaseReporter

logger = logging.getLogger(__name__)

class Orchestrator:
    def __init__(
        self,
        file_path: str,
        file_format: str,
        config_path: str | Path | None = None,
        reporter_config_path: str | Path | None = None,
        workers: int = 10,
        timeout: float = 300.0,
    ):
        self.target_file = TargetFile(file_path, file_format)
        self.file_format = file_format.lower()
        self.analyzers = []
        self.reporters = []
        self.workers = workers
        self.timeout = timeout
        self.runtime: RuntimeContext | None = None
        logger.debug(f"Orchestrator initialized for file: {file_path} with format: {file_format}")

        # Defaults are anchored to the project layout, not the caller's CWD.
        self.config_path = Path(config_path) if config_path else PROJECT_ROOT / "tools_config.json"
        if reporter_config_path:
            self.reporter_config_path = Path(reporter_config_path)
        else:
            self.reporter_config_path = PROJECT_ROOT / "reporter_config.json"

        self.config = self._load_tool_config(str(self.config_path))
        self.reporter_config = self._load_reporter_config(str(self.reporter_config_path))
        # bin_path is resolved relative to the config file's directory so a
        # config with "./bin" means "bin next to the config", not "bin next
        # to wherever the user happened to invoke statcheck".
        self.bin_dir = resolve_path(
            self.config.get("bin_path", "./bin"), base=self.config_path.resolve().parent
        )

    def _load_tool_config(self, config_path: str) -> dict:
        # Consumers read config["plugins"], so the fallback must use that
        # namespace (not "tools") or every plugin lookup would miss.
        config = self._load_config(config_path, default={"bin_path": "./bin", "plugins": {}})
        for warning in validate_tool_config(config):
            logger.warning(f"Tool config: {warning}")
        return config

    def _load_reporter_config(self, config_path: str) -> dict:
        config = self._load_config(config_path, default={"reporters": {}})
        for warning in validate_reporter_config(config):
            logger.warning(f"Reporter config: {warning}")
        return config

    def _load_config(self, config_path: str, default: dict) -> dict:
        if os.path.exists(config_path):
            with open(config_path) as f:
                return json.load(f)
        else:
            logger.warning(f"Config file {config_path} not found. Using defaults.")
            return default

    def _import_plugin_files(self, file_paths: list):
        if not hasattr(self, '_loaded_modules'):
            self._loaded_modules = []
        if not hasattr(self, '_imported_module_names'):
            # Guard against re-importing the same plugin file, which would
            # create duplicate class objects and duplicate registrations.
            self._imported_module_names = set()

        for file_path in file_paths:
            if file_path.name in ["__init__.py", "base_analyzer.py", "base_reporter.py"]:
                continue
            logger.debug(f"Importing plugin: {file_path}")
            file_path = Path(file_path)
            try:
                module_name = ".".join(file_path.with_suffix("").parts)
                if module_name in self._imported_module_names:
                    logger.debug(f"Plugin already imported, skipping: {file_path.name}")
                    continue
                spec = importlib.util.spec_from_file_location(module_name, file_path)
                module = importlib.util.module_from_spec(spec)
                sys.modules[module_name] = module
                self._loaded_modules.append(module)
                self._imported_module_names.add(module_name)

                spec.loader.exec_module(module)
            except Exception as e:
                logger.exception(f"Failed to load plugin file {file_path.name}: {e}")

    def _iter_plugin_subclasses(self, base_cls, id_attr: str):
        """Yield each distinct plugin subclass exactly once.

        Re-importing a plugin file creates a *new* class object even though the
        module/class name is unchanged, and ``__subclasses__()`` then reports
        both. Deduplicate by fully-qualified class name and by plugin id.
        """
        seen_class_names = set()
        seen_ids = set()
        for cls in base_cls.__subclasses__():
            class_key = f"{cls.__module__}.{cls.__qualname__}"
            if class_key in seen_class_names:
                continue
            seen_class_names.add(class_key)

            # A non-overridden BaseAnalyzer.plugin_id is a property object;
            # treat it as "no id" and fall back to class-identity dedupe.
            plugin_id = getattr(cls, id_attr, None)
            if isinstance(plugin_id, property):
                plugin_id = None
            if plugin_id is not None:
                if plugin_id in seen_ids:
                    continue
                seen_ids.add(plugin_id)
            yield cls

    def _analyzer_files(self, base_plugins_dir: str | Path) -> list:
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
            upd_target_files.append(target_file)
        return upd_target_files

    def load_analyzers(self, base_plugins_dir: str | Path | None = None):
        base_plugins_dir = base_plugins_dir or (PROJECT_ROOT / "src" / "analyzers")
        upd_target_files = self._analyzer_files(base_plugins_dir)

        logger.debug(f"Targeting {len(upd_target_files)} analyzer files for {self.file_format}.")

        self._import_plugin_files(upd_target_files)

        # Reset state so repeated calls are idempotent instead of appending
        # duplicate registrations.
        self.analyzers = []
        for analyzer_class in self._iter_plugin_subclasses(BaseAnalyzer, "plugin_id"):
            analyzer = analyzer_class()
            formats = analyzer.supported_formats
            if 'all' in formats or self.file_format in formats:
                self.analyzers.append(analyzer)
                logger.debug(f"Analyzer loaded: {analyzer.name}")
            else:
                logger.debug(f"Analyzer {analyzer.name} skipped (unsupported format: {self.file_format})")
        logger.info(f"Total analyzers loaded: {len(self.analyzers)}")

        configured_ids = set(self.config.get("plugins", {}).keys())
        if configured_ids:
            # Warn about plugin ids in the config that no analyzer implements
            # (regardless of format support, to avoid false positives).
            all_ids = set()
            for cls in self._iter_plugin_subclasses(BaseAnalyzer, "plugin_id"):
                pid = getattr(cls, "plugin_id", None)
                if not isinstance(pid, property):
                    all_ids.add(pid)
            unknown = sorted(configured_ids - all_ids)
            if unknown:
                logger.warning(f"Config references unknown plugin ids: {unknown}")

    def load_reporters(self, reporter_dir: str | Path | None = None, desired_reporter: list | None = None):
        desired_reporter = desired_reporter or ["json"]
        reporter_dir = reporter_dir or (PROJECT_ROOT / "src" / "reporters")
        file_ignore_list = ["__init__.py", "base_reporter.py"]
        base_path = Path(reporter_dir)

        all_py_files = list(base_path.glob("*.py"))
        available_reporters = []

        for py_file in all_py_files:
            if py_file.name in file_ignore_list:
                continue
            available_reporters.append(py_file)
        logger.debug(f"Total reporters identified: {len(available_reporters)}")

        self._import_plugin_files(available_reporters)

        self.reporters = []
        for reporter_class in self._iter_plugin_subclasses(BaseReporter, "reporter_id"):
            reporter = reporter_class()
            if 'all' in desired_reporter or reporter.format_id in desired_reporter:
                self.reporters.append(reporter)
                logger.debug(f"Reporter loaded: {reporter.name} (format: {reporter.format_id})")
            else:
                logger.debug(f"Reporter {reporter.name} skipped (unsupported format: {reporter.format_id})")
        logger.info(f"Total reporters loaded: {len(self.reporters)}")

    def list_plugins(self) -> dict:
        """Import every plugin file and return metadata for all of them.

        Used by ``--list-plugins``; independent of the target file format.
        """
        analyzer_dir = PROJECT_ROOT / "src" / "analyzers"
        analyzer_files = [
            p for p in analyzer_dir.rglob("*.py")
            if p.name not in ("__init__.py", "base_analyzer.py")
        ]
        self._import_plugin_files(analyzer_files)

        analyzers = []
        for cls in self._iter_plugin_subclasses(BaseAnalyzer, "plugin_id"):
            analyzer = cls()
            analyzers.append({
                "plugin_id": analyzer.plugin_id,
                "name": analyzer.name,
                "supported_formats": list(analyzer.supported_formats),
                "depends": analyzer.depends,
            })

        reporter_dir = PROJECT_ROOT / "src" / "reporters"
        reporter_files = [
            p for p in reporter_dir.glob("*.py")
            if p.name not in ("__init__.py", "base_reporter.py")
        ]
        self._import_plugin_files(reporter_files)

        reporters = []
        for cls in self._iter_plugin_subclasses(BaseReporter, "reporter_id"):
            reporter = cls()
            reporters.append({
                "reporter_id": reporter.reporter_id,
                "name": reporter.name,
                "format_id": reporter.format_id,
            })

        return {
            "analyzers": sorted(analyzers, key=lambda a: str(a["plugin_id"])),
            "reporters": sorted(reporters, key=lambda r: str(r["reporter_id"])),
        }

    def execute(self, report_dir: str):
        logger.info("Pre-Processing analyzer dependencies..")

        # --- Create Unified Run Directory ---
        self.timestamp = int(time.time())
        clean_name = re.sub(r'[^a-zA-Z0-9.-]+', '_', self.target_file.filename)
        self.run_dir = os.path.join(report_dir, f"{clean_name}_{self.timestamp}")
        os.makedirs(self.run_dir, exist_ok=True)
        logger.info(f"Created Unified Run Directory: {self.run_dir}")

        # --- Build the runtime context handed to every analyzer ---
        self.runtime = RuntimeContext(
            config_path=self.config_path.resolve(),
            run_dir=Path(self.run_dir),
            project_root=PROJECT_ROOT,
            timeout=self.timeout,
            limits=self.config.get("limits", {}),
        )

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
                        if missing_all:
                            reason = f"Missing 'all' deps: {missing_all}."
                        else:
                            reason = f"None of 'any' deps enabled: {any_deps}."
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

        with concurrent.futures.ThreadPoolExecutor(max_workers=self.workers, thread_name_prefix="Worker") as executor:
            
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

                    # Give the analyzer access to runtime paths/limits without
                    # changing its public analyze() signature.
                    analyzer.set_runtime(self.runtime)

                    # Submit to the thread pool and store the Future
                    future = executor.submit(analyzer.analyze, self.target_file, tool_path, plugin_config, self.run_dir)
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
                        except Exception:
                            logger.exception(f"Analyzer '{analyzer.name}' crashed!")
                        
                        # Even if it crashed, we mark it completed so the pipeline doesn't freeze.
                        # Downstream plugins will run, gracefully realize data is missing, and exit.
                        completed_plugins.add(analyzer.plugin_id)
        logger.info("Analysis phase complete. Starting reporting phase...")

        self.target_file.results["metadata"]["analyzed_by"] = sorted(completed_plugins)

        # 2. Generate Reports
        for reporter in self.reporters:

            rep_config = self.reporter_config.get("reporters", {}).get(reporter.reporter_id, {})

            if rep_config.get("enabled", True) is False:
                logger.debug(f"Skipping Reporter: {reporter.name} (Disabled in config)")
                continue

            logger.debug(f"Generating report using: {reporter.name}")

            try:
                reporter.generate(self.target_file, self.run_dir, rep_config, self.timestamp)
            except Exception as e:
                logger.exception(f"Error occurred while generating report with {reporter.name}: {e}")
        logger.info("Report generation completed.")
