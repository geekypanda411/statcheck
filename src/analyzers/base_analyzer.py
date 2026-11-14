from abc import ABC, abstractmethod
import json
import os

class BaseAnalyzer(ABC):
    @property
    @abstractmethod
    def name(self) -> str:
        pass

    @property
    @abstractmethod
    def supported_formats(self) -> list:
        pass

    @property
    def plugin_id(self) -> str:
        #Optional: to look up tool path and plugin config in tools_config.json
        return None

    @property
    def depends(self) -> dict:
        """
        Dictionary of plugin_ids this analyzer depends on.
        'all': Strict dependencies. All must be enabled and complete.
        'any': Aggregate dependencies. At least ONE must be enabled. Will wait for all enabled ones to complete.
        """
        return {"all": [], "any": []}

    def get_plugin_dir(self, run_dir: str) -> str:
        #Helper to dynamically create and return this plugin's dedicated output folder
        plugin_dir = os.path.join(run_dir, self.plugin_id)
        os.makedirs(plugin_dir, exist_ok=True)
        return plugin_dir

    def save_raw(self, run_dir: str, filename: str, data) -> str:
        """Write raw analyzer output as JSON into this plugin's directory.

        Always returns a path **relative to** ``run_dir`` so reports stay
        portable across machines and output locations.
        """
        plugin_dir = self.get_plugin_dir(run_dir)
        path = os.path.join(plugin_dir, filename)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=4, default=str)
        return os.path.relpath(path, start=run_dir)

    @abstractmethod
    def analyze(self, target_file, tool_path: str, plugin_config: dict, run_dir: str):
        pass