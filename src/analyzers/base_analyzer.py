from abc import ABC, abstractmethod

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
    def depends(self) -> list:
        #List of plugins a plugin depends e.g.
        #If plugin B depends on output of plugin A then plugin B's depends list will have plugin A
        #The core engine will make sure the depends plugin gets executed first.
        return []

    @abstractmethod
    def analyze(self, target_file, tool_path: str, plugin_config: dict):
        pass