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
    def priority(self) -> int:
        #Mechanism to prioritise execution of specific plugins
        #Intent is to avoid situations where a plugin B requiring results of plugin A
        #Does not end up running before plugin A
        #It is int so you can have it set at whatever but the sorting will be in
        #ascending order.
        return 50

    @abstractmethod
    def analyze(self, target_file, tool_path: str, plugin_config: dict):
        pass