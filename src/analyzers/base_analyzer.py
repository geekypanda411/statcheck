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
    def binary_id(self) -> str:
        #Optional: to look up tool paths/config in tools_config.json
        return None

    @abstractmethod
    def analyze(self, target_file):
        pass