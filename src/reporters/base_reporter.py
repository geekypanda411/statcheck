from abc import ABC, abstractmethod
from src.core.target_file import TargetFile

class BaseReporter(ABC):
    @property
    @abstractmethod
    def name(self) -> str:
        #Name of reporter
        pass

    @property
    @abstractmethod
    def format_id(self) -> str:
        #Report format
        pass

    @property
    @abstractmethod
    def reporter_id(self) -> str:
        #The key used in reporter_config.json (e.g., 'json_reporter')
        pass
    
    @abstractmethod
    def generate(self, target_file: TargetFile, output_dir: str, reporter_config: dict, timestamp: int):
        #Actual report writer
        pass