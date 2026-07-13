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

    @abstractmethod
    def generate(self, target_file: TargetFile, output_dir: str):
        #Actual report writer
        pass