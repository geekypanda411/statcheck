from pathlib import Path

class TargetFile:
    def __init__(self, file_path: str, file_format: str = "unknown"):
        self.path = Path(file_path)
        self.filename = self.path.name
        self.format = file_format.lower()
        self.results = {"metadata": {},"result_summary":{},"internal_context":{}}

    def add_result(self, tool_name: str, summary_data=None, internal_context_data=None):
        # use .setdefault() so that if the key gets deleted somehow Python will recreate it on the fly!
        
        if summary_data is not None:
            self.results.setdefault("result_summary", {})[tool_name] = summary_data
            
        if internal_context_data is not None:
            self.results.setdefault("internal_context", {})[tool_name] = internal_context_data