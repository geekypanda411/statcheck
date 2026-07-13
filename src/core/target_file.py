from pathlib import Path

class TargetFile:
    def __init__(self, file_path: str):
        self.path = Path(file_path)
        self.filename = self.path.name
        self.results = {"result_summary":{},"result_complete":{}}

    def add_result(self, tool_name: str, summary_data=None, complete_data=None):
        # use .setdefault() so that if the key gets deleted somehow Python will recreate it on the fly!
        
        if summary_data is not None:
            self.results.setdefault("result_summary", {})[tool_name] = summary_data
            
        if complete_data is not None:
            self.results.setdefault("result_complete", {})[tool_name] = complete_data