# Statcheck
Statchec is a highly modular orchestrator designed to automate the static analysis of binaries using Python-based plugins.

It supports chaining together custom analyzers and reporters, significantly reducing manual intervention in scenarios where heavy, automated sandbox systems are not accessible or necessary. 
While built with malware analysis and reverse engineering in mind, the core engine is flexible enough to orchestrate almost any automated processing task.

## Why?
While there are existing solutions that can extract every type of valuable information from a binary, these systems often force users into a strict, monolithic process flow.

I wanted a solution that is truly modular—one that allows analysts to build custom analysis pipelines using external, industry-standard tools for maximum speed and reliability.

The advantages of this approach:

- Build Your Own Tool: Choose the tools you trust and are familiar with, chain them as you like.
- Maximize Performance: Heavy processing is offloaded to compiled tools (like Capa, Detect It Easy, FLOSS etc.) that are already optimized for those tasks.
- Extensible: Easy integration of new tools for both analysis and reporting with simple python wrapper.
- Custom Insights: Write custom Python logic to parse, clean, and correlate the raw outputs into intelligence/insights meaningful for you.
- LLM-Ready Reporting: Data is split into "Summary" (high signal-to-noise) and "Complete" (raw output) structures by default, making the reports highly efficient for AI context windows.

## 🚀 Features

* **Smart Auto-Detection:** Automatically detects the target file format (PE, ELF, Mach-O) using Detect It Easy (DiE).
* **Format-Aware Execution:** Dynamically loads only the plugins that support the submitted file format, saving memory and CPU cycles.
* **Format Overrides:** Allows analysts to manually override detection for obfuscated malware or memory dumps.
* **Separation of Code & Config:** Manage your external binary paths via a simple `tools_config.json` file without ever modifying Python code.
* **Bifurcated Data Structure:** Generates reports that separate critical insights from raw tool output.

## 🗺️ Future Roadmap

- [ ] **Environment Variables Support:** Integrate `.env` file parsing to securely manage secrets and API keys for web-based plugins.
- [ ] **Execution Templates:** Introduce JSON-based execution configurations to define strict tool chaining, specify execution order, and create repeatable analysis templates.
- [ ] **Threat Intelligence (TI) Plugins:** Add analyzers to automatically query indicators against platforms like VirusTotal, ThreatFox, and MalwareBazaar etc.
- [ ] **Parallel Execution:** Upgrade the Orchestrator engine to run independent analyzers concurrently to drastically reduce analysis time.
- [ ] **Human-Readable Reporters:** Implement Markdown and HTML reporters for easily shareable, visually clean forensic reports.
- [ ] **LLM Integration:** Create a dedicated reporter/analyzer that feeds the high-signal `result_summary` into an LLM (Cloud/Local) for automated insight generation.
- [ ] **Archive Pre-processing:** Add native support to automatically unpack password-protected malware archives (e.g., zip/7z files) prior to analysis.

---

## ⚙️ Installation & Setup

**1. Clone the repository**
```bash
git clone https://github.com/geekypanda411/statchec.git
cd statchec
```

**2. Install Python dependencies**
```bash
pip install -r requirements.txt
```

**3. Configure your external tools**
Statchec relies on external binaries (like `diec`, `capa`, etc.). 
Copy the example configuration file and update it with the paths to the binaries on your specific machine:
```bash
cp tools_config.example.json tools_config.json
```
Edit `tools_config.json` to point to your installed tools:
```json
{
    "bin_path": "./bin",
    "tools": {
        "diec": "diec",
        "capa": "capa-linux"
    }
}
```

---

## 💻 Usage

Run Statchec via the command line.

**Standard Auto-Detect Run:**
```bash
python main.py malware_sample.exe --format auto --report json
```

**Force a specific format (e.g., for memory dumps):**
```bash
python main.py dumped_payload.bin --format pe --report json
```

**Enable Debug Logging:**
```bash
python main.py malware_sample.exe --format auto --debug
```

---

## 🧩 Writing a Plugin (Analyzers)

Statchec is designed to be infinitely extensible. To add a new tool to your pipeline, simply create a new Python file in the `src/analyzers/` directory that inherits from `BaseAnalyzer`.

Because of the dynamic plugin architecture, you do not need to register your plugin anywhere. The orchestrator will automatically find it, check its supported formats, and execute it!

### Example Plugin
```python
import subprocess
from src.analyzers.base_analyzer import BaseAnalyzer

class MyCustomAnalyzer(BaseAnalyzer):
    name = "My Awesome Tool"
    supported_formats = ['pe', 'elf'] # Or ['all']
    binary_id = "my_tool"             # Maps to tools_config.json

    def analyze(self, target_file, tool_path):
        # 1. Run your external tool
        result = subprocess.run([tool_path, str(target_file.path)], capture_output=True)
        
        # 2. Parse the output (extract the signal from the noise)
        summary = {"status": "malicious", "ioc": "192.168.1.1"}
        raw_output = result.stdout
        
        # 3. Save it back to the file using our bifurcated structure
        target_file.add_result(
            self.name, 
            summary_data=summary, 
            complete_data={"raw": raw_output}
        )
```

---

## 🤝 Contributing
Contributions, issues, and feature requests are welcome! Feel free to check the [issues page](https://github.com/yourusername/statchec/issues). If you write a cool new Analyzer or Reporter plugin, please submit a Pull Request!

## 📝 License
This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
