# Statcheck

Statcheck is a modular orchestrator designed to automate the metadata analysis of binaries using Python-based plugins. 

It supports chaining together custom analyzers and reporters, helping reduce manual intervention.

While built with malware analysis and reverse engineering in mind, the core engine is adaptable and can be used to orchestrate various automated processing tasks.

## Why Statcheck?

Many existing analysis frameworks have specific, predefined workflows. Statcheck was built to offer a flexible alternative, allowing analysts to create custom pipelines using the external tools they already rely on.

The advantages of this approach include:
- **Familiar Tooling:** Choose the external analysis tools you prefer and chain them as needed.
- **Efficiency:** Offload heavy processing to compiled utilities (like Capa, Detect It Easy, FLOSS) that are optimized for those tasks.
- **Extensibility:** Integrate new tools for analysis or reporting by writing a standard Python wrapper.
- **Custom Insights:** Use Python logic to parse and correlate raw outputs into metrics that are meaningful for your workflow.
- **LLM-Ready Reporting:** Data is split into "Summary" (high signal-to-noise) and "Complete" (raw output) structures. This makes the reports easier for humans to read and highly efficient for AI context windows.

## Features

- **Concurrent Execution:** Uses a Directed Acyclic Graph (DAG) dependency system to run independent analyzers in parallel, reducing overall analysis time.
- **Format-Aware Routing:** Identifies file types (PE, ELF, Mach-O) using native Python header checks, dynamically loading only the plugins that support the submitted format.
- **Manual Overrides:** Allows analysts to bypass automatic detection for obfuscated malware or memory dumps and define the format in the command line.
- **External Configuration:** Manages external binary paths, tool toggles, and API keys via simple `tools_config.json` and `.env` files without requiring code modifications.
- **Resilient Threat Intelligence:** Built-in integration with VirusTotal and MalwareBazaar, featuring automated rate-limiting, retry adapters, and error handling.
- **Template-Based Reporting:** Presentation layers (like JSON output) are entirely decoupled from the analysis logic and configurable via `reporter_config.json`.

## Installation & Setup

**1. Clone the repository**
```bash
git clone https://github.com/geekypanda411/statcheck.git
cd statcheck
```

**2. Install Python dependencies**
```bash
pip install -r requirements.txt
```

**3. Configure your external tools and environment**
Statcheck integrates with external binaries and APIs. Copy the example configuration file to set up your environment:

```bash
cp tools_config.json.example tools_config.json
```

Edit `tools_config.json` to point to your installed binaries, and securely add any required API keys to a `.env` file (e.g., `MB_API_KEY`, `VT_API_KEY`).

## Usage

Statcheck is run via the command line.

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

## Writing a Plugin (Analyzers)

To add a new tool to your pipeline, create a Python file in the `src/analyzers/` directory that inherits from `BaseAnalyzer`. The orchestrator will automatically discover it, check its dependencies, and execute it.

### Example Plugin

```python
import subprocess
from src.analyzers.base_analyzer import BaseAnalyzer

class CustomAnalyzer(BaseAnalyzer):
    name = "Custom Tool Analyzer"
    plugin_id = "custom_tool"
    supported_formats = ['all']
    
    # Define plugins that must run before this one
    depends = {"all":["<List of plugins that must be executed before your plugin>"],"any":["<List of plugins where at least one of these should be enabled and executed before your plugin>"]} 

    def analyze(self, target_file, tool_path, plugin_config, run_dir):
        # 1. Run your external tool
        result = subprocess.run([tool_path, str(target_file.path)], capture_output=True, text=True)
        
        # 2. Parse the output into a clean summary
        summary = {"status": "analyzed"}
        
        # Base Analyzer has a helper (get_plugin_dir) that generates a directory for the plugin calling it
        plugin_dir = self.get_plugin_dir(run_dir)
        # Name of your complete raw results, ideally <plugin id>_raw_output.<format>
        raw_output_path = os.path.join(plugin_dir, "custom_tool_raw_output.json")
        with open(raw_output_path, "w") as f:
            json.dump(complete, f, indent=4)
        # Linking raw tool output to the summary
        summary["raw_output_path"] = raw_output_path

        # 3. Save it back to the target file
        target_file.add_result(
            self.plugin_id, 
            summary_data=summary, 
            internal_context_data={
                "whatever_you_want_passed_to_other_plugins": generated_internal_context,
            }
        )
```

## Future Roadmap

**Core Engine & Architecture**
- [x] **Environment Variables:** Integrate `.env` parsing to securely manage API keys.
- [x] **Parallel Execution:** Upgrade the Orchestrator engine to run independent analyzers concurrently.
- [ ] **Execution Templates:** Use JSON to define strict tool chaining and repeatable analysis templates.

**Analysis & Threat Intelligence**
- [x] **Public TI APIs:** Automated querying against VirusTotal and MalwareBazaar.
- [x] **String Extraction:** Add a FLOSS and QUANTUMSTRAND analyzer to extract and filter IOCs via regex.
- [ ] **Custom YARA:** Add support to trigger local scans using custom YARA rulesets.
- [ ] **Prompt Injection strings Detection:** Add support to analyze extracted strings and identify potential prompt injection strings.
- [ ] **OSINT Hash Search:** Automate Google querying to find existing sandbox reports or threat write-ups for a sample.
- [ ] **Internal CTI Integration:** Add the ability to query internal intelligence platforms like MISP and OpenCTI.
- [ ] **Dynamic Analysis (CAPEv2):** Automate submitting samples to a CAPEv2 instance and parsing the behavioral results.

**Reporting & Output**
- [ ] **Human-Readable Reporters:** Implement Markdown and HTML reporters for shareable forensic reports.
- [ ] **LLM Integration:** Feed the high-signal `result_summary` into an LLM for automated narrative threat assessments.
- [ ] **STIX 2.1 Reporter:** Convert results to STIX 2.1 compliant output for automated ingestion by enterprise TI platforms.

## Contributing

Contributions, issues, and feature requests are welcome. Feel free to check the [issues page](https://github.com/geekypanda411/statcheck/issues) if you would like to contribute.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
