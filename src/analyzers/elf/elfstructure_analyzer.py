import logging
import lief
import json
import os
from src.analyzers.base_analyzer import BaseAnalyzer

logger = logging.getLogger(__name__)

class ELFStructureAnalyzer(BaseAnalyzer):
    name = "ELF Structure Analyzer"
    supported_formats = ['elf']
    plugin_id = "elfstructure"
    
    depends = {"all": [], "any": []}

    def analyze(self, target_file, tool_path, plugin_config, run_dir):
        logger.debug(f"Starting ELF Structure analysis on {target_file.filename}")
        
        try:
            elf = lief.ELF.parse(str(target_file.path))
            if not elf:
                logger.error(f"LIEF failed to parse {target_file.filename} as an ELF.")
                return
        except Exception as e:
            logger.error(f"LIEF threw an exception while parsing ELF: {e}")
            return

        summary = {
            "flags": {
                "is_stripped": False,
                "is_statically_linked": not elf.has_interpreter,
                "has_rwx_segments": False,
                "has_custom_rpath": False
            },
            "interpreter": elf.interpreter if elf.has_interpreter else "None (Statically Linked)",
            "anomalies": {}
        }
        
        complete_raw = {
            "segments": [],
            "dynamic_libraries": elf.libraries
        }

        # CHECK FOR STRIPPED SYMBOLS
        if not elf.has_section(".symtab"):
            summary["flags"]["is_stripped"] = True

        # ANALYZE SEGMENTS
        rwx_segments = []
        
        for segment in elf.segments:
            # LIEF frequently renames their enums. To be version-immune (hopefully),
            # cast the flags to an integer and use standard ELF bitwise logic:
            # PF_R (Read) = 4, PF_W (Write) = 2, PF_X (Execute) = 1
            flags = int(segment.flags)
            
            is_read = bool(flags & 4)
            is_write = bool(flags & 2)
            is_exec = bool(flags & 1)
            
            perms = ""
            perms += "R" if is_read else "-"
            perms += "W" if is_write else "-"
            perms += "X" if is_exec else "-"
            
            seg_data = {
                "type": str(segment.type).split('.')[-1],
                "virtual_address": hex(segment.virtual_address),
                "virtual_size": segment.virtual_size,
                "permissions": perms
            }
            
            complete_raw["segments"].append(seg_data)
            
            if perms == "RWX":
                summary["flags"]["has_rwx_segments"] = True
                rwx_segments.append(seg_data)

        if rwx_segments:
            summary["anomalies"]["rwx_segments"] = rwx_segments

        # ANALYZE DYNAMIC ENTRIES (RPATH / RUNPATH)
        custom_paths = []
        
        # We can just iterate directly; if it's empty, the loop safely skips!
        for entry in elf.dynamic_entries:
            # Safely check if the object contains the rpath or runpath properties
            if hasattr(entry, "rpath"):
                custom_paths.append(f"RPATH: {entry.rpath}")
            elif hasattr(entry, "runpath"):
                custom_paths.append(f"RUNPATH: {entry.runpath}")

        if custom_paths:
            summary["flags"]["has_custom_rpath"] = True
            summary["anomalies"]["custom_library_paths"] = custom_paths

        plugin_dir = self.get_plugin_dir(run_dir)
        raw_output_path = os.path.join(plugin_dir, "elfstructure_raw_output.json")
        with open(raw_output_path, "w") as f:
            json.dump(complete_raw, f, indent=4)
        summary["raw_output_path"] = raw_output_path

        # FORMAT AND SAVE RESULTS
        target_file.add_result(
            self.plugin_id, 
            summary_data=summary
        )
        logger.info("Successfully analyzed ELF Structure.")