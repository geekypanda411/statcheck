import logging
import pefile
from src.analyzers.base_analyzer import BaseAnalyzer

logger = logging.getLogger(__name__)

class PESectionAnalyzer(BaseAnalyzer):
    name = "PE Section Analyzer"
    supported_formats = ['pe']
    plugin_id = "pe_sections"
    depends = []

    def analyze(self, target_file, tool_path, plugin_config):
        logger.debug(f"Analyzing PE sections for {target_file.filename}")
        
        try:
            pe = pefile.PE(target_file.path)
        except pefile.PEFormatError:
            logger.error(f"{target_file.filename} is not a valid PE file.")
            return
        except Exception as e:
            logger.exception(f"Unexpected error parsing PE file: {e}")
            return

        summary = {
            "flags": {
                "has_rwx_section": False,
                "has_highly_anomalous_sizes": False,
                "entry_point_in_writable_section": False
            },
            "sections": []
        }
        complete_raw = []

        # Entry Point (EP)
        ep = pe.OPTIONAL_HEADER.AddressOfEntryPoint

        for section in pe.sections:
            # 1. remove null bytes
            sec_name = section.Name.decode('utf-8', errors='ignore').rstrip('\x00')
            
            # 2. Extract Sizes
            v_size = section.Misc_VirtualSize
            r_size = section.SizeOfRawData
            
            # 3. Calculate Permissions using Bitwise operations on Characteristics
            # 0x20000000 = Executable, 0x40000000 = Readable, 0x80000000 = Writable
            is_read = bool(section.Characteristics & 0x40000000)
            is_write = bool(section.Characteristics & 0x80000000)
            is_exec = bool(section.Characteristics & 0x20000000)
            
            perms = ""
            perms += "R" if is_read else "-"
            perms += "W" if is_write else "-"
            perms += "X" if is_exec else "-"

            # 4. Calculate Entropy
            entropy = round(section.get_entropy(), 4)

            # 5. Does this section contain the Entry Point?
            # Check if the EP address falls within this section's virtual memory boundaries
            is_ep_section = section.VirtualAddress <= ep < (section.VirtualAddress + v_size)

            # --- ANOMALY CHECKS ---
            
            # Check A: RWX Permissions
            if perms == "RWX":
                summary["flags"]["has_rwx_section"] = True
                
            # Check B: Entry Point in a Writable Section
            if is_ep_section and is_write:
                summary["flags"]["entry_point_in_writable_section"] = True
                
            # Check C: Virtual Size >> Raw Size
            # (e.g., Virtual Size is at least 2x larger AND the difference is > 10KB to ignore tiny paddings)
            if v_size > (r_size * 2) and (v_size - r_size) > 10240:
                summary["flags"]["has_highly_anomalous_sizes"] = True
                
            # Compile the clean summary object
            sec_summary = {
                "name": sec_name,
                "virtual_size": v_size,
                "raw_size": r_size,
                "permissions": perms,
                "entropy": entropy,
                "contains_ep": is_ep_section
            }
            summary["sections"].append(sec_summary)
            
            # Save raw attributes for the complete report
            complete_raw.append({
                "name": sec_name,
                "virtual_address": hex(section.VirtualAddress),
                "pointer_to_raw_data": hex(section.PointerToRawData),
                "characteristics": hex(section.Characteristics)
            })

        # Close the PE file to free memory
        pe.close()

        # Save to TargetFile
        target_file.add_result(
            self.plugin_id, 
            summary_data=summary, 
            complete_data={"raw_section_headers": complete_raw}
        )
        logger.info("Successfully analyzed PE sections.")