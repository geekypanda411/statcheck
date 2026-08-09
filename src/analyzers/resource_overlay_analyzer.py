import logging
import os
import json
import math
import hashlib
import re
import pefile
import lief
from src.analyzers.base_analyzer import BaseAnalyzer

logger = logging.getLogger(__name__)

class ResourceOverlayAnalyzer(BaseAnalyzer):
    name = "Resource & Overlay Analyzer"
    supported_formats = ['pe', 'elf']
    plugin_id = "resource_overlay"
    
    depends = {"all": [], "any": []}

    def _calc_entropy(self, data):
        if not data: return 0.0
        entropy = 0
        for x in range(256):
            p_x = float(data.count(x)) / len(data)
            if p_x > 0: entropy += - p_x * math.log2(p_x)
        return round(entropy, 4)

    def _get_magic_type(self, data):
        if data.startswith(b'MZ'): return "Windows Executable (MZ)"
        if data.startswith(b'\x7FELF'): return "Linux Executable (ELF)"
        if data.startswith(b'PK\x03\x04'): return "ZIP Archive"
        if data.startswith(b'Rar!\x1a\x07'): return "RAR Archive"
        if data.startswith(b'7z\xbc\xaf\x27\x1c'): return "7z Archive"
        if data.startswith(b'\x1f\x8b\x08'): return "GZIP Archive"
        return "Unknown Data"

    def analyze(self, target_file, tool_path, plugin_config, run_dir):
        logger.debug(f"Starting Resource & Overlay analysis on {target_file.filename}")
        
        extract_rsrc = plugin_config.get("extract_resources", True)
        extract_ovl = plugin_config.get("extract_overlay", True)
        plugin_dir = self.get_plugin_dir(run_dir)
        base_dir = plugin_dir
        
        # Output Directories
        rsrc_out_dir = os.path.join(base_dir, "extracted_resources")
        ovl_out_dir = os.path.join(base_dir, "extracted_overlay")
        
        try:
            with open(target_file.path, "rb") as f:
                file_bytes = f.read()
        except Exception as e:
            logger.error(f"Failed to read target file: {e}")
            return

        summary = {"resources": [], "overlay": []}
        complete = {"raw_resources": []}

        # ==========================================
        # PE FILE PARSING (Resources & Overlay)
        # ==========================================
        if target_file.format == 'pe':
            try:
                pe = pefile.PE(data=file_bytes)
                
                # PE Resources
                if hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE'):
                    # Map standard PE resource types
                    rt_types = {
                        1: "RT_CURSOR", 2: "RT_BITMAP", 3: "RT_ICON", 4: "RT_MENU", 5: "RT_DIALOG", 
                        6: "RT_STRING", 9: "RT_ACCELERATOR", 10: "RT_RCDATA", 16: "RT_VERSION", 24: "RT_MANIFEST"
                    }
                    
                    for resource_type in pe.DIRECTORY_ENTRY_RESOURCE.entries:
                        # Identify the resource type (e.g., RT_RCDATA)
                        res_type_str = rt_types.get(resource_type.struct.Id, f"CUSTOM_TYPE_{resource_type.struct.Id}")
                        
                        for resource_id in resource_type.directory.entries:
                            for resource_lang in resource_id.directory.entries:
                                
                                offset = resource_lang.data.struct.OffsetToData
                                size = resource_lang.data.struct.Size
                                res_data = pe.get_memory_mapped_image()[offset:offset+size]
                                
                                if not res_data: continue
                                
                                entropy = self._calc_entropy(res_data)
                                sha256 = hashlib.sha256(res_data).hexdigest()
                                magic_type = self._get_magic_type(res_data)
                                
                                # High fidelity risk check
                                is_risk = entropy > 7.0 or magic_type != "Unknown Data"
                                
                                # Extract to disk if configured
                                extracted_path = None
                                if extract_rsrc and is_risk:
                                    os.makedirs(rsrc_out_dir, exist_ok=True)
                                    res_name = str(resource_id.name) if resource_id.name else str(resource_id.struct.Id)
                                    # Create a safe filename
                                    safe_res_name = "".join([c if c.isalnum() else "_" for c in res_name])
                                    file_name = f"rsrc_{res_type_str}_{safe_res_name}.bin"
                                    extracted_path = os.path.join(rsrc_out_dir, file_name)
                                    with open(extracted_path, "wb") as out_f:
                                        out_f.write(res_data)

                                summary["resources"].append({
                                    "id": resource_id.struct.Id if resource_id.struct.Id else str(resource_id.name),
                                    "name": str(resource_id.name) if resource_id.name else None,
                                    "resource_type": res_type_str,
                                    "size": size,
                                    "offset": offset,
                                    "file_type": magic_type,
                                    "entropy": entropy,
                                    "hash_sha256": sha256,
                                    "is_risk": is_risk,
                                    "extracted_to": extracted_path
                                })
                                
                # PE Overlay
                overlay_data = pe.get_overlay()
                overlay_offset = pe.get_overlay_data_start_offset()

            except Exception as e:
                logger.error(f"PEFile failed during resource/overlay parsing: {e}")
                overlay_data = None


        # ==========================================
        # ELF FILE PARSING (Overlay Only)
        # ==========================================
        elif target_file.format == 'elf':
            try:
                elf = lief.ELF.parse(file_bytes)
                
                # Find the end of the last section to locate the overlay
                max_offset = 0
                for section in elf.sections:
                    if section.file_offset + section.size > max_offset:
                        max_offset = section.file_offset + section.size
                
                # If the file is larger than the defined sections, we have an overlay
                if len(file_bytes) > max_offset:
                    overlay_data = file_bytes[max_offset:]
                    overlay_offset = max_offset
                else:
                    overlay_data = None
                    
            except Exception as e:
                logger.error(f"LIEF failed during ELF overlay parsing: {e}")
                overlay_data = None

        # ==========================================
        # OVERLAY ANALYSIS (Both PE & ELF)
        # ==========================================
        if overlay_data:
            ovl_entropy = self._calc_entropy(overlay_data)
            ovl_sha256 = hashlib.sha256(overlay_data).hexdigest()
            
            # Deep Carving Regex Signatures (re.DOTALL allows matching across newlines)
            filetype_signatures = {
                "Windows Executable (PE)": rb'MZ.{0,1024}?This program cannot be run in DOS mode',
                "Linux Executable (ELF)": rb'\x7FELF',
                "ZIP Archive": rb'PK\x03\x04',
                "RAR Archive": rb'Rar!\x1A\x07',
                "7z Archive": rb'7z\xBC\xAF\x27\x1C'
            }
            
            detected_artifacts = []
            for art_type, magic_regex in filetype_signatures.items():
                # finditer quickly sweeps the memory buffer for signatures
                for match in re.finditer(magic_regex, overlay_data, re.DOTALL | re.IGNORECASE):
                    relative_offset = match.start()
                    detected_artifacts.append({
                        "type": art_type,
                        "offset_within_overlay": relative_offset,
                        "absolute_offset": overlay_offset + relative_offset
                    })
            
            # Extract to disk if configured
            extracted_ovl_path = None
            if extract_ovl:
                os.makedirs(ovl_out_dir, exist_ok=True)
                extracted_ovl_path = os.path.join(ovl_out_dir, "extracted_overlay.bin")
                with open(extracted_ovl_path, "wb") as out_f:
                    out_f.write(overlay_data)

            summary["overlay"].append({
                "size": len(overlay_data),
                "absolute_offset": overlay_offset,
                "entropy": ovl_entropy,
                "hash_sha256": ovl_sha256,
                "is_risk": True,  # Any overlay presence is generally considered an anomaly/risk
                "carved_artifacts": detected_artifacts,
                "extracted_to": extracted_ovl_path
            })

        # --- SAVE RESULTS ---
        # Clean empty lists so we don't bloat the JSON
        clean_summary = {k: v for k, v in summary.items() if v}

        raw_output_path = os.path.join(plugin_dir, "resource_overlay_raw_output.json")
        with open(raw_output_path, "w") as f:
            json.dump(complete, f, indent=4)
        summary["raw_output_path"] = raw_output_path

        if clean_summary:
            target_file.add_result(self.plugin_id, summary_data=clean_summary)
            logger.info("Successfully analyzed Resources and Overlays.")
        else:
            logger.info("No significant resources or overlays found.")