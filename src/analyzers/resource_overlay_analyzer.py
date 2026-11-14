import hashlib
import logging
import os
import re

import lief
import pefile

from src.analyzers.base_analyzer import BaseAnalyzer
from src.core.analysis_utils import shannon_entropy

logger = logging.getLogger(__name__)


class ResourceOverlayAnalyzer(BaseAnalyzer):
    name = "Resource & Overlay Analyzer"
    supported_formats = ["pe", "elf"]
    plugin_id = "resource_overlay"

    depends = {"all": [], "any": []}

    def _calc_entropy(self, data):
        return shannon_entropy(data)

    def _get_magic_type(self, data):
        if data.startswith(b"MZ"):
            return "Windows Executable (MZ)"
        if data.startswith(b"\x7fELF"):
            return "Linux Executable (ELF)"
        if data.startswith(b"PK\x03\x04"):
            return "ZIP Archive"
        if data.startswith(b"Rar!\x1a\x07"):
            return "RAR Archive"
        if data.startswith(b"7z\xbc\xaf\x27\x1c"):
            return "7z Archive"
        if data.startswith(b"\x1f\x8b\x08"):
            return "GZIP Archive"
        return "Unknown Data"

    @staticmethod
    def _resource_filename(res_type_str: str, res_id_name: str, lang_id) -> str:
        """Deterministic, collision-free name for an extracted resource.

        Includes the language ID so the same type/id in different languages
        cannot overwrite each other: ``rsrc_{type}_{id}_{lang}.bin``.
        """
        safe_id = "".join([c if c.isalnum() else "_" for c in str(res_id_name)])
        return f"rsrc_{res_type_str}_{safe_id}_{lang_id}.bin"

    def analyze(self, target_file, tool_path, plugin_config, run_dir):
        logger.debug(f"Starting Resource & Overlay analysis on {target_file.filename}")

        extract_rsrc = plugin_config.get("extract_resources", True)
        extract_ovl = plugin_config.get("extract_overlay", True)
        max_resource_bytes = int(plugin_config.get("max_resource_bytes", self.get_limit("max_resource_bytes")))
        max_total_extracted = int(
            plugin_config.get("max_total_extracted_bytes", self.get_limit("max_total_extracted_bytes"))
        )
        plugin_dir = self.get_plugin_dir(run_dir)

        # Output Directories
        rsrc_out_dir = os.path.join(plugin_dir, "extracted_resources")
        ovl_out_dir = os.path.join(plugin_dir, "extracted_overlay")

        total_extracted_bytes = 0

        # Cached read: the file is loaded once per run and shared across
        # byte-based analyzers.
        try:
            file_bytes = target_file.read_bytes()
        except Exception as e:
            logger.error(f"Failed to read target file: {e}")
            return

        summary = {"resources": [], "overlay": []}
        complete = {"raw_resources": []}
        overlay_data = None
        overlay_offset = None

        def budget_extract(size: int, label: str) -> bool:
            """Check extraction limits; log and refuse when they would blow."""
            nonlocal total_extracted_bytes
            if size > max_resource_bytes:
                logger.warning(
                    f"Refusing to extract {label}: {size} bytes exceeds max_resource_bytes ({max_resource_bytes})."
                )
                return False
            if total_extracted_bytes + size > max_total_extracted:
                logger.warning(
                    f"Refusing to extract {label}: total extracted bytes "
                    f"would exceed max_total_extracted_bytes ({max_total_extracted})."
                )
                return False
            return True

        # ==========================================
        # PE FILE PARSING (Resources & Overlay)
        # ==========================================
        if target_file.format == "pe":
            try:
                pe = pefile.PE(data=file_bytes)

                # PE Resources
                if hasattr(pe, "DIRECTORY_ENTRY_RESOURCE"):
                    # Map standard PE resource types
                    rt_types = {
                        1: "RT_CURSOR",
                        2: "RT_BITMAP",
                        3: "RT_ICON",
                        4: "RT_MENU",
                        5: "RT_DIALOG",
                        6: "RT_STRING",
                        9: "RT_ACCELERATOR",
                        10: "RT_RCDATA",
                        16: "RT_VERSION",
                        24: "RT_MANIFEST",
                    }

                    # Hoisted out of the loop: mapping the image once is O(n).
                    image = pe.get_memory_mapped_image()

                    for resource_type in pe.DIRECTORY_ENTRY_RESOURCE.entries:
                        # Identify the resource type (e.g., RT_RCDATA)
                        type_id = getattr(resource_type.struct, "Id", None)
                        if type_id:
                            res_type_str = rt_types.get(type_id, f"CUSTOM_TYPE_{type_id}")
                        else:
                            res_type_str = str(resource_type.name)

                        for resource_id in resource_type.directory.entries:
                            # Guard malformed nodes in the resource tree
                            if not hasattr(resource_id, "directory"):
                                continue
                            for resource_lang in resource_id.directory.entries:
                                if not hasattr(resource_lang, "data"):
                                    continue

                                offset = resource_lang.data.struct.OffsetToData
                                size = resource_lang.data.struct.Size
                                res_data = image[offset : offset + size]

                                if not res_data:
                                    continue

                                entropy = self._calc_entropy(res_data)
                                sha256 = hashlib.sha256(res_data).hexdigest()
                                magic_type = self._get_magic_type(res_data)
                                lang_id = getattr(resource_lang.struct, "Id", None) or 0
                                res_id = resource_id.struct.Id if resource_id.struct.Id else str(resource_id.name)
                                res_name = str(resource_id.name) if resource_id.name else None

                                # High fidelity risk check
                                is_risk = entropy > 7.0 or magic_type != "Unknown Data"

                                # Extract to disk if configured (with size limits)
                                extracted_path = None
                                may_extract = extract_rsrc and is_risk
                                label = f"resource {res_type_str}/{res_id}"
                                if may_extract and budget_extract(size, label):
                                    os.makedirs(rsrc_out_dir, exist_ok=True)
                                    file_name = self._resource_filename(res_type_str, str(res_id), lang_id)
                                    extracted_path = os.path.join(rsrc_out_dir, file_name)
                                    with open(extracted_path, "wb") as out_f:
                                        out_f.write(res_data)
                                    total_extracted_bytes += size
                                    # Reports carry run-dir-relative paths only.
                                    extracted_path = os.path.relpath(extracted_path, start=run_dir)

                                summary["resources"].append(
                                    {
                                        "id": res_id,
                                        "name": res_name,
                                        "language": lang_id,
                                        "resource_type": res_type_str,
                                        "size": size,
                                        "offset": offset,
                                        "file_type": magic_type,
                                        "entropy": entropy,
                                        "hash_sha256": sha256,
                                        "is_risk": is_risk,
                                        "extracted_to": extracted_path,
                                    }
                                )
                                complete["raw_resources"].append(
                                    {
                                        "type": res_type_str,
                                        "id": res_id,
                                        "language": lang_id,
                                        "offset": offset,
                                        "size": size,
                                        "sha256": sha256,
                                        "entropy": entropy,
                                        "file_type": magic_type,
                                    }
                                )

                # PE Overlay
                overlay_data = pe.get_overlay()
                overlay_offset = pe.get_overlay_data_start_offset()

            except Exception as e:
                logger.error(f"PEFile failed during resource/overlay parsing: {e}")
                overlay_data = None

        # ==========================================
        # ELF FILE PARSING (Overlay Only)
        # ==========================================
        elif target_file.format == "elf":
            try:
                elf = lief.ELF.parse(file_bytes)
                if elf is None:
                    logger.error("LIEF failed to parse the ELF file.")
                else:
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
                "Windows Executable (PE)": rb"MZ.{0,1024}?This program cannot be run in DOS mode",
                "Linux Executable (ELF)": rb"\x7FELF",
                "ZIP Archive": rb"PK\x03\x04",
                "RAR Archive": rb"Rar!\x1A\x07",
                "7z Archive": rb"7z\xBC\xAF\x27\x1C",
            }

            detected_artifacts = []
            for art_type, magic_regex in filetype_signatures.items():
                # finditer quickly sweeps the memory buffer for signatures
                for match in re.finditer(magic_regex, overlay_data, re.DOTALL | re.IGNORECASE):
                    relative_offset = match.start()
                    detected_artifacts.append(
                        {
                            "type": art_type,
                            "offset_within_overlay": relative_offset,
                            "absolute_offset": overlay_offset + relative_offset,
                        }
                    )
            # Deterministic ordering for byte-identical reports.
            detected_artifacts.sort(key=lambda a: (a["absolute_offset"], a["type"]))

            # Extract to disk if configured (with size limits)
            extracted_ovl_path = None
            if extract_ovl and budget_extract(len(overlay_data), "overlay"):
                os.makedirs(ovl_out_dir, exist_ok=True)
                extracted_ovl_path = os.path.join(ovl_out_dir, "extracted_overlay.bin")
                with open(extracted_ovl_path, "wb") as out_f:
                    out_f.write(overlay_data)
                total_extracted_bytes += len(overlay_data)
                extracted_ovl_path = os.path.relpath(extracted_ovl_path, start=run_dir)

            summary["overlay"].append(
                {
                    "size": len(overlay_data),
                    "absolute_offset": overlay_offset,
                    "entropy": ovl_entropy,
                    "hash_sha256": ovl_sha256,
                    "is_risk": True,  # Any overlay presence is generally considered an anomaly/risk
                    "carved_artifacts": detected_artifacts,
                    "extracted_to": extracted_ovl_path,
                }
            )

        # Deterministic ordering of resource entries.
        summary["resources"].sort(
            key=lambda r: (str(r["resource_type"]), str(r["id"]), str(r["language"]), r["offset"])
        )
        complete["raw_resources"].sort(key=lambda r: (str(r["type"]), str(r["id"]), str(r["language"]), r["offset"]))

        # --- SAVE RESULTS ---
        # The raw contract: always write the raw file, and the summary must
        # always reference it (relative to the run dir).
        raw_rel_path = self.save_raw(run_dir, "resource_overlay_raw_output.json", complete)
        summary["raw_output_path"] = raw_rel_path

        clean_summary = {k: v for k, v in summary.items() if v}

        if summary["resources"] or summary["overlay"]:
            target_file.add_result(self.plugin_id, summary_data=clean_summary)
            logger.info("Successfully analyzed Resources and Overlays.")
        else:
            target_file.add_result(
                self.plugin_id,
                summary_data={
                    "status": "no_resources_or_overlay",
                    "raw_output_path": raw_rel_path,
                },
            )
            logger.info("No significant resources or overlays found.")
