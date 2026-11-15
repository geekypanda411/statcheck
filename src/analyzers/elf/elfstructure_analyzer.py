import logging

import lief

from src.analyzers.base_analyzer import BaseAnalyzer

logger = logging.getLogger(__name__)


class ELFStructureAnalyzer(BaseAnalyzer):
    name = "ELF Structure Analyzer"
    supported_formats = ["elf"]
    plugin_id = "elfstructure"

    depends = {"all": [], "any": []}

    @staticmethod
    def _has_relro(elf) -> bool:
        """True when a GNU_RELRO segment is present."""
        try:
            for segment in elf.segments:
                if "GNU_RELRO" in str(segment.type):
                    return True
        except Exception as e:
            logger.debug(f"RELRO detection failed: {e}")
        return False

    @staticmethod
    def _has_stack_canary(elf) -> bool | None:
        """True when __stack_chk_fail is imported; None when undeterminable."""
        try:
            return any(symbol.name == "__stack_chk_fail" for symbol in elf.dynamic_symbols)
        except Exception as e:
            logger.debug(f"Stack canary detection failed: {e}")
            return None

    def analyze(self, target_file, tool_path, plugin_config, run_dir):
        logger.debug(f"Starting ELF Structure analysis on {target_file.filename}")

        try:
            elf = lief.ELF.parse(str(target_file.path))
            if not elf:
                logger.error(f"LIEF failed to parse {target_file.filename} as an ELF.")
                target_file.add_result(
                    self.plugin_id,
                    summary_data={
                        "status": "unavailable",
                        "reason": "LIEF could not parse the file as ELF.",
                    },
                )
                return
        except Exception as e:
            logger.error(f"LIEF threw an exception while parsing ELF: {e}")
            target_file.add_result(
                self.plugin_id,
                summary_data={
                    "status": "unavailable",
                    "reason": f"LIEF parse error: {e}",
                },
            )
            return

        # Hardening flags; guarded with getattr because LIEF availability of
        # these properties varies across versions.
        is_pie = bool(getattr(elf, "is_pie", False) or False)
        has_nx = getattr(elf, "has_nx", None)
        has_nx = bool(has_nx) if has_nx is not None else None
        has_relro = self._has_relro(elf)
        has_canary = self._has_stack_canary(elf)

        # Imported libraries (defensive: LIEF returns iterators in 1.0).
        try:
            libraries = sorted(str(lib) for lib in elf.libraries)
        except Exception:
            libraries = []

        has_interpreter = bool(elf.has_interpreter)
        header = getattr(elf, "header", None)
        file_type = str(getattr(header, "file_type", "")).split(".")[-1]
        entrypoint = int(getattr(header, "entrypoint", 0) or 0)
        # A dependency-free shared object still is not a statically linked
        # executable. ET_DYN with no entry point represents that common case;
        # static PIE executables retain a nonzero entry point.
        is_shared_object = file_type == "DYN" and not has_interpreter and entrypoint == 0
        is_statically_linked = not has_interpreter and not libraries and not is_shared_object
        if has_interpreter:
            interpreter = elf.interpreter
        elif is_statically_linked:
            interpreter = "None (Statically Linked)"
        else:
            interpreter = "None (No PT_INTERP segment)"

        summary = {
            "flags": {
                "is_stripped": False,
                "is_statically_linked": is_statically_linked,
                "has_rwx_segments": False,
                "has_custom_rpath": False,
            },
            "hardening": {
                "is_pie": is_pie,
                "has_nx": has_nx,
                "has_relro": has_relro,
                "has_stack_canary": has_canary,
            },
            "interpreter": interpreter,
            "anomalies": {},
            "imported_libraries": libraries,
        }

        complete_raw = {"segments": [], "dynamic_libraries": libraries}

        # CHECK FOR STRIPPED SYMBOLS
        try:
            if not elf.has_section(".symtab"):
                summary["flags"]["is_stripped"] = True
        except Exception as e:
            logger.debug(f"symtab check failed: {e}")

        # ANALYZE SEGMENTS (guard None defensively for older LIEF versions)
        rwx_segments = []
        segments = elf.segments
        if segments is not None:
            for segment in segments:
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
                    "type": str(segment.type).split(".")[-1],
                    "virtual_address": hex(segment.virtual_address),
                    "virtual_size": segment.virtual_size,
                    "permissions": perms,
                }

                complete_raw["segments"].append(seg_data)

                if perms == "RWX":
                    summary["flags"]["has_rwx_segments"] = True
                    rwx_segments.append(seg_data)

        if rwx_segments:
            summary["anomalies"]["rwx_segments"] = rwx_segments

        # ANALYZE DYNAMIC ENTRIES (RPATH / RUNPATH); guard None defensively.
        custom_paths = []
        dynamic_entries = elf.dynamic_entries
        if dynamic_entries is not None:
            # We can just iterate directly; if it's empty, the loop safely skips!
            for entry in dynamic_entries:
                # Safely check if the object contains the rpath or runpath properties
                if hasattr(entry, "rpath"):
                    custom_paths.append(f"RPATH: {entry.rpath}")
                elif hasattr(entry, "runpath"):
                    custom_paths.append(f"RUNPATH: {entry.runpath}")

        if custom_paths:
            summary["flags"]["has_custom_rpath"] = True
            summary["anomalies"]["custom_library_paths"] = custom_paths

        summary["raw_output_path"] = self.save_raw(run_dir, "elfstructure_raw_output.json", complete_raw)

        # FORMAT AND SAVE RESULTS
        target_file.add_result(self.plugin_id, summary_data=summary)
        logger.info("Successfully analyzed ELF Structure.")
