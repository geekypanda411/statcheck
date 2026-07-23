import logging
import pefile
import tlsh
import ppdeep
from src.analyzers.base_analyzer import BaseAnalyzer

logger = logging.getLogger(__name__)

class FuzzyHashAnalyzer(BaseAnalyzer):
    name = "Fuzzy Hash Analyzer"
    # SSDeep and TLSH work on any file type. ImpHash handled inside the logic.
    supported_formats = ['all']
    plugin_id = "fuzzyhasher"
    priority = 10  

    def analyze(self, target_file, tool_path, plugin_config):
        logger.debug(f"Starting fuzzy hashing on {target_file.filename}")
        
        results = {}
        
        # Read the file data into memory once to speed up hashing
        try:
            with open(target_file.path, "rb") as f:
                file_data = f.read()
        except Exception as e:
            logger.error(f"Failed to read file {target_file.filename} for hashing: {e}")
            return

        try:
            ssdeep_hash = ppdeep.hash(file_data)
            if ssdeep_hash:
                results["ssdeep"] = ssdeep_hash
                logger.debug("Successfully calculated SSDeep.")
        except Exception as e:
            logger.warning(f"Failed to calculate SSDeep: {e}")

        try:
            # TLSH requires file size > 50 bytes and have enough entropy else returns TNULL or empty
            tlsh_hash = tlsh.hash(file_data)
            if tlsh_hash and tlsh_hash != "TNULL":
                results["tlsh"] = tlsh_hash
                logger.debug("Successfully calculated TLSH.")
            else:
                logger.debug("File too small or simple for TLSH. Skipping.")
        except Exception as e:
            logger.warning(f"Failed to calculate TLSH: {e}")

        try:
            # pefile will automatically throw a PEFormatError if we feed it an ELF or macho file
            pe = pefile.PE(target_file.path)
            imphash = pe.get_imphash()
            if imphash:
                results["imphash"] = imphash
                logger.debug("Successfully calculated ImpHash.")
        except pefile.PEFormatError:
            # This is expected behavior for Linux/Mac binaries
            logger.debug(f"Skipped ImpHash: '{target_file.filename}' is not a valid PE file.")
        except Exception as e:
            logger.warning(f"Failed to calculate ImpHash: {e}")

        if results:
            target_file.add_result(self.plugin_id, summary_data=results)
            logger.info("Successfully added advanced hashes to report summary.")
        else:
            logger.warning("No advanced hashes could be generated for this file.")