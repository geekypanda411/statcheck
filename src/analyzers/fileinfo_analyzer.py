import logging
import hashlib
import math
import pefile
import tlsh
import ppdeep
import mimetypes
from src.analyzers.base_analyzer import BaseAnalyzer

logger = logging.getLogger(__name__)

class BasicInfoAnalyzer(BaseAnalyzer):
    name = "Basic File Information"
    supported_formats = ['all']
    plugin_id = "fileinfo"
    depends = {"all": [], "any": []}

    def calculate_entropy(self, data):
        #Calculates Shannon Entropy of a byte sequence (0.0 to 8.0)
        if not data:
            return 0.0
        entropy = 0
        for x in range(256):
            p_x = float(data.count(x)) / len(data)
            if p_x > 0:
                entropy += - p_x * math.log2(p_x)
        return round(entropy, 4)

    def analyze(self, target_file, tool_path, plugin_config, run_dir):
        logger.debug(f"Extracting basic information for {target_file.filename}")
        
        # Read the file into RAM
        try:
            with open(target_file.path, "rb") as f:
                file_data = f.read()
        except Exception as e:
            logger.error(f"Failed to read file {target_file.filename}: {e}")
            return

        summary = {}

        # 1. Basic Metadata
        summary = {
            "Filename": target_file.filename,
            "Size_Bytes": len(file_data),
            "MIME_Type": mimetypes.guess_type(target_file.path)[0] or "Unknown",
            "Entropy": self.calculate_entropy(file_data),
            "File_MD5": hashlib.md5(file_data).hexdigest(),
            "File_SHA1": hashlib.sha1(file_data).hexdigest(),
            "File_SHA256": hashlib.sha256(file_data).hexdigest(),
            "File_SHA512": hashlib.sha512(file_data).hexdigest()
        }
        
        try:
            ssdeep_hash = ppdeep.hash(file_data)
            if ssdeep_hash: summary["File_ssdeep"] = ssdeep_hash
        except Exception as e:
            logger.warning(f"Failed to calculate SSDeep: {e}")

        try:
            tlsh_hash = tlsh.hash(file_data)
            if tlsh_hash and tlsh_hash != "TNULL": 
                summary["File_tlsh"] = tlsh_hash
        except Exception as e:
            logger.warning(f"Failed to calculate TLSH: {e}")

        try:
            pe = pefile.PE(target_file.path)
            imphash = pe.get_imphash()
            if imphash: summary["File_imphash"] = imphash
        except pefile.PEFormatError:
            pass # Not a PE file, totally fine.
        except Exception as e:
            logger.warning(f"Failed to calculate ImpHash: {e}")

        # SAVE TO TARGET FILE
        target_file.add_result(self.plugin_id, summary_data=summary)
        logger.info("Successfully extracted Basic Information and Hashes.")