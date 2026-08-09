import logging
import lief
import json
import os
from src.analyzers.base_analyzer import BaseAnalyzer

logger = logging.getLogger(__name__)

class AuthenticodeAnalyzer(BaseAnalyzer):
    name = "Authenticode Signature Analyzer"
    supported_formats = ['pe']
    plugin_id = "authenticode"
    
    # Standalone plugin, runs immediately
    depends = {"all": [], "any": []}

    def analyze(self, target_file, tool_path, plugin_config, run_dir):
        logger.debug(f"Starting Authenticode analysis on {target_file.filename}")
        
        try:
            pe = lief.PE.parse(str(target_file.path))
            if not pe:
                logger.error(f"LIEF failed to parse {target_file.filename}.")
                return
        except Exception as e:
            logger.error(f"LIEF threw an exception while parsing: {e}")
            return

        # CHECK FOR SIGNATURES
        if not pe.has_signatures:
            logger.info("File is NOT digitally signed.")
            target_file.add_result(
                self.plugin_id,
                summary_data={"is_signed": False, "details": "No Authenticode signature found."}
            )
            return

        # EXTRACT SIGNATURE DATA
        summary_signers = []
        complete_certs = []

        for sig in pe.signatures:
            # Extract summary info from the signers
            for signer in sig.signers:
                
                # LIEF returns certificates as objects. extract the details.
                cert = signer.cert
                if cert:
                    # Format standard X.509 datetimes
                    valid_from = f"{cert.valid_from[0]}-{cert.valid_from[1]:02d}-{cert.valid_from[2]:02d}"
                    valid_to = f"{cert.valid_to[0]}-{cert.valid_to[1]:02d}-{cert.valid_to[2]:02d}"
                    
                    signer_summary = {
                        "issuer": cert.issuer,
                        "subject": cert.subject,
                        "serial_number": cert.serial_number.hex(),
                        "algorithm": cert.signature_algorithm,
                        "valid_from": valid_from,
                        "valid_to": valid_to
                    }
                    summary_signers.append(signer_summary)

            # Extract the raw certificate chain for the complete report
            for cert in sig.certificates:
                complete_certs.append({
                    "issuer": cert.issuer,
                    "subject": cert.subject,
                    "serial_number": cert.serial_number.hex(),
                    "valid_from": list(cert.valid_from),
                    "valid_to": list(cert.valid_to),
                    "is_ca": cert.is_ca,
                    "signature_algorithm": cert.signature_algorithm
                })

        # FORMAT AND SAVE RESULTS
        summary = {
            "is_signed": True,
            "signers": summary_signers
        }

        plugin_dir = self.get_plugin_dir(run_dir)
        raw_output_path = os.path.join(plugin_dir, "authenticode_raw_output.json")
        with open(raw_output_path, "w") as f:
            complete_raw = {"certificate_chain": complete_certs}
            json.dump(complete_raw, f, indent=4)
        summary["raw_output_path"] = raw_output_path

        # Save to the TargetFile
        target_file.add_result(
            self.plugin_id, 
            summary_data=summary
        )
        logger.info(f"Successfully extracted Authenticode data: {len(summary_signers)} signer(s) found.")