import logging

import lief

from src.analyzers.base_analyzer import BaseAnalyzer

logger = logging.getLogger(__name__)


class AuthenticodeAnalyzer(BaseAnalyzer):
    name = "Authenticode Signature Analyzer"
    supported_formats = ["pe"]
    plugin_id = "authenticode"

    # Standalone plugin, runs immediately
    depends = {"all": [], "any": []}

    def _sig_validity(self, sig) -> dict:
        """Best-effort signature validity via LIEF's verifier.

        Verification depends on system trust stores and LIEF build options,
        so failures degrade to 'unknown' instead of crashing the analyzer.
        """
        try:
            check = getattr(sig, "check", None)
            if check is None:
                return {"is_valid": "unknown", "reason": "verifier unavailable"}
            result = check()
            # LIEF returns verification flags; zero flags == fully valid.
            try:
                ok = int(result) == 0
            except (TypeError, ValueError):
                ok = bool(result)
            return {"is_valid": ok, "verification_flags": str(result)}
        except Exception as e:
            return {"is_valid": "unknown", "reason": f"verification failed: {e}"}

    def _sig_timestamp_info(self, sig) -> dict:
        """Inspect LIEF 1.0 signer attributes for countersignature data.

        ``PKCS9_SIGNING_TIME`` is an authenticated signer attribute, not an
        RFC 3161 timestamp. RFC 3161 timestamps are carried by the
        unauthenticated ``MS_COUNTER_SIGN`` attribute; the older PKCS #9
        countersignature is reported as countersigning only.
        """
        info: dict = {"has_timestamp": False, "countersigned": False}
        complete_scan = True
        try:
            signers = list(sig.signers)
        except Exception as e:
            logger.debug(f"Authenticode attribute enumeration unavailable: {e}")
            return {"has_timestamp": None, "countersigned": None}

        for signer in signers:
            try:
                attributes = signer.unauthenticated_attributes
                for attribute in attributes:
                    attribute_type = getattr(attribute, "type", None)
                    type_name = getattr(attribute_type, "name", None) or str(attribute_type).rsplit(".", 1)[-1]
                    if type_name == "MS_COUNTER_SIGN":
                        info["has_timestamp"] = True
                        info["countersigned"] = True
                    elif type_name == "PKCS9_COUNTER_SIGNATURE":
                        info["countersigned"] = True
            except Exception as e:
                complete_scan = False
                logger.debug(f"Authenticode attribute inspection failed: {e}")

        if not complete_scan:
            # A partial scan must not turn unavailable evidence into a negative.
            if not info["has_timestamp"]:
                info["has_timestamp"] = None
            if not info["countersigned"]:
                info["countersigned"] = None
        return info

    def analyze(self, target_file, tool_path, plugin_config, run_dir):
        logger.debug(f"Starting Authenticode analysis on {target_file.filename}")

        try:
            pe = lief.PE.parse(str(target_file.path))
            if not pe:
                logger.error(f"LIEF failed to parse {target_file.filename}.")
                target_file.add_result(
                    self.plugin_id,
                    summary_data={
                        "status": "unavailable",
                        "is_signed": None,
                        "details": "LIEF could not parse the file as PE.",
                    },
                )
                return
        except Exception as e:
            logger.error(f"LIEF threw an exception while parsing: {e}")
            target_file.add_result(
                self.plugin_id,
                summary_data={
                    "status": "unavailable",
                    "is_signed": None,
                    "details": f"LIEF parse error: {e}",
                },
            )
            return

        # CHECK FOR SIGNATURES
        if not pe.has_signatures:
            logger.info("File is NOT digitally signed.")
            target_file.add_result(
                self.plugin_id, summary_data={"is_signed": False, "details": "No Authenticode signature found."}
            )
            return

        # EXTRACT SIGNATURE DATA (per-signature error isolation: one broken
        # signature must not lose the others)
        summary_signers = []
        summary_signatures = []
        complete_certs = []

        for sig_index, sig in enumerate(pe.signatures):
            sig_entry = {
                "index": sig_index,
                "digest_algorithm": str(getattr(sig, "digest_algorithm", "unknown")),
                **self._sig_validity(sig),
                **self._sig_timestamp_info(sig),
                "signers": [],
            }

            try:
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
                            "algorithm": str(cert.signature_algorithm),
                            "valid_from": valid_from,
                            "valid_to": valid_to,
                        }
                        summary_signers.append(signer_summary)
                        sig_entry["signers"].append(signer_summary)
            except Exception as e:
                logger.warning(f"Authenticode: failed to extract signer {sig_index}: {e}")
                sig_entry["signers"] = "extraction failed"

            try:
                # Extract the raw certificate chain for the complete report
                for cert in sig.certificates:
                    complete_certs.append(
                        {
                            "issuer": cert.issuer,
                            "subject": cert.subject,
                            "serial_number": cert.serial_number.hex(),
                            "valid_from": list(cert.valid_from),
                            "valid_to": list(cert.valid_to),
                            "is_ca": cert.is_ca,
                            "signature_algorithm": str(cert.signature_algorithm),
                        }
                    )
            except Exception as e:
                logger.warning(f"Authenticode: failed to extract certificate chain {sig_index}: {e}")

            summary_signatures.append(sig_entry)

        # FORMAT AND SAVE RESULTS
        summary = {
            "is_signed": True,
            "signers": summary_signers,
            "signatures": summary_signatures,
        }

        summary["raw_output_path"] = self.save_raw(
            run_dir, "authenticode_raw_output.json", {"certificate_chain": complete_certs}
        )

        # Save to the TargetFile
        target_file.add_result(self.plugin_id, summary_data=summary)
        logger.info(f"Successfully extracted Authenticode data: {len(summary_signers)} signer(s) found.")
