import os
import logging
from typing import Iterable, List, Optional, Dict
from pathlib import Path

from auditor.detectors.plugin_base import DetectorPlugin, PluginMetadata
from auditor.core.engine import Finding

logger = logging.getLogger(__name__)


class LicenseScanner(DetectorPlugin):
    """
    Legal compliance checker for restrictive OSS licenses.
    Hardened against Symlink attacks and Information Disclosure.
    """

    @property
    def metadata(self) -> PluginMetadata:
        """Required plugin metadata for the Auditor core system."""
        return PluginMetadata(
            name="LicenseScanner",
            version="1.2.1",
            vendor="DataWizual Lab - Auditor Core",
            description="Secure legal compliance checker with path sanitization and symlink protection.",
        )

    def scan(
        self,
        project_path: str,
        files: Optional[List[str]] = None,
        exclude: Optional[List[str]] = None,
    ) -> List[Finding]:
        """
        Scans for license files and identifies restrictive legal markers.
        RCA Fix: Implements path validation and symlink protection.
        """
        # RCA Fix: Base path validation
        try:
            target_abs = Path(project_path).resolve()
        except Exception:
            logger.error("License Audit: Invalid target path provided.")
            return []

        if not target_abs.exists():
            logger.error("License Audit: Target directory not found on filesystem.")
            return []

        logger.info("Compliance: Starting legal license audit.")
        findings = []

        restricted_patterns = {
            "GPL": "Reciprocal license detected (GPL). May require source code disclosure.",
            "AGPL": "Network-reciprocal license (AGPL). High risk for SaaS delivery models.",
            "SSPL": "Server Side Public License detected. Commercial usage restrictions apply.",
            "MPL": "Weak copyleft license (MPL). Requires separate file maintenance.",
        }

        target_filenames = {
            "LICENSE",
            "COPYING",
            "LICENSE.TXT",
            "LICENSE.MD",
            "COPYRIGHT",
        }

        # Security constant: Prevent DoS via massive license files
        MAX_LICENSE_SIZE = 1 * 1024 * 1024  # 1MB

        for root, dirs, files in os.walk(target_abs):
            if exclude:
                # RCA Fix: Reliable directory filtering via Path logic
                dirs[:] = [d for d in dirs if d not in exclude]

            for file in files:
                if file.upper() in target_filenames:
                    file_path_obj = Path(root) / file

                    # RCA Fix: Symlink Attack Protection (verify file is not a link)
                    if file_path_obj.is_symlink():
                        logger.debug(f"License Audit: Skipping symlink entry: {file}")
                        continue

                    try:
                        # RCA Fix: Size check before file operation
                        if file_path_obj.stat().st_size > MAX_LICENSE_SIZE:
                            continue

                        with open(
                            file_path_obj, "r", encoding="utf-8", errors="ignore"
                        ) as f:
                            # Read initial chunk for marker identification (100KB)
                            content = f.read(102400).upper()

                            # Secure relative path construction
                            rel_file_path = str(
                                file_path_obj.relative_to(target_abs)
                            ).replace("\\", "/")

                            for lit, desc in restricted_patterns.items():
                                if lit in content:
                                    findings.append(
                                        Finding(
                                            rule_id=f"LICENSE_RISK_{lit}",
                                            severity="MEDIUM",
                                            file_path=rel_file_path,
                                            line=1,
                                            description=desc,
                                            cvss_score=0.0,
                                            detector="LicenseScanner",
                                        )
                                    )

                    except Exception:
                        # RCA Fix: Safe logging without path leakage
                        logger.error(
                            "License Scanner: Security exception during file processing."
                        )

        return findings

    def scan_file(self, file_path: str, content: str) -> List[Finding]:
        """Bulk directory scanning is the preferred method for this detector."""
        return []
