"""
Gitleaks Detector - Auditor Secrets Suite.
High-performance entropy-based secret detection engine.
"""

import subprocess
import json
import os
import tempfile
import logging
import shutil
import fnmatch
from typing import List, Optional
from pathlib import Path

from auditor.detectors.plugin_base import DetectorPlugin, PluginMetadata
from auditor.core.engine import Finding

logger = logging.getLogger(__name__)


class GitleaksDetector(DetectorPlugin):
    """
    Secrets detector utilizing the Gitleaks engine.
    Optimized for no-git environments and large-scale project audits.
    """

    def __init__(self):
        super().__init__()
        self.gitleaks_bin = shutil.which("gitleaks")

    @property
    def metadata(self) -> PluginMetadata:
        """Required plugin metadata for core integration."""
        return PluginMetadata(
            name="GitleaksDetector",
            version="1.2.0",
            vendor="DataWizual Lab - Auditor Core",
            description="Entropy-aware secret detection with secure exclusion support.",
        )

    def scan(
        self,
        project_path: str,
        files: Optional[List[str]] = None,
        exclude: Optional[List[str]] = None,
    ) -> List[Finding]:
        """
        Executes Gitleaks detection on a directory.
        RCA Item 11: Explicitly returns List[Finding] for stable orchestration.
        """
        all_findings: List[Finding] = []

        if not self.gitleaks_bin:
            logger.warning("Gitleaks binary not found in system PATH.")
            return []

        logger.info(f"Secrets: Initiating Gitleaks scan for: {project_path}")

        # Secure temporary report path using process ID to avoid collisions
        _tmp_fd, report_path = tempfile.mkstemp(suffix=".json", prefix="gitleaks_")
        os.close(_tmp_fd)

        cmd = [
            self.gitleaks_bin,
            "detect",
            "--source",
            project_path,
            "--report-path",
            report_path,
            "--no-git",
            "--exit-code",
            "0",
        ]

        try:
            if os.path.exists(report_path):
                os.remove(report_path)

            # Subprocess execution with strict timeout
            result = subprocess.run(
                cmd, capture_output=True, text=True, check=False, timeout=300
            )

            # Check if report exists and contains data
            if not os.path.exists(report_path) or os.path.getsize(report_path) == 0:
                logger.debug("Gitleaks: Scan completed, no secrets detected.")
                return []

            # Hardening: Secure JSON parsing for report consumption
            try:
                with open(report_path, "r", encoding="utf-8") as f:
                    findings_data = json.load(f)

                if not isinstance(findings_data, list):
                    logger.error(
                        "Gitleaks: Malformed report format (Expected JSON List)."
                    )
                    return []

            except (json.JSONDecodeError, Exception) as e:
                logger.error(f"Gitleaks: Failed to parse report JSON: {e}")
                return []

            logger.info(f"Gitleaks: Processing {len(findings_data)} raw findings.")

            # Map raw JSON leaks to Auditor Finding objects
            for leak in findings_data:
                try:
                    raw_file = leak.get("File", "")

                    # Filtering against exclusion list
                    if exclude and any(
                        self._fnmatch_check(raw_file, pattern) for pattern in exclude
                    ):
                        continue

                    # Canonicalize relative path for the report
                    try:
                        rel_path = os.path.relpath(raw_file, project_path).replace(
                            "\\", "/"
                        )
                    except Exception:
                        rel_path = raw_file

                    rule_id_str = str(leak.get("RuleID", "hardcoded-secret")).lower()
                    if any(
                        x in rule_id_str for x in ["aws", "gcp", "azure", "private-key"]
                    ):
                        sev, cvss = "CRITICAL", 9.5
                    else:
                        sev, cvss = "HIGH", 7.5
                    # Hardening: Explicit type casting and detector attribution
                    fnd = Finding(
                        rule_id=str(leak.get("RuleID", "hardcoded-secret")),
                        severity=sev,
                        file_path=rel_path,
                        line=int(leak.get("StartLine", 0)),
                        column=int(leak.get("StartColumn", 0)),
                        description=f"SECRET EXPOSURE: {leak.get('Description', 'Sensitive Key')} identified.",
                        detector="GitleaksDetector",
                        cvss_score=cvss,
                        meta={
                            "offending_line": leak.get("Line", ""),
                            "commit": leak.get("Commit", "N/A"),
                            "fingerprint": leak.get("Fingerprint", ""),
                        },
                    )
                    all_findings.append(fnd)
                except (ValueError, TypeError, Exception) as e:
                    logger.debug(f"Gitleaks: Skipping malformed entry: {e}")
                    continue

        except Exception as e:
            logger.error(f"Gitleaks: Execution error: {e}")
        finally:
            # Cleanup: Always remove the temporary JSON report
            if os.path.exists(report_path):
                try:
                    os.remove(report_path)
                except Exception:
                    pass

        return all_findings

    def _fnmatch_check(self, file_path: str, pattern: str) -> bool:
        """Internal helper for glob pattern matching during filtration."""
        return fnmatch.fnmatch(file_path, pattern) or any(
            fnmatch.fnmatch(part, pattern) for part in Path(file_path).parts
        )

    def scan_file(self, file_path: str, content: str) -> List[Finding]:
        """Gitleaks is batch-optimized; individual file scanning is handled via directory scan."""
        return []
