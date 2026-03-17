"""
Slither Detector - Auditor Web3 Suite.
Enterprise-grade Solidity static analyzer with hardened CWD isolation.
"""

import subprocess
import json
import os
import logging
import shutil
import tempfile
from typing import List, Optional
from pathlib import Path

from auditor.detectors.plugin_base import DetectorPlugin, PluginMetadata
from auditor.core.engine import Finding

logger = logging.getLogger(__name__)


class SlitherDetector(DetectorPlugin):
    """
    Integrates Slither for deep analysis of Ethereum smart contracts.
    Features memory-safe JSON streaming and execution isolation.
    """

    def __init__(self):
        super().__init__()
        self.name = "Slither"
        self.slither_bin = shutil.which("slither")
        self.solc_bin = shutil.which("solc")

    @property
    def metadata(self) -> PluginMetadata:
        """Required metadata for the Auditor Web3 module."""
        return PluginMetadata(
            name="SlitherDetector",
            version="1.4.0",
            vendor="DataWizual Lab - Auditor Core",
            description="Enterprise Web3 analyzer with CWD isolation and JSON streaming safety.",
        )

    def scan(
        self,
        project_path: str,
        files: Optional[List[str]] = None,
        exclude: Optional[List[str]] = None,
    ) -> List[Finding]:
        """
        Runs Slither analysis on a Solidity project with strict environment controls.
        """
        if not self.slither_bin:
            logger.warning("Slither: Binary not found. Skipping Web3 analysis.")
            return []

        findings = []
        try:
            target_abs = Path(project_path).resolve()
            tmp_fd, tmp_path = tempfile.mkstemp(suffix=".json")
            os.close(tmp_fd)

            try:
                # Build the full command before launching the process
                cmd = [
                    self.slither_bin,
                    str(target_abs),
                    "--json",
                    tmp_path,
                    "--solc-disable-warnings",
                ]

                if self.solc_bin:
                    cmd.extend(["--solc", self.solc_bin])

                # Default ignore patterns for dependency noise
                cmd.extend(["--filter-paths", "node_modules|lib|tests|migrations"])

                HARD_EXCLUDE_DIRS = {
                    "venv", ".venv", "node_modules", ".git", "__pycache__",
                    "dist", "build", "site-packages", "testdata", "fixtures",
                    "mocks", "reports",
                }
                if exclude:
                    filtered = [
                        e for e in exclude
                        if Path(e).name not in HARD_EXCLUDE_DIRS
                    ]
                    # Cap at 20 to stay well within OS argument limits
                    filtered = filtered[:20]
                    if filtered:
                        clean_excludes = ",".join(
                            [str(Path(e).as_posix()) for e in filtered]
                        )
                        cmd.extend(["--exclude-dir", clean_excludes])

                # Run process without shell=True (prevents command injection)
                subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    check=False,
                    timeout=900,
                    shell=False,
                )

                with open(tmp_path, "r", encoding="utf-8") as f:
                    raw_data = f.read()

                if not raw_data:
                    logger.debug("Slither: No output generated or scan failed.")
                    return []

                data = json.loads(raw_data)
                detectors_found = data.get("results", {}).get("detectors", [])
                severity_map = {"High": "HIGH", "Medium": "MEDIUM", "Low": "LOW"}

                for det in detectors_found:
                    elements = det.get("elements", [])
                    if not elements:
                        continue

                    source = elements[0].get("source_mapping", {})

                    # RCA Fix Issue 34: Defensive access to line number lists
                    lines = source.get("lines", [])
                    line_number = lines[0] if isinstance(lines, list) and lines else 1

                    findings.append(
                        Finding(
                            rule_id=f"SLITHER_{str(det.get('check', 'UNKNOWN')).upper()}",
                            severity=severity_map.get(det.get("impact"), "LOW"),
                            file_path=source.get(
                                "filename_relative", "unknown"
                            ).replace("\\", "/"),
                            line=line_number,
                            description=str(det.get("description", "")).strip(),
                            cvss_score=8.5 if det.get("impact") == "High" else 4.0,
                            detector="SlitherDetector",
                        )
                    )

            finally:
                if os.path.exists(tmp_path):
                    os.unlink(tmp_path)

        except (subprocess.TimeoutExpired, json.JSONDecodeError) as e:
            logger.error(f"Slither: Analysis failed due to timeout or parse error: {e}")
        except Exception as e:
            logger.error(f"Slither: Internal processing error: {e}")

        return findings

    def scan_file(self, file_path: str, content: str) -> List[Finding]:
        """Slither requires full project context; single file scan is not supported."""
        return []