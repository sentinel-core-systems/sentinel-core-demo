"""
Semgrep Detector - Auditor Core Professional.
Enterprise-ready Semgrep wrapper with memory-safe streaming and dynamic timeout management.
"""

import subprocess
import json
import logging
import shutil
import os
import tempfile
from typing import Iterable, List, Optional
from pathlib import Path

from auditor.detectors.plugin_base import DetectorPlugin, PluginMetadata
from auditor.core.engine import Finding

logger = logging.getLogger(__name__)


class SemgrepDetector(DetectorPlugin):
    """
    Orchestrates Semgrep analysis using both default and proprietary logic rules.
    Optimized for memory efficiency by using temporary file streaming for large reports.
    """

    def __init__(self):
        super().__init__()
        self.name = "Semgrep"
        self.semgrep_bin = shutil.which("semgrep")
        # RCA Fix Issue 27: Calculate absolute path to local rules relative to detector location
        self.rules_path = (
            Path(__file__).resolve().parent.parent / "rules" / "bridge_logic.yaml"
        )

    @property
    def metadata(self) -> PluginMetadata:
        """Required plugin metadata for the orchestration engine."""
        return PluginMetadata(
            name="SemgrepDetector",
            version="1.4.0",
            vendor="DataWizual Lab - Auditor Core",
            description="Enterprise-ready Semgrep wrapper with memory-safe streaming and dynamic path resolution.",
        )

    def _calculate_dynamic_timeout(self, project_path: Path) -> int:
        """Heuristically determines timeout based on file count to prevent process hangs."""
        try:
            file_count = sum([len(files) for r, d, files in os.walk(project_path)])
            # Range: 5 min to 30 min based on project size
            return max(300, min(60 + (file_count * 2), 1800))
        except Exception:
            return 600

    def scan(
        self,
        project_path: str,
        files: Optional[List[str]] = None,
        exclude: Optional[List[str]] = None,
    ) -> List[Finding]:

        findings = []

        if not self.semgrep_bin:
            logger.warning("Semgrep: Binary not found. Skipping.")
            return []

        try:
            target_abs = Path(project_path).resolve()
        except Exception:
            return []

        timeout = self._calculate_dynamic_timeout(target_abs)

        config_args = []
        if self.rules_path.exists():
            config_args.extend(["--config", str(self.rules_path)])
        else:
            logger.warning(
                "Semgrep: No local rules found. Using 'p/default' (requires network)."
            )
            config_args.extend(["--config", "p/default"])

        with tempfile.NamedTemporaryFile(
            mode="w+", suffix=".json", delete=True
        ) as tmp_report:

            cmd = (
                [self.semgrep_bin, "scan"]
                + config_args
                + ["--json", "--quiet", "--output", tmp_report.name, "--jobs", "2"]
            )

            if exclude:
                if len(exclude) > 50:
                    logger.warning(
                        "Semgrep: Too many excludes, truncating to prevent OS limit error."
                    )
                    exclude = exclude[:50]

                for skip in exclude:
                    safe_chars = set(
                        "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_./-*"
                    )
                    if len(skip) < 255 and set(skip).issubset(safe_chars):
                        cmd.extend(["--exclude", str(Path(skip).as_posix())])

            # -------------------------------------------------
            # RCA Fix: Resolve [Errno 7] Argument list too long
            # -------------------------------------------------
            cmd.append(str(target_abs))

            try:
                subprocess.run(cmd, timeout=timeout, shell=False)

                tmp_report.seek(0)
                content = tmp_report.read()
                if not content:
                    return []

                data = json.loads(content)

                severity_map = {
                    "ERROR": "CRITICAL",
                    "HIGH": "HIGH",
                    "WARNING": "HIGH",
                    "MEDIUM": "MEDIUM",
                    "INFO": "INFO",  # ← keep original severity level
                    "LOW": "LOW",
                }

                for match in data.get("results", []):
                    extra = match.get("extra", {})
                    raw_sev = extra.get("severity", "WARNING").upper()

                    findings.append(
                        Finding(
                            rule_id=str(match.get("check_id")),
                            severity=severity_map.get(raw_sev, "LOW"),
                            file_path=match.get("path", ""),
                            line=int(match.get("start", {}).get("line", 0)),
                            column=int(match.get("start", {}).get("col", 0)),
                            description=str(
                                extra.get("message", "No description provided.")
                            ),
                            cvss_score=0.0,
                            detector="SemgrepDetector",
                        )
                    )

            except Exception as e:
                logger.error(f"Semgrep failure: {e}")

        return findings

    def scan_file(self, file_path: str, content: str) -> List[Finding]:
        """Bulk scanning is the default operational mode for Semgrep."""
        return []
