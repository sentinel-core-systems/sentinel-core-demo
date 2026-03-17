import subprocess
import json
import logging
import os
from typing import List, Optional, Iterable
from pathlib import Path
from auditor.detectors.plugin_base import DetectorPlugin, PluginMetadata
from auditor.core.engine import Finding

logger = logging.getLogger(__name__)


class BanditDetector(DetectorPlugin):
    """
    Enterprise Bandit Wrapper.
    Hardened against RCE and DoS. Optimized for high-speed Python source code analysis.
    """

    @property
    def metadata(self) -> PluginMetadata:
        """Required metadata for the Auditor plugin system."""
        return PluginMetadata(
            name="bandit_detector",
            version="1.7.5",
            vendor="DataWizual Lab - Auditor Core",
            description="Security linter for Python source code using Bandit.",
        )

    def __init__(self):
        super().__init__()
        # Set execution timeout to 10 minutes (RCA Item: DoS mitigation)
        self.timeout = 600

    def scan(
        self,
        project_path: str,
        files: Optional[List[str]] = None,
        exclude: Optional[List[str]] = None,
    ) -> List[Finding]:
        findings = []

        try:
            safe_path = str(Path(project_path).resolve())
        except Exception:
            logger.error("Bandit: Critical error during project path resolution.")
            return []

        cmd = ["bandit", "-r", safe_path, "-f", "json", "-q", "--aggregate", "file"]

        # Hard excludes for bandit - always applied
        hard_excludes = ["venv", ".venv", "env", "node_modules", ".git",
                         "__pycache__", "dist", "build"]

        # Use only real directories from config exclude list
        config_dirs = []
        if exclude:
            for ex in exclude:
                clean = ex.rstrip("/*")
                candidate = Path(safe_path) / clean
                if candidate.is_dir():
                    config_dirs.append(str(candidate))

        all_excludes = hard_excludes + config_dirs
        if all_excludes:
            cmd.extend(["-x", ",".join(all_excludes)])

        try:
            process = subprocess.run(
                cmd, capture_output=True, text=True, timeout=self.timeout, check=False
            )

            if not process.stdout.strip():
                return []

            # Parse Bandit JSON output
            data = json.loads(process.stdout)

            for issue in data.get("results", []):
                raw_path = issue.get("filename", "")
                try:
                    abs_path = Path(raw_path).resolve()
                    rel_path = str(abs_path.relative_to(Path(safe_path).resolve()))
                except ValueError:
                    rel_path = raw_path.replace(safe_path, "").lstrip("/\\")

                findings.append(
                    Finding(
                        rule_id=f"BANDIT_{issue.get('test_id')}",
                        severity=issue.get("issue_severity", "LOW").upper(),
                        file_path=rel_path.replace("\\", "/"),
                        line=issue.get("line_number", 0),
                        description=issue.get("issue_text", ""),
                        detector="BanditDetector",
                        meta={"code": issue.get("code", "").strip()},
                    )
                )

        except subprocess.TimeoutExpired:
            logger.error(f"Bandit: Analysis timed out after {self.timeout}s.")
        except json.JSONDecodeError:
            logger.error(
                "Bandit: Failed to parse JSON output. Check Bandit installation."
            )
        except Exception as e:
            logger.error(f"Bandit: Internal execution error: {e}")

        return findings

    def scan_file(self, file_path: str, content: str) -> List[Finding]:
        """
        Bandit is optimized for directory-level batch scanning.
        File-specific scanning is handled by the main scan method.
        """
        return []
