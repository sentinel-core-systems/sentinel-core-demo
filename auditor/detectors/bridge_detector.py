"""
Bridge Detector - Auditor Web3 Suite.
Specialized logic engine for Cross-Chain Bridge security analysis.
"""

import subprocess
import json
import os
import logging
import shutil
from typing import List, Optional
from pathlib import Path

from auditor.detectors.plugin_base import DetectorPlugin, PluginMetadata
from auditor.core.engine import Finding

logger = logging.getLogger(__name__)


class BridgeDetector(DetectorPlugin):
    """
    Connects Auditor Core to specialized 'bridge_logic.yaml' rules.
    Designed to detect complex logical flaws in cross-chain protocols
    using static analysis with ReDoS protection.
    """

    def __init__(self):
        super().__init__()
        self.name = "BridgeDetector"

    @property
    def metadata(self) -> PluginMetadata:
        """Required plugin metadata for the Auditor core."""
        return PluginMetadata(
            name="BridgeDetector",
            version="1.1.2",
            vendor="DataWizual Lab - Auditor Core",
            description="Specialized logic scanner for Web3 Bridges with ReDoS and DoS protection.",
        )

    def scan(
        self,
        project_path: str,
        files: Optional[List[str]] = None,
        exclude: Optional[List[str]] = None,
    ) -> List[Finding]:
        """
        Executes logic-based scanning across the entire project directory.
        Arguments follow the base class signature (target_path, exclude).
        """
        findings = []

        # 1. Environment Verification
        semgrep_bin = shutil.which("semgrep")
        if not semgrep_bin:
            logger.warning(
                "BridgeDetector: Semgrep binary not found in PATH. Skipping logic audit."
            )
            return []

        # 2. Ruleset Resolution (Project-specific 'Mercedes' feature)
        # Search for rules relative to the plugin location
        plugin_root = Path(__file__).resolve().parent.parent
        rules_path = plugin_root / "rules" / "bridge_logic.yaml"

        if not rules_path.exists():
            logger.warning(f"BridgeDetector: Custom ruleset '{rules_path}' missing.")
            return []

        try:
            # 3. Path Normalization
            target_abs = Path(project_path).resolve()

            # Command construction (shell=False for RCE prevention)
            cmd = [
                semgrep_bin,
                "scan",
                "--config",
                str(rules_path),
                "--json",
                "--quiet",
                "--timeout",
                "25",  # Limit of 25s per file (ReDoS protection)
                "--timeout-threshold",
                "3",  # Skip file after 3 timeout attempts
                "--jobs",
                "2",  # Limit concurrency to preserve CPU
            ]

            if exclude:
                if len(exclude) > 50:
                    logger.warning(
                        "BridgeDetector: Too many excludes, truncating to prevent OS limit error."
                    )
                    exclude = exclude[:50]

            safe_chars = set(
                "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_./-*"
            )
            for skip in exclude:
                skip_str = str(skip)
                if len(skip_str) < 255 and set(skip_str).issubset(safe_chars):
                    cmd.extend(["--exclude", skip_str])
                else:
                    logger.warning(
                        f"BridgeDetector: Skipping unsafe exclude pattern: {skip_str!r}"
                    )

            cmd.append(str(target_abs))

            # 4. Secure Execution with Global Timeout
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                check=False,
                timeout=600,  # 10 minute total scan limit
                encoding="utf-8",
                errors="ignore",
            )

            if not result.stdout or not result.stdout.strip():
                return []

            if result.stderr and "Error" in result.stderr:
                logger.debug(f"Semgrep stderr diagnostics: {result.stderr}")

            data = json.loads(result.stdout)

            # Mapping Semgrep findings to Auditor unified model
            for res in data.get("results", []):
                raw_path = res.get("path", "")

                # Canonicalize paths for Baseline engine compatibility
                try:
                    clean_path = os.path.relpath(raw_path, str(target_abs))
                except ValueError:
                    clean_path = raw_path

                raw_sev = res.get("extra", {}).get("severity", "HIGH").upper()
                severity_map = {
                    "ERROR": "CRITICAL",
                    "WARNING": "HIGH",
                    "INFO": "MEDIUM",
                }
                mapped_sev = severity_map.get(raw_sev, "HIGH")

                findings.append(
                    Finding(
                        rule_id=f"BRIDGE_{str(res['check_id'].split('.')[-1]).upper()}",
                        severity=mapped_sev,
                        file_path=clean_path.replace("\\", "/"),
                        line=int(res["start"].get("line", 0)),
                        description=str(
                            res["extra"].get(
                                "message",
                                "Potential cross-chain bridge logic violation detected.",
                            )
                        ).strip(),
                        cvss_score=7.0,
                        detector="BridgeDetector",
                        meta={"code_snippet": res["extra"].get("lines", "")},
                    )
                )

        except subprocess.TimeoutExpired:
            logger.error(
                "BridgeDetector: Global scan timeout reached. Check for complex regex in bridge_logic.yaml."
            )
        except json.JSONDecodeError:
            logger.error("BridgeDetector: Failed to parse Semgrep JSON output.")
        except Exception as e:
            logger.error(f"BridgeDetector: Internal execution failure: {e}")

        return findings

    def scan_file(self, file_path: str, content: str) -> List[Finding]:
        """
        Bridge logic requires inter-functional analysis.
        File-level scanning is deferred to the directory-level scan method.
        """
        return []
