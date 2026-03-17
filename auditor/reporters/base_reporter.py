"""
Base Reporter - Auditor Reporting Engine.
Standardized interface for all report generators with hardened security controls.
"""

import logging
import re
import os
from abc import ABC, abstractmethod
from typing import List, Any, Optional
from pathlib import Path

# Absolute imports for consistent core mapping
from auditor.core.engine import Finding
from auditor.core.policy import Decision

logger = logging.getLogger(__name__)


class BaseReporter(ABC):
    """
    Abstract base class for all Auditor reporters (JSON, HTML, CSV).
    Includes mandatory security checks for path traversal and resource exhaustion.
    """

    # RCA Fix Issue 3: Maximum report size limit (50MB) to prevent Disk DoS
    MAX_REPORT_SIZE = 50 * 1024 * 1024

    @abstractmethod
    def generate(
        self,
        findings: List[Finding],
        decision: Decision,
        output_path: str,
        project_name: str = "Auditor Core V2",
        ai_recommendations=None,
    ) -> None:
        """Core generation method to be implemented by specific reporters."""
        pass

    def _validate_inputs(self, findings: List[Any], decision: Any) -> bool:
        """
        RCA Item 15: Input sanity-check.
        Ensures the reporting engine receives valid objects from the core.
        """
        if not isinstance(findings, list):
            logger.error("Reporter Error: 'findings' attribute must be a list.")
            return False

        if decision is None:
            logger.error("Reporter Error: Missing 'decision' object.")
            return False

        # Verify mandatory attributes on the Decision object
        if not hasattr(decision, "action") or not hasattr(decision, "summary"):
            logger.error(
                "Reporter Error: Invalid decision format. Action/Summary missing."
            )
            return False

        if len(findings) == 0:
            logger.warning("Reporter: Generating report with 0 findings.")
            # Empty report is valid — allows audit trail even when no issues found

        return True

    def _get_safe_path(
        self, output_dir: str, project_name: str, extension: str
    ) -> Path:
        """
        RCA Fix Issue 1 & 2: Hardened path sanitization for cross-platform compatibility.
        Protects against Windows reserved filenames and Path Traversal attacks.
        """
        # 1. Clean project name of special characters
        safe_name = re.sub(r"[^\w\s-]", "", project_name).strip().replace(" ", "_")

        # RCA Fix Issue 1: Protection against Windows reserved device names
        windows_reserved = {
            "CON",
            "PRN",
            "AUX",
            "NUL",
            "COM1",
            "COM2",
            "COM3",
            "COM4",
            "COM5",
            "COM6",
            "COM7",
            "COM8",
            "COM9",
            "LPT1",
            "LPT2",
            "LPT3",
            "LPT4",
            "LPT5",
            "LPT6",
            "LPT7",
            "LPT8",
            "LPT9",
        }
        if safe_name.upper() in windows_reserved:
            safe_name = f"auditor_{safe_name}"

        if not safe_name:
            safe_name = "unnamed_project"

        # 2. Path construction and validation
        try:
            base_path = Path(output_dir).resolve()
            filename = f"report_{safe_name}.{extension.lstrip('.')}"
            final_path = (base_path / filename).resolve()
        except Exception as e:
            logger.error(f"Reporter: Path generation error: {e}")
            raise ValueError("Invalid output directory or project name configuration.")

        # RCA Fix Issue 2: Reliable Path Traversal detection
        if base_path != final_path and base_path not in final_path.parents:
            logger.critical(
                f"Security Alert: Path Traversal Attempt blocked. Target: {final_path}"
            )
            raise PermissionError(
                "Access Denied: Target path is outside allowed directory."
            )

        # Ensure target directory exists
        final_path.parent.mkdir(parents=True, exist_ok=True)

        return final_path

    def _check_quota(self, data_size: int):
        """
        RCA Fix Issue 3: Enforce report data quota before disk write operations.
        """
        if data_size > self.MAX_REPORT_SIZE:
            logger.error(
                f"Reporter: Size {data_size} exceeds limit {self.MAX_REPORT_SIZE}"
            )
            raise IOError(
                "Report Quota Exceeded: File size too large for current policy."
            )
