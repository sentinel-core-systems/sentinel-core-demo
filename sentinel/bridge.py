"""
Auditor Bridge - connecting module between Auditor Core and Sentinel Engine.

Two operating modes:
1. Passive  - reads an existing JSON report (fast, for CI)
2. Active   - runs AuditorRunner itself, generates report, reads result

JSON report structure from JSONReporter:
{
    "findings": [
        {
            "id": "...",
            "severity": "HIGH",
            "ai_advisory": {          # ai_recommendations embedded inside finding
                "verdict": "SUPPORTED",
                "reasoning": "...",
                "confidence": 85
            },
            ...
        }
    ]
}
"""

import os
import json
import glob
import logging
from pathlib import Path
from typing import List, Dict, Optional

logger = logging.getLogger(__name__)


class AuditorBridge:
    """
    Bridge between Auditor Core and Sentinel.
    Sentinel does not analyze - it only enforces the Auditor decision.
    """

    SEVERITY_MAP = {
        "CRITICAL": "BLOCK",
        "HIGH":     "BLOCK",
        "MEDIUM":   "WARN",
        "LOW":      "WARN",
        "INFO":     "INFO",
    }

    def __init__(self, report_path: Optional[str] = None, auto_run: bool = False,
                 auditor_config: Optional[dict] = None, license_key: Optional[str] = None):
        """
        Args:
            report_path:    Explicit path to JSON report. If None - finds the latest.
            auto_run:       If True and no report found - runs AuditorRunner.
            auditor_config: Config for AuditorRunner (required if auto_run=True).
            license_key:    License key for AuditorRunner.
        """
        self.auto_run = auto_run
        self.auditor_config = auditor_config or {}
        _key = license_key or os.getenv("SENTINEL_LICENSE_KEY") or os.getenv("AUDITOR_LICENSE_KEY")
        # Fall back to TRIAL if no license configured
        self.license_key = _key if _key else "TRIAL"
        self.report_path = report_path or self._find_latest_report()

    def _find_latest_report(self) -> Optional[str]:
        """Finds the latest Auditor Core JSON report."""
        search_patterns = [
            "reports/report_*.json",
            "auditor/reports/report_*.json",
        ]
        for pattern in search_patterns:
            matches = sorted(glob.glob(pattern), reverse=True)
            if matches:
                logger.info(f"🔗 Bridge: Found Auditor report: {matches[0]}")
                return matches[0]
        return None

    def is_available(self) -> bool:
        """Checks report availability."""
        return bool(self.report_path and os.path.exists(self.report_path))

    def ensure_report(self, target_path: str = ".") -> bool:
        """
        Ensures a current report is available.
        If auto_run=True and no report exists - runs AuditorRunner.
        """
        if self.is_available():
            return True

        if not self.auto_run:
            logger.debug("Bridge: No report found, auto_run disabled.")
            return False

        logger.info("🔗 Bridge: No report found. Running Auditor Core...")
        try:
            from auditor.runner import AuditorRunner
            runner = AuditorRunner(self.auditor_config, self.license_key)
            report = runner.run(target_path)
            if report:
                self.report_path = report
                return True
        except Exception as e:
            logger.error(f"Bridge: AuditorRunner failed: {e}")

        return False

    def load_violations(self) -> List[Dict]:
        """
        Loads SUPPORTED findings from the report and converts them to Sentinel violations.

        JSONReporter stores AI data inside each finding in the ai_advisory field:
        finding["ai_advisory"]["verdict"] == "SUPPORTED"
        """
        if not self.is_available():
            logger.debug("Bridge: Report not available.")
            return []

        try:
            with open(self.report_path, "r", encoding="utf-8") as f:
                report = json.load(f)
        except Exception as e:
            logger.error(f"Bridge: Failed to read report: {e}")
            return []

        violations = []
        findings = report.get("findings", [])

        for finding in findings:
            # AI data is embedded inside finding in the ai_advisory field
            ai_data = finding.get("ai_advisory", {})
            verdict = ai_data.get("verdict", "")

            # Take only AI-verified real threats
            if verdict != "SUPPORTED":
                continue

            severity_raw = finding.get("severity", "MEDIUM").upper()
            sentinel_sev = self.SEVERITY_MAP.get(severity_raw, "WARN")

            file_path = finding.get("file_path", "unknown")
            line = finding.get("line", 0)
            description = finding.get("description", "No description")
            rule_id = finding.get("rule_id", "AUDITOR")
            reasoning = ai_data.get("reasoning", ai_data.get("advice", ""))
            confidence = ai_data.get("confidence", 0)

            violations.append({
                "rule_id":       f"AUDITOR-{rule_id}",
                "location":      f"{file_path}:{line}",
                "message":       f"[{sentinel_sev}] AUDITOR-{rule_id}: {description}",
                "severity":      sentinel_sev,
                "cvss_score":    float(finding.get("cvss", 7.5)),
                "cwe":           finding.get("cwe", "CWE-Generic"),
                "compliance":    "ISO 27001 A.14.2.1 / SOC 2 CC8.1",
                "is_overridden": False,
                "justification": None,
                "remediation":   reasoning or "Remediate per Auditor Core recommendation.",
                "ai_insight":    (
                    f"Auditor Core: SUPPORTED "
                    f"(confidence: {confidence}%). {reasoning}"
                ),
                "_source":       "auditor_bridge",
                "_verdict":      verdict,
            })

        logger.info(
            f"🔗 Bridge: {len(violations)} SUPPORTED findings loaded "
            f"from {Path(self.report_path).name}"
        )
        return violations