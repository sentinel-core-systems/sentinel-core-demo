"""
JSON Reporter - Auditor Enterprise Suite.
High-fidelity reporting engine with streaming-ready structure and integrity hashing.
"""

import json
import logging
import hashlib
from datetime import datetime, UTC
from typing import List, Dict, Optional
from pathlib import Path

from .base_reporter import BaseReporter
from auditor.core.engine import Finding
from auditor.core.policy import Decision

logger = logging.getLogger(__name__)


class JSONReporter(BaseReporter):
    """
    Standardized JSON exporter for CI/CD integration.
    Features Path Traversal protection and cryptographic integrity verification.
    """

    def generate(
        self,
        findings: List[Finding],
        decision: Decision,
        output_path: str,
        project_name: str = "Auditor Core V2",
        ai_recommendations: Optional[List[Dict]] = None,
    ) -> None:
        # RCA Item 15: Baseline input validation
        if not self._validate_inputs(findings, decision):
            logger.error(
                "JSON Reporter: Generation aborted due to corrupted input state."
            )
            return

        # RCA Fix Issue 9: Enforce hardened output path
        full_path = self._get_safe_path(output_path, project_name, "json")

        try:
            findings_list = []
            findings_raw_content = ""

            ai_map = {}
            if ai_recommendations:
                import ast

                def _parse_advice(advice):
                    """Unpacks advice into a dict if it is a string."""
                    if isinstance(advice, dict):
                        return advice
                    if isinstance(advice, str):
                        try:
                            parsed = ast.literal_eval(advice)
                            if isinstance(parsed, dict):
                                return parsed
                        except Exception:
                            pass
                    return {"advice": str(advice), "type": "advisory"}

                # If input is a dict {uuid: advice}
                if isinstance(ai_recommendations, dict):
                    for fid, advice in ai_recommendations.items():
                        parsed = _parse_advice(advice)
                        ai_map[str(fid)] = parsed
                # If input is a list [{"finding_id": "...", "advice": "..."}]
                elif isinstance(ai_recommendations, list):
                    for r in ai_recommendations:
                        if isinstance(r, dict):
                            fid = str(r.get("finding_id") or r.get("id", ""))
                            advice = r.get("advice") or r
                            if fid:
                                ai_map[fid] = _parse_advice(advice)

            for f in findings:
                finding_dict = {
                    "id": str(f.id),
                    "rule_id": str(f.rule_id),
                    "severity": str(f.severity).upper(),
                    "confidence": str(f.confidence).upper(),
                    "cwe": getattr(f, "cwe", "CWE-UNKNOWN"),
                    "risk_category": getattr(f, "risk_category", "Unclassified"),
                    "impact": getattr(f, "impact", "Unclassified Risk"),
                    "is_automated_advisory": getattr(f, "semantic_adjustment", False),
                    "disclaimer": (
                        "Automated advisory based on validation matrix. Manual review recommended."
                        if getattr(f, "semantic_adjustment", False)
                        else None
                    ),
                    "file_path": str(f.file_path),
                    "line": f.line,
                    "column": f.column,
                    "description": str(f.description),
                    "cvss": float(getattr(f, "cvss_score", 0.0)),
                    "detector": getattr(f, "detector", "unknown"),
                    "evidence_strength": getattr(f, "evidence_strength", "standard"),
                    "validation_state": getattr(f, "validation_state", "RAW"),
                    "meta": f.meta,
                }
                fid = str(f.id)
                if fid in ai_map:
                    finding_dict["ai_advisory"] = ai_map[fid]
                findings_list.append(finding_dict)

                findings_raw_content += (
                    f"{f.rule_id}{f.file_path}{f.line}"
                    f"{f.severity}{finding_dict['cwe']}{f.description}"
                )

            # Cryptographic integrity hash
            integrity_hash = hashlib.sha256(findings_raw_content.encode()).hexdigest()

            # ---------------------------
            # Credibility Evaluation (From ReportSanity/Decision)
            # ---------------------------
            credibility_score = getattr(decision, "credibility_score", 100)
            credibility_status = getattr(decision, "credibility_status", "UNKNOWN")

            # ---------------------------
            # Executive Risk Evaluation (Consistent with HTML Reporter)
            # ---------------------------
            stats = decision.summary
            critical_count = stats.get("CRITICAL", 0)
            high_count = stats.get("HIGH", 0)

            if critical_count > 0:
                overall_risk = "CRITICAL"
                risk_desc = (
                    "Immediate remediation required: Critical vulnerabilities detected."
                )
            elif high_count > 0:
                overall_risk = "HIGH"
                risk_desc = "High risk: Multiple significant security gaps found."
            else:
                overall_risk = "MODERATE" if stats.get("MEDIUM", 0) > 5 else "LOW"
                risk_desc = "Routine maintenance: No critical exposures identified."

            # RCA Item 13: Accurate statistics block
            data = {
                "metadata": {
                    "project": project_name,
                    "timestamp": datetime.now(UTC).isoformat(),
                    "scanner": "Auditor Core Enterprise",
                    "integrity_hash": integrity_hash,
                    "total_reported": sum(stats.values()),
                    "reported_count": len(findings_list),
                    "overall_risk": overall_risk,
                    "risk_summary": risk_desc,
                    "credibility_score": credibility_score,
                    "credibility_status": credibility_status,
                },
                "summary": {
                    "decision": decision.action.value.upper(),
                    "rationale": decision.rationale,
                    "stats": stats,
                },
                "findings": findings_list,
            }

            # RCA Fix Issue 3: Pre-write quota enforcement
            json_string = json.dumps(data, indent=4, ensure_ascii=False)
            self._check_quota(len(json_string.encode("utf-8")))

            with open(full_path, "w", encoding="utf-8") as f:
                f.write(json_string)

            logger.info(
                f"JSON Reporter: Success. Standardized report saved at: {full_path}"
            )

        except Exception as e:
            logger.error(f"JSON Reporter: Critical failure: {e}")
            raise