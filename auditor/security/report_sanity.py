"""
Report Diagnostics Module

Performs deterministic meta-level analysis of a full findings set.

Purpose:
Provide observability into scan characteristics such as
severity distribution, detector concentration, rule clustering,
and score distribution.

IMPORTANT:
This module does NOT modify findings.
This module does NOT influence severity.
This module is purely diagnostic.
"""

from collections import Counter
from typing import List, Dict, Any
import math


class ReportDiagnostics:
    """
    Deterministic scan diagnostics.
    Produces report quality metrics and concentration signals.
    """

    def _compute_score(self, diagnostics: Dict[str, float]) -> int:
        score = 100
        if diagnostics["high_severity_ratio"] > 0.7:
            score -= 20
        if diagnostics["rule_concentration_ratio"] > 0.5:
            score -= 15
        if diagnostics["detector_concentration_ratio"] > 0.75:
            score -= 15
        if diagnostics["file_concentration_ratio"] > 0.6:
            score -= 10
        if diagnostics["high_cvss_ratio"] > 0.6:
            score -= 10
        if diagnostics["severity_entropy"] < 0.8:
            score -= 10
        return max(score, 0)

    def analyze(self, findings: List[Any]) -> Dict[str, Any]:
        if not findings:
            return self._empty_report()

        total = len(findings)
        severity_counter = Counter(f.severity.upper() for f in findings)
        rule_counter = Counter(f.rule_id for f in findings)
        detector_counter = Counter(f.detector for f in findings)
        file_counter = Counter(f.file_path for f in findings)

        high_ratio = (
            severity_counter.get("CRITICAL", 0) + severity_counter.get("HIGH", 0)
        ) / total
        top_rule_ratio = max(rule_counter.values()) / total
        top_detector_ratio = max(detector_counter.values()) / total
        top_file_ratio = max(file_counter.values()) / total
        cvss_values = [getattr(f, "cvss_score", 0.0) or 0.0 for f in findings]
        avg_cvss = sum(cvss_values) / total
        high_cvss_ratio = sum(1 for v in cvss_values if v >= 9.0) / total
        entropy = self._calculate_entropy(severity_counter, total)

        diagnostics = {
            "total_findings": total,
            "severity_distribution": dict(severity_counter),
            "high_severity_ratio": round(high_ratio, 3),
            "rule_concentration_ratio": round(top_rule_ratio, 3),
            "detector_concentration_ratio": round(top_detector_ratio, 3),
            "file_concentration_ratio": round(top_file_ratio, 3),
            "average_cvss": round(avg_cvss, 2),
            "high_cvss_ratio": round(high_cvss_ratio, 3),
            "severity_entropy": round(entropy, 3),
        }

        signals = self._generate_signals(diagnostics)

        score = self._compute_score(diagnostics)
        return {
            "status": self._classify(diagnostics),
            "credibility_score": score,
            "metrics": diagnostics,
            "signals": signals,
        }

    def _calculate_entropy(self, counter: Counter, total: int) -> float:
        entropy = 0.0
        for count in counter.values():
            p = count / total
            entropy -= p * math.log2(p)
        return entropy

    def _generate_signals(self, d: Dict[str, float]) -> List[str]:
        signals = []

        if d["high_severity_ratio"] > 0.7:
            signals.append("High concentration of critical/high findings")

        if d["rule_concentration_ratio"] > 0.5:
            signals.append("Single rule concentration observed")

        if d["detector_concentration_ratio"] > 0.75:
            signals.append("Detector concentration observed")

        if d["file_concentration_ratio"] > 0.6:
            signals.append("File-level finding concentration observed")

        if d["high_cvss_ratio"] > 0.6:
            signals.append("High CVSS score clustering")

        if d["severity_entropy"] < 0.8:
            signals.append("Low severity distribution diversity")

        if d["severity_entropy"] < 0.8 and d["total_findings"] >= 10:
            signals.append("Low severity distribution diversity")
        return signals

    def _classify(self, diagnostics: Dict[str, float]) -> str:
        score = self._compute_score(diagnostics)
        if score >= 80:
            return "STABLE_SCAN_PROFILE"
        elif score >= 50:
            return "CONCENTRATED_SCAN_PROFILE"
        else:
            return "ANOMALOUS_SCAN_PROFILE"

    def _empty_report(self) -> Dict[str, Any]:
        return {
            "status": "EMPTY",
            "credibility_score": 100,
            "metrics": {},
            "signals": [],
        }
