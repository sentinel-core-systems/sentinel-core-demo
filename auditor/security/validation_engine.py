import os
import math
import logging

# RCA Fix: Added Tuple and Optional for strict type hinting
from typing import Dict, Any, List, Tuple, Optional
from auditor.core.risk_taxonomy import resolve_taxonomy
from auditor.security.taint_engine import TaintEngine

logger = logging.getLogger(__name__)


class ValidationEngine:
    """
    Enterprise-grade Validation & Annotation Engine (v2.2).
    Optimized with Session Caching and Singleton Taint Integration.
    """

    # 1. DETECTOR TRUST MODEL
    DETECTOR_TRUST = {
        "SastScanner": 1.0,
        "SemgrepDetector": 1.0,
        "GitleaksDetector": 0.35,
        "RegexLinter": 0.25,
        "unknown": 0.5,
    }

    # 4. CVSS CEILING
    DETECTOR_CVSS_CAP = {"GitleaksDetector": 7.5, "SastScanner": 9.0, "unknown": 10.0}

    SEVERITY_BASE = {
        "CRITICAL": 9.5,
        "HIGH": 8.0,
        "MEDIUM": 5.0,
        "LOW": 2.5,
        "INFO": 0.0,
    }

    def __init__(self, report_credibility=None):
        self.report_credibility = report_credibility or {
            "status": "STABLE",
            "credibility_score": 100,
        }
        # RCA Fix: Move TaintEngine to init to prevent resource waste in loops
        self.taint_engine = TaintEngine()

    def _detect_project_type(self, path: str, content: str) -> str:
        content_lower = content.lower()
        path_lower = path.lower()

        if "manage.py" in path_lower or "django" in content_lower:
            return "WEB_APP"
        if "springboot" in content_lower or "@restcontroller" in content_lower:
            return "WEB_APP"
        if path_lower.endswith(".py") and "__main__" in content:
            return "CLI_TOOL"
        if "ghidra" in path_lower:
            return "DESKTOP_APP"
        if any(x in path_lower for x in ["dockerfile", ".github", ".tf", "terraform"]):
            return "INFRA"
        return "UNKNOWN"

    def _analyze_dockerfile_user(self, content: str):
        stages = [s for s in content.split("FROM ") if s.strip()]
        if not stages:
            return "NO_STAGES"
        final_stage = stages[-1].lower()
        if "user " in final_stage:
            user = final_stage.split("user ")[1].split("\n")[0].strip()
            return "ROOT_USER" if user in ["root", "0", "0:0"] else "SAFE_USER"
        return "MISSING_USER"

    def validate(self, finding):
        """
        Main validation entry point.
        Calculates final CVSS, reachability and gate relevance.
        """
        updates = {}
        path = getattr(finding, "file_path", "").lower().replace("\\", "/")
        meta = (getattr(finding, "meta", {}) or {}).copy()
        detector = getattr(finding, "detector", "unknown")
        rule_id = getattr(finding, "rule_id", "unknown")

        # --- TAXONOMY ---
        taxonomy = resolve_taxonomy(rule_id) or {}

        # --- TAINT ANALYSIS ---
        # RCA Fix: Use pre-initialized engine instance
        try:
            reachability = self.taint_engine.compute_taint(finding)
        except Exception as e:
            logger.warning(f"Validation: Taint analysis failed: {e}")
            reachability = "UNKNOWN"

        meta["taint_result"] = reachability

        # --- CONTEXT LABEL ---
        if any(x in path for x in ["/test", "test_", "_test", "/spec", "/mock"]):
            current_context = "TEST"
        elif any(x in path for x in ["/demo", "/sample", "/example"]):
            current_context = "DEMO"
        elif any(x in path for x in ["/vendor", "/ext/", "/deps", "/third_party"]):
            current_context = "VENDOR"
        elif any(x in path for x in ["/.github", "/docker", "/terraform", "/ci/"]):
            current_context = "INFRA"
        else:
            current_context = "PRODUCTION"

        current_context = meta.get("context_label", current_context)
        updates["context"] = current_context
        meta["context_label"] = current_context

        # --- CVSS BASE PER RULE ---
        RULE_CVSS_BASE = {
            "dangerous-exec-command": 7.0,
            "grpc-server-insecure-connection": 6.5,
            "missing-unlock-before-return": 5.5,
        }

        original_severity = getattr(finding, "severity", "INFO").upper()
        raw_cvss = RULE_CVSS_BASE.get(
            rule_id, self.SEVERITY_BASE.get(original_severity, 0.0)
        )
        detector_cap = self.DETECTOR_CVSS_CAP.get(detector, 10.0)
        effective_cvss = min(raw_cvss, detector_cap)
        trust_factor = self.DETECTOR_TRUST.get(detector, 0.5)

        meta["trust_factor"] = trust_factor
        updates["cvss_score"] = effective_cvss * trust_factor

        # --- HARD GATE POLICY ---
        is_hard_fail = (
            original_severity == "CRITICAL"
            and current_context == "PRODUCTION"
            and reachability == "REACHABLE"
        )

        updates["gate_relevant"] = is_hard_fail or (
            original_severity in ["CRITICAL", "HIGH"]
            and current_context == "PRODUCTION"
        )
        meta["hard_fail_triggered"] = is_hard_fail

        # --- PROJECT TYPE ---
        content = meta.get("_file_content_for_validation") or meta.get(
            "file_content", ""
        )
        updates["project_type"] = self._detect_project_type(path, content)

        if "dockerfile" in path and "missing-user" in rule_id.lower():
            updates["docker_user_analysis"] = self._analyze_dockerfile_user(content)

        # --- CWE ---
        meta["cwe"] = taxonomy.get("cwe", "CWE-000")

        updates["meta"] = meta
        updates["severity_rationale"] = (
            f"Trust: {trust_factor}, Context: {current_context}, "
            f"HardFail: {'YES' if is_hard_fail else 'NO'}"
        )

        return finding.model_copy(update=updates)

    def confirm_existence(
        self, path: str, line: int, rule_id: str, cache: dict = None
    ) -> Tuple[bool, str]:
        """
        RCA Fix: Implements high-speed finding verification with I/O caching.
        """
        try:
            # Check cache first to avoid Disk I/O (Resource Waste Fix)
            if cache is not None and path in cache:
                content = cache[path]
            else:
                if not os.path.exists(path):
                    return False, "File not found"
                with open(path, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read()
                if cache is not None:
                    cache[path] = content

            lines = content.splitlines()
            if 0 < line <= len(lines):
                evidence = lines[line - 1].strip()
                return True, evidence
            return False, "Line number out of range"
        except Exception as e:
            logger.error(f"Validation: Runtime error for {path}: {e}")
            return False, str(e)
