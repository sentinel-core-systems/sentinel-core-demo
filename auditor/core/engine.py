import os
import logging
import json
from datetime import datetime, UTC
from typing import List, Dict, Any, Optional
from uuid import UUID, uuid4
from pydantic import BaseModel, Field, field_validator
from pathlib import Path
from auditor.security.validation_engine import ValidationEngine
from auditor.security.taint_engine import analyze_risk_reachability

logger = logging.getLogger(__name__)


class Finding(BaseModel):
    """
    STRICT DATA MODEL (RCA Item 16: Strict Validation)
    Ensures data integrity across all detector outputs.
    """

    id: UUID = Field(default_factory=uuid4)
    rule_id: str = Field(..., min_length=1)
    file_path: str = Field(..., min_length=1)
    line: int = Field(..., ge=0)
    column: Optional[int] = None
    description: str = Field(default="No description provided")
    severity: str
    confidence: str = "MEDIUM"
    semantic_adjustment: bool = False
    detector: str = "unknown"
    cvss_score: float = 0.0
    meta: Dict[str, Any] = Field(default_factory=dict)

    risk_category: str = "UNCLASSIFIED"
    exploitability_score: int = 0
    exploitability_level: str = "PATTERN_ONLY"
    trust_boundary_crossed: bool = False
    privilege_boundary_crossed: bool = False
    remote_reachable: bool = False
    validation_state: str = "UNVALIDATED"

    @field_validator("severity", mode="before")
    @classmethod
    def normalize_severity(cls, v: Any) -> str:
        if v is None:
            return "INFO"
        val = str(v).strip().upper()
        sev_map = {
            "CRIT": "CRITICAL",
            "CRITICAL": "CRITICAL",
            "HIGH": "HIGH",
            "MED": "MEDIUM",
            "MEDIUM": "MEDIUM",
            "LOW": "LOW",
            "INFO": "INFO",
        }
        result = sev_map.get(val)
        if result is None:
            logger.warning(f"Unknown severity value '{v}' normalized to INFO")
            return "INFO"
        return result


class AuditProcessor:

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.findings: List[Finding] = []
        self.created_at = datetime.now(UTC)
        self.finished_at: Optional[datetime] = None
        self._dedup_index = set()
        self._raw_stats = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}

        scanner_cfg = config.get("scanner", {}) if config else {}
        self.max_findings = scanner_cfg.get("max_findings", 10000)
        self.max_file_size = scanner_cfg.get("max_file_size", 1048576)
        self.max_per_file = scanner_cfg.get("max_per_file", 1000)

        self._per_file_counter: Dict[str, int] = {}
        self.config = config or {}
        self.validator = ValidationEngine()

        base_path = Path(__file__).parent.parent
        rules_path = base_path / "resources" / "universal_logic.json"
        self.universal_semantic_rules = []

        if rules_path.exists():
            try:
                with open(rules_path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    self.universal_semantic_rules = data.get(
                        "universal_semantic_rules", []
                    )
                logger.info(
                    f"Inference Engine: Loaded {len(self.universal_semantic_rules)} semantic rules"
                )
            except Exception as e:
                logger.error(f"Inference Engine: Failed to load semantic rules: {e}")
        else:
            logger.warning("Inference Engine: universal_logic.json not found")

    def _get_base_cvss(self, severity: str) -> float:
        mapping = {"CRITICAL": 9.5, "HIGH": 8.0, "MEDIUM": 5.0, "LOW": 2.0, "INFO": 0.1}
        return mapping.get(severity.upper(), 0.1)

    def _apply_universal_inference(self, finding: Finding) -> Finding:
        if not self.universal_semantic_rules:
            return finding

        path = finding.file_path.lower().replace("\\", "/")
        rule_id = finding.rule_id.lower()
        context = "CORE"

        if any(
            x in path for x in ["/test", "/fixture", "/mock", "/example", "/sample"]
        ):
            context = "TEST"
        elif any(x in path for x in ["/docs", "readme", ".md"]):
            context = "DOCS"
        elif any(
            x in path for x in [".github", "docker", "terraform", ".tf", "compose"]
        ):
            context = "INFRA"

        for rule in self.universal_semantic_rules:
            if context != rule.get("file_context"):
                continue

            category = rule.get("risk_category", "")
            is_match = False

            if "SECRETS" in category and any(
                x in rule_id for x in ["secret", "token", "key", "password"]
            ):
                is_match = True
            elif "COMMAND" in category and any(
                x in rule_id for x in ["b602", "shell", "subprocess", "exec"]
            ):
                is_match = True
            elif "ASSERT" in category and "b101" in rule_id:
                is_match = True
            elif "IAC" in category and ("terraform" in path or ".tf" in path):
                is_match = True

            if not is_match:
                continue

            update_data = {"semantic_adjustment": True}
            new_meta = finding.meta.copy()
            rule_confidence = rule.get("confidence_level", 0.5)
            new_meta["context_label"] = context
            update_data.update(
                {
                    "meta": new_meta,
                    "severity": finding.severity,
                    "confidence": "HIGH" if rule_confidence >= 0.8 else "MEDIUM",
                }
            )

            return finding.model_copy(update=update_data)

        return finding

    def add_finding(self, finding_data: Any):
        try:
            if isinstance(finding_data, dict):
                sev = str(finding_data.get("severity", "INFO")).upper()
                finding_data["severity"] = sev
                if not finding_data.get("cvss_score"):
                    finding_data["cvss_score"] = self._get_base_cvss(sev)
                new_f = Finding(**finding_data)

            elif isinstance(finding_data, Finding):
                if not finding_data.cvss_score:
                    new_f = finding_data.model_copy(
                        update={
                            "cvss_score": self._get_base_cvss(finding_data.severity)
                        }
                    )
                else:
                    new_f = finding_data
            else:
                sev = str(getattr(finding_data, "severity", "INFO")).upper()
                cvss = getattr(finding_data, "cvss_score", None)
                new_f = Finding(
                    rule_id=str(getattr(finding_data, "rule_id", "unknown")),
                    file_path=str(getattr(finding_data, "file_path", "unknown")),
                    line=int(getattr(finding_data, "line", 0) or 0),
                    description=str(
                        getattr(finding_data, "description", "No description")
                    ),
                    severity=sev,
                    detector=str(getattr(finding_data, "detector", "unknown")),
                    cvss_score=float(cvss) if cvss else self._get_base_cvss(sev),
                )
        except Exception as e:
            logger.error(f"Invalid finding dropped (schema error): {e}")
            return

        full_path = Path(new_f.file_path)
        if full_path.exists() and full_path.is_file():
            if full_path.stat().st_size <= self.max_file_size:
                try:
                    with open(full_path, "r", encoding="utf-8", errors="ignore") as f:
                        lines = f.readlines()
                        # Save a +-50 line window around the finding for AI context
                        start = max(0, new_f.line - 50)
                        end = min(len(lines), new_f.line + 50)
                        relevant_code = "".join(lines[start:end])

                        # Store the snippet in finding metadata
                        new_f.meta["_source_code_snippet"] = relevant_code
                        new_f.meta["_file_content_for_validation"] = "".join(lines)
                        new_f.meta.pop("_file_content_for_validation", None)
                except Exception as e:
                    logger.warning(f"Could not read file content: {e}")

        path = new_f.file_path.lower().replace("\\", "/")
        if any(
            x in path
            for x in [
                "test",
                "tests",
                "fixture",
                "mock",
                "spec",
                "example",
                "bench",
                "sample",
                "testsuite",
                "ext/",
                "vendor/",
            ]
        ):
            context = "TEST"
        elif any(
            x in path
            for x in [".github", "docker", "terraform", ".tf", "compose", "ci/"]
        ):
            context = "INFRA"
        elif any(x in path for x in ["/docs", "readme", ".md"]):
            context = "DOCS"
        else:
            context = "CORE"

        new_f.meta["context_label"] = context
        new_f.meta["detector_severity"] = new_f.severity
        new_f = self._apply_universal_inference(new_f)
        new_f = self.validator.validate(new_f)
        new_f = self._refine_context(new_f)
        # new_f.meta.pop("_file_content_for_validation", None)

        if self._is_duplicate(new_f):
            return

        file_count = self._per_file_counter.get(new_f.file_path, 0)
        if file_count >= self.max_per_file:
            return
        self._per_file_counter[new_f.file_path] = file_count + 1

        sev_key = new_f.severity.upper()
        if sev_key in self._raw_stats:
            self._raw_stats[sev_key] += 1

        if len(self.findings) < self.max_findings:
            self.findings.append(new_f)
            self._dedup_index.add(
                (new_f.rule_id, new_f.file_path, new_f.line, new_f.detector)
            )

    def _is_duplicate(self, f: Finding) -> bool:
        return (f.rule_id, f.file_path, f.line, f.detector) in self._dedup_index

    def get_all_findings(self) -> List[Finding]:
        return list(self.findings)

    @property
    def summary(self) -> Dict[str, int]:
        return self._raw_stats

    def get_file_stats(self) -> Dict[str, int]:
        ext_stats = {}
        for f in self.findings:
            ext = Path(f.file_path).suffix or "no_ext"
            ext_stats[ext] = ext_stats.get(ext, 0) + 1
        return ext_stats

    def get_report_data(self) -> Dict[str, Any]:
        all_f = self.get_all_findings()
        processed_issues = [f.model_dump() for f in all_f]

        return {
            "summary": self.summary,
            "file_stats": self.get_file_stats(),
            "issues": processed_issues,
            "total_issues": sum(self._raw_stats.values()),
            "saved_issues": len(all_f),
            "created_at": self.created_at.isoformat(),
            "duration": str(datetime.now(UTC) - self.created_at),
        }

    def _refine_context(self, finding: Finding) -> Finding:
        # Use only the local snippet, not the entire file content
        snippet = finding.meta.get("_source_code_snippet", "")
        if not snippet:
            return finding

        if "BEGIN RSA PRIVATE KEY" in snippet:
            return finding.model_copy(
                update={
                    "remote_reachable": False,
                    "exploitability_level": "STATIC_SECRET",
                    "exploitability_score": 9,
                }
            )

        if "subprocess" in snippet and "shell=True" in snippet:
            return finding.model_copy(
                update={
                    "remote_reachable": True,
                    "exploitability_level": "REMOTE_EXECUTION",
                    "exploitability_score": 10,
                }
            )

        return finding