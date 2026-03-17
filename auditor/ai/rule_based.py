import logging
from typing import List, Dict, Any

# Assuming templates are updated to English as well
from auditor.ai.templates import REMEDIATION_TEMPLATES

logger = logging.getLogger(__name__)


class RuleBasedAdvisor:
    """
    Deterministic remediation advisor using predefined security templates.
    Used as a primary source for offline scans or as a fallback for LLM providers.
    """

    def generate_recommendations(self, findings: List[Any], **kwargs) -> List[Dict]:
        """
        Maps findings to specific remediation steps based on Rule IDs.
        """
        recommendations = []

        for f in findings:
            # 1. Try exact rule match
            advice = REMEDIATION_TEMPLATES.get(f.rule_id)
            if not advice:
                advice = REMEDIATION_TEMPLATES.get(f.detector)

            # 2. Try generic detector match if rule match fails
            if not advice:
                # Additional lookup by CWE from meta
                cwe = (getattr(f, "meta", {}) or {}).get("cwe", "")
                if cwe:
                    advice = REMEDIATION_TEMPLATES.get(cwe)
            if not advice:
                advice = self._get_smart_fallback(f)

            recommendations.append(
                {"finding_id": str(f.id), "advice": advice, "type": "static_advisory"}
            )

        return recommendations

    def _get_smart_fallback(self, finding: Any) -> str:
        """
        Provides a category-based advice when a specific template is missing.
        RCA: Synchronized with Severity levels for better UX.
        """
        desc = finding.description.lower()
        rule = str(finding.rule_id).lower()
        sev = finding.severity.upper()

        if "secret" in rule or "key" in desc or "token" in desc:
            return "[ACTION REQUIRED] Sensitive credential detected. Revoke immediately and migrate to a Secure Vault (e.g., HashiCorp Vault or AWS Secrets Manager)."

        if "docker" in rule or "container" in desc or "kubernetes" in desc:
            return "[INFRA ADVICE]: Harden container configuration. Ensure non-root user execution and follow CIS Docker/K8s Benchmarks."

        if "sql" in desc or "injection" in desc or "query" in desc:
            return "[SECURITY ADVICE]: Potential Injection risk. Implement parameterized queries, use ORMs, and sanitize all user-controlled inputs."

        if "version" in desc or "vulnerable" in desc or "cve" in desc:
            return f"[PATCHING REQUIRED]: Vulnerable component detected. Execute 'npm audit fix' or equivalent for your stack. Current Severity: {sev}."

        short_rule = str(finding.rule_id)[:60]  # truncate long rule IDs
        return f"[REMEDIATION] Technical investigation of '{short_rule}' required. Refer to internal security guidelines for {sev} level findings."
