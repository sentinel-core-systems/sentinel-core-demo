"""
Risk Taxonomy Registry - Auditor Core v2.1
Centralized security classification layer.
"""

from typing import Dict


RULE_TAXONOMY: Dict[str, Dict[str, str]] = {
    # Injection
    "SAST_COMMAND_INJECTION": {
        "cwe": "CWE-78",
        "category": "Injection",
        "impact": "Remote Code Execution",
    },
    # Secrets
    "SECRET_GENERIC_SECRET": {
        "cwe": "CWE-798",
        "category": "Hardcoded Credentials",
        "impact": "Credential Exposure",
    },
    "generic.secrets.security.detected-aws-access-key-id-value.detected-aws-access-key-id-value": {
        "cwe": "CWE-798",
        "category": "Hardcoded Credentials",
        "impact": "Cloud Account Compromise",
    },
    "SECRET_AWS_KEY": {
        "cwe": "CWE-798",
        "category": "Hardcoded Credentials",
        "impact": "Exposure of cloud credentials",
    },
    "aws-access-token": {
        "cwe": "CWE-798",
        "category": "Hardcoded Credentials",
        "impact": "Exposure of cloud credentials",
    },
    "BANDIT_B605": {
        "cwe": "CWE-78",
        "category": "Command Injection",
        "impact": "Remote command execution risk",
    },
    "BANDIT_B307": {
        "cwe": "CWE-94",
        "category": "Code Injection",
        "impact": "Arbitrary code execution risk",
    },
    "BANDIT_B105": {
        "cwe": "CWE-798",
        "category": "Hardcoded Credentials",
        "impact": "Credential exposure risk",
    },
    "IAC_OPEN_ACCESS": {
        "cwe": "CWE-284",
        "category": "Improper Access Control",
        "impact": "Infrastructure exposure",
    },
}


def resolve_taxonomy(rule_id: str) -> Dict[str, str]:
    """
    Returns standardized taxonomy data for a given rule.
    """
    return RULE_TAXONOMY.get(
        rule_id,
        {
            "cwe": "CWE-UNKNOWN",
            "category": "Unclassified",
            "impact": "Unclassified Risk",
        },
    )
