import re
import os
import logging
from typing import List, Dict
from sentinel.rules.base import BaseRule

logger = logging.getLogger(__name__)


class SecretsRule(BaseRule):
    def __init__(self):
        super().__init__()
        self.id = "SEC-001"
        self.severity = "BLOCK"
        self.cwe_id = "CWE-798"
        self.description = "Detection of credentials, private keys, and insecure settings."
        self.rationale = "Hardcoded secrets lead to immediate infrastructure compromise."

        self.patterns = {
            "AWS Access Key":        r"AKIA[0-9A-Z]{16}",
            "Private Key":           r"-----BEGIN (RSA|OPENSSH|DSA|EC|PGP)? PRIVATE KEY-----",
            "Slack Bot Token":       r"xox[bapz]-[0-9]{12}-[0-9]{12}-[a-zA-Z0-9]{24}",
            # FIX: Require explicit Authorization header to avoid false positives
            # in documentation and README examples
            "Generic Bearer Token":  r"(?i)Authorization\s*[:=]\s*['\"]?Bearer\s+[a-zA-Z0-9_\-\.]{32,}",
            "Hardcoded Password":    r"(?i)(password|pwd|db_pass|admin_pass)\s*[:=]\s*['\"][^'\" ]{4,}['\"]",
            "Insecure TLS (Python)": r"verify\s*=\s*False",
            "Insecure TLS (NodeJS)": r"NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*['\"]?0['\"]?",
        }

        # Indicators of non-production context in the line itself
        self._fake_hints = ["example", "fake", "placeholder", "dummy", "test", "sample", "your_", "<", ">"]

    def check(self, artifacts: Dict[str, any]) -> List[str]:
        violations = []

        # FIX: Correctly build the set of test paths
        test_paths = {
            p for p in artifacts.get("all_files", [])
            if any(x in p.lower() for x in ["test", "mock", "fixture", "example", "sample", "docs", ".md"])
        }

        # Collect all content from category dictionaries
        all_content = {}
        for cat in artifacts.values():
            if isinstance(cat, dict):
                all_content.update(cat)

        for path, content in all_content.items():
            # Skip internal Sentinel files
            if "sentinel/" in path.replace("\\", "/"):
                continue

            lines = content.splitlines()
            for line_num, line in enumerate(lines, 1):
                clean_line = line.strip()
                # Skip comments and lines that are too short
                if len(clean_line) < 8:
                    continue
                if clean_line.startswith("#") or clean_line.startswith("//"):
                    continue

                for secret_type, regex in self.patterns.items():
                    if re.search(regex, clean_line):
                        is_test_context = (
                            path in test_paths
                            or any(h in clean_line.lower() for h in self._fake_hints)
                        )

                        if is_test_context:
                            violations.append(
                                f"[WARN] SEC-001-SUSPICIOUS: Potential {secret_type} in {path} "
                                f"at line {line_num}. Likely non-production artifact (Test/Mock context)."
                            )
                        else:
                            violations.append(
                                f"[BLOCK] SEC-001: {secret_type} identified in {path} "
                                f"at line {line_num}. Action: REVOKE IMMEDIATELY AND ROTATE."
                            )
                        break  # One violation per line

        return violations