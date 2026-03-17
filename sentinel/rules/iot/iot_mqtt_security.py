import re
from sentinel.rules.base import BaseRule


class IoTMQTTSecurityRule(BaseRule):
    def __init__(self):
        super().__init__()
        # FIX: Fixed duplicate ID (was CICD-001 - collision with gh_pinning.py)
        self.id = "IOT-001"
        # self.severity = "BLOCK"
        self.cwe_id = "CWE-319"
        self.rationale = "Insecure MQTT (port 1883) found. IoT devices must use port 8883 with TLS/SSL encryption."

    def check(self, artifacts):
        findings = []
        files = artifacts.get("all_files", {})
        if not isinstance(files, dict):
            return findings

        for file_path, content in files.items():
            if "sentinel/rules/" in file_path:
                continue

            # FIX: Match port 1883 only as a network port, not an arbitrary number
            # Pattern: port=1883 / port: 1883 / :1883 / "1883" - but not bare "1883" in text
            if re.search(r'(?:port\s*[:=]\s*1883|:\s*1883\b|["\']1883["\'])', content):
                findings.append(f"IOT-001: Insecure MQTT port 1883 detected in {file_path}")

            # MQTT without TLS - only if connect is used explicitly without tls_set
            if (
                "mqtt" in content.lower()
                and re.search(r'\.connect\s*\(', content)
                and "tls_set" not in content
            ):
                findings.append(f"IOT-001: MQTT connection without TLS detected in {file_path}")

        return findings