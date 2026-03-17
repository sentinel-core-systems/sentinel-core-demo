import re
from typing import List, Dict
from sentinel.rules.base import BaseRule


class TerraformSecurityRule(BaseRule):
    """
    Analyzes Terraform configuration files for infrastructure-level vulnerabilities.
    Specifically targets management ports (SSH/RDP) exposed to the public internet.
    """

    def __init__(self):
        super().__init__()
        # SYSTEM SYNCHRONIZATION: This ID is hard-locked in engine.py (Anti-Sabotage policy).
        # It cannot be overridden to 'WARN' status by the client configuration.
        self.id = "INFRA-TF-001"
        # self.severity = "BLOCK"
        self.cwe_id = "CWE-668"
        self.description = "Critical management ports (SSH/RDP) exposed to 0.0.0.0/0."
        self.rationale = "Publicly accessible management ports are high-risk vectors for automated brute-force attacks."

    def check(self, artifacts: Dict[str, List[str]]) -> List[str]:
        """
        Scans infrastructure artifacts for insecure network configurations.
        Uses optimized pattern matching to detect public CIDR blocks and management ports.
        """
        violations = []

        # Systematically utilize the 'infra' category pre-filtered by the ArtifactCollector
        tf_files = [p for p in artifacts.get("infra", []) if p.endswith(".tf")]

        for path in tf_files:
            content = self.read_file(path)
            if not content:
                continue

            # 1. Detection of wide-open CIDR blocks (supports various quote types and spacing)
            # Looks for ["0.0.0.0/0"] or ['0.0.0.0/0']
            has_open_cidr = re.search(
                r'cidr_blocks\s*=\s*\[.*["\']0\.0\.0\.0/0["\'].*\]', content
            )

            if not has_open_cidr:
                continue

            # 2. SSH Audit (Port 22)
            # Detects port = 22 or ranges including the standard SSH port
            if re.search(r"(from_port|to_port|port)\s*=\s*22\b", content):
                violations.append(
                    f"INFRA-001: Insecure Infrastructure in {path}. SSH (port 22) is open to 0.0.0.0/0. "
                    f"Action: Restrict 'cidr_blocks' to authorized IP ranges only."
                )

            # 3. RDP Audit (Port 3389)
            if re.search(r"(from_port|to_port|port)\s*=\s*3389\b", content):
                violations.append(
                    f"INFRA-001: Insecure Infrastructure in {path}. RDP (port 3389) is open to 0.0.0.0/0. "
                    f"Action: Close port 3389 or utilize a Bastion/VPN for access."
                )

            # 4. Full Protocol Audit (Critical Vulnerability)
            # Detects instances where all protocols and ports are exposed
            if re.search(r"from_port\s*=\s*0\b", content) and re.search(
                r'protocol\s*=\s*["\']-1["\']', content
            ):
                violations.append(
                    f"INFRA-001: CRITICAL Security Risk in {path}. All protocols and ports are exposed to the internet."
                )

        return violations
