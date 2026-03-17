"""
IaC Scanner - Auditor Cloud Suite.
Analyzes Terraform, Docker, and Kubernetes configurations for security misconfigurations.
"""

import re
import logging
import os
from pathlib import Path
from typing import List, Optional

from auditor.detectors.plugin_base import DetectorPlugin, PluginMetadata
from auditor.core.engine import Finding

logger = logging.getLogger(__name__)


class IacScanner(DetectorPlugin):
    """
    Scanner for Infrastructure as Code files with hardened path filtering.
    Detects misconfigurations in Terraform, Docker, and K8s.
    """

    def __init__(self):
        super().__init__()
        self.name = "IacScanner"
        # Original patterns preserved as requested
        self.iac_patterns = {
            "terraform": [
                (
                    r'(password|secret_key|access_key)\s*=\s*["\'][^"\']+["\']',
                    "CRITICAL",
                    "IAC_HARDCODED_CREDENTIAL",
                ),
                (r"publicly_accessible\s*=\s*true", "HIGH", "IAC_PUBLIC_RESOURCE"),
                (
                    r'cidr_blocks\s*=\s*\[\s*["\']0\.0\.0\.0/0["\']\s*\]',
                    "HIGH",
                    "IAC_OPEN_ACCESS",
                ),
            ],
            "dockerfile": [
                (r"USER\s+root", "MEDIUM", "DOCKER_RUN_AS_ROOT"),
                (
                    r"ENV\s+(.*(?:PASSWORD|SECRET|TOKEN|KEY).*)=.+",
                    "CRITICAL",
                    "DOCKER_ENV_SECRET",
                ),
                (r"FROM\s+.+:latest", "LOW", "DOCKER_LATEST_TAG"),
            ],
            "kubernetes": [
                (r"privileged:\s*true", "HIGH", "K8S_PRIVILEGED_CONTAINER"),
                (
                    r"allowPrivilegeEscalation:\s*true",
                    "MEDIUM",
                    "K8S_PRIVILEGE_ESCALATION",
                ),
                (r"hostNetwork:\s*true", "HIGH", "K8S_HOST_NETWORK"),
            ],
        }

    @property
    def metadata(self) -> PluginMetadata:
        """Returns metadata for the IaC scanning plugin."""
        return PluginMetadata(
            name="iac_scanner",
            version="1.2.1",
            vendor="DataWizual Lab - Auditor Core",
            description="Analyzes IaC files (TF, Docker, K8s) with enterprise path filtering",
        )

    def scan(
        self,
        project_path: str,
        files: Optional[List[str]] = None,
        exclude: Optional[List[str]] = None,
    ) -> List[Finding]:
        """
        Scans for IaC files in the project directory, respecting exclusions.
        """
        findings = []
        iac_exts = {".tf", ".tfvars", ".dockerfile", ".yaml", ".yml"}

        try:
            target_abs = Path(project_path).resolve()

            for root, dirs, files in os.walk(str(target_abs)):
                # Filter directories based on exclude list
                if exclude:
                    dirs[:] = [d for d in dirs if d not in exclude]

                # Self-analysis protection to avoid scanning the auditor itself
                auditor_root = str(Path(__file__).resolve().parent.parent)
                if str(Path(root).resolve()).startswith(auditor_root):
                    continue

                for file in files:
                    path_obj = Path(root) / file
                    # Check extension OR specific filename (Dockerfile)
                    if (
                        path_obj.suffix.lower() in iac_exts
                        or file.lower() == "dockerfile"
                    ):
                        try:
                            with open(
                                path_obj, "r", encoding="utf-8", errors="ignore"
                            ) as f:
                                content = f.read()

                            # Calculate relative path for reporting
                            rel_path = str(path_obj.relative_to(target_abs)).replace(
                                "\\", "/"
                            )
                            findings.extend(self.scan_file(rel_path, content))
                        except Exception:
                            continue
        except Exception:
            logger.error("IaC Scanner: Critical error during directory traversal.")

        return findings

    def scan_file(self, file_path: str, content: str) -> List[Finding]:
        """Processes an individual file for IaC vulnerabilities."""
        path_obj = Path(file_path)
        tech_type = self._detect_tech_type(path_obj, content)
        # Use generic rules if technology type is unknown
        tech_key = tech_type if tech_type != "unknown" else "generic"
        return self._analyze_content(content, file_path, tech_key)

    def _detect_tech_type(self, file_path: Path, content: str) -> str:
        """
        Identifies the technology stack of the file.
        Fix for Issue 9: Validates Kubernetes content before assignment.
        """
        suffix = file_path.suffix.lower()
        name = file_path.name.lower()

        if name == "dockerfile" or suffix == ".dockerfile":
            return "dockerfile"

        if suffix in [".tf", ".tfvars"]:
            return "terraform"

        if suffix in [".yaml", ".yml"]:
            # Issue 9 Fix: Verify if YAML is actually a Kubernetes manifest
            is_k8s = re.search(r"^\s*apiVersion:", content, re.MULTILINE) and re.search(
                r"^\s*kind:", content, re.MULTILINE
            )
            if is_k8s:
                return "kubernetes"
            return "unknown"

        return "unknown"

    def _analyze_content(
        self, content: str, file_path: str, tech: str
    ) -> List[Finding]:
        """Matches specific security patterns against the file content."""
        findings = []
        lines = content.splitlines()

        # Default patterns for generic/unknown configurations
        default_patterns = [
            (r"0\.0\.0\.0/0", "HIGH", "IAC_GENERAL_OPEN_NETWORK"),
            (r"(?i)admin" + r"_password", "CRITICAL", "IAC_GENERIC_PASSWORD"),
        ]

        patterns = self.iac_patterns.get(tech, default_patterns)

        for line_num, line in enumerate(lines, 1):
            line_s = line.strip()
            # Skip empty lines, comments, and boilerplate
            if not line_s or line_s.startswith(("#", "//", "import", "from")):
                continue

            for pattern, severity, rule_id in patterns:
                if re.search(pattern, line_s, re.IGNORECASE):
                    findings.append(
                        Finding(
                            rule_id=rule_id,
                            file_path=file_path,
                            line=line_num,
                            description=f"Security risk in {tech} configuration: {rule_id}",
                            severity=severity,
                            detector="IacScanner",
                        )
                    )
        return findings
