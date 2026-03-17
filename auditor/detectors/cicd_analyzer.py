"""
CI/CD Configuration Analyzer.
Identifies overly permissive permissions, secrets in environment, and script injections.
"""

import os
import re
import yaml
import logging
from pathlib import Path
from typing import List, Dict, Any, Iterable, Optional

from auditor.detectors.plugin_base import DetectorPlugin, PluginMetadata
from auditor.core.engine import Finding

logger = logging.getLogger(__name__)

# Security threshold to prevent DoS via large YAML files (YAML bombs)
MAX_CICD_FILE_SIZE = 500 * 1024


class CicdAnalyzer(DetectorPlugin):
    """
    Analyzes CI/CD configuration files (GitHub Actions, GitLab CI, Jenkins)
    for security vulnerabilities and misconfigurations.
    """

    def __init__(self):
        super().__init__()
        # Untrusted contexts that can lead to script injection in shell steps
        self.dangerous_contexts = [
            r"github\.event\.pull_request\.title",
            r"github\.event\.pull_request\.body",
            r"github\.event\.issue\.title",
            r"github\.event\.issue\.body",
            r"github\.event\.comment\.body",
            r"github\.event\.review\.body",
            r"github\.actor",
            r"github\.head_ref",
        ]

    @property
    def metadata(self) -> PluginMetadata:
        """Returns plugin metadata for the orchestration engine."""
        return PluginMetadata(
            name="cicd_analyzer",
            version="1.4.0",
            vendor="DataWizual Lab - Auditor Core",
            description="Security analyzer for CI/CD configurations with exclusion support.",
        )

    def scan(
        self,
        project_path: str,
        files: Optional[List[str]] = None,
        exclude: Optional[List[str]] = None,
    ) -> List[Finding]:
        """
        Walks through the project to find and analyze CI/CD configuration files.
        """
        findings = []
        try:
            target_abs = Path(project_path).resolve()
        except Exception:
            return []

        # Hard excludes - always applied regardless of config
        hard_exclude_dirs = {"venv", ".venv", "env", "node_modules", ".git",
                             "__pycache__", "dist", "build", "site-packages"}

        for root, dirs, files in os.walk(target_abs):
            # Apply hard excludes
            dirs[:] = [d for d in dirs if d not in hard_exclude_dirs]

            # Apply user-configured excludes
            if exclude:
                dirs[:] = [
                    d for d in dirs
                    if not any(
                        d == ex.rstrip("/*") or
                        str(Path(root) / d).endswith(ex.rstrip("/*"))
                        for ex in exclude
                    )
                ]

            for file in files:
                full_path = Path(root) / file

                # Check file size before processing to prevent DoS
                MEDIA_EXTENSIONS = {
                    '.jpg', '.jpeg', '.png', '.gif', '.bmp', '.svg', '.ico',
                    '.mp4', '.mov', '.avi', '.mkv', '.webm',
                    '.mp3', '.wav', '.ogg',
                    '.pdf', '.zip', '.tar', '.gz', '.whl', '.exe', '.bin',
                }
                if full_path.suffix.lower() in MEDIA_EXTENSIONS:
                    continue

                try:
                    if full_path.stat().st_size > MAX_CICD_FILE_SIZE:
                        logger.warning(
                            f"CI/CD: Skipping {file} (File exceeds size limit)."
                        )
                        continue
                except OSError:
                    continue

                # Identify CI/CD configuration files
                path_str = str(full_path).replace("\\", "/")
                if (
                    ".github/workflows" in path_str
                    or file == ".gitlab-ci.yml"
                    or "Jenkinsfile" in file
                ):
                    try:
                        with open(
                            full_path, "r", encoding="utf-8", errors="ignore"
                        ) as f:
                            content = f.read()

                        # Get path relative to target for clean reporting
                        rel_path = os.path.relpath(full_path, target_abs)
                        findings.extend(self.scan_file(rel_path, content))
                    except Exception as e:
                        logger.error(f"CI/CD: Error reading {file}: {e}")

        return findings

    def scan_file(self, file_path: str, content: str) -> List[Finding]:
        """
        Analyzes the content of a single CI/CD file based on its detected type.
        """
        if not content or len(content) > MAX_CICD_FILE_SIZE:
            return []

        findings = []
        try:
            file_type = self._detect_file_type(file_path)

            if file_type == "github_actions":
                findings.extend(self._analyze_github_actions(content, file_path))
            elif file_type == "gitlab_ci":
                findings.extend(self._analyze_gitlab_ci(content, file_path))
            else:
                findings.extend(self._analyze_generic_cicd(content, file_path))
        except Exception as e:
            logger.error(f"CI/CD Analyzer error in {file_path}: {e}")

        return findings

    def _detect_file_type(self, file_path: str) -> str:
        path_str = file_path.lower().replace("\\", "/")
        if ".github/workflows" in path_str:
            return "github_actions"
        if ".gitlab-ci" in path_str:
            return "gitlab_ci"
        return "generic"

    def _analyze_github_actions(self, content: str, file_path: str) -> List[Finding]:
        """Specific logic for GitHub Actions YAML analysis."""
        findings = []
        try:
            data = yaml.safe_load(content)
            if not isinstance(data, dict):
                return findings

            # 1. Dangerous Triggers
            on_event = str(data.get("on", {}))
            if "pull_request_target" in on_event:
                findings.append(
                    self._create_finding(
                        "HIGH",
                        "Workflow uses 'pull_request_target'. Risk of PR-based environment hijacking.",
                        file_path,
                        "GHA_PULL_REQUEST_TARGET",
                    )
                )

            # 2. Permissive Permissions
            permissions = data.get("permissions", {})
            if permissions == "write-all" or (
                isinstance(permissions, dict)
                and any(v == "write" for v in permissions.values())
            ):
                findings.append(
                    self._create_finding(
                        "HIGH",
                        "Workflow has excessive write permissions. Principle of least privilege violation.",
                        file_path,
                        "GHA_EXCESSIVE_PERMISSIONS",
                    )
                )

            # 3. Actions Integrity (SHA Pinning)
            jobs = data.get("jobs", {})
            if isinstance(jobs, dict):
                for job in jobs.values():
                    if not isinstance(job, dict):
                        continue
                    for step in job.get("steps", []):
                        if not isinstance(step, dict):
                            continue

                        action = step.get("uses")
                        if (
                            action
                            and isinstance(action, str)
                            and not (
                                action.startswith("./")
                                or action.startswith("docker://")
                            )
                        ):
                            if "@" in action:
                                _, version = action.split("@", 1)
                                if not re.match(r"^[0-9a-f]{40}$", version):
                                    findings.append(
                                        self._create_finding(
                                            "MEDIUM",
                                            f"Unpinned action '{action}'. Use a full SHA hash to prevent supply chain attacks.",
                                            file_path,
                                            "GHA_UNPINNED_ACTION",
                                        )
                                    )
                            else:
                                findings.append(
                                    self._create_finding(
                                        "HIGH",
                                        f"Action '{action}' is missing a version pin.",
                                        file_path,
                                        "GHA_NO_VERSION_PIN",
                                    )
                                )

                        # 4. Script Injection Detection
                        run_cmd = step.get("run", "")
                        if run_cmd and isinstance(run_cmd, str):
                            for context in self.dangerous_contexts:
                                if re.search(r"{{\s*" + context + r"\s*}}", run_cmd):
                                    findings.append(
                                        self._create_finding(
                                            "CRITICAL",
                                            f"Potential Script Injection: untrusted context '{context}' used in shell.",
                                            file_path,
                                            "GHA_SCRIPT_INJECTION",
                                        )
                                    )
        except Exception as e:
            logger.warning(f"CI/CD: GitHub Actions parse error in {file_path}: {e}")
        return findings

    def _analyze_gitlab_ci(self, content: str, file_path: str) -> List[Finding]:
        """Specific logic for GitLab CI analysis."""
        findings = []
        try:
            data = yaml.safe_load(content)
            if isinstance(data, dict):
                variables = data.get("variables", {})
                if isinstance(variables, dict):
                    for k, v in variables.items():
                        # Removed len(v) > 32 check - pattern matching is sufficient
                        if isinstance(v, str) and re.search(
                            r"gh[pousr]_[A-Za-z0-9_]+", v
                        ):
                            findings.append(
                                self._create_finding(
                                    "CRITICAL",
                                    f"Potential secret hardcoded in GitLab CI variable '{k}'.",
                                    file_path,
                                    "GL_SECRET_IN_VARS",
                                )
                            )
        except Exception:
            pass
        return findings

    def _analyze_generic_cicd(self, content: str, file_path: str) -> List[Finding]:
        """Fallback analysis for Jenkinsfiles and other CI scripts."""
        findings = []
        patterns = [
            (
                r'password\s*[:=]\s*["\'][^"\']{4,}["\']',
                "CRITICAL",
                "CICD_HARDCODED_SECRET",
            ),
            (r"sudo\s+", "MEDIUM", "CICD_SUDO_USAGE"),
        ]
        for pattern, sev, rid in patterns:
            if re.search(pattern, content, re.IGNORECASE):
                findings.append(
                    self._create_finding(
                        sev, f"Pipeline Security Risk: {rid}", file_path, rid
                    )
                )
        return findings

    def _create_finding(
        self, severity: str, description: str, file_path: str, rule_id: str
    ) -> Finding:
        """Helper to standardize Finding object creation."""
        return Finding(
            rule_id=rule_id,
            severity=severity.upper(),
            file_path=file_path.replace("\\", "/"),
            line=1,
            description=description,
            detector="cicd_analyzer",
        )
