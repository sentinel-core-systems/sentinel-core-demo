"""
Dependency Scanner - Auditor Core Professional.
Offline Software Composition Analysis (SCA) engine with Zero Call-Home policy.
"""

import json
import re
import os
import logging
from pathlib import Path
from typing import Dict, Iterable, List, Optional

from auditor.detectors.plugin_base import DetectorPlugin, PluginMetadata
from auditor.core.engine import Finding

logger = logging.getLogger(__name__)


class DependencyScanner(DetectorPlugin):
    """
    Identifies vulnerable dependencies in Python, Node.js, and Ruby projects.
    Uses a local JSON database to ensure maximum privacy and offline capability.
    """

    def __init__(self):
        super().__init__()
        # Path to the local vulnerability database
        self.db_path = (
            Path(__file__).resolve().parent.parent
            / "resources"
            / "vulnerability_db.json"
        )
        self.vulnerabilities = self._load_db()

    def _load_db(self) -> Dict:
        """Loads the local vulnerability definitions from JSON."""
        if self.db_path.exists():
            try:
                with open(self.db_path, "r") as f:
                    return json.load(f)
            except Exception as e:
                logger.error(f"SCA: Failed to load vulnerability database: {e}")

        # Fallback to internal list if DB is missing or corrupted
        logger.error(
            "SCA: Vulnerability database not found or corrupted. "
            "Dependency scanning will be skipped to avoid false positives."
        )
        return {"pypi": [], "npm": []}

    @property
    def metadata(self) -> PluginMetadata:
        """Returns plugin metadata for the orchestration engine."""
        return PluginMetadata(
            name="DependencyScanner",
            version="1.2.0",
            vendor="DataWizual Lab - Auditor Core",
            description="Offline SCA scanner with local database and path exclusion support.",
        )

    def scan(
        self,
        project_path: str,
        files: Optional[List[str]] = None,
        exclude: Optional[List[str]] = None,
    ) -> List[Finding]:
        """
        Scans project directory for manifests and analyzes their dependencies.
        Respects directory exclusions (e.g., venv, node_modules).
        """
        findings = []
        manifests = {
            "requirements.txt",
            "package.json",
            "Pipfile",
            "Gemfile",
            "Gemfile.lock",
        }

        try:
            target_abs = Path(project_path).resolve()
        except Exception:
            return []

        for root, dirs, files in os.walk(target_abs):
            # RCA Item: Efficiency - Prune excluded directories immediately
            if exclude:
                dirs[:] = [d for d in dirs if d not in exclude]

            for file in files:
                if file in manifests:
                    file_path = Path(root) / file
                    try:
                        # Normalize path for reporting
                        rel_path = os.path.relpath(file_path, target_abs).replace(
                            "\\", "/"
                        )

                        with open(
                            file_path, "r", encoding="utf-8", errors="ignore"
                        ) as f:
                            content = f.read()

                        if file == "requirements.txt":
                            findings.extend(
                                list(self._scan_requirements_txt(content, rel_path))
                            )
                        elif file == "package.json":
                            findings.extend(
                                list(self._scan_package_json(content, rel_path))
                            )
                        elif file == "Pipfile":
                            findings.extend(list(self._scan_pipfile(content, rel_path)))
                        elif file in ["Gemfile", "Gemfile.lock"]:
                            findings.extend(list(self._scan_gemfile(content, rel_path)))

                    except Exception as e:
                        logger.error(f"SCA: Failed to process {file}: {e}")

        return findings

    def _is_vulnerable(self, package: str, ecosystem: str) -> bool:
        """
        ISSUE 7 Fix: Matches package names against the loaded vulnerability database.
        """
        ecosystem_db = self.vulnerabilities.get(ecosystem, [])
        return package.lower() in [p.lower() for p in ecosystem_db]

    def _scan_requirements_txt(self, content: str, file_path: str) -> Iterable[Finding]:
        """Parses PyPI requirements.txt files for known vulnerabilities."""
        pattern = r"^([a-zA-Z0-9_\-\[\]]+)([=<>!~]+[a-zA-Z0-9\.\-\*]+)?.*$"
        for line_num, line in enumerate(content.splitlines(), 1):
            line = line.strip()
            if not line or line.startswith("#"):
                continue

            match = re.match(pattern, line)
            if match:
                package = match.group(1).lower()
                if self._is_vulnerable(package, "pypi"):
                    yield Finding(
                        rule_id="DEP_VULN_PYPI",
                        severity="HIGH",
                        file_path=file_path,
                        line=line_num,
                        description=f"Known vulnerable PyPI package detected: '{package}'",
                        cvss_score=7.5,
                        detector="DependencyScanner",
                    )

    def _scan_package_json(self, content: str, file_path: str) -> Iterable[Finding]:
        """Analyzes NPM package.json for vulnerable dependencies."""
        try:
            data = json.loads(content)
            deps = {**data.get("dependencies", {}), **data.get("devDependencies", {})}
            for package, version in deps.items():
                if self._is_vulnerable(package, "npm"):
                    yield Finding(
                        rule_id="DEP_VULN_NPM",
                        severity="HIGH",
                        file_path=file_path,
                        line=1,
                        description=f"Known vulnerable NPM package detected: '{package}' (Version: {version})",
                        cvss_score=7.5,
                        detector="DependencyScanner",
                    )
        except json.JSONDecodeError:
            pass

    def _scan_pipfile(self, content: str, file_path: str) -> Iterable[Finding]:
        """Checks Pipfile for insecure versioning practices."""
        if re.search(r'=\s*["\'][*]["\']', content):
            yield Finding(
                rule_id="DEP_WILDCARD_VERSION",
                severity="MEDIUM",
                file_path=file_path,
                line=1,
                description="Wildcard versioning '*' detected in Pipfile. This allows unverified package updates.",
                cvss_score=4.0,
                detector="DependencyScanner",
            )

    def _scan_gemfile(self, content: str, file_path: str) -> Iterable[Finding]:
        """Analyzes Ruby Gemfiles for insecure source definitions."""
        if "http://" in content:
            yield Finding(
                rule_id="DEP_INSECURE_SOURCE",
                severity="MEDIUM",
                file_path=file_path,
                line=1,
                description="Insecure HTTP source detected in Gemfile. Use HTTPS to prevent MITM attacks.",
                cvss_score=5.0,
                detector="DependencyScanner",
            )

    def scan_file(self, file_path: str, content: str) -> List[Finding]:
        """Individual file scanning is handled via the bulk directory scan method."""
        return []
