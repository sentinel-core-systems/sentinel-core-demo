"""
SAST Scanner - Auditor Core Professional.
Hybrid detection engine: Multi-language Regex + Deep Python AST analysis.
"""

import re
import logging
import os
import ast
from pathlib import Path
from typing import List, Iterable, Optional

from auditor.detectors.plugin_base import DetectorPlugin, PluginMetadata
from auditor.core.engine import Finding

logger = logging.getLogger(__name__)


class SastScanner(DetectorPlugin):
    """
    Enterprise-grade SAST engine.
    Combines high-speed pattern matching with semantic AST analysis for Python.
    """

    def __init__(self):
        super().__init__()
        self.name = "SastScanner"
        # Original vulnerability patterns preserved in full
        self.vulnerability_patterns = {
            "sql_injection": [
                (r"execute\(.*\+.*\)", "high"),
                (r'cursor\.execute\(f".*" \+ .*\)', "high"),
                (r"raw\(.*\+.*\)", "medium"),
                (r"executescript\(", "critical"),
            ],
            "command_injection": [
                (r"os\.system\(", "critical"),
                (r"subprocess\.(call|Popen|run)\(.*shell=True\)", "high"),
                (r"\beval\(", "critical"),
                (r"exec\(", "critical"),
            ],
            "xss": [
                (r"innerHTML\s*=\s*.+", "high"),
                (r"document\.write\(", "medium"),
                (r"\.html\(.*\)", "medium"),
            ],
            "insecure_crypto": [
                (r"hashlib\.md5\(", "low"),
                (r"hashlib\.sha1\(", "low"),
                (r"PyCrypto", "medium"),
            ],
        }

    @property
    def metadata(self) -> PluginMetadata:
        """Required plugin metadata for the Auditor core system."""
        return PluginMetadata(
            name="sast_scanner",
            version="1.2.1",
            vendor="DataWizual Lab - Auditor Core",
            description="Hybrid SAST engine: Multi-language Regex + Taint-aware Python AST analysis.",
        )

    def scan(
        self,
        project_path: str,
        files: Optional[List[str]] = None,
        exclude: Optional[List[str]] = None,
    ) -> List[Finding]:
        """
        Performs project-wide static analysis with automated path normalization.
        """
        findings = []
        try:
            # Canonicalize path to prevent Path Traversal during scan
            target_abs = Path(project_path).resolve()

            for root, dirs, files in os.walk(str(target_abs)):
                # Apply directory exclusions
                if exclude:
                    dirs[:] = [d for d in dirs if d not in exclude]

                # Self-analysis protection
                if "auditor" in root:
                    continue

                for file in files:
                    path_obj = Path(root) / file
                    if self._get_language(path_obj) != "unknown":
                        try:
                            with open(
                                path_obj, "r", encoding="utf-8", errors="ignore"
                            ) as f:
                                content = f.read()

                            # Clean relative path for unified reporting
                            rel_path = str(path_obj.relative_to(target_abs)).replace(
                                "\\", "/"
                            )
                            findings.extend(self.scan_file(rel_path, content))
                        except Exception:
                            continue
        except Exception as e:
            logger.error(f"SAST: Failure during project traversal: {e}")

        return findings

    def scan_file(self, file_path: str, content: str) -> List[Finding]:
        """Analyzes a single file using both Regex and AST layers."""
        findings = []
        path_obj = Path(file_path)
        language = self._get_language(path_obj)

        if language == "unknown":
            return findings

        # Layer 1: Regex Pattern Matching (Cross-language)
        lines = content.splitlines()
        for line_num, line in enumerate(lines, 1):
            line_s = line.strip()
            if not line_s or line_s.startswith(("#", "//", "/*")):
                continue

            for category, patterns in self.vulnerability_patterns.items():
                for pattern, severity in patterns:
                    if re.search(pattern, line_s, re.IGNORECASE):
                        findings.append(
                            Finding(
                                rule_id=f"SAST_{category.upper()}",
                                file_path=file_path,
                                line=line_num,
                                description=f"Potential {category.replace('_', ' ')} detected in {language} code.",
                                severity=severity.upper(),
                                cvss_score=0.0,
                                detector="SastScanner",
                            )
                        )

        # Layer 2: AST Analysis (Python specific - High business value)
        if language == "python":
            findings.extend(self._ast_analyze_python(file_path, content))

        return findings

    def _ast_analyze_python(self, file_path: str, content: str) -> List[Finding]:
        """
        Semantic analysis using Python's Abstract Syntax Tree.
        RCA Fix Issue 11: Implements basic Taint Tracking for SQLi.
        """
        ast_findings = []
        try:
            tree = ast.parse(content)

            for func_node in ast.walk(tree):
                if not isinstance(func_node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    continue
                tainted_vars = set()
                for node in ast.walk(func_node):
                    if isinstance(node, ast.Assign):
                        if (
                            isinstance(node.value, ast.Call)
                            and getattr(node.value.func, "id", "") == "input"
                        ):
                            for target in node.targets:
                                if isinstance(target, ast.Name):
                                    tainted_vars.add(target.id)

                # 2. Sink Identification & Analysis
                if isinstance(node, ast.Call):
                    # Check for SQL Injection in execute() calls
                    if (
                        isinstance(node.func, ast.Attribute)
                        and node.func.attr == "execute"
                    ):
                        for arg in node.args:
                            # Detect string concatenation with tainted variables (BinOp)
                            if isinstance(arg, ast.BinOp) and isinstance(
                                arg.op, ast.Add
                            ):
                                for sub_node in ast.walk(arg):
                                    if (
                                        isinstance(sub_node, ast.Name)
                                        and sub_node.id in tainted_vars
                                    ):
                                        ast_findings.append(
                                            Finding(
                                                rule_id="SAST_SQL_INJECTION_AST",
                                                file_path=file_path,
                                                line=node.lineno,
                                                description=f"Confirmed SQL Injection: tainted variable '{sub_node.id}' flows into execute() via concatenation.",
                                                severity="CRITICAL",
                                                cvss_score=9.0,
                                                detector="SastScanner",
                                            )
                                        )

                # Insecure Deserialization Check
                if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
                    if (
                        node.func.attr == "loads"
                        and getattr(node.func.value, "id", "") == "pickle"
                    ):
                        ast_findings.append(
                            Finding(
                                rule_id="SAST_INSECURE_DESERIALIZATION",
                                file_path=file_path,
                                line=node.lineno,
                                description="Critical security risk: Unsafe 'pickle.loads()' detected via AST traversal.",
                                severity="CRITICAL",
                                cvss_score=8.5,
                                detector="SastScanner",
                            )
                        )
        except SyntaxError:
            # Skip malformed Python files
            pass
        except Exception as e:
            logger.debug(f"SAST: AST error in {file_path}: {e}")

        return ast_findings

    def _get_language(self, file_path: Path) -> str:
        """Determines the programming language based on file extension."""
        extension_map = {
            ".py": "python",
            ".js": "javascript",
            ".jsx": "javascript",
            ".ts": "typescript",
            ".tsx": "typescript",
            ".java": "java",
            ".go": "go",
            ".php": "php",
            ".rb": "ruby",
        }
        return extension_map.get(file_path.suffix.lower(), "unknown")
