"""
Secret Detector - Auditor Secrets Suite.
High-performance secrets scanner with recursion control and entropy analysis.
"""

import re
import os
import math
import logging
from pathlib import Path
from typing import List, Optional, Dict

from auditor.detectors.plugin_base import DetectorPlugin, PluginMetadata
from auditor.core.engine import Finding

logger = logging.getLogger(__name__)


class SecretDetector(DetectorPlugin):
    """
    Advanced secrets detector utilizing regex patterns and Shannon entropy.
    Hardened against path traversal and recursive DoS attacks.
    """

    def __init__(self):
        super().__init__()
        self.name = "SecretDetector"

        # RCA Fix Issue 25: Pre-compiled regex patterns for performance optimization
        self.compiled_patterns = {
            "aws_key": re.compile(r"AKIA[0-9A-Z]{16}"),
            "slack_token": re.compile(r"xox[bapz]-[0-9]{12}-[0-9]{12}-[a-zA-Z0-9]{24}"),
            "private_key": re.compile(r"-----BEGIN .* PRIVATE KEY-----"),
            "generic_secret": re.compile(
                r"(?i)(api_key|secret|password|token)[^a-z0-9]{1,3}['\"]([a-zA-Z0-9_\-\.]{8,})['\"]"
            ),
        }

        # Noise reduction patterns (UUIDs and hex hashes usually aren't actionable secrets)
        self.uuid_pattern = re.compile(r"^[a-fA-F0-9-]{36}$")
        self.hash_pattern = re.compile(r"^[a-fA-F0-9]{32,64}$")

        self.fp_hints = ["example", "mock", "dummy", "placeholder", "todo"]
        entropy_cache: Dict[str, float] = {}

        # Self-analysis protection path (RCA Issue 23)
        self.auditor_root = str(Path(__file__).resolve().parent.parent)

    def _calculate_entropy(self, data: str) -> float:
        """Calculates Shannon entropy to identify high-randomness strings."""
        if not data or len(data) > 512:
            return 0
        if data in self._entropy_cache:
            return self._entropy_cache[data]

        # Optimized O(N) calculation
        prob = [float(data.count(c)) / len(data) for c in dict.fromkeys(data)]
        entropy = -sum([p * math.log2(p) for p in prob])

        if len(self._entropy_cache) < 1000:
            self._entropy_cache[data] = entropy
        return entropy

    @property
    def metadata(self) -> PluginMetadata:
        """Metadata for the secrets detection plugin."""
        return PluginMetadata(
            name="SecretDetector",
            version="1.6.0",
            vendor="DataWizual Lab - Auditor Core",
            description="High-performance secret scanner with recursion control and path hardening.",
        )

    def scan(
        self,
        project_path: str,
        files: Optional[List[str]] = None,
        exclude: Optional[List[str]] = None,
    ) -> List[Finding]:
        """
        Project-wide secrets scan with recursion depth limiting and exclusion support.
        """
        findings = []
        target_abs = Path(project_path).resolve()
        entropy_cache: Dict[str, float] = {}

        # RCA Fix Issue 22: Prepare exclusion absolute paths
        abs_excludes = []
        if exclude:
            abs_excludes = [str(Path(target_abs / e).resolve()) for e in exclude]

        for root_dir, dirs, files in os.walk(str(target_abs)):
            # RCA Fix Issue 21: Recursion depth limit to prevent system DoS
            depth = len(Path(root_dir).relative_to(target_abs).parts)
            if depth > 20:
                dirs[:] = []  # Stop recursion
                logger.warning(f"Secrets: Max recursion depth reached at {root_dir}")
                continue

            # RCA Fix Issue 22: Reliable folder filtering by full path
            if exclude:
                dirs[:] = [
                    d for d in dirs if str(Path(root_dir) / d) not in abs_excludes
                ]

            # RCA Fix Issue 23: Self-analysis protection
            if root_dir.startswith(self.auditor_root):
                continue

            for file in files:
                full_path = Path(root_dir) / file
                try:
                    # Ignore massive files to save memory
                    if full_path.stat().st_size > 512 * 1024:
                        continue

                    rel_path = str(full_path.relative_to(target_abs)).replace("\\", "/")

                    with open(full_path, "r", encoding="utf-8", errors="ignore") as f:
                        for i, line in enumerate(f, 1):
                            if (
                                len(line) > 2000
                            ):  # Skip unusually long lines (likely minified)
                                continue

                            clean_line = line.strip()
                            if len(clean_line) < 10:
                                continue

                            # 1. Pattern Matching (Fast layer)
                            found_by_pattern = False
                            for rule_id, compiled_re in self.compiled_patterns.items():
                                if compiled_re.search(clean_line):
                                    findings.append(
                                        Finding(
                                            rule_id=f"SECRET_{rule_id.upper()}",
                                            severity="HIGH",
                                            file_path=rel_path,
                                            line=i,
                                            description=f"Potential secret pattern matched: {rule_id}",
                                            cvss_score=7.5,
                                            detector="SecretDetector",
                                        )
                                    )
                                    found_by_pattern = True
                                    break

                            # 2. Entropy Analysis (Deeper layer for unknown tokens)
                            if not found_by_pattern:
                                # RCA: Optimization - only check tokens if line doesn't contain test hints
                                if any(
                                    hint in clean_line.lower() for hint in self.fp_hints
                                ):
                                    continue

                                potential_tokens = re.findall(
                                    r"['\"]([a-zA-Z0-9_\-\.]{16,64})['\"]", clean_line
                                )
                                for token in potential_tokens:
                                    # RCA Fix Issue 26: Robust filtering of non-secret hex/uuids
                                    if self.uuid_pattern.match(
                                        token
                                    ) or self.hash_pattern.match(token):
                                        continue

                                    # Context check
                                    context_match = any(
                                        k in clean_line.lower()
                                        for k in [
                                            "key",
                                            "secret",
                                            "token",
                                            "pwd",
                                            "auth",
                                            "api",
                                            "pass",
                                        ]
                                    )

                                    # RCA: Refined entropy threshold to 4.0 for better signal-to-noise ratio
                                    token_entropy = self._calculate_entropy(token)
                                    if context_match and token_entropy > 4.0:
                                        findings.append(
                                            Finding(
                                                rule_id="SECRET_HIGH_ENTROPY",
                                                severity="MEDIUM",
                                                file_path=rel_path,
                                                line=i,
                                                description=f"High entropy string detected in sensitive context (Entropy: {token_entropy:.2f})",
                                                cvss_score=5.0,
                                                detector="SecretDetector",
                                            )
                                        )
                except Exception as e:
                    # RCA Fix Issue 24: Log access errors for visibility
                    logger.debug(f"Secrets: Could not scan file {full_path}: {e}")
                    continue
        return findings

    def scan_file(self, file_path: str, content: str) -> List[Finding]:
        """Bulk scanning is preferred for secrets detection; this method is a placeholder."""
        return []
