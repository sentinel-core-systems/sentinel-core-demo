"""
Plugin Base Definitions - Auditor Core.
Provides standardized interfaces for Detectors and Policy engines.
"""

import logging
import re
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Iterable, Any, List, Optional

# Standard internal import for cross-plugin consistency
from auditor.core.engine import Finding

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class PluginMetadata:
    """
    Immutable metadata for full traceability with automated sanitization.
    Ensures that plugin identity cannot be spoofed or used for injection.
    """

    name: str
    version: str
    vendor: str
    description: str
    signature: Optional[str] = None

    def __post_init__(self):
        # RCA Fix: Protection against Log Injection.
        # Sanitizes plugin name to allow only alphanumeric, underscores, and hyphens.
        if not re.match(r"^[a-zA-Z0-9_\-]+$", self.name):
            object.__setattr__(self, "name", re.sub(r"[^a-zA-Z0-9_\-]", "_", self.name))


class DetectorPlugin(ABC):

    def __init__(self):
        # RCA Fix: Secure logger initialization.
        # Fallback to class name if metadata is corrupted or missing during init.
        try:
            name = self.metadata.name
            if self.metadata.vendor != "DataWizual Lab - Auditor Core":
                logging.getLogger("auditor.core").warning(
                    f"Core: Initializing unverified third-party plugin from vendor: {self.metadata.vendor}"
                )
        except Exception:
            name = self.__class__.__name__.lower()
            logging.getLogger("auditor.core").warning(
                f"Core: Plugin {self.__class__.__name__} provided invalid metadata. Falling back to class name."
            )

        self.logger = logging.getLogger(f"auditor.plugin.{name}")
        self.start_time = 0.0
        self.timeout = 0.0

    def set_budget(self, timeout: float):
        """Sets the execution time limit before scanning starts."""
        self.start_time = time.time()
        self.timeout = timeout

    def is_budget_exceeded(self) -> bool:
        """
        RCA Fix Issue 20: Time-budgeting check.
        Plugins must call this within loops to prevent system-wide DoS during heavy analysis.
        """
        if self.timeout <= 0:
            return False

        elapsed = time.time() - self.start_time
        if elapsed > self.timeout:
            self.logger.error(
                f"Plugin execution aborted: Global scan budget exceeded ({self.timeout}s)."
            )
            return True
        return False

    @property
    @abstractmethod
    def metadata(self) -> PluginMetadata:
        """Returns the immutable metadata of the plugin."""
        pass

    @abstractmethod
    def scan(
        self,
        project_path: str,
        files: Optional[List[str]] = None,
        exclude: Optional[List[str]] = None,
    ) -> List[Finding]:
        """
        Unified scanning interface for all detectors.

        project_path: root of the project
        files: optional list of specific files to scan
        exclude: optional exclusion patterns
        """
        raise NotImplementedError

    def scan_file(self, file_path: str, content: str) -> List[Finding]:
        """
        Optional entry point for single-file analysis.
        """
        return []

    # RCA: Helper to ensure all findings from this plugin have the correct 'detector' field
    def _enrich_finding(self, finding: Finding) -> Finding:
        if finding.detector == "unknown":
            return finding.model_copy(update={"detector": self.metadata.name})
        return finding


class PolicyPlugin(ABC):
    """
    Base class for reporting, decision-making, and post-processing plugins.
    Used for filtering results or generating final audit reports.
    """

    @property
    @abstractmethod
    def metadata(self) -> PluginMetadata:
        """Returns the immutable metadata of the policy plugin."""
        pass

    @abstractmethod
    def evaluate(self, findings: Iterable[Finding]) -> Any:
        """Process findings to generate a report or make a pass/fail decision."""
        pass
