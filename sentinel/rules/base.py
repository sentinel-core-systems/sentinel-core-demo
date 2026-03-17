import os
import yaml
import logging
from abc import ABC, abstractmethod
from typing import List, Dict


logger = logging.getLogger("sentinel.rules")

class BaseRule(ABC):
    """
    Base architectural contract for all Sentinel security rules.
    Every rule must inherit from this class to ensure Engine compatibility
    and dynamic discovery.
    """

    def __init__(self):
        # RULE IDENTITY: Must match the IDs in Engine's IMMUTABLE_RULES (e.g., SEC-001)
        self.id: str = "GENERIC"
        self.severity: str = "BLOCK" # RCA: Restored default
        self.cwe_id: str = "CWE-000"
        self.description: str = "Security policy description"
        self.rationale: str = "Standard remediation and mitigation steps"

    @abstractmethod
    def check(self, artifacts: Dict[str, List[str]]) -> List[str]:
        """
        Executes the rule-specific evaluation logic.

        Args:
            artifacts: Dictionary of categorized files from the ArtifactCollector.

        Returns:
            A list of strings describing detected violations.
        """
        pass

    def read_file(self, file_path: str) -> str:
        """
        [Sentinel V2] Strict file reader with failure visibility.
        """
        try:
            if not os.path.exists(file_path):
                return ""
            
            # RCA Fix: Remove errors="ignore". We need to know if the file is binary/corrupted.
            with open(file_path, "r", encoding="utf-8") as f:
                return f.read()
        except UnicodeDecodeError:
            # RCA Fix: Explicit log for binary/unsupported encoding
            logger.debug(f"Skipping non-UTF8/binary file: {file_path}")
            return ""
        except Exception as e:
            logger.warning(f"Error reading {file_path}: {e}")
            return ""

    def load_yaml(self, file_path: str) -> dict:
        """
        [Sentinel V2] YAML loader with structural integrity check.
        """
        content = self.read_file(file_path)
        if not content:
            return {}
        try:
            return yaml.safe_load(content) or {}
        except yaml.YAMLError as e:
            # RCA Fix: Notify about malformed YAML. This is a security risk (shadow config).
            logger.error(f"❌ Structural Integrity Error in {file_path}: {e}")
            return {}
        except Exception as e:
            logger.warning(f"Unexpected error parsing YAML {file_path}: {e}")
            return {}

    def __repr__(self):
        # RCA Fix: Added safe getattr to prevent crashes if severity is missing
        sev = getattr(self, "severity", "UNKNOWN")
        return f"<{self.id} [{sev}]>"
