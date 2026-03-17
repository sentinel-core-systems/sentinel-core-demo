import logging
from abc import ABC, abstractmethod
from typing import List, Dict, Any, Optional
from auditor.core.engine import Finding

# Initialize logger for base class if needed by subclasses
logger = logging.getLogger(__name__)


class AIAdvisor(ABC):

    @abstractmethod
    def generate_recommendations(
        self, findings: List[Finding], context: Optional[Dict[str, Any]] = None
    ) -> List[Dict[str, Any]]:
        """
        Processes security findings and returns actionable remediation advice.

        Args:
            findings: List of identified security issues.
            context: Additional metadata (e.g., repository URL, branch).

        Returns:
            A list of recommendation objects containing 'finding_id' and 'advice'.
            This layer does NOT alter severity levels or influence gate decisions.
        """
        pass
