import logging
import requests
import json
import re
from typing import List, Dict, Any
from auditor.ai.base import AIAdvisor
from auditor.ai.rule_based import RuleBasedAdvisor

# English only logging configuration
logger = logging.getLogger(__name__)


class LocalLLMAdvisor(AIAdvisor):
    """
    Adapter for local LLM inference (e.g., via Ollama).
    Maintains complete data privacy by processing findings locally.
    """

    def __init__(self, config: Dict[str, Any]):
        # Extract configurations from the 'ai' -> 'local' section
        ai_cfg = config.get("ai", {})
        local_cfg = ai_cfg.get("local", {})

        self.model = local_cfg.get("model", "mistral")
        self.endpoint = local_cfg.get("endpoint", "http://localhost:11434/api/generate")
        self.timeout = ai_cfg.get("timeout_sec", 60)
        self.fallback_advisor = RuleBasedAdvisor()

    def generate_recommendations(self, findings: List[Any], **kwargs) -> List[Dict]:
        """
        Requests remediation advice from a local LLM instance.
        Fails over to rule-based logic if the service is unreachable.
        """
        if not findings:
            return []

        try:
            logger.info(
                f"⚙️ Local Expert Engine: Analyzing {len(findings)} issues using {self.model}..."
            )

            # Focus on top 20 findings to prevent context window overflow
            target_findings = findings[:20]
            prompt = self._build_offline_prompt(target_findings)

            response = requests.post(
                self.endpoint,
                json={
                    "model": self.model,
                    "prompt": prompt,
                    "stream": False,
                    "format": "json",  # Forces Ollama to return structured data
                },
                timeout=(10, self.timeout),
            )
            response.raise_for_status()

            raw_response = response.json().get("response", "")
            results = self._parse_local_response(raw_response)

            if results:
                return results

            return self.fallback_advisor.generate_recommendations(findings)

        except Exception as e:
            logger.warning(
                f"⚠️ Local LLM service error: {e}. Switching to deterministic fallback."
            )
            return self.fallback_advisor.generate_recommendations(findings)

    def _build_offline_prompt(self, findings: List[Any]) -> str:
        """Creates a structured prompt for local inference engines."""
        data = [{"id": str(f.id), "desc": f.description} for f in findings]
        return (
            "SYSTEM: You are a Cyber Security Expert. Analyze the following findings and provide remediation advice.\n"
            "INSTRUCTION: Return ONLY a JSON array of objects with 'finding_id' and 'advice' keys.\n"
            f"DATA: {json.dumps(data)}"
        )

    def _parse_local_response(self, text: str) -> List[Dict]:
        try:
            # Strip markdown code fences if model wraps response
            clean = re.sub(
                r"^```(?:json)?\s*|\s*```$", "", text.strip(), flags=re.DOTALL
            )
            # Try to extract JSON array if there's surrounding text
            match = re.search(r"\[.*\]", clean, re.DOTALL)
            if match:
                clean = match.group(0)
            result = json.loads(clean)
            if not isinstance(result, list):
                logger.error("Local LLM returned JSON but not an array.")
                return []
            return result
        except (json.JSONDecodeError, TypeError) as e:
            logger.error(
                f"Failed to parse local advisory data: {e}. Raw text: {text[:200]!r}"
            )
            return []
