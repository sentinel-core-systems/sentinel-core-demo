import yaml
import logging
from typing import List, Dict
from sentinel.rules.base import BaseRule


logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("SentinelCore")


class K8sSecurityRule(BaseRule):
    """
    Enforces Kubernetes security best practices for pod specifications.
    """

    def __init__(self):
        super().__init__()
        # FIX: Separate ID to avoid conflict with INFRA-001 in IMMUTABLE_RULES
        # INFRA-001 is reserved for Terraform (terraform_security.py)
        self.id = "INFRA-K8S-001"
        # self.severity = "BLOCK"
        self.cwe_id = "CWE-250"
        self.description = "Audits K8s manifests for 'runAsNonRoot' and resource limits."
        self.rationale = "Privileged containers and missing limits risk host takeover or DoS."

    def check(self, artifacts: Dict[str, List[str]]) -> List[str]:
        if not isinstance(artifacts, dict) or "infra" not in artifacts:
            return []

        violations = []
        infra_files = artifacts.get("infra", [])

        for path in infra_files:
            content_str = self.read_file(path)
            if not content_str:
                continue

            try:
                docs = yaml.safe_load_all(content_str)

                for doc in docs:
                    if not isinstance(doc, dict) or "kind" not in doc:
                        continue

                    spec = self._get_pod_spec(doc)
                    if not spec:
                        continue

                    pod_sec_ctx = spec.get("securityContext", {}) or {}
                    pod_non_root = pod_sec_ctx.get("runAsNonRoot", False)

                    containers = spec.get("containers", [])
                    if not isinstance(containers, list):
                        continue

                    for container in containers:
                        c_name = container.get("name", "unknown")
                        c_sec_ctx = container.get("securityContext", {}) or {}
                        run_as_non_root = c_sec_ctx.get("runAsNonRoot", pod_non_root)

                        if not run_as_non_root:
                            violations.append(
                                f"INFRA-K8S-001: K8s Security Risk in {path}. "
                                f"Container '{c_name}' must set 'runAsNonRoot: true'."
                            )

                        resources = container.get("resources", {}) or {}
                        if not resources or "limits" not in resources:
                            violations.append(
                                f"INFRA-K8S-001: K8s Resource Risk in {path}. "
                                f"Missing CPU/Memory limits for container '{c_name}'."
                            )

            except yaml.YAMLError as e:
                logger.error(f"Failed to parse YAML in {path}: {e}")
                continue
            except Exception as e:  # FIX: added 'as e' - previously e was undefined
                logger.error(f"Unexpected error during K8s scan of {path}: {e}")
                continue

        return violations

    def _get_pod_spec(self, doc: dict) -> dict:
        kind = doc.get("kind")
        if kind == "Pod":
            return doc.get("spec")

        controllers = [
            "Deployment", "StatefulSet", "DaemonSet",
            "Job", "ReplicaSet", "CronJob",
        ]
        if kind in controllers:
            spec = doc.get("spec", {})
            if kind == "CronJob":
                template = spec.get("jobTemplate", {}).get("spec", {}).get("template", {})
            else:
                template = spec.get("template", {})
            return template.get("spec")
        return None