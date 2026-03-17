import re
from typing import List, Dict
from sentinel.rules.base import BaseRule


class GithubActionPinningRule(BaseRule):
    """
    Enforces security best practices for GitHub Actions by requiring full commit SHA pinning.
    Protects the CI/CD pipeline against supply chain attacks via mutable version tags.
    """

    def __init__(self):
        super().__init__()
        self.id = "CICD-001"
        # self.severity = "BLOCK"
        self.cwe_id = "CWE-1104"
        self.description = (
            "Ensures GitHub Actions are pinned to an immutable 40-character commit SHA."
        )
        self.rationale = "Tags (like @v1) can be moved by attackers. Only a SHA ensures code integrity."

    def check(self, artifacts: Dict[str, List[str]]) -> List[str]:
        violations = []
        workflow_files = artifacts.get("workflows", [])

        for path in workflow_files:
            content = self.load_yaml(path)
            if not content or not isinstance(content, dict):
                continue

            jobs = content.get("jobs", {})
            if not isinstance(jobs, dict):
                continue

            for job_id, job_data in jobs.items():
                if not isinstance(job_data, dict):
                    continue

                steps = job_data.get("steps", [])
                if not isinstance(steps, list):
                    continue

                for step in steps:
                    if not isinstance(step, dict):
                        continue

                    action = step.get("uses")

                    if (
                        not action
                        or not isinstance(action, str)
                        or action.startswith("./")
                        or action.startswith("docker://")
                    ):
                        continue

                    if "@" in action:
                        name, version = action.split("@", 1)
                        if not re.match(r"^[0-9a-f]{40}$", version):
                            # FIX: ID in violation line matches self.id
                            violations.append(
                                f"CICD-001: Unpinned action '{action}' in job '{job_id}' ({path}). "
                                f"Current version: '{version}'. Required: 40-character SHA."
                            )
                    else:
                        violations.append(
                            f"CICD-001: Action '{action}' in {path} (job: {job_id}) is missing a version pin."
                        )

        return violations