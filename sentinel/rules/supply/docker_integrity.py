from typing import List, Dict
from sentinel.rules.base import BaseRule


class DockerIntegrityRule(BaseRule):
    def __init__(self):
        super().__init__()
        self.id = "SUPPLY-001"
        self.severity = "BLOCK"
        self.cwe_id = "CWE-494"
        self.description = "Prohibition of mutable ':latest' image tags."
        self.rationale = "Using ':latest' leads to unpredictable builds. Use fixed tags or digests."

    def check(self, artifacts: Dict[str, List[str]]) -> List[str]:
        violations = []
        dockerfiles = artifacts.get("dockerfiles", [])

        for path in dockerfiles:
            content = self.read_file(path)
            if not content:
                continue

            # RCA Fix: Track aliases to avoid False Positives in multi-stage builds
            stage_aliases = set()
            lines = content.splitlines()

            for line_num, line in enumerate(lines, 1):
                clean_line = line.strip()
                if not clean_line.upper().startswith("FROM"):
                    continue

                parts = clean_line.split()
                image_name = ""
                
                # Find image name (skip --platform flags)
                for i, part in enumerate(parts):
                    if part.upper() == "FROM":
                        for j in range(i + 1, len(parts)):
                            if not parts[j].startswith("--"):
                                image_name = parts[j] # Preserve case for alias
                                break
                        break

                if not image_name or image_name.lower() == "scratch":
                    continue

                # RCA Fix: Handle 'AS' keyword to register aliases
                # FROM python:3.9 AS builder -> 'builder' is now a valid internal reference
                upper_parts = [p.upper() for p in parts]
                if "AS" in upper_parts:
                    as_index = upper_parts.index("AS")
                    if as_index + 1 < len(parts):
                        stage_aliases.add(parts[as_index + 1])

                # RCA Fix: If image_name is a known alias, it's NOT a supply chain risk
                if image_name in stage_aliases:
                    continue

                img_lower = image_name.lower()
                
                # RCA Fix: Improved logic for tags vs ports in private registries
                # Tag is absent if the last path segment contains no ':' or '@'
                # Example: my-registry:5000/image -> no tag (colon is not at the end)
                
                has_digest = "@sha256:" in img_lower
                
                # Look for tag colon: it must appear after the last slash (if any)
                last_slash = img_lower.rfind('/')
                last_colon = img_lower.rfind(':')
                
                is_latest = ":latest" in img_lower
                # If colon appears after last slash - it is a tag. If absent - no tag.
                has_tag = last_colon > last_slash

                if is_latest or (not has_tag and not has_digest):
                    violations.append(
                        f"SUPPLY-001: Mutable image tag '{image_name}' detected in {path} at line {line_num}. "
                        f"Action: Pin the image to a specific version tag or a SHA-256 digest."
                    )

        return violations