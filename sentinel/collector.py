import os
import yaml
import logging
from typing import List, Dict


logger = logging.getLogger(__name__)

class ArtifactCollector:
    """
    Scans the project directory and categorizes relevant files for security analysis.
    Synchronized with the organizational ignore list defined in sentinel.yaml.
    """

    def __init__(self, base_path: str, config_path: str = "sentinel.yaml"):
        self.base_path = os.path.abspath(base_path or ".")
        self.config_path = config_path
        self.found_artifacts: Dict[str, List[str]] = {
            "workflows": [],
            "dockerfiles": [],
            "lockfiles": [],
            "infra": [],
            "all_files": [],
            "source_code": [],
        }

        # Load system-level exceptions from the configuration
        self.ignored_patterns = self._load_ignored_patterns()

    def _load_ignored_patterns(self) -> List[str]:
        """Loads ignore patterns from sentinel.yaml to sync with Administrative settings."""
        default_ignore = [
            ".git",
            "node_modules",
            "venv",
            ".venv",
            "dist",
            "build",
            "__pycache__",
            ".egg-info",
        ]
        if not os.path.exists(self.config_path):
            return default_ignore

        try:
            with open(self.config_path, "r", encoding="utf-8") as f:
                raw_content = f.read()
                expanded_content = os.path.expandvars(raw_content)

                conf = yaml.safe_load(expanded_content) or {}

                user_ignore = conf.get("ignore", [])
                clean_user_ignore = [
                    p.replace("/*", "").replace("/", "") for p in user_ignore
                ]
                return list(set(default_ignore + clean_user_ignore))
        except Exception:
            return default_ignore

    def collect(self) -> Dict[str, List[str]]:
        """
        Scans the project filesystem and categorizes artifacts for evaluation.
        Synchronized with the authoritative ignore list.
        """

        for key in self.found_artifacts:
            self.found_artifacts[key] = []

        for root, dirs, files in os.walk(self.base_path):
            dirs[:] = [d for d in dirs if d not in self.ignored_patterns]

            for file in files:
                full_path = os.path.join(root, file)
                rel_path = os.path.relpath(full_path, self.base_path)
                file_lower = file.lower()
                _, ext = os.path.splitext(file_lower)

                if file == "sentinel.yaml" or file == "sentinel_report.html":
                    continue

                self.found_artifacts["all_files"].append(rel_path)

                if ".github/workflows" in root or "gitlab-ci" in file_lower:
                    self.found_artifacts["workflows"].append(rel_path)
                elif "dockerfile" in file_lower or "docker-compose" in file_lower:
                    self.found_artifacts["dockerfiles"].append(rel_path)
                elif file in [
                    "package-lock.json",
                    "poetry.lock",
                    "go.sum",
                    "requirements.txt",
                    "pnpm-lock.yaml",
                ]:
                    self.found_artifacts["lockfiles"].append(rel_path)
                elif ext in [".tf", ".tfvars", ".hcl"]:
                    self.found_artifacts["infra"].append(rel_path)
                elif ext in [".yaml", ".yml"]:
                    infra_keywords = [
                        "pod",
                        "deployment",
                        "service",
                        "ingress",
                        "aws_",
                        "google_",
                        "azurerm_",
                        "cluster",
                        "playbook",
                        "chart",
                        "k8s",
                    ]
                    if any(key in file_lower for key in infra_keywords):
                        self.found_artifacts["infra"].append(rel_path)
                elif ext in [".sol", ".ts", ".js", ".tsx", ".jsx", ".py", ".rs", ".go"]:
                    self.found_artifacts["source_code"].append(rel_path)

        return self.found_artifacts

    def get_content(self, relative_path: str) -> str:
        """
        [Sentinel V2] Hardened content reader with Path Traversal protection 
        and Binary visibility.
        """
        # RCA Fix: Use realpath to resolve symlinks before checking bounds
        full_path = os.path.join(self.base_path, relative_path)
        real_target = os.path.realpath(full_path)
        real_base = os.path.realpath(self.base_path)

        if not real_target.startswith(real_base):
            logger.error(f"🛡️ Security Alert: Path traversal attempt blocked: {relative_path}")
            return ""

        if not os.path.exists(real_target) or os.path.isdir(real_target):
            return ""

        try:
            # RCA Fix: Attempt strict read first to detect binary/encoded files
            with open(real_target, "r", encoding="utf-8") as f:
                return f.read()
        except UnicodeDecodeError:
            # RCA Fix: Log binary files instead of silently ignoring via 'errors=ignore'
            logger.debug(f"ℹ️ Skipping binary/encoded artifact: {relative_path}")
            return ""
        except Exception as e:
            logger.warning(f"⚠️ Failed to read artifact {relative_path}: {e}")
            return ""
