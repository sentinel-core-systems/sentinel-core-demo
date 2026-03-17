"""
Block 0: Intake Manager.
Handles file collection, Trust Boundary verification, and exclusion filtering.
Synchronized with strict English coding standards.
"""

import os
import logging
import fnmatch
import tempfile
import subprocess
import shutil
from pathlib import Path
from urllib.parse import urlparse
from typing import List, Dict, Any, Tuple, Callable

logger = logging.getLogger(__name__)


class FileIntake:
    """
    Manages the initial phase of the audit by collecting and filtering target files.
    Supports local directories and remote Git repositories.
    """

    def __init__(self, config: Dict[str, Any]):
        # Configuration initialization from YAML/Env
        self.config = config or {}
        self.base_dir = None

        # Extract scanner constraints
        scanner_cfg = self.config.get("scanner", {})
        self.max_size = scanner_cfg.get("max_file_size", 1048576)  # Default: 1MB

        default_excludes = [
            "venv/*",
            "node_modules/*",
            ".git/*",
            "__pycache__/*",
            "reports/*",
            "dist/*",
            "build/*",
            "*.pyc",
            ".idea/*",
            ".vscode/*",
            "**/testdata/*",
            "**/fixtures/*",
            "**/mocks/*",
            "**/examples/*",
        ]

        user_excludes = scanner_cfg.get("exclude", [])
        self.exclude_patterns = list(set(default_excludes + user_excludes))

        # Supported file extensions for static analysis
        allowed_exts = scanner_cfg.get("file_types", [])
        if allowed_exts:
            self.file_types = {ext.lower() for ext in allowed_exts}
        else:
            self.file_types = {
                ".py",
                ".js",
                ".ts",
                ".json",
                ".yaml",
                ".yml",
                ".sql",
                ".go",
                ".rs",
                ".php",
                ".sh",
                ".bat",
            }

    def _validate_git_url(self, url: str) -> bool:
        """Validate that the URL is a safe remote git target."""
        try:
            parsed = urlparse(url)
            if parsed.scheme in ("file", ""):
                return False
            if parsed.scheme in ("http", "https"):
                return bool(parsed.netloc)
            if url.startswith("git@"):
                return True
            return False
        except Exception:
            return False

    def prepare_target(self, target: str) -> Tuple[str, Callable]:
        """
        Prepares the scan target. If a URL is provided, it clones the repository.
        Returns the working directory path and a cleanup callback.
        """
        temp_dir = None
        try:
            if target.startswith(("http://", "https://", "git@")):
                if not shutil.which("git"):
                    raise RuntimeError(
                        "System Error: 'git' is not installed or not in PATH."
                    )

                # ✅ FIX: validate URL before passing to subprocess
                if not self._validate_git_url(target):
                    raise ValueError(f"Unsafe or invalid git URL rejected: {target}")

                logger.info(
                    f"External target detected: {target}. Cloning repository..."
                )
                temp_dir = tempfile.mkdtemp(prefix="auditor_scan_")

                subprocess.check_call(
                    ["git", "clone", "--depth", "1", target, temp_dir],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.STDOUT,
                )
                work_dir = temp_dir
            else:
                work_dir = str(Path(target).resolve())

            def cleanup():
                if temp_dir and os.path.exists(temp_dir):
                    logger.debug(f"Cleaning up temporary directory: {temp_dir}")
                    shutil.rmtree(temp_dir)

            return work_dir, cleanup
        except Exception as e:
            if temp_dir and os.path.exists(temp_dir):
                shutil.rmtree(temp_dir)
            logger.error(f"Failed to prepare scan target: {e}")
            raise e

    def collect(self, target_path: str) -> List[Path]:
        path = Path(target_path)
        self.base_dir = path if path.is_dir() else path.parent  # FIX: set base_dir
        collected = []
        if path.is_file():
            if self._is_allowed(path):
                return [path]
            else:
                logger.warning(f"File type not allowed: {path.suffix}")
                return []
        if path.is_dir():
            for p in path.rglob("*"):
                if p.is_file() and self._is_allowed(p):
                    collected.append(p)
        logger.info(f"Intake: Successfully collected {len(collected)} files.")
        return collected

    def _is_excluded(self, path: Path) -> bool:
        try:
            rel_path = str(path.relative_to(self.base_dir)).replace("\\", "/").lower()
            hard_excludes = [
                ".git/",
                "node_modules/",
                "venv/",
                "__pycache__/",
                "dist/",
                "build/",
            ]
            if any(zone in rel_path for zone in hard_excludes):
                return True
            # Apply user-configured and default patterns
            for pattern in self.exclude_patterns:
                if fnmatch.fnmatch(rel_path, pattern.lower()):
                    return True
            return False
        except Exception:
            return True

    def _is_allowed(self, path: Path) -> bool:
        try:
            if path.stat().st_size > self.max_size:
                return False

            if self._is_excluded(path):
                return False

            suffix = path.suffix.lower()
            return suffix in self.file_types

        except Exception:
            return False