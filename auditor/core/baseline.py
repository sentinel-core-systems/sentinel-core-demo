"""
Baseline Engine - Auditor Core.
Handles suppression of known findings and semantic correlation.
"""

import os
import json
import logging
import hashlib
from datetime import datetime
from pathlib import Path
from typing import List, Set, Any, Union, Optional, Dict

from auditor.core.engine import Finding

logger = logging.getLogger(__name__)


class BaselineEngine:
    """
    Handles the 'Known Facts' database and correlates findings without data loss.
    """

    def __init__(self, baseline_path: str = "baseline.json"):
        try:
            allowed_root = Path.cwd().resolve()
            resolved = Path(baseline_path).resolve()
            allowed_prefix = str(allowed_root) + os.sep
            if not (
                str(resolved) == str(allowed_root)
                or str(resolved).startswith(allowed_prefix)
            ):
                raise ValueError("Baseline path outside trust boundary")
            self.baseline_path = resolved
        except Exception:
            self.baseline_path = Path("baseline.json")

        self.known_fingerprints: Set[str] = set()
        self._load_baseline()

    def _generate_fingerprint(self, rule_id: str, file_path: str, line: int) -> str:
        """
        Fingerprint based on rule + path + line.
        Snippet stored in JSON for human reference only, not used in fingerprint
        to ensure stability across minor code changes.
        """
        norm_path = str(file_path).replace("\\", "/").strip("/")
        data = f"{rule_id}:{norm_path}:{line}"
        return hashlib.sha256(data.encode()).hexdigest()

    def _load_baseline(self) -> None:
        if not self.baseline_path.exists():
            return
        try:
            if self.baseline_path.stat().st_size > 10 * 1024 * 1024:
                logger.error("Baseline: File too large (DoS limit exceeded).")
                return
            with open(self.baseline_path, "r", encoding="utf-8") as f:
                data = json.load(f)
                findings = data.get("findings", [])
                for entry in findings:
                    fp = entry.get("fingerprint")
                    if fp:
                        self.known_fingerprints.add(fp)
                    else:
                        legacy_fp = self._generate_fingerprint(
                            str(entry.get("rule_id", "")),
                            str(entry.get("file_path", "")),
                            int(entry.get("line", 0) or 0),
                        )
                        self.known_fingerprints.add(legacy_fp)
            logger.info(f"Baseline: Loaded {len(self.known_fingerprints)} entries.")
        except (json.JSONDecodeError, KeyError):
            logger.error("Baseline: Failed to parse JSON or invalid format.")
        except Exception as e:
            logger.exception("Baseline load failed: %s", e)

    def is_baselined(self, finding: Union[Finding, dict]) -> bool:
        try:
            if isinstance(finding, dict):
                rule_id = finding.get("rule_id", "")
                file_path = finding.get("file_path", "")
                line = int(finding.get("line", 0) or 0)
            else:
                rule_id = finding.rule_id
                file_path = finding.file_path
                line = finding.line
            current_fp = self._generate_fingerprint(rule_id, file_path, line)
            return current_fp in self.known_fingerprints
        except Exception:
            return False

    def correlate(self, findings: List[Finding]) -> List[Finding]:
        path_map: Dict[str, List[Finding]] = {}
        for f in findings:
            path = str(f.file_path).replace("\\", "/")
            path_map.setdefault(path, []).append(f)

        for path, cluster in path_map.items():
            path_lower = path.lower()
            is_noise_path = any(
                x in path_lower
                for x in ["/test", "/fixture", "/mock", "test_", "/example", "/sample"]
            )
            if is_noise_path:
                continue
            high_risks = [f for f in cluster if f.severity in ["CRITICAL", "HIGH"]]
            if len(high_risks) >= 2 or len(cluster) >= 5:
                tag_hash = hashlib.sha256(path.encode()).hexdigest()[:12]
                for f in cluster:
                    f.meta.update(
                        {
                            "hotspot": True,
                            "cluster_size": len(cluster),
                            "correlation_tag": f"HOTSPOT-{tag_hash}",
                        }
                    )
        return findings

    def write_baseline(
        self, findings: List[Finding], output_dir: Optional[str] = None
    ) -> None:
        if output_dir:
            try:
                target_dir = Path(output_dir).resolve()
                final_path = (target_dir / "baseline.json").resolve()
                allowed_prefix = str(target_dir) + os.sep
                if not (
                    str(final_path) == str(target_dir)
                    or str(final_path).startswith(allowed_prefix)
                ):
                    return
            except Exception:
                return
        else:
            final_path = self.baseline_path

        final_path.parent.mkdir(parents=True, exist_ok=True)

        baseline_data = {
            "version": 3,
            "generated_at": datetime.utcnow().isoformat(),
            "findings": [],
        }
        for f in findings:
            fp = self._generate_fingerprint(f.rule_id, f.file_path, f.line)
            baseline_data["findings"].append(
                {
                    "rule_id": f.rule_id,
                    "file_path": f.file_path,
                    "line": f.line,
                    "snippet": getattr(f, "line_content", "")[:50],
                    "fingerprint": fp,
                }
            )

        tmp_path = final_path.with_suffix(".tmp")
        try:
            with open(tmp_path, "w", encoding="utf-8") as fh:
                json.dump(baseline_data, fh, indent=2, ensure_ascii=False)
            tmp_path.replace(final_path)
            logger.info(f"Baseline written to {final_path}")
        except Exception as e:
            logger.error(f"Baseline write failed: {e}")
            raise
        finally:
            if tmp_path.exists():
                tmp_path.unlink()
