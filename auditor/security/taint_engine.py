import ast
import os
from pathlib import Path
from typing import Optional

MAX_TAINT_FILE_SIZE = 2 * 1024 * 1024  # 2MB


class TaintEngine:

    def compute_taint(self, finding) -> str:
        """
        Returns: REACHABLE | STATIC_SAFE | EXPLOITABLE | UNKNOWN
        """
        file_path: Optional[str] = getattr(finding, "file_path", None)
        meta = getattr(finding, "meta", {}) or {}
        var_name: Optional[str] = meta.get("variable")  # FIX: dict.get, not getattr

        if not file_path or not Path(file_path).exists():
            return "UNKNOWN"
        if not var_name:
            return "UNKNOWN"

        project_root = Path(file_path).parent
        return self._analyze_file(file_path, var_name, project_root)

    def _analyze_file(self, file_path: str, var_name: str, project_root: Path) -> str:
        try:
            path = Path(file_path)
            if path.stat().st_size > MAX_TAINT_FILE_SIZE:
                return "UNKNOWN"
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                tree = ast.parse(f.read(), filename=file_path)
            analyzer = DeepTaintAnalyzer(var_name, project_root)
            analyzer.visit(tree)
            if not analyzer.found_assignment:
                return "UNKNOWN"
            return "STATIC_SAFE" if analyzer.is_static else "EXPLOITABLE"
        except Exception:
            return "UNKNOWN"


class DeepTaintAnalyzer(ast.NodeVisitor):

    def __init__(self, target_var: str, project_root: Path):
        self.target_var = target_var
        self.project_root = project_root
        self.is_static = True
        self.found_assignment = False

    def check_source(self, node: ast.AST) -> bool:
        dangerous_sources = ["input", "getenv", "argv", "args", "form", "request"]
        code_str = ast.dump(node).lower()
        return any(src in code_str for src in dangerous_sources)

    def visit_Assign(self, node: ast.Assign):
        for target in node.targets:
            if isinstance(target, ast.Name) and target.id == self.target_var:
                self.found_assignment = True
                if self.check_source(node.value):
                    self.is_static = False
                # FIX: removed generic ast.Call branch — too many false positives
        self.generic_visit(node)

    def visit_AugAssign(self, node: ast.AugAssign):
        target = node.target
        if isinstance(target, ast.Name) and target.id == self.target_var:
            self.found_assignment = True
            if self.check_source(node.value):
                self.is_static = False
            # FIX: removed generic ast.Call branch
        self.generic_visit(node)


def analyze_risk_reachability(
    file_path: str, line_max: int, var_name: Optional[str], project_root: Optional[str]
) -> str:
    if not var_name:
        return "UNKNOWN"
    project_root_path = Path(project_root) if project_root else Path(file_path).parent
    engine = TaintEngine()
    return engine._analyze_file(file_path, var_name, project_root_path)
