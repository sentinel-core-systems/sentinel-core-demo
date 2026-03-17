import os
import re
import logging

logger = logging.getLogger(__name__)


class IntelligenceEngine:
    def __init__(self, project_root):
        self.project_root = project_root
        self.block_markers = [
            # Python, JS function, classes, and DevOps tools
            r"(?i)(func|def|function|class|task|job|procedure|step|const|let|var)\s+([\w\-\.]+)",
            # YAML/JSON/Config structures
            r"^(\s*)([\w\-\.]+):",
            # Bash, C, and classic JS: function name() {
            r"([\w\-\.]+)\s*\(\)\s*\{",
            # JS: name = function... or name = (...) =>
            r"([\w\-\.]+)\s*=\s*(?:function|\([^)]*\)\s*=>)",
        ]
        # Dangerous functions tracked for call-count analysis
        self.danger_functions = ["eval", "exec", "os.system", "subprocess.run"]

    def _get_indent(self, line):
        return len(line) - len(line.lstrip())

    def _quick_extract_name(self, line):
        """
        Extracts the function, class, or task name from a block signature line.
        """
        line = line.strip()
        for pattern in self.block_markers:
            match = re.search(pattern, line)
            if match:
                groups = match.groups()
                if len(groups) >= 2:
                    return groups[1]
                elif len(groups) == 1:
                    return groups[0]

        # Go/C style fallback: func keyword with parentheses
        if "(" in line and "func" in line:
            parts = line.split("(")
            name_part = parts[0].replace("func", "").strip()
            if " " in name_part:  # Handle receivers like (t *Target) Name
                return name_part.split()[-1]
            return name_part

        return "unknown_block"

    def extract_function_context(self, file_path, target_line):
        full_path = self._resolve_path(file_path)
        if not os.path.exists(full_path):
            return "", "global"

        try:
            with open(full_path, "r", encoding="utf-8", errors="replace") as f:
                lines = f.readlines()
        except OSError as e:
            logger.warning(f"IntelligenceEngine: Cannot read {full_path}: {e}")
            return "", "unknown"

        target_idx = target_line - 1
        if target_idx >= len(lines):
            return "".join(lines[-20:]), "unknown"

        # 1. Search for block start (upward from target line)
        start_idx = target_idx
        indent_level = self._get_indent(lines[target_idx])

        for i in range(target_idx, -1, -1):
            line = lines[i].strip()
            if not line:
                continue
            if any(
                re.match(m, line)
                for m in [r"func\s+", r"def\s+", r"class\s+", r"type\s+\w+\s+struct"]
            ):
                start_idx = i
                break
            if i < target_idx and self._get_indent(lines[i]) < indent_level:
                stripped = lines[i].strip()
                if any(
                    re.match(m, stripped)
                    for m in [r"def\s+", r"func\s+", r"class\s+", r"async\s+def\s+"]
                ):
                    start_idx = i
                    break

        # 2. Search for block end (brace balance or indent return)
        end_idx = min(target_idx + 50, len(lines))
        brace_count = 0
        started_braces = False

        for i in range(start_idx, len(lines)):
            brace_count += lines[i].count("{") - lines[i].count("}")
            if "{" in lines[i]:
                started_braces = True

            if started_braces and brace_count <= 0:
                end_idx = i + 1
                break
            if (
                not started_braces
                and i > target_idx
                and self._get_indent(lines[i]) <= self._get_indent(lines[start_idx])
                and lines[i].strip()
            ):
                end_idx = i
                break

        context_code = "".join(lines[start_idx:end_idx])
        entity_name = self._quick_extract_name(lines[start_idx])
        return context_code, entity_name

    def _resolve_path(self, path: str) -> str:
        """
        Resolves a relative path to an absolute path relative to the project root.
        """
        import os

        if os.path.isabs(path):
            return path

        base_path = getattr(self, "project_root", os.getcwd())
        return os.path.abspath(os.path.join(base_path, path))

    def get_semantic_slices(self, file_path, context_code):
        """Finds all lines in a file related to key objects extracted from context."""
        full_path = self._resolve_path(file_path)
        interesting_vars = set(re.findall(r"(\w+\.[\w\d_]+|[\w\d_]{3,})", context_code))

        slices = []
        try:
            with open(full_path, "r", encoding="utf-8", errors="replace") as f:
                for i, line in enumerate(f):
                    if any(
                        v in line
                        for v in interesting_vars
                        if v not in ["return", "string", "context"]
                    ):
                        slices.append(f"Line {i+1}: {line.strip()}")
        except OSError as e:
            logger.warning(f"IntelligenceEngine: Cannot read {full_path}: {e}")
            return ""

        # Limit output to avoid LLM context overflow
        return "\n".join(slices[:30])

    def analyze_deep_taint(self, context_code, sink_code):
        """Proximity taint analysis with simple call chains and function argument tracking."""
        vars_in_sink = re.findall(r"\b([a-zA-Z_][\w\.]+)\b", sink_code)
        danger_markers = [
            r"input",
            r"param",
            r"get",
            r"post",
            r"env",
            r"arg",
            r"secret",
            r"token",
            r"schema",
        ]

        tainted = []
        taint_paths = {}
        for var in vars_in_sink:
            if var in ["fmt", "Sprintf", "Exec", "os", "sys", "run"]:
                continue

            # Direct variable definition match
            var_escaped = re.escape(var)
            def_match = re.search(
                rf"\b{var_escaped}\b\s*[:=]+\s*(.*)", context_code, re.I
            )
            path_chain = []
            if def_match:
                source_expr = def_match.group(1).lower()
                path_chain.append(source_expr)
                if any(re.search(m, source_expr) for m in danger_markers):
                    tainted.append(var)
                    taint_paths[var] = path_chain

            # Function argument taint check
            first_line = context_code.split("\n")[0].lower()
            if re.search(rf"\b{var_escaped}\b", first_line) and any(
                m in first_line for m in danger_markers
            ):
                if var not in tainted:
                    tainted.append(var)
                    taint_paths[var] = [first_line]

        return ("TAINTED" if tainted else "CLEAN"), list(set(tainted)), taint_paths

    def get_intelligence_verdict(self, finding):
        if not finding:
            return {"reachability": "UNKNOWN", "reason": "Empty finding provided"}

        if isinstance(finding, dict):
            file_path = finding.get("file_path", "")
            meta = finding.get("meta") or {}
            line_num = finding.get("line", 0)
        else:
            file_path = str(getattr(finding, "file_path", ""))
            meta = getattr(finding, "meta", {}) or {}
            line_num = getattr(finding, "line", 0)
        sink_code = meta.get("code", "") if isinstance(meta, dict) else ""

        if file_path == "." or not file_path:
            file_path = meta.get("file", file_path)

        context, entity_name = self.extract_function_context(file_path, line_num)
        taint_status, sources, taint_paths = self.analyze_deep_taint(context, sink_code)

        calls_count = len(
            re.findall(r"\b(" + "|".join(self.danger_functions) + r")\b", context or "")
        )

        res = {
            "reachability": "UNKNOWN",
            "taint_sources": sources,
            "taint_paths": taint_paths,
            "calls_count": calls_count,
            "func_name": entity_name,
            "full_context": context,
            "reason": "",
        }

        is_test = any(x in file_path.lower() for x in ["test", "mock", "bench"])
        is_config = file_path.endswith((".yml", ".yaml", ".json", ".toml", ".conf"))

        if is_test:
            res.update(
                {
                    "reachability": "STATIC_SAFE",
                    "reason": "Test environment. No exploitable impact on production.",
                }
            )
        elif is_config:
            res.update(
                {
                    "reachability": "REACHABLE",
                    "reason": "Critical configuration or pipeline file. Direct infrastructure exposure.",
                }
            )
        elif taint_status == "TAINTED":
            res.update(
                {
                    "reachability": "REACHABLE",
                    "reason": f"Data from {sources} flows into a dangerous method in block '{entity_name}'.",
                }
            )
        elif entity_name and entity_name[0].isupper() and entity_name != "global_scope":
            res.update(
                {
                    "reachability": "POTENTIALLY_REACHABLE",
                    "reason": f"Entity '{entity_name}' is public and accessible via external call.",
                }
            )
        else:
            res.update(
                {
                    "reachability": "UNKNOWN",
                    "reason": f"No direct external data found, deep analysis required for '{entity_name}'.",
                }
            )

        return res

    def extract_smart_context(self, file_path: str, line_num: int, rule_id: str) -> str:
        # Path traversal protection
        abs_path = os.path.realpath(os.path.join(self.project_root, file_path))
        abs_root = os.path.realpath(self.project_root)
        if not abs_path.startswith(abs_root + os.sep):
            logger.warning(
                f"IntelligenceEngine: Path outside project root blocked: {file_path}"
            )
            return f"[BLOCKED: path outside project root]"

        try:
            with open(abs_path, "r", encoding="utf-8") as f:
                lines = f.readlines()
        except Exception as e:
            return f"Error reading file: {e}"

        # 1. Base context window around target line
        start_idx = max(0, line_num - 5)
        end_idx = min(len(lines), line_num + 15)
        base_context = "".join(lines[start_idx:end_idx])

        # 2. Smart Tracing for import-related findings
        if "import" in rule_id.lower():
            match = re.search(
                r"\"(.+?)\"", lines[line_num - 1] if line_num <= len(lines) else ""
            )
            if match:
                package_full_name = match.group(1)
                package_alias = package_full_name.split("/")[-1]  # e.g. 'template' from 'text/template'

                usage_context = self._find_usage(lines, package_alias, line_num)
                if usage_context:
                    return (
                        f"{base_context}\n"
                        f"// --- Auditor Core: Usage Trace for '{package_alias}' ---\n"
                        f"{usage_context}"
                    )

        return base_context

    def _find_usage(self, lines: list, package_name: str, start_from: int) -> str:
        """
        Finds the first occurrence of package.Something after the imports block.
        """
        pattern = re.compile(rf"{re.escape(package_name)}\.[A-Za-z]")

        for i in range(start_from, len(lines)):
            if pattern.search(lines[i]):
                u_start = max(0, i - 5)
                u_end = min(len(lines), i + 15)
                return "".join(lines[u_start:u_end])
        return ""