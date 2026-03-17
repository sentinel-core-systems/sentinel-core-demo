import re
import os
import json
import logging
import requests
import datetime
import yaml
import importlib.util
import inspect
import sys
from pathlib import Path
from sentinel.rules.base import BaseRule
from dotenv import load_dotenv

load_dotenv()

logger = logging.getLogger(__name__)


class AIEngine:
    def __init__(self):
        self.api_key = os.getenv("SENTINEL_AI_KEY")
        self.provider_url = os.getenv("SENTINEL_AI_URL", "https://api.groq.com/openai/v1/chat/completions")
        self.ai_model = os.getenv("SENTINEL_AI_MODEL", "llama-3.3-70b-versatile")
        self.risk_markers = [
            "payable", "onlyOwner", "selfdestruct", "delegatecall",
            "internal _pay", "anchor_lang", "ProgramResult", "AccountInfo",
            "Signer<'info>", "module ", "resource ", "public fun ", "signer",
        ]

    def is_high_risk(self, code):
        if not code or not isinstance(code, str): return False
        if "interface " in code: return False
        return any(marker.lower() in code.lower() for marker in self.risk_markers)

    def analyze_violation(self, rule_id, violation_msg, code=""):
        if not self.api_key: return "AI Key not set."
        prompt = (
            f"As a Senior Web3 Security Auditor, analyze this issue:\n"
            f"Rule: {rule_id}\nIssue: {violation_msg}\n"
            f"Context Code:\n{code[:1000]}\n"
            f"Provide a 2-3 sentence technical recommendation."
        )
        return self._call_ai(prompt)

    def generate_full_audit(self, file_name, code):
        if not self.api_key: return "AI Key not set."
        prompt = (
            f"Audit file '{file_name}' for security risks.\n"
            f"CRITICAL INSTRUCTION: If the code appears to be a legitimate part of the "
            f"project logic, provide a 'Contextual Advisory'.\n\nCode:\n{code[:3000]}"
        )
        system_role = (
            "You are a Senior Security Architect. "
            "Use tags: [RISK: HIGH/MEDIUM/LOW], [CONTEXT: LOGIC/THREAT], [CONFIDENCE: %]"
        )
        return self._call_ai(prompt, system_role=system_role)

    def _call_ai(self, prompt, system_role="You are a Senior Web3 Security Expert."):
        try:
            headers = {
                "Authorization": f"Bearer {self.api_key}",
                "Content-Type": "application/json",
            }
            data = {
                "model": self.ai_model,
                "messages": [
                    {"role": "system", "content": system_role},
                    {"role": "user", "content": prompt},
                ],
            }
            response = requests.post(self.provider_url, headers=headers, json=data, timeout=15)
            return (
                response.json()["choices"][0]["message"]["content"]
                if response.status_code == 200
                else f"Error: {response.status_code}"
            )
        except Exception as e:
            return str(e)


class SentinelEngine:
    IMMUTABLE_RULES = ["SEC-001", "SUPPLY-001", "INFRA-001"]
    SEVERITY_ORDER = {
        "BLOCK": 0, "CRITICAL": 1, "HIGH": 2,
        "MEDIUM": 3, "WARN": 4, "LOW": 5, "INFO": 6, "N/A": 7,
    }

    def __init__(self, root_path=".", config_path="sentinel.yaml", rules_path=None):
        self.root_path = root_path
        self.config_path = config_path
        self.rules_root = rules_path or os.path.join(os.path.dirname(__file__), "rules")
        self.config = self._load_full_config()
        self.overrides = self._extract_overrides()
        self.severity_config = self.config.get("severity", {})
        self.universal_logic_path = os.path.join(os.path.dirname(__file__), "universal_logic.json")
        self.semantic_rules = self._load_universal_logic()
        self.rules = []
        self.last_result = None
        self.ai_engine = AIEngine()
        self._autodiscover_rules(self.rules_root)

        # Bridge: connect Auditor Core if available
        self._bridge = self._init_bridge()

    def _init_bridge(self):
        """
        Initializes Bridge with Auditor Core.
        If report already exists - passive mode (reads JSON).
        If not - active mode (runs AuditorRunner via auto_run=True).
        Does not fail if Auditor is unavailable.
        """
        try:
            from sentinel.bridge import AuditorBridge
            # Load audit-config.yml for AuditorRunner
            audit_cfg = {}
            # Look for audit-config.yml in the client working directory (cwd)
            # and as fallback - next to the package
            audit_cfg_candidates = [
                Path.cwd() / "audit-config.yml",
                Path(__file__).parent.parent / "audit-config.yml",
            ]
            for audit_cfg_path in audit_cfg_candidates:
                if audit_cfg_path.exists():
                    import yaml as _yaml
                    with open(audit_cfg_path) as f:
                        audit_cfg = _yaml.safe_load(f) or {}
                    logger.info(f"Bridge: Loaded audit-config from {audit_cfg_path}")
                    break

            license_key = (
                os.getenv("SENTINEL_LICENSE_KEY") or
                os.getenv("AUDITOR_LICENSE_KEY", "")
            )

            bridge = AuditorBridge(
                auto_run=True,
                auditor_config=audit_cfg,
                license_key=license_key,
            )
            # ensure_report is called in evaluate() with a specific target_path
            return bridge
        except ImportError:
            logger.debug("Bridge: sentinel.bridge not available.")
        except Exception as e:
            logger.warning(f"Bridge init failed: {e}")
        return None

    def _load_universal_logic(self):
        if os.path.exists(self.universal_logic_path):
            try:
                with open(self.universal_logic_path, "r", encoding="utf-8") as f:
                    return json.load(f).get("universal_semantic_rules", [])
            except:
                return []
        return []

    def _determine_context(self, path):
        p = str(path).lower().replace("\\", "/")
        # TEST takes priority - even over INFRA
        if any(x in p for x in ["/test", "/fixture", "/mock", "test_", ".test."]):
            return "TEST"
        # FIX: removed .yml/.yaml and setup.py - they are not infrastructure
        if any(x in p for x in [".github", "docker", "terraform", "compose", ".tf", ".hcl"]):
            return "INFRA"
        if any(x in p for x in ["/docs", "readme", ".md", ".svg"]):
            return "DOCS"
        return "CORE"

    def _apply_universal_inference(self, rule_id, path, current_severity):
        context = self._determine_context(path)
        rid = rule_id.lower()
        scope_map = {
            "sec-":    "secretdetector",
            "cicd-":   "iac_scanner",
            "iot-":    "slitherdetector",
            "sup-":    "bandit",
            "auditor-": "semgrep",  # Bridge findings use semgrep scope
        }
        target_scope = next((v for k, v in scope_map.items() if rid.startswith(k)), rid)
        for rule in self.semantic_rules:
            if any(scope in target_scope for scope in rule["detector_scope"]):
                if rule["file_context"] == context:
                    return {
                        "severity":   rule["adjusted_severity"],
                        "compliance": rule["compliance_mapping"],
                        "rationale":  rule["audit_rationale"],
                    }
        return {"severity": current_severity, "compliance": "N/A", "rationale": None}

    def _load_full_config(self):
        if not os.path.exists(self.config_path):
            return {}
        try:
            with open(self.config_path, "r", encoding="utf-8") as f:
                return yaml.safe_load(f) or {}
        except:
            return {}

    def _extract_overrides(self):
        return {
            str(ov["rule_id"]).upper(): ov["justification"]
            for ov in self.config.get("overrides", [])
            if "rule_id" in ov
        }

    def _autodiscover_rules(self, rules_path):
        for root, _, files in os.walk(rules_path):
            for file in files:
                if file.endswith(".py") and not file.startswith("__") and file != "base.py":
                    rel_path = os.path.relpath(os.path.join(root, file), rules_path)
                    module_subpath = os.path.splitext(rel_path)[0].replace(os.sep, ".")
                    module_name = f"sentinel.rules.{module_subpath}"
                    try:
                        module = importlib.import_module(module_name)
                        for _, obj in inspect.getmembers(module):
                            if inspect.isclass(obj) and issubclass(obj, BaseRule) and obj is not BaseRule:
                                if not any(isinstance(r, obj) for r in self.rules):
                                    self.rules.append(obj())
                    except Exception as e:
                        print(
                            f"❌ Sentinel Engine: Failed to load rule {module_name}: {e}",
                            file=sys.stderr,
                        )
                        continue

    def evaluate(self, artifacts: dict) -> dict:
        all_violations = []
        structured_results = []
        block_detected = False

        full_flat_content = {}
        for cat_dict in artifacts.values():
            if isinstance(cat_dict, dict):
                full_flat_content.update(cat_dict)

        # ── STAGE 1: Sentinel native rules ─────────────────────────────────
        for rule in self.rules:
            try:
                rid = getattr(rule, "id", "GENERIC").upper()
                vls = rule.check(full_flat_content if rid == "IOT-001" else artifacts)
                base_sev = self.severity_config.get(rid, getattr(rule, "severity", "BLOCK")).upper()
                if rid in self.IMMUTABLE_RULES:
                    base_sev = "BLOCK"

                for v in vls:
                    loc = "Global"
                    clean_msg = v
                    if " in " in v:
                        clean_msg, loc = v.split(" in ", 1)
                    inf = self._apply_universal_inference(rid, loc, base_sev)
                    is_ovr = rid in self.overrides
                    final_sev = "WARN" if is_ovr else inf["severity"]

                    structured_results.append({
                        "rule_id":       rid,
                        "location":      loc,
                        "message":       clean_msg,
                        "severity":      final_sev,
                        "cvss_score":    9.5 if final_sev in ["BLOCK", "CRITICAL"] else 4.0,
                        "cwe":           getattr(rule, "cwe_id", "CWE-Generic"),
                        "compliance":    inf["compliance"],
                        "is_overridden": is_ovr,
                        "justification": self.overrides.get(rid) if is_ovr else None,
                        "remediation":   getattr(rule, "rationale", "Follow security best practices."),
                    })
                    if not is_ovr and final_sev in ["BLOCK", "CRITICAL"]:
                        block_detected = True
                    all_violations.append(f"[{final_sev}] {rid}: {v}")

            except Exception as e:
                print(f"⚠️ Rule error: {e}", file=sys.stderr)
                continue

        # ── STAGE 2: Auditor Core Bridge ───────────────────────────────────────
        if self._bridge:
            try:
                # Ensure report exists - if not, run AuditorRunner
                self._bridge.ensure_report(target_path=self.root_path)
                bridge_violations = self._bridge.load_violations()
                for bv in bridge_violations:
                    structured_results.append(bv)
                    all_violations.append(bv["message"])
                    if bv["severity"] in ["BLOCK", "CRITICAL"]:
                        block_detected = True

                if bridge_violations:
                    print(
                        f"🔗 Bridge: {len(bridge_violations)} Auditor Core findings injected.",
                        file=sys.stderr,
                    )
            except Exception as e:
                print(f"⚠️ Bridge error: {e}", file=sys.stderr)

        # ── Sort by severity ────────────────────────────────────────────────
        structured_results.sort(
            key=lambda x: self.SEVERITY_ORDER.get(x.get("severity"), 99)
        )

        self.last_result = {
            "decision":          "BLOCK" if block_detected else "ALLOW",
            "structured_results": structured_results,
            "details":           all_violations,
        }
        return self.last_result

    def _get_html_content(self, result):
        now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        table_rows = ""
        for r in result["structured_results"]:
            badge = "badge-block" if r["severity"] in ["BLOCK", "CRITICAL"] else "badge-warn"
            ai_html = (
                f'<div class="ai-box"><strong>AI Insight:</strong> {r["ai_insight"]}</div>'
                if r.get("ai_insight") else ""
            )
            # Source label for Bridge findings
            source_tag = (
                '<br><span style="font-size:10px; color:#6366f1;">🔗 Auditor Core</span>'
                if r.get("_source") == "auditor_bridge" else ""
            )
            compliance_tag = (
                f'<br><span style="font-size:10px; color:#6366f1;">Standard: {r["compliance"]}</span>'
                if r["compliance"] != "N/A" else ""
            )
            rem = (
                f'<strong style="color:#057a55;">OVERRIDDEN:</strong> {r["justification"]}'
                if r["is_overridden"]
                else f'<em>{r["remediation"]}</em>'
            )

            table_rows += f"""
            <tr>
                <td style="width:110px; text-align:center;">
                    <span class="badge {badge}">{r['severity']}</span>
                    <br><small>CVSS: {r['cvss_score']}</small>
                </td>
                <td style="width:200px;">
                    <strong>{r['rule_id']}</strong>
                    <br><small>{r['cwe']}</small>
                    {compliance_tag}{source_tag}
                </td>
                <td style="width:250px; word-break:break-all;"><code>{r['location']}</code></td>
                <td>{r['message']}{ai_html}</td>
                <td style="width:140px; font-size:12px; color:#475569;">{rem}</td>
            </tr>"""

        return f"""
        <!DOCTYPE html><html><head><meta charset="UTF-8"><title>Sentinel V2 Report</title>
        <style>
            body {{ font-family: 'Inter', sans-serif; margin: 40px; background:#f7fafc; color:#1a1f36; }}
            .header {{ display:flex; justify-content:space-between; align-items:center; border-bottom:2px solid #e3e8ee; padding-bottom:20px; }}
            .status {{ font-size:28px; font-weight:800; color:{'#e02424' if result['decision'] == 'BLOCK' else '#057a55'}; }}
            .legal-notice {{ background:#fff3cd; border-left:5px solid #856404; padding:15px; margin:20px 0; border-radius:4px; font-size:0.85em; color:#644d03; }}
            .recommendation-block {{ background:#d4edda; border-left:5px solid #155724; padding:15px; margin:20px 0; border-radius:4px; font-size:0.85em; color:#155724; }}
            table {{ width:100%; border-collapse:collapse; background:#fff; border-radius:12px; overflow:hidden; box-shadow:0 4px 6px rgba(0,0,0,0.05); table-layout:fixed; }}
            th {{ background:#f8fafc; padding:15px; text-align:left; font-size:12px; color:#64748b; text-transform:uppercase; }}
            td {{ padding:15px; border-bottom:1px solid #e2e8f0; font-size:14px; vertical-align:top; }}
            .badge {{ padding:4px 8px; border-radius:6px; font-size:11px; font-weight:700; }}
            .badge-block {{ background:#fee2e2; color:#991b1b; }}
            .badge-warn {{ background:#fef3c7; color:#92400e; }}
            .ai-box {{ margin-top:10px; padding:10px; background:#f0f4ff; border-left:4px solid #4f46e5; font-size:12px; }}
        </style></head>
        <body>
            <div class="header">
                <div><h1>Sentinel Security Gate</h1>
                <div class="status">DECISION: {result['decision']}</div></div>
                <div>{now}</div>
            </div>
            <div class="legal-notice"><strong>Legal Notice:</strong> This report is for research and technical analysis purposes. Sentinel Core identifies technical patterns that may correlate with security control failures (e.g., ISO 27001, SOC 2). Final determination of regulatory compliance remains exclusively within the competence of certified auditors.</div>
            <div class="recommendation-block"><strong>Strategic Recommendation:</strong> It is recommended to perform a technical review of the identified patterns to assess their impact on the organization's security posture and audit readiness.</div>
            <table><thead><tr>
                <th style="width:110px;">Severity</th>
                <th style="width:200px;">Rule ID</th>
                <th style="width:250px;">Location</th>
                <th>Finding & AI Insight</th>
                <th style="width:140px;">Remediation</th>
            </tr></thead>
            <tbody>{table_rows}</tbody></table>
        </body></html>"""

    def generate_report(self, result_data=None, target_dir=None):
        data = result_data or self.last_result
        if not data:
            return "Error"
        r_dir = os.path.join(os.getcwd(), "reports")
        if not os.path.exists(r_dir):
            os.makedirs(r_dir)
        ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        base_path = os.path.join(r_dir, f"sentinel_report_{ts}")

        with open(f"{base_path}.json", "w", encoding="utf-8") as f:
            json.dump(data, f, indent=4, ensure_ascii=False)
        with open(f"{base_path}.html", "w", encoding="utf-8") as f:
            f.write(self._get_html_content(data))
        self.generate_markdown_report(data, f"{base_path}.md")

        return f"{base_path}.html"

    def generate_markdown_report(self, result: dict, output_path: str):
        now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        sorted_res = sorted(
            result["structured_results"],
            key=lambda x: self.SEVERITY_ORDER.get(x["severity"], 99),
        )
        criticals = sum(1 for r in sorted_res if r["severity"] in ["BLOCK", "CRITICAL"])
        warnings  = sum(1 for r in sorted_res if r["severity"] in ["WARN", "HIGH", "MEDIUM"])
        bridge_count = sum(1 for r in sorted_res if r.get("_source") == "auditor_bridge")

        md_content = (
            f"# 🛡️ Sentinel Security Audit Report\n"
            f"**Date:** {now} | **Decision:** `{result['decision']}`\n\n"
            f"## 📊 Executive Summary\n"
            f"- **Critical Blockers:** {criticals}\n"
            f"- **Warnings:** {warnings}\n"
            f"- **Auditor Core findings:** {bridge_count}\n\n---\n\n"
        )

        for r in sorted_res:
            sev_icon = "🔴" if r["severity"] in ["BLOCK", "CRITICAL"] else "🟡"
            source = " `[Auditor Core]`" if r.get("_source") == "auditor_bridge" else ""
            md_content += f"### {sev_icon} {r['rule_id']}{source} | Severity: `{r['severity']}`\n"
            if r.get("compliance") and r["compliance"] != "N/A":
                md_content += f"- **🏛️ Compliance:** `{r['compliance']}`\n"
            md_content += f"- **📍 Finding:** {r['message']}\n"
            md_content += f"- **🔗 Location:** `{r['location']}`\n"
            md_content += f"#### 🛠️ Remediation\n{r['remediation']}\n\n"
            if r.get("ai_insight"):
                md_content += f"> **🤖 AI Expert Insight**\n> {r['ai_insight']}\n\n"
            md_content += "---\n"

        with open(output_path, "w", encoding="utf-8") as f:
            f.write(md_content)
        return output_path