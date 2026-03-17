import click
import os
import sys
import yaml
import fcntl
import sentinel
from pathlib import Path
from dotenv import load_dotenv
from sentinel.engine import SentinelEngine
from sentinel.collector import ArtifactCollector
from auditor.security.guard import AuditorGuard

load_dotenv()

PLACEHOLDER_REPO = "DataWizual/sentinel-core"


def _print_hint(message, hint):
    click.secho(f"\n❌ ERROR: {message}", fg="red", bold=True)
    if hint:
        click.secho(f"💡 HINT: {hint}", fg="yellow")


def _verify_authorization():
    authorized_repo = os.getenv("SENTINEL_ADMIN_REPO")
    alert_token = os.getenv("SENTINEL_ALERT_TOKEN")

    if not alert_token:
        config_path = Path.home() / ".sentinel" / "config.yaml"
        if config_path.exists():
            try:
                with open(config_path, "r") as f:
                    conf = yaml.safe_load(f)
                    alert_token = conf.get("SENTINEL_ALERT_TOKEN")
                    authorized_repo = authorized_repo or conf.get("SENTINEL_ADMIN_REPO")
                    # Restore AI config from secure storage
                    for key in ["SENTINEL_AI_KEY", "SENTINEL_AI_URL", "SENTINEL_AI_MODEL",
                                "GOOGLE_API_KEY", "GOOGLE_MODEL"]:
                        val = conf.get(key)
                        if val:
                            os.environ.setdefault(key, val)
            except Exception as e:
                click.secho(f"⚠️ Warning: Could not read config: {e}", fg="red")
        else:
            click.secho(
                f"⚠️ Warning: Config file not found at {config_path}", fg="yellow"
            )

    if not alert_token and os.getenv("GITHUB_ACTIONS"):
        _print_hint("Authorization Missing", "SENTINEL_ADMIN_REPO not found in environment.")
        sys.exit(2)

    if not alert_token:
        _print_hint("Security Gate Offline", "Shield is not initialized. Alert token missing.")
        sys.exit(1)

    return alert_token, authorized_repo


@click.group()
@click.option("--id", is_flag=True, help="Show Machine ID for licensing.")
def cli(id):
    """
    Sentinel Core: Engineering Policy Enforcement Engine.
    Developed by DataWizual Security.
    """
    if id:
        guard = AuditorGuard()
        click.echo(f"{guard.get_machine_id()}")
        sys.exit(0)


@cli.command()
@click.argument("path", default=".")
@click.option("--report", is_flag=True, default=False,
              help="Generate HTML report on violations.")
@click.option("--audit", is_flag=True, default=False,
              help="Run Auditor Core analysis before enforcement (auto Bridge).")
def scan(path, report, audit):
    """
    Performs a high-authority security scan on the specified path.
    Sentinel V2 + Auditor Core AI-powered verification.
    """
    # --- Trial check ---
    license_key = os.getenv("SENTINEL_LICENSE_KEY") or os.getenv("AUDITOR_LICENSE_KEY")
    if not license_key:
        guard = AuditorGuard()
        allowed, remaining = guard.check_trial()
        if allowed:
            click.secho(f"\033[0;33m⚠️  Trial mode: {remaining} free run(s) remaining after this.\033[0m")
            click.secho("\033[0;33m   To get a full license: eldorzufarov66@gmail.com\033[0m\n")
            # Disable AI in trial mode
            os.environ["GOOGLE_API_KEY"] = ""
        else:
            click.secho("\n\033[0;31m🛑 Trial limit reached (3 free runs used).\033[0m")
            click.secho(f"   Get your license key: eldorzufarov66@gmail.com")
            click.secho(f"   Your Machine ID: {AuditorGuard().get_machine_id()}\n")
            sys.exit(1)

    try:
        alert_token, authorized_repo = _verify_authorization()
        os.environ["SENTINEL_ALERT_TOKEN"] = alert_token
        os.environ["SENTINEL_ADMIN_REPO"] = authorized_repo or ""
    except Exception as e:
        _print_hint("Authorization Check Failed", f"{str(e)} - Running in COMMUNITY mode")
        return

    try:
        click.secho("🔍 Starting Sentinel V2 Security Scan...", fg="cyan", bold=True)

        # If --audit flag is set - run Auditor Core before Sentinel
        if audit:
            click.secho("🧠 Running Auditor Core analysis...", fg="cyan")
            try:
                import yaml as _yaml
                audit_cfg_path = Path(__file__).parent.parent / "audit-config.yml"
                if audit_cfg_path.exists():
                    with open(audit_cfg_path) as f:
                        audit_cfg = _yaml.safe_load(f)
                    from auditor.runner import AuditorRunner
                    license_key = os.getenv("SENTINEL_LICENSE_KEY") or os.getenv("AUDITOR_LICENSE_KEY", "")
                    runner = AuditorRunner(audit_cfg, license_key)
                    report_path = runner.run(path)
                    if report_path:
                        click.secho(f"✅ Auditor Core report: {report_path}", fg="green")
                    else:
                        click.secho("⚠️ Auditor Core: No report generated.", fg="yellow")
                else:
                    click.secho("⚠️ audit-config.yml not found — skipping Auditor Core.", fg="yellow")
            except Exception as e:
                click.secho(f"⚠️ Auditor Core failed: {e}", fg="yellow")

        collector = ArtifactCollector(path)
        paths_dict = collector.collect()

        artifacts_with_content = {}
        for category, file_paths in paths_dict.items():
            artifacts_with_content[category] = {}
            for p in file_paths:
                content = collector.get_content(p)
                if content:
                    artifacts_with_content[category][p] = content

        engine = SentinelEngine(root_path=path)
        result = engine.evaluate(artifacts_with_content)
        violations = result["details"]
        structured_data = result["structured_results"]

        if violations:
            click.secho(
                f"\n❌ Found {len(violations)} security violations!",
                fg="red", bold=True,
            )
            for v in violations:
                click.echo(f"- {v}")

            try:
                from sentinel.alert import report_violation
                report_violation(violations, structured_data)
                click.secho("🚀 Remote Alert Sent Successfully!", fg="green")
            except Exception as e:
                click.secho(f"⚠️ Alert system failed: {e}", fg="yellow")

            if report:
                report_path = engine.generate_report(result, target_dir=".")
                click.secho(f"\n✅ Report generated: {report_path}", fg="green")

            critical_issues = [
                v for v in violations if "[BLOCK]" in v and "SUSPICIOUS" not in v
            ]

            if critical_issues:
                click.secho(
                    f"\n❌ Terminating: {len(critical_issues)} CRITICAL threats found.",
                    fg="red", bold=True,
                )
                sys.exit(1)
            else:
                click.secho(
                    "\n✅ Build Proceeding: No critical production blockers.",
                    fg="green", bold=True,
                )
                sys.exit(0)

        click.secho(
            "\n✅ No security violations found. Project is compliant.",
            fg="green", bold=True,
        )

    except Exception as e:
        _print_hint("Internal Engine Failure", f"{e}")
        sys.exit(3)


@cli.command()
@click.option("--token", help="GitHub Alert Token", default=None)
@click.option("--repo", help="Admin Repository Name", default=None)
@click.option("--model", help="AI Model Name", default=None)
@click.option("--license", "license_key", help="Sentinel License Key", default=None)
def init(token, repo, model, license_key):
    """
    Initializes the Sentinel Security Gate.
    Binds license to machine, stores secure config, installs git hooks.
    """
    try:
        guard = AuditorGuard()
        m_id = guard.get_machine_id()

        current_license = license_key or os.getenv("SENTINEL_LICENSE_KEY") or os.getenv("AUDITOR_LICENSE_KEY")

        if not current_license:
            _print_hint(
                "License Missing",
                f"Machine ID: {m_id}\nSend this to eldorzufarov66@gmail.com to get your key.",
            )
            sys.exit(1)

        if not guard.verify_license(current_license, m_id):
            _print_hint("Invalid License", f"Key does not match Machine ID: {m_id}")
            sys.exit(1)

        click.secho(f"✅ License verified for Machine ID: {m_id}", fg="green")

        target_admin_repo = repo or os.getenv("SENTINEL_ADMIN_REPO") or PLACEHOLDER_REPO
        current_token = token or os.getenv("SENTINEL_ALERT_TOKEN")

        if not current_token:
            _print_hint("Init Failed", "SENTINEL_ALERT_TOKEN is required for reports.")
            sys.exit(1)

        # AI config - Gemini takes priority
        google_api_key   = os.getenv("GOOGLE_API_KEY", "")
        google_model     = model or os.getenv("GOOGLE_MODEL", "gemini-2.5-flash")
        sentinel_ai_key  = os.getenv("SENTINEL_AI_KEY", "")
        sentinel_ai_url  = os.getenv("SENTINEL_AI_URL", "https://api.groq.com/openai/v1/chat/completions")
        sentinel_ai_model = os.getenv("SENTINEL_AI_MODEL", "llama-3.3-70b-versatile")

        # Save to ~/.sentinel/config.yaml
        config_dir = Path.home() / ".sentinel"
        config_dir.mkdir(exist_ok=True)
        secure_config_path = config_dir / "config.yaml"

        with open(secure_config_path, "a+", encoding="utf-8") as f:
            if os.name != "nt":
                fcntl.flock(f, fcntl.LOCK_EX)
            secure_data = {
                "SENTINEL_ALERT_TOKEN":  current_token,
                "SENTINEL_ADMIN_REPO":   target_admin_repo,
                "SENTINEL_LICENSE_KEY":  current_license,
                # Gemini (Auditor Core AI)
                "GOOGLE_API_KEY":        google_api_key,
                "GOOGLE_MODEL":          google_model,
                # Sentinel AI (optional)
                "SENTINEL_AI_KEY":       sentinel_ai_key,
                "SENTINEL_AI_URL":       sentinel_ai_url,
                "SENTINEL_AI_MODEL":     sentinel_ai_model,
            }
            f.seek(0)
            f.truncate()
            yaml.dump(secure_data, f, default_flow_style=False)
            if os.name != "nt":
                fcntl.flock(f, fcntl.LOCK_UN)

        click.secho(f"✅ Secure config stored: {secure_config_path}", fg="green")

        # sentinel.yaml - public config with current severity levels
        sentinel_yaml_path = "sentinel.yaml"
        default_config = {
            "admin_repo": target_admin_repo,
            "severity": {
                "SEC-001":       "BLOCK",
                "SUPPLY-001":    "BLOCK",
                "INFRA-001":     "BLOCK",
                "INFRA-K8S-001": "WARN",
                "CICD-001":      "WARN",
                "IOT-001":       "WARN",
            },
            "ignore": [
                "venv/*",
                ".git/*",
                "node_modules/*",
                "reports/*",
                "sentinel_report.html",
            ],
            "overrides": [],
        }
        with open(sentinel_yaml_path, "w", encoding="utf-8") as f:
            yaml.dump(default_config, f, default_flow_style=False, allow_unicode=True)
        click.secho(f"✅ sentinel.yaml initialized", fg="green")

        # GitHub Actions workflow
        github_action_content = f"""name: Sentinel Security Gate
on:
  push:
    branches: [ main ]
  pull_request:
    branches: [ main ]
jobs:
  security-check:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout Code
        uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683
      - name: Install Sentinel
        env:
          INSTALL_TOKEN: ${{{{ secrets.SENTINEL_INSTALL_TOKEN }}}}
        run: |
          python -m pip install --upgrade pip
          pip install git+https://x-access-token:${{INSTALL_TOKEN}}@github.com/{target_admin_repo}.git@main
      - name: Execute Security Scan
        id: scan_step
        env:
          SENTINEL_ADMIN_REPO: '{target_admin_repo}'
          SENTINEL_ALERT_TOKEN: ${{{{ secrets.SENTINEL_ALERT_TOKEN }}}}
          GOOGLE_API_KEY: ${{{{ secrets.GOOGLE_API_KEY }}}}
          AUDITOR_LICENSE_KEY: ${{{{ secrets.AUDITOR_LICENSE_KEY }}}}
          AUDITOR_LICENSE_SALT: ${{{{ secrets.AUDITOR_LICENSE_SALT }}}}
        run: sentinel scan . --report
        continue-on-error: true
      - name: Terminate on Failure
        if: steps.scan_step.outcome == 'failure'
        run: exit 1
"""
        workflow_path = ".github/workflows/sentinel.yml"
        os.makedirs(os.path.dirname(workflow_path), exist_ok=True)
        with open(workflow_path, "w", encoding="utf-8") as f:
            f.write(github_action_content.strip())
        click.secho(f"✅ GitHub Workflow initialized: {workflow_path}", fg="green")

        # Git pre-commit hook
        dot_git_path = os.path.join(os.getcwd(), ".git")
        if os.path.exists(dot_git_path):
            hook_path = os.path.join(dot_git_path, "hooks", "pre-commit")
            os.makedirs(os.path.dirname(hook_path), exist_ok=True)
            sentinel_hook = (
                "\n# --- Sentinel Security Gate ---\n"
                "sentinel scan . || exit 1\n"
                "# --- End Sentinel ---\n"
            )
            if os.path.exists(hook_path):
                with open(hook_path, "r", encoding="utf-8") as f:
                    existing = f.read()
                if "sentinel scan" not in existing:
                    with open(hook_path, "a", encoding="utf-8") as f:
                        f.write(sentinel_hook)
                    click.secho("✅ Git pre-commit hook updated.", fg="green")
                else:
                    click.secho("ℹ️ Sentinel already in pre-commit hook.", fg="yellow")
            else:
                with open(hook_path, "w", encoding="utf-8") as f:
                    f.write(f"#!/bin/bash{sentinel_hook}")
                if os.name != "nt":
                    os.chmod(hook_path, 0o755)
                click.secho("✅ Git pre-commit hook installed.", fg="green")

        click.secho("\n🛡️ Sentinel Core is ready.", fg="cyan", bold=True)

    except Exception as e:
        _print_hint("Initialization Failed", str(e))


if __name__ == "__main__":
    cli()