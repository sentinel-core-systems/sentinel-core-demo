import os
import requests
import socket
import getpass
from dotenv import load_dotenv

# English: Load environment variables once at the module level
load_dotenv()


def report_violation(violations: list, structured_results: list = None):
    """
    Sends a security report to the Administrative repository.
    Strictly follows .env configuration to avoid reporting test data as critical.
    """
    # 1. SYSTEM CONFIGURATION LOADING
    token = os.getenv("SENTINEL_ALERT_TOKEN")
    # Clean logic: Priority to .env, fallback to CI environment
    repo = os.getenv("SENTINEL_ADMIN_REPO") or os.getenv("GITHUB_REPOSITORY")

    # Exit if configuration is missing or looks like a placeholder
    if not token or not repo or "/" not in repo or "YOUR_ORG" in repo:
        return

    # 2. Forensics Context Collection
    is_ci = os.getenv("GITHUB_ACTIONS") is not None
    hostname = socket.gethostname()

    try:
        username = os.getenv("GITHUB_ACTOR") or getpass.getuser()
    except Exception:
        username = "unknown-user"

    environment = "🌐 GitHub Actions" if is_ci else "💻 Local Development"

    # 3. Severity Analysis (Normalization)
    # RCA: Strictly separate real production threats from test/suspicious data
    real_blockers = [v for v in violations if "[BLOCK]" in v and "SUSPICIOUS" not in v]
    test_warnings = [
        v
        for v in violations
        if "SUSPICIOUS" in v or "[WARN]" in v or "[OVERRIDDEN]" in v
    ]

    block_count = len(real_blockers)
    warn_count = len(test_warnings)

    # ANTI-SPAM: Do not report to Admin repo if it's a local test with 0 real blockers
    if not is_ci and block_count == 0:
        return

    status_icon = "🔴 BLOCK" if block_count > 0 else "🟡 WARN"

    # 4. GitHub Issue Payload Preparation
    clean_repo = repo.strip()
    url = f"https://api.github.com/repos/{clean_repo}/issues"

    report_header = (
        f"## 🔒 Sentinel V2 Security Violation Detected\n\n"
        f"**Target Admin Repo:** `{clean_repo}`\n"
        f"**Status:** {status_icon}\n"
        f"**Environment:** {environment}\n"
        f"**Machine:** `{hostname}`\n"
        f"**Triggered by:** `{username}`\n"
        f"---"
    )

    # 5. Build detailed violation list (Normalizing data from V1 and V2 engines)
    details = ""

    if structured_results:
        # Sort structured data into categories
        block_items = [
            r
            for r in structured_results
            if r.get("severity") == "BLOCK" and "SUSPICIOUS" not in r.get("message", "")
        ]
        warn_items = [
            r
            for r in structured_results
            if r.get("severity") == "WARN" or "SUSPICIOUS" in r.get("message", "")
        ]

        if block_items:
            details += "### 🚨 Critical Blockers (with AI Insights):\n"
            for b in block_items[:10]:
                details += f"- **{b['rule_id']}**: {b['message']}\n"
                if b.get("ai_insight"):
                    details += (
                        f"  > 🤖 **AI Expert Recommendation:** {b['ai_insight']}\n"
                    )

        if warn_items:
            details += "\n### ⚠️ Warnings/Overrides:\n"
            for w in warn_items[:10]:
                details += f"- {w['rule_id']}: {w['message']}\n"
    else:
        # Normalization for simple string reports
        if real_blockers:
            details += "### 🚨 Real Production Threats:\n"
            details += "\n".join([f"- {v}" for v in real_blockers[:10]])

        if test_warnings:
            details += "\n\n### ⚠️ Test Suspicions / Warnings:\n"
            details += "\n".join([f"- {v}" for v in test_warnings[:10]])

    report_footer = (
        "\n\n---\n*Reported by Sentinel Security Engine V2 (Encrypted Core)*"
    )

    # 6. JSON Payload Construction
    payload = {
        "title": f"{status_icon} | Issues: {block_count + warn_count} | {hostname}",
        "body": f"{report_header}\n\n{details}{report_footer}",
        "labels": ["security", "sentinel-gate", "v2-ai"],
    }

    if block_count > 0:
        payload["labels"].append("critical")

    headers = {
        "Authorization": f"token {token}",
        "Accept": "application/vnd.github.v3+json",
    }

    # 7. Silent Submission (Maintain zero call-home if network fails)
    try:
        requests.post(url, headers=headers, json=payload, timeout=10)
    except Exception:
        pass
