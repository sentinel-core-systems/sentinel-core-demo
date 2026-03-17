<div align="center">

# 🛡️ Sentinel Core v2.1

**Real-Time Security Enforcement Gate for Development Teams**

[![License](https://img.shields.io/badge/license-Commercial-red.svg)](TERMS_OF_USE.md)
[![Python](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://python.org)
[![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20macOS%20%7C%20Windows-lightgrey.svg)]()
[![Status](https://img.shields.io/badge/status-Production%20Ready-brightgreen.svg)]()

*ALLOW or BLOCK — no ambiguity, no silent bypass.*

**[🌐 Website](https://datawizual.github.io) · [📧 Get License](mailto:eldorzufarov66@gmail.com)**

---

### Installation Demo
![Sentinel Core Installation](demo_1.gif)

### Security Gate in Action
![Sentinel Core Block](demo_2.gif)

</div>

---

## What Is Sentinel Core?

Sentinel Core is an enterprise-grade security enforcement system that **intercepts every git commit** before it reaches your codebase. It runs an embedded [Auditor Core](https://datawizual.github.io) engine with AI-powered analysis via Gemini 2.5 Flash — verifying threats and eliminating false positives in real time.

Every violation is **blocked immediately** and creates an alert in your admin repository. Developers have no way to silently bypass enforcement.

---

## What Sentinel Protects

| Category | Details |
|---|---|
| 🔑 **Secrets** | Passwords, API keys, tokens hardcoded in source files |
| ⚙️ **CI/CD Configurations** | GitHub Actions, GitLab CI, Jenkinsfile |
| 🏗️ **Infrastructure** | Kubernetes, Terraform, Docker misconfigurations |
| 🐍 **Python Source Code** | Injection, insecure cryptography, SQL injection |
| 📦 **Supply Chain** | Unpinned dependencies, unsafe base images |

---

## How It Works

```
Developer runs: git commit
        ↓
Sentinel intercepts via pre-commit hook
        ↓
Auditor Core scans changed files (10 detection engines)
        ↓
Gemini AI verifies and classifies threats
        ↓
ALLOW → commit proceeds normally
BLOCK → commit rejected + alert fired to admin GitHub Issues
```

---

## Installation

### Step 1 — Get Your Machine ID

Each machine requires a hardware-bound License Key. Run on every machine to be protected:

```bash
python3 get_id.py
```

Output:
```
==================================================
  Sentinel Core — Machine ID
==================================================
  Machine ID: 81CE1239487E2EA172FF41BC4DD13BED
==================================================
  Send this ID to: eldorzufarov66@gmail.com
```

Send the Machine ID to **eldorzufarov66@gmail.com** — you will receive a License Key unique to that machine.

> ⚠️ A key issued for one machine will not work on another.

### Step 2 — Prepare GitHub Tokens

Create two Personal Access Tokens at `GitHub → Settings → Developer settings → Fine-grained tokens`:

**SENTINEL_INSTALL_TOKEN** — installs Sentinel from the private repository
```
Repository: sentinel-core
Permissions: Contents → Read-only
```

**SENTINEL_ALERT_TOKEN** — posts enforcement alerts as GitHub Issues
```
Repository: your admin repository
Permissions: Issues → Read and write
```

### Step 3 — Install via start.sh

Copy `start.sh` into the root of the project you want to protect:

```bash
bash start.sh
```

The script handles everything automatically:
- Accepts Terms of Use
- Installs Sentinel from the private GitHub repository
- Configures `.env` with your credentials
- Initializes hardware-bound license
- Creates `sentinel.yaml` enforcement policy
- Sets up GitHub Actions workflow
- Installs pre-commit hook

Successful output:
```
✅ License verified for Machine ID: 81CE1239487E2EA172FF41BC4DD13BED
✅ sentinel.yaml initialized
✅ GitHub Workflow initialized
✅ Pre-commit hook installed
------------------------------------------------------------
✅ SENTINEL CORE DEPLOYED SUCCESSFULLY
------------------------------------------------------------
```

### Step 4 — Verify

Test the enforcement gate immediately after installation:

```bash
echo 'password = "admin123"' > test_vuln.py
git add test_vuln.py
git commit -m "test"
```

Expected result:
```
🔍 Sentinel is verifying commit security...
❌ Found 1 security violations!
- [CRITICAL] SEC-001: Hardcoded Password in test_vuln.py at line 1.
🚀 Remote Alert Sent Successfully!
❌ Terminating: 1 CRITICAL threats found.
```

Clean up:
```bash
rm test_vuln.py
```

---

## Policy Configuration

All enforcement rules are defined in `sentinel.yaml`:

```yaml
severity:
  SEC-001: BLOCK        # Hardcoded secrets
  SUPPLY-001: BLOCK     # Supply chain integrity
  INFRA-K8S-001: BLOCK  # Kubernetes misconfigurations
  CICD-001: BLOCK       # CI/CD security issues

overrides: []
ignore:
  - venv/*
  - node_modules/*
```

To temporarily allow a violation with documented justification:

```yaml
overrides:
  - rule_id: SUPPLY-001
    justification: "Legacy base image — reviewed by security team"
```

---

## Enforcement Alerts

Every blocked commit automatically creates a GitHub Issue in your admin repository:

```
🔴 BLOCK — SEC-001: Hardcoded Password
Environment: 💻 Local Development
Machine: worker-pc-01
Triggered by: developer_username
Timestamp: 2026-03-13 14:22:01
```

Administrators have full visibility. Developers have no access to the enforcement dashboard.

---

## Project Structure After Installation

```
your-project/
├── start.sh                    ← provisioning script
├── audit-config.yml            ← Auditor Core configuration
├── sentinel.yaml               ← enforcement policy
├── .env                        ← credentials (never commit)
├── .github/
│   └── workflows/
│       └── sentinel.yml        ← CI/CD pipeline protection
├── reports/
│   └── report_*.json           ← scan reports
└── venv/                       ← Python virtual environment
```

---

## Requirements

| Component | Version |
|---|---|
| Python | 3.10+ |
| Git | any |
| OS | Linux / macOS / Windows |
| Gemini API | Optional (AI analysis) |
| Groq API | Optional (Gemini fallback) |

---

## FAQ

**Can a developer bypass Sentinel?**
A developer can run `git commit --no-verify` locally. However, the CI/CD pipeline will catch the push, block it, and alert the administrator with the developer's identity and machine ID.

**Does Sentinel slow down commits?**
Basic scanning takes 2–5 seconds. With Gemini AI enabled — 15–30 seconds depending on project size.

**What if Gemini API quota is exceeded?**
Sentinel automatically switches to Groq (llama-3.3-70b-versatile) as fallback. Zero interruption to enforcement.

**How do I update Sentinel?**
Run `start.sh` again. It updates the package while preserving your existing `.env` configuration.

**Is developer activity logged?**
Yes. Every blocked commit is recorded as a GitHub Issue with machine identity, username, timestamp, and violation details — creating an immutable audit trail.

**How is Sentinel different from Auditor Core?**
Sentinel is a real-time gate — it intercepts every commit automatically. [Auditor Core](https://datawizual.github.io) is a deep on-demand audit engine for comprehensive posture reports. Sentinel uses Auditor Core internally as its scanning engine.

---

## Support

📧 **eldorzufarov66@gmail.com**

Please include: Machine ID · OS version · Python version · description of the issue.

---

<div align="center">

© 2026 DataWizual Security Labs. All rights reserved.

Use governed by [TERMS_OF_USE.md](TERMS_OF_USE.md)

</div>
