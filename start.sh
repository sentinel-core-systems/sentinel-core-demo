#!/bin/bash
# =================================================================
# SENTINEL CORE — UNIFIED PROVISIONING SCRIPT
# DataWizual Security (c) 2026
# =================================================================

set -e

GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BOLD='\033[1m'
NC='\033[0m'

ok()   { echo -e "${GREEN}✅ $1${NC}"; }
info() { echo -e "${BLUE}ℹ️  $1${NC}"; }
warn() { echo -e "${YELLOW}⚠️  $1${NC}"; }
fail() { echo -e "${RED}❌ $1${NC}"; exit 1; }

# =================================================================
# STEP 1 — TERMS OF USE
# =================================================================
echo ""
echo -e "${BOLD}------------------------------------------------------------"
echo "🛡️  DATAWIZUAL SECURITY — SENTINEL CORE DEMO"
echo "------------------------------------------------------------${NC}"
echo "This installation is subject to the Terms of Use"
echo "defined in TERMS_OF_USE.md."
echo ""
echo "By typing YES, you acknowledge that:"
echo "  1. Software is provided 'AS-IS' (No Financial Liability)."
echo "  2. You are responsible for all security decisions & overrides."
echo "  3. Machine ID submission constitutes full acceptance of Terms."
echo "------------------------------------------------------------"
echo ""
read -p "Type YES to accept terms and proceed: " confirm
[ "$confirm" != "YES" ] && fail "Installation aborted. Terms of Use must be accepted."

# =================================================================
# STEP 2 — PYTHON CHECK
# =================================================================
info "Checking Python version..."
python3 --version >/dev/null 2>&1 || fail "Python 3 not found. Install Python 3.10+ and retry."
PY_VER=$(python3 -c "import sys; print(sys.version_info.minor)")
[ "$PY_VER" -lt 10 ] && fail "Python 3.10+ required. Found: $(python3 --version)"
ok "Python OK"

# =================================================================
# STEP 3 — VIRTUAL ENVIRONMENT
# =================================================================
if [ ! -d "venv" ]; then
    info "Creating virtual environment..."
    python3 -m venv venv
fi
source venv/bin/activate
SENTINEL_BIN="$(pwd)/venv/bin/sentinel"
info "Installing/updating dependencies..."
pip install -q --upgrade pip
ok "pip updated"

# =================================================================
# STEP 4 — INSTALL SENTINEL FROM GITHUB (Before Machine ID — sentinel needed)
# =================================================================
echo ""
info "Installing Sentinel Core from GitHub..."

read -p "  Enter Sentinel Core repository URL: " SENTINEL_REPO_URL
[ -z "$SENTINEL_REPO_URL" ] && fail "Repository URL is required."
SENTINEL_REPO_URL="${SENTINEL_REPO_URL%.git}"

read -p "  Enter Install Token (press Enter for public repo): " install_token
if [ -n "$install_token" ]; then
    pip install -q \
        git+https://x-access-token:${install_token}@${SENTINEL_REPO_URL#https://}.git@main \
        && ok "Sentinel installed from GitHub" \
        || warn "GitHub install failed — trying public install"
    unset install_token
fi

if ! python3 -c "import sentinel" 2>/dev/null; then
    pip install -q \
        git+${SENTINEL_REPO_URL}.git@main \
        && ok "Sentinel installed from public repository" \
        || fail "Installation failed. Check repository URL."
fi

# =================================================================
# STEP 5 — COPY CONFIG FILES FROM INSTALLED PACKAGE
# =================================================================
info "Copying configuration files from package..."

PKG_DIR=$(python3 -c "
import importlib.util, os
spec = importlib.util.find_spec('sentinel')
if spec:
    print(os.path.dirname(os.path.dirname(spec.origin)))
" 2>/dev/null || echo "")

# .env.example embedded in start.sh — independent of network or package
if [ ! -f ".env.example" ]; then
    cat > .env.example << 'ENVEOF'
# ============================================================
# Sentinel Core — Environment Configuration
# Copy to .env and fill with your values:
#   cp .env.example .env
# ============================================================

# --- Licensing ---
# Get Machine ID: python3 get_id.py
# Send to eldorzufarov66@gmail.com to receive your key
AUDITOR_LICENSE_KEY=YOUR_LICENSE_KEY_HERE
SENTINEL_LICENSE_KEY=YOUR_LICENSE_KEY_HERE
SENTINEL_ALERT_TOKEN=YOUR_GITHUB_TOKEN_HERE
SENTINEL_ADMIN_REPO=YOUR_ADMIN_REPO

# --- AI Advisory (Google Gemini) ---
GOOGLE_API_KEY=YOUR_GEMINI_API_KEY_HERE
GOOGLE_MODEL=gemini-2.5-flash

# --- AI Advisory (Groq — optional) ---
GROQ_API_KEY=YOUR_GROQ_API_KEY_HERE
GROQ_MODEL=llama-3.3-70b-versatile

# --- Scanner Limits ---
MAX_FINDINGS=5000
MAX_FILE_SIZE=1048576

# --- Logging ---
LOG_LEVEL=INFO
ENVEOF
    ok ".env.example created"
fi

# audit-config.yml — embedded configuration
if [ ! -f "audit-config.yml" ]; then
    cat > audit-config.yml << 'CFGEOF'
# Auditor Core — Internal configuration for Sentinel operations
scanner:
  offline_mode: false
  baseline_file: "baseline.json"
  max_file_size_kb: 500
  exclude_patterns:
    - "*.min.js"
    - "*.lock"
    - "*.pyc"
    - "*.whl"
    - "*.so"
    - "*.pack"
    - "node_modules/*"
    - "venv/*"
    - ".venv/*"
    - ".git/*"
    - "__pycache__/*"
    - "dist/*"
    - "build/*"
    - "reports/*"
    - "site-packages/*"

detectors:
  bandit_detector: true
  semgrep_detector: true
  gitleaks_detector: true
  secret_detector: true
  dependency_scanner: true
  iac_scanner: true
  cicd_analyzer: true
  sast_scanner: true
  slither_detector: false
  license_scanner: false

ai:
  enabled: true
  mode: "external"
  provider: "google"
  model: "gemini-2.5-flash"
  max_findings_per_scan: 15
  min_severity_for_ai: "LOW"
  batch_size: 3
  sleep_between_batches: 20

reporting:
  output_dir: "reports"

policy:
  fail_on_severity: "HIGH"
  min_severity_for_ai: "LOW"
CFGEOF
    ok "audit-config.yml created"
fi

# =================================================================
# STEP 6 — MACHINE ID (Sentinel is now installed)
# =================================================================
echo ""
info "Detecting Machine ID for license binding..."
MACHINE_ID=$(python3 -c "
import os
os.environ.setdefault('AUDITOR_LICENSE_SALT', 'placeholder')
try:
    from auditor.security.guard import AuditorGuard
    print(AuditorGuard().get_machine_id())
except Exception:
    print('UNKNOWN')
" 2>/dev/null || echo "UNKNOWN")
echo ""
echo -e "${BOLD}  Your Machine ID: ${YELLOW}${MACHINE_ID}${NC}"
echo ""
echo "  Send this ID to DataWizual Security to receive your License Key."
echo "  Contact: eldorzufarov66@gmail.com"
echo ""

# =================================================================
# STEP 7 — ENVIRONMENT CONFIGURATION (.env)
# =================================================================
if [ ! -f ".env" ]; then
    info "Configuring environment..."
    [ ! -f ".env.example" ] && fail ".env.example not found."
    cp .env.example .env

    echo ""
    echo -e "${YELLOW}📋 License Key Setup${NC}"
    echo "You have 3 free trial runs without a license key."
    echo "To get a full license: eldorzufarov66@gmail.com"
    echo ""
    read -p "  Enter License Key (press Enter to use trial mode): " license_key

    read -s -p "  Enter Google Gemini API Key: " gemini_key
    echo ""
    [ -z "$gemini_key" ] && warn "Gemini API Key not set. AI analysis will be disabled."

    read -p "  Enter Gemini Model [gemini-2.5-flash]: " gemini_model
    gemini_model=${gemini_model:-gemini-2.5-flash}

    read -s -p "  Enter GitHub Alert Token: " alert_token
    echo ""
    [ -z "$alert_token" ] && warn "GitHub Alert Token not set. Remote reporting disabled."

    read -p "  Enter Admin Repo (e.g. your-org/your-repo): " admin_repo
    admin_repo=${admin_repo:-YOUR_ADMIN_REPO}

    python3 - << PYEOF
content = open('.env').read()
replacements = {
    'YOUR_LICENSE_KEY_HERE': '${license_key}',
    'YOUR_GEMINI_API_KEY_HERE': '${gemini_key}',
    '<KEY>': '${gemini_key}',
    'gemini-2.5-flash': '${gemini_model}',
    'YOUR_GITHUB_TOKEN_HERE': '${alert_token}',
    'YOUR_ADMIN_REPO': '${admin_repo}',
}
for old, new in replacements.items():
    content = content.replace(old, new)
open('.env', 'w').write(content)
PYEOF

    chmod 600 .env
    ok ".env configured"
else
    ok ".env already exists — skipping configuration"
fi

# =================================================================
# STEP 8 — SENTINEL INIT
# =================================================================
source .env 2>/dev/null || true

if [ -n "$license_key" ]; then
    info "Initializing Sentinel with license..."
    SENTINEL_LICENSE_KEY="$license_key" \
    AUDITOR_LICENSE_KEY="$license_key" \
    "$SENTINEL_BIN" init \
        --token "${alert_token:-$SENTINEL_ALERT_TOKEN}" \
        --repo "${admin_repo:-${SENTINEL_ADMIN_REPO:-YOUR_ADMIN_REPO}}" \
        && ok "Sentinel initialized" \
        || warn "Init failed — check your license key"
else
    echo -e "${YELLOW}⚠️  Trial mode active (3 free runs). To get a license: eldorzufarov66@gmail.com${NC}"
fi

# =================================================================
# STEP 9 — PRE-COMMIT HOOK (With full path to sentinel)
# =================================================================
if [ ! -d ".git" ]; then
    info "No git repository found — initializing..."
    git init && ok "Git repository initialized"
fi

if [ -d ".git" ]; then
    info "Installing pre-commit security hook..."

    # Remove old hooks to avoid conflicts
    rm -f .git/hooks/pre-commit .git/hooks/pre-commit.legacy

    cat > .git/hooks/pre-commit << HOOKEOF
#!/bin/bash
SENTINEL="${SENTINEL_BIN}"
echo "🔍 Sentinel is verifying commit security..."
"\${SENTINEL}" scan . || exit 1
HOOKEOF

    chmod +x .git/hooks/pre-commit
    ok "Pre-commit hook installed"
else
    warn "Not a git repository — pre-commit hook skipped"
fi

# =================================================================
# CLEANUP
# =================================================================
unset install_token gemini_key alert_token
history -c 2>/dev/null || true

# =================================================================
# DONE
# =================================================================
echo ""
echo -e "${BOLD}${GREEN}------------------------------------------------------------"
echo "✅ SENTINEL CORE DEMO DEPLOYED SUCCESSFULLY"
echo "------------------------------------------------------------${NC}"
echo ""
echo -e "  Run security scan:  ${YELLOW}${SENTINEL_BIN} scan .${NC}"
echo -e "  Run with report:    ${YELLOW}${SENTINEL_BIN} scan . --report${NC}"
echo -e "  View Machine ID:    ${YELLOW}${SENTINEL_BIN} --id${NC}"
echo ""