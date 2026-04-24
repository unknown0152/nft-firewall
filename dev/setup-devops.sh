#!/usr/bin/env bash
set -euo pipefail

PROJECT_DIR="${PROJECT_DIR:-$PWD}"
BRANCH_BASE="${BRANCH_BASE:-v12-dev}"
BRANCH_WORK="${BRANCH_WORK:-v12.1-smartops-safety}"

echo "== NFT Firewall DevOps Bootstrap =="
echo "Project: $PROJECT_DIR"

cd "$PROJECT_DIR"

echo "== Installing system packages =="
sudo apt update
sudo apt install -y \
  git curl jq unzip ca-certificates \
  python3 python3-venv python3-pip \
  shellcheck \
  nftables wireguard-tools \
  systemd

echo "== Installing Node.js/npm if needed =="
if ! command -v npm >/dev/null 2>&1; then
  sudo apt install -y nodejs npm
fi

echo "== Installing Codex CLI =="
sudo npm i -g @openai/codex

echo "== Creating Python venv =="
python3 -m venv .venv
. .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install pytest ruff

echo "== Creating/normalizing Git repo =="
if [ ! -d .git ]; then
  git init
fi

git add .
git commit -m "baseline before devops bootstrap" || true

if git show-ref --verify --quiet "refs/heads/$BRANCH_BASE"; then
  git checkout "$BRANCH_BASE"
else
  git checkout -b "$BRANCH_BASE"
fi

if git show-ref --verify --quiet "refs/heads/$BRANCH_WORK"; then
  git checkout "$BRANCH_WORK"
else
  git checkout -b "$BRANCH_WORK"
fi

echo "== Writing ruff config =="
cat > pyproject.toml <<'EOF'
[tool.ruff]
line-length = 100
target-version = "py311"

[tool.ruff.lint]
select = ["E", "F", "I", "UP", "B", "SIM"]
ignore = ["E501"]

[tool.pytest.ini_options]
testpaths = ["tests"]
python_files = ["test_*.py"]
EOF

mkdir -p tests scripts systemd .github/workflows

echo "== Creating safe nft check script =="
cat > scripts/nft-check-ruleset.sh <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

RULESET="${1:-}"

if [ -z "$RULESET" ]; then
  echo "Usage: $0 /path/to/ruleset.nft" >&2
  exit 2
fi

if [ ! -f "$RULESET" ]; then
  echo "FAIL: ruleset not found: $RULESET" >&2
  exit 1
fi

sudo nft --check -f "$RULESET"
echo "OK: nft ruleset syntax is valid: $RULESET"
EOF
chmod +x scripts/nft-check-ruleset.sh

echo "== Creating pre-apply wrapper =="
cat > scripts/safe-nft-apply.sh <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

RULESET="${1:-}"
BACKUP_DIR="${BACKUP_DIR:-/var/backups/nft-firewall}"
TS="$(date +%Y%m%d-%H%M%S)"
BACKUP_FILE="$BACKUP_DIR/ruleset-before-$TS.nft"

if [ -z "$RULESET" ]; then
  echo "Usage: $0 /path/to/ruleset.nft" >&2
  exit 2
fi

if [ ! -f "$RULESET" ]; then
  echo "FAIL: ruleset not found: $RULESET" >&2
  exit 1
fi

sudo mkdir -p "$BACKUP_DIR"

echo "Backing up current nft ruleset to $BACKUP_FILE"
sudo nft list ruleset | sudo tee "$BACKUP_FILE" >/dev/null

echo "Checking new ruleset..."
sudo nft --check -f "$RULESET"

echo "Applying new ruleset..."
sudo nft -f "$RULESET"

echo "OK: ruleset applied."
echo "Backup: $BACKUP_FILE"
EOF
chmod +x scripts/safe-nft-apply.sh

echo "== Creating dev check script =="
cat > scripts/dev-check.sh <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

echo "== Ruff check =="
. .venv/bin/activate
ruff check .

echo "== ShellCheck =="
find . -type f \( -name "*.sh" -o -path "./scripts/*" \) -print0 \
  | xargs -0 -r shellcheck

echo "== Pytest =="
pytest -q

echo "OK: all dev checks passed."
EOF
chmod +x scripts/dev-check.sh

echo "== Creating GitHub Actions workflow =="
cat > .github/workflows/ci.yml <<'EOF'
name: NFT Firewall CI

on:
  pull_request:
  push:
    branches:
      - v12-dev
      - v12.1-smartops-safety
      - main
      - master

jobs:
  test:
    runs-on: ubuntu-latest

    steps:
      - uses: actions/checkout@v4

      - name: Install system tools
        run: |
          sudo apt update
          sudo apt install -y shellcheck nftables

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: "3.11"

      - name: Install Python tools
        run: |
          python -m pip install --upgrade pip
          pip install pytest ruff

      - name: Ruff
        run: ruff check .

      - name: ShellCheck
        run: |
          find . -type f \( -name "*.sh" -o -path "./scripts/*" \) -print0 \
            | xargs -0 -r shellcheck

      - name: Pytest
        run: pytest -q
EOF

echo "== Creating systemd service/timer examples =="
cat > systemd/nft-firewall-doctor.service <<'EOF'
[Unit]
Description=NFT Firewall doctor check

[Service]
Type=oneshot
User=fw-admin
ExecStart=/usr/local/bin/fw doctor
EOF

cat > systemd/nft-firewall-doctor.timer <<'EOF'
[Unit]
Description=Run NFT Firewall doctor every 15 minutes

[Timer]
OnBootSec=2min
OnUnitActiveSec=15min
Persistent=true

[Install]
WantedBy=timers.target
EOF

cat > systemd/nft-firewall-threatfeed.service <<'EOF'
[Unit]
Description=NFT Firewall threat feed update

[Service]
Type=oneshot
User=fw-admin
ExecStart=/usr/local/bin/fw threatfeed update
EOF

cat > systemd/nft-firewall-threatfeed.timer <<'EOF'
[Unit]
Description=Run NFT Firewall threat feed update hourly

[Timer]
OnBootSec=5min
OnUnitActiveSec=1h
Persistent=true

[Install]
WantedBy=timers.target
EOF

echo "== Creating Codex prompt file =="
cat > CODEX_V12_1_PROMPT.md <<'EOF'
You are working on my NFT Firewall project, branch v12.1-smartops-safety.

Goal: implement V12.1 SmartOps Safety Layer.

Focus only on:
- fw wrapper command
- fw doctor
- fw safe-apply
- shared IP/CIDR validation
- never_block protection
- persistent dynamic nft sets
- least-privilege sudoers wrappers
- safer setup
- tests

Hard rules:
- Do not weaken VPN killswitch logic.
- Do not remove SSH safety protections.
- Do not apply live firewall rules without explicit user approval.
- Do not use broad sudoers wildcards.
- Always run nft --check before any apply.
- Keep changes reviewable in git.
EOF

echo "== Committing bootstrap files =="
git add .
git commit -m "add devops bootstrap tooling for smartops safety layer" || true

echo
echo "DONE."
echo
echo "Next commands:"
echo "  codex login --device-auth"
echo "  codex"
echo
echo "Codex CLI can be installed with npm and run locally in a repo; it supports ChatGPT sign-in or API key auth. Treat ~/.codex/auth.json like a password."
