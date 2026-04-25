#!/usr/bin/env bash
set -euo pipefail

echo "[+] NFT Firewall + Cosmos Installer"

COSMOS_HTTP_PORT="${COSMOS_HTTP_PORT:-80}"
COSMOS_HTTPS_PORT="${COSMOS_HTTPS_PORT:-443}"

detect_user() {
  if [[ -n "${SUDO_USER:-}" && "${SUDO_USER}" != "root" ]]; then
    echo "$SUDO_USER"
    return
  fi

  if logname >/dev/null 2>&1; then
    local u
    u="$(logname)"
    if [[ "$u" != "root" ]]; then
      echo "$u"
      return
    fi
  fi

  awk -F: '$3>=1000 && $1!="nobody"{print $1; exit}' /etc/passwd
}

echo "[+] Checking sudo / user setup..."

if [[ "$EUID" -ne 0 ]]; then
  echo "[ERROR] Run this installer as root or with sudo:"
  echo "  sudo ./install.sh"
  exit 1
fi

if ! command -v sudo >/dev/null 2>&1; then
  echo "[+] Installing sudo..."
  apt-get update
  apt-get install -y sudo
fi

TARGET_USER="$(detect_user || true)"

if [[ -n "$TARGET_USER" ]]; then
  echo "[+] Ensuring $TARGET_USER is in sudo group..."
  usermod -aG sudo "$TARGET_USER" || true
  echo "[!] $TARGET_USER may need to log out/in or reboot for sudo group changes to apply."
else
  echo "[!] No normal non-root user detected — skipping sudo group setup."
fi

cosmos_installed() {
  [[ -s /etc/systemd/system/CosmosCloud.service ]] || [[ -x /opt/cosmos/start.sh ]]
}

echo "[+] Installing base dependencies..."
apt-get update
apt-get install -y curl python3 sudo systemd git

echo "[+] Downloading nft-firewall source..."
INSTALL_TMP=$(mktemp -d /tmp/nft-firewall-install.XXXXXX)
git clone https://github.com/unknown0152/nft-firewall.git "$INSTALL_TMP"
cd "$INSTALL_TMP"

echo "[+] Installing nft-firewall..."
python3 setup.py install </dev/tty

echo "[+] Installing or hardening Cosmos..."

if cosmos_installed; then
  echo "[+] Cosmos already installed — skipping installer, applying hardening only"
else
  echo "[+] Downloading Cosmos installer..."

  COSMOS_INSTALLER="$(mktemp /tmp/cosmos-get.XXXXXX.sh)"
  curl -fL https://cosmos-cloud.io/get.sh -o "$COSMOS_INSTALLER"
  chmod +x "$COSMOS_INSTALLER"

  echo "[+] Patching Cosmos installer to skip iptables..."

  python3 - "$COSMOS_INSTALLER" <<'PY'
from pathlib import Path
import sys

p = Path(sys.argv[1])
s = p.read_text()

start = s.find("check_ports()")
if start == -1:
    raise SystemExit("check_ports() not found")

brace = s.find("{", start)
depth = 0
end = None

for i in range(brace, len(s)):
    if s[i] == "{":
        depth += 1
    elif s[i] == "}":
        depth -= 1
        if depth == 0:
            end = i + 1
            break

if end is None:
    raise SystemExit("Could not locate end of check_ports()")

replacement = '''check_ports() {
    echo "[+] Skipping Cosmos iptables firewall configuration; nft-firewall manages ports."
}
'''

p.write_text(s[:start] + replacement + s[end:])
PY

  export COSMOS_HTTP_PORT
  export COSMOS_HTTPS_PORT
  export NO_DOCKER=1

  bash "$COSMOS_INSTALLER"
fi

echo "[+] Applying Cosmos least-privilege hardening..."

# Fix Cosmos start.sh pathing (must cd to /opt/cosmos)
if [[ -f /opt/cosmos/start.sh ]]; then
  echo "[+] Fixing Cosmos start.sh pathing..."
  cat > /opt/cosmos/start.sh <<'EOF'
#!/bin/bash
cd /opt/cosmos
chmod +x cosmos
chmod +x cosmos-launcher
./cosmos-launcher && ./cosmos
EOF
  chmod +x /opt/cosmos/start.sh
fi

id media >/dev/null 2>&1 || useradd -m -s /bin/bash media

if getent group docker >/dev/null 2>&1; then
  usermod -aG docker media || true
fi

cat > /usr/local/bin/fix-cosmos-perms <<'EOF'
#!/usr/bin/env bash
set -e
chown -R media:media /opt/cosmos /var/lib/cosmos 2>/dev/null || true
chmod -R u+rwX /var/lib/cosmos 2>/dev/null || true
EOF

chmod +x /usr/local/bin/fix-cosmos-perms

chown -R media:media /opt/cosmos 2>/dev/null || true
chown -R media:media /var/lib/cosmos 2>/dev/null || true
chmod -R u+rwX /var/lib/cosmos 2>/dev/null || true

echo "[+] Applying systemd override..."

mkdir -p /etc/systemd/system/CosmosCloud.service.d

cat > /etc/systemd/system/CosmosCloud.service.d/override.conf <<'EOF'
[Service]
User=media
Group=media
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
ExecStartPre=/usr/local/bin/fix-cosmos-perms
EOF

echo "[+] Ensuring Docker firewall authority is disabled..."
mkdir -p /etc/docker
if [[ ! -f /etc/docker/daemon.json ]]; then
  echo '{"iptables": false, "ip6tables": false}' > /etc/docker/daemon.json
  systemctl restart docker || true
fi

echo "[+] Enabling nftables service..."
systemctl enable --now nftables || true

echo "[+] Optional: Keybase ChatOps setup"
read -p "  Would you like to install Keybase for ChatOps? [y/N]: " install_kb
if [[ "$install_kb" =~ ^[Yy]$ ]]; then
  echo "[+] Downloading Keybase..."
  curl -O https://prerelease.keybase.io/keybase_amd64.deb
  echo "[+] Installing Keybase dependencies..."
  apt-get update
  apt-get install -y ./keybase_amd64.deb
  rm keybase_amd64.deb
  echo "[!] Keybase installed. IMPORTANT: You must log in manually to enable ChatOps:"
  echo "    1. Run: keybase login"
  echo "    2. Then run: fw menu (Option 0) to restart the listener"
fi

echo "[+] Reloading systemd..."
systemctl daemon-reload

if cosmos_installed; then
  echo "[+] Restarting CosmosCloud..."
  systemctl restart CosmosCloud
fi

echo "[+] Running verification..."

if command -v fw >/dev/null 2>&1; then
  fw doctor || true
fi

if cosmos_installed; then
  systemctl status CosmosCloud --no-pager || true
  ps -eo user,cmd | grep cosmos | grep -v grep || true
  ss -tulpen | grep -E ':80|:443' || true
fi

echo
echo "[OK] Installer finished."
echo
echo "Expected clean state:"
echo "  - nft-firewall runs as fw-admin"
echo "  - Cosmos runs as media (NOT root)"
echo "  - Docker iptables/ip6tables are disabled"
echo "  - nftables is the only firewall"
echo "  - LAN is restricted (if strict mode enabled)"
echo "  - Cosmos 80/443 only reachable via allowed interfaces"
