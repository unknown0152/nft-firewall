#!/usr/bin/env bash
set -euo pipefail

FW_USER="fw-admin"
LEGACY_FW_USER="nft-firewall"
ADMIN_USER="nuc"
MEDIA_USER="media"
BACKUP_USER="backup"
DEPLOY_USER="deploy"

FIREWALL_DIRS=(
  /opt/nft-firewall
  /var/lib/nft-firewall
  /var/log/nft-firewall
  /etc/nft-firewall
)
MEDIA_COMPOSE_DIR="/home/media/compose"
COSMOS_COMPOSE_DIR="/home/media/compose/cosmos"

need_root() {
  if [ "$(id -u)" -ne 0 ]; then
    echo "setup.sh must run as root: sudo bash setup.sh" >&2
    exit 1
  fi
}

ensure_group() {
  local group="$1"
  if ! getent group "$group" >/dev/null; then
    groupadd "$group"
  fi
}

ensure_user() {
  local user="$1"
  local home="$2"
  local shell="$3"
  local mode="$4"

  if id "$user" >/dev/null 2>&1; then
    return
  fi

  if [ "$mode" = "system" ]; then
    useradd --system --user-group --no-create-home --shell "$shell" "$user"
  else
    useradd --user-group --create-home --home-dir "$home" --shell "$shell" "$user"
  fi
}

migrate_legacy_firewall_user() {
  if id "$LEGACY_FW_USER" >/dev/null 2>&1 && ! id "$FW_USER" >/dev/null 2>&1; then
    usermod --login "$FW_USER" "$LEGACY_FW_USER"
    if getent group "$LEGACY_FW_USER" >/dev/null && ! getent group "$FW_USER" >/dev/null; then
      groupmod --new-name "$FW_USER" "$LEGACY_FW_USER"
    fi
    usermod --shell /bin/false "$FW_USER"
  fi
}

add_to_group_if_user_exists() {
  local user="$1"
  local group="$2"
  if id "$user" >/dev/null 2>&1; then
    usermod --append --groups "$group" "$user"
  fi
}

remove_from_group_if_member() {
  local user="$1"
  local group="$2"
  if id "$user" >/dev/null 2>&1 && id -nG "$user" | tr ' ' '\n' | grep -qx "$group"; then
    gpasswd --delete "$user" "$group" >/dev/null || true
  fi
}

need_root

echo "== nft-firewall base user model =="
migrate_legacy_firewall_user
ensure_user "$FW_USER" "" /bin/false system
ensure_user "$MEDIA_USER" /home/media /bin/bash regular
ensure_user "$BACKUP_USER" /home/backup /bin/bash regular
ensure_user "$DEPLOY_USER" /home/deploy /bin/bash regular

ensure_group docker
add_to_group_if_user_exists "$MEDIA_USER" docker
add_to_group_if_user_exists "$ADMIN_USER" docker
remove_from_group_if_member "$FW_USER" docker

for dir in "${FIREWALL_DIRS[@]}"; do
  mkdir -p "$dir"
  chown -R "$FW_USER:$FW_USER" "$dir"
done

mkdir -p "$COSMOS_COMPOSE_DIR"
chown -R "$MEDIA_USER:$MEDIA_USER" "$MEDIA_COMPOSE_DIR"

cat <<EOF
User model ready:
  $ADMIN_USER  = human admin/dev user
  $FW_USER = nft-firewall runtime/systemd user
  $MEDIA_USER = Docker/Cosmos/compose runtime user
  $BACKUP_USER = backup user
  $DEPLOY_USER = rsync/deploy user

Next:
  1. Copy nft-firewall code as $ADMIN_USER.
  2. Install firewall with: sudo python3 setup.py install
  3. Run Cosmos compose as $MEDIA_USER from $COSMOS_COMPOSE_DIR.
EOF
