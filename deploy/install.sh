#!/usr/bin/env bash
# Install the SPP v1 durable relay as a systemd service.
#
# Usage:
#   sudo bash deploy/install.sh [REPO_URL] [INSTALL_ROOT]
#
# Defaults:
#   REPO_URL     https://github.com/Drefetr/swarm-pointer-protocol
#   INSTALL_ROOT /opt/spp
#
# Creates the unprivileged `spp` user, clones the repository, installs the
# systemd unit from deploy/spp-relay.service, writes a starter configuration at
# /etc/spp/relay.conf.json, and starts the relay. Re-running updates the tree
# in place (git pull) and restarts the service. It never touches the database
# at /var/lib/spp/relay.sqlite3.

set -euo pipefail

REPO_URL="${1:-https://github.com/Drefetr/swarm-pointer-protocol}"
INSTALL_ROOT="${2:-/opt/spp}"
SERVICE_USER="spp"
SERVICE_NAME="spp-relay"
DATA_DIR="/var/lib/spp"
CONFIG_DIR="/etc/spp"
CONFIG="${CONFIG_DIR}/relay.conf.json"
UNIT="/etc/systemd/system/${SERVICE_NAME}.service"

if [ "$(id -u)" -ne 0 ]; then
    echo "install.sh: run as root (sudo bash deploy/install.sh)" >&2
    exit 1
fi

for tool in python3 git systemctl; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        echo "install.sh: required tool not found: $tool" >&2
        exit 1
    fi
done

if ! id -u "$SERVICE_USER" >/dev/null 2>&1; then
    useradd --system --user-group --home-dir "$INSTALL_ROOT" --shell /usr/sbin/nologin "$SERVICE_USER"
fi

if [ -d "$INSTALL_ROOT/.git" ]; then
    git -C "$INSTALL_ROOT" pull --ff-only
elif [ -e "$INSTALL_ROOT" ] && [ -n "$(ls -A "$INSTALL_ROOT" 2>/dev/null)" ]; then
    echo "install.sh: $INSTALL_ROOT exists and is not a git checkout; refusing to overwrite" >&2
    exit 1
else
    git clone "$REPO_URL" "$INSTALL_ROOT"
fi

if [ ! -f "$INSTALL_ROOT/implementations/relay/server.py" ]; then
    echo "install.sh: $INSTALL_ROOT does not look like the SPP repository" >&2
    exit 1
fi

install -d -o "$SERVICE_USER" -g "$SERVICE_USER" -m 0750 "$DATA_DIR" "$CONFIG_DIR"
if [ ! -f "$CONFIG" ]; then
    printf '{\n  "bootstrap_channels": []\n}\n' > "$CONFIG"
fi
chown "root:${SERVICE_USER}" "$CONFIG"
chmod 0640 "$CONFIG"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
sed "s#__SPP_ROOT__#${INSTALL_ROOT}#g" "$SCRIPT_DIR/spp-relay.service" > "$UNIT"
chmod 0644 "$UNIT"

systemctl daemon-reload
systemctl enable "$SERVICE_NAME"
systemctl reset-failed "$SERVICE_NAME" 2>/dev/null || true
systemctl restart "$SERVICE_NAME"

echo "installed ${SERVICE_NAME}"
echo "config:   ${CONFIG}"
echo "database: ${DATA_DIR}/relay.sqlite3"
echo "verify:   curl -fsS http://127.0.0.1:18760/.well-known/spp"
