#!/usr/bin/env bash
set -euo pipefail

# --- Configurable destinations (under ~) ---
DEST_BASE="$HOME/configuration"
DEST_IMAGE_BUILD="$DEST_BASE/image_builds/dtrack-satellite"
DEST_QUADLETS="$DEST_BASE/quadlets"
DEST_SECRETS="$DEST_BASE/secrets"
DEST_ENV_FILE="$DEST_SECRETS/dtrack.env"

# Quadlet systemd directory
QUADLET_SYSTEMD_DIR="$HOME/.config/containers/systemd"

# --- Helpers ---
log() {
    echo "[install] $*" >&2
}

prompt_with_default() {
    local prompt="$1"
    local default="$2"
    local var
    if [ -n "$default" ]; then
        read -r -p "$prompt [$default]: " var || true
        echo "${var:-$default}"
    else
        read -r -p "$prompt: " var || true
        echo "$var"
    fi
}

prompt_required_secret() {
    local prompt="$1"
    local value=""
    while [ -z "$value" ]; do
        echo -n "$prompt (required): " >&2
        read -r value || true
        if [ -z "$value" ]; then
            echo "Value is required, please try again." >&2
        fi
    done
    echo "$value"
}

# --- Locate source tree ---
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

TEMPLATE_ENV="$SCRIPT_DIR/dtrack.env"
if [ ! -f "$TEMPLATE_ENV" ]; then
    log "ERROR: dtrack.env template not found."
    exit 1
fi

# --- Prepare destination directories ---
log "Creating destination directories under $DEST_BASE"
mkdir -p "$DEST_IMAGE_BUILD" "$DEST_QUADLETS" "$DEST_SECRETS" "$QUADLET_SYSTEMD_DIR"

# --- Copy files ---
log "Copying Containerfile and satellite.py"
cp "$SCRIPT_DIR/podman/Containerfile" "$DEST_IMAGE_BUILD/Containerfile"
cp "$SCRIPT_DIR/podman/satellite.py" "$DEST_IMAGE_BUILD/satellite.py"

log "Copying quadlet files"
cp "$SCRIPT_DIR/quadlets/dtrack-satellite.container" "$DEST_QUADLETS/dtrack-satellite.container"
cp "$SCRIPT_DIR/quadlets/satellite-network.network" "$DEST_QUADLETS/satellite-network.network"

log "Copying dtrack.env template"
cp "$TEMPLATE_ENV" "$DEST_ENV_FILE"

# --- Default Values ---
DT_URL_DEFAULT=$(grep -E '^DT_URL=' "$DEST_ENV_FILE" | cut -d= -f2- || true)
DT_URL_DEFAULT=${DT_URL_DEFAULT:-"https://api.dtrack.humlab.umu.se"}

SCAN_INTERVAL_DEFAULT=$(grep -E '^SCAN_INTERVAL_SECONDS=' "$DEST_ENV_FILE" | cut -d= -f2- || true)
SCAN_INTERVAL_DEFAULT=${SCAN_INTERVAL_DEFAULT:-"86400"}

DT_PROJECT_VERSION_DEFAULT=$(grep -E '^DT_PROJECT_VERSION=' "$DEST_ENV_FILE" | cut -d= -f2- || true)
DT_PROJECT_VERSION_DEFAULT=${DT_PROJECT_VERSION_DEFAULT:-"v0.0.0"}

PARENT_DIR="$(dirname "$(pwd)")"
DT_PROJECT_NAME_DEFAULT="$(basename "$PARENT_DIR")"

if [ -r /etc/hostname ]; then
    SERVER_HOSTNAME_DEFAULT="$(tr -d '\n' < /etc/hostname)"
else
    SERVER_HOSTNAME_DEFAULT="$(hostname || echo "")"
fi

# --- Prompts ---
echo
echo "=== dtrack-satellite configuration ==="
echo

DT_URL="$(prompt_with_default "DT_URL" "$DT_URL_DEFAULT")"
DT_API_KEY="$(prompt_required_secret "DT_API_KEY")"
DT_PROJECT_NAME="$(prompt_with_default "DT_PROJECT_NAME" "$DT_PROJECT_NAME_DEFAULT")"
SCAN_INTERVAL_SECONDS="$(prompt_with_default "SCAN_INTERVAL_SECONDS" "$SCAN_INTERVAL_DEFAULT")"
SERVER_HOSTNAME="$(prompt_with_default "SERVER_HOSTNAME" "$SERVER_HOSTNAME_DEFAULT")"
DT_PROJECT_VERSION="$DT_PROJECT_VERSION_DEFAULT"

echo
echo "Writing updated configuration to: $DEST_ENV_FILE"
cat >"$DEST_ENV_FILE" <<EOF
DT_URL=$DT_URL
DT_API_KEY=$DT_API_KEY
DT_PROJECT_NAME=$DT_PROJECT_NAME
DT_PROJECT_VERSION=$DT_PROJECT_VERSION
SCAN_INTERVAL_SECONDS=$SCAN_INTERVAL_SECONDS
SERVER_HOSTNAME=$SERVER_HOSTNAME
EOF

chmod 600 "$DEST_ENV_FILE" || true

# --- Symlinking Quadlets ---
log "Setting up quadlet symlinks in $QUADLET_SYSTEMD_DIR"

link_quadlet() {
    local filename="$1"
    local target_file="$DEST_QUADLETS/$filename"
    local link_path="$QUADLET_SYSTEMD_DIR/$filename"

    # Remove existing (even if broken)
    if [ -L "$link_path" ] || [ -e "$link_path" ]; then
        rm -f "$link_path"
    fi

    ln -s "$target_file" "$link_path"
    log "Symlinked: $link_path -> $target_file"
}

link_quadlet "dtrack-satellite.container"
link_quadlet "satellite-network.network"

# --- Systemd Reload ---
echo
log "Reloading systemd user units"

if systemctl --user daemon-reload; then
    log "Enabling and starting dtrack-satellite.service"

    if systemctl --user enable --now dtrack-satellite.service; then
        log "dtrack-satellite.service enabled and started"
    else
        log "WARNING: Could not enable/start service"
    fi
else
    log "WARNING: systemctl --user daemon-reload failed"
fi

echo
echo "Installation complete."
echo "Quadlets installed in: $DEST_QUADLETS"
echo "Symlinks created in:   $QUADLET_SYSTEMD_DIR"
echo "Environment file:      $DEST_ENV_FILE"
