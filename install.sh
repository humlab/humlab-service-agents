#!/usr/bin/env bash
set -euo pipefail

# --- Configurable destinations (under ~) ---
DEST_BASE="$HOME/configuration"
DEST_IMAGE_BUILD_DTRACK="$DEST_BASE/image_builds/dtrack-agent"
DEST_IMAGE_BUILD_OPENSEARCH="$DEST_BASE/image_builds/opensearch-agent"
DEST_QUADLETS="$DEST_BASE/quadlets"
DEST_SECRETS="$DEST_BASE/secrets"
DEST_ENV_FILE_DTRACK="$DEST_SECRETS/dtrack.env"
DEST_ENV_FILE_OPENSEARCH="$DEST_SECRETS/opensearch.env"

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

TEMPLATE_ENV_DTRACK="$SCRIPT_DIR/env/dtrack.env"
TEMPLATE_ENV_OPENSEARCH="$SCRIPT_DIR/env/opensearch.env"
if [ ! -f "$TEMPLATE_ENV_DTRACK" ]; then
    log "ERROR: dtrack.env template not found."
    exit 1
fi
if [ ! -f "$TEMPLATE_ENV_OPENSEARCH" ]; then
    log "ERROR: opensearch.env template not found."
    exit 1
fi

# --- Prepare destination directories ---
log "Creating destination directories under $DEST_BASE"
mkdir -p "$DEST_IMAGE_BUILD_DTRACK" "$DEST_IMAGE_BUILD_OPENSEARCH" "$DEST_QUADLETS" "$DEST_SECRETS" "$QUADLET_SYSTEMD_DIR"

# --- Copy dtrack files ---
log "Copying dtrack-agent files"
cp "$SCRIPT_DIR/image_builds/dtrack/Containerfile" "$DEST_IMAGE_BUILD_DTRACK/Containerfile"
cp "$SCRIPT_DIR/image_builds/dtrack/agent.py" "$DEST_IMAGE_BUILD_DTRACK/agent.py"
cp "$SCRIPT_DIR/image_builds/dtrack/build-dtrack-agent.sh" "$DEST_IMAGE_BUILD_DTRACK/build-dtrack-agent.sh"

# --- Copy opensearch files ---
log "Copying opensearch-agent files"
cp "$SCRIPT_DIR/image_builds/opensearch/Containerfile" "$DEST_IMAGE_BUILD_OPENSEARCH/Containerfile"
cp "$SCRIPT_DIR/image_builds/opensearch/agent.py" "$DEST_IMAGE_BUILD_OPENSEARCH/agent.py"

# --- Copy quadlet files ---
log "Copying quadlet files"
cp "$SCRIPT_DIR/quadlets/dtrack-agent.container" "$DEST_QUADLETS/dtrack-agent.container"
cp "$SCRIPT_DIR/quadlets/opensearch-agent.container" "$DEST_QUADLETS/opensearch-agent.container"
cp "$SCRIPT_DIR/quadlets/egress.network" "$DEST_QUADLETS/egress.network"

log "Copying env templates"
cp "$TEMPLATE_ENV_DTRACK" "$DEST_ENV_FILE_DTRACK"
cp "$TEMPLATE_ENV_OPENSEARCH" "$DEST_ENV_FILE_OPENSEARCH"

# --- Default Values ---
DT_URL_DEFAULT=$(grep -E '^DT_URL=' "$DEST_ENV_FILE_DTRACK" | cut -d= -f2- || true)
DT_URL_DEFAULT=${DT_URL_DEFAULT:-"https://api.dtrack.humlab.umu.se"}

SCAN_INTERVAL_DEFAULT=$(grep -E '^SCAN_INTERVAL_SECONDS=' "$DEST_ENV_FILE_DTRACK" | cut -d= -f2- || true)
SCAN_INTERVAL_DEFAULT=${SCAN_INTERVAL_DEFAULT:-"86400"}

DT_PROJECT_VERSION_DEFAULT=$(grep -E '^DT_PROJECT_VERSION=' "$DEST_ENV_FILE_DTRACK" | cut -d= -f2- || true)
DT_PROJECT_VERSION_DEFAULT=${DT_PROJECT_VERSION_DEFAULT:-"v0.0.0"}

DT_PROJECT_NAME_DEFAULT="$(basename "$(dirname "$(pwd)")")"

if [ -r /etc/hostname ]; then
    SERVER_HOSTNAME_DEFAULT="$(tr -d '\n' < /etc/hostname)"
else
    SERVER_HOSTNAME_DEFAULT="$(hostname || echo "")"
fi

OPENSEARCH_URL_DEFAULT=$(grep -E '^OPENSEARCH_URL' "$DEST_ENV_FILE_OPENSEARCH" | cut -d= -f2- | tr -d ' "' || true)
OPENSEARCH_URL_DEFAULT=${OPENSEARCH_URL_DEFAULT:-"http://opensearch:9200"}

AGENT_MODE_DEFAULT=$(grep -E '^AGENT_MODE' "$DEST_ENV_FILE_OPENSEARCH" | cut -d= -f2- | tr -d ' "' || true)
AGENT_MODE_DEFAULT=${AGENT_MODE_DEFAULT:-"local"}

NODE_NAME_DEFAULT=$(grep -E '^NODE_NAME' "$DEST_ENV_FILE_OPENSEARCH" | cut -d= -f2- | tr -d ' "' || true)
NODE_NAME_DEFAULT=${NODE_NAME_DEFAULT:-"$SERVER_HOSTNAME_DEFAULT"}

# --- Prompts for dtrack-agent ---
echo
echo "=== dtrack-agent configuration ==="
echo

DT_URL="$(prompt_with_default "DT_URL" "$DT_URL_DEFAULT")"
DT_API_KEY="$(prompt_required_secret "DT_API_KEY")"
DT_PROJECT_NAME="$(prompt_with_default "DT_PROJECT_NAME" "$DT_PROJECT_NAME_DEFAULT")"
SCAN_INTERVAL_SECONDS="$(prompt_with_default "SCAN_INTERVAL_SECONDS" "$SCAN_INTERVAL_DEFAULT")"
SERVER_HOSTNAME="$(prompt_with_default "SERVER_HOSTNAME" "$SERVER_HOSTNAME_DEFAULT")"
DT_PROJECT_VERSION="$DT_PROJECT_VERSION_DEFAULT"

echo
echo "Writing dtrack configuration to: $DEST_ENV_FILE_DTRACK"
cat >"$DEST_ENV_FILE_DTRACK" <<EOF
DT_URL=$DT_URL
DT_API_KEY=$DT_API_KEY
DT_PROJECT_NAME=$DT_PROJECT_NAME
DT_PROJECT_VERSION=$DT_PROJECT_VERSION
SCAN_INTERVAL_SECONDS=$SCAN_INTERVAL_SECONDS
SERVER_HOSTNAME=$SERVER_HOSTNAME
EOF

chmod 600 "$DEST_ENV_FILE_DTRACK" || true

# --- Prompts for opensearch-agent ---
echo
echo "=== opensearch-agent configuration ==="
echo

OPENSEARCH_URL="$(prompt_with_default "OPENSEARCH_URL" "$OPENSEARCH_URL_DEFAULT")"
AGENT_MODE="$(prompt_with_default "AGENT_MODE (opensearch/local)" "$AGENT_MODE_DEFAULT")"
NODE_NAME="$(prompt_with_default "NODE_NAME" "$NODE_NAME_DEFAULT")"

echo
echo "Writing opensearch configuration to: $DEST_ENV_FILE_OPENSEARCH"
cat >"$DEST_ENV_FILE_OPENSEARCH" <<EOF
PODMAN_SOCKET_PATH=/run/podman/podman.sock
OPENSEARCH_URL=$OPENSEARCH_URL
OPENSEARCH_INDEX_PREFIX=podman-logs
NODE_NAME=$NODE_NAME
DISCOVERY_INTERVAL_SECONDS=3600
LOG_LEVEL=INFO
AGENT_MODE=$AGENT_MODE
EOF

chmod 600 "$DEST_ENV_FILE_OPENSEARCH" || true

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

link_quadlet "dtrack-agent.container"
link_quadlet "opensearch-agent.container"
link_quadlet "egress.network"

# --- Build the container images ---
log "Building dtrack-agent container image"
if cd "$DEST_IMAGE_BUILD_DTRACK" && bash build-dtrack-agent.sh; then
    log "dtrack-agent image built successfully"
else
    log "ERROR: Failed to build dtrack-agent image"
    exit 1
fi

log "Building opensearch-agent container image"
if cd "$DEST_IMAGE_BUILD_OPENSEARCH" && podman build --no-cache -t localhost/opensearch-agent:latest .; then
    log "opensearch-agent image built successfully"
else
    log "ERROR: Failed to build opensearch-agent image"
    exit 1
fi

# --- Enable Podman socket ---
log "Enabling Podman socket"
if systemctl --user enable --now podman.socket; then
    log "Podman socket enabled and started"
else
    log "ERROR: Failed to enable/start Podman socket"
    exit 1
fi

# --- Systemd Reload ---
echo
log "Reloading systemd user units"

if systemctl --user daemon-reload; then
    log "Starting egress-network.service"
    if systemctl --user start egress-network.service; then
        log "egress-network.service started successfully"
    else
        log "WARNING: Could not start egress-network.service"
    fi

    log "Starting dtrack-agent.service"
    if systemctl --user start --now dtrack-agent.service; then
        log "dtrack-agent.service started"
    else
        log "WARNING: Could not start dtrack-agent.service"
    fi

    log "Starting opensearch-agent.service"
    if systemctl --user start --now opensearch-agent.service; then
        log "opensearch-agent.service started"
    else
        log "WARNING: Could not start opensearch-agent.service"
    fi
else
    log "WARNING: systemctl --user daemon-reload failed"
fi

echo
echo "Installation complete."
echo "Quadlets installed in: $DEST_QUADLETS"
echo "Symlinks created in:   $QUADLET_SYSTEMD_DIR"
echo "Environment files:"
echo "  - $DEST_ENV_FILE_DTRACK"
echo "  - $DEST_ENV_FILE_OPENSEARCH"
