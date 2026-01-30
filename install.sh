#!/usr/bin/env bash
set -euo pipefail

# --- Configurable destinations (under ~) ---
DEST_BASE="$HOME/configuration"
DEST_IMAGE_BUILD_DTRACK="$DEST_BASE/image_builds/dtrack-agent"
DEST_IMAGE_BUILD_OPENSEARCH="$DEST_BASE/image_builds/opensearch-agent"
DEST_IMAGE_BUILD_CADVISOR="$DEST_BASE/image_builds/cadvisor-agent"
DEST_QUADLETS="$DEST_BASE/quadlets"
DEST_SECRETS="$DEST_BASE/secrets"
DEST_ENV_FILE_DTRACK="$DEST_SECRETS/dtrack.env"
DEST_ENV_FILE_OPENSEARCH="$DEST_SECRETS/opensearch.env"
DEST_ENV_FILE_CADVISOR="$DEST_SECRETS/cadvisor.env"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Quadlet systemd directory
QUADLET_SYSTEMD_DIR="$HOME/.config/containers/systemd"

# --- Helpers ---
log() {
    echo "[install] $*" >&2
}

fail() { log "ERROR: $*"; exit 1; }

have_cmd() { command -v "$1" >/dev/null 2>&1; }

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

detect_podman_sock() {
  local candidates=(
    "${XDG_RUNTIME_DIR:-/run/user/$UID}/podman/podman.sock"
    "/run/user/$UID/podman/podman.sock"
    "/run/podman/podman.sock"
  )
  local s
  for s in "${candidates[@]}"; do
    [ -S "$s" ] && echo "$s" && return 0
  done
  return 1
}

check_readable_file() {
  local f="$1"
  [ -f "$f" ] || fail "Required file not found: $f"
  [ -r "$f" ] || fail "Required file not readable: $f"
}

check_writable_dir() {
  local d="$1"
  mkdir -p "$d" 2>/dev/null || fail "Cannot create directory: $d"
  [ -w "$d" ] || fail "Directory not writable: $d"
}

# --- Preflight checks ---
log "Running preflight checks"

# Basic environment
[ -n "${HOME:-}" ] || fail "\$HOME is not set"
check_writable_dir "$HOME"

# Required commands
for c in bash cp ln rm mkdir grep cut tr basename dirname sed hostname; do
  have_cmd "$c" || fail "Missing required command: $c"
done

have_cmd podman    || fail "podman is not installed or not in PATH"
have_cmd systemctl || fail "systemctl is not installed or not in PATH"

# Python requirement (host)
have_cmd python3 || fail "python3 is required but not installed"
python3 -c 'import sys; assert sys.version_info >= (3,8), sys.version' \
  || fail "python3 >= 3.8 is required"

# Podman usability (rootless)
podman info >/dev/null 2>&1 || fail "podman is installed but not usable for this user (podman info failed)"

# systemd user session availability
if ! systemctl --user status >/dev/null 2>&1; then
  fail "systemd user instance not available (systemctl --user failed).
You may need an active user session or to enable lingering: sudo loginctl enable-linger $USER"
fi

# Quadlet directory expectation (rootless quadlets)
check_writable_dir "$QUADLET_SYSTEMD_DIR"

# Locate source tree (requires SCRIPT_DIR already set)
check_readable_file "$SCRIPT_DIR/env/dtrack.env"
check_readable_file "$SCRIPT_DIR/env/opensearch.env"
check_readable_file "$SCRIPT_DIR/env/cadvisor.env"

check_readable_file "$SCRIPT_DIR/image_builds/dtrack/Containerfile"
check_readable_file "$SCRIPT_DIR/image_builds/dtrack/agent.py"
check_readable_file "$SCRIPT_DIR/image_builds/dtrack/build-dtrack-agent.sh"

check_readable_file "$SCRIPT_DIR/image_builds/opensearch/Containerfile"
check_readable_file "$SCRIPT_DIR/image_builds/opensearch/agent.py"

check_readable_file "$SCRIPT_DIR/image_builds/cadvisor/Containerfile"

check_readable_file "$SCRIPT_DIR/quadlets/dtrack-agent.container"
check_readable_file "$SCRIPT_DIR/quadlets/opensearch-agent.container"
check_readable_file "$SCRIPT_DIR/quadlets/cadvisor-agent.container"
check_readable_file "$SCRIPT_DIR/quadlets/egress.network"

log "Preflight checks passed"

# --- Source templates ---
TEMPLATE_ENV_DTRACK="$SCRIPT_DIR/env/dtrack.env"
TEMPLATE_ENV_OPENSEARCH="$SCRIPT_DIR/env/opensearch.env"
TEMPLATE_ENV_CADVISOR="$SCRIPT_DIR/env/cadvisor.env"

# --- Prepare destination directories ---
log "Creating destination directories under $DEST_BASE"
mkdir -p \
  "$DEST_IMAGE_BUILD_DTRACK" \
  "$DEST_IMAGE_BUILD_OPENSEARCH" \
  "$DEST_IMAGE_BUILD_CADVISOR" \
  "$DEST_QUADLETS" \
  "$DEST_SECRETS" \
  "$QUADLET_SYSTEMD_DIR"

# --- Copy dtrack files ---
log "Copying dtrack-agent files"
cp "$SCRIPT_DIR/image_builds/dtrack/Containerfile" "$DEST_IMAGE_BUILD_DTRACK/Containerfile"
cp "$SCRIPT_DIR/image_builds/dtrack/agent.py" "$DEST_IMAGE_BUILD_DTRACK/agent.py"
cp "$SCRIPT_DIR/image_builds/dtrack/build-dtrack-agent.sh" "$DEST_IMAGE_BUILD_DTRACK/build-dtrack-agent.sh"

# --- Copy opensearch files ---
log "Copying opensearch-agent files"
cp "$SCRIPT_DIR/image_builds/opensearch/Containerfile" "$DEST_IMAGE_BUILD_OPENSEARCH/Containerfile"
cp "$SCRIPT_DIR/image_builds/opensearch/agent.py" "$DEST_IMAGE_BUILD_OPENSEARCH/agent.py"

# --- Copy cadvisor files ---
log "Copying cadvisor-agent files"
cp "$SCRIPT_DIR/image_builds/cadvisor/Containerfile" "$DEST_IMAGE_BUILD_CADVISOR/Containerfile"

# --- Copy quadlet files ---
log "Copying quadlet files"
cp "$SCRIPT_DIR/quadlets/dtrack-agent.container" "$DEST_QUADLETS/dtrack-agent.container"
cp "$SCRIPT_DIR/quadlets/opensearch-agent.container" "$DEST_QUADLETS/opensearch-agent.container"
cp "$SCRIPT_DIR/quadlets/cadvisor-agent.container" "$DEST_QUADLETS/cadvisor-agent.container"
cp "$SCRIPT_DIR/quadlets/egress.network" "$DEST_QUADLETS/egress.network"

log "Copying env templates"
cp "$TEMPLATE_ENV_DTRACK" "$DEST_ENV_FILE_DTRACK"
cp "$TEMPLATE_ENV_OPENSEARCH" "$DEST_ENV_FILE_OPENSEARCH"
cp "$TEMPLATE_ENV_CADVISOR" "$DEST_ENV_FILE_CADVISOR"

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

case "$AGENT_MODE" in
  local|opensearch) ;;
  *) fail "AGENT_MODE must be 'local' or 'opensearch' (got: $AGENT_MODE)" ;;
esac

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
link_quadlet "cadvisor-agent.container"
link_quadlet "egress.network"

# --- Build the container images ---
log "Building dtrack-agent container image"
if cd "$DEST_IMAGE_BUILD_DTRACK" && bash build-dtrack-agent.sh; then
    log "dtrack-agent image built successfully"
else
    fail "Failed to build dtrack-agent image"
fi

log "Building opensearch-agent container image"
if cd "$DEST_IMAGE_BUILD_OPENSEARCH" && podman build --no-cache -t localhost/opensearch-agent:latest .; then
    log "opensearch-agent image built successfully"
else
    fail "Failed to build opensearch-agent image"
fi

log "Building cadvisor-agent container image"
if cd "$DEST_IMAGE_BUILD_CADVISOR" && podman build --no-cache -t localhost/cadvisor-agent:latest .; then
    log "cadvisor-agent image built successfully"
else
    fail "Failed to build cadvisor-agent image"
fi

# --- Enable Podman socket ---
log "Enabling Podman socket"
systemctl --user enable --now podman.socket || fail "Failed to enable/start podman.socket"
systemctl --user is-active --quiet podman.socket || fail "podman.socket is not active after enabling"

PODMAN_SOCK="$(detect_podman_sock)" || fail "Could not find Podman socket after enabling podman.socket"

# Update opensearch env file safely
sed -i "s|^PODMAN_SOCKET_PATH=.*$|PODMAN_SOCKET_PATH=$PODMAN_SOCK|" "$DEST_ENV_FILE_OPENSEARCH"

# --- Systemd Reload ---
echo
log "Reloading systemd user units"

if systemctl --user daemon-reload; then
    log "Validating quadlet unit generation"
    for unit in egress-network.service dtrack-agent.service opensearch-agent.service cadvisor-agent.service; do
        # list-unit-files is less sensitive to inactive/failed units than status
        systemctl --user list-unit-files "$unit" >/dev/null 2>&1 \
            || fail "Quadlet did not generate expected unit: $unit"
    done

    log "Starting egress-network.service"
    systemctl --user start egress-network.service || log "WARNING: Could not start egress-network.service"

    log "Starting dtrack-agent.service"
    systemctl --user start --now dtrack-agent.service || log "WARNING: Could not start dtrack-agent.service"

    log "Starting opensearch-agent.service"
    systemctl --user start --now opensearch-agent.service || log "WARNING: Could not start opensearch-agent.service"

    log "Starting cadvisor-agent.service"
    systemctl --user start --now cadvisor-agent.service || log "WARNING: Could not start cadvisor-agent.service"
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
echo "  - $DEST_ENV_FILE_CADVISOR"
