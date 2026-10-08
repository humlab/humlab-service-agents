#!/usr/bin/env bash
#
# Install the Humlab telemetry agents on one server. Run as root:
#
#   sudo ./install.sh             Install or update. Safe to re-run; keeps earlier answers.
#   sudo ./install.sh services    Look for services again and update the registry.
#   sudo ./install.sh status      Show what is running and recent problems.
#   sudo ./install.sh uninstall   Stop and remove the agents (keeps /etc/humlab-agents).
#
# Works the same on quadlet, podman-compose and docker-compose servers; see README.md.

set -euo pipefail

VECTOR_VERSION=0.59.0
SYFT_VERSION=1.54.1
DEFAULT_DOMAIN=blackbox.humlab.umu.se

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LIB_DIR=/usr/local/lib/humlab-agents
BIN_DIR=$LIB_DIR/bin
CONF_DIR=/etc/humlab-agents
SECRETS_DIR=$CONF_DIR/secrets
VECTOR_CONF_DIR=$CONF_DIR/vector
ENV_FILE=$CONF_DIR/agents.env
UNIT_DIR=/etc/systemd/system
DOCKER_DROPIN=$UNIT_DIR/humlab-vector.service.d/docker.conf
CLI=/usr/local/bin/humlab-agents
TIMERS=(humlab-inventory.timer humlab-sbom.timer)
ENROLLED=0
UNITS=(humlab-vector.service humlab-inventory.service humlab-inventory.timer humlab-sbom.service humlab-sbom.timer)

# Agents the previous per-user installer put in each service user's home, and a
# line that only its env file for that agent contains. Env files are deleted
# only when they match: other services use the same names (blackbox's own
# configuration/secrets/opensearch.env holds the OpenSearch admin password).
LEGACY_UNITS=(dtrack-agent opensearch-agent cadvisor-agent)
declare -A LEGACY_ENV_MARKER=(
    [dtrack-agent]='^DT_API_KEY='
    [opensearch-agent]='^AGENT_MODE'
    [cadvisor-agent]='^PODMAN_HOST=unix:///run/podman/podman.sock$'
)

# --- Helpers ---

log() { echo "[install] $*" >&2; }
warn() { echo "[install] WARNING: $*" >&2; }
fail() { echo "[install] ERROR: $*" >&2; exit 1; }
have_cmd() { command -v "$1" >/dev/null 2>&1; }

ask() {
    local prompt=$1 default=${2:-} answer
    read -r -p "$prompt${default:+ [$default]}: " answer || true
    echo "${answer:-$default}"
}

ask_yes() {
    local prompt=$1 default=$2 answer
    read -r -p "$prompt $([ "$default" = y ] && echo '[Y/n]' || echo '[y/N]'): " answer || true
    answer=${answer:-$default}
    [[ $answer =~ ^[Yy] ]]
}

# Current value of KEY in agents.env, or the default.
env_get() {
    local value=""
    [ -f "$ENV_FILE" ] && value=$(sed -n "s/^$1=//p" "$ENV_FILE" | tail -1)
    echo "${value:-$2}"
}

# --- Preflight ---

preflight() {
    [ "$(id -u)" -eq 0 ] || fail "Run as root: sudo $0 ${1:-}"
    [ -d /run/systemd/system ] || fail "systemd is not running"
    local c
    for c in curl tar sha256sum python3 getent useradd install systemctl journalctl; do
        have_cmd "$c" || fail "Missing required command: $c"
    done
    # subprocess.run(user=...) needs 3.9
    python3 -c 'import sys; assert sys.version_info >= (3, 9)' 2>/dev/null || fail "python3 >= 3.9 is required"
    # LoadCredential= needs systemd 247
    local sd_version
    sd_version=$(systemctl --version | awk 'NR==1 {print $2}')
    [ "${sd_version%%.*}" -ge 247 ] 2>/dev/null || fail "systemd >= 247 is required (found $sd_version)"
    getent group systemd-journal >/dev/null || fail "group systemd-journal does not exist"
    have_cmd podman || have_cmd docker || fail "Neither podman nor docker is installed"

    case "$(uname -m)" in
        x86_64)  VECTOR_ARCH=x86_64-unknown-linux-musl;  SYFT_ARCH=amd64 ;;
        aarch64) VECTOR_ARCH=aarch64-unknown-linux-musl; SYFT_ARCH=arm64 ;;
        *) fail "Unsupported architecture: $(uname -m)" ;;
    esac

    [ -d /var/log/journal ] || warn "The journal is not persistent (/var/log/journal is missing). Logs written while the agent is down are lost at reboot."
}

# --- Binaries ---

# download_verified <url> <checksums-url> <dir>: fetches the file and checks it
# against the release's checksum list.
download_verified() {
    local url=$1 sums_url=$2 dir=$3 file
    file=$(basename "$url")
    curl -sSfL --retry 3 -o "$dir/$file" "$url" || fail "Download failed: $url"
    curl -sSfL --retry 3 -o "$dir/SUMS" "$sums_url" || fail "Download failed: $sums_url"
    (cd "$dir" && grep -E " \*?$file\$" SUMS | sha256sum -c --quiet -) || fail "Checksum mismatch for $file"
}

install_binaries() {
    local tmp
    tmp=$(mktemp -d)
    install -d -m 755 "$BIN_DIR"

    if "$BIN_DIR/vector" --version 2>/dev/null | grep -q "^vector $VECTOR_VERSION "; then
        log "Vector $VECTOR_VERSION already installed"
    else
        log "Installing Vector $VECTOR_VERSION"
        local base=https://github.com/vectordotdev/vector/releases/download/v$VECTOR_VERSION
        download_verified "$base/vector-$VECTOR_VERSION-$VECTOR_ARCH.tar.gz" "$base/vector-$VECTOR_VERSION-SHA256SUMS" "$tmp"
        tar -xzf "$tmp/vector-$VECTOR_VERSION-$VECTOR_ARCH.tar.gz" -C "$tmp"
        install -m 755 "$tmp/vector-$VECTOR_ARCH/bin/vector" "$BIN_DIR/vector"
    fi

    if "$BIN_DIR/syft" version 2>/dev/null | grep -qE "^Version: +$SYFT_VERSION$"; then
        log "Syft $SYFT_VERSION already installed"
    else
        log "Installing Syft $SYFT_VERSION"
        local base=https://github.com/anchore/syft/releases/download/v$SYFT_VERSION
        download_verified "$base/syft_${SYFT_VERSION}_linux_$SYFT_ARCH.tar.gz" "$base/syft_${SYFT_VERSION}_checksums.txt" "$tmp"
        tar -xzf "$tmp/syft_${SYFT_VERSION}_linux_$SYFT_ARCH.tar.gz" -C "$tmp" syft
        install -m 755 "$tmp/syft" "$BIN_DIR/syft"
    fi
    rm -rf -- "$tmp"
}

create_users() {
    local u
    for u in humlab-vector humlab-sbom; do
        id -u "$u" >/dev/null 2>&1 && continue
        log "Creating system user $u"
        useradd --system --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin "$u"
    done
}

# --- Configuration ---

configure() {
    local host domain
    install -d -m 755 "$CONF_DIR" "$VECTOR_CONF_DIR"
    install -d -m 700 "$SECRETS_DIR"

    echo
    echo "=== Server and endpoints ==="
    host=$(ask "Short name of this server (its name on blackbox)" "$(env_get HOST_NAME "$(hostname -s)")")
    [[ $host =~ ^[a-z0-9][a-z0-9.-]*$ ]] || fail "Server name must be lowercase letters, digits, '.' or '-'"
    domain=$(ask "Blackbox domain" "$(env_get DOMAIN "$DEFAULT_DOMAIN")")

    enroll "$host" "$domain"

    local tmp
    tmp=$(mktemp "$ENV_FILE.XXXXXX")
    cat >"$tmp" <<EOF
# Humlab agents: settings for this server. Written by install.sh; re-run it after
# editing so the Vector config is rendered again. Secrets live in $SECRETS_DIR.
HOST_NAME=$host
DOMAIN=$domain
OPENSEARCH_URL=https://api.opensearch.$domain
OPENSEARCH_USER=ingest-$host
PROMETHEUS_URL=https://api.prometheus.$domain/api/v1/write
PROMETHEUS_USER=metrics-$host
DT_URL=https://api.dtrack.$domain

# Host (non-container) journal entries sent to logs-syslog-*: priority 4
# (warning) and worse, plus everything from these units.
HOST_LOG_MAX_PRIORITY=$(env_get HOST_LOG_MAX_PRIORITY 4)
HOST_LOG_UNITS=$(env_get HOST_LOG_UNITS "ssh.service sshd.service")

# Docker container logs when Docker does not log to journald: api or skip.
DOCKER_LOGS=$(env_get DOCKER_LOGS "")

# Paths used in the Vector config.
DATA_DIR=/var/lib/humlab-vector
CREDENTIALS_DIR=/run/credentials/humlab-vector.service
INVENTORY=/var/lib/humlab-agents/inventory.csv
EOF
    chmod 644 "$tmp"
    mv "$tmp" "$ENV_FILE"
}

# Enrolls this server with blackbox, which creates its accounts there,
# allowlists the address it calls from, and returns the credentials. Needs a
# one-time key (on blackbox: ./enroll/enroll.sh key new). Enrolling again with
# a new key replaces all three credentials.
enroll() {
    local host=$1 domain=$2 key response code have=1 f
    for f in opensearch.password prometheus.password dtrack.apikey; do
        [ -s "$SECRETS_DIR/$f" ] || have=0
    done

    echo
    echo "=== Enrollment ==="
    while :; do
        if [ $have = 1 ]; then
            read -r -s -p "Enrollment key (Enter keeps the current credentials): " key || true
        else
            read -r -s -p "Enrollment key (on blackbox: ./enroll/enroll.sh key new): " key || true
        fi
        echo >&2
        [ -n "$key" ] && break
        [ $have = 1 ] && return 0
        echo "A key is required." >&2
    done

    response=$(mktemp)
    # The key goes in as a curl config on stdin (-K -) so it never shows in ps.
    code=$(printf 'header = "Authorization: Bearer %s"\n' "$key" | curl -sS -o "$response" -w '%{http_code}' \
        --max-time 120 -K - -H 'Content-Type: application/json' --data "{\"name\": \"$host\"}" \
        "https://enroll.$domain/v1/enroll") || true
    if [ "$code" != 200 ]; then
        local error
        error=$(python3 -c 'import json, sys; print(json.load(open(sys.argv[1])).get("error", ""))' "$response" 2>/dev/null || true)
        rm -f "$response"
        case $code in
            000) fail "Could not reach https://enroll.$domain (is this server's address allowed in blackbox's humlab-enroll-allow.conf?)" ;;
            403) [ -n "$error" ] || error="this server's address may not use the enrollment service" ;;
            429) error="too many attempts, wait a minute" ;;
        esac
        fail "Enrollment failed (HTTP $code): ${error:-no details}"
    fi
    python3 - "$response" "$SECRETS_DIR" <<'PY' || { rm -f "$response"; fail "Unexpected answer from the enrollment service"; }
import json, os, sys
r = json.load(open(sys.argv[1]))
secrets = {"opensearch.password": r["opensearch"]["password"],
           "prometheus.password": r["prometheus"]["password"],
           "dtrack.apikey": r["dtrack"]["api_key"]}
os.umask(0o077)
for name, value in secrets.items():
    path = os.path.join(sys.argv[2], name)
    with open(path + ".new", "w") as f:
        f.write(value)
    os.replace(path + ".new", path)
print(f"[install] Enrolled as {r['server']} from {r['ip']}; credentials saved in {sys.argv[2]}", file=sys.stderr)
PY
    rm -f "$response"
    ENROLLED=1
}

set_env() {
    sed -i "s|^$1=.*|$1=$2|" "$ENV_FILE"
}

# Docker's default json-file driver keeps logs out of the journal. The Docker
# API can still read them, but access to the Docker socket is root-equivalent,
# so it is the admin's call.
configure_docker_logs() {
    rm -f "$VECTOR_CONF_DIR/docker-logs.yaml"
    have_cmd docker || return 0
    local driver choice
    driver=$(docker info --format '{{.LoggingDriver}}' 2>/dev/null || true)
    if [ "$driver" = journald ]; then
        log "Docker logs to journald; container logs are collected from the journal"
        set_env DOCKER_LOGS skip
    else
        choice=$(env_get DOCKER_LOGS "")
        if [ -z "$choice" ]; then
            echo
            echo "=== Docker container logs ==="
            echo "Docker logs to '${driver:-unknown}', not journald. Either:"
            echo "  api   read them through the Docker API. Adds humlab-vector to the docker group,"
            echo "        which is root-equivalent."
            echo "  skip  don't collect Docker container logs. To collect them later without extra"
            echo "        privileges, set \"log-driver\": \"journald\" in /etc/docker/daemon.json,"
            echo "        restart Docker, recreate the containers and re-run install.sh."
            choice=$(ask "api or skip" skip)
        fi
        case "$choice" in
            api)  install -m 640 -o root -g humlab-vector "$SCRIPT_DIR/vector/docker-logs.yaml" "$VECTOR_CONF_DIR/" ;;
            skip) ;;
            *) fail "Answer api or skip" ;;
        esac
        set_env DOCKER_LOGS "$choice"
    fi
    if [ "$(env_get DOCKER_LOGS skip)" = api ]; then
        install -d -m 755 "$(dirname "$DOCKER_DROPIN")"
        # Adds to the unit's SupplementaryGroups (systemd-journal).
        printf '[Service]\nSupplementaryGroups=docker\n' >"$DOCKER_DROPIN"
    else
        rm -f "$DOCKER_DROPIN"
    fi
}

install_files() {
    log "Installing agent files"
    install -d -m 755 "$LIB_DIR" /var/lib/humlab-agents
    install -m 755 "$SCRIPT_DIR/agent/humlab_agents.py" "$LIB_DIR/humlab_agents.py"
    ln -sfn "$LIB_DIR/humlab_agents.py" "$CLI"

    local rendered
    rendered=$(mktemp)
    "$CLI" render "$SCRIPT_DIR/vector/vector.yaml" "$ENV_FILE" >"$rendered" || { rm -f "$rendered"; fail "Could not render the Vector config"; }
    install -m 640 -o root -g humlab-vector "$rendered" "$VECTOR_CONF_DIR/vector.yaml"
    rm -f "$rendered"

    local u
    for u in "${UNITS[@]}"; do
        install -m 644 "$SCRIPT_DIR/systemd/$u" "$UNIT_DIR/$u"
    done
}

register_services() {
    echo
    echo "=== Services ==="
    if [ -s "$CONF_DIR/services.conf" ]; then
        "$CLI" list
        ask_yes "Look for new services?" n || return 0
    fi
    "$CLI" services
}

# The old installer ran dtrack/opensearch/cadvisor agent containers in every
# service user's account. Offer to remove them, including their copy of the
# Dependency-Track API key.
remove_legacy_agents() {
    local home user uid found=() name
    for home in /srv/*; do
        [ -d "$home/.config/containers/systemd" ] || continue
        for name in "${LEGACY_UNITS[@]}" egress; do
            if [ -e "$home/.config/containers/systemd/$name.container" ] || [ -L "$home/.config/containers/systemd/$name.container" ] \
                || [ -L "$home/.config/containers/systemd/$name.network" ]; then
                found+=("$home")
                break
            fi
        done
    done
    [ ${#found[@]} -gt 0 ] || return 0

    echo
    echo "=== Old per-user agents ==="
    echo "These service users still run the previous agent containers (dtrack-agent, opensearch-agent, cadvisor-agent):"
    printf '  %s\n' "${found[@]}"
    ask_yes "Stop and remove them, with their images and env files (including the Dependency-Track API key copy)?" y || return 0

    local env_file
    for home in "${found[@]}"; do
        user=$(stat -c %U "$home")
        uid=$(id -u "$user" 2>/dev/null) || { warn "No user owns $home, skipped"; continue; }
        log "Removing old agents for $user"
        systemctl --user -M "$user@" stop "${LEGACY_UNITS[@]/%/.service}" egress-network.service 2>/dev/null || true
        for name in "${LEGACY_UNITS[@]}"; do
            rm -f "$home/.config/containers/systemd/$name.container" "$home/configuration/quadlets/$name.container"
            rm -rf -- "${home:?}/configuration/image_builds/$name"
            env_file="$home/configuration/secrets/${name%-agent}.env"
            if [ -f "$env_file" ] && grep -qE "${LEGACY_ENV_MARKER[$name]}" "$env_file"; then
                rm -f "$env_file"
            fi
        done
        rm -f "$home/.config/containers/systemd/egress.network" "$home/configuration/quadlets/egress.network"
        systemctl --user -M "$user@" daemon-reload 2>/dev/null || true
        if [ -d "/run/user/$uid" ]; then
            runuser -u "$user" -- env XDG_RUNTIME_DIR="/run/user/$uid" HOME="$home" sh -c \
                'cd / && podman rmi -f localhost/dtrack-agent:latest localhost/opensearch-agent:latest localhost/cadvisor-agent:latest; podman network rm egress-network' \
                >/dev/null 2>&1 || true
        fi
    done
}

start_agents() {
    log "Starting agents"
    systemctl daemon-reload
    "$CLI" inventory --no-reload
    "$BIN_DIR/vector" validate --no-environment --config-dir "$VECTOR_CONF_DIR" >/dev/null \
        || { "$BIN_DIR/vector" validate --no-environment --config-dir "$VECTOR_CONF_DIR" >&2; fail "Vector config is invalid"; }
    systemctl enable --now "${TIMERS[@]}" >/dev/null
    systemctl enable humlab-vector.service >/dev/null 2>&1
    systemctl restart humlab-vector.service
    sleep 5
    systemctl is-active --quiet humlab-vector.service \
        || { journalctl -u humlab-vector.service -n 30 --no-pager >&2; fail "humlab-vector did not start"; }
}

# --- Connection checks ---

# http_code <url> <curl config>: status code of a GET. Credentials go in as a
# curl config on stdin (-K -) so they never show in ps.
http_code() {
    local url=$1 config=$2
    local code
    code=$(printf '%s\n' "$config" | curl -sS -o /dev/null -w '%{http_code}' --max-time 20 -K - "$url" 2>/dev/null) || true
    echo "${code:-000}"
}

check_connections() {
    local host os_url prom_url dt_url code ok=1
    host=$(env_get HOST_NAME "")
    os_url=$(env_get OPENSEARCH_URL "")
    prom_url=$(env_get PROMETHEUS_URL "")
    dt_url=$(env_get DT_URL "")

    echo
    echo "=== Connection checks ==="
    code=$(http_code "$os_url/" "user = \"ingest-$host:$(cat "$SECRETS_DIR/opensearch.password")\"")
    # Right after enrolling, blackbox may need a few seconds to allowlist this server.
    local tries=0
    while [ "$ENROLLED" = 1 ] && [ "$code" = 403 ] && [ $tries -lt 10 ]; do
        sleep 3
        tries=$((tries + 1))
        code=$(http_code "$os_url/" "user = \"ingest-$host:$(cat "$SECRETS_DIR/opensearch.password")\"")
    done
    case $code in
        200) echo "  OpenSearch:       OK" ;;
        401) echo "  OpenSearch:       wrong user or password (ingest-$host)"; ok=0 ;;
        403) echo "  OpenSearch:       403, this server's IP is probably not on blackbox's allowlist"; ok=0 ;;
        *)   echo "  OpenSearch:       no answer (HTTP $code) from $os_url"; ok=0 ;;
    esac

    # Prometheus only accepts POST here; 405 (or 404) means auth and allowlist passed.
    code=$(http_code "$prom_url" "user = \"metrics-$host:$(cat "$SECRETS_DIR/prometheus.password")\"")
    case $code in
        404|405) echo "  Prometheus push:  OK" ;;
        401) echo "  Prometheus push:  wrong user or password (metrics-$host)"; ok=0 ;;
        403) echo "  Prometheus push:  403, this server's IP is probably not on blackbox's allowlist"; ok=0 ;;
        *)   echo "  Prometheus push:  no answer (HTTP $code) from $prom_url"; ok=0 ;;
    esac

    # Polling an unknown upload token needs BOM_UPLOAD and returns 200. The
    # token must be a valid v4 UUID; the nil UUID gets 400.
    code=$(http_code "$dt_url/api/v1/bom/token/6f1c2d3e-4b5a-4c7d-8e9f-0a1b2c3d4e5f" \
        "header = \"X-Api-Key: $(cat "$SECRETS_DIR/dtrack.apikey")\"")
    case $code in
        200) echo "  Dependency-Track: OK" ;;
        401|403) echo "  Dependency-Track: API key rejected or missing BOM_UPLOAD permission"; ok=0 ;;
        *)   echo "  Dependency-Track: no answer (HTTP $code) from $dt_url"; ok=0 ;;
    esac

    [ $ok = 1 ] || warn "Some checks failed. The agents buffer to disk and retry, so fix the cause and they catch up."
}

# --- Commands ---

do_install() {
    preflight install
    install_binaries
    create_users
    configure
    configure_docker_logs
    install_files
    register_services
    remove_legacy_agents
    start_agents
    check_connections
    echo
    log "Done. 'sudo ./install.sh status' shows the agents; the first SBOM scan runs within a day"
    log "(start it now with: sudo systemctl start humlab-sbom.service)."
}

do_services() {
    preflight services
    [ -x "$CLI" ] || fail "Agents are not installed yet; run: sudo $0"
    # Use this checkout's discovery code, not the copy from the last install.
    install -m 755 "$SCRIPT_DIR/agent/humlab_agents.py" "$LIB_DIR/humlab_agents.py"
    "$CLI" services
    "$CLI" inventory
}

do_status() {
    preflight status
    systemctl --no-pager list-units "${UNITS[@]}" || true
    echo
    systemctl --no-pager list-timers "${TIMERS[@]}" || true
    echo
    [ -x "$CLI" ] && "$CLI" list
    echo
    echo "Warnings from the last hour:"
    journalctl --no-pager -p warning --since -1h -n 20 -u humlab-vector.service -u humlab-inventory.service -u humlab-sbom.service || true
}

do_uninstall() {
    preflight uninstall
    ask_yes "Stop and remove the Humlab agents?" n || exit 0
    systemctl disable --now "${UNITS[@]}" 2>/dev/null || true
    local u
    for u in "${UNITS[@]}"; do rm -f "$UNIT_DIR/$u"; done
    rm -f "$DOCKER_DROPIN"
    rmdir "$(dirname "$DOCKER_DROPIN")" 2>/dev/null || true
    systemctl daemon-reload
    rm -f "$CLI"
    rm -rf -- "$LIB_DIR"
    log "Removed. Kept $CONF_DIR (settings, secrets, service registry) and /var/lib/humlab-vector (buffers)."
    log "Delete those and the users humlab-vector and humlab-sbom by hand if you don't need them."
}

case "${1:-install}" in
    install)   do_install ;;
    services)  do_services ;;
    status)    do_status ;;
    uninstall) do_uninstall ;;
    *) sed -n '3,9p' "$0" | sed 's/^# \{0,1\}//'; exit 1 ;;
esac
