# Humlab Service Agents

Lightweight satellite agents for automated security scanning and log collection in Podman environments.

## Agents

### Dependency-Track Agent
Automatically scans container images with Syft and uploads SBOMs to Dependency-Track for vulnerability tracking.

### OpenSearch Agent
Streams container logs to OpenSearch (or stdout in local mode) for centralized log management.

## Installation

```bash
./install.sh
```

The installer will:
- Prompt for configuration (API keys, URLs, etc.)
- Build agent containers
- Set up systemd services
- Start the agents

Configuration is stored in `~/configuration/secrets/`:
- `dtrack.env` - Dependency-Track settings
- `opensearch.env` - OpenSearch settings

## Management

```bash
# View status
systemctl --user status dtrack-agent.service
systemctl --user status opensearch-agent.service

# View logs
journalctl --user -u dtrack-agent.service -f
journalctl --user -u opensearch-agent.service -f

# Restart after config changes
systemctl --user restart dtrack-agent.service
```

## How It Works

Both agents:
- Discover running containers via Podman socket
- Run as unprivileged user containers
- Operate on isolated egress network
- Require no manual intervention after setup
