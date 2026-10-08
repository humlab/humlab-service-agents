# Humlab Service Agents

Client side of the blackbox monitoring stack. One install per server sends:

| What | Where | How |
|---|---|---|
| Container logs (stdout/stderr) | OpenSearch, `logs-container-YYYY.MM` | Vector reads the journal |
| Host logs (warnings and worse, plus sshd) | OpenSearch, `logs-syslog-YYYY.MM` | Vector reads the journal |
| Host metrics and per-container CPU/memory | Prometheus remote write | Vector `host_metrics` |
| SBOM per container image, daily | Dependency-Track | Syft |

It works the same on servers that run services as rootless quadlets (one user
per service under `/srv/<service>`), with podman-compose, or with docker-compose.

## How it runs

Everything runs on the host, once per server. Nothing is added to the service
users' accounts.

| Unit | Runs as | Can do |
|---|---|---|
| `humlab-vector.service` | `humlab-vector`, in group `systemd-journal` | Read the journal, `/proc` and cgroups. No container runtime access. |
| `humlab-inventory.timer` (every 2 min) | root | List running containers, to map them to services. Switches to the owning user for rootless Podman. |
| `humlab-sbom.timer` (daily) | root, dropping privileges | Saves each image as its owner (rootless Podman) or as root (Docker, rootful Podman), and runs Syft as the owner or as `humlab-sbom`. |

Passwords and the API key are root-only files in `/etc/humlab-agents/secrets/`.
Vector gets its two passwords through systemd credentials; the Dependency-Track
key never leaves root.

**Docker hosts.** Docker's default `json-file` log driver keeps container logs
out of the journal. The installer then asks whether to read them through the
Docker API, which adds `humlab-vector` to the `docker` group and makes it
root-equivalent. The alternative is to switch Docker to journald
(`"log-driver": "journald"` in `/etc/docker/daemon.json`, restart Docker,
recreate the containers) and re-run the installer.

**Podman** logs to journald by default. A container started with
`--log-driver k8s-file` (or `LogDriver=k8s-file` in a quadlet) is not collected.

## Before installing: an enrollment key

Get a one-time enrollment key from blackbox's service user:

```bash
./enroll/enroll.sh key new      # in the humlab-service-agent-servers repo
```

The installer uses it to enroll the server. Blackbox then creates the server's
accounts (OpenSearch, Prometheus push and a Dependency-Track API key) and
allowlists the address the server calls from. Nothing else needs to be set up
by hand. A key works once and expires after 7 days. See
`nginx/README.md` in the servers repo.

## Install

```bash
git clone https://github.com/humlab/humlab-service-agents
cd humlab-service-agents
sudo ./install.sh
```

The installer:

1. Downloads Vector and Syft (pinned versions, checksums verified) to
   `/usr/local/lib/humlab-agents/bin/`.
2. Asks for the server name, the blackbox domain and the enrollment key, and
   enrolls the server. Enter keeps the earlier answers, and the current
   credentials, when you re-run it.
3. Finds services and asks which to monitor (next section).
4. Offers to remove the old per-user agent containers, if a service user still
   has them.
5. Starts the agents and checks that OpenSearch, Prometheus and
   Dependency-Track accept the credentials from this server.

Re-run `sudo ./install.sh` to update. To get new credentials, re-run it with a new
key; this works from the address the server enrolled from. A server that has
moved to a new address needs a key made with `key new --server <name>`. It needs a systemd of version 247 or later,
Python 3.9 or later, and Podman or Docker.

## Services

A service is the name used for `service.name` in OpenSearch, the `service`
label in Prometheus, and the project in Dependency-Track. The registry is
`/etc/humlab-agents/services.conf`:

```ini
[visp]
deployment = quadlet
runtime = podman
owner = visp
path = /srv/visp

[sead-query-api]
deployment = compose
runtime = docker
owner = root
path = /data/sead_query_api
```

- **Quadlet**: every user whose home is `/srv/<name>` and who has
  `~/.config/containers/systemd/`. All containers in that user's Podman belong
  to the service.
- **Compose**: a directory with a compose file. The installer searches `/srv`,
  `/home`, `/data`, `/data-spinn` and `/opt` (four levels deep, and you can
  change the list), and you can add other directories by hand. Containers belong
  to the project when their `com.docker.compose.project.working_dir` label is
  that directory. Docker Compose and podman-compose both set it. A `project =`
  line matches on the project name instead.
- **Owner**: the user whose Podman runs the containers, or `root` for Docker and
  rootful Podman. A rootless owner needs lingering (`loginctl enable-linger
  <user>`) so its containers and runtime directory exist without a login.

Run `sudo ./install.sh services` to look again after deploying something new.
Containers that belong to no registered service are still logged and measured,
under their container name (logs) or `service="unregistered"` (metrics), and get
no SBOM.

## What the data looks like

Log documents follow the blackbox client guide: `@timestamp`, `host.name`,
`service.name`, `message`, plus `container.name`, `container.id`,
`container.image.name` and `stream` for container lines, and `log.level`,
`process.*` and `systemd.unit` for host lines.

Metrics carry `host` (required by the push-health alert in Grafana).
Per-container series are `host_cgroup_cpu_usage_seconds_total`,
`host_cgroup_memory_current_bytes` and similar, with `service` and `container`
labels. Host series are `host_cpu_seconds_total`, `host_memory_*`,
`host_filesystem_*`, `host_network_*` and so on. These are Vector's names, not
node_exporter's, so stock node_exporter dashboards need their queries adapted.

In Dependency-Track, each service is a project `<service>` with version
`<host>`, and each container a child project `<service>/<container>` with the
same version.

## Operating it

```bash
sudo ./install.sh status                    # units, timers, services, recent warnings
sudo humlab-agents list                     # services and their containers
sudo systemctl start humlab-sbom.service    # scan now
journalctl -u humlab-vector -f              # agent log
```

| File | Contents |
|---|---|
| `/etc/humlab-agents/agents.env` | Server name, endpoints, host-log filter. Re-run the installer after editing. |
| `/etc/humlab-agents/services.conf` | Service registry |
| `/etc/humlab-agents/secrets/` | Passwords and API key from enrollment (root only) |
| `/etc/humlab-agents/vector/` | Rendered Vector config |
| `/var/lib/humlab-agents/inventory.csv` | Container to service map |
| `/var/lib/humlab-vector/` | Journal position and disk buffers (up to about 1.3 GB) |

When blackbox is unreachable, Vector buffers to disk and catches up afterwards.
The journal position is saved, so a restart of the agent loses nothing either.

## Repository layout

```
install.sh              installer (install, services, status, uninstall)
agent/humlab_agents.py  service registry, inventory, SBOM scans
vector/vector.yaml      Vector config template (@...@ filled in by install.sh)
vector/docker-logs.yaml Docker API log source, only when chosen
systemd/                units and timers
```
