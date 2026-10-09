# Humlab Service Agents

Client side of the blackbox monitoring stack. One install per server sends:

| What | Where | How |
|---|---|---|
| Container logs (stdout/stderr) | OpenSearch, `logs-container-<server>_YYYY.MM` | Vector reads the journal |
| Host logs (warnings and worse, plus sshd and authentication events) | OpenSearch, `logs-syslog-<server>_YYYY.MM` | Vector reads the journal |
| Host metrics and per-container CPU/memory | Prometheus remote write | Vector `host_metrics` |
| SBOM per container image, daily | Dependency-Track | Syft |

Some log lines are never sent: kernel firewall drops (`[UFW BLOCK]`), container
healthcheck requests (`GET /health`, `/healthz`, `/is_alive`, `/ping`, curl
requests for `/`), the MongoDB connection and authentication lines each probe
causes, MongoDB checkpoint notices, and nginx's error line for each 404 (the
access log already has the request). Each rule applies only to the source that
writes such lines (kernel, or container) and only to the start of the line, so
text inside a user name or User-Agent cannot make a line disappear. Host logs
are also rate-limited: at most 10 lines of the same kind (same sender, same
text apart from numbers and ids) per 10 minutes; logins and privilege changes
are never thinned out.

Host logs are warnings and worse, everything from `HOST_LOG_UNITS`, and
authentication events: sudo, su, login, pkexec and the account tools (useradd,
usermod, passwd, ...), whatever their priority. Journal fields that do not start
with `_` (`CONTAINER_*`, `SYSLOG_*`, `PRIORITY`) can be set by any local user, so
trust rests on the `_` fields journald adds: a line counts as a container line
only when it comes from the container runtime (conmon or dockerd, by `_EXE`),
the throttle key is built from the sender, and `process.executable` and
`user.id` are stored with every host line. The rules are in `logs_shape` and
`logs_repeats` in `vector/vector.yaml`; `vector/tests/run.sh` tests them.

It works the same on servers that run services as rootless quadlets (one user
per service under `/srv/<service>`), with podman-compose, or with docker-compose.

## How it runs

Everything runs on the host, once per server. Nothing is added to the service
users' accounts.

| Unit | Runs as | Can do |
|---|---|---|
| `humlab-vector.service` | `humlab-vector`, in group `systemd-journal` | Read the journal, `/proc` and cgroups. No container runtime access. |
| `humlab-inventory.timer` (every 2 min) | root | List running containers, to map them to services. Switches to the owning user for rootless Podman. |
| `humlab-discover.timer` (nightly, 23:30) | root | Register new services and unregister long-gone ones (next section). |
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

1. Downloads Vector and Syft (pinned versions and SHA-256 checksums) to
   `/usr/local/lib/humlab-agents/bin/`.
2. Asks for the server name, the blackbox domain and the enrollment key, and
   enrolls the server. Enter keeps the earlier answers, and the current
   credentials, when you re-run it.
3. Finds services and asks which to monitor (next section).
4. Offers to remove the old per-user agent containers, if a service user still
   has them.
5. Starts the agents and checks that OpenSearch, Prometheus and
   Dependency-Track accept the credentials from this server.

It needs a systemd of version 247 or later, Python 3.9 or later, and Podman or
Docker.

## Later changes: the menu

Once the agents are installed, `sudo ./install.sh` opens a menu instead of the
wizard:

```
  [A] Agent status and recent warnings
  [L] List and change services (rename, unregister)
  [F] Find new services
  [E] Enroll with a new key
  [C] Check the connections to blackbox
  [S] Scan images and upload SBOMs now
  [U] Update the agents from this checkout (after git pull)
  [W] Run the whole setup wizard again
  [X] Uninstall
  [Q] Quit
```

The menu says when the checkout differs from what is installed. To update:
`git pull`, then `sudo ./install.sh` and **U**, or `sudo ./install.sh update`
without the menu. Update asks no questions; it keeps the settings, credentials
and services.

New credentials (**E**) need a new key and work from the address the server
enrolled from. A server that has moved to a new address needs a key made with
`key new --server <name>`.

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
- **Systemd-started Podman projects** in any other account, for example a
  deployment that installs its quadlets into `~/.config/containers/systemd/`
  of a personal user. These are found through the running containers: quadlet
  labels each one with its systemd unit (`PODMAN_SYSTEMD_UNIT`). The unit's
  quadlet file leads to the project directory:
  - A symlinked quadlet belongs to the project the link points into.
  - A copied or generated quadlet belongs to the project its `EnvironmentFile=`
    and `Volume=` paths point into.

  The project directory is the nearest directory with `.git`, `.env` or a
  compose file. Repositories checked out inside it count as part of it. The
  service is registered with `deployment = quadlet` and that directory as
  `path`, and is named after the directory by default. Containers that no
  unit started, such as ones a service creates through the Podman API, belong
  to the user's service if the user has only one.
- **Compose**: a directory with a compose file. The installer searches `/srv`,
  `/home`, `/data`, `/data-spinn` and `/opt` (four levels deep, and you can
  change the list), and you can add other directories by hand. Containers belong
  to the project when their `com.docker.compose.project.working_dir` label is
  that directory. Docker Compose and podman-compose both set it. A `project =`
  line matches on the project name instead. The installer writes that line
  when the label doesn't lead to a directory but the project name does: the
  directory's name, `name:` in the compose file, or `COMPOSE_PROJECT_NAME`
  in `.env`. Running compose projects outside the search directories are found
  through that label too.
- **Container**: a container nothing else covers, started by hand (`podman
  run`, `docker run`) or from a compose directory that no longer exists. One
  service per container, matched by its name (`container =`). A name the
  runtime made up (`heuristic_blackburn`) changes when the container is
  recreated, so such containers are only offered, never registered
  automatically.
- **Owner**: the user whose Podman runs the containers, or `root` for Docker and
  rootful Podman. A rootless owner needs lingering (`loginctl enable-linger
  <user>`) so its containers and runtime directory exist without a login.

The installer looks for containers in Docker, rootful Podman, and the Podman of
every user who has running containers (found by their `conmon` processes) or a
runtime directory. It warns about a user whose running containers it cannot
list, usually because lingering is off. Then it lists the running containers
that no registered service covers, so you can add their directories by hand.

The suggested service name skips directories named after the deployment: a
project in `swedeb-api/docker` is offered as `swedeb-api`, one in
`swedeb-api/docker/compose/production` as `swedeb-api-production`. A project
name set in the compose file (`name:`) is offered as is. Systemd-started
containers without a project directory (a quadlet in `/etc/containers/systemd`)
are named after their unit, a standalone container after itself. Rename a
service later with **L** in the menu.

### Automatic discovery

Every night `humlab-discover.timer` does what **F** does, without asking:

- It registers new services under their suggested names, except what was
  declined in **F** or unregistered with **L**. Those are listed in
  `/etc/humlab-agents/ignored.conf`; delete a line, or say yes in **F**, to
  have one registered again.
- It unregisters services that have had no running containers for
  `SERVICE_EXPIRE_DAYS` days (60 by default). A service whose runtime cannot be
  listed that night is kept. Its Dependency-Track projects are kept.

What it changed is logged to the journal of `humlab-discover.service` and sent
to blackbox (`systemd.unit: humlab-discover.service` in Discover). Set
`SERVICE_DISCOVERY=manual` in `agents.env` (then **U**) to register services
only through the menu.

**F** in the menu offers only compose projects with running containers; the
others are counted and can be listed, or added by path.
Containers that belong to no registered service are still logged and measured,
under their container name (logs) or `service="unregistered"` (metrics), and get
no SBOM.

## What the data looks like

Log documents follow the blackbox client guide: `@timestamp`, `host.name`,
`service.name`, `message`, plus `container.name`, `container.id`,
`container.image.name` and `stream` for container lines, and `log.level`,
`process.*` and `systemd.unit` for host lines.

`service.name` of a host line is the name it logs under (`SYSLOG_IDENTIFIER`)
only when that comes from the kernel, a system account (uid below 1000) or the
program that sent it; otherwise it is the program's own name, and the claimed
name is in `log.syslog.appname`. `user.id` is the uid that sent the line, for
host and container lines alike.

Every 5 minutes the agent also sends a heartbeat line (`service.name:
humlab-vector`, `event.dataset: humlab.heartbeat`), so blackbox can tell a quiet
server from one whose logs stopped.

Metrics carry `host` (required by the push-health alert in Grafana).
Per-container series are `host_cgroup_cpu_usage_seconds_total`,
`host_cgroup_memory_current_bytes` and similar, with `service` and `container`
labels. Host series are `host_cpu_seconds_total`, `host_memory_*`,
`host_filesystem_*`, `host_network_*` and so on. These are Vector's names, not
node_exporter's, so stock node_exporter dashboards need their queries adapted.

In Dependency-Track, each service is a project `<service>` with version
`<host>`, and each container a child project `<service>/<container>` with the
same version. Containers that no systemd unit or compose file started (their
names change, e.g. one per user session) are grouped by image instead:
`<service>/image-<image name>`. Service projects carry the tag `service`;
blackbox turns them into collection projects within 10 minutes, so their
vulnerability and component counts are the totals of their containers.

## Operating it

```bash
sudo ./install.sh                           # the menu
sudo ./install.sh status                    # units, timers, services, recent warnings
sudo humlab-agents list                     # services and their containers
sudo humlab-agents edit                     # rename or unregister services by number
sudo systemctl start humlab-sbom.service    # scan now
journalctl -u humlab-vector -f              # agent log
```

| File | Contents |
|---|---|
| `/etc/humlab-agents/agents.env` | Server name, endpoints, host-log filter, service discovery. Run `sudo ./install.sh update` after editing. |
| `/etc/humlab-agents/services.conf` | Service registry |
| `/etc/humlab-agents/ignored.conf` | Services automatic discovery leaves alone |
| `/etc/humlab-agents/secrets/` | Passwords and API key from enrollment (root only) |
| `/etc/humlab-agents/vector/` | Rendered Vector config |
| `/var/lib/humlab-agents/inventory.csv` | Container to service map, with the uid whose runtime runs each container |
| `/var/lib/humlab-vector/` | Journal position and disk buffers (up to about 1.3 GB); private to `humlab-vector` (mode 0700) |

When blackbox is unreachable, Vector buffers to disk and catches up afterwards.
The journal position is saved, so a restart of the agent loses nothing either.

## Trusting the checkout

`install.sh`, the agent and the systemd units are installed as root from this
checkout, and again at every update. Whoever can push to the repository, or write
to the checkout on a server, therefore gets root on every server that updates
from it. Keep that narrow:

- Clone it as root into `/opt` (not a home directory), so that it is owned by
  root. `install.sh` warns when it is not.
- Install from a signed tag, not a branch: `git fetch --tags && git verify-tag
  <tag> && git checkout <tag>`.
- On GitHub, protect the main branch (required review, no force pushes) and
  require signed commits or tags for releases.

## Repository layout

```
install.sh              installer: setup wizard, then a menu (also install, update, services, enroll, status, uninstall)
agent/humlab_agents.py  service registry, inventory, SBOM scans
vector/vector.yaml      Vector config template (@...@ filled in by install.sh)
vector/docker-logs.yaml Docker API log source, only when chosen
vector/tests/           unit tests for the log transforms: vector/tests/run.sh [path/to/vector]
tests/                  tests for the agent: python3 -m unittest discover -s tests
systemd/                units and timers
```
