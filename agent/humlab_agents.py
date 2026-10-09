#!/usr/bin/env python3
"""Service registry, container inventory and SBOM scanning for one server.

  humlab-agents services [--yes]   Find services and register them (interactive)
  humlab-agents list               Show registered services and their containers
  humlab-agents inventory          Map running containers to services for Vector
  humlab-agents sbom [SERVICE...]  Scan images with syft, upload to Dependency-Track
  humlab-agents render TPL ENV     Fill @NAME@ placeholders in TPL from ENV

Runs as root (from install.sh or systemd). Talks to a rootless Podman only as
the user who owns it, and runs syft unprivileged. Standard library only.
"""

import argparse
import base64
import configparser
import glob
import json
import os
import pwd
import re
import shutil
import subprocess
import sys
import tempfile
import urllib.error
import urllib.request
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path

CONF_DIR = Path(os.environ.get("HUMLAB_AGENTS_CONF", "/etc/humlab-agents"))
REGISTRY = CONF_DIR / "services.conf"
INVENTORY = Path(os.environ.get("HUMLAB_INVENTORY", "/var/lib/humlab-agents/inventory.csv"))
BIN_DIR = Path(os.environ.get("HUMLAB_AGENTS_BIN", "/usr/local/lib/humlab-agents/bin"))
SCAN_USER = "humlab-sbom"
VECTOR_UNIT = "humlab-vector.service"

COMPOSE_FILES = ("compose.yaml", "compose.yml", "docker-compose.yaml", "docker-compose.yml")
DEFAULT_ROOTS = ("/srv", "/home", "/data", "/data-spinn", "/opt")
SKIP_DIRS = {".git", ".cache", ".local", ".config", "node_modules", "venv", ".venv",
             "__pycache__", "site-packages", "overlay", "overlay-containers", "volumes"}
SEARCH_DEPTH = 4

# Containers started by a systemd unit (quadlet, or podman generate systemd)
# carry this label. The unit's source file leads to the project directory.
SYSTEMD_UNIT_LABEL = "PODMAN_SYSTEMD_UNIT"
WORKING_DIR_LABEL = "com.docker.compose.project.working_dir"
PROJECT_MARKERS = (".git", ".env") + COMPOSE_FILES
SYSTEM_PATHS = ("/etc/", "/run/", "/var/run/", "/proc/", "/sys/", "/dev/", "/tmp/", "/usr/")

NAME_RE = re.compile(r"^[a-z0-9][a-z0-9._-]*$")
SAFE_PATH = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"


def log(msg: str) -> None:
    print(msg, file=sys.stderr, flush=True)


# ---------------------------------------------------------------- registry

@dataclass
class Service:
    name: str
    deployment: str            # quadlet | compose
    runtime: str               # podman | docker
    owner: str                 # user whose runtime holds the containers (root for docker)
    path: str                  # quadlet: the user's home, or the project directory its
                               # units come from; compose: the project directory
    project: str = ""          # compose project name, when it differs from the directory name
    containers: list = field(default_factory=list)

    @property
    def compose_project(self) -> str:
        return self.project or compose_project_name(self.path)

    def matches(self, labels: dict, name_fallback: bool = True) -> bool:
        """True if a compose container (by its labels) belongs to this service:
        by its working directory, or (if name_fallback) by compose project name
        when it has none (older podman-compose). A working directory that no
        longer exists matches nothing: many projects share a name like "docker"."""
        wd = labels.get(WORKING_DIR_LABEL)
        if wd:
            return same_path(wd, self.path)
        return name_fallback and labels.get("com.docker.compose.project") == self.compose_project


def compose_project_name(path: str) -> str:
    # Docker Compose's default: the directory name, lowercased, [a-z0-9_-] only.
    return re.sub(r"[^a-z0-9_-]", "", os.path.basename(os.path.normpath(path)).lower())


def same_path(a: str, b: str) -> bool:
    return os.path.realpath(a) == os.path.realpath(b)


def is_under(path: str, parent: str) -> bool:
    path, parent = os.path.realpath(path), os.path.realpath(parent)
    return path == parent or path.startswith(parent.rstrip("/") + "/")


def load_registry() -> list:
    cp = configparser.ConfigParser(interpolation=None)
    cp.read(REGISTRY)
    services = []
    for name in cp.sections():
        s = cp[name]
        services.append(Service(name=name, deployment=s.get("deployment", "compose"),
                                runtime=s.get("runtime", "podman"), owner=s.get("owner", "root"),
                                path=s.get("path", ""), project=s.get("project", "")))
    return services


def save_registry(services: list) -> None:
    cp = configparser.ConfigParser(interpolation=None)
    for s in sorted(services, key=lambda s: s.name):
        cp[s.name] = {"deployment": s.deployment, "runtime": s.runtime, "owner": s.owner, "path": s.path}
        if s.project and s.project != compose_project_name(s.path):
            cp[s.name]["project"] = s.project
    REGISTRY.parent.mkdir(parents=True, exist_ok=True)
    tmp = REGISTRY.with_suffix(".tmp")
    with open(tmp, "w") as f:
        f.write("# Services monitored on this server. Written by 'humlab-agents services';\n"
                "# safe to edit by hand. The section name is the service name used in\n"
                "# OpenSearch (service.name), Prometheus (service) and Dependency-Track.\n\n")
        cp.write(f)
    os.chmod(tmp, 0o644)
    os.replace(tmp, REGISTRY)


# ---------------------------------------------------------------- runtimes

def run_as(owner: str, argv: list, env: dict = None, timeout: int = 120,
           user_session: bool = True) -> subprocess.CompletedProcess:
    """Run argv as owner, with the environment a rootless Podman expects.

    user_session=False is for commands that need no runtime directory
    (/run/user/<uid>), such as syft as SCAN_USER, a system user without lingering.

    Uses setuid/setgid directly rather than runuser, so frequent calls don't
    open a PAM session (and an auth.log line) each time.
    """
    pw = pwd.getpwnam(owner)
    full_env = {"PATH": SAFE_PATH, "LANG": "C.UTF-8", "HOME": pw.pw_dir,
                "USER": owner, "LOGNAME": owner}
    kwargs = {}
    if pw.pw_uid != 0 and user_session:
        runtime_dir = f"/run/user/{pw.pw_uid}"
        if not os.path.isdir(runtime_dir):
            raise RuntimeError(f"{runtime_dir} does not exist; enable lingering: loginctl enable-linger {owner}")
        full_env["XDG_RUNTIME_DIR"] = runtime_dir
    if pw.pw_uid != os.getuid():
        kwargs = {"user": pw.pw_uid, "group": pw.pw_gid,
                  "extra_groups": os.getgrouplist(owner, pw.pw_gid)}
    full_env.update(env or {})
    return subprocess.run(argv, env=full_env, cwd="/", capture_output=True, text=True,
                          timeout=timeout, check=True, **kwargs)


def list_containers(runtime: str, owner: str) -> list:
    """Running containers as dicts: id, name, image, image_id, labels."""
    if runtime == "podman":
        out = run_as(owner, ["podman", "ps", "--format", "json"]).stdout
        return [{"id": c["Id"], "name": (c.get("Names") or [c["Id"][:12]])[0], "image": c.get("Image", ""),
                 "image_id": c.get("ImageID", ""), "labels": c.get("Labels") or {}}
                for c in json.loads(out or "[]")]
    ids = run_as(owner, ["docker", "ps", "-q", "--no-trunc"]).stdout.split()
    if not ids:
        return []
    return [{"id": c["Id"], "name": c["Name"].lstrip("/"), "image": c["Config"].get("Image", ""),
             "image_id": c.get("Image", ""), "labels": c["Config"].get("Labels") or {}}
            for c in json.loads(run_as(owner, ["docker", "inspect", *ids]).stdout)]


def attach_containers(services: list, listed: dict = None) -> None:
    """Fill each service's .containers from its runtime, or from listed
    ((runtime, owner) -> containers, see running_containers) when given.

    Compose services claim containers by their compose labels. A quadlet
    service claims the containers whose systemd unit comes from its directory
    (the most specific one wins). A quadlet service for a whole user (path is
    the user's home) also owns every other container in that user's Podman;
    otherwise a user's only quadlet service owns the containers that no unit
    started, such as containers its own services start through the Podman API.
    """
    groups = {}
    for s in services:
        s.containers = []
        groups.setdefault((s.runtime, s.owner), []).append(s)
    for (runtime, owner), group in groups.items():
        if listed is not None:
            containers = listed.get((runtime, owner), [])
        else:
            try:
                containers = list_containers(runtime, owner)
            except (RuntimeError, KeyError, subprocess.SubprocessError, OSError, ValueError) as e:
                detail = getattr(e, "stderr", "") or e
                log(f"WARNING: cannot list {runtime} containers for {owner}: {str(detail).strip()}")
                continue
        compose = [s for s in group if s.deployment == "compose"]
        quadlet = [s for s in group if s.deployment == "quadlet"]
        projects = systemd_projects(owner, containers) if runtime == "podman" and quadlet else {}
        home = pwd.getpwnam(owner).pw_dir if quadlet else ""
        whole_user = next((s for s in quadlet if same_path(s.path, home)), None)
        # A service whose directory has running containers owns just those; the
        # project-name fallback is for services registered by name.
        live_dirs = {os.path.realpath(wd) for c in containers
                     if (wd := c["labels"].get(WORKING_DIR_LABEL)) and os.path.isdir(wd)}
        for c in containers:
            owner_svc = next((s for s in compose
                              if s.matches(c["labels"], os.path.realpath(s.path) not in live_dirs)), None)
            project = projects.get(c["id"], "")
            if owner_svc is None and project:
                owner_svc = max((s for s in quadlet if is_under(project, s.path)),
                                key=lambda s: len(os.path.realpath(s.path)), default=None)
            if owner_svc is None and whole_user:
                owner_svc = whole_user
            if owner_svc is None and not project and len(quadlet) == 1:
                owner_svc = quadlet[0]
            if owner_svc:
                owner_svc.containers.append(c)


# ---------------------------------------------------------------- systemd units

def unit_sources(owner: str, units: list) -> dict:
    """unit -> the file it was generated from (a quadlet), or else its unit file."""
    if not units:
        return {}
    argv = ["systemctl", *([] if owner == "root" else ["--user"]), "show",
            "-p", "Id", "-p", "SourcePath", "-p", "FragmentPath", "--", *units]
    sources = {}
    for block in run_as(owner, argv).stdout.split("\n\n"):
        props = dict(line.split("=", 1) for line in block.splitlines() if "=" in line)
        if props.get("Id"):
            sources[props["Id"]] = props.get("SourcePath") or props.get("FragmentPath") or ""
    return sources


def in_unit_dir(path: str) -> bool:
    """True for files in the directories systemd and quadlet read units from."""
    return (path.startswith(("/etc/", "/usr/", "/run/"))
            or "/.config/containers/systemd/" in path or "/.config/systemd/user/" in path)


def host_paths(unit_file: str, owner: str) -> list:
    """Host paths a quadlet loads or mounts (EnvironmentFile=, Volume=, Mount=), drop-ins included."""
    pw = pwd.getpwnam(owner)
    paths = []
    for f in [unit_file] + sorted(glob.glob(glob.escape(unit_file) + ".d/*.conf")):
        try:
            lines = Path(f).read_text(errors="replace").splitlines()
        except OSError:
            continue
        for line in lines:
            key, _, value = line.strip().partition("=")
            if key == "EnvironmentFile":
                found = [value.lstrip("-")]
            elif key == "Volume":
                found = [value.split(":", 1)[0]]
            elif key == "Mount":
                found = [kv.split("=", 1)[1] for kv in value.split(",") if kv.startswith(("source=", "src="))]
            else:
                continue
            for p in found:
                p = p.strip().replace("%h", pw.pw_dir).replace("%U", str(pw.pw_uid))
                if p.startswith("/") and "%" not in p and not p.startswith(SYSTEM_PATHS):
                    paths.append(os.path.normpath(p))
    return paths


def project_root(path: str) -> str:
    """Nearest directory at or above path that holds .git, .env or a compose file."""
    d = os.path.realpath(path if os.path.isdir(path) else os.path.dirname(path))
    while d != "/":
        if any(os.path.exists(os.path.join(d, m)) for m in PROJECT_MARKERS):
            return d
        d = os.path.dirname(d)
    return ""


def unit_project(source: str, owner: str) -> str:
    """The project directory a unit comes from, or '' when it cannot be told.

    A unit file that lives in a project (usually a quadlet symlinked into
    ~/.config/containers/systemd) belongs to that project. A copied or
    generated quadlet belongs to the project most of its env files and
    mounts point into.
    """
    if not source:
        return ""
    real = os.path.realpath(source)
    if not in_unit_dir(real):
        return project_root(real) or os.path.dirname(real)
    votes = Counter(r for r in map(project_root, host_paths(real, owner)) if r)
    return votes.most_common(1)[0][0] if votes else ""


def systemd_projects(owner: str, containers: list) -> dict:
    """container id -> project directory, for containers a systemd unit started."""
    units = sorted({c["labels"].get(SYSTEMD_UNIT_LABEL) for c in containers} - {None, ""})
    try:
        sources = unit_sources(owner, units)
    except (RuntimeError, KeyError, subprocess.SubprocessError, OSError) as e:
        log(f"WARNING: cannot read systemd units for {owner}: {str(getattr(e, 'stderr', '') or e).strip()}")
        return {}
    projects = {u: unit_project(sources.get(u, ""), owner) for u in units}
    return {c["id"]: projects.get(c["labels"].get(SYSTEMD_UNIT_LABEL), "") for c in containers}


# ---------------------------------------------------------------- inventory

def cmd_inventory(args) -> int:
    services = load_registry()
    attach_containers(services)
    lines = ["container_id,container_name,service,image"]
    for s in services:
        for c in s.containers:
            lines.append(",".join(csv_field(v) for v in (c["id"], c["name"], s.name, c["image"])))
    content = "\n".join([lines[0]] + sorted(lines[1:])) + "\n"
    if INVENTORY.exists() and INVENTORY.read_text() == content:
        return 0
    INVENTORY.parent.mkdir(parents=True, exist_ok=True)
    tmp = INVENTORY.with_suffix(".tmp")
    tmp.write_text(content)
    os.chmod(tmp, 0o644)
    os.replace(tmp, INVENTORY)
    log(f"Inventory updated: {len(lines) - 1} containers")
    if not args.no_reload:
        # Vector re-reads enrichment tables on reload (SIGHUP).
        subprocess.run(["systemctl", "try-reload-or-restart", VECTOR_UNIT], check=False)
    return 0


def csv_field(value: str) -> str:
    value = str(value)
    if any(ch in value for ch in ',"\n'):
        return '"' + value.replace('"', '""') + '"'
    return value


# ---------------------------------------------------------------- SBOM

class DependencyTrack:
    def __init__(self, url: str, api_key: str):
        self.url = url.rstrip("/")
        self.api_key = api_key

    def upload(self, name: str, version: str, bom: dict, tags: list, parent: tuple = None) -> None:
        """Upload a BOM, creating the project (under parent) if needed.

        Needs the API key permissions BOM_UPLOAD and PROJECT_CREATION_UPLOAD.
        """
        payload = {"projectName": name, "projectVersion": version, "autoCreate": True,
                   "projectTags": [{"name": t} for t in tags],
                   "bom": base64.b64encode(json.dumps(bom).encode()).decode()}
        if parent:
            payload["parentName"], payload["parentVersion"] = parent
        req = urllib.request.Request(f"{self.url}/api/v1/bom", data=json.dumps(payload).encode(),
                                     method="PUT", headers={"X-Api-Key": self.api_key,
                                                            "Content-Type": "application/json",
                                                            "Accept": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=300) as r:
                r.read()
        except urllib.error.HTTPError as e:
            raise RuntimeError(f"HTTP {e.code}: {e.read().decode(errors='replace')[:300]}") from None


EMPTY_BOM = {"bomFormat": "CycloneDX", "specVersion": "1.5", "version": 1, "components": []}


def split_image_ref(ref: str) -> tuple:
    """'docker.io/library/nginx:1.27' -> ('docker.io/library/nginx', '1.27')."""
    if "@" in ref:
        name, digest = ref.split("@", 1)
        return name, digest
    last = ref.rsplit("/", 1)[-1]
    if ":" in last:
        name, tag = ref.rsplit(":", 1)
        return name, tag
    return ref, "latest"


def sbom_project_name(c: dict) -> str:
    """The container's project name under its service in Dependency-Track: its
    own name when a systemd unit or compose file keeps that name stable, else
    its image's. Containers created on demand (e.g. one per user session) get
    new names all the time and would leave a project behind each."""
    labels = c["labels"]
    if labels.get(SYSTEMD_UNIT_LABEL) or labels.get("com.docker.compose.project"):
        return c["name"]
    return "image-" + split_image_ref(c["image"])[0].rsplit("/", 1)[-1]


def scan_image(svc: Service, container: dict) -> dict:
    """Save the container's image to a tar and run syft on it, both unprivileged
    where possible: a rootless Podman image is saved and scanned as its owner;
    docker and rootful Podman images are saved as root and scanned as SCAN_USER.
    """
    rootless = svc.runtime == "podman" and svc.owner != "root"
    scanner = pwd.getpwnam(svc.owner if rootless else SCAN_USER)
    tmp = tempfile.mkdtemp(prefix="humlab-sbom-", dir="/var/tmp")
    try:
        os.chown(tmp, scanner.pw_uid, scanner.pw_gid)
        archive = os.path.join(tmp, "image.tar")
        run_as(svc.owner if rootless else "root",
               [svc.runtime, "image", "save", "-o", archive, container["image_id"] or container["image"]],
               env={"TMPDIR": tmp}, timeout=3600)
        if not rootless:
            os.chown(archive, scanner.pw_uid, scanner.pw_gid)
        name, version = split_image_ref(container["image"])
        out = run_as(scanner.pw_name,
                     [str(BIN_DIR / "syft"), "-q", f"docker-archive:{archive}", "-o", "cyclonedx-json",
                      "--source-name", name, "--source-version", version],
                     env={"SYFT_CHECK_FOR_APP_UPDATE": "false", "XDG_CACHE_HOME": tmp, "TMPDIR": tmp},
                     timeout=3600, user_session=False).stdout
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    bom = json.loads(out)
    sanitize_licenses(bom)
    return bom


def sanitize_licenses(bom: dict) -> None:
    """Reduce each component's licenses to one expression Dependency-Track accepts;
    drop broken ones and invalid URLs."""
    url_pattern = re.compile(r"^(https?|ftp)://[^\s/$.?#].[^\s]*$")
    for component in bom.get("components", []):
        if "licenses" not in component:
            continue
        valid = None
        for lic in component["licenses"]:
            if not isinstance(lic, dict):
                continue
            if isinstance(lic.get("expression"), str):
                valid = {"expression": lic["expression"]}
                break
            obj = lic.get("license")
            if isinstance(obj, dict):
                if "id" in obj or "name" in obj:
                    valid = {"expression": obj.get("id") or obj["name"]}
                    break
                if "url" in obj and not url_pattern.match(obj["url"]):
                    obj.pop("url", None)
        if valid:
            component["licenses"] = [valid]
        else:
            component.pop("licenses", None)


def cmd_sbom(args) -> int:
    host = os.environ.get("HOST_NAME") or os.uname().nodename.split(".")[0]
    dt_url = os.environ.get("DT_URL")
    key_file = Path(os.environ.get("DT_API_KEY_FILE", CONF_DIR / "secrets" / "dtrack.apikey"))
    if not dt_url or not key_file.is_file():
        log(f"ERROR: DT_URL must be set and {key_file} must exist")
        return 2
    dt = DependencyTrack(dt_url, key_file.read_text().strip())

    services = load_registry()
    if args.service:
        services = [s for s in services if s.name in args.service]
    attach_containers(services)

    failures = 0
    for svc in services:
        if not svc.containers:
            log(f"{svc.name}: no running containers, skipped")
            continue
        # Project tree: <service> @ <host>  ->  <service>/<container> @ <host>
        # (<service>/image-<name> for containers without a stable name).
        # Blackbox turns projects tagged "service" into collections that add up
        # their containers; a collection takes no BOM, but it exists, so go on.
        try:
            dt.upload(svc.name, host, EMPTY_BOM, [host, svc.name, "service"])
        except (RuntimeError, OSError) as e:
            if "collection project" not in str(e):
                log(f"ERROR: {svc.name}: cannot create parent project: {e}")
                failures += 1
                continue
        boms = {}
        uploaded = set()
        for c in svc.containers:
            image_key = c["image_id"] or c["image"]
            child = sbom_project_name(c)
            if child in uploaded:
                continue
            try:
                if image_key not in boms:
                    log(f"{svc.name}: scanning {c['image']}")
                    boms[image_key] = scan_image(svc, c)
                dt.upload(f"{svc.name}/{child}", host, boms[image_key], [host, svc.name],
                          parent=(svc.name, host))
                uploaded.add(child)
                log(f"{svc.name}: uploaded SBOM for {child} ({len(boms[image_key].get('components', []))} components)")
            except subprocess.CalledProcessError as e:
                log(f"ERROR: {svc.name}/{c['name']}: {' '.join(e.cmd[:3])} failed: {(e.stderr or '').strip()[:300]}")
                failures += 1
            except (RuntimeError, OSError, ValueError, KeyError, subprocess.SubprocessError) as e:
                log(f"ERROR: {svc.name}/{c['name']}: {e}")
                failures += 1
    return 1 if failures else 0


# ---------------------------------------------------------------- discovery

def quadlet_users() -> list:
    """Service users: home directly under /srv with a quadlet directory."""
    return sorted((pw for pw in pwd.getpwall()
                   if re.fullmatch(r"/srv/[^/]+", pw.pw_dir)
                   and os.path.isdir(os.path.join(pw.pw_dir, ".config/containers/systemd"))),
                  key=lambda pw: pw.pw_name)


def find_compose_dirs(roots: list) -> list:
    found = []
    for root in roots:
        base_depth = root.rstrip("/").count("/")
        for dirpath, dirnames, filenames in os.walk(root, onerror=lambda e: None):
            if any(f in filenames for f in COMPOSE_FILES):
                found.append(dirpath)
            if dirpath.count("/") - base_depth >= SEARCH_DEPTH:
                dirnames[:] = []
            else:
                dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS and not d.startswith(".")]
    return sorted(set(found))


def conmon_uids() -> set:
    """Users with running Podman containers: each container has a conmon process
    running as the user whose Podman started it."""
    uids = set()
    for pid in os.listdir("/proc"):
        if not pid.isdigit():
            continue
        try:
            with open(f"/proc/{pid}/comm") as f:
                if f.read().strip() not in ("conmon", "conmonrs"):
                    continue
            uids.add(os.stat(f"/proc/{pid}").st_uid)
        except OSError:
            pass
    return uids


def container_runtimes(busy: set) -> list:
    """(runtime, owner) for Docker, rootful Podman, and the rootless Podman of every
    user with a runtime dir or running containers (busy: their uids)."""
    sources = []
    if shutil.which("docker") and os.path.exists("/var/run/docker.sock"):
        sources.append(("docker", "root"))
    if shutil.which("podman"):
        sources.append(("podman", "root"))
        uids = set(busy)
        if os.path.isdir("/run/user"):
            uids |= {int(e) for e in os.listdir("/run/user") if e.isdigit()}
        for uid in sorted(uids - {0}):
            try:
                sources.append(("podman", pwd.getpwuid(uid).pw_name))
            except KeyError:
                pass
    return sources


def running_containers() -> dict:
    """(runtime, owner) -> running containers, for every runtime on the host. Warns
    about each runtime that has containers running but cannot be listed; those
    would be missing from discovery, and from the inventory."""
    busy = conmon_uids()
    found = {}
    for runtime, owner in container_runtimes(busy):
        try:
            found[(runtime, owner)] = list_containers(runtime, owner)
        except (RuntimeError, subprocess.SubprocessError, OSError, ValueError) as e:
            if runtime == "docker" or pwd.getpwnam(owner).pw_uid in busy:
                detail = getattr(e, "stderr", "") or e
                log(f"WARNING: {owner} has running {runtime} containers, but they cannot be listed: "
                    f"{str(detail).strip()}")
    return found


@dataclass
class RunningProject:
    """A compose project with running containers."""
    runtime: str
    owner: str
    name: str                  # com.docker.compose.project
    working_dir: str           # realpath of com.docker.compose.project.working_dir, or ''
    containers: list

    @property
    def labels(self) -> dict:
        return {"com.docker.compose.project": self.name, WORKING_DIR_LABEL: self.working_dir}


def running_compose_projects(listed: dict) -> list:
    projects = {}
    for (runtime, owner), containers in listed.items():
        for c in containers:
            name = c["labels"].get("com.docker.compose.project")
            if name:
                wd = c["labels"].get(WORKING_DIR_LABEL, "")
                key = (runtime, owner, name, os.path.realpath(wd) if wd else "")
                projects.setdefault(key, []).append(c["name"])
    return [RunningProject(*key, sorted(names)) for key, names in sorted(projects.items())]


def declared_project_names(path: str) -> set:
    """Names a compose directory's project may run under: the directory's name, the
    compose file's top-level name:, and COMPOSE_PROJECT_NAME in .env."""
    names = {compose_project_name(path)}
    for f, pattern in [(f, r"^name:\s*['\"]?([^'\"\s#]+)") for f in COMPOSE_FILES] + \
                      [(".env", r"^COMPOSE_PROJECT_NAME=\s*['\"]?([^'\"\s#]+)")]:
        try:
            text = Path(path, f).read_text(errors="replace")
        except OSError:
            continue
        names |= {m.group(1).lower() for m in re.finditer(pattern, text, re.M) if "$" not in m.group(1)}
    return names


def find_running_project(path: str, running: list, services: list):
    """(project, how it matched) for the running project that a compose directory
    holds, or (None, ''). The working-dir label decides when it leads to a
    directory; otherwise a project name the directory declares, if no
    registered service has that project yet, preferring the directory's owner.
    Only projects without a working-dir label match by name."""
    real = os.path.realpath(path)
    exact = next((p for p in running if p.working_dir == real), None)
    if exact:
        return exact, "working directory"
    names = declared_project_names(path)
    loose = [p for p in running if p.name in names and not p.working_dir
             and not any(s.deployment == "compose" and (s.runtime, s.owner) == (p.runtime, p.owner)
                         and s.matches(p.labels) for s in services)]
    dir_owner = pwd.getpwuid(os.stat(path).st_uid).pw_name
    loose.sort(key=lambda p: p.owner != dir_owner)
    return (loose[0], f"project name '{loose[0].name}'") if loose else (None, "")


def running_systemd_projects(listed: dict) -> list:
    """(owner, project directory, units) for running Podman containers that systemd
    units started, in any account. A project nested in another (a repository
    checked out inside a deployment) counts as the outer one. Units whose project
    cannot be told go to the owner's only project, or else count as the owner's home."""
    found = []
    for (runtime, owner), containers in listed.items():
        if runtime != "podman":
            continue
        containers = [c for c in containers if c["labels"].get(SYSTEMD_UNIT_LABEL)]
        projects = systemd_projects(owner, containers)
        known = {p for p in projects.values() if p}
        outer = {p: min((q for q in known if is_under(p, q)), key=len) for p in known}
        tops = set(outer.values())
        fallback = next(iter(tops)) if len(tops) == 1 else pwd.getpwnam(owner).pw_dir
        groups = {}
        for c in containers:
            project = outer.get(projects.get(c["id"], ""), fallback)
            groups.setdefault(project, set()).add(c["labels"][SYSTEMD_UNIT_LABEL].removesuffix(".service"))
        found += [(owner, project, sorted(units)) for project, units in sorted(groups.items())]
    return found


def uncovered_containers(services: list, listed: dict) -> list:
    """Running containers that no service claims, by the same matching as the
    inventory: one line per owner and compose project."""
    attach_containers(services, listed)
    claimed = {c["id"] for s in services for c in s.containers}
    groups = {}
    for (runtime, owner), containers in sorted(listed.items()):
        for c in containers:
            if c["id"] not in claimed:
                key = (owner, runtime, c["labels"].get("com.docker.compose.project", ""),
                       c["labels"].get(WORKING_DIR_LABEL, ""))
                groups.setdefault(key, []).append(c["name"])
    lines = []
    for (owner, runtime, project, wd), names in groups.items():
        what = f"compose project {project}{f' in {wd}' if wd else ''}: " if project else ""
        lines.append(f"{owner} ({runtime}): {what}{', '.join(sorted(names))}")
    return lines


# Directory names that say how a project is deployed rather than what it is,
# and the environment names that are kept as a suffix.
GENERIC_DIRS = {"docker", "compose", "docker-compose", "podman", "container", "containers",
                "deploy", "deployment", "deployments", "infra", "ops", "src", "app"}
ENV_DIRS = {"production", "prod", "staging", "stage", "test", "testing", "dev", "development", "local"}


def suggest_name(path: str, fallback: str) -> str:
    """A service name for a project directory: its own name, or for a directory
    named after the deployment the project it belongs to, keeping environment
    names: swedeb-api/docker -> swedeb-api, swedeb-api/docker/compose/production
    -> swedeb-api-production. Stops at a home directory or a search root."""
    stops = {"/"} | set(DEFAULT_ROOTS) | {pw.pw_dir for pw in pwd.getpwall()}
    path = os.path.normpath(path)
    envs = []
    while os.path.dirname(path) not in stops:
        base = os.path.basename(path).lower()
        if base in ENV_DIRS:
            envs.insert(0, base)
        elif base not in GENERIC_DIRS:
            break
        path = os.path.dirname(path)
    parts = [os.path.basename(path).lower()] + [e for e in envs if e != os.path.basename(path).lower()]
    return re.sub(r"[^a-z0-9._-]+", "-", "-".join(parts)).strip("-.") or fallback


def user_exists(name: str) -> bool:
    try:
        pwd.getpwnam(name)
        return True
    except KeyError:
        return False


def ask(prompt: str, default: str = "") -> str:
    answer = input(f"{prompt} [{default}]: " if default else f"{prompt}: ").strip()
    return answer or default


def ask_yes(prompt: str, default: bool) -> bool:
    answer = input(f"{prompt} [{'Y/n' if default else 'y/N'}]: ").strip().lower()
    return default if not answer else answer.startswith("y")


def ask_name(default: str, taken: set) -> str:
    while True:
        name = ask("  Service name", default).lower()
        if not NAME_RE.match(name):
            print("  Use lowercase letters, digits, '.', '_' or '-'.")
        elif name in taken:
            print(f"  '{name}' is already registered.")
        else:
            return name


def cmd_services(args) -> int:
    services = load_registry()
    registered_paths = {(s.deployment, os.path.realpath(s.path)) for s in services}
    taken = {s.name for s in services}
    auto = args.yes

    if services:
        print("Already registered:")
        for s in services:
            print(f"  {s.name:24} {s.deployment:8} {s.runtime:7} owner={s.owner:12} {s.path}")
        print()

    # Quadlet service users
    for pw in quadlet_users():
        if ("quadlet", os.path.realpath(pw.pw_dir)) in registered_paths:
            continue
        print(f"Quadlet service user {pw.pw_name} ({pw.pw_dir})")
        if auto or ask_yes("  Monitor it?", True):
            name = pw.pw_name if auto else ask_name(pw.pw_name, taken)
            services.append(Service(name, "quadlet", "podman", pw.pw_name, pw.pw_dir))
            taken.add(name)

    listed = running_containers()

    # Containers that systemd units start in other accounts (quadlets outside
    # /srv, e.g. a deployment that installs its quadlets in a user's
    # ~/.config/containers/systemd), one service per project directory.
    for owner, project, units in running_systemd_projects(listed):
        if any(s.deployment == "quadlet" and s.owner == owner and is_under(project, s.path) for s in services):
            continue
        whole_user = same_path(project, pwd.getpwnam(owner).pw_dir)
        what = f"Podman containers of {owner}" if whole_user else f"Podman project {project} (user {owner})"
        print(f"{what}, started by systemd: {', '.join(units)}")
        if auto or ask_yes("  Monitor it?", True):
            name = suggest_name(project, owner)
            if auto:
                name = name if name not in taken else f"{name}-{len(taken)}"
            else:
                name = ask_name(name, taken)
            services.append(Service(name, "quadlet", "podman", owner, project))
            taken.add(name)

    # Compose projects
    roots = [r for r in DEFAULT_ROOTS if os.path.isdir(r)]
    if not auto:
        roots = ask("Directories to search for compose files", " ".join(roots)).split()
    running = running_compose_projects(listed)
    quadlet_homes = [os.path.realpath(s.path) for s in services if s.deployment == "quadlet"]
    candidates = [d for d in find_compose_dirs(roots)
                  if ("compose", os.path.realpath(d)) not in registered_paths
                  and not any(os.path.realpath(d).startswith(h + "/") for h in quadlet_homes)]

    def add_compose(path: str, info, interactive: bool) -> None:
        if info:
            runtime, owner, project = info.runtime, info.owner, info.name
        else:
            runtime, owner, project = "", pwd.getpwuid(os.stat(path).st_uid).pw_name, compose_project_name(path)
        # A project name set in the compose file says more than a directory name.
        if project and project != compose_project_name(path):
            default_name = project
        else:
            default_name = suggest_name(path, compose_project_name(path))
        if not interactive:
            name = default_name if default_name not in taken else f"{default_name}-{len(taken)}"
        else:
            name = ask_name(default_name, taken)
            if not runtime:
                runtime = ask("  Runtime (podman/docker)", "docker" if shutil.which("docker") else "podman")
                if runtime == "docker":
                    owner = "root"
                owner = ask("  Owner (the user who runs it; root for docker or rootful podman)", owner)
                while not user_exists(owner):
                    owner = ask(f"  No user '{owner}'. Owner", "root")
                project = ask("  Compose project name (the prefix of its container names)", project)
        if runtime not in ("podman", "docker"):
            print(f"  Skipped {path}: unknown runtime '{runtime}'")
            return
        services.append(Service(name, "compose", runtime, owner, os.path.realpath(path),
                                project if project != compose_project_name(path) else ""))
        taken.add(name)

    # Only running projects are offered; a home directory can hold dozens of
    # checkouts that are never started. Those can be added by path below.
    idle = []
    for d in candidates:
        info, how = find_running_project(d, running, services)
        if not info:
            idle.append(d)
            continue
        print(f"Compose project {d} (running under {info.runtime} as {info.owner}, matched by {how})")
        if auto:
            add_compose(d, info, False)
        elif ask_yes("  Monitor it?", True):
            add_compose(d, info, True)
    if idle and not auto:
        print(f"\n{len(idle)} compose directories have no running containers and are not offered.")
        if ask_yes("  List them?", False):
            for d in idle:
                print(f"    {d}")

    # Everything the inventory would leave out, so it can be added by hand.
    uncovered = uncovered_containers(services, listed)
    if uncovered:
        print("\nRunning containers that no service covers (logged under their own names, no SBOM):")
        for line in uncovered:
            print(f"  {line}")
        print()

    if not auto:
        while True:
            path = input("Add another compose directory (blank to finish): ").strip()
            if not path:
                break
            if not any(os.path.isfile(os.path.join(path, f)) for f in COMPOSE_FILES):
                print(f"  No compose file in {path}")
                continue
            info, how = find_running_project(path, running, services)
            if info:
                print(f"  Running under {info.runtime} as {info.owner}, matched by {how}")
            add_compose(path, info, True)

        for s in list(services):
            if not os.path.isdir(s.path) and ask_yes(f"{s.name}: {s.path} no longer exists. Remove it?", True):
                services.remove(s)

    for owner in sorted({s.owner for s in services if s.runtime == "podman" and s.owner != "root"}):
        if user_exists(owner):
            uid = pwd.getpwnam(owner).pw_uid
            if not os.path.exists(f"/var/lib/systemd/linger/{owner}"):
                print(f"NOTE: {owner} has no lingering; its containers stop at logout and cannot be "
                      f"scanned while it is logged out. Fix: loginctl enable-linger {owner}")
            elif not os.path.isdir(f"/run/user/{uid}"):
                print(f"NOTE: /run/user/{uid} for {owner} is missing")

    save_registry(services)
    print(f"Saved {len(services)} services to {REGISTRY}")
    return 0


def cmd_remove(args) -> int:
    services = load_registry()
    unknown = sorted(set(args.service) - {s.name for s in services})
    if unknown:
        log(f"ERROR: not registered: {', '.join(unknown)}")
        return 1
    save_registry([s for s in services if s.name not in args.service])
    print(f"Removed {', '.join(args.service)}. Its containers are now logged under their own names; "
          f"its Dependency-Track project is kept.")
    return 0


def print_services(services: list) -> None:
    for i, s in enumerate(services, 1):
        print(f"{i:3}. {s.name:24} {s.deployment:8} {s.runtime:7} owner={s.owner:12} {s.path}")
        for c in s.containers:
            print(f"       {c['name']:36} {c['image']}")
        if not s.containers:
            print("       (no running containers)")


def cmd_list(args) -> int:
    services = load_registry()
    attach_containers(services)
    print_services(services)
    return 0


def cmd_edit(args) -> int:
    """Numbered list of the services; rename or unregister one at a time."""
    services = load_registry()
    attach_containers(services)
    while True:
        print_services(services)
        if not services:
            return 0
        try:
            choice = input("\nNumber of a service to change (blank to finish): ").strip()
        except EOFError:
            choice = ""
        if not choice:
            return 0
        if not (choice.isdigit() and 1 <= int(choice) <= len(services)):
            print(f"  Enter a number from 1 to {len(services)}.\n")
            continue
        s = services[int(choice) - 1]
        print(f"\n{s.name}: {s.deployment} project in {s.path}")
        action = input("  [N] New name  [D] Unregister  [Enter] Back: ").strip().lower()
        if action == "n":
            suggestion = suggest_name(s.path, s.name)
            name = ask_name(suggestion, {x.name for x in services} - {s.name})
            if name != s.name:
                print(f"  Renamed {s.name} to {name}. New logs and metrics use the new name; stored logs keep\n"
                      f"  the old one. Dependency-Track gets a project '{name}' at the next scan; the old\n"
                      f"  project '{s.name}' stays there until you delete it.")
                s.name = name
                save_registry(services)
                services.sort(key=lambda x: x.name)
        elif action == "d":
            if ask_yes(f"  Unregister {s.name}?", False):
                services.remove(s)
                save_registry(services)
                print(f"  Unregistered {s.name}. Its containers are now logged under their own names.")
        print()


def cmd_render(args) -> int:
    """Fill @NAME@ placeholders in a template from an env file (KEY=value lines)."""
    values = {}
    for line in Path(args.env_file).read_text().splitlines():
        if "=" in line and not line.lstrip().startswith("#"):
            key, value = line.split("=", 1)
            values[key.strip()] = value.strip()
    text = Path(args.template).read_text()
    text = re.sub(r"@([A-Z][A-Z0-9_]*)@", lambda m: values.get(m.group(1), m.group(0)), text)
    missing = sorted(set(re.findall(r"@([A-Z][A-Z0-9_]*)@", text)))
    if missing:
        log(f"ERROR: {args.template}: no value for {', '.join(missing)} in {args.env_file}")
        return 1
    sys.stdout.write(text)
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(prog="humlab-agents", description=__doc__.split("\n\n")[0])
    sub = parser.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("services", help="find and register services")
    p.add_argument("--yes", action="store_true", help="register quadlet users, systemd-started projects and running compose projects without asking")
    p.set_defaults(func=cmd_services)
    sub.add_parser("list", help="show registered services").set_defaults(func=cmd_list)
    sub.add_parser("edit", help="rename or unregister services, picked by number").set_defaults(func=cmd_edit)
    p = sub.add_parser("remove", help="unregister services")
    p.add_argument("service", nargs="+")
    p.set_defaults(func=cmd_remove)
    p = sub.add_parser("inventory", help="write the container-to-service table for Vector")
    p.add_argument("--no-reload", action="store_true", help="don't reload Vector afterwards")
    p.set_defaults(func=cmd_inventory)
    p = sub.add_parser("sbom", help="scan images and upload SBOMs")
    p.add_argument("service", nargs="*", help="only these services")
    p.set_defaults(func=cmd_sbom)
    p = sub.add_parser("render", help="fill @NAME@ placeholders in a template from an env file")
    p.add_argument("template")
    p.add_argument("env_file")
    p.set_defaults(func=cmd_render)
    args = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
