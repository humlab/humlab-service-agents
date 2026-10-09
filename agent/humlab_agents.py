#!/usr/bin/env python3
"""Service registry, container inventory and SBOM scanning for one server.

  humlab-agents services [--auto]  Find services and register them (interactive;
                                   --auto: without asking, nightly)
  humlab-agents list               Show registered services and their containers
  humlab-agents edit               Rename or unregister services, picked by number
  humlab-agents inventory          Map running containers to services for Vector
  humlab-agents sbom [SERVICE...]  Scan images with syft, upload to Dependency-Track
  humlab-agents render TPL ENV     Fill @NAME@ placeholders in TPL from ENV

Runs as root (from install.sh or systemd). Talks to a rootless Podman only as
the user who owns it, and runs syft unprivileged. Standard library only.
"""

import argparse
import configparser
import glob
import json
import os
import pwd
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import urllib.error
import urllib.request
import uuid
from collections import Counter
from dataclasses import dataclass, field
from datetime import date
from pathlib import Path

CONF_DIR = Path(os.environ.get("HUMLAB_AGENTS_CONF", "/etc/humlab-agents"))
REGISTRY = CONF_DIR / "services.conf"
# Services that were declined or unregistered; automatic discovery skips them.
IGNORED = CONF_DIR / "ignored.conf"
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
# Compose project names, as Compose itself restricts them.
PROJECT_RE = re.compile(r"^[a-z0-9][a-z0-9_-]*$")
CONTROL_CHARS = re.compile(r"[\x00-\x1f\x7f]")
# Most a user-controlled file is read for, and how many drop-ins of a unit.
MAX_USER_FILE = 1 << 20
MAX_DROPINS = 50

# Names Docker and Podman make up for a container started without --name
# (adjective_surname). They change whenever the container is recreated.
GENERATED_NAME = re.compile(
    r"^(admiring|adoring|affectionate|agitated|amazing|angry|awesome|beautiful|blissful|bold|"
    r"boring|brave|busy|charming|clever|compassionate|competent|condescending|confident|cool|"
    r"cranky|crazy|dazzling|determined|distracted|dreamy|eager|ecstatic|elastic|elated|elegant|"
    r"eloquent|epic|exciting|fervent|festive|flamboyant|focused|friendly|frosty|funny|gallant|"
    r"gifted|goofy|gracious|great|happy|hardcore|heuristic|hopeful|hungry|infallible|inspiring|"
    r"intelligent|interesting|jolly|jovial|keen|kind|laughing|loving|lucid|magical|modest|musing|"
    r"mystifying|naughty|nervous|nice|nifty|nostalgic|objective|optimistic|peaceful|pedantic|"
    r"pensive|practical|priceless|quirky|quizzical|recursing|relaxed|reverent|romantic|sad|"
    r"serene|sharp|silly|sleepy|stoic|strange|stupefied|suspicious|sweet|tender|thirsty|"
    r"trusting|unruffled|upbeat|vibrant|vigilant|vigorous|wizardly|wonderful|xenodochial|"
    r"youthful|zealous|zen)_[a-z]+$")
SAFE_PATH = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"


def _stderr_is_journal() -> bool:
    try:
        dev, ino = os.environ["JOURNAL_STREAM"].split(":")
        st = os.fstat(2)
        return (st.st_dev, st.st_ino) == (int(dev), int(ino))
    except (KeyError, ValueError, OSError):
        return False


# Under systemd, a <N> prefix sets the journal priority: errors and warnings
# then reach blackbox, which only receives host logs of warning and worse.
JOURNAL = _stderr_is_journal()


def log(msg: str) -> None:
    prefix = ""
    if JOURNAL:
        prefix = "<3>" if msg.startswith("ERROR") else "<4>" if msg.startswith("WARNING") else ""
    print(prefix + msg, file=sys.stderr, flush=True)


def read_user_file(path: str, limit: int = MAX_USER_FILE) -> str:
    """Text of a file that a user controls, read as root. Refuses symlinks, FIFOs,
    devices (a symlink to /dev/zero) and anything but a regular file, and reads
    at most limit bytes. Raises OSError for what it refuses."""
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise OSError(f"{path} is not a regular file")
        with os.fdopen(fd, "rb", closefd=False) as f:
            return f.read(limit).decode(errors="replace")
    finally:
        os.close(fd)


# ---------------------------------------------------------------- registry

@dataclass
class Service:
    name: str
    deployment: str            # quadlet | compose | container
    runtime: str               # podman | docker
    owner: str                 # user whose runtime holds the containers (root for docker)
    path: str                  # quadlet: the user's home, or the project directory its
                               # units come from; compose: the project directory;
                               # container: ''
    project: str = ""          # compose project name, when it differs from the directory name
    container: str = ""        # container: the container's name
    last_seen: str = ""        # date it last had running containers (YYYY-MM-DD)
    containers: list = field(default_factory=list)

    @property
    def key(self) -> str:
        """What the service is, independent of its name (for ignored.conf)."""
        if self.deployment == "container":
            return f"container {self.runtime} {self.owner} {self.container}"
        if self.deployment == "quadlet":
            return f"quadlet {self.owner} {os.path.realpath(self.path)}"
        return f"compose {self.runtime} {self.owner} {os.path.realpath(self.path)}"

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
        if not NAME_RE.match(name):
            log(f"WARNING: {REGISTRY}: ignoring service with invalid name {name!r}")
            continue
        s = cp[name]
        services.append(Service(name=name, deployment=s.get("deployment", "compose"),
                                runtime=s.get("runtime", "podman"), owner=s.get("owner", "root"),
                                path=s.get("path", ""), project=s.get("project", ""),
                                container=s.get("container", ""), last_seen=s.get("last_seen", "")))
    return services


def save_registry(services: list) -> None:
    cp = configparser.ConfigParser(interpolation=None)
    for s in sorted(services, key=lambda s: s.name):
        # Names and values come from container labels, which any user with a
        # rootless Podman controls. A newline would add sections to this file.
        if not NAME_RE.match(s.name) or any(CONTROL_CHARS.search(v) for v in
                                            (s.deployment, s.runtime, s.owner, s.path, s.project, s.container)):
            log(f"WARNING: not registering service {s.name!r}: its name or settings contain unusable characters")
            continue
        cp[s.name] = {"deployment": s.deployment, "runtime": s.runtime, "owner": s.owner, "path": s.path}
        if s.project and s.project != compose_project_name(s.path):
            cp[s.name]["project"] = s.project
        if s.container:
            cp[s.name]["container"] = s.container
        if s.last_seen:
            cp[s.name]["last_seen"] = s.last_seen
    REGISTRY.parent.mkdir(parents=True, exist_ok=True)
    tmp = REGISTRY.with_suffix(".tmp")
    with open(tmp, "w") as f:
        f.write("# Services monitored on this server. Written by 'humlab-agents services';\n"
                "# safe to edit by hand. The section name is the service name used in\n"
                "# OpenSearch (service.name), Prometheus (service) and Dependency-Track.\n\n")
        cp.write(f)
    os.chmod(tmp, 0o644)
    os.replace(tmp, REGISTRY)


def load_ignored() -> dict:
    """Service key -> comment, from ignored.conf."""
    ignored = {}
    try:
        for line in IGNORED.read_text().splitlines():
            key, _, comment = line.partition("#")
            if key.strip():
                ignored[key.strip()] = comment.strip()
    except OSError:
        pass
    return ignored


def save_ignored(ignored: dict) -> None:
    lines = ["# Services that automatic discovery leaves alone: declined, or unregistered",
             "# by hand. Delete a line to have it offered again. Written by humlab-agents.", ""]
    lines += [f"{k}  # {c}" if c else k for k, c in sorted(ignored.items())
              if not CONTROL_CHARS.search(k + c)]
    IGNORED.parent.mkdir(parents=True, exist_ok=True)
    tmp = IGNORED.with_suffix(".tmp")
    tmp.write_text("\n".join(lines) + "\n")
    os.chmod(tmp, 0o644)
    os.replace(tmp, IGNORED)


def ignore(ignored: dict, s: Service, why: str) -> None:
    ignored[s.key] = f"{s.name}, {why} {date.today().isoformat()}"


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
    # No stdin and a session of its own: the command must not read what the
    # admin types at the terminal, or share its session.
    return subprocess.run(argv, env=full_env, cwd="/", capture_output=True, text=True,
                          timeout=timeout, check=True, stdin=subprocess.DEVNULL,
                          start_new_session=True, **kwargs)


def list_containers(runtime: str, owner: str) -> list:
    """Running containers as dicts: id, name, image, image_id, labels."""
    if runtime == "podman":
        out = run_as(owner, ["podman", "ps", "--format", "json"]).stdout
        return [{"id": c["Id"], "name": (c.get("Names") or [c["Id"][:12]])[0], "image": c.get("Image", ""),
                 "image_id": c.get("ImageID", ""), "labels": c.get("Labels") or {},
                 "infra": bool(c.get("IsInfra"))}
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
        by_name = {s.container: s for s in group if s.deployment == "container"}
        projects = systemd_projects(owner, containers) if runtime == "podman" and quadlet else {}
        home = pwd.getpwnam(owner).pw_dir if quadlet else ""
        whole_user = next((s for s in quadlet if same_path(s.path, home)), None)
        # A service whose directory has running containers owns just those; the
        # project-name fallback is for services registered by name.
        live_dirs = {os.path.realpath(wd) for c in containers
                     if (wd := c["labels"].get(WORKING_DIR_LABEL)) and os.path.isdir(wd)}
        for c in containers:
            owner_svc = by_name.get(c["name"]) or next(
                (s for s in compose if s.matches(c["labels"], os.path.realpath(s.path) not in live_dirs)), None)
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
    for f in [unit_file] + sorted(glob.glob(glob.escape(unit_file) + ".d/*.conf"))[:MAX_DROPINS]:
        try:
            lines = read_user_file(f).splitlines()
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
    # owner_uid: Vector accepts a registered container's journal lines only from
    # this user's runtime (anyone can run conmon and claim a container id).
    lines = ["container_id,container_name,service,image,owner_uid"]
    for s in services:
        try:
            uid = str(pwd.getpwnam(s.owner).pw_uid)
        except KeyError:
            uid = ""
        for c in s.containers:
            lines.append(",".join(csv_field(v) for v in (c["id"], c["name"], s.name, c["image"], uid)))
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

        Multipart rather than Base64 in JSON, which Dependency-Track refuses above
        20 MB (a large image's BOM). Needs the API key permissions BOM_UPLOAD and
        PROJECT_CREATION_UPLOAD.
        """
        fields = {"projectName": name, "projectVersion": version, "autoCreate": "true",
                  "projectTags": ",".join(tags)}
        if parent:
            fields["parentName"], fields["parentVersion"] = parent
        boundary = "humlab-" + uuid.uuid4().hex
        parts = [f'--{boundary}\r\nContent-Disposition: form-data; name="{k}"\r\n\r\n{v}\r\n'.encode()
                 for k, v in fields.items()]
        parts.append(f'--{boundary}\r\nContent-Disposition: form-data; name="bom"; filename="bom.json"\r\n'
                     f'Content-Type: application/json\r\n\r\n'.encode() + json.dumps(bom).encode() + b"\r\n")
        body = b"".join(parts) + f"--{boundary}--\r\n".encode()
        req = urllib.request.Request(f"{self.url}/api/v1/bom", data=body, method="POST",
                                     headers={"X-Api-Key": self.api_key,
                                              "Content-Type": f"multipart/form-data; boundary={boundary}",
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


def sbom_project_name(c: dict, svc: Service) -> str:
    """The container's project name under its service in Dependency-Track: its
    own name when a systemd unit, compose file or registration keeps that name
    stable, else its image's. Containers created on demand (e.g. one per user
    session) get new names all the time and would leave a project behind each."""
    labels = c["labels"]
    if svc.deployment == "container" or labels.get(SYSTEMD_UNIT_LABEL) or labels.get("com.docker.compose.project"):
        return c["name"]
    return "image-" + split_image_ref(c["image"])[0].rsplit("/", 1)[-1]


def scan_image(svc: Service, container: dict) -> dict:
    """Save the container's image to a tar and run syft on it, both unprivileged
    where possible: a rootless Podman image is saved and scanned as its owner;
    docker and rootful Podman images are saved as root and scanned as SCAN_USER.

    The scanner never gets a directory that root writes into. Root-run saves go
    to a directory only root can write to; the finished archive is handed over
    with a chown that does not follow symlinks, and the scanner gets its own
    work directory below it.
    """
    rootless = svc.runtime == "podman" and svc.owner != "root"
    scanner = pwd.getpwnam(svc.owner if rootless else SCAN_USER)
    tmp = tempfile.mkdtemp(prefix="humlab-sbom-", dir="/var/tmp")
    try:
        archive = os.path.join(tmp, "image.tar")
        if rootless:
            # The owner saves and scans in its own directory; root only removes it.
            os.chown(tmp, scanner.pw_uid, scanner.pw_gid)
            work = tmp
        else:
            # Root-owned and not writable by the scanner, which can only traverse it.
            os.chmod(tmp, 0o711)
            work = os.path.join(tmp, "work")
            os.mkdir(work, 0o700)
            os.chown(work, scanner.pw_uid, scanner.pw_gid, follow_symlinks=False)
        run_as(svc.owner if rootless else "root",
               [svc.runtime, "image", "save", "-o", archive, container["image_id"] or container["image"]],
               env={"TMPDIR": tmp}, timeout=3600)
        if not rootless:
            if not stat.S_ISREG(os.lstat(archive).st_mode):
                raise RuntimeError(f"{archive} is not a regular file")
            os.chown(archive, scanner.pw_uid, scanner.pw_gid, follow_symlinks=False)
        name, version = split_image_ref(container["image"])
        out = run_as(scanner.pw_name,
                     [str(BIN_DIR / "syft"), "-q", f"docker-archive:{archive}", "-o", "cyclonedx-json",
                      "--source-name", name, "--source-version", version],
                     env={"SYFT_CHECK_FOR_APP_UPDATE": "false", "XDG_CACHE_HOME": work, "TMPDIR": work},
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
            child = sbom_project_name(c, svc)
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


def running_containers(failed: set = None) -> dict:
    """(runtime, owner) -> running containers, for every runtime on the host. Warns
    about each runtime that has containers running but cannot be listed (added to
    failed); those would be missing from discovery, and from the inventory."""
    busy = conmon_uids()
    found = {}
    for runtime, owner in container_runtimes(busy):
        try:
            found[(runtime, owner)] = list_containers(runtime, owner)
        except (RuntimeError, subprocess.SubprocessError, OSError, ValueError) as e:
            if failed is not None:
                failed.add((runtime, owner))
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
            wd = c["labels"].get(WORKING_DIR_LABEL, "")
            # Labels are set by whoever starts the container; a name or directory
            # with control characters can only be an attempt to corrupt the registry.
            if CONTROL_CHARS.search(f"{name or ''}{wd}"):
                log(f"WARNING: ignoring compose project of container {c['name']}: its labels contain control characters")
                continue
            if name:
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
            text = read_user_file(os.path.join(path, f))
        except OSError:
            continue
        names |= {m.group(1).lower() for m in re.finditer(pattern, text, re.M)
                  if "$" not in m.group(1) and PROJECT_RE.match(m.group(1).lower())}
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
            if c["id"] not in claimed and not c.get("infra"):
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
    return clean_name("-".join(parts), fallback)


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


def clean_name(name: str, fallback: str) -> str:
    """name reduced to what NAME_RE accepts, or fallback (or "service") when nothing is left."""
    cleaned = re.sub(r"[^a-z0-9._-]+", "-", name.lower()).strip("-._")
    if NAME_RE.match(cleaned):
        return cleaned
    return fallback if NAME_RE.match(fallback) else "service"


def name_from_units(units: list, fallback: str) -> str:
    """A service name for containers that systemd units start but whose project
    directory cannot be told: the unit's name, or what several share
    (sead-api, sead-db -> sead)."""
    if len(units) == 1:
        return clean_name(units[0], fallback)
    common = []
    for parts in zip(*(re.split(r"[-_.]", u) for u in units)):
        if len(set(parts)) > 1:
            break
        common.append(parts[0])
    name = "-".join(common)
    return clean_name(name, fallback) if len(name) >= 3 else fallback


def unique_name(name: str, taken: set) -> str:
    n, candidate = 2, name
    while candidate in taken:
        candidate, n = f"{name}-{n}", n + 1
    return candidate


def days_since(day: str) -> int:
    try:
        return (date.today() - date.fromisoformat(day)).days
    except ValueError:
        return 0


def cmd_services(args) -> int:
    """Find services and register them. Interactive by default. With --auto (the
    nightly humlab-discover.service) it registers what it finds without asking,
    except what was declined or unregistered before, and unregisters services
    that have had no running containers for SERVICE_EXPIRE_DAYS days."""
    auto = args.auto
    if auto and os.environ.get("SERVICE_DISCOVERY", "auto") != "auto":
        print("SERVICE_DISCOVERY is not 'auto' in agents.env; nothing done")
        return 0
    services = load_registry()
    ignored = load_ignored()
    ignored_before = dict(ignored)
    registered = {s.key for s in services}
    taken = {s.name for s in services}
    asked = set()
    changes = []

    if services and not auto:
        print("Already registered:")
        for s in services:
            print(f"  {s.name:24} {s.deployment:9} {s.runtime:7} owner={s.owner:12} {s.path or s.container}")
        print()

    def offer(svc: Service, what: str, recommended: bool = True, note: str = "") -> None:
        """Registers svc: in auto mode if recommended and not ignored, else if the
        admin says yes. A no is remembered in ignored.conf."""
        if svc.key in registered or svc.key in asked:
            return
        asked.add(svc.key)
        # Names can derive from container labels, which any user controls.
        svc.name = clean_name(svc.name, "service")
        if auto:
            if not recommended or svc.key in ignored:
                return
            svc.name = unique_name(svc.name, taken)
        else:
            print(what)
            if note:
                print(f"  {note}")
            declined = svc.key in ignored
            if declined:
                print(f"  Declined or unregistered before ({ignored[svc.key]}).")
            if not ask_yes("  Monitor it?", recommended and not declined):
                if not declined:
                    ignore(ignored, svc, "declined")
                return
            svc.name = ask_name(unique_name(svc.name, taken), taken)
            ignored.pop(svc.key, None)
        svc.last_seen = date.today().isoformat()
        services.append(svc)
        registered.add(svc.key)
        taken.add(svc.name)
        changes.append(f"Registered {svc.name}: {what}")

    # Quadlet service users
    for pw in quadlet_users():
        offer(Service(pw.pw_name, "quadlet", "podman", pw.pw_name, pw.pw_dir),
              f"Quadlet service user {pw.pw_name} ({pw.pw_dir})")

    failed = set()
    listed = running_containers(failed)

    # Containers that systemd units start in other accounts (quadlets outside
    # /srv, e.g. a deployment that installs its quadlets in a user's
    # ~/.config/containers/systemd), one service per project directory.
    for owner, project, units in running_systemd_projects(listed):
        if any(s.deployment == "quadlet" and s.owner == owner and is_under(project, s.path) for s in services):
            continue
        whole_user = same_path(project, pwd.getpwnam(owner).pw_dir)
        what = f"Podman containers of {owner}" if whole_user else f"Podman project {project} (user {owner})"
        # Without a project directory, the units say more than the home directory.
        name = name_from_units(units, owner) if whole_user else suggest_name(project, owner)
        offer(Service(name, "quadlet", "podman", owner, project), f"{what}, started by systemd: {', '.join(units)}")

    # Compose projects, found on disk
    roots = [r for r in DEFAULT_ROOTS if os.path.isdir(r)]
    if not auto:
        roots = ask("Directories to search for compose files", " ".join(roots)).split()
    running = running_compose_projects(listed)
    quadlet_homes = [os.path.realpath(s.path) for s in services if s.deployment == "quadlet"]

    def compose_service(path: str, info) -> Service:
        # A project name set in the compose file says more than a directory name.
        if info.name != compose_project_name(path):
            name = info.name
        else:
            name = suggest_name(path, compose_project_name(path))
        return Service(name, "compose", info.runtime, info.owner, os.path.realpath(path),
                       info.name if info.name != compose_project_name(path) else "")

    # Only running projects are offered; a home directory can hold dozens of
    # checkouts that are never started. Those can be added by path below.
    registered_dirs = {os.path.realpath(s.path) for s in services if s.deployment == "compose"}
    idle = []
    for d in find_compose_dirs(roots):
        if os.path.realpath(d) in registered_dirs or any(os.path.realpath(d).startswith(h + "/") for h in quadlet_homes):
            continue
        info, how = find_running_project(d, running, services)
        if not info:
            idle.append(d)
            continue
        offer(compose_service(d, info), f"Compose project {d} (running under {info.runtime} as {info.owner}, matched by {how})")

    # Running compose projects whose directory the search did not find (outside
    # the search roots, or an unusual compose file name).
    for p in running:
        if not (p.working_dir and os.path.isdir(p.working_dir)):
            continue
        if any(s.deployment == "compose" and (s.runtime, s.owner) == (p.runtime, p.owner) and s.matches(p.labels)
               for s in services):
            continue
        offer(compose_service(p.working_dir, p),
              f"Compose project {p.working_dir} (running under {p.runtime} as {p.owner})")

    # Containers nothing else covers: started by hand, or from a compose
    # directory that no longer exists. One service each.
    attach_containers(services, listed)
    claimed = {c["id"] for s in services for c in s.containers}
    for (runtime, owner), containers in sorted(listed.items()):
        for c in sorted(containers, key=lambda c: c["name"]):
            labels = c["labels"]
            wd = labels.get(WORKING_DIR_LABEL)
            if c["id"] in claimed or c.get("infra") or labels.get(SYSTEMD_UNIT_LABEL) \
                    or (labels.get("com.docker.compose.project") and wd and os.path.isdir(wd)):
                continue
            how = (f"compose project {labels['com.docker.compose.project']}, directory gone"
                   if labels.get("com.docker.compose.project") else "started by hand")
            generated = bool(GENERATED_NAME.match(c["name"]))
            offer(Service(clean_name(c["name"], "container"), "container", runtime, owner, "", container=c["name"]),
                  f"Container {c['name']} ({owner}, {runtime}, {how}, image {c['image']})",
                  recommended=not generated,
                  note="Its name was made up by the runtime and changes when the container is recreated."
                  if generated else "")

    if idle and not auto:
        print(f"\n{idle} compose directories have no running containers and are not offered.")
        if ask_yes("  List them?", False):
            for d in idle:
                print(f"    {d}")

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
                svc = compose_service(path, info)
            else:
                runtime = ask("  Runtime (podman/docker)", "docker" if shutil.which("docker") else "podman")
                owner = "root" if runtime == "docker" else pwd.getpwuid(os.stat(path).st_uid).pw_name
                owner = ask("  Owner (the user who runs it; root for docker or rootful podman)", owner)
                while not user_exists(owner):
                    owner = ask(f"  No user '{owner}'. Owner", "root")
                project = ask("  Compose project name (the prefix of its container names)", compose_project_name(path))
                svc = Service(suggest_name(path, project), "compose", runtime, owner, os.path.realpath(path),
                              project if project != compose_project_name(path) else "")
            if svc.runtime not in ("podman", "docker"):
                print(f"  Skipped {path}: unknown runtime '{svc.runtime}'")
                continue
            asked.discard(svc.key)
            ignored.pop(svc.key, None)
            offer(svc, f"Compose project {path}")

        for s in list(services):
            if s.path and not os.path.isdir(s.path) and ask_yes(f"{s.name}: {s.path} no longer exists. Remove it?", True):
                services.remove(s)

    # Last seen, and in auto mode unregistering what has been gone for a while.
    # A runtime that could not be listed proves nothing about its services.
    attach_containers(services, listed)
    today = date.today().isoformat()
    for s in services:
        if s.containers or not s.last_seen:
            s.last_seen = today
    if auto:
        expire = int(os.environ.get("SERVICE_EXPIRE_DAYS", "60"))
        for s in list(services):
            if (s.runtime, s.owner) not in failed and days_since(s.last_seen) >= expire:
                services.remove(s)
                changes.append(f"Unregistered {s.name}: no running containers since {s.last_seen}")

    if not auto:
        uncovered = uncovered_containers(services, listed)
        if uncovered:
            print("\nRunning containers that no service covers (logged under their own names, no SBOM):")
            for line in uncovered:
                print(f"  {line}")
            print()
        for owner in sorted({s.owner for s in services if s.runtime == "podman" and s.owner != "root"}):
            if user_exists(owner):
                uid = pwd.getpwnam(owner).pw_uid
                if not os.path.exists(f"/var/lib/systemd/linger/{owner}"):
                    print(f"NOTE: {owner} has no lingering; its containers stop at logout and cannot be "
                          f"scanned while it is logged out. Fix: loginctl enable-linger {owner}")
                elif not os.path.isdir(f"/run/user/{uid}"):
                    print(f"NOTE: /run/user/{uid} for {owner} is missing")

    save_registry(services)
    if ignored != ignored_before:
        save_ignored(ignored)
    for line in changes:
        print(line)
    if auto and not changes:
        print("No changes")
    elif not auto:
        print(f"Saved {len(services)} services to {REGISTRY}")
    return 0


def cmd_remove(args) -> int:
    services = load_registry()
    unknown = sorted(set(args.service) - {s.name for s in services})
    if unknown:
        log(f"ERROR: not registered: {', '.join(unknown)}")
        return 1
    ignored = load_ignored()
    for s in services:
        if s.name in args.service:
            ignore(ignored, s, "unregistered")
    save_registry([s for s in services if s.name not in args.service])
    save_ignored(ignored)
    print(f"Removed {', '.join(args.service)}. Its containers are now logged under their own names, and "
          f"automatic discovery leaves it alone; its Dependency-Track project is kept.")
    return 0


def print_services(services: list) -> None:
    for i, s in enumerate(services, 1):
        print(f"{i:3}. {s.name:24} {s.deployment:9} {s.runtime:7} owner={s.owner:12} {s.path or s.container}")
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
        print(f"\n{s.name}: " + (f"container {s.container}" if s.container else f"{s.deployment} project in {s.path}"))
        action = input("  [N] New name  [D] Unregister  [Enter] Back: ").strip().lower()
        if action == "n":
            suggestion = clean_name(s.container, s.name) if s.container else suggest_name(s.path, s.name)
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
                ignored = load_ignored()
                ignore(ignored, s, "unregistered")
                save_ignored(ignored)
                print(f"  Unregistered {s.name}. Its containers are now logged under their own names, and\n"
                      f"  automatic discovery leaves it alone (find it again with F to undo that).")
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
    p.add_argument("--auto", "--yes", action="store_true",
                   help="register what is found without asking (except what was declined or unregistered), "
                        "and unregister services without running containers for SERVICE_EXPIRE_DAYS days")
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
