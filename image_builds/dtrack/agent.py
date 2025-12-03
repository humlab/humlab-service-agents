#!/usr/bin/env python3
import os
import json
import base64
import socket
import subprocess
import time
import re
from datetime import datetime, UTC

import requests

# ========= Config from environment =========
DT_URL = os.environ.get("DT_URL")
DT_API_KEY = os.environ.get("DT_API_KEY")
DT_PROJECT_NAME = os.environ.get("DT_PROJECT_NAME")  # logical root/app/service name
DT_PROJECT_VERSION_BASE = os.environ.get("DT_PROJECT_VERSION", "v0.0.0")
SCAN_INTERVAL_SECONDS = int(os.environ.get("SCAN_INTERVAL_SECONDS", "3600"))
SERVER_HOSTNAME = os.environ.get("SERVER_HOSTNAME")

if not DT_URL or not DT_API_KEY or not DT_PROJECT_NAME:
    raise SystemExit("DT_URL, DT_API_KEY and DT_PROJECT_NAME must be set")

DT_URL = DT_URL.rstrip("/")

SESSION = requests.Session()
SESSION.headers.update(
    {
        "X-Api-Key": DT_API_KEY,
        "Content-Type": "application/json",
        "Accept": "application/json",
    }
)

# make syft behave nicely in our environment
os.environ.setdefault("SYFT_CHECK_FOR_APP_UPDATE", "false")
os.environ.setdefault("DOCKER_HOST", "unix:///run/podman/podman.sock")


# ========= Helpers =========
def log(msg: str) -> None:
    now = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    print(f"[{now}] {msg}", flush=True)


def discover_containers():
    """
    Use Podman's Docker-compatible HTTP API over /run/podman/podman.sock
    to discover running containers and their images.
    """
    try:
        out = subprocess.check_output(
            [
                "curl",
                "--unix-socket",
                "/run/podman/podman.sock",
                "-s",
                "-H",
                "Content-Type: application/json",
                "http://d/containers/json",
            ],
            text=True,
        )
        data = json.loads(out)
    except Exception as e:
        log(f"ERROR: failed to query podman socket: {e}")
        return []

    containers = []
    for c in data:
        raw_name = c.get("Names", ["unknown"])[0]
        # PODMAN/DOCKER: names often come like "/foo"
        name = raw_name.lstrip("/") if raw_name else "unknown"
        containers.append(
            {
                "id": c.get("Id"),
                "name": name,
                "image": c.get("Image"),
            }
        )
    
    log(f"Discovered {len(containers)} containers:")
    for c in containers:
        log(f"  - {c['name']} ({c['image']})")
    
    return containers


def sanitize_licenses(bom: dict) -> None:
    """
    Fix the 'licenses' field to be CycloneDX-friendly:
    - Prefer a single 'expression'.
    - Strip invalid URLs.
    - Drop completely broken licenses.
    """
    url_pattern = re.compile(r"^(https?|ftp)://[^\s/$.?#].[^\s]*$")

    for component in bom.get("components", []):
        if "licenses" not in component:
            continue

        valid_license = None
        for lic in component["licenses"]:
            if not isinstance(lic, dict):
                continue

            expr = lic.get("expression")
            if isinstance(expr, str):
                valid_license = {"expression": expr}
                break

            lic_obj = lic.get("license")
            if isinstance(lic_obj, dict):
                if "id" in lic_obj:
                    valid_license = {"expression": lic_obj["id"]}
                    break
                if "name" in lic_obj:
                    valid_license = {"expression": lic_obj["name"]}
                    break
                if "url" in lic_obj:
                    url = lic_obj["url"]
                    if not url_pattern.match(url):
                        lic_obj.pop("url", None)

        if valid_license:
            component["licenses"] = [valid_license]
        else:
            component.pop("licenses", None)


def get_or_create_project(name: str, hostname: str, parent_uuid: str = None) -> str | None:
    """
    Parent project (no parent_uuid):
      name: "<DT_PROJECT_NAME>"
      version: "<DT_PROJECT_VERSION_BASE>_<YYYYMMDD>_<hostname>"

    Child project (with parent_uuid):
      name: "<container/service name>"
      version: "<DT_PROJECT_VERSION_BASE>_<YYYYMMDD>_<last4(parent_uuid)>"
    """

    today = datetime.now(UTC).strftime("%Y%m%d")

    if parent_uuid is None:
        # parent project always uses DT_PROJECT_NAME, not container name
        project_name = DT_PROJECT_NAME
        project_version = f"{DT_PROJECT_VERSION_BASE}_{today}_{hostname}"
        classifier = "APPLICATION"
    else:
        project_name = name
        project_version = f"{DT_PROJECT_VERSION_BASE}_{today}_{parent_uuid[-4:]}"
        classifier = "CONTAINER"

    # 1) search existing
    search_url = f"{DT_URL}/api/v1/project?name={project_name}&version={project_version}"
    log(f"Checking for project '{project_name}' (version {project_version})")
    r = SESSION.get(search_url)
    if r.status_code == 200:
        projects = r.json()
        if projects:
            uuid = projects[0]["uuid"]
            log(f"Project already exists: {uuid}")
            return uuid
    elif r.status_code != 404:
        log(f"ERROR: search failed for project {project_name}: {r.status_code} {r.text}")
        return None

    # 2) create
    payload = {
        "name": project_name,
        "version": project_version,
        "classifier": classifier,
        "active": True,
    }
    if parent_uuid is not None:
        payload["parent"] = {"uuid": parent_uuid}

    log(f"Creating project '{project_name}' (version {project_version})")
    create_url = f"{DT_URL}/api/v1/project"
    r = SESSION.put(create_url, json=payload)
    try:
        body = r.json()
    except Exception:
        body = {}

    if r.status_code != 201 or "uuid" not in body:
        log(f"ERROR: failed to create project: {r.status_code} {body}")
        return None

    uuid = body["uuid"]
    log(f"Created project {project_name} uuid={uuid}")

    # 3) tag / parent metadata (inspired by old script)
    tags = [{"name": hostname}]
    if SERVER_HOSTNAME:
        tags.append({"name": SERVER_HOSTNAME})

    try:
        SESSION.patch(f"{DT_URL}/api/v1/project/{uuid}", json={"tags": tags})
    except Exception as e:
        log(f"WARNING: failed to tag project {uuid}: {e}")

    return uuid


def run_syft(image: str, service_name: str) -> dict | None:
    """
    Run syft against docker:<image> via DOCKER_HOST (Podman socket).
    Returns parsed CycloneDX JSON with metadata + tweaks.
    """
    if ":" not in image:
        image = image + ":latest"

    log(f"Scanning {image} with syft")
    cmd = ["syft", "-q", f"docker:{image}", "-o", "cyclonedx-json"]
    try:
        out = subprocess.check_output(cmd, text=True)
    except subprocess.CalledProcessError as e:
        log(f"ERROR: syft failed for {image}: {e}")
        return None

    try:
        bom = json.loads(out)
    except Exception as e:
        log(f"ERROR: failed to parse syft output for {image}: {e}")
        return None

    # inject metadata.component if missing
    bom.setdefault("metadata", {})
    bom["metadata"].setdefault(
        "component",
        {
            "type": "application",
            "name": service_name,
            "version": "1.0.0",  # can be refined based on image/tag
        },
    )

    # set group on each component to service_name
    for comp in bom.get("components", []):
        comp["group"] = service_name

    sanitize_licenses(bom)
    return bom


def upload_bom(project_uuid: str, bom: dict, service_name: str) -> str | None:
    """
    Base64-encode the BOM and upload it to DTrack for the given project UUID.
    Inspired by your old send_to_dtrack().
    """
    try:
        bom_json = json.dumps(bom)
    except Exception as e:
        log(f"ERROR: failed to serialize BOM for {service_name}: {e}")
        return None

    bom_encoded = base64.b64encode(bom_json.encode("utf-8")).decode("utf-8")
    payload = {"project": project_uuid, "bom": bom_encoded}
    url = f"{DT_URL}/api/v1/bom"
    r = SESSION.put(url, json=payload)
    if r.status_code != 200:
        log(f"ERROR: BOM upload failed for {service_name}: {r.status_code} {r.text}")
        return None

    try:
        token = r.json().get("token")
    except Exception:
        token = None

    if token:
        log(f"BOM uploaded for {service_name}, token={token}")
    else:
        log(f"BOM uploaded for {service_name}, but no token returned")

    return token


def wait_for_bom(token: str) -> None:
    """
    Optional: poll BOM processing status like in your old script.
    """
    url = f"{DT_URL}/api/v1/bom/token/{token}"
    headers = {"X-Api-Key": DT_API_KEY}
    for _ in range(10):
        r = requests.get(url, headers=headers)
        if r.status_code != 200:
            log(f"WARNING: BOM status check failed: {r.status_code} {r.text}")
            return
        js = r.json()
        if not js.get("processing", False):
            log("BOM processing completed")
            return
        time.sleep(5)
    log("BOM processing may still be ongoing")


def main_loop():
    hostname = socket.gethostname()
    log(f"Agent starting, DT root project={DT_PROJECT_NAME}, host={hostname}")

    parent_uuid = get_or_create_project(DT_PROJECT_NAME, hostname, parent_uuid=None)
    if not parent_uuid:
        log("ERROR: could not create/find parent project, aborting.")
        return

    while True:
        log("Starting scan cycle")
        containers = discover_containers()
        if not containers:
            log("No containers discovered, sleeping")
            time.sleep(SCAN_INTERVAL_SECONDS)
            continue

        log("Intended project structure:")
        log(f"  {DT_PROJECT_NAME}")
        for c in containers:
            if c["image"]:
                log(f"    └─ {c['name']}")

        for c in containers:
            name = c["name"]
            image = c["image"]
            if not image:
                continue

            # child project per container/service
            project_uuid = get_or_create_project(name, hostname, parent_uuid=parent_uuid)
            if not project_uuid:
                continue

            bom = run_syft(image, service_name=name)
            if not bom:
                continue

            token = upload_bom(project_uuid, bom, service_name=name)
            if token:
                wait_for_bom(token)

        log(f"Scan cycle done, sleeping {SCAN_INTERVAL_SECONDS}s")
        time.sleep(SCAN_INTERVAL_SECONDS)


if __name__ == "__main__":
    main_loop()
