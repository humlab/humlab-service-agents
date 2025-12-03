import os
import time
import json
import threading
import logging
from typing import Dict, Set

import requests_unixsocket
from opensearchpy import OpenSearch, RequestsHttpConnection

# -----------------------------------------------------------------------------
# Config
# -----------------------------------------------------------------------------
PODMAN_SOCKET_PATH = os.getenv("PODMAN_SOCKET_PATH", "/run/podman/podman.sock")
OPENSEARCH_URL = os.getenv("OPENSEARCH_URL", "http://opensearch:9200")
OPENSEARCH_INDEX_PREFIX = os.getenv("OPENSEARCH_INDEX_PREFIX", "podman-logs")
NODE_NAME = os.getenv("NODE_NAME", "podman-node")
DISCOVERY_INTERVAL_SECONDS = int(os.getenv("DISCOVERY_INTERVAL_SECONDS", "10"))
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO").upper()
AGENT_MODE = os.getenv("AGENT_MODE", "opensearch").lower()  # "opensearch" or "local"

logging.basicConfig(
    level=getattr(logging, LOG_LEVEL, logging.INFO),
    format="%(asctime)s [%(levelname)s] %(threadName)s: %(message)s",
)
logger = logging.getLogger(__name__)

# -----------------------------------------------------------------------------
# Clients
# -----------------------------------------------------------------------------
# Unix socket session for Podman API
session = requests_unixsocket.Session()
PODMAN_BASE_URL = f"http+unix://{PODMAN_SOCKET_PATH.replace('/', '%2F')}"

# OpenSearch client (lazy init; only when needed)
opensearch_client = None
if AGENT_MODE == "opensearch":
    try:
        opensearch_client = OpenSearch(
            hosts=[OPENSEARCH_URL],
            connection_class=RequestsHttpConnection,
            use_ssl=OPENSEARCH_URL.startswith("https"),
            verify_certs=False,  # change to True + CA bundle in production
        )
        logger.info("OpenSearch mode enabled, URL=%s", OPENSEARCH_URL)
    except Exception as e:
        logger.error("Failed to init OpenSearch client: %s", e)


# -----------------------------------------------------------------------------
# Helpers
# -----------------------------------------------------------------------------
def list_containers() -> Dict[str, str]:
    """
    Returns {container_id: name} for all running containers using Podman API.
    """
    url = f"{PODMAN_BASE_URL}/v4.0.0/libpod/containers/json"
    try:
        r = session.get(url)
        r.raise_for_status()
        containers = r.json()
    except Exception as e:
        logger.error("Error listing containers via Podman API: %s", e)
        return {}

    out = {}
    for c in containers:
        cid = c.get("Id") or c.get("ID")
        names = c.get("Names") or []
        name = names[0] if names else (cid[:12] if cid else "unknown")
        if cid:
            out[cid] = name
    return out


def send_log(doc: dict):
    """
    Sends a log doc either to OpenSearch or stdout depending on AGENT_MODE.
    """
    if AGENT_MODE == "local":
        # Local/debug mode: just print JSON lines to stdout so you can inspect with
        # `podman logs opensearch-satellite`.
        # Trim message a bit to avoid insane spam.
        msg = doc.get("message", "")
        doc_print = dict(doc)
        if len(msg) > 300:
            doc_print["message"] = msg[:300] + "...[truncated]"
        print(json.dumps(doc_print, ensure_ascii=False))
        return

    # Default: OpenSearch mode
    if opensearch_client is None:
        logger.error("OpenSearch client not initialized, cannot send log")
        return

    index_name = f"{OPENSEARCH_INDEX_PREFIX}-{time.strftime('%Y.%m.%d')}"
    try:
        opensearch_client.index(index=index_name, body=doc)
    except Exception as e:
        logger.error("Failed to index log line: %s", e)


def stream_logs(container_id: str, name: str):
    """
    Follow logs for a single container and send to OpenSearch or stdout.
    """
    url = (
        f"{PODMAN_BASE_URL}/v4.0.0/libpod/containers/{container_id}/logs"
        "?stdout=1&stderr=1&follow=1&since=0&timestamps=1"
    )

    logger.info("Starting log stream for %s (%s)", name, container_id[:12])

    try:
        with session.get(url, stream=True) as r:
            r.raise_for_status()
            for raw_line in r.iter_lines():
                if not raw_line:
                    continue
                try:
                    line = raw_line.decode("utf-8", errors="replace")
                except Exception:
                    line = str(raw_line)

                doc = {
                    "@timestamp": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
                    "message": line,
                    "container_id": container_id,
                    "container_name": name,
                    "node": NODE_NAME,
                }

                send_log(doc)
    except Exception as e:
        logger.error("Error streaming logs for %s (%s): %s", name, container_id[:12], e)

    logger.info("Log stream ended for %s (%s)", name, container_id[:12])


# -----------------------------------------------------------------------------
# Main discovery loop
# -----------------------------------------------------------------------------
def main():
    logger.info("Starting OpenSearch satellite")
    logger.info("Mode: %s", AGENT_MODE)
    logger.info("Podman socket: %s", PODMAN_SOCKET_PATH)

    active_streams: Set[str] = set()
    threads: Dict[str, threading.Thread] = {}

    while True:
        containers = list_containers()
        logger.debug("Discovered containers: %s", containers)

        for cid, name in containers.items():
            if cid not in active_streams:
                logger.info("Starting log collector for container %s (%s)", name, cid[:12])
                t = threading.Thread(
                    target=stream_logs,
                    args=(cid, name),
                    daemon=True,
                    name=f"log-{name}",
                )
                t.start()
                active_streams.add(cid)
                threads[cid] = t

        # Clean up threads that died
        dead = [cid for cid, t in threads.items() if not t.is_alive()]
        for cid in dead:
            logger.info("Cleaning up dead log stream for %s", cid[:12])
            active_streams.discard(cid)
            threads.pop(cid, None)

        time.sleep(DISCOVERY_INTERVAL_SECONDS)


if __name__ == "__main__":
    main()