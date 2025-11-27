# Dependency-Track Satellite Scanner

## Installation
1. Git clone this repository into your `<service home directory>`.
2. Run `install.sh`.

## Overview

This system provides **automatic SBOM scanning** for each service.
A lightweight “satellite” container runs inside the service’s Podman/Quadlet stack and periodically:

1. **Generates SBOMs** for the service’s container images using *Syft*.
2. **Uploads them** to Dependency-Track via its API.

Each service runs its own satellite.
The satellite is configured with a small `dtrack.env` file that tells it:

* where the Dependency-Track server is
* which project/version to upload to
* which images to scan
* how often to scan

A Quadlet unit starts the satellite, places it on the service’s network, and keeps it running.

In short: **every service automatically reports its real dependencies to Dependency-Track**, with no manual work and no privileged host access.
