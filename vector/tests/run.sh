#!/usr/bin/env bash
# Renders vector.yaml with test values and runs the unit tests in logs.yaml.
#
#   vector/tests/run.sh [path/to/vector]
set -euo pipefail

here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
root=$(cd "$here/../.." && pwd)
vector=${1:-${VECTOR:-vector}}
tmp=$(mktemp -d)
trap 'rm -rf -- "$tmp"' EXIT

mkdir "$tmp/creds"
echo test >"$tmp/creds/opensearch_password"
echo test >"$tmp/creds/prometheus_password"
printf 'container_id,container_name,service,image,owner_uid\n%s,web-1,web,nginx,0\n' "$(printf '1%.0s' {1..64})" >"$tmp/inventory.csv"
cat >"$tmp/agents.env" <<ENV
HOST_NAME=testhost
OPENSEARCH_URL=https://api.opensearch.example.org
OPENSEARCH_USER=ingest-testhost
PROMETHEUS_URL=https://api.prometheus.example.org/api/v1/write
PROMETHEUS_USER=metrics-testhost
HOST_LOG_MAX_PRIORITY=4
HOST_LOG_UNITS=ssh.service sshd.service
DATA_DIR=$tmp/data
CREDENTIALS_DIR=$tmp/creds
INVENTORY=$tmp/inventory.csv
ENV
mkdir "$tmp/data"

python3 "$root/agent/humlab_agents.py" render "$root/vector/vector.yaml" "$tmp/agents.env" >"$tmp/vector.yaml"
"$vector" validate --no-environment --skip-healthchecks "$tmp/vector.yaml"
"$vector" test "$tmp/vector.yaml" "$here/logs.yaml"
